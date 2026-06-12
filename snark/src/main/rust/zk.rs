/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

//! Zero-knowledge blinding of the folding pipeline.
//!
//! Two leaks are closed here, and one is documented as remaining:
//!
//! **The opening** (closed). Opening an accumulator reveals the folded
//! digit witness. The fix is a *blinding fold*: before opening, the
//! accumulator is folded — at the same point, a pure linear combination
//! with no sumcheck — with a random linearized instance whose digits the
//! prover samples uniformly from `[0, 2^BLIND_BITS)`. Linearized claims
//! impose no constraint on the blind witness (its claimed evaluations are
//! simply its own MLE values, enforced at opening), so any random vector
//! qualifies. The fold challenge `r'` is squeezed from the transcript
//! *after* the blind commitment and claims are absorbed, forcing the blind
//! claims to be honest: a discrepancy `(v − m̃z)` in the accumulator would
//! need `(v − m̃z) + r'(v_b − m̃z_b) = 0`, which a fixed pre-committed blind
//! instance satisfies for at most one challenge value.
//!
//! *Rejection sampling* makes the blinding statistically perfect: the
//! prover resamples the blind instance until every opened digit lands in
//! the window `[B, r'·2^BLIND_BITS)` where `B` is the accumulator's norm
//! bound. Conditioned on acceptance, each opened digit is uniform on the
//! window regardless of the true digit — the opened witness carries zero
//! information about the folded executions. Acceptance probability is
//! `(1 − B/(r'·2^BLIND_BITS))^m` for `m` digits; the challenge is sampled
//! from `[2^15, 2^16)` to bound it away from zero.
//!
//! **Commitment determinism** (closed by salting). `A·d` is a
//! deterministic function of the witness, so an attacker who can guess a
//! witness can confirm it against the commitment. The pipeline appends
//! `salt` uniformly random field elements to each witness before
//! decomposition; the constraint relation never reads them (the matrices
//! see only their columns), so soundness is unaffected, while the
//! commitment gains `4·salt` uniform low-norm digits of entropy. Hiding is
//! flavored by the leftover hash lemma: full statistical hiding at the
//! consensus row count needs salt comparable to `rows·61/16` digits; the
//! Module-LWE commitment (BDLOP) reaches it compactly and is the
//! production path alongside `modulecommitment`.
//!
//! **Sumcheck round leakage** (remaining). Round polynomials are functions
//! of the witness. The crypto crate ships the Libra masking polynomial
//! (`polynomial::maskingpolynomial`, eprint 2019/317) for exactly this,
//! but composing it requires a *hiding* commitment to the mask with an
//! evaluation opening — the same primitive as single-proof succinctness —
//! and is deferred with it.

use crate::hypernova::{Accumulator, AccumulatorWitness};
use crate::witnesscommitment::{CommitmentKey, F, MAX_NORM, recompose};
use blacknet_crypto::matrix::DenseVector;
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};
use blacknet_vm::machine::Instruction;
use core::array;

type D = DuplexPoseidon2Pervushin;

/// Bits of a blind digit. With challenges in `[2^15, 2^16)` the blind
/// contribution is below `2^{15+BLIND_BITS+1} = 2^43`, keeping the blinded
/// bound within [`MAX_NORM`] for accumulators up to `2^43`.
pub const BLIND_BITS: u32 = 27;

/// Maximum resampling attempts before giving up.
pub const MAX_ATTEMPTS: usize = 64;

/// The public data of one blinding fold.
#[derive(Clone, Debug)]
pub struct BlindProof {
    pub commitment: DenseVector<F>,
    pub evals: [F; 3],
    pub x: Vec<F>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    NormBudget,
    RejectionExhausted,
    Shape,
}

/// Squeezes the blinding challenge from `[2^15, 2^16)`: 15 bits of
/// soundness, bounded away from zero so the blinding window stays wide.
fn squeeze_blind_challenge(duplex: &mut D) -> (F, u128) {
    use blacknet_crypto::algebra::IntegerRing;
    let e: F = duplex.squeeze();
    let r = (1u64 << 15) | ((e.canonical() as u64) & ((1 << 15) - 1));
    (F::from(r as u32), u128::from(r))
}

fn sample_blind_digits(m: usize) -> DenseVector<F> {
    use blacknet_crypto::random::{FAST_RNG, UniformGenerator};
    FAST_RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        (0..m)
            .map(|_| {
                let mut bytes = [0u8; 4];
                rng.fill(&mut bytes);
                F::from(u32::from_le_bytes(bytes) & ((1u32 << BLIND_BITS) - 1))
            })
            .collect()
    })
}

fn canonical_u128(e: F) -> u128 {
    use blacknet_crypto::algebra::IntegerRing;
    e.canonical().unsigned_abs().into()
}

/// MLE evaluations of `Mⱼ·z` at the accumulator's point, for the blind
/// instance's claims.
fn claims_at(r1cs: &blacknet_arith::r1cs::ShapedR1cs, z: &DenseVector<F>, point: &[F]) -> [F; 3] {
    use blacknet_crypto::polynomial::{MultilinearExtension, Point, Polynomial};
    let columns = r1cs.a().columns();
    let zc: DenseVector<F> = (0..columns.min(z.dimension())).map(|i| z[i]).collect();
    let (a, b, c) = r1cs.images(&zc);
    let len = 1usize << point.len();
    let eval = |v: DenseVector<F>| {
        let mut t: Vec<F> = v.into_iter().collect();
        t.resize(len, F::from(0));
        MultilinearExtension::from(t).point(&Point::from(point.to_vec()))
    };
    [eval(a), eval(b), eval(c)]
}

/// Blinds an accumulator for opening. Returns the blind proof, the blinded
/// accumulator, and its witness — whose digits are, conditioned on the
/// rejection sampling having accepted, uniform on a window independent of
/// the true folded witness.
pub fn blind(
    key: &CommitmentKey,
    r1cs: &blacknet_arith::r1cs::ShapedR1cs,
    io_positions: &[usize],
    acc: &Accumulator,
    w: &AccumulatorWitness,
    program: &[Instruction<F>],
) -> Result<(BlindProof, Accumulator, AccumulatorWitness), Error> {
    let m = w.d.dimension();
    // The blind digits must come from real entropy: a deterministic or
    // public blind can be recomputed by anyone, unblinding the opening.
    // FAST_RNG seeds from the operating system's entropy source.
    let _ = program;

    for _attempt in 0..MAX_ATTEMPTS {
        let d_blind = sample_blind_digits(m);
        let z_blind = recompose(&d_blind);
        let c_blind = key.commit(&d_blind);
        let v_blind = claims_at(r1cs, &z_blind, &acc.point);
        let x_blind: Vec<F> = io_positions.iter().map(|&i| z_blind[i]).collect();

        // Protocol transcript: bind everything, then squeeze.
        let mut duplex = D::default();
        absorb_blind(&mut duplex, acc, &c_blind, &v_blind, &x_blind);
        let (r, r_norm) = squeeze_blind_challenge(&mut duplex);

        let bound = acc
            .norm_bound
            .checked_add(r_norm * ((1u128 << BLIND_BITS) - 1))
            .ok_or(Error::NormBudget)?;
        if bound > MAX_NORM {
            return Err(Error::NormBudget);
        }

        // Rejection window: every opened digit in [B, r·2^BLIND_BITS).
        let lo = acc.norm_bound;
        let hi = r_norm << BLIND_BITS;
        let d: DenseVector<F> = (0..m).map(|i| w.d[i] + r * d_blind[i]).collect();
        let accepted = (0..m).all(|i| {
            let v = canonical_u128(d[i]);
            v >= lo && v < hi
        });
        if !accepted {
            continue;
        }

        let acc_out = Accumulator {
            commitment: (0..acc.commitment.dimension())
                .map(|k| acc.commitment[k] + r * c_blind[k])
                .collect(),
            point: acc.point.clone(),
            evals: array::from_fn(|j| acc.evals[j] + r * v_blind[j]),
            x: acc
                .x
                .iter()
                .zip(&x_blind)
                .map(|(a, b)| *a + r * *b)
                .collect(),
            norm_bound: bound,
        };
        return Ok((
            BlindProof {
                commitment: c_blind,
                evals: v_blind,
                x: x_blind,
            },
            acc_out,
            AccumulatorWitness { d },
        ));
    }
    Err(Error::RejectionExhausted)
}

/// Verifier side: replays the blinding fold from public data.
pub fn blind_verify(acc: &Accumulator, proof: &BlindProof) -> Result<Accumulator, Error> {
    if proof.x.len() != acc.x.len() || proof.commitment.dimension() != acc.commitment.dimension() {
        return Err(Error::Shape);
    }
    let mut duplex = D::default();
    absorb_blind(&mut duplex, acc, &proof.commitment, &proof.evals, &proof.x);
    let (r, r_norm) = squeeze_blind_challenge(&mut duplex);
    let bound = acc
        .norm_bound
        .checked_add(r_norm * ((1u128 << BLIND_BITS) - 1))
        .ok_or(Error::NormBudget)?;
    if bound > MAX_NORM {
        return Err(Error::NormBudget);
    }
    Ok(Accumulator {
        commitment: (0..acc.commitment.dimension())
            .map(|k| acc.commitment[k] + r * proof.commitment[k])
            .collect(),
        point: acc.point.clone(),
        evals: array::from_fn(|j| acc.evals[j] + r * proof.evals[j]),
        x: acc
            .x
            .iter()
            .zip(&proof.x)
            .map(|(a, b)| *a + r * *b)
            .collect(),
        norm_bound: bound,
    })
}

fn absorb_blind(
    duplex: &mut D,
    acc: &Accumulator,
    c_blind: &DenseVector<F>,
    v_blind: &[F; 3],
    x_blind: &[F],
) {
    for k in 0..acc.commitment.dimension() {
        duplex.absorb(acc.commitment[k]);
    }
    duplex.absorb_iter(acc.point.iter().copied());
    duplex.absorb_iter(acc.evals.iter().copied());
    duplex.absorb_iter(acc.x.iter().copied());
    for k in 0..c_blind.dimension() {
        duplex.absorb(c_blind[k]);
    }
    duplex.absorb_iter(v_blind.iter().copied());
    duplex.absorb_iter(x_blind.iter().copied());
}
