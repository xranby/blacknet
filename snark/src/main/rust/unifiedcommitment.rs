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

//! The unified hiding commitment — the resolution of the one open question.
//!
//! The question was whether a single ring can carry the Module-SIS *binding*
//! bound, the Module-LWE *hiding* noise, and the *folding* norm growth at
//! once, or whether distinct ring towers are forced. The parameter analysis
//! (`snark/params.py`, extended here) answers: **one commitment ring
//! suffices** — at 32 ring rows (lattice dimension 2048) binding reaches
//! 128-bit classical security and hiding is over-provisioned by a wide
//! margin, so binding is the binding constraint and a second ring buys
//! nothing.
//!
//! But the ring is *not* the folding field. Pervushin (q = 2⁶¹ − 1, a
//! Mersenne prime) is ideal for folding — cheap reduction, used as the
//! sumcheck field — yet it has no NTT, so ring multiplication is slow. The
//! commitment, which multiplies a public matrix by a witness every fold,
//! wants NTT. That is exactly why the crypto crate carries `LMRing64` and
//! `LMNTT64`: the LM prime q = 2⁶⁰ − 2³² + 1 is NTT-smooth. So the
//! production shape is **one commitment ring, the NTT-friendly LM ring,
//! distinct from the Pervushin folding field** — Answer A in substance
//! (a single lattice for binding and hiding), refined by rat4's ring
//! menu to put the commitment on the ring built for it.
//!
//! BDLOP construction (eprint 2017/1192): the commitment to a message `m`
//! (the packed digit witness) with hiding randomness `r` is
//!
//!   C = A₁·r          (binding part, Module-SIS on r)
//!   D = A₂·r + m      (hiding part, Module-LWE masks m with A₂·r)
//!
//! over the LM ring. Binding: a second opening `(m′, r′)` of `(C, D)` with
//! both `r, r′` short yields `A₁(r − r′) = 0`, a short Module-SIS solution.
//! Hiding: `A₂·r` is pseudorandom under Module-LWE, so `D` reveals nothing
//! about `m`. Both reduce to the same ring at the same dimension — the
//! unification the question asked about.
//!
//! Norm growth under folding is inherited from the digit domain unchanged:
//! `m` and `r` fold linearly with the small challenge, and the budget
//! accounting of `crate::witnesscommitment` applies coordinate-wise after
//! packing, since packing is norm-preserving.

use blacknet_crypto::algebra::IntegerRing;
use blacknet_crypto::convolution::Negacyclic;
use blacknet_crypto::lm::LMField;
use blacknet_crypto::matrix::{DenseMatrix, DenseVector};
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};

/// The folding field (Pervushin), in which witnesses and challenges live.
pub type Fold = blacknet_crypto::pervushin::PervushinField;

/// The commitment ring (NTT-friendly LM), degree 64.
pub type Ring = blacknet_crypto::algebra::UnivariateRing<LMField, DEGREE, Negacyclic>;

pub const DEGREE: usize = 64;

/// Module rank of the binding part (rows of `A₁`): 32 ring rows = lattice
/// dimension 2048, 128-bit classical binding per the extended analysis.
pub const BIND_ROWS: usize = 32;

/// Module rank of the hiding part (rows of `A₂`): the message width in ring
/// elements; one row per packed message element.
pub const HIDE_ROWS: usize = 4;

/// Hiding randomness width in ring elements (the Module-LWE secret length).
pub const RANDOMNESS: usize = 8;

const SETUP_TAG: u32 = 0x424c_4b55; // "BLKU"

/// A BDLOP commitment: a binding part and a hiding part.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment {
    pub binding: DenseVector<Ring>,
    pub hiding: DenseVector<Ring>,
}

/// Transparent commitment key over the LM ring.
pub struct UnifiedKey {
    a1: DenseMatrix<Ring>,
    a2: DenseMatrix<Ring>,
    message_rows: usize,
}

impl UnifiedKey {
    /// Sets up keys for a message of `message_rows` ring elements. Matrices
    /// are squeezed from the duplex (transparent setup); the dimensions are
    /// bound into the seed.
    #[must_use]
    pub fn setup(message_rows: usize) -> Self {
        let mut duplex = DuplexPoseidon2Pervushin::default();
        duplex.absorb(Fold::from(SETUP_TAG));
        duplex.absorb(Fold::from(message_rows as u32));
        let a1 = sample_matrix(&mut duplex, BIND_ROWS, RANDOMNESS);
        let a2 = sample_matrix(&mut duplex, message_rows, RANDOMNESS);
        Self {
            a1,
            a2,
            message_rows,
        }
    }

    /// Commits to a packed message with explicit hiding randomness `r`
    /// (short, Module-LWE secret). Returns `(C, D) = (A₁r, A₂r + m)`. The
    /// message length must not exceed the key's `message_rows`.
    #[must_use]
    pub fn commit(&self, message: &DenseVector<Ring>, r: &DenseVector<Ring>) -> Commitment {
        let binding = &self.a1 * r;
        let mut hiding = &self.a2 * r;
        let rows = message.dimension().min(self.message_rows);
        for i in 0..rows {
            hiding[i] += message[i];
        }
        Commitment { binding, hiding }
    }

    /// Opening check: recompute and compare, with the randomness norm bound
    /// enforced fail-closed (binding holds only for short `r`).
    #[must_use]
    pub fn open(
        &self,
        commitment: &Commitment,
        message: &DenseVector<Ring>,
        r: &DenseVector<Ring>,
        randomness_bound: u128,
    ) -> bool {
        randomness_norm(r) <= randomness_bound && self.commit(message, r) == *commitment
    }
}

fn sample_matrix(
    duplex: &mut DuplexPoseidon2Pervushin,
    rows: usize,
    cols: usize,
) -> DenseMatrix<Ring> {
    DenseMatrix::new(
        rows,
        cols,
        (0..rows * cols)
            .map(|_| {
                let mut e = Ring::default();
                for k in 0..DEGREE {
                    // LM coefficients squeezed from the Pervushin-field
                    // transcript, reduced into the LM field.
                    let s: Fold = duplex.squeeze();
                    e[k] = <LMField as IntegerRing>::new(s.canonical());
                }
                e
            })
            .collect(),
    )
}

/// Infinity norm of a ring-element vector over centered coefficients.
#[must_use]
pub fn randomness_norm(r: &DenseVector<Ring>) -> u128 {
    const MODULUS: i64 = 1_152_921_504_606_847_009;
    let mut max = 0i64;
    for i in 0..r.dimension() {
        for k in 0..DEGREE {
            let c = r[i][k].canonical();
            let centered = c.unsigned_abs().min((MODULUS - c).unsigned_abs());
            max = max.max(centered as i64);
        }
    }
    u128::from(max.unsigned_abs())
}

/// Packs Pervushin folding-field digits coefficient-wise into LM ring
/// elements. Linear and infinity-norm preserving (digits are small,
/// reduction is the identity below the LM modulus), so the digit-domain
/// folding of `crate::hypernova` carries over to the commitment unchanged.
#[must_use]
pub fn pack(digits: &DenseVector<Fold>) -> DenseVector<Ring> {
    let elements = digits.dimension().div_ceil(DEGREE);
    (0..elements)
        .map(|i| {
            let mut e = Ring::default();
            for k in 0..DEGREE {
                let idx = i * DEGREE + k;
                if idx < digits.dimension() {
                    e[k] = <LMField as IntegerRing>::new(digits[idx].canonical());
                }
            }
            e
        })
        .collect()
}

/// Samples short Module-LWE hiding randomness from a discrete Gaussian over
/// the LM ring.
#[must_use]
pub fn sample_randomness() -> DenseVector<Ring> {
    use blacknet_crypto::random::{DiscreteGaussianDistribution, Distribution, FAST_RNG};
    FAST_RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        let mut dist = DiscreteGaussianDistribution::<i64, _>::new(0.0, 4.0);
        (0..RANDOMNESS)
            .map(|_| {
                let mut e = Ring::default();
                for k in 0..DEGREE {
                    e[k] = <LMField as IntegerRing>::new(dist.sample(&mut *rng));
                }
                e
            })
            .collect()
    })
}
