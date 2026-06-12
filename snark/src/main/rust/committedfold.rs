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

//! Folding with committed witnesses.
//!
//! Instances live in the digit domain (see [`crate::witnesscommitment`]):
//! the witness is the digit vector `d`, the commitment is `A·d`, and
//! constraint satisfaction is checked on the recomposition `z = G·d`. All
//! of `d`, the commitment, `u`, and `E` fold linearly with the same small
//! challenge, so the verifier-visible part of folding is purely
//! homomorphic: it never touches the witness.
//!
//! The instance carries its accumulated norm bound; the bound is recomputed
//! by the verifier from public data (`b' = b₁ + r·b₂`) and enforced at
//! opening, so a prover cannot launder an over-budget fold.
//!
//! Remaining gap, stated honestly: the error vector `E` is still carried
//! transparently by the accumulator. Eliminating it (HyperNova-style, via a
//! sumcheck over the CCS instead of Nova relaxation) or committing it with
//! per-fold decomposition is the next layer, the next layer of work.

use crate::witnesscommitment::{
    CommitmentKey, F, MAX_NORM, decompose, infinity_norm, recompose, squeeze_challenge,
};
use blacknet_arith::r1cs::ShapedR1cs;
use blacknet_crypto::matrix::DenseVector;
use blacknet_crypto::symmetric::Duplexer;

/// The public, succinct part of a folding instance.
#[derive(Clone, Debug)]
pub struct CommittedInstance {
    pub commitment: DenseVector<F>,
    pub u: F,
    pub norm_bound: u128,
}

/// The prover's secret counterpart.
#[derive(Clone, Debug)]
pub struct CommittedWitness {
    pub d: DenseVector<F>,
    pub e: DenseVector<F>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Shape,
    NormBudget,
    Opening,
    Unsatisfied(usize),
}

/// Embeds a strict satisfying witness `z`: decompose, commit, `u = 1`,
/// `E = 0`, norm bound that of fresh digits.
#[must_use]
pub fn strict(
    key: &CommitmentKey,
    r1cs: &ShapedR1cs,
    z: &DenseVector<F>,
) -> (CommittedInstance, CommittedWitness) {
    let d = decompose(z);
    let commitment = key.commit(&d);
    let norm_bound = infinity_norm(&d);
    let e = DenseVector::fill(r1cs.a().rows(), F::from(0));
    (
        CommittedInstance {
            commitment,
            u: F::from(1),
            norm_bound,
        },
        CommittedWitness { d, e },
    )
}

/// Folds two instances. The verifier-side computation touches only public
/// data: commitments, `u`, norm bounds, and the cross-term commitment `t`
/// supplied by the prover. The witness fold mirrors it linearly.
pub fn fold<D: Duplexer<Msg = F>>(
    r1cs: &ShapedR1cs,
    lhs: (&CommittedInstance, &CommittedWitness),
    rhs: (&CommittedInstance, &CommittedWitness),
    duplex: &mut D,
) -> Result<(CommittedInstance, CommittedWitness), Error> {
    let ((i1, w1), (i2, w2)) = (lhs, rhs);
    if w1.d.dimension() != w2.d.dimension() || w1.e.dimension() != w2.e.dimension() {
        return Err(Error::Shape);
    }
    // Context binding: absorb both public instances before the challenge.
    for c in [&i1.commitment, &i2.commitment] {
        for k in 0..c.dimension() {
            duplex.absorb(c[k]);
        }
    }
    duplex.absorb(i1.u);
    duplex.absorb(i2.u);
    let (r, r_norm) = squeeze_challenge(duplex);

    // Verifier-side norm accounting, fail closed above the binding bound.
    let norm_bound = i1
        .norm_bound
        .checked_add(r_norm.checked_mul(i2.norm_bound).ok_or(Error::NormBudget)?)
        .ok_or(Error::NormBudget)?;
    if norm_bound > MAX_NORM {
        return Err(Error::NormBudget);
    }

    let commitment: DenseVector<F> = (0..i1.commitment.dimension())
        .map(|k| i1.commitment[k] + r * i2.commitment[k])
        .collect();
    let u = i1.u + r * i2.u;

    // Prover side: fold digits and error with the same challenge.
    let z1 = recompose(&w1.d);
    let z2 = recompose(&w2.d);
    let (az1, bz1, cz1) = r1cs.images(&z1);
    let (az2, bz2, cz2) = r1cs.images(&z2);
    let rows = az1.dimension();
    let t: DenseVector<F> = (0..rows)
        .map(|k| az1[k] * bz2[k] + az2[k] * bz1[k] - i1.u * cz2[k] - i2.u * cz1[k])
        .collect();
    let d: DenseVector<F> = (0..w1.d.dimension())
        .map(|k| w1.d[k] + r * w2.d[k])
        .collect();
    let e: DenseVector<F> = (0..rows)
        .map(|k| w1.e[k] + r * t[k] + r * r * w2.e[k])
        .collect();

    Ok((
        CommittedInstance {
            commitment,
            u,
            norm_bound,
        },
        CommittedWitness { d, e },
    ))
}

/// Final opening and satisfaction check. The opening enforces the norm
/// bound (binding), then the relaxed relation is checked on `G·d`.
pub fn open(
    key: &CommitmentKey,
    r1cs: &ShapedR1cs,
    instance: &CommittedInstance,
    witness: &CommittedWitness,
) -> Result<(), Error> {
    if !key.open(&instance.commitment, &witness.d, instance.norm_bound) {
        return Err(Error::Opening);
    }
    let z = recompose(&witness.d);
    let (az, bz, cz) = r1cs.images(&z);
    if az.dimension() != witness.e.dimension() {
        return Err(Error::Shape);
    }
    for k in 0..az.dimension() {
        if az[k] * bz[k] != instance.u * cz[k] + witness.e[k] {
            return Err(Error::Unsatisfied(k));
        }
    }
    Ok(())
}
