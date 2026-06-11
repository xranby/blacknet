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

//! Milestone 3: folding of step instances (Nova, eprint 2021/370) over the
//! R1CS shape of the step relation.
//!
//! A relaxed instance is `(z, u, E)` with satisfaction
//! `Az ∘ Bz = u·Cz + E`. A strict instance embeds as `(z, 1, 0)`. Folding
//! two instances with challenge `r` squeezed from the duplex transcript:
//!
//! `z = z₁ + r·z₂`, `u = u₁ + r·u₂`, `E = E₁ + r·T + r²·E₂`
//!
//! with cross term `T = Az₁∘Bz₂ + Az₂∘Bz₁ − u₁·Cz₂ − u₂·Cz₁`.
//!
//! This module folds *plain* instances: commitments to `z` and `E` (Ajtai)
//! and the in-circuit fold verifier (recursion, milestone 5) are layered on
//! top. The fold budget plays the role of the lattice norm budget in the
//! architecture: it is checked here on the verifier path, not trusted from
//! the prover, because exceeding it breaks soundness silently.

use blacknet_arith::r1cs::ShapedR1cs;
use blacknet_crypto::matrix::DenseVector;
use blacknet_crypto::pervushin::PervushinField;
use blacknet_crypto::symmetric::Duplexer;

pub type F = PervushinField;

#[derive(Clone, Debug)]
pub struct RelaxedInstance {
    pub z: DenseVector<F>,
    pub u: F,
    pub e: DenseVector<F>,
    /// Remaining folds this instance may absorb. Decremented per fold and
    /// enforced by [`is_satisfied`]; the future lattice instantiation maps
    /// this to a witness norm budget.
    pub budget: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Shape,
    BudgetExhausted,
    Unsatisfied(usize),
}

impl RelaxedInstance {
    /// Embeds a strict (satisfying) instance: `u = 1`, `E = 0`.
    #[must_use]
    pub fn strict(r1cs: &ShapedR1cs, z: DenseVector<F>, budget: u32) -> Self {
        let rows = r1cs.a().rows();
        Self {
            z,
            u: F::from(1),
            e: DenseVector::fill(rows, F::from(0)),
            budget,
        }
    }
}

/// Checks `Az ∘ Bz = u·Cz + E`. Verifier-side: also rejects exhausted
/// budgets so a chain of folds longer than declared can never verify.
pub fn is_satisfied(r1cs: &ShapedR1cs, instance: &RelaxedInstance) -> Result<(), Error> {
    let (az, bz, cz) = r1cs.images(&instance.z);
    if az.dimension() != instance.e.dimension() {
        return Err(Error::Shape);
    }
    for i in 0..az.dimension() {
        if az[i] * bz[i] != instance.u * cz[i] + instance.e[i] {
            return Err(Error::Unsatisfied(i));
        }
    }
    Ok(())
}

/// Folds two relaxed instances with a transcript challenge. The caller must
/// absorb both instances (or binding commitments to them) into `duplex`
/// before calling, with full context binding per the architecture §7.
pub fn fold<D: Duplexer<Msg = F>>(
    r1cs: &ShapedR1cs,
    lhs: &RelaxedInstance,
    rhs: &RelaxedInstance,
    duplex: &mut D,
) -> Result<RelaxedInstance, Error> {
    if lhs.z.dimension() != rhs.z.dimension() || lhs.e.dimension() != rhs.e.dimension() {
        return Err(Error::Shape);
    }
    if lhs.budget == 0 || rhs.budget == 0 {
        return Err(Error::BudgetExhausted);
    }
    let r: F = duplex.squeeze();

    let (az1, bz1, cz1) = r1cs.images(&lhs.z);
    let (az2, bz2, cz2) = r1cs.images(&rhs.z);
    let rows = az1.dimension();

    // T = Az1∘Bz2 + Az2∘Bz1 − u1·Cz2 − u2·Cz1
    let t: DenseVector<F> = (0..rows)
        .map(|i| az1[i] * bz2[i] + az2[i] * bz1[i] - lhs.u * cz2[i] - rhs.u * cz1[i])
        .collect();

    let z: DenseVector<F> = (0..lhs.z.dimension())
        .map(|i| lhs.z[i] + r * rhs.z[i])
        .collect();
    let e: DenseVector<F> = (0..rows)
        .map(|i| lhs.e[i] + r * t[i] + r * r * rhs.e[i])
        .collect();

    Ok(RelaxedInstance {
        z,
        u: lhs.u + r * rhs.u,
        e,
        budget: lhs.budget.min(rhs.budget) - 1,
    })
}
