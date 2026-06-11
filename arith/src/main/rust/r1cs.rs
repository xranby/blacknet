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

//! The R1CS shape `Az ∘ Bz = Cz` of the step relation, keeping the three
//! matrices addressable (the folding scheme needs them), with a lossless
//! embedding into the crypto crate's [`CustomizableConstraintSystem`].

use blacknet_crypto::customizableconstraintsystem::CustomizableConstraintSystem;
use blacknet_crypto::matrix::{DenseVector, SparseMatrix};
use blacknet_crypto::pervushin::PervushinField;

pub type F = PervushinField;

pub struct ShapedR1cs {
    a: SparseMatrix<F>,
    b: SparseMatrix<F>,
    c: SparseMatrix<F>,
}

impl ShapedR1cs {
    pub const fn new(a: SparseMatrix<F>, b: SparseMatrix<F>, c: SparseMatrix<F>) -> Self {
        Self { a, b, c }
    }

    #[must_use]
    pub const fn a(&self) -> &SparseMatrix<F> {
        &self.a
    }

    #[must_use]
    pub const fn b(&self) -> &SparseMatrix<F> {
        &self.b
    }

    #[must_use]
    pub const fn c(&self) -> &SparseMatrix<F> {
        &self.c
    }

    /// `Az ∘ Bz - Cz` as multisets `{A,B}, {C}` with constants `1, -1`.
    #[must_use]
    pub fn to_ccs(&self) -> CustomizableConstraintSystem<F> {
        CustomizableConstraintSystem::new(
            vec![self.a.clone(), self.b.clone(), self.c.clone()],
            vec![vec![0, 1], vec![2]],
            [1, -1].map(F::from).into(),
        )
    }

    /// `Az ∘ Bz`, `Cz` — the building blocks of relaxed satisfaction.
    #[must_use]
    pub fn images(&self, z: &DenseVector<F>) -> (DenseVector<F>, DenseVector<F>, DenseVector<F>) {
        (&self.a * z, &self.b * z, &self.c * z)
    }
}
