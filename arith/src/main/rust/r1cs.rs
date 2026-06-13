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

impl ShapedR1cs {
    /// Extracts the R1CS shape from a built circuit's `R1CS`, destructuring
    /// the public `(a, b, c)` matrices. This is the bridge that lets a
    /// *circuit* — in particular the IVC step verifier — be folded by the
    /// same HyperNova machinery as VM traces, completing the recursive
    /// fixed point: the circuit that verifies a fold is itself a foldable
    /// instance.
    #[must_use]
    pub fn from_circuit_r1cs(r1cs: blacknet_crypto::r1cs::R1CS<F>) -> Self {
        let (a, b, c): (
            blacknet_crypto::matrix::SparseMatrix<F>,
            blacknet_crypto::matrix::SparseMatrix<F>,
            blacknet_crypto::matrix::SparseMatrix<F>,
        ) = r1cs.into();
        Self::new(a, b, c)
    }

    /// Builds an R1CS shape directly from quadratic constraint rows. Kept
    /// for callers that assemble a relation without a `CircuitBuilder`.
    #[must_use]
    pub fn from_quadratic_rows(
        rows: &[(Vec<(usize, F)>, Vec<(usize, F)>, Vec<(usize, F)>)],
        columns: usize,
    ) -> Self {
        use blacknet_crypto::matrix::SparseMatrixBuilder;
        let mut a = SparseMatrixBuilder::<F>::new(rows.len(), columns);
        let mut b = SparseMatrixBuilder::<F>::new(rows.len(), columns);
        let mut c = SparseMatrixBuilder::<F>::new(rows.len(), columns);
        for (ar, br, cr) in rows {
            for &(col, v) in ar {
                a.column(col, v);
            }
            for &(col, v) in br {
                b.column(col, v);
            }
            for &(col, v) in cr {
                c.column(col, v);
            }
            a.row();
            b.row();
            c.row();
        }
        Self::new(a.build(), b.build(), c.build())
    }
}
