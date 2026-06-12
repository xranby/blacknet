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

//! Module-SIS witness commitment: the production path flagged by the
//! parameter analysis (`snark/params.py`).
//!
//! Digits are packed coefficient-wise into the negacyclic ring
//! `R = F[X]/(X⁶⁴ + 1)` over the Pervushin field, built from the crypto
//! crate's generic `UnivariateRing` and `Negacyclic` convolution — the same
//! construction as `PervushinField2`, `LMRing64`, and `FermatRing1024`.
//! The commitment is `A·m` over `R` with `SECURE_ROWS / 64 = 32` ring rows:
//! the underlying MSIS dimension is `32 · 64 = 2048`, matching the scalar
//! analysis, with a 64× smaller matrix and NTT-friendly arithmetic.
//!
//! Folding compatibility: packing is coefficient-wise, so it is linear and
//! norm-preserving (`‖pack(d)‖∞ = ‖d‖∞`); a small scalar challenge embeds
//! as a constant polynomial; therefore the digit-domain folding of
//! [`crate::hypernova`] carries over verbatim, including the additive norm
//! accounting against [`MAX_NORM`].

use crate::witnesscommitment::{DIGITS, MAX_NORM, SECURE_ROWS};
use blacknet_crypto::algebra::UnivariateRing;
use blacknet_crypto::convolution::Negacyclic;
use blacknet_crypto::matrix::{DenseMatrix, DenseVector};
use blacknet_crypto::norm::InfinityNorm;
use blacknet_crypto::pervushin::PervushinField;
use blacknet_crypto::random::UniformGenerator;
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};

pub type F = PervushinField;

/// Ring degree.
pub const DEGREE: usize = 64;

/// The negacyclic module ring `F[X]/(X⁶⁴ + 1)`.
pub type PervushinRing64 = UnivariateRing<F, DEGREE, Negacyclic>;

/// Module rows at the consensus security level: same MSIS dimension as the
/// scalar [`SECURE_ROWS`].
pub const MODULE_ROWS: usize = SECURE_ROWS / DEGREE;

const SETUP_TAG: u32 = 0x424c_4b4d; // "BLKM"

/// Packs a digit vector coefficient-wise into ring elements, padding the
/// tail with zeros. Linear and infinity-norm preserving.
#[must_use]
pub fn pack(d: &DenseVector<F>) -> DenseVector<PervushinRing64> {
    let elements = d.dimension().div_ceil(DEGREE);
    (0..elements)
        .map(|i| {
            let mut r = PervushinRing64::default();
            for k in 0..DEGREE {
                let idx = i * DEGREE + k;
                if idx < d.dimension() {
                    r[k] = d[idx];
                }
            }
            r
        })
        .collect()
}

/// Transparent Module-SIS commitment key.
pub struct ModuleCommitmentKey {
    a: DenseMatrix<PervushinRing64>,
}

impl ModuleCommitmentKey {
    /// `rows` is the module dimension: [`MODULE_ROWS`] for consensus use,
    /// fewer only in tests.
    #[must_use]
    pub fn setup(elements: usize, rows: usize) -> Self {
        let columns = (elements * DIGITS).div_ceil(DEGREE);
        let mut duplex = DuplexPoseidon2Pervushin::default();
        duplex.absorb(F::from(SETUP_TAG));
        duplex.absorb(F::from(rows as u32));
        duplex.absorb(F::from(columns as u32));
        let a = DenseMatrix::new(
            rows,
            columns,
            (0..rows * columns)
                .map(|_| {
                    let mut r = PervushinRing64::default();
                    for k in 0..DEGREE {
                        r[k] = duplex.generate();
                    }
                    r
                })
                .collect(),
        );
        Self { a }
    }

    /// Commits to a digit vector. Homomorphic: linear in `d`.
    #[must_use]
    pub fn commit(&self, d: &DenseVector<F>) -> DenseVector<PervushinRing64> {
        &self.a * &pack(d)
    }

    /// Opening check with the binding norm bound enforced fail-closed on
    /// the verifier path.
    #[must_use]
    pub fn open(
        &self,
        commitment: &DenseVector<PervushinRing64>,
        d: &DenseVector<F>,
        norm_bound: u128,
    ) -> bool {
        norm_bound <= MAX_NORM && centered_norm(d) <= norm_bound && self.commit(d) == *commitment
    }
}

/// Infinity norm of digits on centered representatives.
#[must_use]
pub fn centered_norm(d: &DenseVector<F>) -> u128 {
    let packed = pack(d);
    let mut max = 0i64;
    for i in 0..packed.dimension() {
        let n: i64 = packed[i].infinity_norm();
        max = max.max(n);
    }
    max.unsigned_abs().into()
}
