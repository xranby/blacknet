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

//! Ajtai commitments to folding witnesses.
//!
//! The Ajtai map `d ↦ A·d` is binding only for low-norm `d`, but folding
//! takes linear combinations that grow norms — the central tension of
//! lattice folding (LatticeFold, eprint 2024/257). The resolution here:
//!
//! 1. Witnesses live in the *digit domain*: `z = G·d` where `d` is the
//!    base-2¹⁶ decomposition and `G` the gadget recomposition, which is
//!    linear. Constraint satisfaction is checked on `G·d`.
//! 2. Folding is linear in `d`, so commitments fold homomorphically:
//!    `A·(d₁ + r·d₂) = A·d₁ + r·A·d₂`.
//! 3. Challenges are squeezed from a small exceptional set so the norm of
//!    the folded digits grows by `1 + r` per fold. The accumulated norm
//!    bound travels with the instance and is enforced at opening time by
//!    the verifier: above [`MAX_NORM`] the commitment is no longer binding
//!    and verification fails closed.
//!
//! The setup is transparent: the SIS matrix is squeezed from the Poseidon2
//! duplex seeded with a domain tag and the dimensions.
//!
//! Parameters (`ROWS`, digit base, challenge set size, [`MAX_NORM`]) are
//! placeholders pending the parameter analysis in `crypto/rings.sage`.

use blacknet_crypto::algebra::IntegerRing;
use blacknet_crypto::matrix::{DenseMatrix, DenseVector};
use blacknet_crypto::pervushin::PervushinField;
use blacknet_crypto::random::UniformGenerator;
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};

pub type F = PervushinField;

/// SIS rows of the commitment matrix at the consensus security level:
/// 128-bit classical per `snark/params.py` with `MAX_NORM = 2^44`. Tests
/// and benchmarks may instantiate [`CommitmentKey::setup`] with fewer rows;
/// consensus code must use this constant. The module-SIS instantiation
/// (`AjtaiCommitment::msis`) will reduce this by the ring degree and is the
/// planned production path.
pub const SECURE_ROWS: usize = 2048;
/// Bits per digit of the gadget decomposition.
pub const DIGIT_BITS: u32 = 16;
/// Digits per field element: ceil(61 / 16).
pub const DIGITS: usize = 4;
/// Bits of a folding challenge (exceptional set size 2^16).
pub const CHALLENGE_BITS: u32 = 16;

/// Soundness repetitions of the folding challenge. A 16-bit challenge gives
/// 2⁻¹⁶ soundness error per fold; for a chain of up to 2¹² folds, reaching
/// 128-bit soundness needs `16·r ≥ 128 + 12`, i.e. `r ≥ 9` (derived in
/// `snark/params.py::shipping_parameters`). Protocols that fold deep chains
/// squeeze and check the fold relation `CHALLENGE_REPETITIONS` times with
/// independent challenges; a single fold instance (depth 1) may use one.
pub const CHALLENGE_REPETITIONS: usize = 9;
/// Maximum infinity norm of an opening for the commitment to stay binding
/// at [`SECURE_ROWS`]: 128-bit classical per `snark/params.py`. Norm growth
/// per multifold is additive (`b + r·2^16 <= b + 2^32`), so this budget
/// supports about 2^12 sequential folds.
pub const MAX_NORM: u128 = 1 << 44;

const SETUP_TAG: u32 = 0x424c_4b43; // "BLKC"

/// Transparent commitment key for witnesses of `elements` field elements.
pub struct CommitmentKey {
    a: DenseMatrix<F>,
    elements: usize,
}

impl CommitmentKey {
    /// `rows` is the SIS dimension: [`SECURE_ROWS`] for consensus use,
    /// fewer only in tests and benchmarks. Both `rows` and the columns are
    /// bound into the transparent setup.
    #[must_use]
    pub fn setup(elements: usize, rows: usize) -> Self {
        let columns = elements * DIGITS;
        let mut duplex = DuplexPoseidon2Pervushin::default();
        duplex.absorb(F::from(SETUP_TAG));
        duplex.absorb(F::from(rows as u32));
        duplex.absorb(F::from(columns as u32));
        let a = DenseMatrix::new(
            rows,
            columns,
            (0..rows * columns).map(|_| duplex.generate()).collect(),
        );
        Self { a, elements }
    }

    #[must_use]
    pub const fn elements(&self) -> usize {
        self.elements
    }

    /// Commits to a digit vector. Homomorphic: linear in `d`.
    #[must_use]
    pub fn commit(&self, d: &DenseVector<F>) -> DenseVector<F> {
        &self.a * d
    }

    /// Opening check: recomputation plus the binding norm bound. The norm
    /// bound is enforced here, on the verifier path, never trusted from the
    /// prover: exceeding it breaks soundness silently, not completeness.
    #[must_use]
    pub fn open(&self, commitment: &DenseVector<F>, d: &DenseVector<F>, norm_bound: u128) -> bool {
        norm_bound <= MAX_NORM && infinity_norm(d) <= norm_bound && self.commit(d) == *commitment
    }
}

/// Decomposes field elements into base-2¹⁶ digits. `‖d‖∞ < 2¹⁶`.
#[must_use]
pub fn decompose(z: &DenseVector<F>) -> DenseVector<F> {
    let mut d = Vec::with_capacity(z.dimension() * DIGITS);
    for i in 0..z.dimension() {
        let mut n = z[i].canonical() as u64;
        for _ in 0..DIGITS {
            d.push(F::from((n & ((1 << DIGIT_BITS) - 1)) as u32));
            n >>= DIGIT_BITS;
        }
    }
    DenseVector::from(d)
}

/// Recomposes digits: the linear gadget map `G·d`.
#[must_use]
pub fn recompose(d: &DenseVector<F>) -> DenseVector<F> {
    let elements = d.dimension() / DIGITS;
    (0..elements)
        .map(|i| {
            (0..DIGITS).fold(F::from(0), |acc, k| {
                acc + <F as IntegerRing>::new(1i64 << (DIGIT_BITS * k as u32)) * d[i * DIGITS + k]
            })
        })
        .collect()
}

/// The infinity norm of a digit vector over canonical representatives,
/// folding negatives to their absolute distance from zero.
#[must_use]
pub fn infinity_norm(d: &DenseVector<F>) -> u128 {
    const MODULUS: i64 = (1 << 61) - 1;
    (0..d.dimension())
        .map(|i| {
            let c = d[i].canonical();
            u128::from(c.unsigned_abs().min((MODULUS - c).unsigned_abs()))
        })
        .max()
        .unwrap_or(0)
}

/// Squeezes a folding challenge from the small exceptional set
/// `[0, 2^CHALLENGE_BITS)`, returning it with its norm.
pub fn squeeze_challenge<D: Duplexer<Msg = F>>(duplex: &mut D) -> (F, u128) {
    let e: F = duplex.squeeze();
    let r = (e.canonical() as u64) & ((1 << CHALLENGE_BITS) - 1);
    (F::from(r as u32), u128::from(r))
}
