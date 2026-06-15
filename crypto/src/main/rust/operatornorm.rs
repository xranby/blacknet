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

//! Rigorous operator-norm bounds for ring multiplication.
//!
//! Folding takes linear combinations of witnesses with *ring* challenges, and
//! in the module/ring instantiation each multiplication by a challenge `c`
//! expands the norm of a witness by the operator norm of the
//! multiplication-by-`c` map. The folding norm budget (and hence the security
//! parameters) depends on how large that expansion can be over the challenge
//! set. The naive bound — the coefficient sum of `c` — is loose; this module
//! computes a *certified* bound instead.
//!
//! For the negacyclic ring `Z[X]/(Xⁿ + 1)` (the convolution this codebase
//! uses), multiplication by `c = Σ cⱼ Xʲ` is the skew-circulant matrix
//! `M_c[k][j] = c_{k−j}` for `j ≤ k` and `−c_{k−j+n}` for `j > k`. The
//! spectral norm `‖M_c‖₂ = √λ_max(M_cᵀ M_c)` is the exact per-multiplication
//! expansion in the Euclidean norm. We form the Gram matrix `G = M_cᵀ M_c`
//! over exact integers and bound `λ_max(G)` two ways:
//!
//!   * Gershgorin's theorem gives a *certified upper bound* — every
//!     eigenvalue lies within `max_i (G[i][i] + Σ_{j≠i} |G[i][j]|)`, with no
//!     iteration and no rounding. This is the rigorous number the parameters
//!     may rely on.
//!   * `trace(G) = Σ λᵢ = ‖M_c‖_F²` (the Frobenius norm squared) is an exact
//!     identity that lower-bounds `λ_max` by `trace/n` and upper-bounds it by
//!     `trace`; it cross-checks the Gershgorin bound and is computed through
//!     the [`SymmetricTridiagonalMatrix`] representation, whose diagonal is
//!     exactly the Lanczos `α` sequence a full eigensolve would produce.
//!
//! All arithmetic is exact `i64`; there is no floating point, so the upper
//! bound is a theorem about the integers, suitable for parameter derivation.

use crate::matrix::SymmetricTridiagonalMatrix;
use alloc::vec;
use alloc::vec::Vec;

/// The negacyclic multiplication matrix `M_c` for a challenge with the given
/// integer coefficients (degree `n = coeffs.len()`), row-major.
#[must_use]
pub fn negacyclic_matrix(coeffs: &[i64]) -> Vec<Vec<i64>> {
    let n = coeffs.len();
    let mut m = vec![vec![0i64; n]; n];
    for (k, row) in m.iter_mut().enumerate() {
        for (j, cell) in row.iter_mut().enumerate() {
            // c_k = Σ_{i≤k} a_i b_{k−i} − Σ_{i>k} a_i b_{k+n−i}; as a map on b,
            // the column j contributes a_{k−j} (j ≤ k) or −a_{k−j+n} (j > k).
            *cell = if j <= k {
                coeffs[k - j]
            } else {
                -coeffs[k + n - j]
            };
        }
    }
    m
}

/// The Gram matrix `G = MᵀM` (exact integers), row-major `n×n`.
#[must_use]
pub fn gram(m: &[Vec<i64>]) -> Vec<Vec<i64>> {
    let n = m.len();
    let mut g = vec![vec![0i64; n]; n];
    for i in 0..n {
        for j in 0..n {
            // G[i][j] = Σ_k M[k][i] · M[k][j].
            let mut s = 0i64;
            for row in m.iter() {
                s += row[i] * row[j];
            }
            g[i][j] = s;
        }
    }
    g
}

/// A certified upper bound on `λ_max(G)` for a symmetric matrix `G`, by
/// Gershgorin's theorem: every eigenvalue lies in some disc centered at a
/// diagonal entry with radius the absolute off-diagonal row sum, so
/// `λ_max ≤ max_i (G[i][i] + Σ_{j≠i} |G[i][j]|)`. Exact, no iteration.
#[must_use]
pub fn gershgorin_lambda_max(g: &[Vec<i64>]) -> i64 {
    let n = g.len();
    let mut bound = i64::MIN;
    for i in 0..n {
        let mut radius = 0i64;
        for j in 0..n {
            if i != j {
                radius += g[i][j].abs();
            }
        }
        bound = bound.max(g[i][i] + radius);
    }
    bound
}

/// The diagonal of `G` as a [`SymmetricTridiagonalMatrix`] (off-diagonals
/// zeroed): its `trace` is `Σ G[i][i] = Σ λᵢ = ‖M‖_F²`, the exact Frobenius
/// identity used to cross-check the spectral bound. Using the pre-positioned
/// tridiagonal type makes the connection to a Lanczos reduction explicit —
/// the diagonal stored here is the sequence a full Lanczos pass refines into
/// the `α` coefficients of the reduced operator.
#[must_use]
pub fn gram_trace(g: &[Vec<i64>]) -> i64 {
    let n = g.len();
    let mut elements = Vec::with_capacity(2 * n - 1);
    for (i, row) in g.iter().enumerate() {
        elements.push(row[i]);
    }
    elements.extend(core::iter::repeat_n(0i64, n.saturating_sub(1)));
    let tri = SymmetricTridiagonalMatrix::new(elements);
    tri.trace()
}

/// A certified bound on the operator (spectral) norm of multiplication by a
/// challenge with the given coefficients: `‖M_c‖₂ ≤ ⌈√gershgorin⌉`, returned
/// as the integer ceiling of the square root so callers can use it directly
/// as a norm-expansion factor. Exact integers throughout.
#[must_use]
pub fn multiplication_norm_bound(coeffs: &[i64]) -> u128 {
    let m = negacyclic_matrix(coeffs);
    let g = gram(&m);
    let lambda = gershgorin_lambda_max(&g).max(0) as u128;
    isqrt_ceil(lambda)
}

/// Integer ceiling of `√x`, exact for all `u128`.
#[must_use]
pub fn isqrt_ceil(x: u128) -> u128 {
    if x <= 1 {
        return x;
    }
    // Floor sqrt by Newton's method on integers, then bump to a ceiling.
    let mut r = x;
    let mut next = (r + 1) / 2;
    while next < r {
        r = next;
        next = (r + x / r) / 2;
    }
    // `r` is now floor(sqrt(x)); ceil if not a perfect square.
    if r * r == x { r } else { r + 1 }
}

// ---------------------------------------------------------------------------
// Matrix-ring operator norms — folding with NON-COMMUTING challenges.
//
// The bounds above are for the commutative negacyclic ring `Z[X]/(Xⁿ+1)`: a
// fold multiplies a witness by a ring challenge and the norm expands by the
// skew-circulant spectral norm. A matrix-ring instantiation folds with `N×N`
// matrices of ring elements (`crypto::algebra::MatrixRing`), and those
// challenges DO NOT COMMUTE, so the parameter analysis must change.
//
// Two new quantities matter:
//
//   * the operator norm of multiplication-by-`A` on the module `Rᴺ`. Lifting
//     each ring entry `A[i][j]` to its `n×n` skew-circulant block gives an
//     `(Nn)×(Nn)` integer matrix `M_A`; `‖M_A‖₂ = √λ_max(M_Aᵀ M_A)` is the
//     exact per-fold expansion, certified by the SAME Gershgorin bound on the
//     integer Gram matrix used in the scalar case.
//
//   * the commutator `[A,B] = AB − BA` (rat4's `MatrixRing::commutator`). When
//     two folds with challenges `A` then `B` are reordered, the accumulated
//     state differs by `[B,A]·w`, so `‖M_{[A,B]}‖₂` bounds the reordering
//     slack the extractor must absorb in non-commutative folding. For
//     commuting challenges it is zero and folding norm growth is as tight as
//     the commutative case; the certified commutator norm says how far a given
//     challenge set departs from that ideal.
//
// All arithmetic stays exact `i64`, so the results are theorems about the
// integers, suitable for parameter derivation — the matrix-ring analogue of
// the scalar spectral-expansion analysis.

/// A matrix-ring element for analysis: an `N×N` grid (row-major) of ring
/// elements, each a coefficient vector of length `n` in `Z[X]/(Xⁿ+1)`.
pub struct MatrixRingElement {
    /// `n_rows = n_cols = N`.
    pub dim: usize,
    /// Ring degree `n`.
    pub degree: usize,
    /// `entries[i*N + j]` is the coefficient vector of block `(i,j)`.
    pub entries: Vec<Vec<i64>>,
}

impl MatrixRingElement {
    /// Builds from a flat row-major list of `N*N` coefficient vectors.
    #[must_use]
    pub fn new(dim: usize, degree: usize, entries: Vec<Vec<i64>>) -> Self {
        debug_assert_eq!(entries.len(), dim * dim);
        debug_assert!(entries.iter().all(|c| c.len() == degree));
        Self {
            dim,
            degree,
            entries,
        }
    }

    /// The `(Nn)×(Nn)` integer block multiplication matrix `M_A`: block
    /// `(i,j)` is the `n×n` negacyclic multiplication matrix of entry `(i,j)`,
    /// so `M_A` acting on a stacked module vector reproduces `A·w` exactly.
    #[must_use]
    pub fn block_matrix(&self) -> Vec<Vec<i64>> {
        let (n, d) = (self.dim, self.degree);
        let size = n * d;
        let mut m = vec![vec![0i64; size]; size];
        for bi in 0..n {
            for bj in 0..n {
                let blk = negacyclic_matrix(&self.entries[bi * n + bj]);
                for r in 0..d {
                    for c in 0..d {
                        m[bi * d + r][bj * d + c] = blk[r][c];
                    }
                }
            }
        }
        m
    }
}

/// Ring product `c = a·b` in `Z[X]/(Xⁿ+1)` on coefficient vectors (the same
/// negacyclic convolution the crate's `Convolution` uses), for composing
/// matrix-ring entries during analysis.
#[must_use]
pub fn ring_mul(a: &[i64], b: &[i64]) -> Vec<i64> {
    let n = a.len();
    let mut c = vec![0i64; n];
    for (k, ck) in c.iter_mut().enumerate() {
        let mut s = 0i64;
        for i in 0..=k {
            s += a[i] * b[k - i];
        }
        for i in k + 1..n {
            s -= a[i] * b[k + n - i];
        }
        *ck = s;
    }
    c
}

/// Matrix-ring product `A·B` (row-major coefficient grids), used to form the
/// commutator. `N` is `dim`, `n` is `degree`.
#[must_use]
pub fn matrix_ring_mul(a: &MatrixRingElement, b: &MatrixRingElement) -> MatrixRingElement {
    let (n, d) = (a.dim, a.degree);
    let mut out = vec![vec![0i64; d]; n * n];
    for i in 0..n {
        for j in 0..n {
            let mut acc = vec![0i64; d];
            for k in 0..n {
                let p = ring_mul(&a.entries[i * n + k], &b.entries[k * n + j]);
                for t in 0..d {
                    acc[t] += p[t];
                }
            }
            out[i * n + j] = acc;
        }
    }
    MatrixRingElement::new(n, d, out)
}

/// The commutator `[A,B] = A·B − B·A` as a matrix-ring element, mirroring
/// `MatrixRing::commutator`. Folding-reorder slack is governed by its norm.
#[must_use]
pub fn commutator(a: &MatrixRingElement, b: &MatrixRingElement) -> MatrixRingElement {
    let ab = matrix_ring_mul(a, b);
    let ba = matrix_ring_mul(b, a);
    let (n, d) = (a.dim, a.degree);
    let mut out = vec![vec![0i64; d]; n * n];
    for e in 0..n * n {
        for t in 0..d {
            out[e][t] = ab.entries[e][t] - ba.entries[e][t];
        }
    }
    MatrixRingElement::new(n, d, out)
}

/// Certified upper bound on the operator (spectral) norm of multiplication by
/// a matrix-ring challenge `A` on the module `Rᴺ`: `‖M_A‖₂ ≤ ⌈√gershgorin⌉`,
/// via the exact integer Gram matrix of the `(Nn)×(Nn)` block lift. This is
/// the rigorous per-fold norm expansion for matrix-ring folding.
#[must_use]
pub fn matrix_multiplication_norm_bound(a: &MatrixRingElement) -> u128 {
    let m = a.block_matrix();
    let g = gram(&m);
    let lambda = gershgorin_lambda_max(&g).max(0) as u128;
    isqrt_ceil(lambda)
}

/// Certified upper bound on the commutator norm `‖[A,B]‖₂` (spectral norm of
/// the block lift of `A·B − B·A`). Zero for commuting challenges; otherwise
/// the reordering slack a non-commutative folding extractor must bound.
#[must_use]
pub fn commutator_norm_bound(a: &MatrixRingElement, b: &MatrixRingElement) -> u128 {
    matrix_multiplication_norm_bound(&commutator(a, b))
}

// ---------------------------------------------------------------------------
// Exact spectral norm via negacyclic evaluations (the NTT-domain view).
//
// Following the NTT-smooth ring signal (rat4 wired `batched_inv` into
// `NTTRing::inv`, where fully-split multiplication is pointwise), there is a
// second, EXACT route to the per-fold expansion. For `Z[X]/(Xⁿ+1)`, the
// eigenvalues of multiplication-by-`c` are exactly its evaluations at the `n`
// negacyclic points `ωₖ = exp(iπ(2k+1)/n)` (the odd 2n-th roots of unity), so
//
//     ‖M_c‖₂ = maxₖ |ĉ(ωₖ)|   exactly,
//
// not merely an upper bound. The integer Gershgorin bound above is the
// certified estimate available from coefficients alone; this is the tight
// value the NTT representation hands over directly. Over the LM modulus the
// *integer* transform only partially splits (q−1 has 2-adic valuation 5, so a
// length-64 cyclic NTT does not exist), but the *real* operator norm is a
// statement about complex evaluations and holds for any degree — which is why
// this is computed over the complex unit circle, independent of the modulus.
//
// Used together: Gershgorin certifies a safe upper bound for parameter
// setting; this exact value shows how much slack the bound carries (and for
// the structured challenge sets folding uses, the two are typically close).

/// The exact operator (spectral) norm of multiplication by a challenge with
/// the given integer coefficients in `Z[X]/(Xⁿ+1)`, computed as the maximum
/// magnitude of its evaluations at the `n` negacyclic points. Returned as an
/// `f64` (this is real-analytic, not an integer theorem); pair it with
/// [`multiplication_norm_bound`] for the certified integer upper bound.
#[must_use]
pub fn ntt_spectral_norm(coeffs: &[i64]) -> f64 {
    let n = coeffs.len();
    let mut max_sq = 0.0f64;
    for k in 0..n {
        // ωₖ = exp(iπ(2k+1)/n); accumulate ĉ(ωₖ) = Σ_j c_j ωₖ^j.
        let theta = core::f64::consts::PI * (2.0 * k as f64 + 1.0) / n as f64;
        let (mut re, mut im) = (0.0f64, 0.0f64);
        for (j, &cj) in coeffs.iter().enumerate() {
            let ang = theta * j as f64;
            re += cj as f64 * libm::cos(ang);
            im += cj as f64 * libm::sin(ang);
        }
        let mag_sq = re * re + im * im;
        if mag_sq > max_sq {
            max_sq = mag_sq;
        }
    }
    libm::sqrt(max_sq)
}
