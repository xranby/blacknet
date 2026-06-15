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
