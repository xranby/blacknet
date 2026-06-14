/*
 * Copyright (c) 2024-2026 Pavel Vasin
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

use crate::algebra::{AlgebraOps, IntegerRing, PolynomialRing, Tensor};
use crate::integer::Integer;
use crate::matrix::{DenseMatrix, DenseVector, IdentityMatrix};
use alloc::vec;
use alloc::vec::Vec;
use core::iter::zip;

// https://eprint.iacr.org/2018/946

fn decompose_impl<Z: IntegerRing, R: PolynomialRing<Z>>(
    polynomial: &R,
    radix_mask: <Z::Int as Integer>::Limb,
    radix_shift: <Z::Int as Integer>::Limb,
    pieces: &mut [R],
) {
    for (i, coefficient) in polynomial.borrow().iter().enumerate() {
        let mut representative = coefficient.canonical();
        for piece in pieces.iter_mut() {
            piece[i] = Z::with_limb(representative & radix_mask);
            representative >>= radix_shift;
        }
    }
}

fn decompose_slice<Z: IntegerRing, R: PolynomialRing<Z> + Clone>(
    slice: &[R],
    radix_mask: <Z::Int as Integer>::Limb,
    radix_shift: <Z::Int as Integer>::Limb,
    digits: usize,
) -> Vec<R> {
    let mut pieces = vec![R::ZERO; slice.len() * digits];
    for (polynomial, pieces) in zip(slice.iter(), pieces.chunks_exact_mut(digits)) {
        decompose_impl(polynomial, radix_mask, radix_shift, pieces)
    }
    pieces
}

/// Decomposes a vector of ring *scalars* (not polynomials) into `digits`
/// base-radix limbs, low limb first, laid out `digits`-contiguously per
/// scalar: `[s0_d0, s0_d1, …, s1_d0, …]`. This is the gadget decomposition
/// specialized to degree-0 elements — the form the lattice witness
/// commitment uses, where each field element splits into base-`2^shift`
/// digits bounded by `radix_mask`. Sharing it here keeps one decomposition
/// kernel rather than a bespoke copy in the commitment.
pub fn decompose_scalars<Z: IntegerRing>(
    scalars: &DenseVector<Z>,
    radix_mask: <Z::Int as Integer>::Limb,
    radix_shift: u32,
    digits: usize,
) -> DenseVector<Z> {
    let mut pieces = Vec::with_capacity(scalars.dimension() * digits);
    for i in 0..scalars.dimension() {
        let mut representative = scalars[i].canonical();
        for _ in 0..digits {
            pieces.push(Z::with_limb(representative & radix_mask));
            representative >>= radix_shift;
        }
    }
    pieces.into()
}

pub fn decompose_polynomial<Z: IntegerRing, R: PolynomialRing<Z> + Clone>(
    polynomial: &R,
    radix_mask: <Z::Int as Integer>::Limb,
    radix_shift: <Z::Int as Integer>::Limb,
    digits: usize,
) -> DenseVector<R> {
    let mut pieces = vec![R::ZERO; digits];
    decompose_impl(polynomial, radix_mask, radix_shift, &mut pieces);
    pieces.into()
}

pub fn decompose_vector<Z: IntegerRing, R: PolynomialRing<Z> + Clone>(
    vector: &DenseVector<R>,
    radix_mask: <Z::Int as Integer>::Limb,
    radix_shift: <Z::Int as Integer>::Limb,
    digits: usize,
) -> DenseVector<R> {
    let pieces = decompose_slice(vector, radix_mask, radix_shift, digits);
    pieces.into()
}

pub fn decompose_matrix<Z: IntegerRing, R: PolynomialRing<Z> + Clone>(
    matrix: &DenseMatrix<R>,
    radix_mask: <Z::Int as Integer>::Limb,
    radix_shift: <Z::Int as Integer>::Limb,
    digits: usize,
) -> DenseMatrix<R> {
    let pieces = decompose_slice(matrix.as_ref(), radix_mask, radix_shift, digits);
    DenseMatrix::new(matrix.rows(), matrix.columns() * digits, pieces)
}

pub fn matrix<Z: IntegerRing + Clone, R: PolynomialRing<Z> + Clone>(
    radix: &Z,
    m: usize,
    n: usize,
) -> DenseMatrix<R> {
    debug_assert!(n >= 2);
    let mut powers = Vec::<R>::with_capacity(n);
    powers.push(R::ONE);
    powers.push(radix.clone().into());
    let mut power = radix.clone();
    for _ in 2..n {
        power *= radix;
        powers.push(power.clone().into());
    }

    let powers = DenseMatrix::<R>::new(1, n, powers);
    let identity = IdentityMatrix::<R>::new(m);
    identity.tensor(powers)
}

pub fn vector<Z: IntegerRing + Clone, R: PolynomialRing<Z> + Clone>(
    polynomial: R,
    radix: &Z,
    digits: usize,
) -> DenseVector<R>
where
    for<'a> &'a R: AlgebraOps<Z, R>,
{
    let mut powers = Vec::<R>::with_capacity(digits);
    powers.push(polynomial.clone());
    let mut power = radix.clone();
    for _ in 1..digits - 1 {
        powers.push(&polynomial * &power);
        power *= radix;
    }
    powers.push(polynomial * power);
    powers.into()
}
