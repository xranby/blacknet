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

use blacknet_crypto::algebra::IntegerRing;
use blacknet_crypto::latticegadget;
use blacknet_crypto::matrix::{DenseMatrix, DenseVector};

type Z = blacknet_crypto::pervushin::PervushinField;
type R = blacknet_crypto::pervushin::PervushinField2;

#[test]
#[rustfmt::skip]
fn matrix() {
    let a = DenseMatrix::new(2, 8, [
            3, 2, 1, 0,
            4, 2, 1, 0,
            5, 2, 1, 0,
            6, 2, 1, 0,
    ].map(Z::from).map(R::from).into());
    let b = DenseMatrix::new(2, 2, [
            R::from([4295098371, 0].map(Z::new)),
            R::from([4295098372, 0].map(Z::new)),
            R::from([4295098373, 0].map(Z::new)),
            R::from([4295098374, 0].map(Z::new)),
     ].into());
    let g = latticegadget::matrix::<Z, R>(&Z::from(65536), 2, 4);
    assert_eq!(&a * g.transpose(), b);
    let c = latticegadget::decompose_matrix(&b, 65535, 16, 4);
    assert_eq!(c, a);
}

#[test]
fn vector() {
    let a = DenseVector::from([3, 2, 1, 0, 4, 2, 1, 0].map(Z::from).map(R::from));
    let b = DenseVector::from([4295098371, 4295098372].map(Z::new).map(R::from));
    let g = latticegadget::matrix::<Z, R>(&Z::from(65536), 2, 4);
    assert_eq!(&g * &a, b);
    let c = latticegadget::decompose_vector(&b, 65535, 16, 4);
    assert_eq!(c, a);
}

#[test]
fn polynomial() {
    let a = R::from([4444, 7789].map(Z::from));
    let b = R::from([34010, -59023].map(Z::from));
    let d = latticegadget::decompose_polynomial(&a, 65535, 16, 4);
    let p = latticegadget::vector::<Z, R>(b, &Z::from(65536), 4);
    assert_eq!(d.dot(&p), a * b);
}

#[test]
fn scalar_decomposition_round_trips() {
    // Base-2^16 digit decomposition of scalar field elements: the form the
    // lattice witness commitment relies on. Decompose, then recompose by the
    // gadget powers, and check we recover the originals.
    let radix_mask = (1i64 << 16) - 1;
    let v: DenseVector<Z> = [
        Z::from(0),
        Z::from(1),
        Z::from(65535),
        Z::from(65536),
        Z::from(123456789),
    ]
    .into_iter()
    .collect();
    let digits = 4;
    let d = latticegadget::decompose_scalars(&v, radix_mask, 16, digits);
    assert_eq!(d.dimension(), v.dimension() * digits);

    // Each scalar's digits are contiguous, low limb first; recompose.
    for i in 0..v.dimension() {
        let mut acc = Z::from(0);
        for k in (0..digits).rev() {
            acc = acc * Z::from(65536) + d[i * digits + k];
        }
        assert_eq!(acc, v[i], "scalar {i} round-trips through its digits");
    }
}

#[test]
fn scalar_digits_are_bounded() {
    // Every digit is < 2^16: the norm bound the commitment depends on.
    let radix_mask = (1i64 << 16) - 1;
    let v: DenseVector<Z> = (0..16).map(|i| Z::from(i * 99991)).collect();
    let d = latticegadget::decompose_scalars(&v, radix_mask, 16, 4);
    for i in 0..d.dimension() {
        assert!(d[i].canonical() < (1i64 << 16), "digit {i} within 2^16");
        assert!(d[i].canonical() >= 0);
    }
}
