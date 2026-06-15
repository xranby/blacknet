/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Validates the matrix-ring operator-norm and commutator bounds against
//! ground truth AND against rat4's own `MatrixRing` / `Commutator`, so the
//! analysis is provably an extension of the pre-positioned primitive rather
//! than a parallel reimplementation.

use blacknet_crypto::algebra::{BalancedRepresentative, Commutator, MatrixRing};
use blacknet_crypto::operatornorm::{
    MatrixRingElement, commutator, commutator_norm_bound, gershgorin_lambda_max, gram,
    matrix_multiplication_norm_bound, matrix_ring_mul,
};
use blacknet_crypto::pervushin::PervushinField as Z;

// 2x2 matrix ring over the scalar field (degree n = 1: each block is 1x1),
// matching rat4's own matrixring test instantiation.
type R = MatrixRing<Z, 2, 4>;

fn elem_deg1(vals: [i64; 4]) -> MatrixRingElement {
    MatrixRingElement::new(2, 1, vals.iter().map(|&v| vec![v]).collect())
}

fn ratring(vals: [i64; 4]) -> R {
    R::new(vals.map(|v| Z::from(v as i32)))
}

// Power-iteration ground truth for lambda_max of a symmetric integer matrix.
fn power_lambda_max(g: &[Vec<i64>]) -> f64 {
    let n = g.len();
    let mut v = vec![1.0f64; n];
    let mut lambda = 0.0;
    for _ in 0..3000 {
        let mut w = vec![0.0f64; n];
        for i in 0..n {
            for j in 0..n {
                w[i] += g[i][j] as f64 * v[j];
            }
        }
        let nrm = w.iter().map(|x| x * x).sum::<f64>().sqrt();
        if nrm == 0.0 {
            return 0.0;
        }
        for x in &mut w {
            *x /= nrm;
        }
        lambda = nrm;
        v = w;
    }
    lambda
}

#[test]
fn my_matrix_mul_matches_rat4_matrixring() {
    // The analysis multiplication must agree with rat4's MatrixRing::mul.
    let a = [1i64, 2, 3, 4];
    let b = [5i64, 6, 7, 8];
    let prod = matrix_ring_mul(&elem_deg1(a), &elem_deg1(b));
    let rat = ratring(a) * ratring(b);
    for i in 0..4 {
        assert_eq!(
            prod.entries[i][0],
            rat[i].balanced(),
            "entry {i}: analysis product must equal MatrixRing::mul"
        );
    }
}

#[test]
fn my_commutator_matches_rat4_commutator() {
    // The analysis commutator must agree with MatrixRing::commutator.
    let a = [1i64, 2, 0, 3];
    let b = [0i64, 1, 4, 2];
    let c = commutator(&elem_deg1(a), &elem_deg1(b));
    let rat = ratring(a).commutator(ratring(b));
    for i in 0..4 {
        assert_eq!(
            c.entries[i][0],
            rat[i].balanced(),
            "entry {i}: analysis [A,B] must equal MatrixRing::commutator"
        );
    }
}

#[test]
fn commuting_challenges_have_zero_commutator_norm() {
    // A and a polynomial in A commute, so [A, A^2] = 0 and its norm is 0.
    let a = elem_deg1([2, 1, 0, 3]);
    let a2 = matrix_ring_mul(&a, &a);
    assert_eq!(commutator_norm_bound(&a, &a2), 0, "[A, A^2] must vanish");
    // The identity commutes with everything.
    let id = elem_deg1([1, 0, 0, 1]);
    let b = elem_deg1([5, 7, 2, 9]);
    assert_eq!(commutator_norm_bound(&id, &b), 0, "[I, B] must vanish");
}

#[test]
fn noncommuting_challenges_have_positive_commutator_norm() {
    // Two generic matrices do not commute; the certified slack is positive.
    let a = elem_deg1([1, 2, 0, 1]);
    let b = elem_deg1([1, 0, 3, 1]);
    assert!(
        commutator_norm_bound(&a, &b) > 0,
        "generic non-commuting challenges have positive reorder slack"
    );
}

#[test]
fn spectral_bound_upper_bounds_truth_degree_one() {
    let a = elem_deg1([3, 1, 2, 4]);
    let g = gram(&a.block_matrix());
    let certified = gershgorin_lambda_max(&g) as f64;
    let truth = power_lambda_max(&g);
    assert!(
        certified >= truth - 1e-6,
        "Gershgorin {certified} must upper-bound true lambda_max {truth}"
    );
}

#[test]
fn spectral_bound_upper_bounds_truth_degree_four() {
    // Degree-4 negacyclic ring entries: each block is a 4x4 skew-circulant,
    // so the lift is 8x8 for a 2x2 matrix ring. The bound must still hold.
    let entries = vec![
        vec![1, 0, -1, 2], // (0,0)
        vec![0, 1, 1, 0],  // (0,1)
        vec![2, -1, 0, 1], // (1,0)
        vec![1, 1, 1, 1],  // (1,1)
    ];
    let a = MatrixRingElement::new(2, 4, entries);
    let m = a.block_matrix();
    assert_eq!(m.len(), 8, "2x2 ring of degree-4 lifts to 8x8");
    let g = gram(&m);
    let certified = gershgorin_lambda_max(&g) as f64;
    let truth = power_lambda_max(&g);
    assert!(
        certified >= truth - 1e-6,
        "bound {certified} >= truth {truth}"
    );
    assert!(matrix_multiplication_norm_bound(&a) > 0);
}

#[test]
fn product_norm_is_submultiplicative() {
    // ||M_{AB}|| <= ||M_A|| * ||M_B|| (operator-norm submultiplicativity),
    // the property that makes sequential folding norm growth bounded.
    let a = elem_deg1([2, 1, 1, 2]);
    let b = elem_deg1([1, 3, 0, 1]);
    let na = matrix_multiplication_norm_bound(&a);
    let nb = matrix_multiplication_norm_bound(&b);
    let nab = matrix_multiplication_norm_bound(&matrix_ring_mul(&a, &b));
    assert!(
        nab <= na * nb + 1,
        "submultiplicative: ||AB||={nab} <= ||A||*||B||={}",
        na * nb
    );
}
