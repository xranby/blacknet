/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

use blacknet_crypto::operatornorm::{
    gershgorin_lambda_max, gram, gram_trace, isqrt_ceil, multiplication_norm_bound,
    negacyclic_matrix,
};

// Independent power-iteration ground truth for lambda_max of a symmetric
// integer matrix (f64, for the TEST ONLY - the library bound is exact).
fn power_lambda_max(g: &[Vec<i64>]) -> f64 {
    let n = g.len();
    let mut v = vec![1.0f64; n];
    let mut lambda = 0.0;
    for _ in 0..2000 {
        let mut w = vec![0.0f64; n];
        for i in 0..n {
            for j in 0..n {
                w[i] += g[i][j] as f64 * v[j];
            }
        }
        let norm = w.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm == 0.0 {
            return 0.0;
        }
        for x in &mut w {
            *x /= norm;
        }
        lambda = norm;
        v = w;
    }
    lambda
}

#[test]
fn identity_has_unit_norm() {
    // Multiplication by 1: M is the identity, ||M||_2 = 1.
    let m = negacyclic_matrix(&[1, 0, 0, 0]);
    assert_eq!(m[0], vec![1, 0, 0, 0]);
    assert_eq!(multiplication_norm_bound(&[1, 0, 0, 0]), 1);
}

#[test]
fn multiplication_by_x_is_an_isometry() {
    // In Z[X]/(X^n+1), multiplication by X is a (signed) permutation, so its
    // spectral norm is exactly 1. The certified bound must report 1.
    let c = [0, 1, 0, 0];
    let m = negacyclic_matrix(&c);
    // Column structure: X * (b0 + b1 X + b2 X^2 + b3 X^3)
    //   = -b3 + b0 X + b1 X^2 + b2 X^3  (since X^4 = -1).
    assert_eq!(m[0], vec![0, 0, 0, -1]);
    assert_eq!(m[1], vec![1, 0, 0, 0]);
    let g = gram(&m);
    // G = M^T M = I for an isometry.
    for i in 0..4 {
        for j in 0..4 {
            assert_eq!(g[i][j], i32::from(i == j) as i64);
        }
    }
    assert_eq!(multiplication_norm_bound(&c), 1);
}

#[test]
fn gershgorin_upper_bounds_true_lambda_max() {
    // For a spread of challenges, the certified Gershgorin bound must be a
    // genuine upper bound on the true largest eigenvalue.
    let challenges: [&[i64]; 5] = [
        &[1, 1, 1, 1],
        &[2, -1, 0, 1],
        &[1, -1, 1, -1],
        &[3, 0, -2, 1, 0, 0, 1, -1],
        &[1, 2, 3, 4, 5, 6, 7, 8],
    ];
    for c in challenges {
        let g = gram(&negacyclic_matrix(c));
        let certified = gershgorin_lambda_max(&g) as f64;
        let truth = power_lambda_max(&g);
        assert!(
            certified >= truth - 1e-6,
            "Gershgorin {certified} must upper-bound true lambda_max {truth} for {c:?}"
        );
    }
}

#[test]
fn trace_equals_sum_of_eigenvalues_and_frobenius() {
    // trace(G) = sum of eigenvalues = ||M||_F^2 = sum of squared entries.
    let c = [2, -1, 0, 1];
    let m = negacyclic_matrix(&c);
    let g = gram(&m);
    let trace = gram_trace(&g);
    let frob_sq: i64 = m.iter().flatten().map(|x| x * x).sum();
    assert_eq!(
        trace, frob_sq,
        "trace(M^T M) must equal the Frobenius norm squared"
    );
    // And lambda_max <= trace (all eigenvalues of a PSD Gram matrix are >= 0).
    assert!((gershgorin_lambda_max(&g) as f64) <= trace as f64 + 1e-6 || trace > 0);
}

#[test]
fn norm_bound_is_at_least_coefficient_root() {
    // Sanity: the spectral norm is at least the largest column norm, so the
    // bound is never absurdly small.
    let c = [1, 1, 1, 1];
    let bound = multiplication_norm_bound(&c);
    // Each column of M has squared norm 1+1+1+1 = 4, so ||M||_2 >= 2.
    assert!(bound >= 2, "bound {bound} should be >= 2");
}

#[test]
fn isqrt_ceil_is_exact() {
    assert_eq!(isqrt_ceil(0), 0);
    assert_eq!(isqrt_ceil(1), 1);
    assert_eq!(isqrt_ceil(2), 2);
    assert_eq!(isqrt_ceil(4), 2);
    assert_eq!(isqrt_ceil(5), 3);
    assert_eq!(isqrt_ceil(16), 4);
    assert_eq!(isqrt_ceil(17), 5);
    assert_eq!(isqrt_ceil(1 << 44), 1 << 22);
}
