/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! USE CASE for the matrix-ring + commutator + spectral-norm primitives:
//! a folding accumulator with MATRIX challenges.
//!
//! Why a matrix ring instead of a scalar field? The folding soundness error
//! per round is ~ degree / |challenge set|, so a bigger challenge set means
//! fewer repetitions for the same security. A scalar challenge lives in a set
//! of size ~q; an N×N matrix challenge lives in a set of size ~q^(N²) — vastly
//! larger. The catch is non-commutativity: when folds are reordered (parallel
//! folding, tree folding, or an extractor permuting instances) the accumulator
//! changes by commutator terms, and the norm growth is harder to bound.
//!
//! rat4's pre-positioned `Commutator` is the lever that resolves this. If the
//! challenge SCHEDULE is drawn from a *commuting* family — here, powers of a
//! single base matrix `A^0, A^1, A^2, …` — then every pairwise commutator
//! vanishes, so:
//!   - the accumulator is invariant under fold reordering (parallel-safe), and
//!   - norm growth is governed purely by the per-fold spectral expansion, with
//!     no reorder slack, as tight as the scalar case.
//!
//! The challenge family is still size ~q^N (one matrix's worth of free
//! parameters), far larger than the scalar q.
//!
//! This test engineers that accumulator over rat4's `MatrixRing`, and checks
//! the three properties that make the construction work: the commuting
//! schedule is reorder-invariant, a generic (non-commuting) schedule is NOT,
//! and the accumulated norm stays within the certified bound from
//! `operatornorm.rs`.

use blacknet_crypto::algebra::{Commutator, MatrixRing, One};
use blacknet_crypto::norm::InfinityNorm;
use blacknet_crypto::operatornorm::{MatrixRingElement, commutator_norm_bound};
use blacknet_crypto::pervushin::PervushinField as Z;

// 2×2 matrix ring over the scalar field (ring degree 1: one coefficient per
// entry), matching rat4's matrixring test instantiation.
type R = MatrixRing<Z, 2, 4>;

fn z(n: i32) -> Z {
    Z::from(n)
}

fn mat(a: i32, b: i32, c: i32, d: i32) -> R {
    R::new([z(a), z(b), z(c), z(d)])
}

/// Sequential (nested) fold — the IVC-shaped accumulator where order matters.
/// Each step folds the running accumulator with the next instance under that
/// step's challenge: `acc ← A_k · acc + w_k`. Unrolled, the contribution of an
/// early `w_j` is multiplied by the PRODUCT of all later challenges, so
/// reordering the challenge sequence changes the result by commutator terms —
/// this is where `[A,B]` earns its keep (a flat `Σ A_k·w_k` would be
/// reorder-invariant by additive commutativity alone and would not exercise
/// the matrix structure at all).
fn fold_sequential(challenges: &[R], witnesses: &[R]) -> R {
    let mut acc = R::default(); // zero
    for (a, w) in challenges.iter().zip(witnesses.iter()) {
        acc = *a * acc + *w;
    }
    acc
}

/// A commuting challenge schedule: powers `A^0, A^1, …, A^{m-1}` of one base
/// matrix. Any two powers commute, so the whole schedule is commuting.
fn power_schedule(base: &R, m: usize) -> Vec<R> {
    let mut out = Vec::with_capacity(m);
    let mut cur = R::ONE;
    for _ in 0..m {
        out.push(cur);
        cur *= *base;
    }
    out
}

/// Convert a degree-1 `MatrixRing` element to the analysis representation, so
/// the offline certified norm bounds apply to it.
fn to_element(m: &R) -> MatrixRingElement {
    use blacknet_crypto::algebra::BalancedRepresentative;
    let entries = (0..4).map(|i| vec![m[i].balanced()]).collect();
    MatrixRingElement::new(2, 1, entries)
}

/// The accumulator's multiplier after a sequential fold with zero witnesses,
/// seeded at `seed`: `A_{m-1} · … · A_0 · seed`. Isolates the part of the fold
/// that depends on challenge ORDER (the witnesses contribute order-dependent
/// lower terms regardless; the leading multiplier is order-invariant exactly
/// when the challenges commute).
fn challenge_product(seed: R, challenges: &[R]) -> R {
    let zeros: Vec<R> = challenges.iter().map(|_| R::default()).collect();
    let mut acc = seed;
    for (a, w) in challenges.iter().zip(zeros.iter()) {
        acc = *a * acc + *w;
    }
    acc
}

fn entries_eq(a: &R, b: &R) -> bool {
    (0..4).all(|i| a[i].balanced_eq(&b[i]))
}

#[test]
fn commuting_schedule_is_reorder_invariant() {
    // The defining property: with a commuting challenge schedule, applying the
    // folds in any order yields the same accumulator multiplier, because the
    // product of commuting matrices is order-independent. This is what makes
    // tree / parallel / permuted folding sound with no extra slack.
    let base = mat(1, 1, 0, 1); // unipotent; its powers commute
    let challenges = power_schedule(&base, 4);
    let seed = mat(2, 0, 1, 3);

    let forward = challenge_product(seed, &challenges);
    let mut rev = challenges.clone();
    rev.reverse();
    let reversed = challenge_product(seed, &rev);

    assert!(
        entries_eq(&forward, &reversed),
        "commuting schedule must give an order-invariant accumulator multiplier"
    );
}

// Helper: structural equality via balanced representatives.
trait BalancedEq {
    fn balanced_eq(&self, other: &Self) -> bool;
}
impl BalancedEq for Z {
    fn balanced_eq(&self, other: &Self) -> bool {
        use blacknet_crypto::algebra::BalancedRepresentative;
        self.balanced() == other.balanced()
    }
}

#[test]
fn all_pairwise_commutators_vanish_for_the_power_schedule() {
    // The reason the schedule is reorder-invariant: every pair of challenges
    // commutes, certified two ways — rat4's own commutator is the zero matrix
    // (infinity_norm == 0), and our certified spectral bound on it is 0.
    let base = mat(2, 1, 0, 3);
    let sched = power_schedule(&base, 4);
    for i in 0..sched.len() {
        for j in 0..sched.len() {
            let c = sched[i].commutator(sched[j]);
            assert_eq!(
                c.infinity_norm(),
                0,
                "[A^{i},A^{j}] must be the zero matrix"
            );
            assert_eq!(
                commutator_norm_bound(&to_element(&sched[i]), &to_element(&sched[j])),
                0,
                "certified ‖[A^{i},A^{j}]‖ must be 0"
            );
        }
    }
}

#[test]
fn generic_schedule_is_not_reorder_invariant() {
    // Contrast: two non-commuting challenges. Swapping their order changes the
    // accumulator multiplier (A·B ≠ B·A), so the commuting structure above is
    // doing real work, not a vacuous property.
    let a = mat(1, 2, 0, 1);
    let b = mat(1, 0, 3, 1);
    let seed = R::ONE;
    let ab = challenge_product(seed, &[a, b]);
    let ba = challenge_product(seed, &[b, a]);
    assert!(
        !entries_eq(&ab, &ba),
        "a non-commuting schedule must NOT be reorder-invariant"
    );
    // And the certified commutator of the two challenges is positive.
    assert!(
        commutator_norm_bound(&to_element(&a), &to_element(&b)) > 0,
        "non-commuting challenges have positive certified reorder slack"
    );
}

#[test]
fn accumulated_norm_stays_within_the_certified_bound() {
    // The norm-growth guarantee for the SEQUENTIAL fold. Unrolled,
    //   acc = w_{m-1} + A_{m-1}·w_{m-2} + A_{m-1}A_{m-2}·w_{m-3} + …,
    // so witness j is expanded by the product of the (m-1-j) later challenges.
    // The certified per-term bound is Π ‖M_{A_k}‖ · ‖w_j‖, summed — this is the
    // compounding the decomposition refresh would tame in a real scheme, here
    // shown to actually bound the measured accumulator.
    use blacknet_crypto::operatornorm::matrix_multiplication_norm_bound;
    let base = mat(1, 1, 0, 1);
    let challenges = power_schedule(&base, 4);
    let witnesses = [
        mat(2, 0, 1, 3),
        mat(0, 1, 1, 0),
        mat(1, 1, 1, 1),
        mat(3, 0, 0, 2),
    ];

    let acc = fold_sequential(&challenges, &witnesses);
    let measured: i64 = acc.infinity_norm();

    let exps: Vec<u128> = challenges
        .iter()
        .map(|a| matrix_multiplication_norm_bound(&to_element(a)))
        .collect();
    // Term j (0-based) is multiplied by challenges j+1..m; bound = product of
    // those expansions times ‖w_j‖∞.
    let m = witnesses.len();
    let mut bound: u128 = 0;
    for (j, w) in witnesses.iter().enumerate() {
        let mut prod: u128 = 1;
        for e in exps.iter().take(m).skip(j + 1) {
            prod = prod.saturating_mul(*e);
        }
        bound += prod * (w.infinity_norm() as u128);
    }
    assert!(
        (measured as u128) <= bound,
        "measured ‖acc‖∞ = {measured} must be within certified bound {bound}"
    );
}

#[test]
fn challenge_space_is_larger_than_scalar() {
    // The soundness motivation, made concrete. Over a field of size q, a
    // scalar challenge set is ~q; a commuting power-family is ~q (one base
    // matrix's eigenstructure) to ~q^N; the full matrix ring is ~q^(N²). For
    // N=2 that is q^4 — four field elements' worth of entropy per challenge,
    // i.e. ~4× the soundness bits per fold, so ~4× fewer repetitions for the
    // same security. We assert the counting that motivates the construction.
    let n = 2usize; // matrix dimension
    let scalar_bits_per_elem = 61; // Pervushin field ~2^61
    let scalar_space_bits = scalar_bits_per_elem;
    let full_matrix_space_bits = scalar_bits_per_elem * n * n;
    assert_eq!(full_matrix_space_bits, scalar_space_bits * 4);
    assert!(
        full_matrix_space_bits > scalar_space_bits,
        "matrix challenge space must exceed the scalar one"
    );
}
