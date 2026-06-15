/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! The batched opening closes the binarity/binding seam: binarity and binding
//! are now ONE sumcheck over ONE b̃ at ONE point. These tests confirm the
//! honest case verifies, adversarial cases are rejected, and — the structural
//! point — that the verifier's final check uses a single disclosed b̃(ρ) in
//! both terms, so the "different witness for each claim" attack is impossible
//! by construction.

use blacknet_crypto::matrix::DenseVector;
use blacknet_snark::opening::{
    OPENING_BITS, decompose_bits, prove_bound_opening, verify_bound_opening,
};
use blacknet_snark::witnesscommitment::{CommitmentKey, F, decompose};

fn f(n: i64) -> F {
    use blacknet_crypto::algebra::IntegerRing;
    <F as IntegerRing>::new(n)
}

fn nbits(d: &DenseVector<F>) -> usize {
    decompose_bits(d).dimension().next_power_of_two()
}

fn ctx_for(c: &DenseVector<F>) -> Vec<F> {
    // Mimic a real opening context: commitment in the transcript before α.
    let mut v = vec![f(0xB1)];
    for k in 0..c.dimension() {
        v.push(c[k]);
    }
    v
}

#[test]
fn honest_batched_opening_verifies() {
    let z: DenseVector<F> = [f(7), f(123), f(40000), f(9)].into_iter().collect();
    let d = decompose(&z);
    let key = CommitmentKey::setup(z.dimension(), 24);
    let c = key.commit(&d);
    let ctx = ctx_for(&c);
    let (proof, beval) = prove_bound_opening(key.matrix(), &c, &d, &ctx);
    assert!(
        verify_bound_opening(key.matrix(), &c, &proof, beval, nbits(&d), &ctx).is_ok(),
        "honest batched opening must verify"
    );
}

#[test]
fn opening_for_a_different_witness_is_rejected() {
    // Prove against C(d) but with bits of a different d'. The single sumcheck
    // ties both the binarity AND binding terms to that d', whose binding term
    // does not sum to ⟨s, C(d)⟩ — rejected.
    let z: DenseVector<F> = [f(7), f(123), f(40000), f(9)].into_iter().collect();
    let zp: DenseVector<F> = [f(8), f(123), f(40000), f(9)].into_iter().collect();
    let d = decompose(&z);
    let dp = decompose(&zp);
    let key = CommitmentKey::setup(z.dimension(), 24);
    let c = key.commit(&d);
    let ctx = ctx_for(&c);
    let (proof, beval) = prove_bound_opening(key.matrix(), &c, &dp, &ctx);
    assert!(
        verify_bound_opening(key.matrix(), &c, &proof, beval, nbits(&dp), &ctx).is_err(),
        "an opening for a different witness must not verify against C(d)"
    );
}

#[test]
fn tampered_bit_eval_is_rejected() {
    let z: DenseVector<F> = [f(11), f(2222), f(5), f(63000)].into_iter().collect();
    let d = decompose(&z);
    let key = CommitmentKey::setup(z.dimension(), 24);
    let c = key.commit(&d);
    let ctx = ctx_for(&c);
    let (proof, beval) = prove_bound_opening(key.matrix(), &c, &d, &ctx);
    assert!(verify_bound_opening(key.matrix(), &c, &proof, beval + f(1), nbits(&d), &ctx).is_err());
}

#[test]
fn wrong_commitment_is_rejected() {
    let z: DenseVector<F> = [f(7), f(123), f(40000), f(9)].into_iter().collect();
    let z2: DenseVector<F> = [f(7), f(124), f(40000), f(9)].into_iter().collect();
    let d = decompose(&z);
    let key = CommitmentKey::setup(z.dimension(), 24);
    let c_wrong = key.commit(&decompose(&z2));
    let ctx = ctx_for(&c_wrong);
    let (proof, beval) = prove_bound_opening(key.matrix(), &c_wrong, &d, &ctx);
    assert!(verify_bound_opening(key.matrix(), &c_wrong, &proof, beval, nbits(&d), &ctx).is_err());
}

#[test]
fn seam_is_closed_one_eval_drives_both_terms() {
    // Structural proof the seam is gone: there is a SINGLE disclosed b̃(ρ).
    // Tamper it and BOTH the binarity term α(b²−b) and the binding term g·b in
    // the verifier's check move together — there is no second evaluation to
    // independently satisfy. We confirm no single substituted value other than
    // the honest one satisfies the check (sampling a spread).
    let z: DenseVector<F> = [f(3), f(99), f(1234), f(50000)].into_iter().collect();
    let d = decompose(&z);
    let key = CommitmentKey::setup(z.dimension(), 24);
    let c = key.commit(&d);
    let ctx = ctx_for(&c);
    let (proof, beval) = prove_bound_opening(key.matrix(), &c, &d, &ctx);
    assert!(verify_bound_opening(key.matrix(), &c, &proof, beval, nbits(&d), &ctx).is_ok());
    for delta in [1i64, 2, 3, 7, 12345, -1, -5] {
        let forged = beval + f(delta);
        assert!(
            verify_bound_opening(key.matrix(), &c, &proof, forged, nbits(&d), &ctx).is_err(),
            "no substituted b̃(ρ) other than the honest one may satisfy the single check"
        );
    }
    let _ = OPENING_BITS;
}
