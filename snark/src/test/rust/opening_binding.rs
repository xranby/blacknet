/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! The commitment binding is what makes the succinct opening sound: it ties
//! the proven-binary bits to the witness the accumulator actually commits to.
//! These tests confirm an honest opening binds, and - the point - that an
//! opening whose bits belong to a DIFFERENT witness than the commitment is
//! rejected.

use blacknet_crypto::matrix::DenseVector;
use blacknet_snark::opening::{decompose_bits, prove_binding, verify_binding};
use blacknet_snark::witnesscommitment::{CommitmentKey, F, decompose};

fn f(n: i64) -> F {
    use blacknet_crypto::algebra::IntegerRing;
    <F as IntegerRing>::new(n)
}

fn nbits_padded(d: &DenseVector<F>) -> usize {
    (decompose_bits(d).dimension()).next_power_of_two()
}

#[test]
fn honest_opening_binds_to_commitment() {
    // Commit to a real witness, then prove+verify the binding against C.
    let z: DenseVector<F> = [f(7), f(123), f(40000), f(9)].into_iter().collect();
    let d = decompose(&z);
    let key = CommitmentKey::setup(z.dimension(), 24); // small rows for test
    let commitment = key.commit(&d);
    let ctx = [f(1), f(2), f(3)];

    let (proof, bit_eval, _target) = prove_binding(key.matrix(), &commitment, &d, &ctx);
    assert!(
        verify_binding(
            key.matrix(),
            &commitment,
            &proof,
            bit_eval,
            nbits_padded(&d),
            &ctx
        )
        .is_ok(),
        "honest opening must bind to its own commitment"
    );
}

#[test]
fn opening_for_a_different_witness_is_rejected() {
    // The soundness case: prover commits to d (from z), but tries to bind an
    // opening computed for a DIFFERENT witness d' (from z'). The verifier
    // recomputes the target from the real C, so the mismatched bits fail.
    let z: DenseVector<F> = [f(7), f(123), f(40000), f(9)].into_iter().collect();
    let z_other: DenseVector<F> = [f(8), f(123), f(40000), f(9)].into_iter().collect();
    let d = decompose(&z);
    let d_other = decompose(&z_other);
    let key = CommitmentKey::setup(z.dimension(), 24);
    let commitment = key.commit(&d); // commit to the REAL d
    let ctx = [f(1), f(2), f(3)];

    // Prover forges: binding proof built from d_other, presented against C(d).
    let (proof, bit_eval, _t) = prove_binding(key.matrix(), &commitment, &d_other, &ctx);
    assert!(
        verify_binding(
            key.matrix(),
            &commitment,
            &proof,
            bit_eval,
            nbits_padded(&d),
            &ctx
        )
        .is_err(),
        "an opening for a different witness must NOT bind to this commitment"
    );
}

#[test]
fn tampered_bit_eval_is_rejected() {
    let z: DenseVector<F> = [f(11), f(2222), f(5), f(63000)].into_iter().collect();
    let d = decompose(&z);
    let key = CommitmentKey::setup(z.dimension(), 24);
    let commitment = key.commit(&d);
    let ctx = [f(9)];
    let (proof, bit_eval, _t) = prove_binding(key.matrix(), &commitment, &d, &ctx);
    // Flip the disclosed evaluation.
    let bad = bit_eval + f(1);
    assert!(
        verify_binding(
            key.matrix(),
            &commitment,
            &proof,
            bad,
            nbits_padded(&d),
            &ctx
        )
        .is_err()
    );
}

#[test]
fn wrong_commitment_is_rejected() {
    // Honest opening for d, but checked against a commitment to a different
    // witness: the target ⟨s,C⟩ no longer matches.
    let z: DenseVector<F> = [f(7), f(123), f(40000), f(9)].into_iter().collect();
    let z2: DenseVector<F> = [f(7), f(124), f(40000), f(9)].into_iter().collect();
    let d = decompose(&z);
    let key = CommitmentKey::setup(z.dimension(), 24);
    let c_wrong = key.commit(&decompose(&z2));
    let ctx = [f(5)];
    let (proof, bit_eval, _t) = prove_binding(key.matrix(), &c_wrong, &d, &ctx);
    // prove_binding used c_wrong for its target, but the bits are d's; verify
    // recomputes target from c_wrong and gets g̃(ρ)·b̃(ρ) != final.
    assert!(
        verify_binding(
            key.matrix(),
            &c_wrong,
            &proof,
            bit_eval,
            nbits_padded(&d),
            &ctx
        )
        .is_err()
    );
}

#[test]
fn binding_through_full_pipeline() {
    use blacknet_snark::pipeline::{
        Shape, prove_aggregate_succinct, prove_execution, verify_aggregate,
    };
    // Mirror the failing pipeline test exactly.
    let shape = Shape::derive(square(), &[f(2)], 10_000).unwrap();
    let key = CommitmentKey::setup(shape.elements, 24);
    let execs: Vec<_> = [3i32, 8]
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[f(x as i64)]).unwrap())
        .collect();
    let proof = prove_aggregate_succinct(&shape, &key, &execs).unwrap();
    assert!(proof.binding.is_some(), "binding must be produced");
    let r = verify_aggregate(&shape, &key, &proof);
    assert!(r.is_ok(), "full pipeline binding must verify: {:?}", r);
}

fn square() -> Vec<blacknet_vm::machine::Instruction<F>> {
    use blacknet_vm::machine::Instruction;
    vec![Instruction::Mul(2, 1, 1), Instruction::Halt]
}
