/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Reviewer's adversarial test: are the binarity sumcheck and the
//! commitment-binding sumcheck bound to the SAME witness? They run over
//! independent transcripts at independent points. This test splices a
//! binding produced for a DIFFERENT (but in-budget) witness onto an honest
//! proof and asks the verifier to accept. If it does, the opening is unsound:
//! the two arguments describe two different b's.

use blacknet_snark::pipeline::{
    Shape, prove_aggregate_succinct, prove_execution, verify_aggregate,
};
use blacknet_snark::witnesscommitment::{CommitmentKey, F};
use blacknet_vm::machine::Instruction;

fn f(n: i32) -> F {
    F::from(n)
}

fn square() -> Vec<Instruction<F>> {
    vec![Instruction::Mul(2, 1, 1), Instruction::Halt]
}

#[test]
fn binding_spliced_from_a_different_proof_is_rejected() {
    let shape = Shape::derive(square(), &[f(2)], 10_000).unwrap();
    let key = CommitmentKey::setup(shape.elements, 24);

    // Two honest proofs of DIFFERENT computations -> different witnesses,
    // different commitments, but both in-budget and internally valid.
    let execs_a: Vec<_> = [3i32, 8]
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[f(x)]).unwrap())
        .collect();
    let execs_b: Vec<_> = [5i32, 9]
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[f(x)]).unwrap())
        .collect();

    let proof_a = prove_aggregate_succinct(&shape, &key, &execs_a).unwrap();
    let proof_b = prove_aggregate_succinct(&shape, &key, &execs_b).unwrap();

    // Sanity: both verify honestly.
    assert!(verify_aggregate(&shape, &key, &proof_a).is_ok());
    assert!(verify_aggregate(&shape, &key, &proof_b).is_ok());

    // ATTACK: rebuild A (deterministic FS => identical proof), then splice
    // B's binding onto it. A's binarity/projection describe A's witness; B's
    // binding describes B's. If the verifier accepts, the binding is not tied
    // to the binarity-proven witness -> unsound.
    let mut spliced = prove_aggregate_succinct(&shape, &key, &execs_a).unwrap();
    spliced.binding = proof_b.binding;
    let r = verify_aggregate(&shape, &key, &spliced);
    assert!(
        r.is_err(),
        "SOUNDNESS FAILURE: verifier accepted a binding spliced from a different witness"
    );
}

#[test]
fn binarity_and_binding_must_share_one_witness() {
    // The sharp attack: ONE commitment C = A*d. The honest binding uses the
    // real bits b(d). Can a prover pass binarity with a DIFFERENT binary
    // vector b1 while the binding still checks against C? Construct an honest
    // opening (binarity for b(d)) and an honest binding (for b(d)) - then ask
    // whether the verifier ever cross-checks that opening.bit_eval and the
    // binding's disclosed bit_eval are evaluations of the SAME b at related
    // points. We probe by tampering ONLY the opening's bit_eval/projection to
    // describe a different (still binary) witness, leaving the binding intact.
    use blacknet_crypto::matrix::DenseVector;
    use blacknet_snark::opening;
    use blacknet_snark::witnesscommitment::decompose;

    let z: DenseVector<F> = [f(7), f(123), f(40000), f(9)].into_iter().collect();
    let zp: DenseVector<F> = [f(8), f(123), f(40000), f(9)].into_iter().collect(); // differs in 1 digit
    let d = decompose(&z);
    let dp = decompose(&zp);
    let key = CommitmentKey::setup(z.dimension(), 24);
    let c = key.commit(&d); // commit to the REAL d
    let ctx = [f(1), f(2), f(3)];

    // Honest opening proves b(d) binary; binding ties b(d) to C. Both real.
    let honest_open = opening::prove(&d, &ctx);
    assert!(opening::verify(&honest_open, d.dimension(), 1u128 << 45, &ctx).is_ok());

    // Adversary swaps the OPENING to describe d' (also binary, in-budget) but
    // keeps the commitment C(d). The opening::verify has no commitment input,
    // so it cannot notice. This is exactly why the BINDING is required.
    let foreign_open = opening::prove(&dp, &ctx);
    // The standalone opening for d' "verifies" (it only checks binarity+norm):
    assert!(
        opening::verify(&foreign_open, dp.dimension(), 1u128 << 45, &ctx).is_ok(),
        "opening alone is commitment-blind - this is the gap the binding must close"
    );
    // The BINDING for d' against C(d) must FAIL (different witness vs C):
    let bind_ctx = [f(0xB1), f(1), f(2), f(3)];
    let (bproof, beval, _t) = opening::prove_binding(key.matrix(), &c, &dp, &bind_ctx);
    let nbits = (dp.dimension() * 45).next_power_of_two();
    assert!(
        opening::verify_binding(key.matrix(), &c, &bproof, beval, nbits, &bind_ctx).is_err(),
        "SOUNDNESS: binding for d' must not verify against C(d)"
    );
}
