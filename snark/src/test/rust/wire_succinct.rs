/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Round-trip and adversarial tests for the succinct wire codec: the
//! referenced-computation form that carries the succinct AggregateProof
//! (witness omitted) instead of the transparent witness.

use blacknet_snark::commitment::commit;
use blacknet_snark::pipeline::{
    Shape, prove_aggregate_succinct, prove_execution, verify_aggregate,
};
use blacknet_snark::wire::{Error, decode_reference_succinct, encode_reference_succinct};
use blacknet_snark::witnesscommitment::{CommitmentKey, F};
use blacknet_vm::machine::Instruction;

fn f(n: i32) -> F {
    F::from(n)
}

fn square() -> Vec<Instruction<F>> {
    vec![Instruction::Mul(2, 1, 1), Instruction::Halt]
}

fn build() -> (
    Shape,
    CommitmentKey,
    blacknet_snark::pipeline::AggregateProof,
    blacknet_snark::commitment::ProgramCommitment,
) {
    let shape = Shape::derive(square(), &[f(2)], 10_000).unwrap();
    let key = CommitmentKey::setup(shape.elements, 24);
    let execs: Vec<_> = [3i32, 8]
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[f(x)]).unwrap())
        .collect();
    let proof = prove_aggregate_succinct(&shape, &key, &execs).unwrap();
    let id = commit(&square());
    (shape, key, proof, id)
}

#[test]
fn round_trips_and_verifies_after_decode() {
    let (shape, key, proof, id) = build();
    let bytes = encode_reference_succinct(&id, &proof).unwrap();
    let (id2, proof2) = decode_reference_succinct(&bytes).unwrap();
    assert_eq!(id2.0, id.0, "program-id must round-trip");
    // The decoded proof must verify exactly as the original does.
    assert!(
        verify_aggregate(&shape, &key, &proof2).is_ok(),
        "decoded succinct proof must verify"
    );
}

#[test]
fn decoded_packet_is_far_smaller_than_transparent() {
    let (_shape, _key, proof, id) = build();
    let bytes = encode_reference_succinct(&id, &proof).unwrap();
    // Sanity bound: a succinct referenced packet is a few KB, not tens of KB.
    println!("succinct reference packet: {} bytes", bytes.len());
    assert!(
        bytes.len() < 8000,
        "succinct packet should be a few KB, got {}",
        bytes.len()
    );
}

#[test]
fn trailing_bytes_are_rejected() {
    let (_s, _k, proof, id) = build();
    let mut bytes = encode_reference_succinct(&id, &proof).unwrap();
    bytes.push(0); // one extra byte
    assert!(
        matches!(decode_reference_succinct(&bytes), Err(Error::Overlong)),
        "non-canonical trailing bytes must be rejected"
    );
}

#[test]
fn truncated_bytes_are_rejected() {
    let (_s, _k, proof, id) = build();
    let bytes = encode_reference_succinct(&id, &proof).unwrap();
    let cut = &bytes[..bytes.len() - 8];
    assert!(
        decode_reference_succinct(cut).is_err(),
        "truncated payload must be rejected"
    );
}

#[test]
fn tampering_the_public_io_is_always_caught() {
    // The soundness-critical property is not byte-uniqueness but that no
    // tamper makes the verifier accept a DIFFERENT computation. The public IO
    // is what binds the statement; flipping any byte of the encoded IO must be
    // caught (it changes the Fiat-Shamir transcript, so the replayed
    // accumulator no longer matches proof.accumulator).
    let (shape, key, proof, id) = build();
    let good = encode_reference_succinct(&id, &proof).unwrap();
    assert!(verify_aggregate(&shape, &key, &decode_reference_succinct(&good).unwrap().1).is_ok());

    // The IO region begins right after version(1) + id(COMMITMENT_WIDTH * 9
    // bytes) + the ios length prefix. Rather than hunt offsets, tamper the
    // first IO field bytes by scanning the early body and requiring that every
    // decode there either fails or fails verification.
    let header = 1 + 4 * 9 + 4; // version + 4 id fields (9B each) + u32 len
    let mut bad_statement_accepted = false;
    for pos in header..(header + 36).min(good.len()) {
        let mut t = good.clone();
        t[pos] ^= 0xFF;
        if let Ok((_, p2)) = decode_reference_succinct(&t) {
            if verify_aggregate(&shape, &key, &p2).is_ok() {
                bad_statement_accepted = true;
            }
        }
    }
    assert!(
        !bad_statement_accepted,
        "tampering the public IO must never verify (it rebinds the statement)"
    );
}

#[test]
fn encoding_is_not_byte_unique_documented_malleability() {
    // HONEST NOTE (reviewer finding): the encoding is NOT a unique
    // representation of a verifying proof. The verifier recomputes the
    // accumulator and checks it against the encoded one, and the JL norm
    // check has slack, so some byte positions are malleable — a tamper there
    // decodes to a DIFFERENT byte string that still verifies the SAME
    // computation. This is benign for soundness (the verified statement is
    // unchanged) but means the payload bytes are not a canonical proof id.
    // On-chain, txid stability must therefore come from the tx envelope
    // (sender, seq, fee, anchor), NOT from the proof bytes. This test asserts
    // the malleability EXISTS so the property is tracked, not assumed away.
    let (shape, key, proof, id) = build();
    let good = encode_reference_succinct(&id, &proof).unwrap();
    let mut malleable_found = false;
    for pos in (40..good.len()).step_by(11) {
        let mut t = good.clone();
        t[pos] ^= 0x01;
        if t != good {
            if let Ok((_, p2)) = decode_reference_succinct(&t) {
                if verify_aggregate(&shape, &key, &p2).is_ok() {
                    malleable_found = true;
                    break;
                }
            }
        }
    }
    assert!(
        malleable_found,
        "documented: proof bytes are malleable; txid must not depend on them"
    );
}

#[test]
fn zk_or_transparent_aggregate_is_refused_by_succinct_encoder() {
    use blacknet_snark::pipeline::prove_aggregate;
    let shape = Shape::derive(square(), &[f(2)], 10_000).unwrap();
    let key = CommitmentKey::setup(shape.elements, 24);
    let execs: Vec<_> = [3i32, 8]
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[f(x)]).unwrap())
        .collect();
    let transparent = prove_aggregate(&shape, &key, &execs).unwrap(); // has witness, no succinct
    let id = commit(&square());
    assert!(
        matches!(
            encode_reference_succinct(&id, &transparent),
            Err(Error::Malformed)
        ),
        "succinct encoder must refuse a transparent aggregate"
    );
}
