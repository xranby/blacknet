/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! The full lite-client story: ask a full node for your notes (outsourced
//! discovery over BlackLemon), then prove a statement about them (your balance)
//! in one folded zkVM proof — without ever scanning the board yourself.
//!
//! This is the outsourced-discovery version of `compose_blacklemon_zkvm`: there
//! the recipient scans locally; here a full node scans on the lite client's
//! behalf and returns a `Digest`, and only the proving half runs on the client.
//!
//! Same soundness boundary as the existing composition: the zkVM proves a
//! statement about the recovered amounts (data boundary), it does not
//! re-verify BlackLemon decryption in-circuit.

use blacknet_crypto::blacklemon::{
    PlainText, PublicKey, SecretKey, encrypt, generate_public_key, generate_secret_key,
};
use blacknet_crypto::lpr::{decode, encode};
use blacknet_crypto::oblivious_retrieval::{
    DetectionKey, Detector, Digest, ReferenceDetector, RetrievalRequest,
};
use blacknet_crypto::random::FastDRG;
use blacknet_snark::universal_run::{Row, asm::*, run};
use blacknet_snark::witnesscommitment::F;

fn f(n: i32) -> F {
    F::from(n)
}

fn drg(seed_byte: u8) -> FastDRG {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    FastDRG::new(&seed)
}

struct Party {
    sk: SecretKey,
    pk: PublicKey,
}

fn new_party(seed: u8) -> Party {
    let mut rng = drg(seed);
    let sk = generate_secret_key(&mut rng);
    let pk = generate_public_key(&mut rng, &sk);
    Party { sk, pk }
}

const fn payment_note(amount: u8) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    bytes[0] = 0;
    bytes[1] = amount;
    bytes
}

fn amount_of(pt: &PlainText) -> i32 {
    i32::from(decode(pt)[1])
}

/// The proving half: prove the sum of the digest's amounts equals a claim,
/// in one folded zkVM run. The amounts are the private witness.
fn prove_balance(digest: &Digest, claimed_total: i32) -> bool {
    let amounts: Vec<i32> = digest
        .entries
        .iter()
        .map(|e| amount_of(&e.payload))
        .collect();
    let mut prog: Vec<Row> = Vec::new();
    for (addr, &a) in amounts.iter().enumerate() {
        prog.push(loadimm(1, i64::from(a)));
        prog.push(loadimm(5, addr as i64));
        prog.push(store(1, 5));
    }
    prog.push(loadimm(2, 0)); // acc
    prog.push(loadimm(5, 0)); // idx
    prog.push(loadimm(6, amounts.len() as i64)); // n
    prog.push(loadimm(7, 1)); // step
    let lb = prog.len();
    prog.push(beq(5, 6, lb + 5));
    prog.push(load(3, 5));
    prog.push(add(2, 2, 3));
    prog.push(add(5, 5, 7));
    prog.push(jump(lb));
    prog.push(loadimm(4, i64::from(claimed_total)));
    prog.push(beq(2, 4, prog.len() + 2));
    prog.push(halt()); // mismatch
    prog.push(halt()); // matched
    let proof = run(&prog, &[], 1_000_000).unwrap();
    proof.accepted() && proof.registers[2] == f(claimed_total)
}

#[test]
fn lite_client_outsources_discovery_then_proves_balance() {
    let alice = new_party(1);
    let bob = new_party(2);
    let mut s = drg(100);
    // Public ledger: 30 -> Alice, 99 -> Bob, 45 -> Alice, 12 -> Alice, 77 -> Bob.
    let board = vec![
        encrypt(&mut s, &alice.pk, &encode(&payment_note(30))),
        encrypt(&mut s, &bob.pk, &encode(&payment_note(99))),
        encrypt(&mut s, &alice.pk, &encode(&payment_note(45))),
        encrypt(&mut s, &alice.pk, &encode(&payment_note(12))),
        encrypt(&mut s, &bob.pk, &encode(&payment_note(77))),
    ];

    // 1. DISCOVERY (outsourced): the lite client asks a full node; the node
    //    scans the board and returns Alice's digest. The client did no scan.
    let req = RetrievalRequest {
        key: DetectionKey { secret: &alice.sk },
        board_start: 0,
        max_results: 64,
    };
    let digest = ReferenceDetector.scan(&req, &board);
    assert_eq!(digest.entries.len(), 3);
    assert!(digest.commitment_is_consistent());

    // 2. COMPUTATION (on the client): prove the balance over the digest.
    assert!(
        prove_balance(&digest, 30 + 45 + 12),
        "the correct total must verify"
    );
    assert!(
        !prove_balance(&digest, 100),
        "a wrong total must not verify"
    );
}
