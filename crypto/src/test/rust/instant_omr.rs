/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! End-to-end oblivious OMR: the FHE backend must recover exactly the
//! recipient's notes — same indices, same payloads, same digest commitment as
//! the trusted ReferenceDetector — while the node only ever sees the encrypted
//! detection key and the board.

use blacknet_crypto::blacklemon::{
    CipherText, PlainText, PublicKey, SecretKey, encrypt, generate_public_key, generate_secret_key,
};
use blacknet_crypto::instant_omr::{ClientSession, client_recover, node_scan, oblivious_retrieve};
use blacknet_crypto::lpr::{decode, encode};
use blacknet_crypto::oblivious_retrieval::{
    DetectionKey, Detector, ReferenceDetector, RetrievalRequest,
};
use blacknet_crypto::random::FastDRG;

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
    bytes[0] = 0; // detectability marker (BlackLemon convention)
    bytes[1] = amount;
    bytes
}

fn amount_of(pt: &PlainText) -> i32 {
    i32::from(decode(pt)[1])
}

fn sample_board(alice: &Party, bob: &Party) -> Vec<CipherText> {
    let mut s = drg(100);
    vec![
        encrypt(&mut s, &alice.pk, &encode(&payment_note(30))), // 0 Alice
        encrypt(&mut s, &bob.pk, &encode(&payment_note(99))),   // 1 Bob
        encrypt(&mut s, &alice.pk, &encode(&payment_note(45))), // 2 Alice
        encrypt(&mut s, &alice.pk, &encode(&payment_note(12))), // 3 Alice
        encrypt(&mut s, &bob.pk, &encode(&payment_note(77))),   // 4 Bob
    ]
}

#[test]
fn oblivious_backend_recovers_exactly_the_recipients_notes() {
    let alice = new_party(1);
    let bob = new_party(2);
    let board = sample_board(&alice, &bob);

    // Ground truth: the trusted detector running detect() in the clear.
    let req = RetrievalRequest {
        key: DetectionKey { secret: &alice.sk },
        board_start: 0,
        max_results: 64,
    };
    let reference = ReferenceDetector.scan(&req, &board);

    // The oblivious backend: node sees only the encrypted key + board.
    let mut rng = drg(7);
    let oblivious = oblivious_retrieve(&mut rng, &alice.sk, &board, 0, 64);

    // Same matched indices.
    let ref_idx: Vec<u64> = reference.entries.iter().map(|e| e.index).collect();
    let obl_idx: Vec<u64> = oblivious.entries.iter().map(|e| e.index).collect();
    assert_eq!(obl_idx, ref_idx, "oblivious matches == reference matches");
    assert_eq!(obl_idx, vec![0, 2, 3], "exactly Alice's three notes");

    // Same payloads (compared by decoded bytes, the client-visible content).
    for (o, r) in oblivious.entries.iter().zip(reference.entries.iter()) {
        assert_eq!(
            decode(&o.payload),
            decode(&r.payload),
            "payload must match detect"
        );
    }
    let amounts: Vec<i32> = oblivious
        .entries
        .iter()
        .map(|e| amount_of(&e.payload))
        .collect();
    assert_eq!(amounts, vec![30, 45, 12], "recovered amounts");

    // Same binding commitment, and it is internally consistent.
    assert_eq!(
        oblivious.commitment, reference.commitment,
        "identical digest commitment"
    );
    assert!(oblivious.commitment_is_consistent());
}

#[test]
fn node_scan_returns_one_ciphertext_per_clue_and_needs_no_secret_key() {
    // The node's entire input is the encrypted detection key and the board; it
    // has no access to the BlackLemon secret. It returns one Enc(d) per clue
    // (uniform — no compression that would leak which match).
    let alice = new_party(3);
    let bob = new_party(4);
    let board = sample_board(&alice, &bob);

    let mut rng = drg(9);
    let session = ClientSession::new(&mut rng, &alice.sk);
    let encrypted = node_scan(session.detection_key(), &board);
    assert_eq!(
        encrypted.len(),
        board.len(),
        "one ciphertext per scanned clue"
    );

    // The client finishes locally and still gets exactly its notes.
    let digest = client_recover(&session, &encrypted, 0, 64);
    let idx: Vec<u64> = digest.entries.iter().map(|e| e.index).collect();
    assert_eq!(idx, vec![0, 2, 3]);
}

#[test]
fn wrong_recipient_recovers_nothing() {
    // A board with no notes for Carol yields an empty digest via the oblivious
    // path — the homomorphic decryption does not spuriously match.
    let alice = new_party(1);
    let bob = new_party(2);
    let carol = new_party(5);
    let board = sample_board(&alice, &bob);

    let mut rng = drg(11);
    let digest = oblivious_retrieve(&mut rng, &carol.sk, &board, 0, 64);
    assert!(digest.entries.is_empty(), "no notes are Carol's");
}
