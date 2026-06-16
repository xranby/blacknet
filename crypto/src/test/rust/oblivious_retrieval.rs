/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! A lite client outsources note discovery to a full node and gets back a
//! digest of exactly its notes — the outsourced-discovery counterpart to the
//! client-side scan in `compose_blacklemon_zkvm`.

use blacknet_crypto::blacklemon::{
    PublicKey, SecretKey, encrypt, generate_public_key, generate_secret_key,
};
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

fn amount_of(pt: &blacknet_crypto::blacklemon::PlainText) -> i32 {
    i32::from(decode(pt)[1])
}

/// Build a mixed board: Alice's and Bob's notes interleaved.
fn sample_board(alice: &Party, bob: &Party) -> Vec<blacknet_crypto::blacklemon::CipherText> {
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
fn lite_client_recovers_exactly_its_notes_from_the_node() {
    let alice = new_party(1);
    let bob = new_party(2);
    let board = sample_board(&alice, &bob);

    // The lite client sends a request; the full node runs the scan.
    let req = RetrievalRequest {
        key: DetectionKey { secret: &alice.sk },
        board_start: 0,
        max_results: 64,
    };
    let digest = ReferenceDetector.scan(&req, &board);

    // Exactly Alice's three notes, at the right indices, with the right amounts.
    assert_eq!(
        digest.entries.len(),
        3,
        "Alice has three notes on this board"
    );
    let indices: Vec<u64> = digest.entries.iter().map(|e| e.index).collect();
    assert_eq!(indices, vec![0, 2, 3]);
    let amounts: Vec<i32> = digest.entries.iter().map(amount_entry).collect();
    assert_eq!(amounts, vec![30, 45, 12]);

    // The digest binds the scanned range and matched indices.
    assert!(digest.commitment_is_consistent());
    assert_eq!(digest.scanned_len, 5);
}

fn amount_entry(e: &blacknet_crypto::oblivious_retrieval::DigestEntry) -> i32 {
    amount_of(&e.payload)
}

#[test]
fn bobs_request_recovers_a_disjoint_set() {
    let alice = new_party(1);
    let bob = new_party(2);
    let board = sample_board(&alice, &bob);

    let req = RetrievalRequest {
        key: DetectionKey { secret: &bob.sk },
        board_start: 0,
        max_results: 64,
    };
    let digest = ReferenceDetector.scan(&req, &board);
    let indices: Vec<u64> = digest.entries.iter().map(|e| e.index).collect();
    assert_eq!(
        indices,
        vec![1, 4],
        "Bob gets his two notes, none of Alice's"
    );
    let amounts: Vec<i32> = digest.entries.iter().map(amount_entry).collect();
    assert_eq!(amounts, vec![99, 77]);
}

#[test]
fn a_third_party_recovers_nothing() {
    let alice = new_party(1);
    let bob = new_party(2);
    let carol = new_party(3);
    let board = sample_board(&alice, &bob);

    let req = RetrievalRequest {
        key: DetectionKey { secret: &carol.sk },
        board_start: 0,
        max_results: 64,
    };
    let digest = ReferenceDetector.scan(&req, &board);
    assert!(
        digest.entries.is_empty(),
        "a non-recipient detects none of the notes"
    );
    assert!(digest.commitment_is_consistent());
}

#[test]
fn max_results_caps_the_digest() {
    let alice = new_party(1);
    let bob = new_party(2);
    let board = sample_board(&alice, &bob);

    // Alice has 3 notes but asks for at most 2.
    let req = RetrievalRequest {
        key: DetectionKey { secret: &alice.sk },
        board_start: 0,
        max_results: 2,
    };
    let digest = ReferenceDetector.scan(&req, &board);
    assert_eq!(digest.entries.len(), 2, "capped at max_results");
    let indices: Vec<u64> = digest.entries.iter().map(|e| e.index).collect();
    assert_eq!(indices, vec![0, 2], "the first two matches in scan order");
}

#[test]
fn streaming_pagination_preserves_absolute_indices() {
    // Streaming: the node scans a later window and reports ABSOLUTE indices via
    // board_start, so a client polling incrementally sees consistent indexing.
    let alice = new_party(1);
    let bob = new_party(2);
    let full = sample_board(&alice, &bob);
    let window = &full[2..]; // indices 2,3,4 in absolute terms

    let req = RetrievalRequest {
        key: DetectionKey { secret: &alice.sk },
        board_start: 2,
        max_results: 64,
    };
    let digest = ReferenceDetector.scan(&req, window);
    let indices: Vec<u64> = digest.entries.iter().map(|e| e.index).collect();
    assert_eq!(indices, vec![2, 3], "absolute indices, not window-relative");
    assert_eq!(digest.board_start, 2);
    assert!(digest.commitment_is_consistent());
}

#[test]
fn tampering_the_reported_range_breaks_the_commitment() {
    let alice = new_party(1);
    let bob = new_party(2);
    let board = sample_board(&alice, &bob);
    let req = RetrievalRequest {
        key: DetectionKey { secret: &alice.sk },
        board_start: 0,
        max_results: 64,
    };
    let mut digest = ReferenceDetector.scan(&req, &board);
    assert!(digest.commitment_is_consistent());
    // A node claiming it scanned a different range than it committed to is
    // caught by the binding.
    digest.scanned_len += 1;
    assert!(
        !digest.commitment_is_consistent(),
        "range tampering must break the digest commitment"
    );
}
