/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Use case: private payment detection on a public ledger, post-quantum.
//!
//! BlackLemon (https://blacknet.ninja/blacklemon.pdf) is a lattice-based
//! fuzzy message-detection / stealth-notification scheme: an LPR ciphertext
//! carries, in its leading coefficients, a flag that only the intended
//! recipient's secret key can read. `detect(sk, ct)` returns `Some` for a
//! note addressed to the holder of `sk` and `None` otherwise, WITHOUT
//! trial-decryption and without the sender and recipient ever interacting.
//!
//! The deployment this enables: a shared, public ledger of encrypted notes
//! (payments, messages, airdrops). Each recipient scans the whole ledger and
//! learns which notes are theirs - and only those - by detection, then
//! decrypts just those. No observer learns who any note is for; recipients
//! do not reveal their identity or which entries they read; and because the
//! scheme is lattice-based, the privacy survives a quantum adversary that
//! would unravel an elliptic-curve stealth-address scheme.
//!
//! This complements the zkFi machine: BlackLemon decides *which* private
//! notes are yours; the folding zkVM proves *statements about* their
//! contents. Together they are the private-discovery and private-computation
//! halves of a confidential ledger.

use blacknet_crypto::blacklemon::{
    PublicKey, SecretKey, decrypt, detect, encrypt, generate_public_key, generate_secret_key,
};
use blacknet_crypto::lpr::{decode, encode};
use blacknet_crypto::random::FastDRG;
use core::array;

/// A distinct deterministic RNG per party, so the parties have independent
/// keys (the default seed is all-zero and would collide).
fn drg(seed_byte: u8) -> FastDRG {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    FastDRG::new(&seed)
}

/// A party with a BlackLemon keypair.
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

/// A 128-byte note payload (D/8 bytes), e.g. an amount + memo. BlackLemon's
/// detectability convention is that the leading KAPPA message bits are zero,
/// so a sender marks a note "detectable by the addressee" by clearing the low
/// bits of byte 0. We keep byte 0 = 0 and carry the distinguishing tag in
/// byte 1, so notes are distinct while remaining detectable.
fn note_bytes(tag: u8) -> [u8; 128] {
    let mut bytes: [u8; 128] = array::from_fn(|i| i as u8);
    bytes[0] = 0; // leading bits clear: this note is addressed/detectable
    bytes[1] = tag; // distinguishing content
    bytes
}

#[test]
fn recipient_detects_only_their_own_notes() {
    // Three parties. A sender posts one note to Alice. Alice detects it;
    // Bob and Carol - scanning the same ledger entry - do not.
    let alice = new_party(1);
    let bob = new_party(2);
    let carol = new_party(3);
    let mut sender_rng = drg(100);

    let pt = encode(&note_bytes(7));
    let ct = encrypt(&mut sender_rng, &alice.pk, &pt);

    assert!(
        detect(&alice.sk, &ct).is_some(),
        "the addressee detects the note"
    );
    assert!(detect(&bob.sk, &ct).is_none(), "a non-addressee does not");
    assert!(
        detect(&carol.sk, &ct).is_none(),
        "nor does another non-addressee"
    );
}

#[test]
fn recipient_scans_a_mixed_ledger_and_decrypts_only_theirs() {
    // A realistic public ledger: notes addressed to a mix of recipients,
    // interleaved. Alice scans the whole ledger, detecting and decrypting
    // exactly her notes and nothing else.
    let alice = new_party(1);
    let bob = new_party(2);
    let mut sender_rng = drg(100);

    // Ledger entries: (ciphertext, the true payload for our assertions).
    let mut ledger = Vec::new();
    // Two notes for Alice (tags 10 and 11), two for Bob (20, 21), interleaved.
    for (recipient, tag) in [
        (&alice.pk, 10u8),
        (&bob.pk, 20u8),
        (&alice.pk, 11u8),
        (&bob.pk, 21u8),
    ] {
        let pt = encode(&note_bytes(tag));
        let ct = encrypt(&mut sender_rng, recipient, &pt);
        ledger.push((ct, tag));
    }

    // Alice scans: detect, then decrypt only the detected entries.
    let mut alice_received: Vec<[u8; 128]> = Vec::new();
    for (ct, _tag) in &ledger {
        if detect(&alice.sk, ct).is_some() {
            let pt = decrypt(&alice.sk, ct);
            alice_received.push(decode(&pt));
        }
    }

    // She recovered exactly her two notes, with correct contents.
    assert_eq!(
        alice_received.len(),
        2,
        "Alice detects exactly her two notes"
    );
    assert!(alice_received.contains(&note_bytes(10)));
    assert!(alice_received.contains(&note_bytes(11)));
    assert!(
        !alice_received.contains(&note_bytes(20)),
        "never Bob's notes"
    );
}

#[test]
fn detection_does_not_leak_to_observers() {
    // An observer holding NO secret key (or the wrong one) cannot tell who a
    // note is for: detection with an unrelated key returns None, so scanning
    // the ledger with the wrong key reveals nothing.
    let alice = new_party(1);
    let observer = new_party(99);
    let mut sender_rng = drg(100);

    let ct = encrypt(&mut sender_rng, &alice.pk, &encode(&note_bytes(5)));
    // The observer learns nothing: every detection attempt with their key
    // fails, regardless of who the note is actually for.
    assert!(detect(&observer.sk, &ct).is_none());
    // Only Alice's key reveals the addressing.
    assert!(detect(&alice.sk, &ct).is_some());
}

#[test]
fn decrypt_recovers_payload_for_addressee() {
    // End to end: the detected note decrypts to exactly the bytes the sender
    // posted - so detection and decryption agree.
    let alice = new_party(1);
    let mut sender_rng = drg(100);
    let bytes = note_bytes(42);
    let ct = encrypt(&mut sender_rng, &alice.pk, &encode(&bytes));
    assert!(detect(&alice.sk, &ct).is_some());
    assert_eq!(decode(&decrypt(&alice.sk, &ct)), bytes);
}

#[test]
fn note_without_address_marker_is_not_detected() {
    // A payload whose leading bits are NOT cleared is not a well-formed
    // addressed note: even the correct key's detection rejects it. This
    // confirms detection is a real test, not always-true.
    let alice = new_party(1);
    let mut sender_rng = drg(100);
    let mut raw: [u8; 128] = core::array::from_fn(|i| i as u8);
    raw[0] = 0xFF; // leading bits set: violates the detectability convention
    let ct = encrypt(&mut sender_rng, &alice.pk, &encode(&raw));
    assert!(
        detect(&alice.sk, &ct).is_none(),
        "an unmarked note is not detected even by the right key"
    );
}
