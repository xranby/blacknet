/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! End-to-end **oblivious** Oblivious Message Retrieval over BlackLemon — the
//! wiring that connects the FHE detector backend ([`crate::oblivious_detector_fhe`])
//! to the retrieval protocol ([`crate::oblivious_retrieval`]).
//!
//! The trusted [`ReferenceDetector`](crate::oblivious_retrieval::ReferenceDetector)
//! runs `detect` in the clear, so the node sees which notes are the recipient's.
//! This module instead runs the detection's linear decryption *homomorphically*:
//!
//! 1. **Client setup.** The recipient derives [`detection_material`] from its
//!    BlackLemon secret key and encrypts it under a leveled-RLWE key, producing
//!    an [`EncryptedDetectionKey`]. Only this (encrypted) key goes to the node.
//! 2. **Node scan ([`node_scan`]).** For each clue the node computes
//!    `Enc(d) = Enc(a + b·s + sk.b)` homomorphically via [`oblivious_scan`]. It
//!    never holds the BlackLemon secret and learns nothing about which clues
//!    match — it returns one ciphertext per clue, uniformly.
//! 3. **Client recovery ([`client_recover`]).** The client decrypts each
//!    `Enc(d)`, applies BlackLemon's exact pertinence check, and for pertinent
//!    clues reconstructs the payload from the recovered `d` — yielding the same
//!    [`Digest`] the trusted backend would, with the node having seen nothing.
//!
//! **Honest scope.** This is oblivious for the decryption step but *not yet
//! bandwidth-lite*: the node returns one `Enc(d)` per scanned clue rather than a
//! compressed pertinent-only digest. Compressing on the node requires evaluating
//! the pertinence check itself under encryption (a bootstrapped range-check),
//! which needs the RNS/NTT accumulator and the circuit-bootstrap fold documented
//! in `blacknet-bootstrap-completion-analysis.md`. The protocol and correctness,
//! however, are complete and tested here.

extern crate alloc;
use alloc::vec::Vec;

use crate::blacklemon::{self, SecretKey};
use crate::oblivious_detector_fhe::{
    Ct, EncryptedDetectionKey, Rlwe, client_check_pertinence, encrypt_detection_key,
    oblivious_scan, recover_d,
};
use crate::oblivious_retrieval::{Clue, Digest, DigestEntry};
use crate::random::UniformGenerator;

/// The recipient's client-side detection session: the leveled-RLWE key (kept
/// secret) and the [`EncryptedDetectionKey`] derived from the BlackLemon secret
/// key (handed to the node).
pub struct ClientSession {
    rlwe: Rlwe,
    key: EncryptedDetectionKey,
}

impl ClientSession {
    /// Build a session from the recipient's BlackLemon secret key. The
    /// [`detection_material`](blacklemon::detection_material) is encrypted under
    /// a fresh RLWE key; the BlackLemon secret never leaves the client.
    pub fn new<R: UniformGenerator<Output = u8>>(rng: &mut R, sk: &SecretKey) -> Self {
        let rlwe = Rlwe::keygen(rng);
        let material = blacklemon::detection_material(sk);
        let key = encrypt_detection_key(rng, &rlwe, &material);
        ClientSession { rlwe, key }
    }

    /// The encrypted detection key to publish to the node. Carries no plaintext
    /// secret.
    #[must_use]
    pub fn detection_key(&self) -> &EncryptedDetectionKey {
        &self.key
    }
}

/// **Node side.** Obliviously scan a board, returning one `Enc(d)` per clue.
/// The node learns nothing about which clues are pertinent.
#[must_use]
pub fn node_scan(key: &EncryptedDetectionKey, board: &[Clue]) -> Vec<Ct> {
    oblivious_scan(key, board)
}

/// **Client side.** Turn the node's encrypted results into a [`Digest`] of the
/// recipient's pertinent notes (index + recovered payload), identical to what
/// the trusted backend would produce — but recovered from the oblivious scan.
#[must_use]
pub fn client_recover(
    session: &ClientSession,
    encrypted: &[Ct],
    board_start: u64,
    max_results: usize,
) -> Digest {
    let mut entries = Vec::new();
    for (offset, enc_d) in encrypted.iter().enumerate() {
        if entries.len() >= max_results {
            break;
        }
        if client_check_pertinence(&session.rlwe, enc_d) {
            let d = recover_d(&session.rlwe, enc_d);
            let payload = blacklemon::payload_from_d(&d);
            entries.push(DigestEntry {
                index: board_start + offset as u64,
                payload,
            });
        }
    }
    Digest::assemble(board_start, encrypted.len() as u64, entries)
}

/// Convenience: the full oblivious round trip (client setup → node scan →
/// client recovery) for a board the client can see. In deployment the three
/// stages are separated by the network; this runs them in sequence.
#[must_use]
pub fn oblivious_retrieve<R: UniformGenerator<Output = u8>>(
    rng: &mut R,
    sk: &SecretKey,
    board: &[Clue],
    board_start: u64,
    max_results: usize,
) -> Digest {
    let session = ClientSession::new(rng, sk);
    let encrypted = node_scan(session.detection_key(), board);
    client_recover(&session, &encrypted, board_start, max_results)
}
