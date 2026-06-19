/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Lite-client oblivious retrieval, layered on BlackLemon.
//!
//! A resource-limited client (a phone) cannot afford to download a confidential
//! ledger and run [`blacklemon::detect`] on every note to find the ones
//! addressed to it. This module outsources that linear scan to a full node: the
//! client sends a [`RetrievalRequest`], the node walks the board and returns a
//! [`Digest`] of just the pertinent notes. This is the Oblivious Message
//! Retrieval (OMR) shape — the clue is the existing BlackLemon ciphertext, and
//! this layer adds the missing client/node interface around it.
//!
//! ## Privacy boundary (stated honestly)
//!
//! [`Detector`] is a trait so the detection backend is pluggable, and the two
//! backends have very different privacy:
//!
//! * [`ReferenceDetector`] (here): the detection key carries BlackLemon secret
//!   material and the node runs `detect` in the clear. It works and exercises
//!   the whole protocol, but the node LEARNS which notes match — so it is the
//!   right mode only when the node is trusted for privacy (e.g. the client's
//!   own full node). It is also the oracle an oblivious backend is tested
//!   against.
//! * An oblivious backend (NOT built here): the detection key is the BlackLemon
//!   secret encrypted under FHE, and the node evaluates `detect`
//!   homomorphically, learning nothing. That is true OMR — what InstantOMR
//!   (ePrint 2025/2317) accelerates — and a substantial separate FHE effort.
//!   BlackLemon's `detect` (an LWE inner product plus a coefficient range
//!   check) has exactly the homomorphically-evaluable shape it needs; the
//!   interface here is built so that backend drops in without touching the
//!   protocol or the client.
//!
//! The soundness of the *answer* (the digest is the correct, complete set of
//! the client's notes over the scanned range) is separate from request privacy
//! and is what the in-tree zkVM proves over the digest, following the
//! `compose_blacklemon_zkvm` pattern — binding at the data boundary, not
//! re-verifying lattice decryption in-circuit.

extern crate alloc;
use alloc::vec::Vec;

use crate::blacklemon::{self, CipherText, PlainText, SecretKey};
use crate::pervushin::PervushinField as F;
use crate::symmetric::{DuplexPoseidon2Pervushin, Duplexer};

/// A per-note tag on the board: a BlackLemon ciphertext addressed to some
/// recipient's clue-key. Senders produce these with `blacklemon::encrypt`.
pub type Clue = CipherText;

/// A binding commitment to a digest: the scanned board range and the pertinent
/// indices, hashed so the exchange is auditable (the client can pin what the
/// node claims to have scanned). Four Pervushin field elements.
pub type DigestCommitment = [F; 4];

/// What the lite client passes to the node. Backend-agnostic by design: the
/// reference backend below carries the BlackLemon secret; an oblivious backend
/// would instead carry the FHE-encrypted secret. Either way the node treats it
/// opaquely through [`Detector`].
pub struct DetectionKey<'a> {
    /// Reference backend: the recipient's BlackLemon secret. (Oblivious
    /// backend would replace this with an FHE-encrypted key.)
    pub secret: &'a SecretKey,
}

/// A lite client's request: detect my notes in `board[start .. start+len]`,
/// returning at most `max_results`.
pub struct RetrievalRequest<'a> {
    /// Detection capability (see the privacy note on [`DetectionKey`]).
    pub key: DetectionKey<'a>,
    /// First board index this request covers (for streaming / pagination).
    pub board_start: u64,
    /// Cap on returned entries, so a digest stays lite-client sized even if the
    /// match set is unexpectedly large.
    pub max_results: usize,
}

/// One recovered note: its absolute board index and decrypted payload.
pub struct DigestEntry {
    pub index: u64,
    pub payload: PlainText,
}

/// What the node returns: the pertinent notes in the scanned range, the range
/// itself, and a commitment binding the two.
pub struct Digest {
    pub entries: Vec<DigestEntry>,
    /// `[board_start, board_start + scanned_len)`.
    pub board_start: u64,
    pub scanned_len: u64,
    pub commitment: DigestCommitment,
}

/// Commits to the scanned range and the matched indices. Independent of the
/// payloads (which are the client's secret) so the commitment can be shown to
/// an auditor without leaking note contents.
fn commit_digest(board_start: u64, scanned_len: u64, indices: &[u64]) -> DigestCommitment {
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(F::from(0xC1u32)); // domain tag: "lite-retrieval digest"
    duplex.absorb(F::from(board_start as u32));
    duplex.absorb(F::from((board_start >> 32) as u32));
    duplex.absorb(F::from(scanned_len as u32));
    duplex.absorb(F::from(indices.len() as u32));
    for &i in indices {
        duplex.absorb(F::from(i as u32));
        duplex.absorb(F::from((i >> 32) as u32));
    }
    core::array::from_fn(|_| duplex.squeeze())
}

/// The detection backend. A node implements this; the client only sees the
/// resulting [`Digest`].
pub trait Detector {
    /// Scan `board` (whose first element is at absolute index
    /// `req.board_start`) and return the pertinent notes.
    fn scan(&self, req: &RetrievalRequest, board: &[Clue]) -> Digest;
}

/// Trusted-node backend: runs BlackLemon `detect` in the clear. Correct and
/// fully testable; NOT oblivious (the node sees matches). See the module's
/// privacy boundary.
pub struct ReferenceDetector;

impl Detector for ReferenceDetector {
    fn scan(&self, req: &RetrievalRequest, board: &[Clue]) -> Digest {
        let sk = req.key.secret;
        let mut entries = Vec::new();
        for (offset, clue) in board.iter().enumerate() {
            if entries.len() >= req.max_results {
                break;
            }
            if let Some(payload) = blacklemon::detect(sk, clue) {
                let index = req.board_start + offset as u64;
                entries.push(DigestEntry { index, payload });
            }
        }
        Digest::assemble(req.board_start, board.len() as u64, entries)
    }
}

impl Digest {
    /// Re-derive the commitment from the entry indices and check it matches.
    /// Lets a client confirm the digest's range/index binding is internally
    /// consistent (a full audit of completeness requires the node's proof or
    /// an oblivious backend; this is the cheap structural check).
    #[must_use]
    pub fn commitment_is_consistent(&self) -> bool {
        let indices: Vec<u64> = self.entries.iter().map(|e| e.index).collect();
        commit_digest(self.board_start, self.scanned_len, &indices) == self.commitment
    }

    /// Assemble a digest from matched entries and the scanned range, computing
    /// the binding commitment. Used by every backend (trusted or oblivious) so
    /// they produce byte-identical digests for the same matches.
    #[must_use]
    pub fn assemble(board_start: u64, scanned_len: u64, entries: Vec<DigestEntry>) -> Digest {
        let indices: Vec<u64> = entries.iter().map(|e| e.index).collect();
        let commitment = commit_digest(board_start, scanned_len, &indices);
        Digest {
            entries,
            board_start,
            scanned_len,
            commitment,
        }
    }
}
