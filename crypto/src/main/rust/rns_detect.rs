/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Front-end bridge — oblivious BlackLemon detection evaluated in the RNS RLWE
//! scheme, producing `Enc(d)` for the step-4 pertinence bootstrap.
//!
//! BlackLemon's detection reduces to one linear step over its ring
//! `Z_q[X]/(X^D+1)` (`q = 65537`, `D = 1024`):
//!
//! ```text
//!   d = ct.a + ct.b · s + sk.b
//! ```
//!
//! where `(ct.a, ct.b)` are the public parts of a clue and `(s, sk.b)` are the
//! recipient's secret. The RNS leveled scheme used for the bootstrap has plaintext
//! modulus `T = 65537` and degree `N = 1024` — *identical* to BlackLemon's ring —
//! so the linear step is a homomorphic plaintext×ciphertext combination with no
//! cross-ring key-switch:
//!
//! ```text
//!   Enc(d) = plain_mul(Enc(s), ct.b) + Enc(sk.b) + ct.a
//! ```
//!
//! The recipient publishes `Enc(s)` and `Enc(sk.b)` (its RNS detection key); the
//! node evaluates the line above against each clue and feeds `Enc(d)` to the
//! pertinence PBS. The node learns neither `s`, `sk.b`, nor `d`. This is the
//! front end that connects the BlackLemon clue to the RNS bootstrap/compaction.

extern crate alloc;

use crate::random::UniformGenerator;
use crate::rns::{NTT_DEGREE, RnsPoly};
use crate::rns_rlwe::{RnsCt, RnsRlwe, trivial_encrypt};

/// A recipient's RNS-encrypted detection key: encryptions of the two
/// secret-bearing terms of BlackLemon's linear decryption. Built client-side
/// from `blacklemon::detection_material`; safe to hand to an untrusted node.
pub struct RnsDetectionKey {
    /// `Enc(s)` — the LWE secret (the `ct.b · s` multiplier term).
    pub enc_secret: RnsCt,
    /// `Enc(sk.b)` — the additive offset term.
    pub enc_offset: RnsCt,
}

impl RnsDetectionKey {
    /// Encrypt the recipient's detection material under its RNS key. `secret`
    /// and `offset` are the coefficient vectors from
    /// `blacklemon::detection_material` (each `< T`). Runs client-side.
    pub fn generate<R: UniformGenerator<Output = u8>>(
        key: &RnsRlwe,
        rng: &mut R,
        secret: &[i64; NTT_DEGREE],
        offset: &[i64; NTT_DEGREE],
    ) -> Self {
        RnsDetectionKey {
            enc_secret: key.encrypt(rng, secret),
            enc_offset: key.encrypt(rng, offset),
        }
    }
}

/// Node-side oblivious detection: evaluate `d = ct.a + ct.b·s + sk.b`
/// homomorphically from the public clue parts and the encrypted detection key.
/// Returns `Enc(d)` as an `RnsCt` under the recipient's RNS key — the input to
/// the step-4 pertinence bootstrap. No secret material is touched.
#[must_use]
pub fn oblivious_detect(
    key: &RnsDetectionKey,
    clue_a: &[i64; NTT_DEGREE],
    clue_b: &[i64; NTT_DEGREE],
) -> RnsCt {
    // ct.b · s : plaintext (public clue) × ciphertext (encrypted secret)
    let cb = RnsPoly::from_balanced(clue_b);
    let product = key.enc_secret.plain_mul(&cb);
    // + sk.b (encrypted) + ct.a (public plaintext, via a trivial encryption)
    product.add(&key.enc_offset).add(&trivial_encrypt(clue_a))
}
