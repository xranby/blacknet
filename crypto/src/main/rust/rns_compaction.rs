/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Step 5 — homomorphic, bandwidth-lite OMR compaction: the paper's bandwidth
//! benefit, turning `O(N)` per-clue ciphertexts into an `O(k̄)` digest.
//!
//! Given encrypted payloads `Enc(payloadᵢ)` and encrypted pertinence bits
//! `RGSW(PVᵢ)` (the output of the detection bootstrap / circuit-bootstrap fold,
//! step 4), and a public `m × N` weight matrix `W`, the node computes
//!
//! ```text
//!   bucketⱼ = Σᵢ PVᵢ · W[j][i] · payloadᵢ
//!           = Σᵢ external_product(RGSW(PVᵢ), W[j][i] · Enc(payloadᵢ))
//! ```
//!
//! Non-pertinent messages (`PVᵢ = 0`) drop out homomorphically, and the digest
//! is `m = O(k̄)` ciphertexts independent of `N`. The masking uses only the
//! external product — so the node learns neither the payloads nor which
//! messages are pertinent (it holds `RGSW(PV)`, not `PV`). The recipient, who
//! knows the matched support (from a small parallel index digest), solves the
//! `k̄ × k̄` linear system per coefficient to recover exactly its payloads.
//!
//! This is the bandwidth-lite + oblivious mechanism the InstantOMR/OMR line is
//! built on. The one input it takes on faith here is `RGSW(PV)` — produced by
//! step 4's fold over the RNS bootstrap (engine built; assembly is the
//! remaining work). Everything downstream of `RGSW(PV)` is implemented and
//! tested here.

extern crate alloc;
use alloc::vec::Vec;

use crate::rns::{NTT_DEGREE, RnsPoly};
use crate::rns_rlwe::{RnsCt, RnsRgsw, T, external_product};

/// A public Vandermonde weight matrix: `W[j][i] = (j+1)^i mod t`. Any `k̄`
/// distinct columns are linearly independent over `Z_t`, so the recipient can
/// always solve for up to `m` pertinent payloads.
#[must_use]
pub fn vandermonde_weights(buckets: usize, messages: usize) -> Vec<Vec<i64>> {
    (0..buckets)
        .map(|j| {
            let base = (j as i64 + 1).rem_euclid(T);
            let mut row = Vec::with_capacity(messages);
            let mut p = 1i64;
            for _ in 0..messages {
                row.push(p);
                p = (p * base).rem_euclid(T);
            }
            row
        })
        .collect()
}

/// Homomorphic, oblivious compaction (node side): `m` bucket ciphertexts from
/// `N` encrypted payloads masked by encrypted pertinence. `weights` is `m × N`.
#[must_use]
pub fn compact_buckets(payloads: &[RnsCt], pv: &[RnsRgsw], weights: &[Vec<i64>]) -> Vec<RnsCt> {
    weights
        .iter()
        .map(|wrow| {
            let mut acc: Option<RnsCt> = None;
            for (i, payload) in payloads.iter().enumerate() {
                let weighted = payload.plain_mul(&RnsPoly::constant(i128::from(wrow[i])));
                let term = external_product(&pv[i], &weighted);
                acc = Some(match acc {
                    Some(a) => a.add(&term),
                    None => term,
                });
            }
            acc.expect("at least one message")
        })
        .collect()
}

// ---- recipient-side recovery: solve the small linear system mod t ----------

fn inv_mod_t(a: i64) -> i64 {
    // t prime -> Fermat inverse
    let mut r = 1i64;
    let mut base = a.rem_euclid(T);
    let mut e = T - 2;
    while e > 0 {
        if e & 1 == 1 {
            r = (r * base).rem_euclid(T);
        }
        base = (base * base).rem_euclid(T);
        e >>= 1;
    }
    r
}

/// Invert a `k × k` matrix modulo `t` (Gauss–Jordan). Returns `None` if
/// singular.
fn invert_mod_t(mut m: Vec<Vec<i64>>) -> Option<Vec<Vec<i64>>> {
    let k = m.len();
    let mut inv: Vec<Vec<i64>> = (0..k)
        .map(|i| (0..k).map(|j| i64::from(i == j)).collect())
        .collect();
    for col in 0..k {
        // find pivot
        let mut piv = col;
        while piv < k && m[piv][col].rem_euclid(T) == 0 {
            piv += 1;
        }
        if piv == k {
            return None;
        }
        m.swap(col, piv);
        inv.swap(col, piv);
        let pinv = inv_mod_t(m[col][col]);
        for j in 0..k {
            m[col][j] = (m[col][j] * pinv).rem_euclid(T);
            inv[col][j] = (inv[col][j] * pinv).rem_euclid(T);
        }
        for r in 0..k {
            if r != col {
                let f = m[r][col].rem_euclid(T);
                if f != 0 {
                    for j in 0..k {
                        m[r][j] = (m[r][j] - f * m[col][j]).rem_euclid(T);
                        inv[r][j] = (inv[r][j] - f * inv[col][j]).rem_euclid(T);
                    }
                }
            }
        }
    }
    Some(inv)
}

/// Recipient side: from the decrypted bucket vectors, the matched `support`
/// indices, and the public weights, recover the pertinent payloads (one
/// per support index), solving `W_support · x = bucket` per coefficient.
#[must_use]
pub fn recover_pertinent_payloads(
    buckets: &[[i64; NTT_DEGREE]],
    support: &[usize],
    weights: &[Vec<i64>],
) -> Vec<[i64; NTT_DEGREE]> {
    let k = support.len();
    let sub: Vec<Vec<i64>> = (0..k)
        .map(|j| {
            support
                .iter()
                .map(|&i| weights[j][i].rem_euclid(T))
                .collect()
        })
        .collect();
    let inv = invert_mod_t(sub).expect("support columns must be independent");

    let mut out = alloc::vec![[0i64; NTT_DEGREE]; k];
    for pos in 0..NTT_DEGREE {
        for (c, slot) in out.iter_mut().enumerate() {
            let mut acc = 0i64;
            for j in 0..k {
                acc = (acc + inv[c][j] * buckets[j][pos]).rem_euclid(T);
            }
            slot[pos] = acc;
        }
    }
    out
}
