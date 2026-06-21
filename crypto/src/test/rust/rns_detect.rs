#![allow(clippy::needless_range_loop)]
/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Front-end bridge tests: oblivious BlackLemon detection in the RNS scheme.

use blacknet_crypto::random::FastDRG;
use blacknet_crypto::rns_detect::{RnsDetectionKey, oblivious_detect};
use blacknet_crypto::rns_rlwe::RnsRlwe;

const N: usize = 4096;
const Q: i64 = 65537;

fn drg(b: u8) -> FastDRG {
    let mut s = [0u8; 32];
    s[0] = b;
    FastDRG::new(&s)
}

fn rand_poly(rng_seed: u64) -> [i64; N] {
    let mut x = rng_seed | 1;
    core::array::from_fn(|_| {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((x >> 40) as i64).rem_euclid(Q)
    })
}

/// Cleartext oracle: d = ct.a + ct.b·s + sk.b over Z_q[X]/(X^N+1), canonical.
fn cleartext_d(ca: &[i64; N], cb: &[i64; N], s: &[i64; N], skb: &[i64; N]) -> [i64; N] {
    let mut prod = [0i64; N];
    for i in 0..N {
        for j in 0..N {
            let mut k = i + j;
            let mut term = (cb[i] * s[j]).rem_euclid(Q);
            if k >= N {
                k -= N;
                term = (-term).rem_euclid(Q);
            }
            prod[k] = (prod[k] + term).rem_euclid(Q);
        }
    }
    core::array::from_fn(|i| (ca[i] + prod[i] + skb[i]).rem_euclid(Q))
}

#[test]
fn oblivious_detect_matches_cleartext_decryption() {
    let mut rng = drg(91);
    let key = RnsRlwe::keygen(&mut rng);

    let s = rand_poly(1);
    let skb = rand_poly(2);
    let ca = rand_poly(3);
    let cb = rand_poly(4);

    // recipient builds the RNS detection key client-side
    let dk = RnsDetectionKey::generate(&key, &mut rng, &s, &skb);
    // node evaluates d obliviously from the public clue
    let enc_d = oblivious_detect(&dk, &ca, &cb);
    let d_rns = key.decrypt(&enc_d);

    let expect = cleartext_d(&ca, &cb, &s, &skb);
    for i in 0..N {
        assert_eq!(
            d_rns[i], expect[i],
            "Enc(d) coefficient {i} != cleartext decryption"
        );
    }
}
