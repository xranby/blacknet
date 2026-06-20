/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! BFV ct×ct multiply, and the oblivious bandwidth-lite compaction built on it
//! with an ENCRYPTED pertinence bit (closing the step 4 -> step 5 connector).

#![allow(clippy::needless_range_loop)]
#![allow(clippy::missing_const_for_fn)]

extern crate alloc;
use alloc::vec::Vec;

use blacknet_crypto::bfv::{Bfv, NB, TB, bfv_mul, compact_buckets};
use blacknet_crypto::random::FastDRG;

fn drg(b: u8) -> FastDRG {
    let mut s = [0u8; 32];
    s[0] = b;
    FastDRG::new(&s)
}

fn payload(seed: u64) -> [i128; NB] {
    let mut x = seed | 1;
    core::array::from_fn(|_| {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        i128::from((x >> 48) as u32) % TB
    })
}

#[test]
fn bfv_multiply_matches_cleartext() {
    let mut rng = drg(1);
    let key = Bfv::keygen(&mut rng);
    // small operands so the negacyclic product stays within t for the check
    let mut a = [0i128; NB];
    let mut b = [0i128; NB];
    for i in 0..4 {
        a[i] = (i as i128) + 1;
        b[i] = (2 * i as i128) + 1;
    }
    let ca = key.encrypt(&mut rng, &a);
    let cb = key.encrypt(&mut rng, &b);
    let prod = key.decrypt2(&bfv_mul(&ca, &cb));

    // cleartext negacyclic product mod t
    let mut expect = [0i128; NB];
    for i in 0..NB {
        for j in 0..NB {
            let mut k = i + j;
            let mut p = a[i] * b[j];
            if k >= NB {
                k -= NB;
                p = -p;
            }
            expect[k] = (expect[k] + p).rem_euclid(TB);
        }
    }
    for i in 0..NB {
        assert_eq!(prod[i], expect[i], "BFV ct*ct product at coeff {i}");
    }
}

#[test]
fn pv_times_payload_is_oblivious_select() {
    // Enc(1)*Enc(payload) = Enc(payload); Enc(0)*Enc(payload) = Enc(0).
    let mut rng = drg(2);
    let key = Bfv::keygen(&mut rng);
    let pl = payload(7);
    let cpl = key.encrypt(&mut rng, &pl);

    let mut one = [0i128; NB];
    one[0] = 1;
    let c1 = key.encrypt(&mut rng, &one);
    let c0 = key.encrypt(&mut rng, &[0i128; NB]);

    let sel1 = key.decrypt2(&bfv_mul(&c1, &cpl));
    let sel0 = key.decrypt2(&bfv_mul(&c0, &cpl));
    assert_eq!(sel1.to_vec(), pl.to_vec(), "PV=1 selects payload");
    assert!(sel0.iter().all(|&v| v == 0), "PV=0 masks to zero");
}

// recover pertinent payloads from buckets (solve k x k mod t)
fn inv_t(a: i128) -> i128 {
    let mut r = 1i128;
    let mut b = a.rem_euclid(TB);
    let mut e = TB - 2;
    while e > 0 {
        if e & 1 == 1 {
            r = (r * b).rem_euclid(TB);
        }
        b = (b * b).rem_euclid(TB);
        e >>= 1;
    }
    r
}

#[test]
fn oblivious_bandwidth_lite_compaction_with_encrypted_pv() {
    let mut rng = drg(3);
    let key = Bfv::keygen(&mut rng);

    const N_MSG: usize = 8;
    let support = [1usize, 4, 6];
    let k = support.len();
    let payloads_pt: Vec<[i128; NB]> = (0..N_MSG).map(|i| payload(100 + i as u64)).collect();
    let is_pert = |i: usize| support.contains(&i);

    // Encrypt payloads AND the pertinence bits (PV encrypted -> oblivious).
    let payloads: Vec<_> = payloads_pt
        .iter()
        .map(|m| key.encrypt(&mut rng, m))
        .collect();
    let pv: Vec<_> = (0..N_MSG)
        .map(|i| {
            let mut bit = [0i128; NB];
            bit[0] = i128::from(is_pert(i));
            key.encrypt(&mut rng, &bit)
        })
        .collect();

    // Vandermonde weights, k buckets.
    let weights: Vec<Vec<i128>> = (0..k)
        .map(|j| {
            let base = (j as i128 + 1) % TB;
            let mut row = Vec::with_capacity(N_MSG);
            let mut p = 1i128;
            for _ in 0..N_MSG {
                row.push(p);
                p = (p * base).rem_euclid(TB);
            }
            row
        })
        .collect();

    let buckets = compact_buckets(&pv, &payloads, &weights);
    assert_eq!(buckets.len(), k, "digest is k buckets, independent of N");

    let bucket_pt: Vec<[i128; NB]> = buckets.iter().map(|b| key.decrypt2(b)).collect();

    // invert the k x k support submatrix mod t and recover payloads
    let mut m: Vec<Vec<i128>> = (0..k)
        .map(|j| support.iter().map(|&i| weights[j][i] % TB).collect())
        .collect();
    let mut inv: Vec<Vec<i128>> = (0..k)
        .map(|i| (0..k).map(|j| i128::from(i == j)).collect())
        .collect();
    for col in 0..k {
        let pinv = inv_t(m[col][col]);
        for j in 0..k {
            m[col][j] = (m[col][j] * pinv).rem_euclid(TB);
            inv[col][j] = (inv[col][j] * pinv).rem_euclid(TB);
        }
        for r in 0..k {
            if r != col {
                let f = m[r][col];
                for j in 0..k {
                    m[r][j] = (m[r][j] - f * m[col][j]).rem_euclid(TB);
                    inv[r][j] = (inv[r][j] - f * inv[col][j]).rem_euclid(TB);
                }
            }
        }
    }
    for (c, &i) in support.iter().enumerate() {
        let recovered: Vec<i128> = (0..NB)
            .map(|pos| {
                (0..k).fold(0i128, |acc, j| {
                    (acc + inv[c][j] * bucket_pt[j][pos]).rem_euclid(TB)
                })
            })
            .collect();
        assert_eq!(
            recovered,
            payloads_pt[i].to_vec(),
            "recovered payload for index {i}"
        );
    }
}
