/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Step 5 end-to-end: oblivious, bandwidth-lite compaction. N encrypted
//! payloads + encrypted pertinence -> k buckets (k << N) -> recipient recovers
//! exactly its payloads. Non-pertinent messages drop out homomorphically.

use blacknet_crypto::random::FastDRG;
use blacknet_crypto::rns::NTT_DEGREE;
use blacknet_crypto::rns_compaction::{
    compact_buckets, recover_pertinent_payloads, vandermonde_weights,
};
use blacknet_crypto::rns_rlwe::{RnsRlwe, T};

const N: usize = NTT_DEGREE;

fn drg(b: u8) -> FastDRG {
    let mut s = [0u8; 32];
    s[0] = b;
    FastDRG::new(&s)
}

fn payload(seed: u64) -> [i64; N] {
    let mut x = seed | 1;
    core::array::from_fn(|_| {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (x >> 48) as i64 % T
    })
}

#[test]
fn oblivious_bandwidth_lite_compaction_recovers_exactly_pertinent_payloads() {
    let mut rng = drg(50);
    let key = RnsRlwe::keygen(&mut rng);

    // A board of N_MSG messages; only the support indices are the recipient's.
    const N_MSG: usize = 16;
    let support = [2usize, 7, 11];
    let k = support.len();

    // Per-message plaintext payloads (distinct), and the pertinence bits.
    let payloads_pt: Vec<[i64; N]> = (0..N_MSG).map(|i| payload(100 + i as u64)).collect();
    let is_pertinent = |i: usize| support.contains(&i);

    // Encrypt payloads; encrypt pertinence as RGSW(0/1) (this RGSW(PV) is the
    // output of step 4's detection fold — supplied here directly).
    let payloads_ct: Vec<_> = payloads_pt
        .iter()
        .map(|m| key.encrypt(&mut rng, m))
        .collect();
    let pv: Vec<_> = (0..N_MSG)
        .map(|i| key.rgsw_encrypt(&mut rng, i128::from(is_pertinent(i))))
        .collect();

    // Node: compact to k buckets (the digest is O(k), not O(N)).
    let weights = vandermonde_weights(k, N_MSG);
    let buckets_ct = compact_buckets(&payloads_ct, &pv, &weights);
    assert_eq!(buckets_ct.len(), k, "digest is k buckets, independent of N");

    // Recipient: decrypt buckets, solve for the pertinent payloads.
    let buckets_pt: Vec<[i64; N]> = buckets_ct.iter().map(|c| key.decrypt(c)).collect();
    let recovered = recover_pertinent_payloads(&buckets_pt, &support, &weights);

    // Exactly the recipient's payloads, in support order.
    for (c, &i) in support.iter().enumerate() {
        assert_eq!(
            recovered[c].to_vec(),
            payloads_pt[i].to_vec(),
            "recovered payload for support index {i}"
        );
    }
}

#[test]
fn non_pertinent_only_board_compacts_to_zero() {
    // If none of the messages are the recipient's (all PV = 0), every bucket
    // decrypts to zero — nothing is recovered, and nothing leaks.
    let mut rng = drg(51);
    let key = RnsRlwe::keygen(&mut rng);
    const N_MSG: usize = 8;
    let payloads_ct: Vec<_> = (0..N_MSG)
        .map(|i| key.encrypt(&mut rng, &payload(200 + i as u64)))
        .collect();
    let pv: Vec<_> = (0..N_MSG).map(|_| key.rgsw_encrypt(&mut rng, 0)).collect();

    let weights = vandermonde_weights(3, N_MSG);
    let buckets = compact_buckets(&payloads_ct, &pv, &weights);
    for b in &buckets {
        assert!(
            key.decrypt(b).iter().all(|&c| c == 0),
            "all-zero pertinence -> zero buckets"
        );
    }
}
