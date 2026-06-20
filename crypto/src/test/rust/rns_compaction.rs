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

// --- path 2: payload limb codec verified through the real compaction ---------

use blacknet_crypto::rns_compaction::{compact_buckets_bfv, join_limbs, split_limbs};

#[test]
fn limbed_payload_compaction_recovers_exactly() {
    // A ~16-bit payload (values < 257^2 = 66049) carried as two base-257 limbs,
    // so the compaction multiply could run in the low-noise t=257 ring. Here we
    // verify the limb mechanism end to end through the existing compaction;
    // correctness is modulus-independent and the t=257 noise win is measured.
    let mut rng = drg(91);
    let key = RnsRlwe::keygen(&mut rng);
    let base = 257i64;
    let n_limbs = 2usize;

    const N_MSG: usize = 4;
    let support = [0usize, 3];
    let k = support.len();
    let is_pert = |i: usize| support.contains(&i);

    // payloads with coefficients in [0, base^2)
    let payloads_pt: Vec<[i64; N]> = (0..N_MSG)
        .map(|m| core::array::from_fn(|i| ((m as i64 + 1) * 9173 + i as i64 * 7) % (base * base)))
        .collect();

    // encrypted pertinence bits Enc(PV)
    let pv: Vec<_> = (0..N_MSG)
        .map(|i| {
            let mut bit = [0i64; N];
            bit[0] = i64::from(is_pert(i));
            key.encrypt(&mut rng, &bit)
        })
        .collect();

    let weights = vandermonde_weights(k, N_MSG);

    // compact each limb independently, recover, then recombine
    let mut recovered_limbs: Vec<Vec<[i64; N]>> = vec![Vec::new(); k];
    for j in 0..n_limbs {
        let limb_payloads: Vec<_> = payloads_pt
            .iter()
            .map(|p| {
                let limb = split_limbs(p, base, n_limbs)[j];
                key.encrypt(&mut rng, &limb)
            })
            .collect();
        let buckets = compact_buckets_bfv(&limb_payloads, &pv, &weights);
        let bucket_pt: Vec<[i64; N]> = buckets.iter().map(|b| key.decrypt2(b)).collect();
        let recovered = recover_pertinent_payloads(&bucket_pt, &support, &weights);
        for c in 0..k {
            recovered_limbs[c].push(recovered[c]);
        }
    }

    for (c, &i) in support.iter().enumerate() {
        let rejoined = join_limbs(&recovered_limbs[c], base);
        assert_eq!(
            rejoined.to_vec(),
            payloads_pt[i].to_vec(),
            "limbed payload {i} recovered"
        );
    }
}

#[test]
fn limb_codec_roundtrips() {
    let base = 257i64;
    let v: [i64; N] = core::array::from_fn(|i| (i as i64 * 131 + 17) % (base * base * base));
    let limbs = split_limbs(&v, base, 3);
    for limb in &limbs {
        assert!(limb.iter().all(|&c| c >= 0 && c < base));
    }
    assert_eq!(join_limbs(&limbs, base).to_vec(), v.to_vec());
}
