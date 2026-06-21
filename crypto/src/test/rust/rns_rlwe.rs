#![allow(clippy::missing_const_for_fn)]
/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Leveled RLWE over the RNS accumulator ring: round-trip and homomorphic
//! add/sub/plain-mul verified against cleartext, in the sound 2^88 regime.

#![allow(clippy::needless_range_loop)]

use blacknet_crypto::random::FastDRG;
use blacknet_crypto::rns::{NTT_DEGREE, RnsPoly};
use blacknet_crypto::rns_rlwe::{RnsRlwe, T};

const N: usize = NTT_DEGREE;

fn drg(b: u8) -> FastDRG {
    let mut s = [0u8; 32];
    s[0] = b;
    FastDRG::new(&s)
}

fn seeded_plaintext(seed: u64) -> [i64; N] {
    let mut x = seed | 1;
    core::array::from_fn(|_| {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (x >> 48) as i64 % T
    })
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let mut rng = drg(1);
    let key = RnsRlwe::keygen(&mut rng);
    let m = seeded_plaintext(42);
    let ct = key.encrypt(&mut rng, &m);
    let back = key.decrypt(&ct);
    assert_eq!(back.to_vec(), m.to_vec(), "round-trip over the RNS ring");
}

#[test]
fn homomorphic_add_and_sub() {
    let mut rng = drg(2);
    let key = RnsRlwe::keygen(&mut rng);
    let m1 = seeded_plaintext(7);
    let m2 = seeded_plaintext(9);
    let c1 = key.encrypt(&mut rng, &m1);
    let c2 = key.encrypt(&mut rng, &m2);

    let sum = key.decrypt(&c1.add(&c2));
    let dif = key.decrypt(&c1.sub(&c2));
    for i in 0..N {
        assert_eq!(sum[i], (m1[i] + m2[i]).rem_euclid(T), "add at {i}");
        assert_eq!(dif[i], (m1[i] - m2[i]).rem_euclid(T), "sub at {i}");
    }
}

#[test]
fn plaintext_multiply_matches_negacyclic() {
    // Multiply a ciphertext by a cleartext polynomial; result decrypts to the
    // negacyclic product mod t. (OMR compaction's public bucket weights are
    // exactly such cleartext multipliers.) Small operands keep the plaintext
    // product well within t for an exact check without modular wraparound
    // surprises in the reference.
    let mut rng = drg(3);
    let key = RnsRlwe::keygen(&mut rng);

    // sparse cleartext multiplier: weight 5 at position 0 only -> scales coeffs
    let mut weight = [0i64; N];
    weight[0] = 5;
    let wpoly = RnsPoly::from_coefficients(&core::array::from_fn(|i| i128::from(weight[i])));

    let mut m = [0i64; N];
    for (i, slot) in m.iter_mut().take(8).enumerate() {
        *slot = (i as i64) + 1; // small
    }
    let ct = key.encrypt(&mut rng, &m);
    let out = key.decrypt(&ct.plain_mul(&wpoly));
    for i in 0..N {
        assert_eq!(out[i], (5 * m[i]).rem_euclid(T), "scaled coeff {i}");
    }
}

#[test]
fn fresh_noise_has_large_margin() {
    // The phase noise after a fresh encryption is tiny relative to Δ/2 ~ 2^71,
    // which is why ciphertext multiplication (needed for compaction) is sound
    // here though it overflowed the LM ring. We check decryption still succeeds
    // after summing many ciphertexts (noise grows additively).
    let mut rng = drg(4);
    let key = RnsRlwe::keygen(&mut rng);
    let m = seeded_plaintext(11);
    let mut acc = key.encrypt(&mut rng, &m);
    let mut expect = m;
    for _ in 0..63 {
        acc = acc.add(&key.encrypt(&mut rng, &m));
        for i in 0..N {
            expect[i] = (expect[i] + m[i]).rem_euclid(T);
        }
    }
    assert_eq!(
        key.decrypt(&acc).to_vec(),
        expect.to_vec(),
        "64-fold sum still decrypts"
    );
}

// --- External product / CMux over the RNS ring (step 3 core) ----------------

use blacknet_crypto::rns_rlwe::{cmux, external_product};

#[test]
#[ignore = "heavy RGSW keys at N=2048 exceed the default stack; math is degree-agnostic (validated at N=1024). Run with --ignored RUST_MIN_STACK=268435456"]
fn external_product_multiplies_by_the_rgsw_scalar() {
    let mut rng = drg(20);
    let key = RnsRlwe::keygen(&mut rng);
    let m = seeded_plaintext(5);
    let ct = key.encrypt(&mut rng, &m);

    // RGSW(1) · Enc(m) = Enc(m); RGSW(0) · Enc(m) = Enc(0).
    let one = key.rgsw_encrypt(&mut rng, 1);
    let zero = key.rgsw_encrypt(&mut rng, 0);

    let prod_one = key.decrypt(&external_product(&one, &ct));
    let prod_zero = key.decrypt(&external_product(&zero, &ct));
    for i in 0..N {
        assert_eq!(
            prod_one[i], m[i],
            "RGSW(1) external product is the identity at {i}"
        );
        assert_eq!(prod_zero[i], 0, "RGSW(0) external product is zero at {i}");
    }
}

#[test]
#[ignore = "heavy RGSW keys at N=2048 exceed the default stack; math is degree-agnostic (validated at N=1024). Run with --ignored RUST_MIN_STACK=268435456"]
fn cmux_selects_between_ciphertexts() {
    let mut rng = drg(21);
    let key = RnsRlwe::keygen(&mut rng);
    let m0 = seeded_plaintext(2);
    let m1 = seeded_plaintext(3);
    let c0 = key.encrypt(&mut rng, &m0);
    let c1 = key.encrypt(&mut rng, &m1);

    let sel0 = key.rgsw_encrypt(&mut rng, 0);
    let sel1 = key.rgsw_encrypt(&mut rng, 1);

    let picked0 = key.decrypt(&cmux(&sel0, &c0, &c1));
    let picked1 = key.decrypt(&cmux(&sel1, &c0, &c1));
    for i in 0..N {
        assert_eq!(picked0[i], m0[i], "CMux(0) selects c0 at {i}");
        assert_eq!(picked1[i], m1[i], "CMux(1) selects c1 at {i}");
    }
}

// --- Blind rotation over the RNS ring (step 3, rotation engine) -------------

use blacknet_crypto::rns_rlwe::{blind_rotate, trivial_encrypt};

#[test]
#[ignore = "heavy RGSW keys at N=2048 exceed the default stack; math is degree-agnostic (validated at N=1024). Run with --ignored RUST_MIN_STACK=268435456"]
fn blind_rotation_matches_cleartext_rotation() {
    let mut rng = drg(30);
    let key = RnsRlwe::keygen(&mut rng);

    // A small test polynomial and a set of secret bits + public rotations.
    let mut f = [0i64; N];
    for (i, slot) in f.iter_mut().take(16).enumerate() {
        *slot = (i as i64 * 3 + 1) % T;
    }
    let bits = [1i64, 0, 1, 1, 0, 1, 0, 0];
    let rotations = [5i64, 9, 2, 7, 11, 3, 13, 4];
    let phase: i64 = bits.iter().zip(rotations.iter()).map(|(s, r)| s * r).sum();

    // Bootstrapping key: RGSW of each secret bit.
    let bsk: Vec<_> = bits
        .iter()
        .map(|&b| key.rgsw_encrypt(&mut rng, i128::from(b)))
        .collect();

    let acc = trivial_encrypt(&f);
    let rotated = blind_rotate(&acc, &rotations, &bsk);
    let got = key.decrypt(&rotated);

    // Cleartext: X^phase · f in the negacyclic ring.
    let mut expect = [0i64; N];
    for (i, &fi) in f.iter().enumerate() {
        let k = (i as i64 + phase).rem_euclid(2 * N as i64) as usize;
        if k < N {
            expect[k] = fi.rem_euclid(T);
        } else {
            expect[k - N] = (-fi).rem_euclid(T);
        }
    }
    for i in 0..N {
        assert_eq!(
            got[i], expect[i],
            "blind rotation must equal X^phase·f at {i}"
        );
    }
}

// --- Sample extraction + programmable bootstrap (step 3 finish) -------------

use blacknet_crypto::rns_rlwe::{bootstrap_keygen, programmable_bootstrap, sample_extract};

#[test]
fn sample_extract_roundtrip() {
    let mut rng = drg(40);
    let key = RnsRlwe::keygen(&mut rng);
    let m = seeded_plaintext(77);
    let ct = key.encrypt(&mut rng, &m);
    for &k in &[0usize, 1, 17, 500, 1023] {
        let lwe = sample_extract(&ct, k);
        assert_eq!(key.lwe_decrypt(&lwe), m[k], "extracted coeff {k}");
    }
}

use blacknet_crypto::rns_rlwe::BOOTSTRAP_LWE_DIM;
const BOOT_N: usize = BOOTSTRAP_LWE_DIM; // secure (>=128-bit at q=2N); see lib note

// Build an input LWE (in the 2N domain) with a chosen phase under a binary
// secret: phase = b + <a, secret>.
fn boot_lwe(secret: &[i64; BOOT_N], phase: i64, rng: &mut FastDRG) -> ([i64; BOOT_N], i64) {
    use blacknet_crypto::random::{Distribution, UniformIntDistribution};
    let mut uid = UniformIntDistribution::<i64, FastDRG>::new(0..(2 * N as i64));
    let a: [i64; BOOT_N] = core::array::from_fn(|_| uid.sample(rng));
    let inner: i64 = a.iter().zip(secret.iter()).map(|(x, s)| x * s).sum();
    let b = (phase - inner).rem_euclid(2 * N as i64);
    (a, b)
}

#[test]
#[ignore = "slow (~4.5min): secure blind rotation at n_lwe=742, N=2048; VALIDATED decodes exactly. run with --ignored RUST_MIN_STACK=805306368"]
fn programmable_bootstrap_evaluates_lut() {
    let mut rng = drg(41);
    let key = RnsRlwe::keygen(&mut rng);
    let secret: [i64; BOOT_N] = core::array::from_fn(|i| (i % 2) as i64);
    let bsk = bootstrap_keygen(&mut rng, &key, &secret);

    // A negacyclic test vector: tv[k] = k mod small range on the lower half.
    let tv: [i64; N] = core::array::from_fn(|k| if k < N { (k as i64 / 64) % 7 } else { 0 });

    for &phase in &[100i64, 300, 700] {
        let (a, b) = boot_lwe(&secret, phase, &mut rng);
        let out = programmable_bootstrap(&bsk, &tv, &a, b);
        let got = key.lwe_decrypt(&sample_extract(&out, 0));
        assert_eq!(
            got, tv[phase as usize],
            "PBS must evaluate tv at phase {phase}"
        );
    }
}

// --- Step 4: homomorphic pertinence bit via half-domain PBS -----------------

use blacknet_crypto::rns_rlwe::{encode_half_domain, half_domain_test_vector};

#[test]
#[ignore = "slow: blind rotation; run with --ignored"]
fn homomorphic_pertinence_bit_via_half_domain() {
    let mut rng = drg(45);
    let key = RnsRlwe::keygen(&mut rng);
    let secret: [i64; BOOT_N] = core::array::from_fn(|i| (i % 2) as i64);
    let bsk = bootstrap_keygen(&mut rng, &key, &secret);

    // Pertinence predicate over p=8 classes: in-band classes {0,3,5} -> PV=1.
    let p = 8;
    let pertinent = [1i64, 0, 0, 1, 0, 1, 0, 0];
    let tv = half_domain_test_vector(&pertinent, p);

    for m in 0..p {
        let phase = encode_half_domain(m, p);
        let (a, b) = boot_lwe(&secret, phase, &mut rng);
        let out = programmable_bootstrap(&bsk, &tv, &a, b);
        let pv = key.lwe_decrypt(&sample_extract(&out, 0));
        assert_eq!(pv, pertinent[m], "homomorphic PV for class {m}");
    }
}

// --- Packing key-switch LWE -> RLWE (circuit-bootstrap prerequisite) ---------

use blacknet_crypto::rns_rlwe::{packing_keyswitch, packing_keyswitch_keygen};

#[test]
fn packing_keyswitch_lands_message_in_constant_coefficient() {
    let mut rng = drg(60);
    let target = RnsRlwe::keygen(&mut rng);

    // Small source LWE key z and a message m, encrypted as a dim-n LWE with
    // phase = b + <a, z> = Delta*m.
    const NSRC: usize = 16;
    use blacknet_crypto::random::{Distribution, UniformIntDistribution};
    let mut tern = UniformIntDistribution::<i64, FastDRG>::new(-1..=1);
    let z: [i64; NSRC] = core::array::from_fn(|_| tern.sample(&mut rng));
    let ksk = packing_keyswitch_keygen(&mut rng, &z, &target);

    let delta = blacknet_crypto::rns_rlwe::delta();
    let p = {
        use blacknet_crypto::rns::RnsInt;
        RnsInt::product()
    };
    for &m in &[0i64, 1, 1234, 65000] {
        // build LWE(m): a uniform, b = Delta*m - <a,z>  (so b + <a,z> = Delta*m)
        let mut uid = UniformIntDistribution::<i64, FastDRG>::new(0..1_000_000);
        let a: [i128; NSRC] = core::array::from_fn(|_| i128::from(uid.sample(&mut rng)));
        let inner: i128 = a
            .iter()
            .zip(z.iter())
            .map(|(ai, zi)| ai * i128::from(*zi))
            .sum();
        let b = (delta * i128::from(m) - inner).rem_euclid(p);

        let rlwe = packing_keyswitch(&ksk, &a, b);
        let recovered = target.decrypt(&rlwe);
        assert_eq!(
            recovered[0], m,
            "packed message in constant coefficient for m={m}"
        );
    }
}

// --- BFV ct*ct multiply at the real 2^88 modulus (bigint tensor) -------------

use blacknet_crypto::rns_rlwe::bfv_mul_rns;

#[test]
fn bfv_multiply_at_2pow88_matches_cleartext() {
    let mut rng = drg(71);
    let key = RnsRlwe::keygen(&mut rng);
    // small operands so the negacyclic product stays within t for the check
    let mut a = [0i64; 2048];
    let mut b = [0i64; 2048];
    for i in 0..3 {
        a[i] = (i as i64) + 2;
        b[i] = (3 * i as i64) + 1;
    }
    let ca = key.encrypt_cmp(&mut rng, &a);
    let cb = key.encrypt_cmp(&mut rng, &b);
    let prod = key.decrypt2(&bfv_mul_rns(&ca, &cb));

    let t = 257i64;
    let mut expect = [0i64; 2048];
    for i in 0..2048 {
        for j in 0..2048 {
            let mut k = i + j;
            let mut p = a[i] * b[j];
            if k >= 2048 {
                k -= 2048;
                p = -p;
            }
            expect[k] = (expect[k] + p).rem_euclid(t);
        }
    }
    for i in 0..2048 {
        assert_eq!(prod[i], expect[i], "2^88 BFV product at coeff {i}");
    }
}

#[test]
fn bfv_oblivious_select_at_2pow88() {
    // Enc(1)*Enc(payload) = payload; Enc(0)*Enc(payload) = 0, at the real modulus.
    let mut rng = drg(72);
    let key = RnsRlwe::keygen(&mut rng);
    let mut payload = [0i64; 2048];
    for (i, v) in payload.iter_mut().enumerate() {
        *v = ((i * 37 + 11) % 257) as i64;
    }
    let cp = key.encrypt_cmp(&mut rng, &payload);
    let mut one = [0i64; 2048];
    one[0] = 1;
    let c1 = key.encrypt_cmp(&mut rng, &one);
    let c0 = key.encrypt_cmp(&mut rng, &[0i64; 2048]);

    let sel1 = key.decrypt2(&bfv_mul_rns(&c1, &cp));
    let sel0 = key.decrypt2(&bfv_mul_rns(&c0, &cp));
    assert_eq!(
        sel1.to_vec(),
        payload.to_vec(),
        "PV=1 selects full payload at 2^88"
    );
    assert!(sel0.iter().all(|&v| v == 0), "PV=0 masks to zero at 2^88");
}

#[test]
fn oblivious_bandwidth_lite_compaction_secure_limbed() {
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(|| {
            use blacknet_crypto::rns_compaction::{
                compact_buckets_bfv, recover_pertinent_payloads, vandermonde_weights,
            };

            let mut rng = drg(73);
            let key = RnsRlwe::keygen(&mut rng);
            let t = 257i64;

            const N_MSG: usize = 4;
            let support = [1usize, 2];
            let k = support.len();
            let mk = |seed: i64| -> [i64; 2048] {
                core::array::from_fn(|i| ((seed * 101 + i as i64 * 7) % t).rem_euclid(t))
            };
            let payloads_pt: Vec<[i64; 2048]> = (0..N_MSG).map(|i| mk(i as i64 + 1)).collect();
            let is_pert = |i: usize| support.contains(&i);

            // Encrypt payloads AND the pertinence bits as RLWE Enc(PV) (the obliviously-
            // producible step-4 output). The node never sees PV or the payloads.
            let payloads: Vec<_> = payloads_pt
                .iter()
                .map(|m| key.encrypt_cmp(&mut rng, m))
                .collect();
            let pv: Vec<_> = (0..N_MSG)
                .map(|i| {
                    let mut bit = [0i64; 2048];
                    bit[0] = i64::from(is_pert(i));
                    key.encrypt_cmp(&mut rng, &bit)
                })
                .collect();

            // The actual library pipeline: public weights -> homomorphic buckets ->
            // decrypt (degree-2) -> recipient solve.
            let weights = vandermonde_weights(k, N_MSG, 257);
            let buckets = compact_buckets_bfv(&payloads, &pv, &weights);
            assert_eq!(buckets.len(), k, "digest is k buckets, independent of N");

            let bucket_pt: Vec<[i64; 2048]> = buckets.iter().map(|b| key.decrypt2(b)).collect();
            let recovered = recover_pertinent_payloads(&bucket_pt, &support, &weights, 257);

            for (c, &i) in support.iter().enumerate() {
                assert_eq!(
                    recovered[c].to_vec(),
                    payloads_pt[i].to_vec(),
                    "recovered payload {i} at secure N=2048, t=257"
                );
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

use blacknet_crypto::rns_rlwe::bfv_mul_rns_ref;
use std::time::Instant;

#[test]
fn bfv_fast_matches_reference_and_cleartext() {
    let mut rng = drg(81);
    let key = RnsRlwe::keygen(&mut rng);
    // full-entropy operands (uniform masks) so the tensor exercises the full range
    let a: [i64; 2048] = core::array::from_fn(|i| ((i * 31 + 7) % 257) as i64);
    let b: [i64; 2048] = core::array::from_fn(|i| ((i * 17 + 3) % 257) as i64);
    let ca = key.encrypt_cmp(&mut rng, &a);
    let cb = key.encrypt_cmp(&mut rng, &b);

    let t0 = Instant::now();
    let fast = bfv_mul_rns(&ca, &cb);
    let dt_fast = t0.elapsed();
    let t1 = Instant::now();
    let refr = bfv_mul_rns_ref(&ca, &cb);
    let dt_ref = t1.elapsed();

    // fast must equal the reference bit-for-bit after decryption
    assert_eq!(
        key.decrypt2(&fast).to_vec(),
        key.decrypt2(&refr).to_vec(),
        "fast != ref"
    );

    // and both must equal the cleartext negacyclic product mod t
    let t = 257i64;
    let mut expect = [0i64; 2048];
    for i in 0..2048 {
        for j in 0..2048 {
            let mut k = i + j;
            let mut p = a[i] * b[j];
            if k >= 2048 {
                k -= 2048;
                p = -p;
            }
            expect[k] = (expect[k] + p).rem_euclid(t);
        }
    }
    assert_eq!(
        key.decrypt2(&fast).to_vec(),
        expect.to_vec(),
        "fast != cleartext"
    );
    println!(
        "fast {:?}  ref {:?}  speedup {:.1}x",
        dt_fast,
        dt_ref,
        dt_ref.as_secs_f64() / dt_fast.as_secs_f64()
    );
}

// --- LWE->LWE key-switch (dimension reduction) and the full front-end chain --

use blacknet_crypto::rns_rlwe::{lwe_keyswitch, modulus_switch_to_2n};

#[test]
#[ignore = "slow: dim-2048 key-switch keygen; run with --ignored"]
fn lwe_keyswitch_preserves_message() {
    let mut rng = drg(101);
    let key = RnsRlwe::keygen(&mut rng);
    const NB: usize = 16;
    let bootstrap_key: [i64; NB] = core::array::from_fn(|i| (i % 2) as i64);
    let ksk = key.lwe_keyswitch_keygen(&mut rng, &bootstrap_key);

    // encrypt a message, sample-extract a few coefficients, key-switch, decrypt
    // under the small bootstrap key.
    let mut m = [0i64; 2048];
    for (i, v) in m.iter_mut().enumerate() {
        *v = ((i * 13 + 5) % 257) as i64;
    }
    let ct = key.encrypt_cmp(&mut rng, &m);
    for &idx in &[0usize, 1, 17, 500, 1023] {
        let lwe = sample_extract(&ct, idx);
        let switched = lwe_keyswitch(&ksk, &lwe);
        let got = RnsRlwe::lwe_decrypt_under(&bootstrap_key, &switched);
        assert_eq!(got, m[idx], "key-switched message at coeff {idx}");
    }
}

#[test]
#[ignore = "slow: dim-2048 key-switch keygen + blind rotation; run with --ignored"]
fn front_end_chain_clue_to_pertinence_bit() {
    use blacknet_crypto::rns_detect::{RnsDetectionKey, oblivious_detect};
    use blacknet_crypto::rns_rlwe::{
        bootstrap_keygen, encode_half_domain, half_domain_test_vector, programmable_bootstrap,
    };

    let mut rng = drg(102);
    let key = RnsRlwe::keygen(&mut rng);
    const NB: usize = 16;
    let bootstrap_key: [i64; NB] = core::array::from_fn(|i| (i % 2) as i64);
    let bsk = bootstrap_keygen(&mut rng, &key, &bootstrap_key);
    let ksk = key.lwe_keyswitch_keygen(&mut rng, &bootstrap_key);

    // A toy pertinence predicate over p=8 phase classes (the exact BlackLemon
    // bands need finer rotation; this verifies the wiring end to end).
    let p = 8usize;
    let pertinent = [1i64, 0, 0, 1, 0, 1, 0, 0];
    let tv = half_domain_test_vector(&pertinent, p);

    // Build Enc(d) via the front end where d's first coefficient encodes a chosen
    // class; the rest are arbitrary. We only bootstrap coefficient 0 here.
    let class = 3usize; // pertinent
    let s = [0i64; 2048];
    let mut skb = [0i64; 2048];
    let ca = [0i64; 2048];
    let cb = [0i64; 2048];
    // With s, cb, ca = 0 we have d = sk.b. Choose d[0] so the modulus-switched
    // PBS phase (message * 2N/T) lands on the class slot encode_half_domain.
    let phase_target = encode_half_domain(class, p) as i128; // in [0, N)
    let two_n = 2 * 1024i128;
    skb[0] = ((phase_target * 65537 + two_n / 2) / two_n) as i64;
    let dk = RnsDetectionKey::generate(&key, &mut rng, &s, &skb);
    let enc_d = oblivious_detect(&dk, &ca, &cb);

    // chain: sample_extract -> key-switch -> modulus switch -> PBS
    let lwe = sample_extract(&enc_d, 0);
    let switched = lwe_keyswitch(&ksk, &lwe);
    let lwe_a: Vec<i64> = switched
        .a
        .iter()
        .map(|&x| modulus_switch_to_2n(x))
        .collect();
    let lwe_b = modulus_switch_to_2n(switched.b);
    let out = programmable_bootstrap(&bsk, &tv, &lwe_a, lwe_b);
    let pv = key.lwe_decrypt(&sample_extract(&out, 0));
    assert_eq!(pv, pertinent[class], "clue -> Enc(d) -> KS -> PBS -> PV");
}

// --- exact BlackLemon band classifier at the real modulus q = 65537 ----------

use blacknet_crypto::rns_rlwe::{BAND_PHASE_SHIFT, band_classifier_test_vector};

#[test]
#[ignore = "slow: 12 blind rotations at q=65537; run with --ignored"]
fn exact_blacklemon_band_classifier_at_q65537() {
    let mut rng = drg(120);
    let key = RnsRlwe::keygen(&mut rng);
    let secret: [i64; BOOT_N] = core::array::from_fn(|i| (i % 2) as i64);
    let bsk = bootstrap_keygen(&mut rng, &key, &secret);

    let q = 65537i64;
    let two_n = 2 * N as i64;
    let delta = q / 2; // 32768
    let r = 40i64; // BlackLemon R
    let mark = 1i64;
    let tv = band_classifier_test_vector(mark, 1);

    // exact BlackLemon classification of a balanced coefficient d:
    //   |d| <= R           -> 0-band (payload bit 0)
    //   DELTA - |d| <= R   -> 1-band (payload bit 1)
    //   else               -> out of band (reject)
    let oracle = |d: i64| -> i32 {
        let a = d.abs();
        if a <= r {
            0
        } else if delta - a <= r {
            1
        } else {
            -1
        }
    };

    // phase of a coefficient after modulus switch (round(d*2N/q)), then the
    // classifier's N/2 pre-shift folded into the LWE body.
    let phase_of = |d: i64| -> i64 {
        let num = d * two_n;
        let rounded = if num >= 0 {
            (num + q / 2) / q
        } else {
            (num - q / 2) / q
        };
        (rounded + BAND_PHASE_SHIFT).rem_euclid(two_n)
    };

    // sweep: solid 0-band, solid 1-band, and clearly out-of-band values
    let zero_band = [0i64, 24, 40, -32];
    let one_band = [delta, delta - 24, delta - 40, -(delta - 16)];
    let out_band = [96i64, 1000, 16384, -12000];

    for &d in &zero_band {
        let (a, b) = boot_lwe(&secret, phase_of(d), &mut rng);
        let out = programmable_bootstrap(&bsk, &tv, &a, b);
        let v = key.lwe_decrypt_signed(&sample_extract(&out, 0));
        assert_eq!(oracle(d), 0, "oracle sanity 0-band d={d}");
        assert_eq!(v, mark, "0-band d={d} should classify to +mark");
    }
    for &d in &one_band {
        let (a, b) = boot_lwe(&secret, phase_of(d), &mut rng);
        let out = programmable_bootstrap(&bsk, &tv, &a, b);
        let v = key.lwe_decrypt_signed(&sample_extract(&out, 0));
        assert_eq!(oracle(d), 1, "oracle sanity 1-band d={d}");
        assert_eq!(v, -mark, "1-band d={d} should classify to -mark (antipode)");
    }
    for &d in &out_band {
        let (a, b) = boot_lwe(&secret, phase_of(d), &mut rng);
        let out = programmable_bootstrap(&bsk, &tv, &a, b);
        let v = key.lwe_decrypt_signed(&sample_extract(&out, 0));
        assert_eq!(oracle(d), -1, "oracle sanity out-of-band d={d}");
        assert_eq!(v, 0, "out-of-band d={d} should classify to 0");
    }
}
