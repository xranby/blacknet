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

const BOOT_N: usize = 16;

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
#[ignore = "slow: blind rotation over N=1024; run with --ignored"]
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
