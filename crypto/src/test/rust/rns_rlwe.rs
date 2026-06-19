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
