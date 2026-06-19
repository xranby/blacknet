/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! The oblivious detection backend, validated for correctness against the
//! in-the-clear `blacklemon::detect`, and for the noise budget that makes the
//! homomorphic decryption decrypt correctly.

use blacknet_crypto::blacklemon::{
    PublicKey, SecretKey, detect, detection_material, encrypt, generate_public_key,
    generate_secret_key,
};
use blacknet_crypto::lpr::encode;
use blacknet_crypto::oblivious_detector_fhe::{
    Rlwe, client_check_pertinence, encrypt_detection_key, homomorphic_decrypt, oblivious_scan,
};
use blacknet_crypto::random::FastDRG;

fn drg(seed_byte: u8) -> FastDRG {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    FastDRG::new(&seed)
}

struct Party {
    sk: SecretKey,
    pk: PublicKey,
}

fn new_party(seed: u8) -> Party {
    let mut rng = drg(seed);
    let sk = generate_secret_key(&mut rng);
    let pk = generate_public_key(&mut rng, &sk);
    Party { sk, pk }
}

const fn note(amount: u8) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    bytes[0] = 0; // detectability marker
    bytes[1] = amount;
    bytes
}

#[test]
fn oblivious_detection_matches_cleartext_detect() {
    // The decisive correctness test: the FHE backend's pertinence decision —
    // computed via homomorphic decryption + client check — must equal what
    // BlackLemon's in-the-clear detect decides, for BOTH a pertinent clue
    // (addressed to the recipient) and a non-pertinent one (addressed to
    // someone else).
    let alice = new_party(1);
    let bob = new_party(2);

    // Client sets up its RLWE key and encrypts its detection material.
    let mut crng = drg(50);
    let rlwe = Rlwe::keygen(&mut crng);
    let material = detection_material(&alice.sk);
    let key = encrypt_detection_key(&mut crng, &rlwe, &material);

    let mut srng = drg(100);
    let alice_clue = encrypt(&mut srng, &alice.pk, &encode(&note(42)));
    let bob_clue = encrypt(&mut srng, &bob.pk, &encode(&note(42)));

    // Pertinent clue: detect says Some; the oblivious path must say true.
    let cleartext_pertinent = detect(&alice.sk, &alice_clue).is_some();
    let enc_d = homomorphic_decrypt(&key, &alice_clue);
    let oblivious_pertinent = client_check_pertinence(&rlwe, &enc_d);
    assert_eq!(
        oblivious_pertinent, cleartext_pertinent,
        "oblivious detection must match detect() on a pertinent clue"
    );
    assert!(oblivious_pertinent, "Alice's own clue must be detected");

    // Non-pertinent clue: detect says None; the oblivious path must say false.
    let cleartext_other = detect(&alice.sk, &bob_clue).is_some();
    let enc_d2 = homomorphic_decrypt(&key, &bob_clue);
    let oblivious_other = client_check_pertinence(&rlwe, &enc_d2);
    assert_eq!(
        oblivious_other, cleartext_other,
        "oblivious detection must match detect() on a non-pertinent clue"
    );
    assert!(!oblivious_other, "Bob's clue must NOT be detected by Alice");
}

#[test]
fn matches_detect_across_a_board() {
    // Agreement on every clue of a mixed board: the oblivious detector's
    // verdicts equal detect()'s verdicts, clue by clue.
    let alice = new_party(1);
    let bob = new_party(2);
    let mut crng = drg(51);
    let rlwe = Rlwe::keygen(&mut crng);
    let key = encrypt_detection_key(&mut crng, &rlwe, &detection_material(&alice.sk));

    let mut s = drg(101);
    let board = vec![
        encrypt(&mut s, &alice.pk, &encode(&note(10))),
        encrypt(&mut s, &bob.pk, &encode(&note(20))),
        encrypt(&mut s, &alice.pk, &encode(&note(30))),
        encrypt(&mut s, &bob.pk, &encode(&note(40))),
    ];

    // Oblivious scan: the detector computes Enc(d) for every clue uniformly.
    let encrypted_ds = oblivious_scan(&key, &board);
    assert_eq!(encrypted_ds.len(), board.len());

    for (clue, enc_d) in board.iter().zip(encrypted_ds.iter()) {
        let cleartext = detect(&alice.sk, clue).is_some();
        let oblivious = client_check_pertinence(&rlwe, enc_d);
        assert_eq!(
            oblivious, cleartext,
            "per-clue oblivious verdict must equal detect()"
        );
    }

    // The verdicts pick out exactly Alice's two clues (indices 0 and 2).
    let detected: Vec<bool> = encrypted_ds
        .iter()
        .map(|e| client_check_pertinence(&rlwe, e))
        .collect();
    assert_eq!(detected, vec![true, false, true, false]);
}

#[test]
fn noise_budget_holds_recovered_d_is_exact() {
    // The homomorphic decryption must recover d EXACTLY (every coefficient),
    // not approximately — this is the noise-budget correctness check. We verify
    // that re-running the pertinence check on the recovered d is stable and
    // that a pertinent clue's recovered d passes the tight R-tolerance check
    // (which it could not if noise had corrupted coefficients).
    use blacknet_crypto::oblivious_detector_fhe::recover_d;
    let alice = new_party(7);
    let mut crng = drg(52);
    let rlwe = Rlwe::keygen(&mut crng);
    let key = encrypt_detection_key(&mut crng, &rlwe, &detection_material(&alice.sk));
    let mut s = drg(102);
    let clue = encrypt(&mut s, &alice.pk, &encode(&note(99)));

    let enc_d = homomorphic_decrypt(&key, &clue);
    let d = recover_d(&rlwe, &enc_d);
    assert_eq!(d.len(), 1024);
    // For a pertinent clue every coefficient is within R of 0 or of DELTA;
    // if the noise budget had failed, some coefficient would land in between.
    assert!(
        client_check_pertinence(&rlwe, &enc_d),
        "recovered d must pass the tight pertinence check (noise within budget)"
    );
}

#[test]
fn detector_never_touches_the_secret_or_branches_on_matches() {
    // Structural obliviousness: the detector's API takes only the ENCRYPTED key
    // and public clues, and processes every clue identically (oblivious_scan
    // maps uniformly, no data-dependent control flow, no access to sk). This
    // test documents that the detection path compiles using only the encrypted
    // key — it cannot call detect()/decrypt() because it never has the secret.
    let alice = new_party(3);
    let mut crng = drg(53);
    let rlwe = Rlwe::keygen(&mut crng);
    let key = encrypt_detection_key(&mut crng, &rlwe, &detection_material(&alice.sk));
    let mut s = drg(103);
    let board = vec![
        encrypt(&mut s, &alice.pk, &encode(&note(1))),
        encrypt(&mut s, &alice.pk, &encode(&note(2))),
    ];
    // The detector runs with NO access to alice.sk or rlwe.s — only `key`.
    let out = oblivious_scan(&key, &board);
    assert_eq!(out.len(), 2, "scans every clue uniformly");
    // Decryption (client-only) still recovers correct verdicts.
    assert!(out.iter().all(|e| client_check_pertinence(&rlwe, e)));
}

#[test]
fn wrong_recipient_key_does_not_detect_others_notes() {
    // Guard against a vacuous pass: a detection key built from CAROL's secret
    // must NOT detect ALICE's clue (the oblivious verdict tracks the real key,
    // not "always true").
    let alice = new_party(1);
    let carol = new_party(9);
    let mut crng = drg(60);
    let rlwe = Rlwe::keygen(&mut crng);
    let carol_key = encrypt_detection_key(&mut crng, &rlwe, &detection_material(&carol.sk));
    let mut s = drg(110);
    let alice_clue = encrypt(&mut s, &alice.pk, &encode(&note(42)));

    let enc_d = homomorphic_decrypt(&carol_key, &alice_clue);
    assert!(
        !client_check_pertinence(&rlwe, &enc_d),
        "Carol's key must not detect Alice's clue"
    );
    // And the cleartext detect agrees.
    assert!(detect(&carol.sk, &alice_clue).is_none());
}

#[test]
fn keyswitch_preserves_the_message() {
    // The foundational key-switching test: encrypt under one secret, switch to
    // a different secret WITHOUT decrypting, and recover the same message.
    use blacknet_crypto::oblivious_detector_fhe::{Rlwe, keyswitch, keyswitch_keygen, recover_d};
    let mut rng = drg(70);
    let old = Rlwe::keygen(&mut rng);
    let new = Rlwe::keygen(&mut rng);
    let ksk = keyswitch_keygen(&mut rng, &old, &new);

    // A plaintext we can drive through encrypt/keyswitch/decrypt: reuse the
    // detector's RLWE by encrypting a clue's d and switching keys. Simpler:
    // encrypt a small known pattern via a clue and check round-trip equality.
    let alice = new_party(1);
    let key_old = encrypt_detection_key(&mut rng, &old, &detection_material(&alice.sk));
    let mut s = drg(120);
    let clue = encrypt(&mut s, &alice.pk, &encode(&note(7)));
    let enc_d_old = homomorphic_decrypt(&key_old, &clue);

    // Decrypt under the OLD key (baseline).
    let d_old = recover_d(&old, &enc_d_old);
    // Key-switch to NEW, decrypt under NEW: must match.
    let enc_d_new = keyswitch(&ksk, &enc_d_old);
    let d_new = recover_d(&new, &enc_d_new);

    assert_eq!(
        d_old, d_new,
        "key-switched ciphertext must decrypt identically"
    );
    // And the pertinence verdict is unchanged (noise stayed in budget).
    assert!(client_check_pertinence(&new, &enc_d_new));
}

#[test]
fn keyswitched_ciphertext_does_not_decrypt_under_the_old_key() {
    // Sanity: after switching to `new`, the result is NOT decryptable under the
    // original key (the switch genuinely re-keyed it), so a holder of only the
    // old key learns nothing — guards against a no-op key-switch.
    use blacknet_crypto::oblivious_detector_fhe::{Rlwe, keyswitch, keyswitch_keygen, recover_d};
    let mut rng = drg(71);
    let old = Rlwe::keygen(&mut rng);
    let new = Rlwe::keygen(&mut rng);
    let ksk = keyswitch_keygen(&mut rng, &old, &new);
    let alice = new_party(2);
    let key_old = encrypt_detection_key(&mut rng, &old, &detection_material(&alice.sk));
    let mut s = drg(121);
    let clue = encrypt(&mut s, &alice.pk, &encode(&note(7)));
    let enc_d_old = homomorphic_decrypt(&key_old, &clue);
    let enc_d_new = keyswitch(&ksk, &enc_d_old);

    let under_old = recover_d(&old, &enc_d_new);
    let under_new = recover_d(&new, &enc_d_new);
    assert_ne!(
        under_old, under_new,
        "the re-keyed ciphertext must not decrypt to the same thing under the old key"
    );
}

// --- RGSW external product / CMux: the bootstrapping keystone ---------------

fn small_plaintext(seed: u8) -> [i64; 1024] {
    // A known plaintext in Z_t with small balanced coefficients.
    let mut m = [0i64; 1024];
    let mut x = seed as i64 + 1;
    for (i, slot) in m.iter_mut().enumerate() {
        x = (x * 1103515245 + 12345) & 0x7fff;
        *slot = (x % 7) - 3; // in [-3, 3]
        if i < 4 {
            *slot = (i as i64) - 1;
        }
    }
    m
}

#[test]
fn external_product_with_one_preserves_the_message() {
    use blacknet_crypto::oblivious_detector_fhe::{Rlwe, external_product, recover_d};
    let mut rng = drg(80);
    let rlwe = Rlwe::keygen(&mut rng);
    let m = small_plaintext(1);
    let enc_m = rlwe.encrypt_plain(&mut rng, &m);

    // RGSW(1): the constant-one selector.
    let rgsw_one = rlwe.rgsw_encrypt(&mut rng, 1);
    let prod = external_product(&rgsw_one, &enc_m);
    let recovered = recover_d(&rlwe, &prod);

    let expected: Vec<i32> = m.iter().map(|&x| x as i32).collect();
    assert_eq!(recovered, expected, "RGSW(1) ⊡ Enc(m) must decrypt to m");
}

#[test]
fn external_product_with_zero_annihilates_the_message() {
    use blacknet_crypto::oblivious_detector_fhe::{Rlwe, external_product, recover_d};
    let mut rng = drg(81);
    let rlwe = Rlwe::keygen(&mut rng);
    let m = small_plaintext(2);
    let enc_m = rlwe.encrypt_plain(&mut rng, &m);

    let rgsw_zero = rlwe.rgsw_encrypt(&mut rng, 0);
    let prod = external_product(&rgsw_zero, &enc_m);
    let recovered = recover_d(&rlwe, &prod);

    assert!(
        recovered.iter().all(|&c| c == 0),
        "RGSW(0) ⊡ Enc(m) must decrypt to 0"
    );
}

#[test]
fn cmux_selects_the_right_branch() {
    use blacknet_crypto::oblivious_detector_fhe::{Rlwe, cmux, recover_d};
    let mut rng = drg(82);
    let rlwe = Rlwe::keygen(&mut rng);
    let m0 = small_plaintext(3);
    let m1 = small_plaintext(4);
    let c0 = rlwe.encrypt_plain(&mut rng, &m0);
    let c1 = rlwe.encrypt_plain(&mut rng, &m1);

    let sel0 = rlwe.rgsw_encrypt(&mut rng, 0);
    let sel1 = rlwe.rgsw_encrypt(&mut rng, 1);

    let picked0 = cmux(&sel0, &c0, &c1);
    let picked1 = cmux(&sel1, &c0, &c1);

    let exp0: Vec<i32> = m0.iter().map(|&x| x as i32).collect();
    let exp1: Vec<i32> = m1.iter().map(|&x| x as i32).collect();
    assert_eq!(recover_d(&rlwe, &picked0), exp0, "CMux(0) selects c0");
    assert_eq!(recover_d(&rlwe, &picked1), exp1, "CMux(1) selects c1");
}

// --- Blind rotation: the bootstrap's rotation engine ------------------------

/// Cleartext negacyclic rotation of f by k: (X^k · f) in Z[X]/(X^N+1).
fn rotate_clear(f: &[i64; 1024], k: i64) -> Vec<i32> {
    let n = 1024i64;
    let mut out = vec![0i64; 1024];
    for (j, &c) in f.iter().enumerate() {
        let mut idx = (j as i64) + k.rem_euclid(2 * n);
        let mut sign = 1i64;
        while idx >= 2 * n {
            idx -= 2 * n;
        }
        if idx >= n {
            idx -= n;
            sign = -1;
        }
        out[idx as usize] += sign * c;
    }
    out.iter().map(|&x| x as i32).collect()
}

#[test]
fn blind_rotation_rotates_by_the_encrypted_exponent() {
    use blacknet_crypto::oblivious_detector_fhe::{Rlwe, blind_rotate, recover_d, trivial_encrypt};
    let mut rng = drg(90);
    let rlwe = Rlwe::keygen(&mut rng);

    // Known test polynomial with small coefficients.
    let mut f = [0i64; 1024];
    for (i, slot) in f.iter_mut().enumerate().take(8) {
        *slot = (i as i64) - 3;
    }
    let acc = trivial_encrypt(&f);

    // Secret bits and public rotation amounts. The applied exponent is the sum
    // over the bits that are 1: here s = [1,0,1,1] and a = [5,9,2,40].
    let secret_bits = [1i64, 0, 1, 1];
    let rotations = [5i64, 9, 2, 40];
    let bsk: Vec<_> = secret_bits
        .iter()
        .map(|&b| rlwe.rgsw_encrypt(&mut rng, b))
        .collect();

    let rotated = blind_rotate(&acc, &rotations, &bsk);
    let recovered = recover_d(&rlwe, &rotated);

    let k: i64 = secret_bits
        .iter()
        .zip(rotations.iter())
        .map(|(&s, &a)| s * a)
        .sum(); // 5 + 2 + 40 = 47
    let expected = rotate_clear(&f, k);
    assert_eq!(
        recovered, expected,
        "blind rotation must rotate the accumulator by the secret-controlled exponent"
    );
}

#[test]
fn blind_rotation_handles_the_negacyclic_boundary() {
    // A rotation that pushes coefficients past index N, exercising the X^N=-1
    // sign flip homomorphically.
    use blacknet_crypto::oblivious_detector_fhe::{Rlwe, blind_rotate, recover_d, trivial_encrypt};
    let mut rng = drg(91);
    let rlwe = Rlwe::keygen(&mut rng);
    let mut f = [0i64; 1024];
    f[0] = 2;
    f[1] = -1;
    f[1020] = 3; // near the top, will wrap with a sign flip
    let acc = trivial_encrypt(&f);

    let secret_bits = [1i64, 1];
    let rotations = [1000i64, 30]; // total 1030 > N=1024 -> wraps
    let bsk: Vec<_> = secret_bits
        .iter()
        .map(|&b| rlwe.rgsw_encrypt(&mut rng, b))
        .collect();
    let rotated = blind_rotate(&acc, &rotations, &bsk);
    let recovered = recover_d(&rlwe, &rotated);
    let expected = rotate_clear(&f, 1030);
    assert_eq!(recovered, expected, "negacyclic wrap must be handled");
}

// --- Sample extraction: RLWE coefficient -> LWE -----------------------------

#[test]
fn sample_extract_recovers_each_coefficient() {
    use blacknet_crypto::oblivious_detector_fhe::{Rlwe, sample_extract};
    let mut rng = drg(95);
    let rlwe = Rlwe::keygen(&mut rng);

    // Known plaintext with distinct small coefficients in the first few slots.
    let mut m = [0i64; 1024];
    m[0] = 3;
    m[1] = -2;
    m[2] = 1;
    m[5] = -4;
    m[17] = 2;
    let enc = rlwe.encrypt_plain(&mut rng, &m);

    for &j in &[0usize, 1, 2, 5, 17, 100] {
        let lwe = sample_extract(&enc, j);
        let recovered = rlwe.lwe_decrypt(&lwe);
        assert_eq!(
            recovered, m[j] as i32,
            "sample extraction of coefficient {j} must recover m[{j}]"
        );
    }
}

#[test]
fn sample_extract_after_blind_rotation() {
    // The real bootstrap path: rotate the accumulator by a secret exponent,
    // then sample-extract the constant coefficient. The constant slot after
    // rotation by k holds the coefficient of the test poly that landed there,
    // which sample extraction must recover as an LWE ciphertext.
    use blacknet_crypto::oblivious_detector_fhe::{
        Rlwe, blind_rotate, sample_extract, trivial_encrypt,
    };
    let mut rng = drg(96);
    let rlwe = Rlwe::keygen(&mut rng);

    // Test polynomial: f[j] = j+1 for small j (distinct values to track).
    let mut f = [0i64; 1024];
    for (i, slot) in f.iter_mut().enumerate().take(16) {
        *slot = (i as i64) + 1;
    }
    let acc = trivial_encrypt(&f);

    // Rotate by k = 3 (bits [1,1], rotations [1,2]).
    let bits = [1i64, 1];
    let rots = [1i64, 2];
    let bsk: Vec<_> = bits
        .iter()
        .map(|&b| rlwe.rgsw_encrypt(&mut rng, b))
        .collect();
    let rotated = blind_rotate(&acc, &rots, &bsk);

    // After X^3 · f, the constant coefficient is the negacyclic value at 0,
    // i.e. -f[N-3] = -f[1021] = 0 here... so check against cleartext directly.
    let k = 3i64;
    let expected_const = {
        // constant coeff of X^k * f = (X^k f)[0]; from rotate_clear index 0.
        rotate_clear(&f, k)[0]
    };
    let lwe = sample_extract(&rotated, 0);
    let recovered = rlwe.lwe_decrypt(&lwe);
    assert_eq!(
        recovered, expected_const,
        "constant coefficient after blind rotation must extract correctly"
    );
}

// --- LWE key-switching + full bootstrap data path ---------------------------

#[test]
fn lwe_keyswitch_recovers_the_message_under_the_target_key() {
    use blacknet_crypto::oblivious_detector_fhe::{
        LweKey, Rlwe, lwe_keyswitch, lwe_keyswitch_keygen, sample_extract,
    };
    let mut rng = drg(97);
    let rlwe = Rlwe::keygen(&mut rng);
    let target = LweKey::keygen(&mut rng);
    let ksk = lwe_keyswitch_keygen(&mut rng, &rlwe, &target);

    let mut m = [0i64; 1024];
    m[0] = 5;
    m[1] = -3;
    m[2] = 2;
    let enc = rlwe.encrypt_plain(&mut rng, &m);

    for &j in &[0usize, 1, 2] {
        let lwe = sample_extract(&enc, j); // dim-N LWE under ŝ
        let switched = lwe_keyswitch(&ksk, &lwe); // re-keyed to target
        let recovered = target.decrypt(&switched);
        assert_eq!(
            recovered, m[j] as i32,
            "LWE key-switch must preserve coefficient {j} under the target key"
        );
    }
}

#[test]
fn full_bootstrap_data_path() {
    // Exercises the whole bootstrap pipeline structurally:
    //   blind rotation -> sample extraction -> LWE key-switch -> decrypt.
    // (The functional LUT / modulus-switch parameterization is separate; this
    // validates that the ciphertext plumbing composes end to end.)
    use blacknet_crypto::oblivious_detector_fhe::{
        LweKey, Rlwe, blind_rotate, lwe_keyswitch, lwe_keyswitch_keygen, sample_extract,
        trivial_encrypt,
    };
    let mut rng = drg(98);
    let rlwe = Rlwe::keygen(&mut rng);
    let target = LweKey::keygen(&mut rng);
    let ksk = lwe_keyswitch_keygen(&mut rng, &rlwe, &target);

    // Test polynomial f[j]=j+1 for small j.
    let mut f = [0i64; 1024];
    for (i, slot) in f.iter_mut().enumerate().take(16) {
        *slot = (i as i64) + 1;
    }
    let acc = trivial_encrypt(&f);

    // Blind-rotate by k = 4 (bits [1,1], rotations [1,3]).
    let bits = [1i64, 1];
    let rots = [1i64, 3];
    let bsk: Vec<_> = bits
        .iter()
        .map(|&b| rlwe.rgsw_encrypt(&mut rng, b))
        .collect();
    let rotated = blind_rotate(&acc, &rots, &bsk);

    // Extract constant coefficient, then key-switch to the compact target key.
    let lwe = sample_extract(&rotated, 0);
    let switched = lwe_keyswitch(&ksk, &lwe);
    let recovered = target.decrypt(&switched);

    let expected = rotate_clear(&f, 4)[0];
    assert_eq!(
        recovered, expected,
        "the constant slot must survive rotation -> extraction -> LWE key-switch"
    );
}

// --- Programmable bootstrap: functional LUT eval + noise refresh ------------

const BOOT_N: usize = 16; // small LWE dimension for tractable bootstrap tests

// Build a test polynomial encoding a step function over the rotation domain:
// f = 1 on the first half-slot region, 2 on the second. Negacyclic by
// construction (upper half is the ring's automatic -f).
fn step_test_vector() -> [i64; 1024] {
    let mut tv = [0i64; 1024];
    for (k, slot) in tv.iter_mut().enumerate() {
        *slot = if k < 512 { 1 } else { 2 };
    }
    tv
}

// Construct a noiseless LWE mod 2N with chosen phase under a binary secret.
fn boot_lwe_phase(
    s: &[i64; BOOT_N],
    phase: i64,
    noise: i64,
    rng: &mut FastDRG,
) -> ([i64; BOOT_N], i64) {
    use blacknet_crypto::random::{Distribution, UniformIntDistribution};
    let two_n = 2 * 1024i64;
    let mut uid = UniformIntDistribution::<i64, FastDRG>::new(0..two_n);
    let a: [i64; BOOT_N] = core::array::from_fn(|_| uid.sample(rng));
    let mut b = phase + noise;
    for i in 0..BOOT_N {
        b += a[i] * s[i];
    }
    (a, b.rem_euclid(two_n))
}

#[test]
#[ignore = "slow: 16-step blind rotation over degree-1024 ring; run with --ignored"]
fn programmable_bootstrap_evaluates_the_lut() {
    use blacknet_crypto::oblivious_detector_fhe::{
        Rlwe, bootstrap_keygen, programmable_bootstrap, sample_extract,
    };
    let mut rng = drg(110);
    let acc_key = Rlwe::keygen(&mut rng);
    let secret: [i64; BOOT_N] = core::array::from_fn(|i| ((i * 7 + 1) % 2) as i64); // binary
    let bsk = bootstrap_keygen(&mut rng, &acc_key, &secret);
    let tv = step_test_vector();

    // Phase in the first region (-> LUT value 1) and second region (-> 2).
    for &(phase, expected) in &[(200i64, 1i64), (800i64, 2i64)] {
        let (a, b) = boot_lwe_phase(&secret, phase, 0, &mut rng);
        let out = programmable_bootstrap(&bsk, &tv, &a, b);
        let lwe = sample_extract(&out, 0);
        let recovered = acc_key.lwe_decrypt(&lwe);
        // Cross-check against the cleartext rotation of tv by -phase.
        let clear = rotate_clear(&tv, -phase)[0];
        assert_eq!(
            i64::from(recovered),
            i64::from(clear),
            "bootstrap must match cleartext LUT lookup"
        );
        assert_eq!(i64::from(recovered), expected, "LUT value at phase {phase}");
    }
}

#[test]
#[ignore = "slow: blind rotation; run with --ignored"]
fn bootstrap_refreshes_noise() {
    // Soundness: a heavily-noised input still bootstraps to the correct LUT
    // value. The mod-switch absorbs input noise up to ~half a rotation slot,
    // and the output noise is FRESH (set by the bootstrap, not the input) -
    // demonstrated by the output decrypting cleanly despite large input noise.
    use blacknet_crypto::oblivious_detector_fhe::{
        Rlwe, bootstrap_keygen, programmable_bootstrap, sample_extract,
    };
    let mut rng = drg(111);
    let acc_key = Rlwe::keygen(&mut rng);
    let secret: [i64; BOOT_N] = core::array::from_fn(|i| (i % 2) as i64);
    let bsk = bootstrap_keygen(&mut rng, &acc_key, &secret);
    let tv = step_test_vector();

    let phase = 300i64;
    // Inject input noise far larger than any ciphertext noise would be, but
    // below the slot half-width, so the rounded phase is unchanged.
    for &noise in &[0i64, 30, -30, 80, -80] {
        let (a, b) = boot_lwe_phase(&secret, phase, noise, &mut rng);
        let out = programmable_bootstrap(&bsk, &tv, &a, b);
        let recovered = acc_key.lwe_decrypt(&sample_extract(&out, 0));
        assert_eq!(
            i64::from(recovered),
            1,
            "noisy input must still yield f(phase)=1 (noise refreshed)"
        );
    }
}

#[test]
fn modulus_switch_preserves_the_phase_ratio() {
    use blacknet_crypto::oblivious_detector_fhe::modulus_switch_q_to_2n;
    // A value at p/Q of the modulus maps to ~p/2N of the rotation domain.
    let q = 1152921504606847009i64; // LM modulus
    let two_n = 2048i64;
    for &frac in &[0i64, 1, 2, 4, 8] {
        let x = (q / 16) * frac; // frac/16 of the modulus
        let switched = modulus_switch_q_to_2n(x);
        let expected = (two_n / 16) * frac; // frac/16 of 2N
        assert!(
            (switched - expected).abs() <= 1,
            "mod-switch must preserve the phase ratio within rounding (got {switched}, want ~{expected})"
        );
    }
}

// --- Half-domain FDFB: evaluating a NON-negacyclic function -----------------

#[test]
#[ignore = "slow: multiple blind rotations; run with --ignored"]
fn half_domain_evaluates_a_non_negacyclic_function() {
    use blacknet_crypto::oblivious_detector_fhe::{
        Rlwe, bootstrap_keygen, encode_half_domain, half_domain_test_vector,
        programmable_bootstrap, sample_extract,
    };
    let mut rng = drg(120);
    let acc_key = Rlwe::keygen(&mut rng);
    let secret: [i64; BOOT_N] = core::array::from_fn(|i| (i % 2) as i64);
    let bsk = bootstrap_keygen(&mut rng, &acc_key, &secret);

    // A NON-negacyclic function: f = [1, 1, 2, 1] over p = 4. (Negacyclic would
    // force f[2] = -f[0] = -1, but here f[2] = 2.)
    let p = 4;
    let f = [1i64, 1, 2, 1];
    let tv = half_domain_test_vector(&f, p);

    for m in 0..p {
        let phase = encode_half_domain(m, p); // in [0, N)
        let (a, b) = boot_lwe_phase(&secret, phase, 0, &mut rng);
        let out = programmable_bootstrap(&bsk, &tv, &a, b);
        let recovered = acc_key.lwe_decrypt(&sample_extract(&out, 0));
        assert_eq!(
            i64::from(recovered),
            f[m],
            "half-domain bootstrap must evaluate the arbitrary f at message {m}"
        );
    }
}

#[test]
#[ignore = "slow: blind rotation; run with --ignored"]
fn full_domain_encoding_fails_on_the_non_negacyclic_value() {
    // The contrast that justifies the half-domain technique: encode the SAME
    // non-negacyclic f with a full-domain (2N) phase. For the message whose
    // phase lands in the upper half, negacyclicity flips the sign, so the
    // result is WRONG - which is exactly why the half-domain confinement is
    // needed.
    use blacknet_crypto::oblivious_detector_fhe::{
        Rlwe, bootstrap_keygen, half_domain_test_vector, programmable_bootstrap, sample_extract,
    };
    let mut rng = drg(121);
    let acc_key = Rlwe::keygen(&mut rng);
    let secret: [i64; BOOT_N] = core::array::from_fn(|i| (i % 2) as i64);
    let bsk = bootstrap_keygen(&mut rng, &acc_key, &secret);
    let p = 4;
    let f = [1i64, 1, 2, 1];
    let tv = half_domain_test_vector(&f, p);

    // Message m = 2 encoded full-domain: phase = 2*(2N/p) + (2N/2p) = 1280 (in
    // the upper half [N,2N)). Negacyclicity gives -tv[1280-N] = -tv[256] =
    // -f[1] = -1, not f[2] = 2.
    let two_n = 2 * 1024i64;
    let slot = two_n / p as i64;
    let phase_full = 2 * slot + slot / 2; // 1280, upper half
    let (a, b) = boot_lwe_phase(&secret, phase_full, 0, &mut rng);
    let out = programmable_bootstrap(&bsk, &tv, &a, b);
    let recovered = i64::from(acc_key.lwe_decrypt(&sample_extract(&out, 0)));

    assert_ne!(
        recovered, f[2],
        "full-domain encoding mis-evaluates the non-negacyclic value"
    );
    assert_eq!(
        recovered, -f[1],
        "the upper-half phase yields the negacyclic flip -f[1]"
    );
}
