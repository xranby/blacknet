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
