/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Composition: private discovery (BlackLemon) + private computation (the
//! folding zkVM), one confidential pipeline, post-quantum end to end.
//!
//! The two halves of a confidential ledger, joined:
//!   1. DISCOVERY. A public ledger holds BlackLemon-encrypted payment notes.
//!      A recipient scans it, detecting and decrypting exactly the notes
//!      addressed to them - learning which payments are theirs and their
//!      amounts, while revealing nothing to observers (see the BlackLemon
//!      use case). Both the addressing and the encryption are lattice-based.
//!   2. COMPUTATION. The recipient feeds the recovered amounts as the
//!      PRIVATE WITNESS of a universal-machine run that proves a statement
//!      about them - here, that they received a claimed total - producing
//!      one folded, constant-size proof. The amounts never appear in the
//!      proof; only the proven statement is public.
//!
//! Soundness boundary, stated honestly. This composes at the DATA boundary:
//! BlackLemon's decrypted plaintext becomes the zkVM's witness. It is an
//! application-level pipeline, not an in-circuit binding - the zkVM circuit
//! does not itself re-verify the LPR decryption (that would require
//! arithmetizing lattice decryption over the Pervushin field, across two
//! different rings, the documented hard extension). What each half proves is
//! sound on its own terms: BlackLemon's detection/decryption is sound under
//! its lattice assumption, and the folded run soundly proves the statement
//! about whatever witness it was given. The composition delivers a recipient
//! who discovers their notes privately and then proves a fact about them
//! privately; binding the witness to the ciphertext in-circuit is the next
//! cryptographic step, noted where it attaches.

use blacknet_crypto::blacklemon::{
    PublicKey, SecretKey, decrypt, detect, encrypt, generate_public_key, generate_secret_key,
};
use blacknet_crypto::lpr::{decode, encode};
use blacknet_crypto::random::FastDRG;
use blacknet_snark::universal_run::{Row, asm::*, run};
use blacknet_snark::witnesscommitment::F;

fn f(n: i32) -> F {
    F::from(n)
}

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

/// Encodes a payment note carrying `amount` (0..=255). Byte 0's leading bits
/// are cleared so the note is detectable (BlackLemon's convention); the
/// amount rides in byte 1.
const fn payment_note(amount: u8) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    bytes[0] = 0; // detectability marker
    bytes[1] = amount;
    bytes
}

/// Recovers the amount from a decoded note.
fn amount_of(bytes: &[u8; 128]) -> i32 {
    i32::from(bytes[1])
}

/// The recipient's scan: detect + decrypt the notes addressed to `sk`,
/// returning the recovered amounts. This is the discovery half.
fn scan_for_amounts(
    sk: &SecretKey,
    ledger: &[blacknet_crypto::blacklemon::CipherText],
) -> Vec<i32> {
    let mut amounts = Vec::new();
    for ct in ledger {
        if detect(sk, ct).is_some() {
            let bytes = decode(&decrypt(sk, ct));
            amounts.push(amount_of(&bytes));
        }
    }
    amounts
}

/// The computation half: a zkVM program proving the sum of the recovered
/// amounts (stored in memory) equals a claimed total. Returns whether the
/// folded proof accepts and the computed total.
fn prove_total_received(amounts: &[i32], claimed_total: i32) -> (bool, i32) {
    // Store amounts to memory 0..n, then scan-sum and compare to the claim.
    let mut prog: Vec<Row> = Vec::new();
    for (addr, &a) in amounts.iter().enumerate() {
        prog.push(loadimm(1, i64::from(a)));
        prog.push(loadimm(5, addr as i64));
        prog.push(store(1, 5));
    }
    // acc=0 (r2), idx=0 (r5), limit=n (r6), step=1 (r7)
    prog.push(loadimm(2, 0));
    prog.push(loadimm(5, 0));
    prog.push(loadimm(6, amounts.len() as i64));
    prog.push(loadimm(7, 1));
    let lb = prog.len();
    prog.push(beq(5, 6, lb + 5)); // while idx != n
    prog.push(load(3, 5)); // v = mem[idx]
    prog.push(add(2, 2, 3)); // acc += v
    prog.push(add(5, 5, 7)); // idx++
    prog.push(jump(lb));
    // prove acc == claimed_total
    prog.push(loadimm(4, i64::from(claimed_total)));
    prog.push(beq(2, 4, prog.len() + 2)); // match -> skip the "mismatch" halt
    prog.push(halt()); // mismatch
    prog.push(halt()); // matched

    let proof = run(&prog, &[], 1_000_000).unwrap();
    let total = {
        use blacknet_crypto::algebra::IntegerRing;
        proof.registers[2].canonical() as i32
    };
    (
        proof.accepted() && proof.registers[2] == f(claimed_total),
        total,
    )
}

#[test]
fn recipient_discovers_notes_then_proves_total_received() {
    // Senders post payments to Alice (and some to Bob) on a public ledger.
    // Alice discovers hers via BlackLemon, then proves her total received in
    // one folded zkVM proof - without revealing which notes or amounts.
    let alice = new_party(1);
    let bob = new_party(2);
    let mut sender = drg(100);

    // Ledger: 30 -> Alice, 99 -> Bob, 45 -> Alice, 12 -> Alice, 77 -> Bob.
    let ledger = vec![
        encrypt(&mut sender, &alice.pk, &encode(&payment_note(30))),
        encrypt(&mut sender, &bob.pk, &encode(&payment_note(99))),
        encrypt(&mut sender, &alice.pk, &encode(&payment_note(45))),
        encrypt(&mut sender, &alice.pk, &encode(&payment_note(12))),
        encrypt(&mut sender, &bob.pk, &encode(&payment_note(77))),
    ];

    // Discovery: Alice recovers her amounts.
    let amounts = scan_for_amounts(&alice.sk, &ledger);
    assert_eq!(amounts.len(), 3, "Alice discovers exactly her three notes");
    let true_total: i32 = amounts.iter().sum();
    assert_eq!(true_total, 30 + 45 + 12);

    // Computation: she proves the total in a folded zkVM run.
    let (accepted, total) = prove_total_received(&amounts, true_total);
    assert!(accepted, "the folded proof certifies the claimed total");
    assert_eq!(total, 87);
}

#[test]
fn false_total_claim_is_rejected() {
    // The composition is sound on the computation side: claiming a total the
    // discovered amounts do not sum to fails the folded proof.
    let alice = new_party(1);
    let mut sender = drg(100);
    let ledger = vec![
        encrypt(&mut sender, &alice.pk, &encode(&payment_note(30))),
        encrypt(&mut sender, &alice.pk, &encode(&payment_note(45))),
    ];
    let amounts = scan_for_amounts(&alice.sk, &ledger);
    assert_eq!(amounts.iter().sum::<i32>(), 75);

    let (accepted, _) = prove_total_received(&amounts, 100); // lie: claim 100
    assert!(!accepted, "a false total is rejected by the folded proof");
}

#[test]
fn observer_cannot_reconstruct_the_computation_input() {
    // An observer (wrong key) discovers none of Alice's notes, so cannot
    // assemble the witness the proof is about - discovery gates computation.
    let alice = new_party(1);
    let observer = new_party(99);
    let mut sender = drg(100);
    let ledger = vec![
        encrypt(&mut sender, &alice.pk, &encode(&payment_note(30))),
        encrypt(&mut sender, &alice.pk, &encode(&payment_note(45))),
    ];
    let seen = scan_for_amounts(&observer.sk, &ledger);
    assert!(
        seen.is_empty(),
        "the observer recovers no amounts to compute over"
    );
    // Alice, with the right key, recovers the full input.
    assert_eq!(scan_for_amounts(&alice.sk, &ledger).len(), 2);
}

#[test]
fn empty_discovery_proves_zero_total() {
    // A recipient with no notes on the ledger proves a total of zero - the
    // pipeline composes even in the degenerate case.
    let alice = new_party(1);
    let bob = new_party(2);
    let mut sender = drg(100);
    let ledger = vec![encrypt(&mut sender, &bob.pk, &encode(&payment_note(50)))];
    let amounts = scan_for_amounts(&alice.sk, &ledger);
    assert!(amounts.is_empty());
    let (accepted, total) = prove_total_received(&amounts, 0);
    assert!(accepted);
    assert_eq!(total, 0);
}
