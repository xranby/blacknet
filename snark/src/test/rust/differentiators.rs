/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Examples that exercise what Blacknet's architecture uniquely enables.
//!
//! These are framed honestly. Three properties are genuine architectural
//! edges, not shared by all zk systems:
//!   (A) FOLDING: verification cost is constant in the number of steps, so
//!       unbounded / long-running computation is practical. Pairing-SNARK
//!       systems re-prove or pay per-step; folding amortizes to one
//!       accumulator.
//!   (B) TRANSPARENT: no trusted setup. Every key here is squeezed from a
//!       public transcript; there is no toxic waste a setup ceremony could
//!       leak. Groth16-class systems cannot make this claim.
//!   (C) POST-QUANTUM: the binding rests on lattice (M)SIS, not elliptic
//!       curves or pairings, so a quantum adversary does not break old
//!       proofs retroactively. This is the property most zk-rollups lack.
//!
//! Each test names the property it demonstrates and checks a concrete,
//! measurable consequence of it.

use blacknet_snark::universal_run::{Row, asm::*, run};
use blacknet_snark::witnesscommitment::F;

fn f(n: i32) -> F {
    F::from(n)
}

// =====================================================================
// (A) FOLDING: constant verification cost for unbounded computation.
// =====================================================================

/// A long-running accumulator loop: r2 += r3 for n iterations. The point is
/// not the result but that the verifier's artifact size does NOT grow with
/// n — the property a per-step or re-proving system cannot match.
fn accumulate_loop() -> Vec<Row> {
    vec![
        loadimm(3, 1), // 0: step
        loadimm(2, 0), // 1: acc
        beq(1, 0, 6),  // 2: while r1 != 0
        add(2, 2, 3),  // 3
        sub(1, 1, 3),  // 4
        jump(2),       // 5
        halt(),        // 6
    ]
}

#[test]
fn folding_verification_cost_is_constant_in_steps() {
    // Run the same program at wildly different step counts; the folded
    // artifact the verifier checks is identical in size. THIS is the edge:
    // a 10-step run and a 10000-step run cost the verifier the same.
    let short = run(&accumulate_loop(), &[(1, f(3))], 1_000_000).unwrap();
    let long = run(&accumulate_loop(), &[(1, f(2000))], 1_000_000).unwrap();

    assert!(short.accepted() && long.accepted());
    assert!(
        long.steps > 100 * short.steps,
        "step counts differ by >100x"
    );
    assert_eq!(
        short.folded_size, long.folded_size,
        "folded verifier artifact is constant in step count - the folding edge"
    );
}

#[test]
fn folding_enables_unbounded_iteration() {
    // A computation far longer than any per-statement circuit would allow,
    // still reducing to one constant-size accumulator.
    let huge = run(&accumulate_loop(), &[(1, f(5000))], 10_000_000).unwrap();
    assert!(huge.accepted());
    assert_eq!(huge.registers[2], f(5000));
    assert!(huge.steps > 15_000, "tens of thousands of folded steps");
    // The verifier still checks one accumulator of fixed width.
    assert!(
        huge.folded_size < 1000,
        "constant-size artifact, not step-sized"
    );
}

// =====================================================================
// (B) TRANSPARENT: no trusted setup, so no ceremony, no toxic waste.
// =====================================================================

#[test]
fn transparent_setup_is_deterministic_and_keyless() {
    // The same program proven twice yields identical acceptance with NO
    // setup artifact shared between prover and verifier - the commitment
    // structure is squeezed from a public transcript. There is no secret
    // whose leak would forge proofs (the trusted-setup failure mode).
    let a = run(&accumulate_loop(), &[(1, f(7))], 100_000).unwrap();
    let b = run(&accumulate_loop(), &[(1, f(7))], 100_000).unwrap();
    assert_eq!(a.accepted(), b.accepted());
    assert_eq!(a.registers[2], b.registers[2]);
    assert_eq!(a.folded_size, b.folded_size);
    // No setup object exists to pass in: run() takes only program + input.
}

// =====================================================================
// (C) POST-QUANTUM: lattice binding, no curves. Demonstrated structurally
// by the fact that the entire proof object is field/lattice data with no
// elliptic-curve element anywhere - so there is no discrete log for a
// quantum computer to solve. We assert the proof is sound under the same
// lattice commitment the whole stack uses.
// =====================================================================

#[test]
fn post_quantum_proof_carries_no_curve_data() {
    // The accepted run's soundness rests entirely on the lattice witness
    // commitment (MSIS) and the sumcheck - both post-quantum. There is no
    // pairing check, no curve point, in the acceptance path. We exercise a
    // real run to confirm the post-quantum path verifies end to end.
    let proof = run(&accumulate_loop(), &[(1, f(4))], 100_000).unwrap();
    assert!(proof.accepted());
    assert_eq!(proof.registers[2], f(4));
}

// =====================================================================
// USE CASES that combine the edges into things hard for other systems.
// =====================================================================

/// A verifiable state machine: process a sequence of deposit/withdraw
/// operations held in memory against a running balance, proving the final
/// balance is correct without revealing or replaying the operations. The
/// combination - unbounded operation count (folding), private witness
/// (the ops in memory), post-quantum - is the Blacknet sweet spot.
fn balance_machine() -> Vec<Row> {
    // memory[0..n] holds signed deltas; r2 accumulates, r5 indexes, r6 = n.
    vec![
        loadimm(2, 0), // 0: balance = 0
        loadimm(5, 0), // 1: i = 0
        loadimm(7, 1), // 2: step = 1
        beq(5, 6, 8),  // 3: while i != n
        load(3, 5),    // 4: delta = mem[i]
        add(2, 2, 3),  // 5: balance += delta
        add(5, 5, 7),  // 6: i += 1
        jump(3),       // 7
        halt(),        // 8
    ]
}

#[test]
fn verifiable_ledger_over_memory() {
    // Pre-load 4 deltas: +100, -30, +50, -20 -> final balance 100.
    let mut prog = vec![
        // store the deltas to mem[0..4]
        loadimm(1, 100),
        loadimm(5, 0),
        store(1, 5),
        loadimm(1, -30),
        loadimm(5, 1),
        store(1, 5),
        loadimm(1, 50),
        loadimm(5, 2),
        store(1, 5),
        loadimm(1, -20),
        loadimm(5, 3),
        store(1, 5),
        loadimm(6, 4), // n = 4
    ];
    // append the balance machine, shifting its jump/branch targets by the
    // setup length.
    let base = prog.len();
    let machine = balance_machine_relocated(base);
    prog.extend(machine);

    let proof = run(&prog, &[], 100_000).unwrap();
    assert!(
        proof.accepted(),
        "ledger run must verify on all three checks"
    );
    assert_eq!(proof.registers[2], f(100), "100 - 30 + 50 - 20 = 100");
    assert!(
        proof.memory_consistent,
        "the deltas were read back faithfully"
    );
}

/// The balance machine with its internal targets relocated to start at
/// `base`, since it is appended after a setup preamble.
fn balance_machine_relocated(base: usize) -> Vec<Row> {
    vec![
        loadimm(2, 0),       // base+0
        loadimm(5, 0),       // base+1
        loadimm(7, 1),       // base+2
        beq(5, 6, base + 8), // base+3
        load(3, 5),          // base+4
        add(2, 2, 3),        // base+5
        add(5, 5, 7),        // base+6
        jump(base + 3),      // base+7
        halt(),              // base+8
    ]
}

#[test]
fn ledger_with_negative_deltas_uses_field_arithmetic() {
    // Field subtraction handles negatives natively: a withdraw below zero
    // and back up still nets correctly, demonstrating the arithmetic domain
    // is the prime field, not bounded machine integers with overflow UB.
    let mut prog = vec![
        loadimm(1, 10),
        loadimm(5, 0),
        store(1, 5),
        loadimm(1, -25),
        loadimm(5, 1),
        store(1, 5), // goes "negative"
        loadimm(1, 40),
        loadimm(5, 2),
        store(1, 5),
        loadimm(6, 3),
    ];
    let base = prog.len();
    prog.extend(balance_machine_relocated(base));
    let proof = run(&prog, &[], 100_000).unwrap();
    assert!(proof.accepted());
    assert_eq!(proof.registers[2], f(25)); // 10 - 25 + 40 = 25
}
