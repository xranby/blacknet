/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Use cases of broad interest to deploy on the zkFi machine.
//!
//! These are realistic verifiable-finance programs, each reducing to one
//! folded proof: an unbounded amount of private computation, a small
//! constant-size receipt anyone can check, post-quantum and with no trusted
//! setup. They are chosen to be *sound with the machine's actual
//! primitives*, and the soundness boundary is stated plainly:
//!
//!   - The arithmetic domain is a prime field. EQUALITY (`beq`/`bne`) and
//!     `+ - *` are sound and exact, including over signed values (the field
//!     represents negatives natively, with no integer-overflow undefined
//!     behaviour). VALUE CONSERVATION and EXACT TALLIES therefore prove
//!     soundly with no extra machinery.
//!   - ORDERING ("balance >= amount", "bid is the maximum") is NOT sound on
//!     a bare field, because field elements wrap: it requires a range-check
//!     / bit-decomposition gadget bounding values to an interval. The
//!     building blocks for that gadget already exist in the tree
//!     (`binarity` and the Johnson-Lindenstrauss norm bound used by the
//!     succinct opening); wiring them into a `cmp` opcode is the documented
//!     extension. The use cases below are written to rely on conservation
//!     and equality, which need no such gadget, and each notes where an
//!     ordering check would attach.

use blacknet_snark::universal_run::{Row, asm::*, run};
use blacknet_snark::witnesscommitment::F;

fn f(n: i32) -> F {
    F::from(n)
}

/// A relocatable "scan an array in memory and accumulate" loop, the workhorse
/// of these programs. Emitted to start at absolute address `base`:
///   while idx != limit { acc += mem[idx]; idx += step } ; fall through.
/// Registers: idx, limit, acc, val (scratch), step. `step` must hold 1 and
/// `acc` its initial value before entry; the loop falls through to `base+5`.
fn scan_accumulate(
    base: usize,
    idx: usize,
    limit: usize,
    acc: usize,
    val: usize,
    step: usize,
) -> Vec<Row> {
    vec![
        beq(idx, limit, base + 5), // base+0: while idx != limit
        load(val, idx),            // base+1: val = mem[idx]
        add(acc, acc, val),        // base+2: acc += val
        add(idx, idx, step),       // base+3: idx += 1
        jump(base + 0),            // base+4: loop
                                   // base+5: (fall-through point)
    ]
}

/// Stores `values` to memory addresses `0..len` using registers r1 (value)
/// and r5 (address). Emitted at the program start (absolute address 0).
fn store_array(values: &[i32]) -> Vec<Row> {
    let mut prog = Vec::new();
    for (addr, &v) in values.iter().enumerate() {
        prog.push(loadimm(1, i64::from(v)));
        prog.push(loadimm(5, addr as i64));
        prog.push(store(1, 5));
    }
    prog
}

// =====================================================================
// 1. CONFIDENTIAL PAYMENT BATCH — conservation of value (a rollup core).
// =====================================================================
//
// A rollup operator applies a batch of transfers and must prove the batch
// created no money: the signed net change across all accounts sums to zero.
// This is THE soundness property of a payment system and it is a pure
// equality check - sound on the field with no range gadget. (Preventing an
// individual account from going negative is the separate ordering check
// noted in the module docs.)

#[test]
fn payment_batch_conserves_value() {
    // Net deltas of a balanced batch: +500 to A, -200 from B, -300 from C.
    // Their sum is 0: no value created or destroyed.
    let deltas = [500, -200, -300];
    let n = deltas.len();

    let mut prog = store_array(&deltas);
    let base = prog.len();
    // acc = 0, idx = 0, limit = n, step = 1
    prog.push(loadimm(2, 0));
    prog.push(loadimm(5, 0));
    prog.push(loadimm(6, n as i64));
    prog.push(loadimm(7, 1));
    let loop_base = prog.len();
    prog.extend(scan_accumulate(loop_base, 5, 6, 2, 3, 7));
    // After the loop, r2 holds the net. Prove it equals zero.
    prog.push(loadimm(4, 0));
    prog.push(beq(2, 4, prog.len() + 2)); // if net == 0 goto valid
    prog.push(halt()); // invalid: net != 0 (falls here)
    prog.push(halt()); // valid

    let proof = run(&prog, &[], 100_000).unwrap();
    assert!(proof.accepted());
    assert_eq!(proof.registers[2], f(0), "batch conserves value: net == 0");
}

#[test]
fn unbalanced_batch_has_nonzero_net() {
    // A batch that mints 100 out of nothing: deltas sum to +100, not 0. The
    // program still runs and proves faithfully - what it proves is that the
    // net is 100, which a verifier checking "net == 0" would reject.
    let deltas = [500, -200, -200]; // sums to +100
    let n = deltas.len();
    let mut prog = store_array(&deltas);
    prog.push(loadimm(2, 0));
    prog.push(loadimm(5, 0));
    prog.push(loadimm(6, n as i64));
    prog.push(loadimm(7, 1));
    let loop_base = prog.len();
    prog.extend(scan_accumulate(loop_base, 5, 6, 2, 3, 7));
    prog.push(halt());

    let proof = run(&prog, &[], 100_000).unwrap();
    assert!(proof.accepted());
    assert_eq!(
        proof.registers[2],
        f(100),
        "the mint is visible as net == 100"
    );
    assert_ne!(
        proof.registers[2],
        f(0),
        "a conservation verifier rejects this"
    );
}

// =====================================================================
// 2. PROOF OF RESERVES / SOLVENCY — reserves == liabilities + surplus.
// =====================================================================
//
// Post-FTX, the flagship verifiable-finance use case. An exchange proves it
// holds enough to cover customer liabilities WITHOUT revealing individual
// balances. Framed as an exact equality - reserves = liabilities + declared
// surplus - it is sound on the field. (Proving surplus >= 0, i.e. genuine
// solvency rather than an exact match, is the ordering check; the equality
// here proves the books balance to a declared, publicly committed surplus.)

#[test]
fn proof_of_reserves_balances_to_declared_surplus() {
    // Customer balances (liabilities) held privately in memory, and the
    // exchange's reserves. Prove reserves == sum(liabilities) + surplus.
    let liabilities = [1000, 2500, 1500, 3000]; // sum = 8000
    let surplus = 750;
    let reserves: i32 = 8000 + surplus; // 8750

    let mut prog = store_array(&liabilities);
    let n = liabilities.len();
    // r2 = sum of liabilities
    prog.push(loadimm(2, 0));
    prog.push(loadimm(5, 0));
    prog.push(loadimm(6, n as i64));
    prog.push(loadimm(7, 1));
    let loop_base = prog.len();
    prog.extend(scan_accumulate(loop_base, 5, 6, 2, 3, 7));
    // r3 = surplus, r4 = liabilities + surplus, r8 = reserves
    prog.push(loadimm(3, i64::from(surplus)));
    prog.push(add(4, 2, 3));
    prog.push(loadimm(1, i64::from(reserves)));
    // prove reserves == liabilities + surplus
    prog.push(beq(1, 4, prog.len() + 2));
    prog.push(halt()); // mismatch
    prog.push(halt()); // balanced

    let proof = run(&prog, &[], 100_000).unwrap();
    assert!(proof.accepted());
    assert_eq!(proof.registers[2], f(8000), "private liabilities summed");
    assert_eq!(proof.registers[4], f(8750), "liabilities + surplus");
    assert_eq!(proof.registers[1], f(reserves), "matches reserves");
}

// =====================================================================
// 3. VERIFIABLE TALLY — sealed ballots, public outcome.
// =====================================================================
//
// Sum a set of ballots held privately and prove the total. Each ballot is a
// field value (e.g. 1 for yes, 0 for no, or a token-weighted amount). The
// tally is an exact sum: sound, with individual ballots never revealed.

#[test]
fn verifiable_vote_tally() {
    // 6 ballots, token-weighted: yes-weights and no-weights as signed votes
    // (+w for yes, -w for no). The signed tally's sign is the outcome; its
    // magnitude the margin. Here: +10 +5 -3 +8 -2 +1 = +19 (yes wins by 19).
    let ballots = [10, 5, -3, 8, -2, 1];
    let n = ballots.len();
    let mut prog = store_array(&ballots);
    prog.push(loadimm(2, 0));
    prog.push(loadimm(5, 0));
    prog.push(loadimm(6, n as i64));
    prog.push(loadimm(7, 1));
    let loop_base = prog.len();
    prog.extend(scan_accumulate(loop_base, 5, 6, 2, 3, 7));
    prog.push(halt());

    let proof = run(&prog, &[], 100_000).unwrap();
    assert!(proof.accepted());
    assert_eq!(proof.registers[2], f(19), "net tally = +19, yes wins");
}

// =====================================================================
// 4. RECURRING SETTLEMENT — a long-lived ledger, the folding edge.
// =====================================================================
//
// A subscription / streaming-payment ledger that applies one charge per
// period over a very long horizon, proving the cumulative settled amount.
// The point: the proof stays constant size whether the ledger has run for
// ten periods or ten thousand - an ongoing financial relationship that
// other proving systems would have to re-prove or bound in advance.

fn recurring_charge(periods: i32, amount: i32) -> Vec<Row> {
    // r2 = total; r1 = remaining periods; r3 = amount; r7 = 1.
    // while remaining != 0 { total += amount; remaining -= 1 }
    let _ = periods; // periods is supplied at run time via input r1
    vec![
        loadimm(3, i64::from(amount)), // 0
        loadimm(7, 1),                 // 1
        loadimm(2, 0),                 // 2: total
        // r1 holds `periods` from inputs
        beq(1, 0, 7), // 3: while remaining != 0
        add(2, 2, 3), // 4: total += amount
        sub(1, 1, 7), // 5: remaining -= 1
        jump(3),      // 6
        halt(),       // 7: done
    ]
}

#[test]
fn recurring_settlement_constant_proof_size() {
    let short = {
        let prog = recurring_charge(10, 5);
        run(&prog, &[(1, f(10))], 10_000_000).unwrap()
    };
    let long = {
        let prog = recurring_charge(4000, 5);
        run(&prog, &[(1, f(4000))], 10_000_000).unwrap()
    };
    assert!(short.accepted() && long.accepted());
    assert_eq!(short.registers[2], f(50)); // 10 * 5
    assert_eq!(long.registers[2], f(20_000)); // 4000 * 5
    assert!(long.steps > 100 * short.steps, "vastly more periods");
    assert_eq!(
        short.folded_size, long.folded_size,
        "the settlement receipt is the same size after 10 or 4000 periods"
    );
}

// =====================================================================
// 5. ALLOWLIST MEMBERSHIP — equality against a committed set.
// =====================================================================
//
// Prove an account identifier is one of a committed allowlist (KYC set,
// airdrop eligibility, permitted counterparties) WITHOUT revealing which
// entry it is or scanning order. Equality-based: sound on the field. The
// program sets a found-flag when the target equals a set entry.

#[test]
fn allowlist_membership_by_equality() {
    // Committed allowlist in memory; prove `target` is present.
    let allowlist = [4242, 1337, 9001, 7777];
    let target = 9001;
    let n = allowlist.len();

    let mut prog = store_array(&allowlist);
    // r1=target, r2=found, r3=v(scratch), r4=found-const(1),
    // r5=idx, r6=n, r7=step. (8 registers, 0..7; r0 is zero.)
    prog.push(loadimm(1, i64::from(target)));
    prog.push(loadimm(2, 0));
    prog.push(loadimm(4, 1));
    prog.push(loadimm(5, 0));
    prog.push(loadimm(6, n as i64));
    prog.push(loadimm(7, 1));
    let loop_base = prog.len();
    // while idx != n: v = mem[idx]; if v == target { found = 1 }; idx++
    prog.push(beq(5, 6, loop_base + 6)); // 0: exit
    prog.push(load(3, 5)); // 1: v = mem[idx]
    prog.push(bne(3, 1, loop_base + 4)); // 2: if v != target skip set
    prog.push(mov(2, 4)); // 3: found = 1
    prog.push(add(5, 5, 7)); // 4: idx++
    prog.push(jump(loop_base)); // 5
    prog.push(halt()); // 6: done

    let proof = run(&prog, &[], 100_000).unwrap();
    assert!(proof.accepted());
    assert_eq!(proof.registers[2], f(1), "target is in the allowlist");
}

#[test]
fn allowlist_rejects_non_member() {
    let allowlist = [4242, 1337, 9001, 7777];
    let target = 5555; // not present
    let n = allowlist.len();
    let mut prog = store_array(&allowlist);
    prog.push(loadimm(1, i64::from(target)));
    prog.push(loadimm(2, 0));
    prog.push(loadimm(4, 1));
    prog.push(loadimm(5, 0));
    prog.push(loadimm(6, n as i64));
    prog.push(loadimm(7, 1));
    let loop_base = prog.len();
    prog.push(beq(5, 6, loop_base + 6));
    prog.push(load(3, 5));
    prog.push(bne(3, 1, loop_base + 4));
    prog.push(mov(2, 4));
    prog.push(add(5, 5, 7));
    prog.push(jump(loop_base));
    prog.push(halt());

    let proof = run(&prog, &[], 100_000).unwrap();
    assert!(proof.accepted());
    assert_eq!(proof.registers[2], f(0), "target absent: found stays 0");
}
