/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */

use blacknet_snark::universal_complete::{
    Decoded, Layout, REGISTERS, assign_complete, complete_step_r1cs, op,
};
use blacknet_snark::witnesscommitment::F;

fn f(n: i32) -> F {
    F::from(n)
}

fn satisfied(z: &blacknet_crypto::matrix::DenseVector<F>) -> bool {
    let (az, bz, cz) = complete_step_r1cs().images(z);
    (0..az.dimension()).all(|i| az[i] * bz[i] == cz[i])
}

fn regs(vals: &[(usize, i32)]) -> [F; REGISTERS] {
    let mut r = [F::from(0); REGISTERS];
    for &(k, v) in vals {
        r[k] = f(v);
    }
    r
}

fn dec(opcode: usize, rd: usize, rs1: usize, rs2: usize, imm: i32, target: usize) -> Decoded {
    Decoded {
        opcode,
        rd,
        rs1,
        rs2,
        imm: f(imm),
        target,
    }
}

#[test]
fn add_writes_and_preserves() {
    let r = regs(&[(1, 3), (2, 4), (5, 99)]);
    let (z, post, next) = assign_complete(dec(op::ADD, 3, 1, 2, 0, 0), &r, 10);
    assert!(satisfied(&z));
    assert_eq!(post[3], f(7)); // 3 + 4
    assert_eq!(post[5], f(99)); // untouched register preserved
    assert_eq!(post[1], f(3));
    assert_eq!(next, 11); // fallthrough
}

#[test]
fn mul_neg_mov_loadimm() {
    let r = regs(&[(1, 6), (2, 7)]);
    let (z, post, _) = assign_complete(dec(op::MUL, 3, 1, 2, 0, 0), &r, 0);
    assert!(satisfied(&z));
    assert_eq!(post[3], f(42));

    let (z, post, _) = assign_complete(dec(op::NEG, 4, 1, 0, 0, 0), &r, 0);
    assert!(satisfied(&z));
    assert_eq!(post[4], -f(6));

    let (z, post, _) = assign_complete(dec(op::MOV, 5, 2, 0, 0, 0), &r, 0);
    assert!(satisfied(&z));
    assert_eq!(post[5], f(7));

    let (z, post, _) = assign_complete(dec(op::LOADIMM, 6, 0, 0, 123, 0), &r, 0);
    assert!(satisfied(&z));
    assert_eq!(post[6], f(123));
}

#[test]
fn jump_sets_pc() {
    let r = regs(&[]);
    let (z, post, next) = assign_complete(dec(op::JUMP, 0, 0, 0, 0, 42), &r, 5);
    assert!(satisfied(&z));
    assert_eq!(next, 42);
    assert_eq!(post, r); // jump writes no register
}

#[test]
fn halt_holds_pc() {
    let r = regs(&[(1, 7)]);
    let (z, post, next) = assign_complete(dec(op::HALT, 0, 0, 0, 0, 0), &r, 9);
    assert!(satisfied(&z));
    assert_eq!(next, 9);
    assert_eq!(post, r);
}

#[test]
fn beq_taken_and_not_taken() {
    // Equal operands: Beq takes the branch to target.
    let r = regs(&[(1, 5), (2, 5)]);
    let (z, _, next) = assign_complete(dec(op::BEQ, 0, 1, 2, 0, 30), &r, 3);
    assert!(satisfied(&z));
    assert_eq!(next, 30);

    // Unequal operands: Beq falls through.
    let r = regs(&[(1, 5), (2, 6)]);
    let (z, _, next) = assign_complete(dec(op::BEQ, 0, 1, 2, 0, 30), &r, 3);
    assert!(satisfied(&z));
    assert_eq!(next, 4);
}

#[test]
fn bne_taken_and_not_taken() {
    // Unequal: Bne takes the branch.
    let r = regs(&[(1, 5), (2, 6)]);
    let (z, _, next) = assign_complete(dec(op::BNE, 0, 1, 2, 0, 30), &r, 3);
    assert!(satisfied(&z));
    assert_eq!(next, 30);

    // Equal: Bne falls through.
    let r = regs(&[(1, 5), (2, 5)]);
    let (z, _, next) = assign_complete(dec(op::BNE, 0, 1, 2, 0, 30), &r, 3);
    assert!(satisfied(&z));
    assert_eq!(next, 4);
}

#[test]
fn one_shape_for_all_opcodes() {
    let n = complete_step_r1cs().a().columns();
    let r = regs(&[(1, 2), (2, 3)]);
    for opcode in 0..10 {
        let (z, _, _) = assign_complete(dec(opcode, 3, 1, 2, 7, 1), &r, 0);
        assert_eq!(z.dimension(), n, "opcode {opcode} width mismatch");
    }
}

#[test]
fn forged_result_rejected() {
    let r = regs(&[(1, 3), (2, 4)]);
    let (mut z, _, _) = assign_complete(dec(op::ADD, 3, 1, 2, 0, 0), &r, 0);
    z[Layout::POST + 3] = f(8); // claim 3+4=8
    assert!(!satisfied(&z));
}

#[test]
fn forged_preservation_rejected() {
    // Tampering with an untouched register must fail the copy constraint.
    let r = regs(&[(1, 3), (2, 4), (6, 50)]);
    let (mut z, _, _) = assign_complete(dec(op::ADD, 3, 1, 2, 0, 0), &r, 0);
    z[Layout::POST + 6] = f(51); // r6 was untouched, must stay 50
    assert!(!satisfied(&z));
}

#[test]
fn forged_pc_rejected() {
    let r = regs(&[(1, 3), (2, 4)]);
    let (mut z, _, _) = assign_complete(dec(op::ADD, 3, 1, 2, 0, 0), &r, 10);
    z[Layout::NEXT_PC] = f(20); // should be 11
    assert!(!satisfied(&z));
}

#[test]
fn forged_branch_outcome_rejected() {
    // Equal operands but claim Beq NOT taken (forge TAKEN=0, pc=fallthrough).
    let r = regs(&[(1, 5), (2, 5)]);
    let (mut z, _, _) = assign_complete(dec(op::BEQ, 0, 1, 2, 0, 30), &r, 3);
    // flip TAKEN and the derived columns to fake a not-taken branch
    z[Layout::TAKEN] = f(0);
    z[Layout::NEXT_PC] = f(4);
    assert!(!satisfied(&z));
}

#[test]
fn forged_source_routing_rejected() {
    // Claim a different source register than the selector indicates.
    let r = regs(&[(1, 3), (2, 4)]);
    let (mut z, _, _) = assign_complete(dec(op::ADD, 3, 1, 2, 0, 0), &r, 0);
    z[Layout::RS1V] = f(99); // not regs[1]
    assert!(!satisfied(&z));
}

#[test]
fn multi_step_program_chains() {
    // A real program with a data-dependent branch, executed step by step
    // through the universal circuit, chaining (registers, pc) across steps.
    // Program: r1 = 5; r2 = 5; if r1 == r2 goto 5; r3 = 1 (skipped); halt
    //          target 5: r3 = 2; halt
    // The branch is TAKEN (5 == 5), so r3 should end as 2.
    let circuit = complete_step_r1cs();
    let check = |z: &blacknet_crypto::matrix::DenseVector<F>| {
        let (az, bz, cz) = circuit.images(z);
        (0..az.dimension()).all(|i| az[i] * bz[i] == cz[i])
    };

    let mut regs = [f(0); REGISTERS];
    let mut pc = 0usize;

    // pc 0: LoadImm r1, 5
    let (z, post, npc) = assign_complete(dec(op::LOADIMM, 1, 0, 0, 5, 0), &regs, pc);
    assert!(check(&z));
    regs = post;
    pc = npc;
    assert_eq!(regs[1], f(5));
    assert_eq!(pc, 1);

    // pc 1: LoadImm r2, 5
    let (z, post, npc) = assign_complete(dec(op::LOADIMM, 2, 0, 0, 5, 0), &regs, pc);
    assert!(check(&z));
    regs = post;
    pc = npc;

    // pc 2: Beq r1, r2, 5  -> taken
    let (z, post, npc) = assign_complete(dec(op::BEQ, 0, 1, 2, 0, 5), &regs, pc);
    assert!(check(&z));
    regs = post;
    pc = npc;
    assert_eq!(pc, 5, "branch should be taken to target 5");

    // pc 5: LoadImm r3, 2
    let (z, post, npc) = assign_complete(dec(op::LOADIMM, 3, 0, 0, 2, 5), &regs, pc);
    assert!(check(&z));
    regs = post;
    pc = npc;

    // pc 6: Halt
    let (z, _post, npc) = assign_complete(dec(op::HALT, 0, 0, 0, 0, 0), &regs, pc);
    assert!(check(&z));

    assert_eq!(regs[3], f(2), "branch path set r3 = 2");
    assert_eq!(regs[1], f(5)); // preserved throughout
    assert_eq!(npc, 6); // halt holds pc
}
