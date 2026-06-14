/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

use blacknet_snark::commitment::commit;
use blacknet_snark::programbinding::committed::{CommittedTable, check_step, leaf_of, verify};
use blacknet_snark::programbinding::{challenge, decode_program};
use blacknet_snark::universal_complete::{Decoded, op};
use blacknet_snark::witnesscommitment::F;
use blacknet_vm::machine::Instruction;

fn f(n: i32) -> F {
    F::from(n)
}

fn prog() -> Vec<Instruction<F>> {
    vec![
        Instruction::LoadImm(1, f(5)),
        Instruction::LoadImm(2, f(5)),
        Instruction::Beq(1, 2, 5),
        Instruction::LoadImm(3, f(1)),
        Instruction::Halt,
        Instruction::LoadImm(3, f(2)),
        Instruction::Halt,
    ]
}

#[test]
fn committed_table_binds_every_step() {
    let program = decode_program(&prog());
    let alpha = challenge(&commit(&prog()));
    let table = CommittedTable::commit(&program, alpha);
    let root = table.root();
    // Every honest step proves inclusion of its instruction at its pc.
    for pc in 0..program.len() {
        let branch = table.prove(pc);
        assert!(
            check_step(&root, pc, &program[pc], alpha, &branch),
            "pc {pc} should bind against the committed root"
        );
    }
}

#[test]
fn verifier_needs_only_the_root() {
    // The verifier holds a constant-size root, not the table, and checks a
    // per-step branch. Confirm the root is fixed-size regardless of program
    // length.
    let small = CommittedTable::commit(&decode_program(&prog()), f(7));
    let big_program: Vec<_> = (0..64).map(|_| Instruction::Halt).collect();
    let big = CommittedTable::commit(&decode_program(&big_program), f(7));
    // Both roots are a single Jive hash word (4 field elements).
    assert_eq!(small.root().len(), 4);
    assert_eq!(big.root().len(), 4);
}

#[test]
fn forged_instruction_fails_against_root() {
    // A prover runs a DIFFERENT instruction than program[pc]: its leaf is
    // not the committed one, so inclusion against the fixed root fails.
    let program = decode_program(&prog());
    let alpha = challenge(&commit(&prog()));
    let table = CommittedTable::commit(&program, alpha);
    let root = table.root();
    // pc 3 is LoadImm r3,1; the prover tries LoadImm r3,2.
    let forged = Decoded {
        opcode: op::LOADIMM,
        rd: 3,
        rs1: 0,
        rs2: 0,
        imm: f(2),
        target: 0,
    };
    let branch = table.prove(3);
    assert!(!check_step(&root, 3, &forged, alpha, &branch));
}

#[test]
fn wrong_pc_branch_fails() {
    // Using pc 4's branch to claim pc 2 fails: the index drives the path.
    let program = decode_program(&prog());
    let alpha = challenge(&commit(&prog()));
    let table = CommittedTable::commit(&program, alpha);
    let root = table.root();
    let branch_for_4 = table.prove(4);
    // Claim the instruction at pc 2 but present pc 4's branch and index.
    assert!(!verify(
        &root,
        2,
        leaf_of(&program[2], alpha),
        &branch_for_4
    ));
}

#[test]
fn tampered_root_rejects_honest_branch() {
    let program = decode_program(&prog());
    let alpha = challenge(&commit(&prog()));
    let table = CommittedTable::commit(&program, alpha);
    let mut root = table.root();
    root[0] = root[0] + f(1); // corrupt the committed root
    let branch = table.prove(1);
    assert!(!check_step(&root, 1, &program[1], alpha, &branch));
}

#[test]
fn different_program_different_root() {
    // The root is bound to the deployed code: changing one instruction
    // changes the root, so a table from a different program is detectable.
    let a = CommittedTable::commit(&decode_program(&prog()), f(9));
    let mut other = prog();
    other[3] = Instruction::LoadImm(3, f(99));
    let b = CommittedTable::commit(&decode_program(&other), f(9));
    assert_ne!(a.root(), b.root());
}
