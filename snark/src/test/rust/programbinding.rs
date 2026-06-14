/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

use blacknet_snark::commitment::commit;
use blacknet_snark::programbinding::{
    bind_step, challenge, check_binding, decode_program, fingerprint, program_table, table_digest,
};
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
fn honest_step_binds() {
    let program = decode_program(&prog());
    let alpha = challenge(&commit(&prog()));
    let table = program_table(&program, alpha);
    // Execute pc 2 (the Beq) honestly.
    let binding = bind_step(&program[2], 2, program.len(), alpha);
    assert!(check_binding(&binding, &table, 2));
}

#[test]
fn every_pc_binds() {
    let program = decode_program(&prog());
    let alpha = challenge(&commit(&prog()));
    let table = program_table(&program, alpha);
    for pc in 0..program.len() {
        let binding = bind_step(&program[pc], pc, program.len(), alpha);
        assert!(check_binding(&binding, &table, pc), "pc {pc} should bind");
    }
}

#[test]
fn wrong_instruction_rejected() {
    // The prover runs a DIFFERENT instruction than program[pc]: binding must
    // fail because its fingerprint will not match table[pc].
    let program = decode_program(&prog());
    let alpha = challenge(&commit(&prog()));
    let table = program_table(&program, alpha);
    // At pc 3 the program has LoadImm r3, 1. Prover tries to run LoadImm r3, 2.
    let forged = Decoded {
        opcode: op::LOADIMM,
        rd: 3,
        rs1: 0,
        rs2: 0,
        imm: f(2),
        target: 0,
    };
    let binding = bind_step(&forged, 3, program.len(), alpha);
    assert!(!check_binding(&binding, &table, 3));
}

#[test]
fn wrong_pc_rejected() {
    // The selector points at a different pc than claimed.
    let program = decode_program(&prog());
    let alpha = challenge(&commit(&prog()));
    let table = program_table(&program, alpha);
    let mut binding = bind_step(&program[2], 2, program.len(), alpha);
    // Move the selector to pc 4 while claiming pc 2.
    binding.pc_selector = vec![f(0); program.len()];
    binding.pc_selector[4] = f(1);
    assert!(!check_binding(&binding, &table, 2));
}

#[test]
fn non_one_hot_selector_rejected() {
    let program = decode_program(&prog());
    let alpha = challenge(&commit(&prog()));
    let table = program_table(&program, alpha);
    let mut binding = bind_step(&program[0], 0, program.len(), alpha);
    binding.pc_selector[1] = f(1); // two entries set
    assert!(!check_binding(&binding, &table, 0));
}

#[test]
fn fingerprint_separates_instructions() {
    // Distinct instructions have distinct fingerprints at a generic alpha.
    let alpha = f(0x9e3d);
    let a = Decoded {
        opcode: op::ADD,
        rd: 1,
        rs1: 2,
        rs2: 3,
        imm: f(0),
        target: 0,
    };
    let b = Decoded {
        opcode: op::ADD,
        rd: 1,
        rs1: 2,
        rs2: 4,
        imm: f(0),
        target: 0,
    };
    let c = Decoded {
        opcode: op::SUB,
        rd: 1,
        rs1: 2,
        rs2: 3,
        imm: f(0),
        target: 0,
    };
    assert_ne!(fingerprint(&a, alpha), fingerprint(&b, alpha));
    assert_ne!(fingerprint(&a, alpha), fingerprint(&c, alpha));
}

#[test]
fn challenge_bound_to_commitment() {
    // Different programs squeeze different challenges - the prover cannot
    // reuse a collision-tuned alpha.
    let p1 = prog();
    let mut p2 = prog();
    p2[3] = Instruction::LoadImm(3, f(99));
    assert_ne!(challenge(&commit(&p1)), challenge(&commit(&p2)));
}

#[test]
fn table_digest_detects_tampering() {
    // A tampered decoded table yields a different digest, so a verifier
    // checking the digest against the committed program rejects it.
    let program = decode_program(&prog());
    let mut tampered = program.clone();
    tampered[3].imm = f(2);
    assert_ne!(table_digest(&program), table_digest(&tampered));
}

#[test]
fn full_execution_is_program_bound() {
    // Bind every step of a real branching execution. Each step's decoded
    // instruction must equal program[pc], at the executed pc sequence.
    let program = decode_program(&prog());
    let alpha = challenge(&commit(&prog()));
    let table = program_table(&program, alpha);

    // The honest pc trace of prog() on no inputs: 0,1,2 -> branch taken -> 5,6.
    let pc_trace = [0usize, 1, 2, 5, 6];
    for &pc in &pc_trace {
        let binding = bind_step(&program[pc], pc, program.len(), alpha);
        assert!(
            check_binding(&binding, &table, pc),
            "step at pc {pc} not bound"
        );
    }
}

#[test]
fn forged_step_in_otherwise_valid_run_rejected() {
    // A prover runs the honest trace except substitutes one instruction.
    // The substituted step fails binding even though every other step is
    // valid - the proof is only as strong as its weakest step.
    let program = decode_program(&prog());
    let alpha = challenge(&commit(&prog()));
    let table = program_table(&program, alpha);

    // At pc 5 the program loads r3 = 2; prover tries to skip it (run a Mov).
    let forged = Decoded {
        opcode: op::MOV,
        rd: 3,
        rs1: 1,
        rs2: 0,
        imm: f(0),
        target: 0,
    };
    let binding = bind_step(&forged, 5, program.len(), alpha);
    assert!(!check_binding(&binding, &table, 5));
}
