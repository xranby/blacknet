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
    let (z, post, next) = assign_complete(dec(op::ADD, 3, 1, 2, 0, 0), &r, 10, f(0));
    assert!(satisfied(&z));
    assert_eq!(post[3], f(7)); // 3 + 4
    assert_eq!(post[5], f(99)); // untouched register preserved
    assert_eq!(post[1], f(3));
    assert_eq!(next, 11); // fallthrough
}

#[test]
fn mul_neg_mov_loadimm() {
    let r = regs(&[(1, 6), (2, 7)]);
    let (z, post, _) = assign_complete(dec(op::MUL, 3, 1, 2, 0, 0), &r, 0, f(0));
    assert!(satisfied(&z));
    assert_eq!(post[3], f(42));

    let (z, post, _) = assign_complete(dec(op::NEG, 4, 1, 0, 0, 0), &r, 0, f(0));
    assert!(satisfied(&z));
    assert_eq!(post[4], -f(6));

    let (z, post, _) = assign_complete(dec(op::MOV, 5, 2, 0, 0, 0), &r, 0, f(0));
    assert!(satisfied(&z));
    assert_eq!(post[5], f(7));

    let (z, post, _) = assign_complete(dec(op::LOADIMM, 6, 0, 0, 123, 0), &r, 0, f(0));
    assert!(satisfied(&z));
    assert_eq!(post[6], f(123));
}

#[test]
fn jump_sets_pc() {
    let r = regs(&[]);
    let (z, post, next) = assign_complete(dec(op::JUMP, 0, 0, 0, 0, 42), &r, 5, f(0));
    assert!(satisfied(&z));
    assert_eq!(next, 42);
    assert_eq!(post, r); // jump writes no register
}

#[test]
fn halt_holds_pc() {
    let r = regs(&[(1, 7)]);
    let (z, post, next) = assign_complete(dec(op::HALT, 0, 0, 0, 0, 0), &r, 9, f(0));
    assert!(satisfied(&z));
    assert_eq!(next, 9);
    assert_eq!(post, r);
}

#[test]
fn beq_taken_and_not_taken() {
    // Equal operands: Beq takes the branch to target.
    let r = regs(&[(1, 5), (2, 5)]);
    let (z, _, next) = assign_complete(dec(op::BEQ, 0, 1, 2, 0, 30), &r, 3, f(0));
    assert!(satisfied(&z));
    assert_eq!(next, 30);

    // Unequal operands: Beq falls through.
    let r = regs(&[(1, 5), (2, 6)]);
    let (z, _, next) = assign_complete(dec(op::BEQ, 0, 1, 2, 0, 30), &r, 3, f(0));
    assert!(satisfied(&z));
    assert_eq!(next, 4);
}

#[test]
fn bne_taken_and_not_taken() {
    // Unequal: Bne takes the branch.
    let r = regs(&[(1, 5), (2, 6)]);
    let (z, _, next) = assign_complete(dec(op::BNE, 0, 1, 2, 0, 30), &r, 3, f(0));
    assert!(satisfied(&z));
    assert_eq!(next, 30);

    // Equal: Bne falls through.
    let r = regs(&[(1, 5), (2, 5)]);
    let (z, _, next) = assign_complete(dec(op::BNE, 0, 1, 2, 0, 30), &r, 3, f(0));
    assert!(satisfied(&z));
    assert_eq!(next, 4);
}

#[test]
fn one_shape_for_all_opcodes() {
    let n = complete_step_r1cs().a().columns();
    let r = regs(&[(1, 2), (2, 3)]);
    for opcode in 0..10 {
        let (z, _, _) = assign_complete(dec(opcode, 3, 1, 2, 7, 1), &r, 0, f(0));
        assert_eq!(z.dimension(), n, "opcode {opcode} width mismatch");
    }
}

#[test]
fn forged_result_rejected() {
    let r = regs(&[(1, 3), (2, 4)]);
    let (mut z, _, _) = assign_complete(dec(op::ADD, 3, 1, 2, 0, 0), &r, 0, f(0));
    z[Layout::POST + 3] = f(8); // claim 3+4=8
    assert!(!satisfied(&z));
}

#[test]
fn forged_preservation_rejected() {
    // Tampering with an untouched register must fail the copy constraint.
    let r = regs(&[(1, 3), (2, 4), (6, 50)]);
    let (mut z, _, _) = assign_complete(dec(op::ADD, 3, 1, 2, 0, 0), &r, 0, f(0));
    z[Layout::POST + 6] = f(51); // r6 was untouched, must stay 50
    assert!(!satisfied(&z));
}

#[test]
fn forged_pc_rejected() {
    let r = regs(&[(1, 3), (2, 4)]);
    let (mut z, _, _) = assign_complete(dec(op::ADD, 3, 1, 2, 0, 0), &r, 10, f(0));
    z[Layout::NEXT_PC] = f(20); // should be 11
    assert!(!satisfied(&z));
}

#[test]
fn forged_branch_outcome_rejected() {
    // Equal operands but claim Beq NOT taken (forge TAKEN=0, pc=fallthrough).
    let r = regs(&[(1, 5), (2, 5)]);
    let (mut z, _, _) = assign_complete(dec(op::BEQ, 0, 1, 2, 0, 30), &r, 3, f(0));
    // flip TAKEN and the derived columns to fake a not-taken branch
    z[Layout::TAKEN] = f(0);
    z[Layout::NEXT_PC] = f(4);
    assert!(!satisfied(&z));
}

#[test]
fn forged_source_routing_rejected() {
    // Claim a different source register than the selector indicates.
    let r = regs(&[(1, 3), (2, 4)]);
    let (mut z, _, _) = assign_complete(dec(op::ADD, 3, 1, 2, 0, 0), &r, 0, f(0));
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
    let (z, post, npc) = assign_complete(dec(op::LOADIMM, 1, 0, 0, 5, 0), &regs, pc, f(0));
    assert!(check(&z));
    regs = post;
    pc = npc;
    assert_eq!(regs[1], f(5));
    assert_eq!(pc, 1);

    // pc 1: LoadImm r2, 5
    let (z, post, npc) = assign_complete(dec(op::LOADIMM, 2, 0, 0, 5, 0), &regs, pc, f(0));
    assert!(check(&z));
    regs = post;
    pc = npc;

    // pc 2: Beq r1, r2, 5  -> taken
    let (z, post, npc) = assign_complete(dec(op::BEQ, 0, 1, 2, 0, 5), &regs, pc, f(0));
    assert!(check(&z));
    regs = post;
    pc = npc;
    assert_eq!(pc, 5, "branch should be taken to target 5");

    // pc 5: LoadImm r3, 2
    let (z, post, npc) = assign_complete(dec(op::LOADIMM, 3, 0, 0, 2, 5), &regs, pc, f(0));
    assert!(check(&z));
    regs = post;
    pc = npc;

    // pc 6: Halt
    let (z, _post, npc) = assign_complete(dec(op::HALT, 0, 0, 0, 0, 0), &regs, pc, f(0));
    assert!(check(&z));

    assert_eq!(regs[3], f(2), "branch path set r3 = 2");
    assert_eq!(regs[1], f(5)); // preserved throughout
    assert_eq!(npc, 6); // halt holds pc
}

#[test]
fn load_writes_memory_value() {
    // Load: rd <- mem[rs2]. Address in r2, loaded value supplied as mem_value.
    let r = regs(&[(2, 100)]); // address 100 in r2
    let (z, post, next) = assign_complete(dec(op::LOAD, 3, 0, 2, 0, 0), &r, 7, f(55));
    assert!(satisfied(&z));
    assert_eq!(post[3], f(55)); // loaded value written to r3
    assert_eq!(post[2], f(100)); // address register preserved
    assert_eq!(next, 8); // memory ops fall through
}

#[test]
fn store_reads_register_value() {
    // Store: mem[rs2] <- rs1. Value in r1, address in r2; writes no register.
    let r = regs(&[(1, 77), (2, 100), (4, 9)]);
    let (z, post, next) = assign_complete(dec(op::STORE, 0, 1, 2, 0, 0), &r, 3, f(77));
    assert!(satisfied(&z));
    assert_eq!(post, r); // store writes no register; state preserved
    assert_eq!(next, 4);
    let (addr, value, is_write) = blacknet_snark::universal_complete::memory::access_of(&z);
    assert_eq!(addr, f(100));
    assert_eq!(value, f(77));
    assert!(is_write);
}

#[test]
fn load_with_wrong_value_rejected() {
    // The loaded value must equal mem_value the circuit was given; tampering
    // with rdv breaks the gated Load constraint.
    let r = regs(&[(2, 100)]);
    let (mut z, _, _) = assign_complete(dec(op::LOAD, 3, 0, 2, 0, 0), &r, 0, f(55));
    z[Layout::POST + 3] = f(56); // claim a different loaded value
    assert!(!satisfied(&z));
}

#[test]
fn store_value_mismatch_rejected() {
    let r = regs(&[(1, 77), (2, 100)]);
    let (mut z, _, _) = assign_complete(dec(op::STORE, 0, 1, 2, 0, 0), &r, 0, f(77));
    z[Layout::MEM_VALUE] = f(78); // store value must equal r1
    assert!(!satisfied(&z));
}

#[test]
fn memory_address_mismatch_rejected() {
    let r = regs(&[(1, 77), (2, 100)]);
    let (mut z, _, _) = assign_complete(dec(op::STORE, 0, 1, 2, 0, 0), &r, 0, f(77));
    z[Layout::MEM_ADDR] = f(101); // address must equal r2
    assert!(!satisfied(&z));
}

#[test]
fn global_memory_consistency_holds() {
    // Offline memory checking: a Load returns the last Stored value at its
    // address. Build the read/write multisets and verify their equality.
    use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};
    use blacknet_snark::universal_complete::memory::{MemoryOp, check};

    // Trace: store 77@addr1 (t0), store 88@addr2 (t1), load addr1->77 (t2).
    // The offline-memory-checking multisets: every access appears once as a
    // "write" tuple (the value after) and once as a "read" tuple (the value
    // before); consistency means these multisets match across a sorted view.
    // Here we model the canonical decomposition: reads = values observed,
    // writes = values placed, at (addr, time). A consistent trace has equal
    // multisets when each load mirrors the prior store at its address.
    let writes = vec![
        MemoryOp {
            address: f(1),
            timestamp: f(0),
            value: f(77),
        },
        MemoryOp {
            address: f(2),
            timestamp: f(1),
            value: f(88),
        },
        MemoryOp {
            address: f(1),
            timestamp: f(2),
            value: f(77),
        }, // load mirrors store
    ];
    let reads = vec![
        MemoryOp {
            address: f(1),
            timestamp: f(0),
            value: f(77),
        },
        MemoryOp {
            address: f(2),
            timestamp: f(1),
            value: f(88),
        },
        MemoryOp {
            address: f(1),
            timestamp: f(2),
            value: f(77),
        },
    ];
    let mut duplex = DuplexPoseidon2Pervushin::default();
    for op in writes.iter().chain(&reads) {
        duplex.absorb(op.address);
        duplex.absorb(op.value);
    }
    assert!(check(&reads, &writes, &mut duplex));
}

#[test]
fn inconsistent_memory_rejected() {
    // A load returning a value never stored breaks multiset equality.
    use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};
    use blacknet_snark::universal_complete::memory::{MemoryOp, check};

    let writes = vec![
        MemoryOp {
            address: f(1),
            timestamp: f(0),
            value: f(77),
        },
        MemoryOp {
            address: f(1),
            timestamp: f(2),
            value: f(77),
        },
    ];
    let reads = vec![
        MemoryOp {
            address: f(1),
            timestamp: f(0),
            value: f(77),
        },
        MemoryOp {
            address: f(1),
            timestamp: f(2),
            value: f(999),
        }, // forged load
    ];
    let mut duplex = DuplexPoseidon2Pervushin::default();
    for op in writes.iter().chain(&reads) {
        duplex.absorb(op.address);
        duplex.absorb(op.value);
    }
    assert!(!check(&reads, &writes, &mut duplex));
}

#[test]
fn all_twelve_opcodes_one_shape() {
    let n = complete_step_r1cs().a().columns();
    let r = regs(&[(1, 2), (2, 3)]);
    for opcode in 0..12 {
        let (z, _, _) = assign_complete(dec(opcode, 3, 1, 2, 7, 1), &r, 0, f(5));
        assert_eq!(z.dimension(), n, "opcode {opcode} width mismatch");
    }
}
