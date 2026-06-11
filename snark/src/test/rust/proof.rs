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
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use blacknet_snark::commitment::commit;
use blacknet_snark::proof::{F, prove, verify};
use blacknet_vm::machine::Instruction;

fn f(n: i32) -> F {
    F::from(n)
}

fn fibonacci() -> Vec<Instruction<F>> {
    // input r1 = n iterations; r2,r3 = fib pair; r4 = 1
    vec![
        Instruction::LoadImm(2, f(0)),
        Instruction::LoadImm(3, f(1)),
        Instruction::LoadImm(4, f(1)),
        Instruction::Add(5, 2, 3),
        Instruction::Mov(2, 3),
        Instruction::Mov(3, 5),
        Instruction::Sub(1, 1, 4),
        Instruction::Bne(1, 0, 3),
        Instruction::Halt,
    ]
}

#[test]
fn prove_verify_roundtrip() {
    let program = fibonacci();
    let id = commit(&program);
    let (io, proof) = prove(&program, &[f(10)], 1000).unwrap();
    assert_eq!(io.outputs[1], f(55)); // r2 = fib(10)
    assert!(verify(&id, &program, &io, &proof, 1 << 20).is_ok());
}

#[test]
fn wrong_program_rejected() {
    let program = fibonacci();
    let (io, proof) = prove(&program, &[f(5)], 1000).unwrap();
    let mut other = program.clone();
    other[0] = Instruction::LoadImm(2, f(1));
    let id = commit(&program);
    assert!(verify(&id, &other, &io, &proof, 1 << 20).is_err());
}

#[test]
fn forged_output_rejected() {
    let program = fibonacci();
    let id = commit(&program);
    let (mut io, proof) = prove(&program, &[f(7)], 1000).unwrap();
    io.outputs[1] = f(999);
    assert!(verify(&id, &program, &io, &proof, 1 << 20).is_err());
}

#[test]
fn forged_witness_rejected() {
    let program = fibonacci();
    let id = commit(&program);
    let (io, mut proof) = prove(&program, &[f(7)], 1000).unwrap();
    let i = proof.witness.len() / 3;
    proof.witness[i] += f(1);
    assert!(verify(&id, &program, &io, &proof, 1 << 20).is_err());
}

#[test]
fn step_bound_enforced() {
    let program = fibonacci();
    let id = commit(&program);
    let (io, proof) = prove(&program, &[f(50)], 10_000).unwrap();
    assert!(verify(&id, &program, &io, &proof, 8).is_err());
}

#[test]
fn truncated_trace_rejected() {
    // A prefix of an execution must not verify: trace must end in Halt.
    let program = fibonacci();
    let id = commit(&program);
    let (io, mut proof) = prove(&program, &[f(5)], 1000).unwrap();
    proof.pc_trace.truncate(proof.pc_trace.len() - 2);
    assert!(verify(&id, &program, &io, &proof, 1 << 20).is_err());
}
