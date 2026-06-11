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

use blacknet_arith::trace::{F, constrain, execute};
use blacknet_crypto::constraintsystem::ConstraintSystem;
use blacknet_vm::machine::Instruction;

fn f(n: i32) -> F {
    F::from(n)
}

fn factorial_program() -> Vec<Instruction<F>> {
    // inputs: r1 = n; r3 = 1 constant; result in r2
    vec![
        Instruction::LoadImm(2, f(1)),
        Instruction::LoadImm(3, f(1)),
        Instruction::Mul(2, 2, 1),
        Instruction::Sub(1, 1, 3),
        Instruction::Bne(1, 0, 2),
        Instruction::Halt,
    ]
}

#[test]
fn trace_satisfies_constraints() {
    let program = factorial_program();
    let execution = execute(&program, &[f(5)], 1000).unwrap();
    assert!(
        execution
            .r1cs
            .to_ccs()
            .is_satisfied(&execution.witness)
            .is_ok()
    );
    assert_eq!(execution.outputs[1], f(120)); // r2
}

#[test]
fn straightline_and_branches() {
    let program = vec![
        Instruction::LoadImm(1, f(7)),
        Instruction::LoadImm(2, f(7)),
        Instruction::Beq(1, 2, 4),
        Instruction::Halt, // skipped
        Instruction::Add(3, 1, 2),
        Instruction::Neg(4, 3),
        Instruction::Mov(5, 4),
        Instruction::Halt,
    ];
    let execution = execute(&program, &[], 100).unwrap();
    assert!(
        execution
            .r1cs
            .to_ccs()
            .is_satisfied(&execution.witness)
            .is_ok()
    );
    assert_eq!(execution.outputs[4], f(-14)); // r5
}

#[test]
fn tampered_witness_rejected() {
    let program = factorial_program();
    let execution = execute(&program, &[f(4)], 1000).unwrap();
    let mut bad: Vec<F> = execution.witness.into_iter().collect();
    let i = bad.len() / 2;
    bad[i] += f(1);
    let z = blacknet_crypto::matrix::DenseVector::from(bad);
    assert!(execution.r1cs.to_ccs().is_satisfied(&z).is_err());
}

#[test]
fn tampered_pc_trace_rejected() {
    let program = factorial_program();
    let execution = execute(&program, &[f(3)], 1000).unwrap();
    let mut pc = execution.pc_trace.clone();
    // Pretend the loop exited one iteration early.
    let i = pc.len() / 2;
    pc[i] = 5;
    match constrain(&program, &[f(3)], &pc) {
        Err(_) => {} // inconsistent control flow detected structurally
        Ok((r1cs, _)) => {
            // or the old witness no longer satisfies the rebuilt system
            assert!(r1cs.to_ccs().is_satisfied(&execution.witness).is_err());
        }
    }
}

#[test]
fn verifier_rebuilds_identical_system() {
    let program = factorial_program();
    let execution = execute(&program, &[f(6)], 1000).unwrap();
    let (rebuilt, _) = constrain(&program, &[f(6)], &execution.pc_trace).unwrap();
    assert!(rebuilt.to_ccs().is_satisfied(&execution.witness).is_ok());
    assert_eq!(
        rebuilt.to_ccs().constraints(),
        execution.r1cs.to_ccs().constraints()
    );
}

#[test]
fn matrices_are_input_independent() {
    // Same program and control flow, different inputs: identical shape.
    // Input binding is positional, done by the snark verifier.
    let program = vec![
        Instruction::Mul(2, 1, 1),
        Instruction::Add(3, 2, 1),
        Instruction::Halt,
    ];
    let e1 = execute(&program, &[f(3)], 100).unwrap();
    let e2 = execute(&program, &[f(11)], 100).unwrap();
    // e2's witness satisfies the system rebuilt for e1's run and vice versa.
    assert!(e1.r1cs.to_ccs().is_satisfied(&e2.witness).is_ok());
    assert!(e2.r1cs.to_ccs().is_satisfied(&e1.witness).is_ok());
    // Witness initial state still records the actual inputs.
    assert_eq!(e1.witness[1], f(3));
    assert_eq!(e2.witness[1], f(11));
}
