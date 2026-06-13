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

use blacknet_snark::pipeline::{Error, Shape, prove_aggregate, prove_execution, verify_aggregate};
use blacknet_snark::witnesscommitment::{CommitmentKey, F};
use blacknet_vm::machine::Instruction;

const TEST_ROWS: usize = 8;

fn f(n: i32) -> F {
    F::from(n)
}

// A uniform (fixed control flow) program: y = x^3 + 2x + 7.
fn cube_program() -> Vec<Instruction<F>> {
    vec![
        Instruction::Mul(2, 1, 1), // x^2
        Instruction::Mul(2, 2, 1), // x^3
        Instruction::Add(3, 1, 1), // 2x
        Instruction::Add(2, 2, 3), // x^3 + 2x
        Instruction::LoadImm(4, f(7)),
        Instruction::Add(5, 2, 4), // result in r5
        Instruction::Halt,
    ]
}

fn expected(x: i64) -> F {
    F::from((x * x * x + 2 * x + 7) as i32)
}

#[test]
fn end_to_end_aggregate() {
    let shape = Shape::derive(cube_program(), &[f(1)], 100).unwrap();
    let key = CommitmentKey::setup(shape.elements, TEST_ROWS);

    let inputs = [3i64, 5, 11, 42];
    let executions: Vec<_> = inputs
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[F::from(x as i32)]).unwrap())
        .collect();
    // IO sanity: r5 is REGISTERS-indexed output slot 1 (input) + 4 (r5).
    for (e, &x) in executions.iter().zip(&inputs) {
        assert_eq!(e.io[1 + 4], expected(x)); // outputs start after 1 input
    }

    let proof = prove_aggregate(&shape, &key, &executions).unwrap();
    assert!(verify_aggregate(&shape, &key, &proof).is_ok());
}

#[test]
fn forged_io_rejected() {
    let shape = Shape::derive(cube_program(), &[f(1)], 100).unwrap();
    let key = CommitmentKey::setup(shape.elements, TEST_ROWS);
    let executions: Vec<_> = [2i64, 9]
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[F::from(x as i32)]).unwrap())
        .collect();
    let mut proof = prove_aggregate(&shape, &key, &executions).unwrap();
    proof.ios[1][1 + 4] += f(1); // claim a wrong output for instance 1
    assert!(verify_aggregate(&shape, &key, &proof).is_err());
}

#[test]
fn forged_opening_rejected() {
    let shape = Shape::derive(cube_program(), &[f(1)], 100).unwrap();
    let key = CommitmentKey::setup(shape.elements, TEST_ROWS);
    let executions: Vec<_> = [2i64, 9]
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[F::from(x as i32)]).unwrap())
        .collect();
    let mut proof = prove_aggregate(&shape, &key, &executions).unwrap();
    let i = proof.opening.dimension() / 2;
    proof.opening[i] += f(1);
    assert!(verify_aggregate(&shape, &key, &proof).is_err());
}

#[test]
fn nonuniform_input_rejected_at_proving() {
    // A program whose control flow depends on the input is not uniform.
    let program = vec![
        Instruction::Bne(1, 0, 3),
        Instruction::LoadImm(2, f(1)),
        Instruction::Halt,
        Instruction::LoadImm(2, f(2)),
        Instruction::Halt,
    ];
    let shape = Shape::derive(program, &[f(1)], 100).unwrap(); // branch taken
    let key = CommitmentKey::setup(shape.elements, TEST_ROWS);
    // Input 0 takes the other branch: shape violation, refused at proving.
    assert!(matches!(
        prove_execution(&shape, &key, &[f(0)]),
        Err(Error::NotUniform)
    ));
}

#[test]
fn succinct_opening_is_sublinear_and_verifies() {
    use blacknet_snark::pipeline::prove_aggregate_succinct;
    let shape = Shape::derive(cube_program(), &[f(1)], 100).unwrap();
    let key = CommitmentKey::setup(shape.elements, TEST_ROWS);
    let executions: Vec<_> = [3i32, 8, 21, 100]
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[f(x)]).unwrap())
        .collect();
    let proof = prove_aggregate_succinct(&shape, &key, &executions).unwrap();
    // The linear witness is gone; the proof carries only the argument.
    assert!(proof.succinct.is_some());
    assert_eq!(proof.opening.dimension(), 0);
    assert!(verify_aggregate(&shape, &key, &proof).is_ok());
}

#[test]
fn succinct_opening_rejects_tampered_argument() {
    use blacknet_snark::pipeline::prove_aggregate_succinct;
    let shape = Shape::derive(cube_program(), &[f(1)], 100).unwrap();
    let key = CommitmentKey::setup(shape.elements, TEST_ROWS);
    let executions: Vec<_> = [2i32, 5]
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[f(x)]).unwrap())
        .collect();
    let mut proof = prove_aggregate_succinct(&shape, &key, &executions).unwrap();
    if let Some(arg) = proof.succinct.as_mut() {
        arg.bit_eval += f(1);
    }
    assert!(verify_aggregate(&shape, &key, &proof).is_err());
}

#[test]
fn succinct_zk_opening_verifies_and_hides() {
    use blacknet_snark::pipeline::prove_aggregate_succinct_zk;
    let shape = Shape::derive(cube_program(), &[f(1)], 100).unwrap();
    let key = CommitmentKey::setup(shape.elements, TEST_ROWS);
    let executions: Vec<_> = [3i32, 8, 21]
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[f(x)]).unwrap())
        .collect();
    let p1 = prove_aggregate_succinct_zk(&shape, &key, &executions).unwrap();
    let p2 = prove_aggregate_succinct_zk(&shape, &key, &executions).unwrap();
    assert!(p1.succinct_zk.is_some());
    assert_eq!(p1.opening.dimension(), 0);
    // Fresh mask each run: disclosed evaluations differ, both verify.
    let e1 = p1.succinct_zk.as_ref().unwrap().bit_eval;
    let e2 = p2.succinct_zk.as_ref().unwrap().bit_eval;
    assert_ne!(e1, e2);
    assert!(verify_aggregate(&shape, &key, &p1).is_ok());
    assert!(verify_aggregate(&shape, &key, &p2).is_ok());
}
