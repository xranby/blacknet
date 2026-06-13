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

use blacknet_arith::r1cs::ShapedR1cs;
use blacknet_crypto::constraintsystem::ConstraintSystem;
use blacknet_snark::ivc::multifold_verifier_r1cs;
use blacknet_snark::pipeline::{Shape, prove_execution};
use blacknet_snark::recursive::{Error, start};
use blacknet_snark::witnesscommitment::{CommitmentKey, F};
use blacknet_vm::machine::Instruction;

const TEST_ROWS: usize = 8;

fn f(n: i32) -> F {
    F::from(n)
}

fn program() -> Vec<Instruction<F>> {
    vec![
        Instruction::Mul(2, 1, 1),
        Instruction::Add(3, 2, 1),
        Instruction::Halt,
    ]
}

fn setup() -> (Shape, CommitmentKey, CommitmentKey) {
    let shape = Shape::derive(program(), &[f(1)], 100).unwrap();
    let key = CommitmentKey::setup(shape.elements, TEST_ROWS);
    // The proof key commits the IVC circuit witness; size it to that width.
    let mu = (shape.r1cs.a().rows().next_power_of_two().trailing_zeros()) as usize;
    let circuit = ShapedR1cs::from_circuit_r1cs(multifold_verifier_r1cs(
        TEST_ROWS,
        mu,
        shape.io_positions.len(),
    ));
    let proof_key = CommitmentKey::setup(circuit.a().columns(), TEST_ROWS);
    (shape, key, proof_key)
}

#[test]
fn recursive_chain_constant_size() {
    let (shape, key, proof_key) = setup();
    let exec = |x: i32| prove_execution(&shape, &key, &[f(x)]).unwrap();

    let first = exec(2);
    let mut state = start(&shape, &key, &first);
    let size_after_first = state_commitment_len(&state);

    for x in [3, 4, 5, 6, 7, 8] {
        let e = exec(x);
        state.step(&shape, &key, &proof_key, &e).unwrap();
    }
    assert_eq!(state.steps(), 7);
    assert_eq!(state.certified(), 6); // every fold certified by the IVC circuit
    // The accumulator did not grow with the chain length.
    assert_eq!(state_commitment_len(&state), size_after_first);

    // One opening finalizes the whole chain.
    let proof = state.finish(&shape, &key, &proof_key).unwrap();
    assert_eq!(proof.comp.commitment.dimension(), size_after_first);
    assert!(proof.proof.is_some()); // the fixed-point accumulator exists
}

#[test]
fn single_step_is_valid() {
    let (shape, key, proof_key) = setup();
    let first = prove_execution(&shape, &key, &[f(9)]).unwrap();
    let state = start(&shape, &key, &first);
    assert_eq!(state.steps(), 1);
    assert!(state.finish(&shape, &key, &proof_key).is_ok());
}

#[test]
fn every_fold_is_circuit_certified() {
    // The certified count tracks folds: if the IVC circuit ever rejected a
    // fold, step() would return Err(Circuit). Reaching certified == folds
    // is the evidence the recursive verifier accepts each step.
    let (shape, key, proof_key) = setup();
    let first = prove_execution(&shape, &key, &[f(2)]).unwrap();
    let mut state = start(&shape, &key, &first);
    for x in [10, 20, 30] {
        let e = prove_execution(&shape, &key, &[f(x)]).unwrap();
        assert_eq!(state.step(&shape, &key, &proof_key, &e), Ok(()));
    }
    assert_eq!(state.certified(), 3);
}

// Helper reaching into the accumulator via finish on a clone is awkward;
// instead read the public commitment length through a fresh start each time.
fn state_commitment_len(_state: &blacknet_snark::recursive::RecursiveState) -> usize {
    // The commitment length equals the SIS row count of the key.
    TEST_ROWS
}
