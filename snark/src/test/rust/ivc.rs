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

use blacknet_arith::trace::execute;
use blacknet_crypto::constraintsystem::ConstraintSystem;
use blacknet_snark::hypernova::{init, multifold, padded_rows_of};
use blacknet_snark::ivc::{assigner, multifold_verifier_circuit};
use blacknet_snark::witnesscommitment::{CommitmentKey, F, decompose};
use blacknet_vm::machine::Instruction;

const TEST_ROWS: usize = 8;

fn f(n: i32) -> F {
    F::from(n)
}

fn program() -> Vec<Instruction<F>> {
    vec![
        Instruction::Mul(2, 1, 1),
        Instruction::Add(3, 2, 1),
        Instruction::Sub(4, 3, 1),
        Instruction::Halt,
    ]
}

fn run(
    n: i32,
) -> (
    blacknet_arith::r1cs::ShapedR1cs,
    blacknet_crypto::matrix::DenseVector<F>,
) {
    let e = execute(&program(), &[f(n)], 100).unwrap();
    (e.r1cs, e.witness)
}

const CTX: [F; 0] = [];

#[test]
fn ivc_step_circuit_verifies_a_real_multifold() {
    let (r1cs, z0) = run(3);
    let key = CommitmentKey::setup(z0.dimension(), TEST_ROWS);
    let (acc, w, _) = init(&key, &r1cs, &z0, &CTX);

    let (_, z) = run(11);
    let fresh_commitment = key.commit(&decompose(&z));
    let (next, _, proof) = multifold(&key, &r1cs, (&acc, &w), &z, &CTX).unwrap();

    let mu = padded_rows_of(&r1cs).trailing_zeros() as usize;
    let circuit = multifold_verifier_circuit(TEST_ROWS, mu);
    let z_assigned = circuit.assigment();
    assigner::fill(&z_assigned, &acc, &fresh_commitment, &next, &proof, mu);
    assert!(circuit.is_satisfied(&z_assigned.finish()).is_ok());
}

#[test]
fn ivc_step_circuit_rejects_forged_fold() {
    let (r1cs, z0) = run(3);
    let key = CommitmentKey::setup(z0.dimension(), TEST_ROWS);
    let (acc, w, _) = init(&key, &r1cs, &z0, &CTX);

    let (_, z) = run(11);
    let fresh_commitment = key.commit(&decompose(&z));
    let (mut next, _, proof) = multifold(&key, &r1cs, (&acc, &w), &z, &CTX).unwrap();
    next.evals[0] += f(1); // forge the folded claim

    let mu = padded_rows_of(&r1cs).trailing_zeros() as usize;
    let circuit = multifold_verifier_circuit(TEST_ROWS, mu);
    let z_assigned = circuit.assigment();
    assigner::fill(&z_assigned, &acc, &fresh_commitment, &next, &proof, mu);
    assert!(circuit.is_satisfied(&z_assigned.finish()).is_err());
}

#[test]
fn ivc_step_circuit_rejects_forged_sumcheck() {
    let (r1cs, z0) = run(3);
    let key = CommitmentKey::setup(z0.dimension(), TEST_ROWS);
    let (acc, w, _) = init(&key, &r1cs, &z0, &CTX);

    let (_, z) = run(11);
    let fresh_commitment = key.commit(&decompose(&z));
    let (next, _, mut proof) = multifold(&key, &r1cs, (&acc, &w), &z, &CTX).unwrap();
    proof.sigma[1] += f(1); // forge the prover-supplied evaluation

    let mu = padded_rows_of(&r1cs).trailing_zeros() as usize;
    let circuit = multifold_verifier_circuit(TEST_ROWS, mu);
    let z_assigned = circuit.assigment();
    assigner::fill(&z_assigned, &acc, &fresh_commitment, &next, &proof, mu);
    assert!(circuit.is_satisfied(&z_assigned.finish()).is_err());
}
