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
use blacknet_crypto::algebra::IntegerRing;
use blacknet_snark::pipeline::{
    SALT_ELEMENTS, Shape, prove_aggregate, prove_aggregate_zk, prove_execution_salted,
    verify_aggregate,
};
use blacknet_snark::witnesscommitment::{CommitmentKey, F};
use blacknet_snark::zk::BLIND_BITS;
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

fn setup() -> (Shape, CommitmentKey) {
    let shape = Shape::derive(program(), &[f(1)], 100).unwrap();
    let key = CommitmentKey::setup(shape.elements + SALT_ELEMENTS, TEST_ROWS);
    (shape, key)
}

#[test]
fn zk_aggregate_roundtrip() {
    let (shape, key) = setup();
    let executions: Vec<_> = [3i32, 7, 19]
        .iter()
        .map(|&x| prove_execution_salted(&shape, &key, &[f(x)], SALT_ELEMENTS).unwrap())
        .collect();
    let proof = prove_aggregate_zk(&shape, &key, &executions).unwrap();
    assert!(proof.blind.is_some());
    assert!(verify_aggregate(&shape, &key, &proof).is_ok());
}

#[test]
fn blinded_opening_is_independent_of_witness() {
    let (shape, key) = setup();
    let executions: Vec<_> = [3i32, 7]
        .iter()
        .map(|&x| prove_execution_salted(&shape, &key, &[f(x)], SALT_ELEMENTS).unwrap())
        .collect();

    // The unblinded folded witness, for comparison.
    let plain = prove_aggregate(&shape, &key, &executions).unwrap();
    let prefold_bound = plain.accumulator.norm_bound;

    // Two ZK proofs of the same batch: openings must differ (fresh
    // entropy) and every opened digit must lie in the rejection window
    // [prefold_bound, 2^(16+BLIND_BITS)), i.e. carry no information about
    // the true digits, which all lie below prefold_bound.
    let p1 = prove_aggregate_zk(&shape, &key, &executions).unwrap();
    let p2 = prove_aggregate_zk(&shape, &key, &executions).unwrap();
    assert_ne!(
        (0..p1.opening.dimension())
            .map(|i| p1.opening[i])
            .collect::<Vec<_>>(),
        (0..p2.opening.dimension())
            .map(|i| p2.opening[i])
            .collect::<Vec<_>>()
    );
    for p in [&p1, &p2] {
        for i in 0..p.opening.dimension() {
            let v = p.opening[i].canonical() as u128;
            assert!(v >= prefold_bound, "digit below the blinding window");
            assert!(v < 1u128 << (16 + BLIND_BITS), "digit above the window");
        }
        // And the blinded opening differs from the true folded witness.
        assert_ne!(
            (0..p.opening.dimension())
                .map(|i| p.opening[i])
                .collect::<Vec<_>>(),
            (0..plain.opening.dimension())
                .map(|i| plain.opening[i])
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn forged_blind_claims_rejected() {
    let (shape, key) = setup();
    let executions: Vec<_> = [5i32, 9]
        .iter()
        .map(|&x| prove_execution_salted(&shape, &key, &[f(x)], SALT_ELEMENTS).unwrap())
        .collect();
    let mut proof = prove_aggregate_zk(&shape, &key, &executions).unwrap();
    if let Some(blind) = proof.blind.as_mut() {
        blind.evals[0] += f(1);
    }
    assert!(verify_aggregate(&shape, &key, &proof).is_err());
}

#[test]
fn salted_commitments_hide() {
    let (shape, key) = setup();
    // Same input, two salted runs: commitments differ, IO identical.
    let e1 = prove_execution_salted(&shape, &key, &[f(6)], SALT_ELEMENTS).unwrap();
    let e2 = prove_execution_salted(&shape, &key, &[f(6)], SALT_ELEMENTS).unwrap();
    assert_eq!(e1.io, e2.io);
    assert_ne!(
        (0..e1.commitment.dimension())
            .map(|i| e1.commitment[i])
            .collect::<Vec<_>>(),
        (0..e2.commitment.dimension())
            .map(|i| e2.commitment[i])
            .collect::<Vec<_>>()
    );
    // Unsalted runs are deterministic - the leak salting closes.
    let key0 = CommitmentKey::setup(shape.elements, TEST_ROWS);
    let u1 = prove_execution_salted(&shape, &key0, &[f(6)], 0).unwrap();
    let u2 = prove_execution_salted(&shape, &key0, &[f(6)], 0).unwrap();
    assert_eq!(
        (0..u1.commitment.dimension())
            .map(|i| u1.commitment[i])
            .collect::<Vec<_>>(),
        (0..u2.commitment.dimension())
            .map(|i| u2.commitment[i])
            .collect::<Vec<_>>()
    );
}

#[test]
fn salted_executions_still_verify_unblinded() {
    // Salt alone (no blinding fold) must not break the base pipeline.
    let (shape, key) = setup();
    let executions: Vec<_> = [2i32, 4, 8]
        .iter()
        .map(|&x| prove_execution_salted(&shape, &key, &[f(x)], SALT_ELEMENTS).unwrap())
        .collect();
    let proof = prove_aggregate(&shape, &key, &executions).unwrap();
    assert!(proof.blind.is_none());
    assert!(verify_aggregate(&shape, &key, &proof).is_ok());
}

#[test]
fn execute_smoke() {
    // Guard: salting does not perturb execution semantics.
    let e = execute(&program(), &[f(6)], 100).unwrap();
    assert_eq!(e.outputs[2], f(42));
}
