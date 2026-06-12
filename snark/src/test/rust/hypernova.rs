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
use blacknet_snark::hypernova::{Error, init, init_verify, multifold, multifold_verify, open};
use blacknet_snark::witnesscommitment::{CommitmentKey, F, MAX_NORM, decompose, infinity_norm};
use blacknet_vm::machine::Instruction;

// Small SIS dimension for test speed; consensus uses SECURE_ROWS.
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
fn init_roundtrip() {
    let (r1cs, z) = run(3);
    let key = CommitmentKey::setup(z.dimension(), TEST_ROWS);
    let (acc, w, proof) = init(&key, &r1cs, &z, &CTX);
    let norm = infinity_norm(&decompose(&z));
    let verified = init_verify(&r1cs, &acc.commitment, norm, &proof, &CTX).unwrap();
    assert_eq!(verified.point, acc.point);
    assert_eq!(verified.evals, acc.evals);
    assert!(open(&key, &r1cs, &acc, &w).is_ok());
    assert!(open(&key, &r1cs, &verified, &w).is_ok());
}

#[test]
fn multifold_chain_no_error_vector() {
    let (r1cs, z0) = run(3);
    let key = CommitmentKey::setup(z0.dimension(), TEST_ROWS);
    let (mut acc, mut w, proof) = init(&key, &r1cs, &z0, &CTX);
    let norm0 = infinity_norm(&decompose(&z0));
    let mut vacc = init_verify(&r1cs, &acc.commitment, norm0, &proof, &CTX).unwrap();

    for n in [5, 7, 11, 13] {
        let (_, z) = run(n);
        let fresh_norm = infinity_norm(&decompose(&z));
        let fresh_commitment = key.commit(&decompose(&z));
        let (nacc, nw, proof) = multifold(&key, &r1cs, (&acc, &w), &z, &CTX).unwrap();
        // Independent verifier from public data only.
        vacc = multifold_verify(&r1cs, &vacc, &fresh_commitment, fresh_norm, &proof, &CTX).unwrap();
        assert_eq!(vacc.point, nacc.point);
        assert_eq!(vacc.evals, nacc.evals);
        assert_eq!(vacc.norm_bound, nacc.norm_bound);
        acc = nacc;
        w = nw;
        assert!(open(&key, &r1cs, &acc, &w).is_ok());
    }
}

#[test]
fn forged_sigma_rejected() {
    let (r1cs, z0) = run(3);
    let key = CommitmentKey::setup(z0.dimension(), TEST_ROWS);
    let (acc, w, iproof) = init(&key, &r1cs, &z0, &CTX);
    let norm0 = infinity_norm(&decompose(&z0));
    let vacc = init_verify(&r1cs, &acc.commitment, norm0, &iproof, &CTX).unwrap();

    let (_, z) = run(5);
    let fresh_norm = infinity_norm(&decompose(&z));
    let fresh_commitment = key.commit(&decompose(&z));
    let (_, _, mut proof) = multifold(&key, &r1cs, (&acc, &w), &z, &CTX).unwrap();
    proof.sigma[0] += f(1);
    assert_eq!(
        multifold_verify(&r1cs, &vacc, &fresh_commitment, fresh_norm, &proof, &CTX).unwrap_err(),
        Error::ClaimMismatch
    );
}

#[test]
fn unsatisfying_fresh_witness_rejected() {
    let (r1cs, z0) = run(3);
    let key = CommitmentKey::setup(z0.dimension(), TEST_ROWS);
    let (acc, w, iproof) = init(&key, &r1cs, &z0, &CTX);
    let norm0 = infinity_norm(&decompose(&z0));
    let vacc = init_verify(&r1cs, &acc.commitment, norm0, &iproof, &CTX).unwrap();

    let (_, z) = run(5);
    let mut bad: Vec<F> = (0..z.dimension()).map(|i| z[i]).collect();
    let mid = bad.len() / 2;
    bad[mid] += f(1);
    let bad = blacknet_crypto::matrix::DenseVector::from(bad);
    // The prover can run the fold locally and the result is even
    // self-consistent at opening - HyperNova soundness lives in the
    // VERIFIER: the fresh term's hypercube sum is nonzero, the claimed sum
    // doesn't include it, and the sumcheck final evaluation check catches
    // the discrepancy with overwhelming probability.
    let fresh_norm = infinity_norm(&decompose(&bad));
    let fresh_commitment = key.commit(&decompose(&bad));
    let (_, _, proof) = multifold(&key, &r1cs, (&acc, &w), &bad, &CTX).unwrap();
    assert_eq!(
        multifold_verify(&r1cs, &vacc, &fresh_commitment, fresh_norm, &proof, &CTX).unwrap_err(),
        Error::ClaimMismatch
    );
}

#[test]
fn norm_budget_enforced_by_verifier() {
    let (r1cs, z0) = run(3);
    let key = CommitmentKey::setup(z0.dimension(), TEST_ROWS);
    let (acc, w, iproof) = init(&key, &r1cs, &z0, &CTX);
    let norm0 = infinity_norm(&decompose(&z0));
    let mut vacc = init_verify(&r1cs, &acc.commitment, norm0, &iproof, &CTX).unwrap();
    vacc.norm_bound = MAX_NORM; // accumulator at the binding limit

    let (_, z) = run(5);
    let fresh_norm = infinity_norm(&decompose(&z));
    let fresh_commitment = key.commit(&decompose(&z));
    let (_, _, proof) = multifold(&key, &r1cs, (&acc, &w), &z, &CTX).unwrap();
    assert_eq!(
        multifold_verify(&r1cs, &vacc, &fresh_commitment, fresh_norm, &proof, &CTX).unwrap_err(),
        Error::NormBudget
    );
}
