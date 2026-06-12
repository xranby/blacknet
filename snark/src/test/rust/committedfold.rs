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
use blacknet_crypto::matrix::DenseVector;
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};
use blacknet_snark::committedfold::{Error, fold, open, strict};
use blacknet_snark::recursion::fold_verifier_circuit;
use blacknet_snark::witnesscommitment::{
    CommitmentKey, F, MAX_NORM, decompose, infinity_norm, recompose,
};
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
        Instruction::Halt,
    ]
}

fn setup(n: i32) -> (blacknet_arith::r1cs::ShapedR1cs, DenseVector<F>) {
    let e = execute(&program(), &[f(n)], 100).unwrap();
    (e.r1cs, e.witness)
}

#[test]
fn decompose_recompose_roundtrip() {
    let (_, z) = setup(12345);
    let d = decompose(&z);
    assert!(infinity_norm(&d) < 1 << 16);
    assert_eq!(recompose(&d), z);
}

#[test]
fn commitment_binds_and_opens() {
    let (_, z) = setup(7);
    let key = CommitmentKey::setup(z.dimension(), TEST_ROWS);
    let d = decompose(&z);
    let c = key.commit(&d);
    assert!(key.open(&c, &d, infinity_norm(&d)));
    // Over-budget norm bound fails closed even with a valid opening.
    assert!(!key.open(&c, &d, MAX_NORM + 1));
    // Tampered digits fail.
    let mut bad: Vec<F> = (0..d.dimension()).map(|i| d[i]).collect();
    bad[0] += f(1);
    assert!(!key.open(&c, &DenseVector::from(bad), MAX_NORM));
}

#[test]
fn committed_fold_satisfies_and_opens() {
    let (r1cs, z1) = setup(3);
    let (_, z2) = setup(11);
    let key = CommitmentKey::setup(z1.dimension(), TEST_ROWS);
    let (i1, w1) = strict(&key, &r1cs, &z1);
    let (i2, w2) = strict(&key, &r1cs, &z2);
    assert!(open(&key, &r1cs, &i1, &w1).is_ok());
    assert!(open(&key, &r1cs, &i2, &w2).is_ok());

    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(f(1)); // protocol context
    let (i, w) = fold(&r1cs, (&i1, &w1), (&i2, &w2), &mut duplex).unwrap();
    assert!(open(&key, &r1cs, &i, &w).is_ok());

    // The folded commitment is the homomorphic combination: re-commit
    // the folded digits and compare.
    assert_eq!(key.commit(&w.d), i.commitment);
}

#[test]
fn norm_budget_fails_closed() {
    let (r1cs, z1) = setup(3);
    let (_, z2) = setup(5);
    let key = CommitmentKey::setup(z1.dimension(), TEST_ROWS);
    let (mut i1, w1) = strict(&key, &r1cs, &z1);
    let (i2, w2) = strict(&key, &r1cs, &z2);
    i1.norm_bound = MAX_NORM; // accumulator at the binding limit
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(f(2));
    assert_eq!(
        fold(&r1cs, (&i1, &w1), (&i2, &w2), &mut duplex).unwrap_err(),
        Error::NormBudget
    );
}

#[test]
fn forged_fold_rejected_at_opening() {
    let (r1cs, z1) = setup(3);
    let (_, z2) = setup(11);
    let key = CommitmentKey::setup(z1.dimension(), TEST_ROWS);
    let (i1, w1) = strict(&key, &r1cs, &z1);
    let (i2, w2) = strict(&key, &r1cs, &z2);
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(f(3));
    let (mut i, w) = fold(&r1cs, (&i1, &w1), (&i2, &w2), &mut duplex).unwrap();
    i.u += f(1);
    assert!(open(&key, &r1cs, &i, &w).is_err());
}

#[test]
fn fold_verifier_circuit_derives_challenge_in_circuit() {
    let (r1cs, z1) = setup(3);
    let (_, z2) = setup(11);
    let key = CommitmentKey::setup(z1.dimension(), TEST_ROWS);
    let (i1, w1) = strict(&key, &r1cs, &z1);
    let (i2, w2) = strict(&key, &r1cs, &z2);

    let mut duplex = DuplexPoseidon2Pervushin::default();
    let (i, _) = fold(&r1cs, (&i1, &w1), (&i2, &w2), &mut duplex).unwrap();

    let limbs = |v: &DenseVector<F>| (0..v.dimension()).map(|k| v[k]).collect::<Vec<_>>();
    let (c1, c2, c) = (
        limbs(&i1.commitment),
        limbs(&i2.commitment),
        limbs(&i.commitment),
    );

    let circuit = fold_verifier_circuit(TEST_ROWS);
    let z = circuit.assigment();
    z.extend([i1.u, i2.u, i.u]);
    z.extend(c1.iter().copied());
    z.extend(c2.iter().copied());
    z.extend(c.iter().copied());
    // Mirror the in-circuit transcript and bit decomposition.
    blacknet_snark::recursion::assigner::fill(&z, i1.u, i2.u, &c1, &c2);
    assert!(circuit.is_satisfied(&z.finish()).is_ok());

    // A forged folded u cannot be assigned satisfyingly: rebuild with u+1.
    let bad = circuit.assigment();
    bad.extend([i1.u, i2.u, i.u + f(1)]);
    bad.extend(c1.iter().copied());
    bad.extend(c2.iter().copied());
    bad.extend(c.iter().copied());
    blacknet_snark::recursion::assigner::fill(&bad, i1.u, i2.u, &c1, &c2);
    assert!(circuit.is_satisfied(&bad.finish()).is_err());
}
