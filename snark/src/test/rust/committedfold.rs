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
use blacknet_snark::recursion::{assign, fold_verifier_circuit};
use blacknet_snark::witnesscommitment::{
    CommitmentKey, F, MAX_NORM, decompose, infinity_norm, recompose,
};
use blacknet_vm::machine::Instruction;

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
    let key = CommitmentKey::setup(z.dimension());
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
    let key = CommitmentKey::setup(z1.dimension());
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
    let key = CommitmentKey::setup(z1.dimension());
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
    let key = CommitmentKey::setup(z1.dimension());
    let (i1, w1) = strict(&key, &r1cs, &z1);
    let (i2, w2) = strict(&key, &r1cs, &z2);
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(f(3));
    let (mut i, w) = fold(&r1cs, (&i1, &w1), (&i2, &w2), &mut duplex).unwrap();
    i.u += f(1);
    assert!(open(&key, &r1cs, &i, &w).is_err());
}

#[test]
fn fold_verifier_circuit_checks_the_fold() {
    let (r1cs, z1) = setup(3);
    let (_, z2) = setup(11);
    let key = CommitmentKey::setup(z1.dimension());
    let (i1, w1) = strict(&key, &r1cs, &z1);
    let (i2, w2) = strict(&key, &r1cs, &z2);

    // Replay the transcript to recover the challenge the fold used.
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(f(4));
    let mut replay = DuplexPoseidon2Pervushin::default();
    replay.absorb(f(4));
    let (i, _) = fold(&r1cs, (&i1, &w1), (&i2, &w2), &mut duplex).unwrap();
    for c in [&i1.commitment, &i2.commitment] {
        for k in 0..c.dimension() {
            replay.absorb(c[k]);
        }
    }
    replay.absorb(i1.u);
    replay.absorb(i2.u);
    let (r, _) = blacknet_snark::witnesscommitment::squeeze_challenge(&mut replay);

    let limbs = |v: &DenseVector<F>| (0..v.dimension()).map(|k| v[k]).collect::<Vec<_>>();
    let circuit = fold_verifier_circuit();
    let z = assign(
        r,
        i1.u,
        i2.u,
        i.u,
        &limbs(&i1.commitment),
        &limbs(&i2.commitment),
        &limbs(&i.commitment),
    );
    assert!(circuit.is_satisfied(&DenseVector::from(z.clone())).is_ok());

    // A forged folded u is rejected by the circuit.
    let mut bad = z;
    bad[4] += f(1); // u is the 4th public input (after the constant 1)
    assert!(circuit.is_satisfied(&DenseVector::from(bad)).is_err());
}
