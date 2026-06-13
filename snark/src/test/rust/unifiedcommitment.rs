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
use blacknet_crypto::matrix::DenseVector;
use blacknet_snark::unifiedcommitment::{
    DEGREE, Fold, HIDE_ROWS, Ring, UnifiedKey, pack, randomness_norm, sample_randomness,
};
use blacknet_snark::witnesscommitment::decompose;
use blacknet_vm::machine::Instruction;

fn f(n: i32) -> Fold {
    Fold::from(n)
}

fn message() -> DenseVector<Ring> {
    let program = vec![
        Instruction::Mul(2, 1, 1),
        Instruction::Add(3, 2, 1),
        Instruction::Halt,
    ];
    let w = execute(&program, &[f(99)], 100).unwrap().witness;
    pack(&decompose(&w))
}

#[test]
fn pack_is_norm_preserving() {
    let program = vec![Instruction::LoadImm(1, f(12345)), Instruction::Halt];
    let w = execute(&program, &[], 100).unwrap().witness;
    let d = decompose(&w);
    let packed = pack(&d);
    assert_eq!(packed.dimension(), d.dimension().div_ceil(DEGREE));
    // digits are < 2^16, so packed coefficients stay small (norm-preserving)
    assert!(randomness_norm(&packed) < 1 << 16);
}

#[test]
fn commitment_binds_and_opens() {
    let m = message();
    let key = UnifiedKey::setup(m.dimension().max(HIDE_ROWS));
    let r = sample_randomness();
    let c = key.commit(&m, &r);
    let bound = randomness_norm(&r);
    assert!(key.open(&c, &m, &r, bound));
    // wrong randomness bound (too tight) fails closed
    assert!(!key.open(&c, &m, &r, bound.saturating_sub(1)));
}

#[test]
fn commitment_hides() {
    // Same message, two fresh hiding randomnesses: commitments differ.
    let m = message();
    let key = UnifiedKey::setup(m.dimension().max(HIDE_ROWS));
    let r1 = sample_randomness();
    let r2 = sample_randomness();
    let c1 = key.commit(&m, &r1);
    let c2 = key.commit(&m, &r2);
    assert_ne!(c1, c2);
}

#[test]
fn commitment_is_homomorphic() {
    // BDLOP is linear: commit(m1,r1) + commit(m2,r2) opens to (m1+m2, r1+r2).
    let m1 = message();
    let key = UnifiedKey::setup(m1.dimension().max(HIDE_ROWS));
    let m2: DenseVector<Ring> = (0..m1.dimension()).map(|i| m1[i] + m1[i]).collect();
    let r1 = sample_randomness();
    let r2 = sample_randomness();
    let c1 = key.commit(&m1, &r1);
    let c2 = key.commit(&m2, &r2);

    let sum_binding: DenseVector<Ring> = (0..c1.binding.dimension())
        .map(|i| c1.binding[i] + c2.binding[i])
        .collect();
    let m_sum: DenseVector<Ring> = (0..m1.dimension()).map(|i| m1[i] + m2[i]).collect();
    let r_sum: DenseVector<Ring> = (0..r1.dimension()).map(|i| r1[i] + r2[i]).collect();
    let c_sum = key.commit(&m_sum, &r_sum);
    assert_eq!(sum_binding, c_sum.binding);
}

#[test]
fn tampered_message_fails() {
    let m = message();
    let key = UnifiedKey::setup(m.dimension().max(HIDE_ROWS));
    let r = sample_randomness();
    let c = key.commit(&m, &r);
    let mut bad: Vec<Ring> = (0..m.dimension()).map(|i| m[i]).collect();
    bad[0] = bad[0] + Ring::default(); // no-op
    bad[0][0] = blacknet_crypto::lm::LMField::from(7u32) + bad[0][0];
    assert!(!key.open(&c, &DenseVector::from(bad), &r, randomness_norm(&r) + 100));
}
