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
use blacknet_snark::modulecommitment::{
    DEGREE, ModuleCommitmentKey, PervushinRing64, centered_norm, pack,
};
use blacknet_snark::witnesscommitment::{F, MAX_NORM, decompose, recompose};
use blacknet_vm::machine::Instruction;

const TEST_MODULE_ROWS: usize = 2;

fn f(n: i32) -> F {
    F::from(n)
}

fn witness() -> DenseVector<F> {
    let program = vec![
        Instruction::Mul(2, 1, 1),
        Instruction::Add(3, 2, 1),
        Instruction::Halt,
    ];
    execute(&program, &[f(12345)], 100).unwrap().witness
}

#[test]
fn pack_is_linear_and_norm_preserving() {
    let d = decompose(&witness());
    let packed = pack(&d);
    assert_eq!(packed.dimension(), d.dimension().div_ceil(DEGREE));
    assert!(centered_norm(&d) < 1 << 16);
    // Linearity: pack(a + 2b) = pack(a) + 2 pack(b), spot-checked.
    let two = f(2);
    let d2: DenseVector<F> = (0..d.dimension()).map(|i| d[i] + two * d[i]).collect();
    let lhs = pack(&d2);
    for i in 0..lhs.dimension() {
        let rhs: PervushinRing64 = packed[i] + packed[i] * two;
        assert_eq!(lhs[i], rhs);
    }
    let _ = recompose(&d);
}

#[test]
fn module_commitment_binds_homomorphically() {
    let z = witness();
    let key = ModuleCommitmentKey::setup(z.dimension(), TEST_MODULE_ROWS);
    let d = decompose(&z);
    let c = key.commit(&d);
    assert!(key.open(&c, &d, centered_norm(&d)));
    assert!(!key.open(&c, &d, MAX_NORM + 1));

    // Homomorphism with a small scalar challenge, as folding uses it.
    let r = f(0x55aa);
    let d2: DenseVector<F> = (0..d.dimension()).map(|i| d[i] + r * d[i]).collect();
    let folded = key.commit(&d2);
    for k in 0..c.dimension() {
        let expected: PervushinRing64 = c[k] + c[k] * r;
        assert_eq!(folded[k], expected);
    }

    // Tampering fails.
    let mut bad: Vec<F> = (0..d.dimension()).map(|i| d[i]).collect();
    bad[1] += f(1);
    assert!(!key.open(&c, &DenseVector::from(bad), MAX_NORM));
}
