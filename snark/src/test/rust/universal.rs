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

use blacknet_snark::universal::{Layout, OPCODES, assign_step, op, universal_step_r1cs};
use blacknet_snark::witnesscommitment::F;

fn f(n: i32) -> F {
    F::from(n)
}

fn satisfied(z: &blacknet_crypto::matrix::DenseVector<F>) -> bool {
    // Az ∘ Bz = Cz over every row.
    let (az, bz, cz) = universal_step_r1cs().images(z);
    (0..az.dimension()).all(|i| az[i] * bz[i] == cz[i])
}

#[test]
fn every_opcode_verifies() {
    // The SAME circuit verifies a step of each opcode - control flow is data.
    assert!(satisfied(&assign_step(op::ADD, f(3), f(4), f(0))));
    assert!(satisfied(&assign_step(op::SUB, f(10), f(7), f(0))));
    assert!(satisfied(&assign_step(op::MUL, f(6), f(7), f(0))));
    assert!(satisfied(&assign_step(op::NEG, f(5), f(0), f(0))));
    assert!(satisfied(&assign_step(op::MOV, f(9), f(0), f(0))));
    assert!(satisfied(&assign_step(op::LOADIMM, f(0), f(0), f(42))));
}

#[test]
fn one_circuit_shape_for_all() {
    // Every opcode's assignment has identical length and the circuit is
    // built once - the uniformity that lets arbitrary programs fold.
    let n = universal_step_r1cs().a().columns();
    for opcode in 0..OPCODES {
        assert_eq!(assign_step(opcode, f(2), f(3), f(4)).dimension(), n);
    }
}

#[test]
fn wrong_result_rejected() {
    let mut z = assign_step(op::ADD, f(3), f(4), f(0));
    z[Layout::RDV] = f(8); // 3 + 4 != 8
    assert!(!satisfied(&z));
}

#[test]
fn wrong_mul_rejected() {
    let mut z = assign_step(op::MUL, f(6), f(7), f(0));
    z[Layout::RDV] = f(41); // 6 * 7 != 41
    assert!(!satisfied(&z));
}

#[test]
fn tampered_product_rejected() {
    let mut z = assign_step(op::MUL, f(6), f(7), f(0));
    z[Layout::PROD] = f(43); // product column lies
    assert!(!satisfied(&z));
}

#[test]
fn non_boolean_flag_rejected() {
    let mut z = assign_step(op::ADD, f(3), f(4), f(0));
    z[Layout::FLAGS + op::ADD] = f(2); // flag must be 0 or 1
    assert!(!satisfied(&z));
}

#[test]
fn two_flags_rejected() {
    let mut z = assign_step(op::ADD, f(3), f(4), f(0));
    z[Layout::FLAGS + op::SUB] = f(1); // two opcodes selected: sum != 1
    assert!(!satisfied(&z));
}

#[test]
fn no_flag_rejected() {
    let mut z = assign_step(op::ADD, f(3), f(4), f(0));
    z[Layout::FLAGS + op::ADD] = f(0); // no opcode selected
    assert!(!satisfied(&z));
}

#[test]
fn loadimm_independent_of_sources() {
    // LoadImm result is the immediate regardless of source registers.
    let z = assign_step(op::LOADIMM, f(99), f(77), f(42));
    assert!(satisfied(&z));
    assert_eq!(z[Layout::RDV], f(42));
}
