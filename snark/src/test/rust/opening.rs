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
use blacknet_snark::opening::{
    Error, JL_ROWS, decompose_bits, jl_norm_limit, norm_squared, prove, recompose_bits, verify,
};
use blacknet_snark::witnesscommitment::{F, decompose};
use blacknet_vm::machine::Instruction;

fn f(n: i32) -> F {
    F::from(n)
}

fn digits() -> blacknet_crypto::matrix::DenseVector<F> {
    let program = vec![
        Instruction::Mul(2, 1, 1),
        Instruction::Add(3, 2, 1),
        Instruction::Halt,
    ];
    let w = execute(&program, &[f(123)], 100).unwrap().witness;
    decompose(&w)
}

fn ctx() -> [F; 1] {
    [f(0x5abc)]
}

#[test]
fn bit_decomposition_roundtrips() {
    let d = digits();
    let b = decompose_bits(&d);
    assert_eq!(recompose_bits(&b), d);
    // bits are actually bits
    for i in 0..b.dimension() {
        assert!(b[i] == f(0) || b[i] == f(1));
    }
}

#[test]
fn honest_opening_verifies() {
    let d = digits();
    let n = d.dimension();
    let proof = prove(&d, &ctx());
    assert_eq!(proof.projection.dimension(), JL_ROWS);
    // digits are below 2^16; use that as the per-digit bound.
    assert!(verify(&proof, n, 1 << 16, &ctx()).is_ok());
}

#[test]
fn opening_does_not_send_digits() {
    // The proof size is the binarity sumcheck + 256 projection + 1 eval,
    // independent of the witness length: this is the succinctness claim.
    let d = digits();
    let proof = prove(&d, &ctx());
    // sumcheck rounds = log2(padded bit count), not the bit count itself.
    let nbits = d.dimension() * 16;
    let rounds = nbits.next_power_of_two().trailing_zeros() as usize;
    assert!(proof.binarity.into_iter().count() <= rounds + 1);
    assert!(proof.projection.dimension() == JL_ROWS);
}

#[test]
fn forged_binarity_rejected() {
    // A vector with a non-bit coefficient must fail the binarity sumcheck.
    let d = digits();
    let mut proof = prove(&d, &ctx());
    proof.bit_eval += f(1); // inconsistent disclosed evaluation
    assert_eq!(
        verify(&proof, d.dimension(), 1 << 16, &ctx()).unwrap_err(),
        Error::Binarity
    );
}

#[test]
fn oversized_norm_rejected() {
    let d = digits();
    let n = d.dimension();
    let proof = prove(&d, &ctx());
    // A budget so small the JL projection cannot fit.
    assert_eq!(
        verify(&proof, n, 1, &ctx()).unwrap_err(),
        Error::NormExceeded
    );
}

#[test]
fn jl_limit_scales() {
    assert!(jl_norm_limit(10, 1 << 16) > jl_norm_limit(10, 1 << 8));
    assert!(jl_norm_limit(100, 1 << 8) > jl_norm_limit(10, 1 << 8));
}

#[test]
fn norm_squared_is_centered() {
    // -1 mod q has centered norm 1, not ~2^61.
    let v = blacknet_crypto::matrix::DenseVector::from(vec![-f(1), f(2)]);
    assert_eq!(norm_squared(&v), 1 + 4);
}
