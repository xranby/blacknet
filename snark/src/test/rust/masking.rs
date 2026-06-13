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
use blacknet_crypto::polynomial::{BinarityPolynomial, MultivariatePolynomial};
use blacknet_snark::masking::{MaskedBinarity, hiding, salt_with, sample_mask};
use blacknet_snark::opening::{Error, prove_zk, verify_zk};
use blacknet_snark::witnesscommitment::{CommitmentKey, F, decompose};
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
    let w = execute(&program, &[f(77)], 100).unwrap().witness;
    decompose(&w)
}

fn ctx() -> [F; 1] {
    [f(0x1234)]
}

#[test]
fn masked_sum_matches() {
    // h = f + rho*g has hypercube sum rho*Sigma(g) when f is binary (Sigma f = 0).
    let mu = 4;
    let zeros = vec![f(0); 1 << mu];
    let bits = BinarityPolynomial::from(zeros); // all-zero is binary, sum 0
    let mut bytes = || 0x9e3779b97f4a7c15u64;
    let g = sample_mask(mu, 2, &mut bytes);
    let rho = f(7);
    let masked = MaskedBinarity::new(bits, g.clone(), rho);
    assert_eq!(masked.claimed_sum(), rho * g.sum());
    assert_eq!(masked.variables(), mu);
    assert_eq!(masked.degree(), 2);
}

#[test]
fn zk_opening_roundtrip() {
    let d = digits();
    let proof = prove_zk(&d, &ctx());
    assert!(verify_zk(&proof, d.dimension(), 1 << 16, &ctx()).is_ok());
}

#[test]
fn zk_opening_hides_evaluations_across_runs() {
    // Two ZK proofs of the same witness: the masked round polynomials and
    // disclosed evaluations differ (fresh mask), yet both verify.
    let d = digits();
    let p1 = prove_zk(&d, &ctx());
    let p2 = prove_zk(&d, &ctx());
    assert_ne!(p1.mask_sum, p2.mask_sum);
    assert_ne!(p1.bit_eval, p2.bit_eval); // masked: the disclosed eval is randomized
    assert!(verify_zk(&p1, d.dimension(), 1 << 16, &ctx()).is_ok());
    assert!(verify_zk(&p2, d.dimension(), 1 << 16, &ctx()).is_ok());
}

#[test]
fn zk_forged_eval_rejected() {
    let d = digits();
    let mut proof = prove_zk(&d, &ctx());
    proof.bit_eval += f(1);
    assert_eq!(
        verify_zk(&proof, d.dimension(), 1 << 16, &ctx()).unwrap_err(),
        Error::Binarity
    );
}

#[test]
fn zk_oversized_norm_rejected() {
    let d = digits();
    let proof = prove_zk(&d, &ctx());
    assert_eq!(
        verify_zk(&proof, d.dimension(), 1, &ctx()).unwrap_err(),
        Error::NormExceeded
    );
}

#[test]
fn hiding_commitment_randomizes() {
    // Gaussian hiding salt makes two commitments of one witness differ.
    let d = digits();
    let key = CommitmentKey::setup(d.dimension() + 16, 8);
    let r1 = hiding::sample(16);
    let r2 = hiding::sample(16);
    assert_ne!(r1, r2);
    let c1 = key.commit(&decompose_pad(&salt_with(&d, &r1)));
    let c2 = key.commit(&decompose_pad(&salt_with(&d, &r2)));
    assert_ne!(
        (0..c1.dimension()).map(|i| c1[i]).collect::<Vec<_>>(),
        (0..c2.dimension()).map(|i| c2[i]).collect::<Vec<_>>()
    );
}

// The hiding salt is field elements; the commitment key decomposes the
// full salted witness. salt_with appends pre-decomposition here, so we
// decompose the salted vector directly.
fn decompose_pad(
    v: &blacknet_crypto::matrix::DenseVector<F>,
) -> blacknet_crypto::matrix::DenseVector<F> {
    blacknet_snark::witnesscommitment::decompose(v)
}
