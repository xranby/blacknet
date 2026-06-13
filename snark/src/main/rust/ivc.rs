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

//! The whole HyperNova multifold verifier as a circuit: the IVC step.
//!
//! Composed entirely from `blacknet-crypto` circuit/assigner pairs, this is
//! the in-circuit counterpart of [`crate::hypernova::multifold_verify`]:
//! the Poseidon2 duplex transcript (`γ`, `β`, the final fold challenge),
//! the sumcheck verifier (claim chain constrained per round), eq-extension
//! evaluation, the final claim identity, the challenge truncation gadget,
//! and the homomorphic commitment/eval folding. Satisfying assignments are
//! produced by [`assigner::fill`], mirroring the circuit's allocation order
//! against a real plain-protocol transcript.
//!
//! Public input order: `acc.commitment[rows]`, `acc.point[μ]`,
//! `acc.evals[3]`, `fresh.commitment[rows]`, sumcheck claims `μ·4`,
//! `σ[3]`, `θ[3]`, `new.evals[3]`, `new.commitment[rows]`.
//!
//! Remaining, stated honestly: norm accounting stays outside the circuit
//! (44-bit range gadgets are mechanical but bulky), and the recursive
//! closure — this circuit folded by itself — needs the step circuit and
//! this verifier unified into one shape with public IO chaining.

use crate::hypernova::{FoldPolynomial, shape_polynomial};
use crate::recursion::{F, truncate_challenge};
use blacknet_crypto::circuit::builder::VariableKind;
use blacknet_crypto::circuit::builder::{CircuitBuilder, Constant, LinearCombination};
use blacknet_crypto::circuit::polynomial::EqExtension as EqCircuit;
use blacknet_crypto::circuit::sumcheck::{Proof as ProofCircuit, SumCheck as SumCheckCircuit};
use blacknet_crypto::circuit::symmetric::DuplexPoseidon2Pervushin as DuplexCircuit;
use blacknet_crypto::customizableconstraintsystem::CustomizableConstraintSystem;
use blacknet_crypto::random::UniformDistribution;
use blacknet_crypto::symmetric::Duplexer;

const SUMCHECK_DEGREE: usize = 3;
const EVALS: usize = 3;

/// Builds the CCS of one multifold verification over a constraint system
/// with `rows` commitment limbs and `2^mu` padded constraint rows.
#[must_use]
pub fn multifold_verifier_circuit(
    rows: usize,
    mu: usize,
    xlen: usize,
) -> CustomizableConstraintSystem<F> {
    build_multifold_verifier(rows, mu, xlen).ccs()
}

/// The same circuit as an `R1CS`, whose public `(a, b, c)` matrices feed
/// `ShapedR1cs::from_circuit_r1cs` — the bridge that makes the IVC step
/// verifier itself foldable, closing the recursive fixed point.
#[must_use]
pub fn multifold_verifier_r1cs(
    rows: usize,
    mu: usize,
    xlen: usize,
) -> blacknet_crypto::r1cs::R1CS<F> {
    build_multifold_verifier(rows, mu, xlen).r1cs()
}

fn build_multifold_verifier(rows: usize, mu: usize, xlen: usize) -> CircuitBuilder<'static, F> {
    let circuit = CircuitBuilder::<F>::new(2);
    {
        let scope = circuit.scope("multifold_verifier");
        let lc = |_: usize| -> LinearCombination<F> { scope.public_input().into() };

        // Public inputs in layout order.
        let acc_c: Vec<_> = (0..rows).map(lc).collect();
        let acc_point: Vec<_> = (0..mu).map(lc).collect();
        let acc_evals: Vec<_> = (0..EVALS).map(lc).collect();
        let acc_x: Vec<_> = (0..xlen).map(lc).collect();
        let fresh_c: Vec<_> = (0..rows).map(lc).collect();
        let fresh_x: Vec<_> = (0..xlen).map(lc).collect();
        let proof =
            ProofCircuit::allocate(&circuit, VariableKind::PublicInput, mu, SUMCHECK_DEGREE);
        let sigma: Vec<_> = (0..EVALS).map(lc).collect();
        let theta: Vec<_> = (0..EVALS).map(lc).collect();
        let new_evals: Vec<_> = (0..EVALS).map(lc).collect();
        let new_x: Vec<_> = (0..xlen).map(lc).collect();
        let new_c: Vec<_> = (0..rows).map(lc).collect();

        // Transcript, matching hypernova::multifold_verify (empty context).
        let mut duplex = DuplexCircuit::new(&circuit);
        duplex.absorb_iter(acc_c.iter().cloned());
        duplex.absorb_iter(acc_point.iter().cloned());
        duplex.absorb_iter(acc_evals.iter().cloned());
        duplex.absorb_iter(acc_x.iter().cloned());
        duplex.absorb_iter(fresh_c.iter().cloned());
        duplex.absorb_iter(fresh_x.iter().cloned());
        let gamma: LinearCombination<F> = duplex.squeeze();
        let beta: Vec<LinearCombination<F>> = (0..mu).map(|_| duplex.squeeze()).collect();

        // Gamma powers and the claimed sum, one aux product each.
        let mul = |a: &LinearCombination<F>, b: &LinearCombination<F>| -> LinearCombination<F> {
            let p = scope.auxiliary();
            scope.constrain(a * b, p);
            p.into()
        };
        let g2 = mul(&gamma, &gamma);
        let g3 = mul(&g2, &gamma);
        let g4 = mul(&g3, &gamma);
        let gammas = [gamma, g2, g3, g4];
        let sum = (0..EVALS).fold(LinearCombination::from(Constant::ZERO), |acc, j| {
            acc + mul(&gammas[j], &acc_evals[j])
        });

        // Sumcheck verifier: constrains the claim chain and derives the
        // evaluation point from the in-circuit transcript.
        type Dist<'a, 'b> = UniformDistribution<DuplexCircuit<'a, 'b>>;
        let shape = shape_polynomial(1 << mu);
        let sumcheck = SumCheckCircuit::<F, FoldPolynomial, DuplexCircuit, Dist>::new(&circuit);
        let mut exceptional = Dist::default();
        let (point, s) =
            sumcheck.verify_early_stopping(&shape, sum, &proof, &mut duplex, &mut exceptional);

        // Final claim identity:
        // eq(ρ,ρ')·Σγʲσⱼ + γ⁴·eq(β,ρ')·(θ₀θ₁ − θ₂) == s
        let eq_rho = EqCircuit::new(&circuit, acc_point).point(&point);
        let eq_beta = EqCircuit::new(&circuit, beta).point(&point);
        let sigma_sum = (0..EVALS).fold(LinearCombination::from(Constant::ZERO), |acc, j| {
            acc + mul(&gammas[j], &sigma[j])
        });
        let lhs1 = mul(&eq_rho, &sigma_sum);
        let theta_prod = mul(&theta[0], &theta[1]);
        let g4eq = mul(&gammas[3], &eq_beta);
        let lhs2 = mul(&g4eq, &(theta_prod - &theta[2]));
        scope.constrain(lhs1 + lhs2, s);

        // Fold challenge from the transcript, truncated in-circuit.
        duplex.absorb_iter(sigma.iter().cloned());
        duplex.absorb_iter(theta.iter().cloned());
        let e: LinearCombination<F> = duplex.squeeze();
        let r = truncate_challenge(&circuit, e);

        // Homomorphic folding of evals and commitment limbs.
        for j in 0..EVALS {
            scope.constrain(&r * &theta[j], &new_evals[j] - &sigma[j]);
        }
        for k in 0..rows {
            scope.constrain(&r * &fresh_c[k], &new_c[k] - &acc_c[k]);
        }
        for i in 0..xlen {
            scope.constrain(&r * &fresh_x[i], &new_x[i] - &acc_x[i]);
        }
    }
    circuit
}

/// Mirrors [`multifold_verifier_circuit`] numerically against the plain
/// protocol, pushing public inputs and auxiliary variables in allocation
/// order.
pub mod assigner {
    use super::EVALS;
    use crate::hypernova::{Accumulator, FoldPolynomial, MultifoldProof, shape_polynomial};
    use crate::recursion::F;
    use crate::recursion::assigner::push_bits;
    use blacknet_crypto::assigner::assigment::Assigment;
    use blacknet_crypto::assigner::polynomial::{
        EqExtension as EqAssigner, UnivariatePolynomial as UniAssigner,
    };
    use blacknet_crypto::assigner::sumcheck::{
        Proof as ProofAssigner, SumCheck as SumCheckAssigner,
    };
    use blacknet_crypto::assigner::symmetric::DuplexPoseidon2Pervushin as DuplexAssigner;
    use blacknet_crypto::matrix::DenseVector;
    use blacknet_crypto::polynomial::Point;
    use blacknet_crypto::random::UniformDistribution;
    use blacknet_crypto::symmetric::Duplexer;

    /// Extends `z` with the public inputs and auxiliary assignment of one
    /// multifold. `acc` and `fresh_commitment` are the pre-fold public
    /// state; `next` is the post-fold accumulator; `proof` is the
    /// transmitted multifold proof. All must come from one plain-protocol
    /// run with empty context.
    pub fn fill(
        z: &Assigment<F>,
        acc: &Accumulator,
        fresh_commitment: &DenseVector<F>,
        fresh_x: &[F],
        next: &Accumulator,
        proof: &MultifoldProof,
        mu: usize,
    ) {
        let limbs = |v: &DenseVector<F>| (0..v.dimension()).map(|k| v[k]).collect::<Vec<F>>();
        let acc_c = limbs(&acc.commitment);
        let fresh_c = limbs(fresh_commitment);
        let new_c = limbs(&next.commitment);

        // Public inputs in layout order.
        z.extend(acc_c.iter().copied());
        z.extend(acc.point.iter().copied());
        z.extend(acc.evals.iter().copied());
        z.extend(acc.x.iter().copied());
        z.extend(fresh_c.iter().copied());
        z.extend(fresh_x.iter().copied());
        for claim in &proof.sumcheck {
            z.extend(claim.as_ref().iter().copied());
        }
        z.extend(proof.sigma.iter().copied());
        z.extend(proof.theta.iter().copied());
        z.extend(next.evals.iter().copied());
        z.extend(next.x.iter().copied());
        z.extend(new_c.iter().copied());

        // Transcript mirror.
        let mut duplex = DuplexAssigner::new(z);
        duplex.absorb_iter(acc_c.iter().copied());
        duplex.absorb_iter(acc.point.iter().copied());
        duplex.absorb_iter(acc.evals.iter().copied());
        duplex.absorb_iter(acc.x.iter().copied());
        duplex.absorb_iter(fresh_c.iter().copied());
        duplex.absorb_iter(fresh_x.iter().copied());
        let gamma: F = duplex.squeeze();
        let beta: Vec<F> = (0..mu).map(|_| duplex.squeeze()).collect();

        let mul = |a: F, b: F| -> F {
            let p = a * b;
            z.push(p);
            p
        };
        let g2 = mul(gamma, gamma);
        let g3 = mul(g2, gamma);
        let g4 = mul(g3, gamma);
        let gammas = [gamma, g2, g3, g4];
        let sum: F = (0..EVALS).map(|j| mul(gammas[j], acc.evals[j])).sum();

        // Sumcheck mirror.
        type Dist<'a> = UniformDistribution<DuplexAssigner<'a>>;
        let shape = shape_polynomial(1 << mu);
        let proof_assigner = ProofAssigner::from(
            (&proof.sumcheck)
                .into_iter()
                .map(|c| UniAssigner::new(c.as_ref().to_owned(), z))
                .collect::<Vec<_>>(),
        );
        let sumcheck = SumCheckAssigner::<F, FoldPolynomial, DuplexAssigner, Dist>::new(z);
        let mut exceptional = Dist::default();
        let (point, _s): (Point<F>, F) = sumcheck.verify_early_stopping(
            &shape,
            sum,
            &proof_assigner,
            &mut duplex,
            &mut exceptional,
        );

        // Final claim identity mirror.
        let eq_rho = EqAssigner::new(acc.point.clone(), z).point(&point);
        let point_v: Vec<F> = point.into();
        let eq_beta = EqAssigner::new(beta, z).point(&Point::from(point_v));
        let sigma_sum: F = (0..EVALS).map(|j| mul(gammas[j], proof.sigma[j])).sum();
        let _lhs1 = mul(eq_rho, sigma_sum);
        let theta_prod = mul(proof.theta[0], proof.theta[1]);
        let g4eq = mul(gammas[3], eq_beta);
        let _lhs2 = mul(g4eq, theta_prod - proof.theta[2]);

        // Fold challenge mirror.
        duplex.absorb_iter(proof.sigma.iter().copied());
        duplex.absorb_iter(proof.theta.iter().copied());
        let e: F = duplex.squeeze();
        let _r = push_bits(z, e);
    }
}
