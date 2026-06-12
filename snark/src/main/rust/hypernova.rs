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

//! HyperNova multifolding (eprint 2023/573): sumcheck-based accumulation
//! that eliminates the error vector of Nova relaxation entirely.
//!
//! The accumulator is a *linearized* claim: at a point `ρ`, the values
//! `vⱼ = M̃ⱼz̃(ρ)` for the three R1CS matrices, where `M̃ⱼz̃` is the
//! multilinear extension of the vector `Mⱼ·z`. Linearized claims are linear
//! in `z`, so they fold with the same small challenge as the digit witness
//! and the Ajtai commitment — homomorphically, with no cross term and no
//! `E`, which was the stated residual of [`crate::committedfold`].
//!
//! One multifold reduces a running linearized claim and a fresh strict
//! instance to a single new linearized claim via the sumcheck protocol over
//!
//! `g(x) = Σⱼ γʲ·eq(ρ,x)·m̃ⱼ¹(x) + γ⁴·eq(β,x)·(m̃₁²(x)·m̃₂²(x) − m̃₃²(x))`
//!
//! whose hypercube sum is `Σⱼ γʲ·vⱼ` iff the running claim holds and the
//! fresh instance satisfies the constraints. The sumcheck implementation,
//! transcript, and challenge distribution are the existing ones from
//! `blacknet-crypto`; this module contributes only the polynomial.

use crate::witnesscommitment::{
    CommitmentKey, F, MAX_NORM, decompose, infinity_norm, recompose, squeeze_challenge,
};
use blacknet_arith::r1cs::ShapedR1cs;
use blacknet_crypto::matrix::DenseVector;
use blacknet_crypto::polynomial::{
    EqExtension, MultilinearExtension, MultivariatePolynomial, Point, Polynomial,
};
use blacknet_crypto::random::UniformDistribution;
use blacknet_crypto::sumcheck::{Proof as SumCheckProof, SumCheck};
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};

type D = DuplexPoseidon2Pervushin;
type E = UniformDistribution<D>;
type SC = SumCheck<F, F, FoldPolynomial, D, E>;

/// The public accumulator: a commitment to the digit witness, the
/// linearized claim, and the norm bound of the opening.
#[derive(Clone, Debug)]
pub struct Accumulator {
    pub commitment: DenseVector<F>,
    pub point: Vec<F>,
    pub evals: [F; 3],
    pub norm_bound: u128,
}

/// The prover's secret counterpart: the digit witness.
#[derive(Clone, Debug)]
pub struct AccumulatorWitness {
    pub d: DenseVector<F>,
}

/// What travels with one multifold.
#[derive(Clone)]
pub struct MultifoldProof {
    pub sumcheck: SumCheckProof<F>,
    pub sigma: [F; 3],
    pub theta: [F; 3],
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Shape,
    NormBudget,
    SumCheck,
    ClaimMismatch,
    Opening,
    Unsatisfied,
}

/// The sumcheck polynomial of one multifold, in evaluation form. All
/// component tables have length `2^μ`. Degree 3 (eq · m̃₁² · m̃₂²).
pub struct FoldPolynomial {
    eq_rho: Vec<F>,
    m1: [Vec<F>; 3],
    eq_beta: Vec<F>,
    m2: [Vec<F>; 3],
    gamma: [F; 4],
}

impl FoldPolynomial {
    fn tables_mut(&mut self) -> impl Iterator<Item = &mut Vec<F>> {
        let Self {
            eq_rho,
            m1,
            eq_beta,
            m2,
            ..
        } = self;
        [eq_rho, eq_beta]
            .into_iter()
            .chain(m1.iter_mut())
            .chain(m2.iter_mut())
    }

    const fn len(&self) -> usize {
        self.eq_rho.len()
    }
}

impl Polynomial for FoldPolynomial {
    type Coefficient = F;
    type Point = Point<F>;

    fn point(&self, point: &Point<F>) -> F {
        let at = |t: &Vec<F>| MultilinearExtension::from(t.clone()).point(point);
        let running: F = (0..3)
            .map(|j| self.gamma[j] * at(&self.eq_rho) * at(&self.m1[j]))
            .sum();
        let fresh = self.gamma[3]
            * at(&self.eq_beta)
            * (at(&self.m2[0]) * at(&self.m2[1]) - at(&self.m2[2]));
        running + fresh
    }
}

impl MultivariatePolynomial for FoldPolynomial {
    fn bind(&mut self, e: &F) {
        for t in self.tables_mut() {
            let half = t.len() >> 1;
            for i in 0..half {
                let (l, r) = (t[i], t[half + i]);
                t[i] = l + (r - l) * e;
            }
            t.truncate(half);
        }
    }

    fn sum_with_var<const VAL: i8>(&self) -> F {
        let half = self.len() >> 1;
        // Substituted value of a multilinear table at the bound variable:
        // l + VAL·(r − l), evaluated per remaining hypercube index.
        let sub = |t: &[F], i: usize| {
            let (l, r) = (t[i], t[half + i]);
            l + (r - l) * F::from(i32::from(VAL))
        };
        (0..half)
            .map(|i| {
                let running: F = (0..3)
                    .map(|j| self.gamma[j] * sub(&self.eq_rho, i) * sub(&self.m1[j], i))
                    .sum();
                let fresh = self.gamma[3]
                    * sub(&self.eq_beta, i)
                    * (sub(&self.m2[0], i) * sub(&self.m2[1], i) - sub(&self.m2[2], i));
                running + fresh
            })
            .sum()
    }

    fn degree(&self) -> usize {
        3
    }

    fn variables(&self) -> usize {
        self.len().trailing_zeros() as usize
    }
}

fn pad(v: DenseVector<F>, len: usize) -> Vec<F> {
    let mut t: Vec<F> = v.into_iter().collect();
    t.resize(len, F::from(0));
    t
}

/// The power-of-two padded constraint count, public for circuit sizing.
#[must_use]
pub const fn padded_rows_of(r1cs: &ShapedR1cs) -> usize {
    padded_rows(r1cs)
}

pub(crate) const fn padded_rows(r1cs: &ShapedR1cs) -> usize {
    r1cs.a().rows().next_power_of_two()
}

fn images(r1cs: &ShapedR1cs, z: &DenseVector<F>, len: usize) -> [Vec<F>; 3] {
    let (a, b, c) = r1cs.images(z);
    [pad(a, len), pad(b, len), pad(c, len)]
}

fn mle_eval(table: &[F], point: &[F]) -> F {
    MultilinearExtension::from(table.to_vec()).point(&Point::from(point.to_vec()))
}

fn eq_eval(lhs: &[F], rhs: &[F]) -> F {
    debug_assert_eq!(lhs.len(), rhs.len());
    lhs.iter()
        .zip(rhs)
        .map(|(x, y)| *x * *y + (F::from(1) - *x) * (F::from(1) - *y))
        .fold(F::from(1), |acc, e| acc * e)
}

fn squeeze_point<DU: Duplexer<Msg = F>>(duplex: &mut DU, mu: usize) -> Vec<F> {
    (0..mu).map(|_| duplex.squeeze()).collect()
}

fn absorb_accumulator<DU: Duplexer<Msg = F>>(duplex: &mut DU, acc: &Accumulator) {
    for k in 0..acc.commitment.dimension() {
        duplex.absorb(acc.commitment[k]);
    }
    duplex.absorb_iter(acc.point.iter().copied());
    duplex.absorb_iter(acc.evals.iter().copied());
}

/// Bootstraps an accumulator from a strict satisfying witness `z` by
/// linearizing it: a sumcheck over `eq(β,x)·(m̃₁m̃₂ − m̃₃)(x)` with claimed
/// sum zero. Prover side; the verifier counterpart is [`init_verify`].
pub fn init(
    key: &CommitmentKey,
    r1cs: &ShapedR1cs,
    z: &DenseVector<F>,
    context: &[F],
) -> (Accumulator, AccumulatorWitness, MultifoldProof) {
    let len = padded_rows(r1cs);
    let mu = len.trailing_zeros() as usize;
    let d = decompose(z);
    let commitment = key.commit(&d);
    let norm_bound = infinity_norm(&d);

    let mut duplex = D::default();
    let mut mirror = D::default();
    for t in [&mut duplex, &mut mirror] {
        t.absorb_iter(context.iter().copied());
        for k in 0..commitment.dimension() {
            t.absorb(commitment[k]);
        }
    }
    let beta = squeeze_point(&mut duplex, mu);
    let _ = squeeze_point(&mut mirror, mu);
    let m2 = images(r1cs, z, len);
    let polynomial = FoldPolynomial {
        eq_rho: vec![F::from(0); len],
        m1: [
            vec![F::from(0); len],
            vec![F::from(0); len],
            vec![F::from(0); len],
        ],
        eq_beta: EqExtension::from(beta.clone())
            .hypercube()
            .into_iter()
            .collect(),
        m2: m2.clone(),
        gamma: [F::from(0), F::from(0), F::from(0), F::from(1)],
    };
    let mut exceptional = E::default();
    let sumcheck = SC::prove(
        clone_polynomial(&polynomial),
        F::from(0),
        &mut duplex,
        &mut exceptional,
    );
    // The verifier's challenges define the new point; recover them by
    // replaying verification on the mirror transcript.
    let (point, _) = replay_point(len, F::from(0), &sumcheck, &mut mirror);
    let theta = core::array::from_fn(|j| mle_eval(&m2[j], &point));
    duplex.absorb_iter(theta.iter().copied());
    (
        Accumulator {
            commitment,
            point,
            evals: theta,
            norm_bound,
        },
        AccumulatorWitness { d },
        MultifoldProof {
            sumcheck,
            sigma: [F::from(0); 3],
            theta,
        },
    )
}

/// Verifies a bootstrap against the fresh instance's public commitment.
pub fn init_verify(
    r1cs: &ShapedR1cs,
    commitment: &DenseVector<F>,
    norm_bound: u128,
    proof: &MultifoldProof,
    context: &[F],
) -> Result<Accumulator, Error> {
    let len = padded_rows(r1cs);
    let mu = len.trailing_zeros() as usize;
    if norm_bound > MAX_NORM {
        return Err(Error::NormBudget);
    }
    let mut duplex = D::default();
    duplex.absorb_iter(context.iter().copied());
    for k in 0..commitment.dimension() {
        duplex.absorb(commitment[k]);
    }
    let beta = squeeze_point(&mut duplex, mu);
    let shape = shape_polynomial(len);
    let mut exceptional = E::default();
    let (point, s) = SC::verify_early_stopping(
        &shape,
        F::from(0),
        &proof.sumcheck,
        &mut duplex,
        &mut exceptional,
    )
    .map_err(|_| Error::SumCheck)?;
    let point: Vec<F> = point.into();
    let theta = proof.theta;
    let expected = eq_eval(&beta, &point) * (theta[0] * theta[1] - theta[2]);
    if expected != s {
        return Err(Error::ClaimMismatch);
    }
    duplex.absorb_iter(theta.iter().copied());
    Ok(Accumulator {
        commitment: commitment.clone(),
        point,
        evals: theta,
        norm_bound,
    })
}

/// One multifold, prover side: running accumulator + fresh strict witness.
pub fn multifold(
    key: &CommitmentKey,
    r1cs: &ShapedR1cs,
    running: (&Accumulator, &AccumulatorWitness),
    fresh_z: &DenseVector<F>,
    context: &[F],
) -> Result<(Accumulator, AccumulatorWitness, MultifoldProof), Error> {
    let (acc, w) = running;
    let len = padded_rows(r1cs);
    let mu = len.trailing_zeros() as usize;

    let fresh_d = decompose(fresh_z);
    let fresh_commitment = key.commit(&fresh_d);
    let fresh_norm = infinity_norm(&fresh_d);

    let mut duplex = D::default();
    let mut mirror = D::default();
    for t in [&mut duplex, &mut mirror] {
        t.absorb_iter(context.iter().copied());
        absorb_accumulator(t, acc);
        for k in 0..fresh_commitment.dimension() {
            t.absorb(fresh_commitment[k]);
        }
    }
    let gamma: F = duplex.squeeze();
    let _g: F = mirror.squeeze();
    let beta = squeeze_point(&mut duplex, mu);
    let _ = squeeze_point(&mut mirror, mu);

    let z1 = recompose(&w.d);
    let m1 = images(r1cs, &z1, len);
    let m2 = images(r1cs, fresh_z, len);
    let gammas = [
        gamma,
        gamma * gamma,
        gamma * gamma * gamma,
        gamma * gamma * gamma * gamma,
    ];
    let polynomial = FoldPolynomial {
        eq_rho: EqExtension::from(acc.point.clone())
            .hypercube()
            .into_iter()
            .collect(),
        m1: m1.clone(),
        eq_beta: EqExtension::from(beta).hypercube().into_iter().collect(),
        m2: m2.clone(),
        gamma: gammas,
    };
    let sum: F = (0..3).map(|j| gammas[j] * acc.evals[j]).sum();
    let mut exceptional = E::default();
    let sumcheck = SC::prove(
        clone_polynomial(&polynomial),
        sum,
        &mut duplex,
        &mut exceptional,
    );
    let (point, _) = replay_point(len, sum, &sumcheck, &mut mirror);

    let sigma = core::array::from_fn(|j| mle_eval(&m1[j], &point));
    let theta = core::array::from_fn(|j| mle_eval(&m2[j], &point));
    duplex.absorb_iter(sigma.iter().copied());
    duplex.absorb_iter(theta.iter().copied());
    let (r, r_norm) = squeeze_challenge(&mut duplex);

    let norm_bound = acc
        .norm_bound
        .checked_add(r_norm.checked_mul(fresh_norm).ok_or(Error::NormBudget)?)
        .ok_or(Error::NormBudget)?;
    if norm_bound > MAX_NORM {
        return Err(Error::NormBudget);
    }

    let commitment: DenseVector<F> = (0..acc.commitment.dimension())
        .map(|k| acc.commitment[k] + r * fresh_commitment[k])
        .collect();
    let evals = core::array::from_fn(|j| sigma[j] + r * theta[j]);
    let d: DenseVector<F> = (0..w.d.dimension())
        .map(|k| w.d[k] + r * fresh_d[k])
        .collect();

    Ok((
        Accumulator {
            commitment,
            point,
            evals,
            norm_bound,
        },
        AccumulatorWitness { d },
        MultifoldProof {
            sumcheck,
            sigma,
            theta,
        },
    ))
}

/// One multifold, verifier side: public data only, never the witness.
pub fn multifold_verify(
    r1cs: &ShapedR1cs,
    acc: &Accumulator,
    fresh_commitment: &DenseVector<F>,
    fresh_norm: u128,
    proof: &MultifoldProof,
    context: &[F],
) -> Result<Accumulator, Error> {
    let len = padded_rows(r1cs);
    let mu = len.trailing_zeros() as usize;

    let mut duplex = D::default();
    duplex.absorb_iter(context.iter().copied());
    absorb_accumulator(&mut duplex, acc);
    for k in 0..fresh_commitment.dimension() {
        duplex.absorb(fresh_commitment[k]);
    }
    let gamma: F = duplex.squeeze();
    let beta = squeeze_point(&mut duplex, mu);
    let gammas = [
        gamma,
        gamma * gamma,
        gamma * gamma * gamma,
        gamma * gamma * gamma * gamma,
    ];
    let sum: F = (0..3).map(|j| gammas[j] * acc.evals[j]).sum();

    let shape = shape_polynomial(len);
    let mut exceptional = E::default();
    let (point, s) =
        SC::verify_early_stopping(&shape, sum, &proof.sumcheck, &mut duplex, &mut exceptional)
            .map_err(|_| Error::SumCheck)?;
    let point: Vec<F> = point.into();

    let (sigma, theta) = (proof.sigma, proof.theta);
    let expected = eq_eval(&acc.point, &point) * (0..3).map(|j| gammas[j] * sigma[j]).sum::<F>()
        + gammas[3] * eq_eval(&beta, &point) * (theta[0] * theta[1] - theta[2]);
    if expected != s {
        return Err(Error::ClaimMismatch);
    }
    duplex.absorb_iter(sigma.iter().copied());
    duplex.absorb_iter(theta.iter().copied());
    let (r, r_norm) = squeeze_challenge(&mut duplex);

    let norm_bound = acc
        .norm_bound
        .checked_add(r_norm.checked_mul(fresh_norm).ok_or(Error::NormBudget)?)
        .ok_or(Error::NormBudget)?;
    if norm_bound > MAX_NORM {
        return Err(Error::NormBudget);
    }
    let commitment: DenseVector<F> = (0..acc.commitment.dimension())
        .map(|k| acc.commitment[k] + r * fresh_commitment[k])
        .collect();
    Ok(Accumulator {
        commitment,
        point,
        evals: core::array::from_fn(|j| sigma[j] + r * theta[j]),
        norm_bound,
    })
}

/// Final opening: norm-bounded commitment opening plus a direct evaluation
/// of the linearized claim against the recomposed witness. No error vector
/// exists to check — that is the point.
pub fn open(
    key: &CommitmentKey,
    r1cs: &ShapedR1cs,
    acc: &Accumulator,
    witness: &AccumulatorWitness,
) -> Result<(), Error> {
    if !key.open(&acc.commitment, &witness.d, acc.norm_bound) {
        return Err(Error::Opening);
    }
    let z = recompose(&witness.d);
    let len = padded_rows(r1cs);
    let m = images(r1cs, &z, len);
    for (mj, ev) in m.iter().zip(acc.evals.iter()) {
        if mle_eval(mj, &acc.point) != *ev {
            return Err(Error::Unsatisfied);
        }
    }
    Ok(())
}

fn clone_polynomial(p: &FoldPolynomial) -> FoldPolynomial {
    FoldPolynomial {
        eq_rho: p.eq_rho.clone(),
        m1: p.m1.clone(),
        eq_beta: p.eq_beta.clone(),
        m2: p.m2.clone(),
        gamma: p.gamma,
    }
}

/// A shape-only polynomial for the verifier's early-stopping path, which
/// consults only `variables()` and `degree()`.
pub(crate) fn shape_polynomial(len: usize) -> FoldPolynomial {
    FoldPolynomial {
        eq_rho: vec![F::from(0); len],
        m1: [
            vec![F::from(0); len],
            vec![F::from(0); len],
            vec![F::from(0); len],
        ],
        eq_beta: vec![F::from(0); len],
        m2: [
            vec![F::from(0); len],
            vec![F::from(0); len],
            vec![F::from(0); len],
        ],
        gamma: [F::from(0); 4],
    }
}

/// Recovers the sumcheck challenge point by replaying verification on the
/// prover's mirror transcript, keeping both sides bit-identical.
fn replay_point(len: usize, sum: F, proof: &SumCheckProof<F>, mirror: &mut D) -> (Vec<F>, F) {
    let mut exceptional = E::default();
    let shape = shape_polynomial(len);
    let (point, s) = SC::verify_early_stopping(&shape, sum, proof, mirror, &mut exceptional)
        .expect("prover-generated proof replays");
    (point.into(), s)
}
