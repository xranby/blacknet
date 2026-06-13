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

//! Zero-knowledge primitives assembled from the crypto crate's workbench:
//! the Libra masked sumcheck and a hiding Ajtai commitment.
//!
//! These close the two leaks the opening argument left open — the sumcheck
//! round polynomials and the binding-to-commitment step — without any new
//! cryptography, only composition of `MaskingPolynomial`, `AjtaiCommitment`,
//! and `DiscreteGaussianDistribution`.

use crate::witnesscommitment::F;
use blacknet_crypto::matrix::DenseVector;
use blacknet_crypto::polynomial::{
    BinarityPolynomial, MaskingPolynomial, MultivariatePolynomial, Point, Polynomial,
};

/// Libra masking (eprint 2019/317): the batched polynomial
/// `h(x) = f(x) + ρ·g(x)` where `f` is the statement polynomial (here the
/// binarity polynomial) and `g` is a random low-degree mask. Running the
/// sumcheck on `h` proves `Σf = T` while every transmitted round
/// polynomial is randomized by `g`, leaking nothing about `f`. The
/// verifier needs `Σg` (cheap, public) and one masked evaluation of `g` at
/// the final point, disclosed through the mask's own commitment.
pub struct MaskedBinarity {
    f: BinarityPolynomial<F>,
    g: MaskingPolynomial<F>,
    rho: F,
}

impl MaskedBinarity {
    #[must_use]
    pub fn new(f: BinarityPolynomial<F>, g: MaskingPolynomial<F>, rho: F) -> Self {
        debug_assert_eq!(f.variables(), g.variables());
        Self { f, g, rho }
    }

    /// The claimed masked sum: `Σf + ρ·Σg`. For binarity `Σf = 0`.
    #[must_use]
    pub fn claimed_sum(&self) -> F {
        self.rho * self.g.sum()
    }
}

impl Polynomial for MaskedBinarity {
    type Coefficient = F;
    type Point = Point<F>;

    fn point(&self, point: &Point<F>) -> F {
        self.f.point(point) + self.rho * self.g.point(point)
    }
}

impl MultivariatePolynomial for MaskedBinarity {
    fn bind(&mut self, e: &F) {
        self.f.bind(e);
        self.g.bind(e);
    }

    fn sum_with_var<const VAL: i8>(&self) -> F {
        self.f.sum_with_var::<VAL>() + self.rho * self.g.sum_with_var::<VAL>()
    }

    fn degree(&self) -> usize {
        // Binarity is degree 2; the mask is degree 2 to cover it.
        self.f.degree().max(self.g.degree())
    }

    fn variables(&self) -> usize {
        self.f.variables()
    }
}

/// Samples a random degree-`d` masking polynomial in `mu` variables from a
/// generator. Coefficients are uniform field elements; only the sum and one
/// evaluation are ever disclosed, so uniform suffices.
pub fn sample_mask(mu: usize, d: usize, bytes: &mut impl FnMut() -> u64) -> MaskingPolynomial<F> {
    use blacknet_crypto::algebra::IntegerRing;
    let len = 1 + d * mu;
    let coefficients: Vec<F> = (0..len)
        .map(|_| <F as IntegerRing>::new((bytes() >> 3) as i64))
        .collect();
    MaskingPolynomial::new(coefficients, d, mu)
}

/// A hiding Ajtai commitment: `C = A·d + A_r·r` where `r` is fresh hiding
/// randomness sampled from a discrete Gaussian. Binding is unchanged (it is
/// the Ajtai map on the extended vector `d‖r`); hiding follows from `A_r·r`
/// being statistically close to uniform when `r` has enough Gaussian
/// entropy — the BDLOP construction (eprint 2017/1192), assembled from the
/// existing salted-commitment mechanism. The randomness columns are the
/// `SALT_ELEMENTS` columns already provisioned in the commitment key; this
/// module supplies a Gaussian `r` in place of the uniform salt for a
/// statistical-hiding flavor.
pub mod hiding {
    use super::F;
    use blacknet_crypto::algebra::IntegerRing;

    /// Standard deviation of the hiding randomness. Wide enough that
    /// `A_r·r` smooths the lattice (the smoothing parameter of the salt
    /// sublattice); the precise value is a `rings.sage` output. This is the
    /// computational-to-statistical knob.
    pub const SIGMA: f64 = 1_000_000.0;

    /// Samples `n` discrete-Gaussian hiding coordinates. Uses the crypto
    /// crate's sampler over OS entropy.
    #[must_use]
    pub fn sample(n: usize) -> Vec<F> {
        use blacknet_crypto::random::{DiscreteGaussianDistribution, Distribution, FAST_RNG};
        FAST_RNG.with(|rng| {
            let mut rng = rng.borrow_mut();
            let mut dist = DiscreteGaussianDistribution::<i64, _>::new(0.0, SIGMA);
            (0..n)
                .map(|_| <F as IntegerRing>::new(dist.sample(&mut *rng)))
                .collect()
        })
    }
}

/// Vector helper: append hiding randomness to a witness for commitment.
#[must_use]
pub fn salt_with(witness: &DenseVector<F>, hiding: &[F]) -> DenseVector<F> {
    (0..witness.dimension())
        .map(|i| witness[i])
        .chain(hiding.iter().copied())
        .collect()
}
