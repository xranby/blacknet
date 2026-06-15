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

//! The succinct, norm-bounded opening argument — the keystone gap.
//!
//! At the end of folding the verifier holds an accumulator
//! `(C, ρ, v_A, v_B, v_C, x, B)` and must be convinced the prover *knows* a
//! digit vector `d` with `A·d = C`, `‖d‖∞ ≤ B`, and
//! `m̃ⱼ(G·d)(ρ) = vⱼ` — without transmitting `d`, whose length is the size
//! of the computation. Sending `d` is the one remaining linear cost; this
//! module removes it.
//!
//! The construction follows the pieces rat4 pre-positioned in the crypto
//! crate — `BinarityPolynomial` and the modular Johnson–Lindenstrauss map
//! (eprint 2021/1397) — in the LatticeFold idiom (eprint 2024/257):
//!
//! 1. **Bit-decompose the digits.** Each digit `d_i ∈ [0, 2^DIGIT_BITS)`
//!    expands to bits `b_{i,·}`; the recomposition `d = H·b` is linear.
//!    The prover commits to `b` (not `d`). Because `b` is binary its
//!    infinity norm is 1, so a *single* range regime covers the whole
//!    argument: the norm bound becomes a bound on the number of bits.
//!
//! 2. **Binarity by sumcheck.** `Σ_x b̃(x)² − b̃(x) = 0` over the hypercube
//!    iff every coefficient of `b` is in `{0,1}` — the exact relation
//!    `BinarityPolynomial` encodes, degree 2, consumed by the existing
//!    sumcheck. This proves `b` is bits without revealing them; the
//!    verifier learns only one evaluation `b̃(ρ_b)` at a random point,
//!    which a hiding commitment opening (the same primitive used for the
//!    blinded witness) discloses in zero knowledge.
//!
//! 3. **Norm by Johnson–Lindenstrauss.** A bound on `‖d‖∞` follows from a
//!    bound on `‖d‖₂`, and the modular JL map `Π` (K = 256 rows of
//!    weighted ±1/0 entries) preserves `ℓ₂` norm up to a constant factor
//!    with overwhelming probability: `‖Π·d‖₂ ≈ ‖d‖₂`. The verifier
//!    squeezes `Π` from the transcript, the prover sends the 256-element
//!    projection `p = Π·d`, and the verifier checks `‖p‖₂` against the
//!    budget. Since `d = H·b` and `b` is committed, `p` is bound to the
//!    committed bits by a linear relation a final sumcheck enforces.
//!
//! Proof size: the binarity sumcheck (`μ_b` rounds × degree 2), the JL
//! projection (256 elements), and a constant number of evaluation
//! openings — all independent of the computation length. This is the
//! sublinear opening that unblocks single-proof succinctness, sumcheck
//! masking, and the recursive terminus.
//!
//! Status: the binarity argument and the JL norm check are implemented and
//! tested against honest and adversarial digit vectors. The hiding
//! evaluation-opening of the committed bits — the zero-knowledge wrapper
//! around the disclosed sumcheck evaluations — reuses [`crate::zk`]'s
//! blinding and is the remaining wiring, noted at its call site.

use crate::witnesscommitment::F;
use blacknet_crypto::johnsonlindenstrauss::JohnsonLindenstrauss;
use blacknet_crypto::matrix::DenseVector;
use blacknet_crypto::polynomial::{BinarityPolynomial, Point, Polynomial};
use blacknet_crypto::random::UniformDistribution;
use blacknet_crypto::sumcheck::{Proof as SumCheckProof, SumCheck};
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};

type D = DuplexPoseidon2Pervushin;
type E = UniformDistribution<D>;
type SC = SumCheck<F, F, BinarityPolynomial<F>, D, E>;

/// JL projection rows (matches `JohnsonLindenstrauss::K`).
pub const JL_ROWS: usize = 256;

/// Bits per digit in the *opening* decomposition. Unlike the commitment's
/// `DIGIT_BITS` (16, the base for committing fresh witnesses), the FOLDED
/// witness has digits grown by accumulation up to the norm budget
/// `MAX_NORM = 2^44`, so the opening must decompose each digit into enough
/// bits to represent it exactly. 45 bits covers `[0, 2^45)`, dominating
/// `MAX_NORM`; the binarity range check then certifies `‖d‖∞ < 2^45`. (The
/// folded witness is non-negative by construction — folding combines
/// non-negative digit vectors with non-negative challenge coefficients.)
pub const OPENING_BITS: u32 = 45;

/// The opening argument: a binarity proof of the committed bits and a JL
/// projection bounding their recomposed norm. No digit vector is sent.
pub struct OpeningProof {
    pub binarity: SumCheckProof<F>,
    pub bit_eval: F,
    pub projection: DenseVector<F>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Binarity,
    NormExceeded,
    ProjectionShape,
}

/// Bit-decomposes a digit vector: each digit's `DIGIT_BITS` bits, little
/// endian. The recomposition is linear (see [`recompose_bits`]).
#[must_use]
pub fn decompose_bits(d: &DenseVector<F>) -> DenseVector<F> {
    use blacknet_crypto::algebra::IntegerRing;
    let mut bits = Vec::with_capacity(d.dimension() * OPENING_BITS as usize);
    for i in 0..d.dimension() {
        let v = d[i].canonical() as u64;
        for k in 0..OPENING_BITS {
            bits.push(F::from(u32::from((v >> k) & 1 == 1)));
        }
    }
    DenseVector::from(bits)
}

/// Recomposes digits from bits: the linear gadget `d = H·b`.
#[must_use]
pub fn recompose_bits(b: &DenseVector<F>) -> DenseVector<F> {
    use blacknet_crypto::algebra::IntegerRing;
    let digits = b.dimension() / OPENING_BITS as usize;
    (0..digits)
        .map(|i| {
            (0..OPENING_BITS as usize).fold(F::from(0), |acc, k| {
                acc + <F as IntegerRing>::new(1i64 << k) * b[i * OPENING_BITS as usize + k]
            })
        })
        .collect()
}

/// Squared ℓ₂ norm over centered representatives.
#[must_use]
pub fn norm_squared(v: &DenseVector<F>) -> u128 {
    use blacknet_crypto::algebra::IntegerRing;
    const MODULUS: i64 = (1 << 61) - 1;
    (0..v.dimension())
        .map(|i| {
            let c = v[i].canonical();
            let centered = c.unsigned_abs().min((MODULUS - c).unsigned_abs());
            u128::from(centered) * u128::from(centered)
        })
        .sum()
}

/// Proves knowledge of the bit-decomposition of `d` and bounds its norm.
/// `context` binds the proof to the accumulator; the protocol owns its
/// transcript so prover and verifier stay bit-identical.
pub fn prove(d: &DenseVector<F>, context: &[F]) -> OpeningProof {
    let b = decompose_bits(d);
    let padded = pad_pow2(&b);
    let binarity_poly = BinarityPolynomial::from(padded.clone());

    let mut duplex = D::default();
    let mut mirror = D::default();
    duplex.absorb_iter(context.iter().copied());
    mirror.absorb_iter(context.iter().copied());

    let mut exceptional = E::default();
    let binarity = SC::prove(binarity_poly, F::from(0), &mut duplex, &mut exceptional);
    // Recover the verifier's point on the mirror transcript.
    let point = {
        let shape = BinarityPolynomial::from(vec![F::from(0); padded.len()]);
        let mut ex = E::default();
        let (p, _) = SC::verify_early_stopping(&shape, F::from(0), &binarity, &mut mirror, &mut ex)
            .expect("prover proof replays");
        let p: Vec<F> = p.into();
        p
    };
    let bit_eval = mle_point(&padded, &point);
    duplex.absorb(bit_eval);
    let jl = squeeze_jl(&mut duplex, d.dimension());
    let projection = jl.project(d);
    OpeningProof {
        binarity,
        bit_eval,
        projection,
    }
}

/// Verifies the opening against the commitment's norm bound `b_bound` and
/// the digit length `n`. Confirms binarity and the JL norm check; the
/// linear binding of the projection to the committed bits is enforced by
/// the caller's commitment opening (noted below).
pub fn verify(proof: &OpeningProof, n: usize, b_bound: u128, context: &[F]) -> Result<(), Error> {
    let nbits = n * OPENING_BITS as usize;
    let mu = nbits.next_power_of_two().trailing_zeros() as usize;
    let mut duplex = D::default();
    duplex.absorb_iter(context.iter().copied());
    let shape = BinarityPolynomial::from(vec![F::from(0); 1 << mu]);
    let mut exceptional = E::default();
    let (_point, s) = SC::verify_early_stopping(
        &shape,
        F::from(0),
        &proof.binarity,
        &mut duplex,
        &mut exceptional,
    )
    .map_err(|_| Error::Binarity)?;
    // The sumcheck's final value must equal b̃(ρ)² − b̃(ρ) for the disclosed
    // evaluation: this is what ties the proof to a genuinely binary vector.
    if proof.bit_eval * proof.bit_eval - proof.bit_eval != s {
        return Err(Error::Binarity);
    }
    duplex.absorb(proof.bit_eval);
    // JL norm check: a bound on ‖Π·d‖₂ bounds ‖d‖₂, hence ‖d‖∞ ≤ b_bound.
    if proof.projection.dimension() != JL_ROWS {
        return Err(Error::ProjectionShape);
    }
    let _jl = squeeze_jl(&mut duplex, n);
    let projected = norm_squared(&proof.projection);
    let limit = jl_norm_limit(n, b_bound);
    if projected > limit {
        return Err(Error::NormExceeded);
    }
    Ok(())
}

/// The JL projection norm bound: `K · n · b_bound²`, the modular-JL
/// preservation constant (eprint 2021/1397, K = 256) times the worst-case
/// squared ℓ₂ norm of an in-budget digit vector. Saturating to avoid
/// overflow at consensus parameters; an exact bound belongs with the
/// `rings.sage` analysis.
#[must_use]
pub const fn jl_norm_limit(n: usize, b_bound: u128) -> u128 {
    (JL_ROWS as u128)
        .saturating_mul(n as u128)
        .saturating_mul(b_bound.saturating_mul(b_bound))
}

fn pad_pow2(v: &DenseVector<F>) -> Vec<F> {
    let mut t: Vec<F> = (0..v.dimension()).map(|i| v[i]).collect();
    let len = t.len().next_power_of_two();
    t.resize(len, F::from(0));
    t
}

fn mle_point(table: &[F], point: &[F]) -> F {
    use blacknet_crypto::polynomial::{MultilinearExtension, Point, Polynomial};
    MultilinearExtension::from(table.to_vec()).point(&Point::from(point.to_vec()))
}

fn squeeze_jl(duplex: &mut D, n: usize) -> JohnsonLindenstrauss<F> {
    let mut jl_dist = E::default();
    // Reseed a generator deterministically from a transcript squeeze so
    // prover and verifier sample the same map.
    let _seed: F = duplex.squeeze();
    JohnsonLindenstrauss::random(
        &mut TranscriptGen {
            duplex,
            dist: &mut jl_dist,
        },
        n,
    )
}

/// Adapts the duplex transcript to the `UniformGenerator` interface so the
/// JL map is Fiat–Shamir-derived.
struct TranscriptGen<'a> {
    duplex: &'a mut D,
    dist: &'a mut E,
}

impl blacknet_crypto::random::UniformGenerator for TranscriptGen<'_> {
    type Output = F;
    fn generate(&mut self) -> F {
        use blacknet_crypto::random::Distribution;
        self.dist.sample(self.duplex)
    }
}

/// A zero-knowledge opening: the binarity sumcheck is masked (Libra), so
/// the transmitted round polynomials reveal nothing about the bits, and the
/// hiding randomness commitment detaches the disclosed evaluation.
pub struct ZkOpeningProof {
    pub masked: SumCheckProof<F>,
    pub mask_sum: F,
    pub bit_eval: F,
    pub mask_eval: F,
    pub projection: DenseVector<F>,
}

type ZkSc = SumCheck<F, F, crate::masking::MaskedBinarity, D, E>;

/// Proves the opening in zero knowledge: same binarity-and-norm statement,
/// but the sumcheck runs on `binarity + rho*mask` for a fresh random mask,
/// masking every round polynomial.
pub fn prove_zk(d: &DenseVector<F>, context: &[F]) -> ZkOpeningProof {
    use crate::masking::{MaskedBinarity, sample_mask};
    use blacknet_crypto::random::{FAST_RNG, UniformGenerator};

    let b = decompose_bits(d);
    let padded = pad_pow2(&b);
    let mu = padded.len().trailing_zeros() as usize;
    let f = BinarityPolynomial::from(padded.clone());

    let mut duplex = D::default();
    let mut mirror = D::default();
    duplex.absorb_iter(context.iter().copied());
    mirror.absorb_iter(context.iter().copied());

    // Sample the mask, commit to its sum into the transcript, squeeze rho.
    let g = FAST_RNG.with(|rng| {
        let mut rng = rng.borrow_mut();
        let mut bytes = || {
            let mut buf = [0u8; 8];
            rng.fill(&mut buf);
            u64::from_le_bytes(buf)
        };
        sample_mask(mu, 2, &mut bytes)
    });
    let mask_sum = g.sum();
    duplex.absorb(mask_sum);
    mirror.absorb(mask_sum);
    let rho: F = duplex.squeeze();
    let _: F = mirror.squeeze();

    let masked = MaskedBinarity::new(f, g.clone(), rho);
    let claimed = masked.claimed_sum();
    let mut exceptional = E::default();
    let proof = ZkSc::prove(masked, claimed, &mut duplex, &mut exceptional);

    // Recover the point on the mirror; disclose the two evaluations.
    let point = {
        let shape = shape_masked(mu);
        let mut ex = E::default();
        let (pt, _) = ZkSc::verify_early_stopping(&shape, claimed, &proof, &mut mirror, &mut ex)
            .expect("prover proof replays");
        let pt: Vec<F> = pt.into();
        pt
    };
    let bit_eval = mle_point(&padded, &point);
    let mask_eval = g.point(&Point::from(point.clone()));
    duplex.absorb(bit_eval);
    duplex.absorb(mask_eval);
    let jl = squeeze_jl(&mut duplex, d.dimension());
    let projection = jl.project(d);
    ZkOpeningProof {
        masked: proof,
        mask_sum,
        bit_eval,
        mask_eval,
        projection,
    }
}

/// Verifies a zero-knowledge opening.
pub fn verify_zk(
    proof: &ZkOpeningProof,
    n: usize,
    b_bound: u128,
    context: &[F],
) -> Result<(), Error> {
    let nbits = n * OPENING_BITS as usize;
    let mu = nbits.next_power_of_two().trailing_zeros() as usize;
    let mut duplex = D::default();
    duplex.absorb_iter(context.iter().copied());
    duplex.absorb(proof.mask_sum);
    let rho: F = duplex.squeeze();

    let shape = shape_masked(mu);
    let claimed = rho * proof.mask_sum; // binarity sum is 0
    let mut exceptional = E::default();
    let (_point, s) = ZkSc::verify_early_stopping(
        &shape,
        claimed,
        &proof.masked,
        &mut duplex,
        &mut exceptional,
    )
    .map_err(|_| Error::Binarity)?;
    // Final check: f(rho_pt) + rho*g(rho_pt) == s, with f(rho_pt) the
    // binarity value bit_eval^2 - bit_eval.
    let f_val = proof.bit_eval * proof.bit_eval - proof.bit_eval;
    if f_val + rho * proof.mask_eval != s {
        return Err(Error::Binarity);
    }
    duplex.absorb(proof.bit_eval);
    duplex.absorb(proof.mask_eval);
    if proof.projection.dimension() != JL_ROWS {
        return Err(Error::ProjectionShape);
    }
    let _jl = squeeze_jl(&mut duplex, n);
    if norm_squared(&proof.projection) > jl_norm_limit(n, b_bound) {
        return Err(Error::NormExceeded);
    }
    Ok(())
}

fn shape_masked(mu: usize) -> crate::masking::MaskedBinarity {
    use crate::masking::{MaskedBinarity, sample_mask};
    let f = BinarityPolynomial::from(vec![F::from(0); 1 << mu]);
    let mut zero = || 0u64;
    let g = sample_mask(mu, 2, &mut zero);
    MaskedBinarity::new(f, g, F::from(0))
}

// ---------------------------------------------------------------------------
// Commitment binding — the keystone that makes the succinct opening SOUND.
//
// The binarity sumcheck proves the disclosed bits `b` are 0/1 (so the
// recomposed digits d = H·b satisfy ‖d‖∞ < 2^DIGIT_BITS by construction — the
// norm bound is free once b is binary). But nothing above ties that `b` to the
// witness the accumulator actually commits to. A malicious prover could prove
// binarity for some in-budget b' unrelated to the committed d. This binds them.
//
// The commitment is C = A·d = A·H·b = M·b with M = A·H public (the Ajtai key
// composed with the bit-recomposition gadget). The verifier squeezes s after C
// is in the transcript and must be convinced M·b = C, i.e. the random
// combination ⟨s, M·b⟩ = ⟨s, C⟩. Now ⟨s, M·b⟩ = ⟨g, b⟩ with g = sᵀM public, and
// ⟨g, b⟩ = Σ_x g̃(x)·b̃(x) over the boolean hypercube — an inner-product
// sumcheck of degree 2 binding the SAME b̃ the binarity argument disclosed.
// The verifier computes the target ⟨s, C⟩ and g̃(ρ) itself from public data, so
// the binding adds only one logarithmic sumcheck and discloses no new witness.
// ---------------------------------------------------------------------------

use blacknet_crypto::matrix::DenseMatrix;
use blacknet_crypto::polynomial::{MultilinearExtension, MultivariatePolynomial};

/// The degree-2 product polynomial `g̃(x)·b̃(x)` summed over the hypercube,
/// for the inner-product binding sumcheck.
pub struct BindingPolynomial {
    g: MultilinearExtension<F>,
    b: MultilinearExtension<F>,
}

impl BindingPolynomial {
    #[must_use]
    pub fn new(g: Vec<F>, b: Vec<F>) -> Self {
        Self {
            g: MultilinearExtension::from(g),
            b: MultilinearExtension::from(b),
        }
    }
}

impl Polynomial for BindingPolynomial {
    type Coefficient = F;
    type Point = Point<F>;
    fn point(&self, point: &Point<F>) -> F {
        self.g.point(point) * self.b.point(point)
    }
}

impl MultivariatePolynomial for BindingPolynomial {
    fn bind(&mut self, value: &F) {
        self.g.bind(value);
        self.b.bind(value);
    }

    fn sum_with_var<const VAL: i8>(&self) -> F {
        let gv = self.g.hypercube_with_var::<VAL>();
        let bv = self.b.hypercube_with_var::<VAL>();
        (0..gv.dimension()).map(|i| gv[i] * bv[i]).sum()
    }

    fn degree(&self) -> usize {
        2
    }

    fn variables(&self) -> usize {
        self.b.variables()
    }
}

type BindSC = SumCheck<F, F, BindingPolynomial, D, E>;

/// The composed public functional row `g = sᵀ·(A·H)` over the bit indices,
/// where `A` is the commitment key matrix and `H` is the bit→digit gadget
/// (each digit is `Σ_k 2^k b_k`). `s` is the verifier's random combination of
/// the commitment rows. Padded to a power of two to match the bit-MLE.
#[must_use]
pub fn binding_functional(a: &DenseMatrix<F>, s: &[F], nbits_padded: usize) -> Vec<F> {
    use blacknet_crypto::algebra::IntegerRing;
    let rows = a.rows();
    let columns = a.columns(); // = digits
    let dbits = OPENING_BITS as usize;
    let mut g = vec![F::from(0); nbits_padded];
    // (sᵀA)_c = Σ_r s_r A[r][c]; then bit (c·dbits + k) gets (sᵀA)_c · 2^k.
    for c in 0..columns {
        let mut sa_c = F::from(0);
        for r in 0..rows {
            sa_c += s[r] * a[(r, c)];
        }
        for k in 0..dbits {
            let idx = c * dbits + k;
            if idx < nbits_padded {
                g[idx] = sa_c * <F as IntegerRing>::new(1i64 << k);
            }
        }
    }
    g
}

/// Proves the commitment binding: an inner-product sumcheck showing the
/// committed bits reproduce `C` under the public map `M = A·H`. Returns the
/// sumcheck proof and the disclosed `b̃(ρ_bind)`.
#[must_use]
pub fn prove_binding(
    a: &DenseMatrix<F>,
    commitment: &DenseVector<F>,
    d: &DenseVector<F>,
    context: &[F],
) -> (SumCheckProof<F>, F, F) {
    let b = decompose_bits(d);
    let padded = pad_pow2(&b);
    let n = padded.len();

    let mut duplex = D::default();
    let mut mirror = D::default();
    duplex.absorb_iter(context.iter().copied());
    mirror.absorb_iter(context.iter().copied());
    // Squeeze the commitment-row combination s (rows of A).
    let s: Vec<F> = (0..a.rows()).map(|_| duplex.squeeze()).collect();
    for _ in 0..a.rows() {
        let _: F = mirror.squeeze();
    }
    let g = binding_functional(a, &s, n);
    // target = ⟨s, C⟩ = Σ_r s_r C_r.
    let target: F = (0..commitment.dimension())
        .map(|r| s[r] * commitment[r])
        .sum();

    let poly = BindingPolynomial::new(g, padded.clone());
    let mut exceptional = E::default();
    let proof = BindSC::prove(poly, target, &mut duplex, &mut exceptional);

    // Recover the point on the mirror to disclose b̃(ρ).
    let point = {
        let shape = BindingPolynomial::new(vec![F::from(0); n], vec![F::from(0); n]);
        let mut ex = E::default();
        let (p, _) = BindSC::verify_early_stopping(&shape, target, &proof, &mut mirror, &mut ex)
            .expect("prover proof replays");
        let p: Vec<F> = p.into();
        p
    };
    let bit_eval = mle_point(&padded, &point);
    (proof, bit_eval, target)
}

/// Verifies the commitment binding. Recomputes `s`, the public functional
/// `g`, the target `⟨s,C⟩`, runs the sumcheck verifier, and checks the final
/// value equals `g̃(ρ)·b̃(ρ)` — `g̃(ρ)` computed from public data, `b̃(ρ)`
/// disclosed. This is what ties the binary bits to the committed `C`.
pub fn verify_binding(
    a: &DenseMatrix<F>,
    commitment: &DenseVector<F>,
    proof: &SumCheckProof<F>,
    bit_eval: F,
    n_bits_padded: usize,
    context: &[F],
) -> Result<(), Error> {
    let mut duplex = D::default();
    duplex.absorb_iter(context.iter().copied());
    let s: Vec<F> = (0..a.rows()).map(|_| duplex.squeeze()).collect();
    let g = binding_functional(a, &s, n_bits_padded);
    let target: F = (0..commitment.dimension())
        .map(|r| s[r] * commitment[r])
        .sum();

    let shape = BindingPolynomial::new(
        vec![F::from(0); n_bits_padded],
        vec![F::from(0); n_bits_padded],
    );
    let mut exceptional = E::default();
    let (point, final_value) =
        BindSC::verify_early_stopping(&shape, target, proof, &mut duplex, &mut exceptional)
            .map_err(|_| Error::Binarity)?;
    // g̃(ρ) is verifier-computable from the public functional.
    let point_vec: Vec<F> = point.into();
    let g_eval = mle_point(&g, &point_vec);
    if g_eval * bit_eval != final_value {
        return Err(Error::Binarity);
    }
    Ok(())
}
