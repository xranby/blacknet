/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! An oblivious detection backend: the homomorphic-decryption step of OMR,
//! built on Blacknet's own homomorphic-encryption primitives.
//!
//! This is the FHE backend the `oblivious_retrieval` module leaves as a slot.
//! It is a thin BFV-style leveled-RLWE layer over the crate's existing ring
//! machinery — the secret is encrypted under a leveled RLWE over the LM ring
//! (`UnivariateRing<LMField, 1024, Negacyclic>`, modulus ~2^60), reusing
//! rat4's modular arithmetic, negacyclic convolution, and sampling
//! distributions rather than any bespoke arithmetic. The plaintext is the clue
//! ring (mod q = 65537, degree 1024).
//!
//! ## What it does (correctly, obliviously)
//!
//! BlackLemon's `detect` computes a linear value d = ct.a + ct.b*s + sk.b
//! over the clue ring, then range-checks d's coefficients. The linear step is
//! evaluable without the secret:
//!
//!   * the client encrypts its detection material (s, sk.b) under the leveled
//!     RLWE and sends the ciphertext as the detection key;
//!   * the detector computes Enc(d) = ct.a + ct.b (x) Enc(s) + Enc(sk.b) with
//!     homomorphic add and plaintext-polynomial multiplication (the RLWE
//!     operations InstantOMR uses), holding only the encrypted key and the
//!     clue's public parts - it never sees s, d, or which clues match, and
//!     processes every clue identically;
//!   * the client decrypts Enc(d) and runs BlackLemon's exact range check.
//!
//! ## Honest boundaries
//!
//! 1. The pertinence range-check is non-linear; doing it under encryption so
//!    the detector returns a compressed pertinent-only digest needs functional
//!    bootstrapping (TFHE) - the InstantOMR core, NOT built. Here the client
//!    finishes the check, so this backend is OBLIVIOUS but not yet
//!    BANDWIDTH-LITE: it returns one Enc(d) per scanned clue.
//! 2. The LM modulus (~2^60) gives an ample noise budget for this depth-1
//!    circuit (verified by the tests recovering d exactly), but the parameter
//!    set is not independently security-analyzed here.

extern crate alloc;
use alloc::vec::Vec;

use crate::algebra::{BalancedRepresentative, IntegerRing, UnivariateRing};
use crate::blacklemon::{self, DetectionMaterial, detect_params};
use crate::branchless::{BlAbs, BlOrd};
use crate::convolution::Negacyclic;
use crate::lm::LMField;
use crate::oblivious_retrieval::Clue;
use crate::random::{Distribution, UniformGenerator, UniformIntDistribution};

const N: usize = detect_params::D; // 1024, the clue ring degree
const T: i64 = detect_params::Q as i64; // 65537, plaintext modulus
const Q: i64 = LMField::MODULUS; // ~2^60, the ciphertext modulus
/// Delta = floor(Q/t): a plaintext coefficient m is carried as Delta*m.
const DELTA: i64 = Q / T;

/// The ciphertext ring: Blacknet's LM ring, negacyclic, degree 1024. All
/// modular arithmetic and convolution are the crate's own implementation.
type Rq = UnivariateRing<LMField, N, Negacyclic>;

/// Lift integer coefficients into the ciphertext ring.
fn lift(coeffs: &[i64; N]) -> Rq {
    core::array::from_fn(|i| LMField::new(coeffs[i])).into()
}

/// A leveled RLWE (BFV-style, symmetric-key) ciphertext (a, b) with
/// b = a*s + Delta*m + e, decrypting via b - a*s.
#[derive(Clone)]
pub struct Ct {
    a: Rq,
    b: Rq,
}

/// The client's leveled-RLWE key.
pub struct Rlwe {
    s: Rq,
}

impl Rlwe {
    /// Generate a key with a ternary secret, using the crate's uniform sampler.
    pub fn keygen<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Self {
        let mut tern = UniformIntDistribution::<i64, R>::new(-1..=1);
        let s: Rq = core::array::from_fn(|_| LMField::new(tern.sample(rng))).into();
        Rlwe { s }
    }

    fn uniform<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Rq {
        let mut uid = UniformIntDistribution::<i64, R>::new(0..Q);
        core::array::from_fn(|_| LMField::new(uid.sample(rng))).into()
    }

    /// Small centered error in [-8, 8], well below Delta.
    fn error<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Rq {
        let mut eid = UniformIntDistribution::<i64, R>::new(-8..=8);
        core::array::from_fn(|_| LMField::new(eid.sample(rng))).into()
    }

    /// Encrypt plaintext coefficients (in Z_t, balanced) as Delta*m + e.
    fn encrypt<R: UniformGenerator<Output = u8>>(&self, rng: &mut R, m: &[i64; N]) -> Ct {
        let a = Self::uniform(rng);
        let e = Self::error(rng);
        let scaled: Rq = core::array::from_fn(|i| LMField::new(DELTA * m[i])).into();
        let b = a * self.s + scaled + e;
        Ct { a, b }
    }

    /// Decrypt to balanced plaintext coefficients in Z_t.
    fn decrypt(&self, ct: &Ct) -> Vec<i32> {
        let v = ct.b - ct.a * self.s; // = Delta*m + e
        (0..N)
            .map(|i| {
                let centered = v[i].balanced(); // in (-Q/2, Q/2]
                let q = ((centered as f64) / (DELTA as f64)).round() as i64;
                let m = q.rem_euclid(T);
                if m > T / 2 { (m - T) as i32 } else { m as i32 }
            })
            .collect()
    }
}

impl Ct {
    fn add(&self, o: &Ct) -> Ct {
        Ct {
            a: self.a + o.a,
            b: self.b + o.b,
        }
    }

    /// Multiply by a public plaintext polynomial p (lifted into Rq):
    /// (p*a, p*b). Decrypts to p (x) m; noise scales by ||p||.
    fn plain_mul(&self, p: &Rq) -> Ct {
        Ct {
            a: *p * self.a,
            b: *p * self.b,
        }
    }

    /// Add a public plaintext constant polynomial k: (a, b + Delta*k).
    fn add_plain(&self, k: &[i64; N]) -> Ct {
        let scaled: Rq = core::array::from_fn(|i| LMField::new(DELTA * k[i])).into();
        Ct {
            a: self.a,
            b: self.b + scaled,
        }
    }
}

/// The client's detection key: detection material encrypted under RLWE.
pub struct EncryptedDetectionKey {
    enc_secret: Ct,
    enc_offset: Ct,
}

/// Build an encrypted detection key from BlackLemon detection material. Run by
/// the client; reveals nothing about the secret to whoever holds the key.
pub fn encrypt_detection_key<R: UniformGenerator<Output = u8>>(
    rng: &mut R,
    rlwe: &Rlwe,
    material: &DetectionMaterial,
) -> EncryptedDetectionKey {
    let s: [i64; N] = core::array::from_fn(|i| i64::from(material.secret[i]));
    let off: [i64; N] = core::array::from_fn(|i| i64::from(material.offset[i]));
    EncryptedDetectionKey {
        enc_secret: rlwe.encrypt(rng, &s),
        enc_offset: rlwe.encrypt(rng, &off),
    }
}

/// The detector's oblivious step: from the encrypted key and a clue's public
/// parts, compute Enc(d) where d = ct.a + ct.b*s + sk.b. Learns nothing.
#[must_use]
pub fn homomorphic_decrypt(key: &EncryptedDetectionKey, clue: &Clue) -> Ct {
    let (a, b) = blacklemon::clue_public_parts(clue);
    let a_i: [i64; N] = core::array::from_fn(|i| i64::from(a[i]));
    let b_poly = lift(&core::array::from_fn(|i| i64::from(b[i])));
    key.enc_secret
        .plain_mul(&b_poly)
        .add(&key.enc_offset)
        .add_plain(&a_i)
}

/// The client decrypts Enc(d) and applies BlackLemon's exact pertinence check,
/// returning whether the clue is pertinent (matching detect).
#[must_use]
pub fn client_check_pertinence(rlwe: &Rlwe, enc_d: &Ct) -> bool {
    let d = rlwe.decrypt(enc_d);
    let r = detect_params::R;
    let delta = detect_params::DELTA;
    // Constant-time: the verdict reveals which messages are the recipient's, so
    // the scan must not short-circuit. Every coefficient is examined and the
    // result accumulated with rat4's branchless primitives (BlAbs/BlOrd) and
    // non-short-circuiting bitwise boolean ops — no early return, no data-
    // dependent control flow on the decrypted value. (Index comparisons are on
    // the public position, not on secret data.)
    let mut ok = true;
    for (i, &coeff) in d.iter().enumerate() {
        let abs = coeff.bl_abs();
        let near_zero = !abs.bl_gt(&r); // abs <= r
        let near_delta = !(delta - abs).bl_abs().bl_gt(&r); // |delta - abs| <= r
        let coeff_ok = near_zero | near_delta;
        // The leading KAPPA coefficients must additionally be near zero.
        let kappa_violation = (i < detect_params::KAPPA) & !near_zero;
        ok = ok & coeff_ok & !kappa_violation;
    }
    ok
}

/// The recovered balanced coefficients of d (for tests / audit).
#[must_use]
pub fn recover_d(rlwe: &Rlwe, enc_d: &Ct) -> Vec<i32> {
    rlwe.decrypt(enc_d)
}

/// An oblivious scan: compute Enc(d) for each clue, uniformly (no
/// data-dependent branching). The detector cannot compress to pertinent-only
/// without the bootstrapped check (see the module boundary note).
#[must_use]
pub fn oblivious_scan(key: &EncryptedDetectionKey, board: &[Clue]) -> Vec<Ct> {
    board.iter().map(|c| homomorphic_decrypt(key, c)).collect()
}

// ===========================================================================
// Gadget-based RLWE key-switching.
//
// The foundational HE primitive the crate was missing, built on the
// pre-positioned `latticegadget` (gadget decomposition, eprint 2018/946).
// Key-switching transforms a ciphertext that decrypts under one secret into
// one that decrypts under another, WITHOUT decrypting — the building block of
// FHE ciphertext maintenance and the outer loop of bootstrapping (blind
// rotation is key-switching + external products). Here it extends the leveled
// RLWE above.
//
// Identity used: for the gadget radix `B` and `digits` limbs, decomposing a
// ring element `a` gives small `a_i` with `Σ a_i Bⁱ = a`. A key-switch key
// from `s` to `s'` is `KSK_i = RLWE_{s'}(raw: Bⁱ·s)`, i.e.
// `KSK_i.b − KSK_i.a·s' = Bⁱ·s + e_i`. Then for `(a,b)` with
// `b − a·s = Δm + e`, setting `b' = b − Σ a_i·KSK_i.b`,
// `a' = −Σ a_i·KSK_i.a` gives `b' − a'·s' = Δm + e − Σ a_i·e_i`, decryptable
// under `s'` because `Σ a_i·e_i` stays within the noise budget (the `a_i` are
// gadget digits bounded by `B`).
// ===========================================================================

use crate::latticegadget::decompose_polynomial;
use alloc::vec::Vec as KsVec;

/// Gadget radix bits and digit count: `DIGITS·DIGIT_BITS = 64 ≥ ⌈log2 Q⌉`.
const DIGIT_BITS: i64 = 16;
const DIGITS: usize = 4;
const RADIX_MASK: i64 = (1i64 << DIGIT_BITS) - 1;

impl Rlwe {
    /// Encrypt a ring element as a *raw* payload (not Δ-scaled): the result
    /// decrypts-without-rounding to the payload plus small noise. Used to
    /// encrypt the gadget-scaled old key inside a key-switch key.
    fn encrypt_raw<R: UniformGenerator<Output = u8>>(&self, rng: &mut R, payload: &Rq) -> Ct {
        let a = Self::uniform(rng);
        let e = Self::error(rng);
        let b = a * self.s + *payload + e;
        Ct { a, b }
    }

    /// The secret as a ring element (for building a key-switch key to it).
    fn secret(&self) -> Rq {
        self.s
    }
}

/// A key-switch key from one RLWE secret to another.
pub struct KeySwitchKey {
    ksk: KsVec<Ct>, // length DIGITS; ksk[i] = Enc_{new}(raw: B^i · s_old)
}

/// Build a key-switch key taking ciphertexts under `old` to ciphertexts under
/// `new`. Reveals nothing about either secret (the old key is encrypted under
/// the new one).
pub fn keyswitch_keygen<R: UniformGenerator<Output = u8>>(
    rng: &mut R,
    old: &Rlwe,
    new: &Rlwe,
) -> KeySwitchKey {
    let s_old = old.secret();
    let mut ksk = KsVec::with_capacity(DIGITS);
    let mut power: i64 = 1;
    for _ in 0..DIGITS {
        // payload = (B^i) · s_old, scalar B^i lifted to a constant polynomial.
        let scalar: Rq = LMField::new(power).into();
        let payload = scalar * s_old;
        ksk.push(new.encrypt_raw(rng, &payload));
        power = power.wrapping_mul(1i64 << DIGIT_BITS);
    }
    KeySwitchKey { ksk }
}

/// Key-switch a ciphertext to the new secret. Output decrypts under `new` to
/// the same message (with a little added noise from the gadget digits).
#[must_use]
pub fn keyswitch(ksk: &KeySwitchKey, ct: &Ct) -> Ct {
    // Decompose a into DIGITS gadget limbs (each a small ring element).
    let digits = decompose_polynomial::<LMField, Rq>(&ct.a, RADIX_MASK, DIGIT_BITS, DIGITS);
    let mut acc_a = Rq::default();
    let mut acc_b = Rq::default();
    for i in 0..DIGITS {
        let d = digits[i];
        acc_a = acc_a + d * ksk.ksk[i].a;
        acc_b = acc_b + d * ksk.ksk[i].b;
    }
    // a' = -Σ a_i·KSK_i.a ; b' = b - Σ a_i·KSK_i.b
    Ct {
        a: Rq::default() - acc_a,
        b: ct.b - acc_b,
    }
}

// ===========================================================================
// RGSW external product — the bootstrapping keystone.
//
// The external product `RLWE(m) ⊡ RGSW(μ) → RLWE(μ·m)` multiplies an encrypted
// message by a (small) RGSW-encrypted scalar with noise controlled by gadget
// decomposition. With μ ∈ {0,1} it is the CMux gate — the building block of
// blind rotation, and hence of FHEW/TFHE bootstrapping (CGGI). Together with
// the key-switching above it is what a homomorphic pertinence check (the
// bandwidth-lite detector's missing piece) would be assembled from.
//
// Construction (the standard gadget product). An RGSW(μ) is `2·DIGITS` RLWE
// encryptions of zero with the gadget-scaled μ added in: rows `i<DIGITS` carry
// `μ·Bⁱ` in the a-component, rows `DIGITS+i` carry it in the b-component. The
// product decomposes the input's `a` and `b` into gadget limbs and pairs them
// against the rows:
//   resultₐ = Σ âᵢ·rowᵢ.a + Σ b̂ᵢ·row_{D+i}.a = W + μ·a
//   result_b = Σ âᵢ·rowᵢ.b + Σ b̂ᵢ·row_{D+i}.b = W·s + E + μ·b
// so `result_b − resultₐ·s = μ·(b − a·s) + (μe+E) = Δ·(μm) + small`, i.e. an
// RLWE encryption of μ·m. The extra noise E = Σ âᵢeᵢ + Σ b̂ᵢe_{D+i} is
// gadget-bounded (limbs < B), so one product stays well within budget.
// ===========================================================================

/// An RGSW ciphertext encrypting a small scalar μ under an RLWE secret:
/// `2·DIGITS` RLWE rows (the gadget-product representation).
pub struct Rgsw {
    rows: KsVec<Ct>,
}

/// Scalar `c` lifted to a constant polynomial in the ciphertext ring.
fn scalar_poly(c: i64) -> Rq {
    LMField::new(c).into()
}

impl Rlwe {
    /// Public encryption of plaintext coefficients (Z_t, balanced). Exposed so
    /// the external product can be exercised on known messages.
    pub fn encrypt_plain<R: UniformGenerator<Output = u8>>(&self, rng: &mut R, m: &[i64; N]) -> Ct {
        self.encrypt(rng, m)
    }

    /// Encrypt a small scalar μ (a constant, e.g. a 0/1 selector) as an RGSW
    /// ciphertext — the form CMux and blind rotation use.
    pub fn rgsw_encrypt<R: UniformGenerator<Output = u8>>(&self, rng: &mut R, mu: i64) -> Rgsw {
        let mut rows = KsVec::with_capacity(2 * DIGITS);
        // a-group: rows[i].a += μ·Bⁱ
        let mut power: i64 = 1;
        for _ in 0..DIGITS {
            let mut row = self.encrypt_raw(rng, &Rq::default()); // RLWE(0)
            row.a = row.a + scalar_poly(mu * power);
            rows.push(row);
            power = power.wrapping_mul(1i64 << DIGIT_BITS);
        }
        // b-group: rows[D+i].b += μ·Bⁱ
        let mut power: i64 = 1;
        for _ in 0..DIGITS {
            let mut row = self.encrypt_raw(rng, &Rq::default());
            row.b = row.b + scalar_poly(mu * power);
            rows.push(row);
            power = power.wrapping_mul(1i64 << DIGIT_BITS);
        }
        Rgsw { rows }
    }
}

/// The external product `RLWE(m) ⊡ RGSW(μ) → RLWE(μ·m)`.
#[must_use]
pub fn external_product(rgsw: &Rgsw, ct: &Ct) -> Ct {
    let a_digits = decompose_polynomial::<LMField, Rq>(&ct.a, RADIX_MASK, DIGIT_BITS, DIGITS);
    let b_digits = decompose_polynomial::<LMField, Rq>(&ct.b, RADIX_MASK, DIGIT_BITS, DIGITS);
    let mut acc_a = Rq::default();
    let mut acc_b = Rq::default();
    for i in 0..DIGITS {
        acc_a = acc_a + a_digits[i] * rgsw.rows[i].a + b_digits[i] * rgsw.rows[DIGITS + i].a;
        acc_b = acc_b + a_digits[i] * rgsw.rows[i].b + b_digits[i] * rgsw.rows[DIGITS + i].b;
    }
    Ct { a: acc_a, b: acc_b }
}

/// The CMux gate: `select ? c1 : c0`, where `select` is RGSW(0) or RGSW(1).
/// Computes `c0 + select ⊡ (c1 − c0)`, the core of blind rotation.
#[must_use]
pub fn cmux(select: &Rgsw, c0: &Ct, c1: &Ct) -> Ct {
    let diff = Ct {
        a: c1.a - c0.a,
        b: c1.b - c0.b,
    };
    let picked = external_product(select, &diff);
    Ct {
        a: c0.a + picked.a,
        b: c0.b + picked.b,
    }
}

// ===========================================================================
// Blind rotation — the bootstrap's rotation engine.
//
// The CMux loop that homomorphically multiplies an encrypted accumulator by a
// monomial X^k whose exponent k = Σ sᵢ·aᵢ depends on an ENCRYPTED secret (the
// bits sᵢ, given as RGSW ciphertexts) and public rotation amounts aᵢ. This is
// the heart of FHEW/TFHE bootstrapping: with the accumulator initialized to a
// test polynomial encoding a lookup table, the rotation lands the table entry
// for the encrypted phase in the constant slot, ready for sample extraction.
//
// Each step is `ACC ← CMux(BSKᵢ, ACC, X^{aᵢ}·ACC)`: if the secret bit is 1 the
// rotation is applied, else skipped — homomorphically, learning nothing. Built
// entirely on the CMux gate above.
//
// What this is and is NOT. This is the rotation engine, correct and tested on
// its own. It is NOT yet a functional bootstrap of BlackLemon's pertinence
// check: that additionally needs a bootstrapping key over the detection
// secret's bits, modulus-switching d's coefficients into the rotation range
// [0,2N), and a test polynomial encoding the range-check indicator — real FHE
// parameter engineering, deliberately not faked here.

/// The monomial `X^k` in `R_Q[X]/(X^N+1)`, with negacyclic sign for the
/// wrapped range: `X^{k}` for `k mod 2N ∈ [0,N)` is `+1` at that index, and
/// for `[N,2N)` is `−1` at index `k−N`.
fn monomial(k: i64) -> Rq {
    let m = k.rem_euclid(2 * N as i64) as usize;
    let mut coeffs = [0i64; N];
    if m < N {
        coeffs[m] = 1;
    } else {
        coeffs[m - N] = -1;
    }
    lift(&coeffs)
}

/// Multiply a ciphertext by the public monomial `X^k` (rotate the encrypted
/// polynomial), reusing the ring's negacyclic multiplication.
fn rotate(ct: &Ct, k: i64) -> Ct {
    let xk = monomial(k);
    Ct {
        a: xk * ct.a,
        b: xk * ct.b,
    }
}

/// A trivial (noiseless) RLWE encryption of a known test polynomial `f`
/// (coefficients in `Z_t`): `a = 0`, `b = Δ·f`. The accumulator's initial
/// value in a bootstrap.
#[must_use]
pub fn trivial_encrypt(f: &[i64; N]) -> Ct {
    let scaled: Rq = core::array::from_fn(|i| LMField::new(DELTA * f[i])).into();
    Ct {
        a: Rq::default(),
        b: scaled,
    }
}

/// Blind rotation: `ACC ⟼ X^{Σ sᵢ·aᵢ}·ACC`, where the bits `sᵢ` are encrypted
/// as `bsk[i] = RGSW(sᵢ)` and the `rotations[i] = aᵢ` are public. The exponent
/// stays hidden; the result is an RLWE ciphertext of the rotated accumulator.
#[must_use]
pub fn blind_rotate(acc: &Ct, rotations: &[i64], bsk: &[Rgsw]) -> Ct {
    debug_assert_eq!(rotations.len(), bsk.len());
    let mut acc = acc.clone();
    for (a_i, bsk_i) in rotations.iter().zip(bsk.iter()) {
        let rotated = rotate(&acc, *a_i);
        acc = cmux(bsk_i, &acc, &rotated);
    }
    acc
}

// ===========================================================================
// Sample extraction — RLWE coefficient → LWE.
//
// Pulls a single coefficient m_j out of an RLWE ciphertext (a(X), b(X))
// [b − a·s = Δ·m + e] as an LWE ciphertext under the secret ŝ = the
// coefficient vector of the RLWE secret s. This is the step after blind
// rotation in a bootstrap: the rotation lands the wanted lookup value in a
// coefficient, and sample extraction turns it into an LWE ciphertext (which a
// subsequent LWE key-switch would return to the original key).
//
// Identity. The j-th coefficient of (b − a·s) is Δ·m_j + e_j. Writing
// (a·s)_j = Σ_l âₗ·sₗ over the negacyclic ring gives âₗ = a_{j−l} for l ≤ j and
// âₗ = −a_{j−l+N} for l > j, with b̂ = b_j. Then (â, b̂) is an LWE sample of
// m_j under ŝ.
// ===========================================================================

/// An LWE ciphertext over `Z_Q` of dimension `N`, under the coefficient-vector
/// secret of an [`Rlwe`] key: `b − ⟨a, ŝ⟩ = Δ·m + e`.
pub struct LweCt {
    a: [i64; N], // balanced coefficients
    b: i64,
}

/// Extract coefficient `index` of an RLWE ciphertext as an LWE ciphertext.
#[must_use]
pub fn sample_extract(ct: &Ct, index: usize) -> LweCt {
    let j = index;
    let a: [i64; N] = core::array::from_fn(|l| {
        if l <= j {
            ct.a[j - l].balanced()
        } else {
            // −a_{j−l+N}
            (-ct.a[j + N - l]).balanced()
        }
    });
    LweCt {
        a,
        b: ct.b[j].balanced(),
    }
}

impl Rlwe {
    /// Decrypt an LWE ciphertext produced by [`sample_extract`] from this key.
    /// Computes `b − ⟨a, ŝ⟩` (ŝ = this key's coefficients), then de-scales.
    #[must_use]
    pub fn lwe_decrypt(&self, lwe: &LweCt) -> i32 {
        let q = Q as i128;
        let mut acc: i128 = i128::from(lwe.b);
        for l in 0..N {
            let s_l = i128::from(self.s[l].balanced());
            acc -= i128::from(lwe.a[l]) * s_l;
        }
        // balance into (−Q/2, Q/2]
        let mut v = acc.rem_euclid(q);
        if v > q / 2 {
            v -= q;
        }
        let scaled = ((v as f64) / (DELTA as f64)).round() as i128;
        let m = scaled.rem_euclid(T as i128);
        if m > (T as i128) / 2 {
            (m - T as i128) as i32
        } else {
            m as i32
        }
    }
}

// ===========================================================================
// LWE key-switching — re-key a sample-extracted LWE ciphertext.
//
// The step after sample extraction in a bootstrap: the extracted ciphertext is
// an N-dimensional LWE under ŝ (the RLWE secret's coefficient vector), and a
// bootstrap must bring it back to a compact target LWE key before the next
// blind rotation. Same gadget identity as the RLWE key-switch, in LWE/vector
// form, using rat4's `decompose_scalars`.
//
// A key-switch key holds, for each source coordinate i and gadget level j, a
// target-key LWE encryption of `ŝ_i·Bʲ`. To switch `(a,b)` [b − ⟨a,ŝ⟩ = Δm+e],
// decompose each `a_i` into gadget limbs `a_{i,j}` and set
//   result = (0, b) − Σ_{i,j} a_{i,j}·KSK[i][j],
// so `result_b − ⟨result_a, s'⟩ = Δm + e − Σ a_{i,j} e_{i,j}` — the same
// message under the target key, with gadget-bounded extra noise.
// ===========================================================================

/// Target LWE dimension. Correctness-demonstration size, not security-analyzed
/// (consistent with the rest of this module's parameters).
const LWE_N: usize = 512;

/// A compact LWE key (ternary secret) — the bootstrap's "user" key that a
/// sample-extracted ciphertext is switched back to.
pub struct LweKey {
    s: [i64; LWE_N],
}

/// An LWE ciphertext under an [`LweKey`].
pub struct LweCtKs {
    a: [i64; LWE_N],
    b: i64,
}

impl LweKey {
    pub fn keygen<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Self {
        let mut tern = UniformIntDistribution::<i64, R>::new(-1..=1);
        LweKey {
            s: core::array::from_fn(|_| tern.sample(rng)),
        }
    }

    /// Encrypt a raw value `v ∈ Z_Q` (not Δ-scaled): `(a, ⟨a,s⟩ + e + v)`.
    fn encrypt_raw<R: UniformGenerator<Output = u8>>(&self, rng: &mut R, v: i64) -> LweCtKs {
        let mut uid = UniformIntDistribution::<i64, R>::new(0..Q);
        let mut eid = UniformIntDistribution::<i64, R>::new(-8..=8);
        let a: [i64; LWE_N] = core::array::from_fn(|_| uid.sample(rng));
        let mut acc: i128 = i128::from(eid.sample(rng)) + i128::from(v);
        for l in 0..LWE_N {
            acc += i128::from(a[l]) * i128::from(self.s[l]);
        }
        LweCtKs {
            a,
            b: balance_q(acc),
        }
    }

    /// Decrypt an [`LweCtKs`] to a balanced plaintext coefficient in `Z_t`.
    #[must_use]
    pub fn decrypt(&self, ct: &LweCtKs) -> i32 {
        let mut acc: i128 = i128::from(ct.b);
        for l in 0..LWE_N {
            acc -= i128::from(ct.a[l]) * i128::from(self.s[l]);
        }
        descale(balance_q(acc))
    }
}

/// Reduce an i128 mod Q into the balanced range (−Q/2, Q/2], as i64.
fn balance_q(x: i128) -> i64 {
    let q = Q as i128;
    let mut v = x.rem_euclid(q);
    if v > q / 2 {
        v -= q;
    }
    v as i64
}

/// Round a balanced `Δ·m + e` back to the balanced plaintext `m ∈ Z_t`.
fn descale(v: i64) -> i32 {
    let scaled = ((v as f64) / (DELTA as f64)).round() as i128;
    let m = scaled.rem_euclid(T as i128);
    if m > (T as i128) / 2 {
        (m - T as i128) as i32
    } else {
        m as i32
    }
}

/// A key-switch key from the N-dimensional extracted key `ŝ` to a target
/// [`LweKey`]. Stores `N·DIGITS` target-key encryptions, coordinate-major:
/// entry `i·DIGITS + j` encrypts `ŝ_i·Bʲ`.
pub struct LweKeySwitchKey {
    ksk: KsVec<LweCtKs>,
}

/// Build the LWE key-switch key from an [`Rlwe`] (whose secret coefficients are
/// the extracted key `ŝ`) to a target [`LweKey`].
pub fn lwe_keyswitch_keygen<R: UniformGenerator<Output = u8>>(
    rng: &mut R,
    source: &Rlwe,
    target: &LweKey,
) -> LweKeySwitchKey {
    let mut ksk = KsVec::with_capacity(N * DIGITS);
    for i in 0..N {
        let s_hat_i = source.s[i].balanced();
        let mut power: i64 = 1;
        for _ in 0..DIGITS {
            // encrypt ŝ_i · Bʲ under the target key
            let v = balance_q(i128::from(s_hat_i) * i128::from(power));
            ksk.push(target.encrypt_raw(rng, v));
            power = power.wrapping_mul(1i64 << DIGIT_BITS);
        }
    }
    LweKeySwitchKey { ksk }
}

/// Key-switch a sample-extracted [`LweCt`] (dim N, under `ŝ`) to the target key.
#[must_use]
pub fn lwe_keyswitch(ksk: &LweKeySwitchKey, src: &LweCt) -> LweCtKs {
    // Gadget-decompose each source mask coordinate (canonical limbs) via rat4's
    // decompose_scalars, coordinate-major.
    let scalars: crate::matrix::DenseVector<LMField> = (0..N)
        .map(|i| LMField::new(src.a[i]))
        .collect::<KsVec<_>>()
        .into();
    let digits = crate::latticegadget::decompose_scalars::<LMField>(
        &scalars,
        RADIX_MASK,
        DIGIT_BITS as u32,
        DIGITS,
    );

    let mut acc_a = [0i128; LWE_N];
    let mut acc_b: i128 = i128::from(src.b);
    for i in 0..N {
        for j in 0..DIGITS {
            let a_ij = i128::from(digits[i * DIGITS + j].canonical());
            if a_ij == 0 {
                continue;
            }
            let entry = &ksk.ksk[i * DIGITS + j];
            acc_b -= a_ij * i128::from(entry.b);
            for l in 0..LWE_N {
                acc_a[l] -= a_ij * i128::from(entry.a[l]);
            }
        }
    }
    LweCtKs {
        a: core::array::from_fn(|l| balance_q(acc_a[l])),
        b: balance_q(acc_b),
    }
}

// ===========================================================================
// Programmable bootstrap — functional LUT evaluation with noise refresh.
//
// Assembles the primitives (modulus switch -> blind rotation over a
// bootstrapping key -> sample extraction) into a programmable bootstrap: given
// an LWE ciphertext of m and a test polynomial encoding a function f, it
// outputs an RLWE/LWE ciphertext of f(m) whose noise is FRESH (independent of
// the input noise) — the property that makes a bootstrap *sound* for unbounded
// computation, and what would let an oblivious detector evaluate the pertinence
// check homomorphically.
//
// Soundness/precision constraints (see the design note for the full analysis):
//   * The phase must be reduced to the rotation modulus 2N. The message space
//     therefore satisfies p <= 2N; for N = 1024 that is <= 2048 distinguishable
//     values. BlackLemon's per-coefficient classification (near 0, near DELTA,
//     else) maps to phases near 0, near N, and the wide band between — robustly
//     separated at this resolution.
//   * Only NEGACYCLIC functions (f(x+N) = -f(x)) are directly representable in
//     the test polynomial. BlackLemon's pertinence indicator is NOT negacyclic
//     (it wants the same value at phase 0 and phase N), so a sound functional
//     bootstrap of it needs a full-domain construction (FDFB) — analysed but
//     not implemented here.

/// Rotation modulus: a phase is reduced mod 2N before blind rotation.
const TWO_N: i64 = 2 * N as i64;

/// Modulus-switch a balanced value from `Z_Q` to `Z_{2N}` (rounded). Used to
/// bring an LWE ciphertext into the rotation domain.
#[must_use]
pub fn modulus_switch_q_to_2n(x: i64) -> i64 {
    let num = i128::from(x) * i128::from(TWO_N);
    let q = i128::from(Q);
    // round(x * 2N / Q) with sign-aware rounding
    let rounded = if num >= 0 {
        (num + q / 2) / q
    } else {
        (num - q / 2) / q
    };
    (rounded.rem_euclid(i128::from(TWO_N))) as i64
}

/// A bootstrapping key: RGSW encryptions (under the accumulator's RLWE key) of
/// the input LWE secret's bits.
pub struct BootstrapKey {
    bsk: KsVec<Rgsw>,
}

/// Build a bootstrapping key from a binary LWE secret, under the accumulator
/// RLWE key.
pub fn bootstrap_keygen<R: UniformGenerator<Output = u8>>(
    rng: &mut R,
    accumulator_key: &Rlwe,
    lwe_secret: &[i64],
) -> BootstrapKey {
    BootstrapKey {
        bsk: lwe_secret
            .iter()
            .map(|&b| accumulator_key.rgsw_encrypt(rng, b))
            .collect(),
    }
}

/// Programmable bootstrap. Inputs: a bootstrapping key, a test polynomial `tv`
/// (degree N, encoding the function over the rotation domain), and an LWE
/// ciphertext `(lwe_a, lwe_b)` ALREADY in the rotation modulus `2N` with phase
/// `φ = lwe_b − ⟨lwe_a, s⟩`. Output: an RLWE ciphertext whose constant
/// coefficient is `tv[φ]` (the LUT value at the encrypted phase), with fresh
/// noise. Apply [`sample_extract`] at index 0 to get the LWE result.
#[must_use]
pub fn programmable_bootstrap(bsk: &BootstrapKey, tv: &[i64; N], lwe_a: &[i64], lwe_b: i64) -> Ct {
    // ACC = X^{-b} · tv  (trivial, noiseless accumulator rotated by -b)
    let acc0 = trivial_encrypt(tv);
    let acc = rotate(&acc0, -lwe_b);
    // Apply X^{a_i} for each set secret bit: ACC = X^{-b + ⟨a,s⟩}·tv = X^{-φ}·tv
    blind_rotate(&acc, lwe_a, &bsk.bsk)
}
