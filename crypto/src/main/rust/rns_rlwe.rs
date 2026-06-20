/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Leveled RLWE over the NTT-friendly RNS accumulator ring ([`RnsPoly`],
//! modulus `P ≈ 2^88`) — the substrate the bandwidth-lite OMR detector needs
//! and that the LM ring (`Q ≈ 2^60`) could not support.
//!
//! The completion analysis showed every homomorphic step past the linear
//! decryption overflows `Q ≈ 2^60`: the range-check fold reaches `~2^70`, and
//! the ciphertext multiplication OMR payload compaction needs reaches
//! `~t·noise ≈ 2^48 > Δ/2 ≈ 2^43`. Re-instantiating the leveled HE over the RNS
//! ring moves all of it into a regime with headroom: here `Δ = ⌊P/t⌋ ≈ 2^72`,
//! so `Δ/2 ≈ 2^71` dwarfs the noise these operations produce.
//!
//! This module is the first layer over the verified [`RnsPoly`] arithmetic
//! core: symmetric-key leveled RLWE (keygen / encrypt / decrypt) with
//! homomorphic addition, subtraction and plaintext multiplication. The external
//! product, CMux, blind rotation and bootstrap that sit on top — already built
//! and tested on the LM ring — are re-instantiated over this in the same way.

extern crate alloc;
use alloc::vec::Vec;

use crate::random::UniformGenerator;
use crate::rns::{GADGET_BITS, GADGET_DIGITS, NTT_DEGREE, RNS_PRIMES, RnsInt, RnsPoly};

/// Plaintext modulus (matches BlackLemon's clue ring).
pub const T: i64 = 65537;

/// Scaling factor `Δ = ⌊P/t⌋` placing a plaintext bit in the high part of the
/// ciphertext modulus.
#[must_use]
pub fn delta() -> i128 {
    RnsInt::product() / i128::from(T)
}

/// A leveled-RLWE secret key over the RNS ring: a ternary polynomial.
pub struct RnsRlwe {
    s: RnsPoly,
}

/// A leveled-RLWE ciphertext `(a, b)` with `b + a·s = Δ·m + e`.
#[derive(Clone)]
pub struct RnsCt {
    a: RnsPoly,
    b: RnsPoly,
}

impl RnsRlwe {
    /// Generate a fresh ternary secret key.
    pub fn keygen<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Self {
        RnsRlwe {
            s: RnsPoly::small(rng, 1),
        }
    }

    /// Encrypt plaintext coefficients `m ∈ [0, t)^N`: sample uniform `a` and
    /// small error `e`, set `b = −(a·s) + e + Δ·m`.
    pub fn encrypt<R: UniformGenerator<Output = u8>>(
        &self,
        rng: &mut R,
        m: &[i64; NTT_DEGREE],
    ) -> RnsCt {
        let a = RnsPoly::uniform(rng);
        let e = RnsPoly::small(rng, 8);
        let scaled = RnsPoly::scale_plaintext(m, delta());
        // b = Δ·m + e − a·s, so that b + a·s = Δ·m + e.
        let b = scaled.add(&e).sub(&a.negacyclic_mul(&self.s));
        RnsCt { a, b }
    }

    /// Decrypt: recover `m = round((b + a·s)/Δ) mod t` per coefficient.
    #[must_use]
    pub fn decrypt(&self, ct: &RnsCt) -> [i64; NTT_DEGREE] {
        let phase = ct.b.add(&ct.a.negacyclic_mul(&self.s));
        let d = delta();
        core::array::from_fn(|i| {
            let c = phase.balanced_coefficient(i);
            let q = ((c as f64) / (d as f64)).round() as i64;
            q.rem_euclid(T)
        })
    }

    /// A fresh RLWE encryption of zero: `a` uniform, `b = e − a·s`, so the phase
    /// `b + a·s = e` is small. The building block of RGSW rows.
    pub fn encrypt_zero<R: UniformGenerator<Output = u8>>(&self, rng: &mut R) -> RnsCt {
        let a = RnsPoly::uniform(rng);
        let e = RnsPoly::small(rng, 8);
        let b = e.sub(&a.negacyclic_mul(&self.s));
        RnsCt { a, b }
    }

    /// Encrypt a small scalar `μ` as an RGSW ciphertext (the CMux selector
    /// form): `2·GADGET_DIGITS` RLWE(0) rows, with `μ·Bⁱ` added to the `a`-part
    /// of the first group and the `b`-part of the second.
    pub fn rgsw_encrypt<R: UniformGenerator<Output = u8>>(&self, rng: &mut R, mu: i128) -> RnsRgsw {
        let mut rows = Vec::with_capacity(2 * GADGET_DIGITS);
        for i in 0..GADGET_DIGITS {
            let g = mu * (1i128 << (GADGET_BITS * i as u32));
            let mut row = self.encrypt_zero(rng);
            row.a = row.a.add(&RnsPoly::constant(g));
            rows.push(row);
        }
        for i in 0..GADGET_DIGITS {
            let g = mu * (1i128 << (GADGET_BITS * i as u32));
            let mut row = self.encrypt_zero(rng);
            row.b = row.b.add(&RnsPoly::constant(g));
            rows.push(row);
        }
        RnsRgsw { rows }
    }
}

/// An RGSW ciphertext over the RNS ring: `2·GADGET_DIGITS` RLWE rows.
pub struct RnsRgsw {
    rows: Vec<RnsCt>,
}

/// External product `RLWE(m) ⊡ RGSW(μ) → RLWE(μ·m)`: gadget-decompose the
/// ciphertext and recombine against the RGSW rows. Sound here because the
/// digit coefficients are `< B = 2^23` and the row noise `~2^3`, so the product
/// noise `~2^39` sits far below `Δ/2 ≈ 2^71`.
#[must_use]
pub fn external_product(rgsw: &RnsRgsw, ct: &RnsCt) -> RnsCt {
    let a_digits = ct.a.gadget_decompose();
    let b_digits = ct.b.gadget_decompose();
    let mut acc_a = RnsPoly::zero();
    let mut acc_b = RnsPoly::zero();
    for i in 0..GADGET_DIGITS {
        acc_a = acc_a
            .add(&a_digits[i].negacyclic_mul(&rgsw.rows[i].a))
            .add(&b_digits[i].negacyclic_mul(&rgsw.rows[GADGET_DIGITS + i].a));
        acc_b = acc_b
            .add(&a_digits[i].negacyclic_mul(&rgsw.rows[i].b))
            .add(&b_digits[i].negacyclic_mul(&rgsw.rows[GADGET_DIGITS + i].b));
    }
    RnsCt { a: acc_a, b: acc_b }
}

/// CMux: `select ? c1 : c0`, computed as `c0 + select ⊡ (c1 − c0)`. The core
/// gate of blind rotation and of the circuit-bootstrap fold.
#[must_use]
pub fn cmux(select: &RnsRgsw, c0: &RnsCt, c1: &RnsCt) -> RnsCt {
    let diff = c1.sub(c0);
    c0.add(&external_product(select, &diff))
}

/// The monomial `X^k` in the negacyclic ring: `+1` at index `k mod 2N` when
/// that is `< N`, else `−1` at index `k − N`.
fn monomial(k: i64) -> RnsPoly {
    let m = k.rem_euclid(2 * NTT_DEGREE as i64) as usize;
    let mut coeffs = [0i64; NTT_DEGREE];
    if m < NTT_DEGREE {
        coeffs[m] = 1;
    } else {
        coeffs[m - NTT_DEGREE] = -1;
    }
    RnsPoly::from_balanced(&coeffs)
}

/// Multiply a ciphertext by the public monomial `X^k` (rotate the encrypted
/// polynomial).
#[must_use]
pub fn rotate(ct: &RnsCt, k: i64) -> RnsCt {
    let xk = monomial(k);
    RnsCt {
        a: ct.a.negacyclic_mul(&xk),
        b: ct.b.negacyclic_mul(&xk),
    }
}

/// A trivial (noiseless) encryption of a known test polynomial `f`: `a = 0`,
/// `b = Δ·f`. The accumulator's initial value in a bootstrap.
#[must_use]
pub fn trivial_encrypt(f: &[i64; NTT_DEGREE]) -> RnsCt {
    RnsCt {
        a: RnsPoly::zero(),
        b: RnsPoly::scale_plaintext(f, delta()),
    }
}

/// Blind rotation: `ACC ← CMux(bskᵢ, ACC, X^{rotᵢ}·ACC)` over all `i`, rotating
/// the accumulator by `Σ sᵢ·rotᵢ` where the `sᵢ` are the (encrypted) secret
/// bits carried by the bootstrapping key `bsk`. The bootstrap's rotation
/// engine, built entirely on CMux.
#[must_use]
pub fn blind_rotate(acc: &RnsCt, rotations: &[i64], bsk: &[RnsRgsw]) -> RnsCt {
    let mut acc = acc.clone();
    for (rot, sel) in rotations.iter().zip(bsk.iter()) {
        let rotated = rotate(&acc, *rot);
        acc = cmux(sel, &acc, &rotated);
    }
    acc
}

impl RnsCt {
    /// Homomorphic addition.
    #[must_use]
    pub fn add(&self, other: &RnsCt) -> RnsCt {
        RnsCt {
            a: self.a.add(&other.a),
            b: self.b.add(&other.b),
        }
    }

    /// Homomorphic subtraction.
    #[must_use]
    pub fn sub(&self, other: &RnsCt) -> RnsCt {
        RnsCt {
            a: self.a.sub(&other.a),
            b: self.b.sub(&other.b),
        }
    }

    /// Multiply by a cleartext polynomial (negacyclic): scales the plaintext by
    /// `p` and the noise by `‖p‖` — no growth in the plaintext scale, so it
    /// stays decryptable. (The public bucket weights of OMR compaction are
    /// exactly such cleartext multipliers.)
    #[must_use]
    pub fn plain_mul(&self, p: &RnsPoly) -> RnsCt {
        RnsCt {
            a: self.a.negacyclic_mul(p),
            b: self.b.negacyclic_mul(p),
        }
    }
}

// ===========================================================================
// Sample extraction + programmable bootstrap over the RNS ring (step 3 finish).
//
// Ports the LM programmable bootstrap onto RnsCt, reusing its sign/index
// conventions, adapted to this scheme's phase = b + a·s. The PBS evaluates an
// arbitrary LUT at an encrypted phase with FRESH output noise — the engine that
// emits the encrypted pertinence bit in step 4.
// ===========================================================================

/// An LWE ciphertext (dimension N) under an [`RnsRlwe`] key's coefficient
/// vector: `phase = b + Σ aₗ·sₗ ≈ Δ·m`.
pub struct RnsLwe {
    pub a: Vec<i128>,
    pub b: i128,
}

/// Extract coefficient `index` of an RLWE ciphertext as an LWE ciphertext under
/// the key's coefficient vector. With phase `B + A·s`, the j-th coefficient is
/// `B[j] + Σₗ âₗ sₗ` where `âₗ = A[j−l]` (l ≤ j) and `−A[j−l+N]` (l > j).
#[must_use]
pub fn sample_extract(ct: &RnsCt, index: usize) -> RnsLwe {
    let j = index;
    let a: Vec<i128> = (0..NTT_DEGREE)
        .map(|l| {
            if l <= j {
                ct.a.balanced_coefficient(j - l)
            } else {
                -ct.a.balanced_coefficient(j + NTT_DEGREE - l)
            }
        })
        .collect();
    RnsLwe {
        a,
        b: ct.b.balanced_coefficient(j),
    }
}

impl RnsRlwe {
    /// Decrypt an LWE ciphertext produced by [`sample_extract`] from this key.
    #[must_use]
    pub fn lwe_decrypt(&self, lwe: &RnsLwe) -> i64 {
        let p = RnsInt::product();
        let mut acc: i128 = lwe.b;
        for (l, &al) in lwe.a.iter().enumerate() {
            acc += al * self.s.balanced_coefficient(l);
            acc = acc.rem_euclid(p);
        }
        let mut v = acc.rem_euclid(p);
        if v > p / 2 {
            v -= p;
        }
        let scaled = ((v as f64) / (delta() as f64)).round() as i128;
        scaled.rem_euclid(i128::from(T)) as i64
    }
}

/// Rotation modulus for the bootstrap.
const TWO_N: i64 = 2 * NTT_DEGREE as i64;

/// Modulus-switch a balanced `Z_P` value into `Z_{2N}` (rounded).
#[must_use]
pub fn modulus_switch_to_2n(x: i128) -> i64 {
    let p = RnsInt::product();
    let num = x * i128::from(TWO_N);
    let rounded = if num >= 0 {
        (num + p / 2) / p
    } else {
        (num - p / 2) / p
    };
    rounded.rem_euclid(i128::from(TWO_N)) as i64
}

/// A bootstrapping key: RGSW (under the accumulator key) of the input LWE
/// secret's bits.
pub struct RnsBootstrapKey {
    pub bsk: Vec<RnsRgsw>,
}

/// Build a bootstrapping key from a binary LWE secret under the accumulator key.
pub fn bootstrap_keygen<R: UniformGenerator<Output = u8>>(
    rng: &mut R,
    accumulator_key: &RnsRlwe,
    lwe_secret: &[i64],
) -> RnsBootstrapKey {
    RnsBootstrapKey {
        bsk: lwe_secret
            .iter()
            .map(|&b| accumulator_key.rgsw_encrypt(rng, i128::from(b)))
            .collect(),
    }
}

/// Programmable bootstrap. Given a bootstrapping key, a test polynomial `tv`,
/// and an LWE ciphertext `(lwe_a, lwe_b)` in the rotation modulus `2N` with
/// phase `φ = lwe_b + Σ lwe_aₗ·secretₗ`, returns an RLWE ciphertext whose
/// constant coefficient is `tv[φ]` with fresh noise. The rotation exponent is
/// `−φ` (this scheme's `phase = b + a·s` convention negates `lwe_a`).
#[must_use]
pub fn programmable_bootstrap(
    bsk: &RnsBootstrapKey,
    tv: &[i64; NTT_DEGREE],
    lwe_a: &[i64],
    lwe_b: i64,
) -> RnsCt {
    let acc0 = trivial_encrypt(tv);
    let acc = rotate(&acc0, -lwe_b);
    let rotations: Vec<i64> = lwe_a.iter().map(|a| -a).collect();
    blind_rotate(&acc, &rotations, &bsk.bsk)
}

// ===========================================================================
// Step 4 — homomorphic pertinence via the half-domain functional bootstrap.
//
// The PBS evaluates negacyclic functions directly; BlackLemon's pertinence
// indicator is even (it wants the same verdict at a phase and its negation), so
// it is evaluated via the half-domain technique: confine the encoded phase to
// the lower half-torus [0,N), where the test polynomial may encode an arbitrary
// function — here the in-band → 1 / else → 0 pertinence predicate. The PBS then
// emits Enc(PV), the encrypted pertinence bit the compaction consumes.
// ===========================================================================

/// Encode message `m ∈ [0,p)` as a phase centred in its slot within `[0,N)`.
#[must_use]
pub const fn encode_half_domain(m: usize, p: usize) -> i64 {
    let slot = NTT_DEGREE / p;
    (m * slot + slot / 2) as i64
}

/// Test polynomial encoding an arbitrary function `values: [0,p) → Z_t` over the
/// half-torus (upper half left zero, never indexed).
#[must_use]
pub fn half_domain_test_vector(values: &[i64], p: usize) -> [i64; NTT_DEGREE] {
    let slot = NTT_DEGREE / p;
    core::array::from_fn(|k| {
        let m = (k / slot).min(p - 1);
        values[m]
    })
}

// ===========================================================================
// Packing key-switch (LWE -> RLWE) — prerequisite for the circuit bootstrap.
//
// Turns an LWE ciphertext (phase b + Σ aᵢ zᵢ = Δm) under a small key z into an
// RLWE ciphertext under the target key s', encrypting m in the constant
// coefficient. The circuit bootstrap that converts Enc(PV) (LWE) into RGSW(PV)
// is built from this plus the PBS: each gadget row is a packed bootstrap output.
//
// KSK[i][j] is an RLWE encryption (under s') of the RAW value zᵢ·Bʲ in the
// constant coefficient. Decomposing each aᵢ into gadget digits and recombining
// against the KSK reconstructs b + Σ aᵢ zᵢ in the constant slot.
// ===========================================================================

/// Signed gadget digits of a scalar `x` (base `2^GADGET_BITS`).
fn signed_scalar_digits(mut x: i128) -> [i64; GADGET_DIGITS] {
    let base: i128 = 1i128 << GADGET_BITS;
    core::array::from_fn(|_| {
        let mut r = x.rem_euclid(base);
        if r > base / 2 {
            r -= base;
        }
        x = (x - r) / base;
        r as i64
    })
}

impl RnsRlwe {
    /// RLWE encryption with the raw value `value` in the constant coefficient
    /// (phase = e + value), not Δ-scaled. The gadget rows of a key-switch key.
    pub fn encrypt_raw_constant<R: UniformGenerator<Output = u8>>(
        &self,
        rng: &mut R,
        value: i128,
    ) -> RnsCt {
        let mut ct = self.encrypt_zero(rng);
        ct.b = ct.b.add(&RnsPoly::constant(value));
        ct
    }
}

/// A packing key-switch key from a small source LWE key `z` (length `n`) to the
/// target [`RnsRlwe`]. Entry `i·GADGET_DIGITS + j` encrypts `zᵢ·Bʲ`.
pub struct PackingKeySwitchKey {
    ksk: Vec<RnsCt>,
    n: usize,
}

/// Build a packing key-switch key from source key `z` to `target`.
pub fn packing_keyswitch_keygen<R: UniformGenerator<Output = u8>>(
    rng: &mut R,
    z: &[i64],
    target: &RnsRlwe,
) -> PackingKeySwitchKey {
    let mut ksk = Vec::with_capacity(z.len() * GADGET_DIGITS);
    for &zi in z {
        for j in 0..GADGET_DIGITS {
            let value = i128::from(zi) * (1i128 << (GADGET_BITS * j as u32));
            ksk.push(target.encrypt_raw_constant(rng, value));
        }
    }
    PackingKeySwitchKey { ksk, n: z.len() }
}

/// Pack an LWE ciphertext `(lwe_a, lwe_b)` (phase `b + Σ aᵢ zᵢ = Δm`, length
/// `n`) into an RLWE ciphertext under the target key, encrypting `m` in the
/// constant coefficient.
#[must_use]
#[allow(clippy::needless_range_loop)]
pub fn packing_keyswitch(ksk: &PackingKeySwitchKey, lwe_a: &[i128], lwe_b: i128) -> RnsCt {
    let mut acc = RnsCt {
        a: RnsPoly::zero(),
        b: RnsPoly::constant(lwe_b),
    };
    for i in 0..ksk.n {
        let digits = signed_scalar_digits(lwe_a[i]);
        for j in 0..GADGET_DIGITS {
            let d = i128::from(digits[j]);
            if d == 0 {
                continue;
            }
            let scaled = ksk.ksk[i * GADGET_DIGITS + j].plain_mul(&RnsPoly::constant(d));
            acc = acc.add(&scaled);
        }
    }
    acc
}

// ===========================================================================
// BFV ciphertext×ciphertext multiplication at the real P ≈ 2^88 RNS modulus.
//
// This is the oblivious-compaction connector (PV·payload) operating at the same
// modulus as detection/bootstrap, so it integrates with the rest of the stack.
// The tensor product of two ciphertexts has coefficients up to N·(P/2)² ≈ 2^184,
// which exceeds i128, so the tensor and the BFV rescale round(D·t/P) are done in
// `BigInt`. Division by P is performed as sequential division by its three NTT
// primes (floor(floor(X/p₀)/p₁)/p₂ = floor(X/P)); the rescaled result fits i128.
// For a single multiplication the product is kept as a degree-2 ciphertext
// (decrypted with s²), so no relinearization is needed.
// ===========================================================================

use crate::bigint::BigInt;

/// A degree-2 RLWE/BFV ciphertext `(c0, c1, c2)` with `c0 + c1·s + c2·s² = Δ·m + e`.
#[derive(Clone)]
pub struct RnsCt2 {
    c0: RnsPoly,
    c1: RnsPoly,
    c2: RnsPoly,
}

fn b4_from_u128(x: u128) -> BigInt<4> {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&x.to_le_bytes());
    BigInt::<4>::from_le_bytes::<32>(bytes)
}

fn b16_from_u128(x: u128) -> BigInt<16> {
    let mut bytes = [0u8; 128];
    bytes[..16].copy_from_slice(&x.to_le_bytes());
    BigInt::<16>::from_le_bytes::<128>(bytes)
}

fn b16_low_u128(x: BigInt<16>) -> u128 {
    let bytes = x.to_le_bytes::<128>();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&bytes[..16]);
    u128::from_le_bytes(lo)
}

/// Accumulate the negacyclic convolution `a * b` (signed, exact) into `acc`.
#[allow(clippy::needless_range_loop)]
fn conv_accumulate(
    acc: &mut [BigInt<8>; NTT_DEGREE],
    a: &[i128; NTT_DEGREE],
    b: &[i128; NTT_DEGREE],
) {
    for i in 0..NTT_DEGREE {
        if a[i] == 0 {
            continue;
        }
        let ma = b4_from_u128(a[i].unsigned_abs());
        let sa = a[i] < 0;
        for j in 0..NTT_DEGREE {
            if b[j] == 0 {
                continue;
            }
            let mut k = i + j;
            let mut neg = sa ^ (b[j] < 0);
            if k >= NTT_DEGREE {
                k -= NTT_DEGREE;
                neg = !neg;
            }
            let prod = ma.widening_mul::<4, 8>(b4_from_u128(b[j].unsigned_abs()));
            acc[k] = if neg { acc[k] - prod } else { acc[k] + prod };
        }
    }
}

/// BFV rescale of one tensor coefficient: `round(D · t / P) mod P`, returned in
/// `[0, P)`. `D` is a signed 2's-complement `BigInt<8>` (|D| < 2^184).
fn rescale_coeff(d: BigInt<8>) -> i128 {
    let half = BigInt::<8>::from([0, 0, 0, 0, 0, 0, 0, 1u64 << 63]);
    let neg = d >= half;
    let mag = if neg { -d } else { d }; // |D|, < 2^184
    // numerator = |D|·t + P/2  (< 2^201, fits BigInt<16>)
    let p = RnsInt::product();
    let mut num = mag.widening_mul::<8, 16>(BigInt::<8>::from(T as u64));
    num += b16_from_u128((p / 2) as u128);
    // floor(num / P) via sequential division by the three RNS primes
    let mut q = num;
    for &prime in &RNS_PRIMES {
        q /= prime as u64;
    }
    let v = b16_low_u128(q) as i128; // |result| < 2^112 fits i128
    let signed = if neg { -v } else { v };
    signed.rem_euclid(p)
}

fn rescale_poly(acc: &[BigInt<8>; NTT_DEGREE]) -> RnsPoly {
    let coeffs: [i128; NTT_DEGREE] = core::array::from_fn(|i| rescale_coeff(acc[i]));
    RnsPoly::from_coefficients(&coeffs)
}

/// Reference BFV multiply: exact O(N²) bigint convolution. Kept as the
/// correctness oracle for the fast NTT version (`bfv_mul_rns`).
#[must_use]
pub fn bfv_mul_rns_ref(x: &RnsCt, y: &RnsCt) -> RnsCt2 {
    // phase = b + a·s, so (c0,c1) := (b,a).
    let xb: [i128; NTT_DEGREE] = core::array::from_fn(|i| x.b.balanced_coefficient(i));
    let xa: [i128; NTT_DEGREE] = core::array::from_fn(|i| x.a.balanced_coefficient(i));
    let yb: [i128; NTT_DEGREE] = core::array::from_fn(|i| y.b.balanced_coefficient(i));
    let ya: [i128; NTT_DEGREE] = core::array::from_fn(|i| y.a.balanced_coefficient(i));

    let mut t0 = [BigInt::<8>::ZERO; NTT_DEGREE];
    let mut t1 = [BigInt::<8>::ZERO; NTT_DEGREE];
    let mut t2 = [BigInt::<8>::ZERO; NTT_DEGREE];
    conv_accumulate(&mut t0, &xb, &yb); // c0·c0'
    conv_accumulate(&mut t1, &xb, &ya); // c0·c1'
    conv_accumulate(&mut t1, &xa, &yb); // + c1·c0'
    conv_accumulate(&mut t2, &xa, &ya); // c1·c1'

    RnsCt2 {
        c0: rescale_poly(&t0),
        c1: rescale_poly(&t1),
        c2: rescale_poly(&t2),
    }
}

impl RnsRlwe {
    /// Decrypt a degree-2 (product) ciphertext: `round((c0 + c1·s + c2·s²)/Δ)`.
    #[must_use]
    pub fn decrypt2(&self, ct: &RnsCt2) -> [i64; NTT_DEGREE] {
        let s2 = self.s.negacyclic_mul(&self.s);
        let phase = ct
            .c0
            .add(&ct.c1.negacyclic_mul(&self.s))
            .add(&ct.c2.negacyclic_mul(&s2));
        let d = delta();
        core::array::from_fn(|i| {
            let c = phase.balanced_coefficient(i);
            let q = ((c as f64) / (d as f64)).round() as i64;
            q.rem_euclid(T)
        })
    }
}

impl RnsCt2 {
    /// Multiply a degree-2 ciphertext by a cleartext scalar weight.
    #[must_use]
    pub fn scalar_mul(&self, w: i128) -> RnsCt2 {
        let k = RnsPoly::constant(w);
        RnsCt2 {
            c0: self.c0.negacyclic_mul(&k),
            c1: self.c1.negacyclic_mul(&k),
            c2: self.c2.negacyclic_mul(&k),
        }
    }

    /// Coefficient-wise sum of two degree-2 ciphertexts.
    #[must_use]
    pub fn add(&self, other: &RnsCt2) -> RnsCt2 {
        RnsCt2 {
            c0: self.c0.add(&other.c0),
            c1: self.c1.add(&other.c1),
            c2: self.c2.add(&other.c2),
        }
    }
}

// ===========================================================================
// Fast BFV multiply: the tensor via an extended-basis RNS-NTT.
//
// The exact signed tensor coefficient fits in (−2^185, 2^185); choosing seven
// NTT primes (the three base RNS primes plus four more) whose product Q_ext ≈
// 2^208 exceeds 2·2^185 lets us compute each tensor polynomial mod every prime
// by an O(N log N) negacyclic NTT, then reconstruct the exact signed integer per
// coefficient by Garner's algorithm (mixed-radix CRT, only u64 modular ops).
// Only the rescale round(D·t/P) is bigint. This replaces the O(N²) bigint
// convolution of `bfv_mul_rns_ref` and is validated to agree with it bit-for-bit.
// ===========================================================================

/// Four extra NTT-friendly primes (≡ 1 mod 2N) extending the base RNS basis so
/// the seven-prime product exceeds the tensor range.
const EXT_EXTRA_PRIMES: [i64; 4] = [1073692673, 1073668097, 1073651713, 1073643521];

#[inline]
const fn ext_primes() -> [i64; 7] {
    [
        RNS_PRIMES[0],
        RNS_PRIMES[1],
        RNS_PRIMES[2],
        EXT_EXTRA_PRIMES[0],
        EXT_EXTRA_PRIMES[1],
        EXT_EXTRA_PRIMES[2],
        EXT_EXTRA_PRIMES[3],
    ]
}

fn b16_to_b8_low(x: BigInt<16>) -> BigInt<8> {
    let bytes = x.to_le_bytes::<128>();
    let mut lo = [0u8; 64];
    lo.copy_from_slice(&bytes[..64]);
    BigInt::<8>::from_le_bytes::<64>(lo)
}

/// `d · m + a` for `m, a` small (u64), result kept at 512 bits.
fn b8_mul_add(d: BigInt<8>, m: u64, a: u64) -> BigInt<8> {
    let prod = d.widening_mul::<8, 16>(BigInt::<8>::from(m));
    b16_to_b8_low(prod + b16_from_u128(u128::from(a)))
}

/// Negacyclic convolution residues of two balanced coefficient vectors, one row
/// per extended prime.
fn conv_residues(a: &[i128; NTT_DEGREE], b: &[i128; NTT_DEGREE]) -> Vec<[i64; NTT_DEGREE]> {
    let primes = ext_primes();
    (0..7)
        .map(|pi| {
            let p = primes[pi];
            let am: [i64; NTT_DEGREE] =
                core::array::from_fn(|i| a[i].rem_euclid(i128::from(p)) as i64);
            let bm: [i64; NTT_DEGREE] =
                core::array::from_fn(|i| b[i].rem_euclid(i128::from(p)) as i64);
            crate::rns::negacyclic_mul_mod(&am, &bm, p)
        })
        .collect()
}

fn add_residues(x: &[[i64; NTT_DEGREE]], y: &[[i64; NTT_DEGREE]]) -> Vec<[i64; NTT_DEGREE]> {
    let primes = ext_primes();
    (0..7)
        .map(|pi| {
            let p = primes[pi];
            core::array::from_fn(|i| (x[pi][i] + y[pi][i]).rem_euclid(p))
        })
        .collect()
}

/// Precomputed Garner data for the seven-prime extended basis.
struct GarnerCtx {
    primes: [i64; 7],
    inv: [[i64; 7]; 7], // inv[i][j] = (p_i)^{-1} mod p_j, for i < j
    q_ext: BigInt<8>,
    q_half: BigInt<8>,
}

impl GarnerCtx {
    fn new() -> Self {
        let primes = ext_primes();
        let mut inv = [[0i64; 7]; 7];
        for i in 0..7 {
            for j in (i + 1)..7 {
                inv[i][j] = crate::rns::inv_mod(primes[i].rem_euclid(primes[j]), primes[j]);
            }
        }
        let mut q_ext = BigInt::<8>::from(1u64);
        for &p in &primes {
            q_ext = b8_mul_add(q_ext, p as u64, 0);
        }
        let q_half = q_ext >> 1u64;
        GarnerCtx {
            primes,
            inv,
            q_ext,
            q_half,
        }
    }

    /// Reconstruct the exact SIGNED integer from its seven residues, then BFV-
    /// rescale: `round(D·t/P) mod P`, returned in `[0, P)`.
    #[allow(clippy::needless_range_loop)]
    fn rescale(&self, residues: &[[i64; NTT_DEGREE]], idx: usize) -> i128 {
        // mixed-radix (Garner) digits
        let mut x = [0i64; 7];
        for j in 0..7 {
            let pj = self.primes[j];
            let mut xj = residues[j][idx].rem_euclid(pj);
            for i in 0..j {
                let diff = (xj - x[i]).rem_euclid(pj);
                xj = ((i128::from(diff) * i128::from(self.inv[i][j])).rem_euclid(i128::from(pj)))
                    as i64;
            }
            x[j] = xj;
        }
        // Horner: D = (((x6)·p5 + x5)·p4 + …)·p0 + x0  (unsigned, in [0, Q_ext))
        let mut d = BigInt::<8>::from(x[6] as u64);
        for j in (0..6).rev() {
            d = b8_mul_add(d, self.primes[j] as u64, x[j] as u64);
        }
        // balance to signed magnitude
        let neg = d > self.q_half;
        let mag = if neg { self.q_ext - d } else { d };
        // round(mag·t + P/2) / P  with P = base-3 product (sequential Div<u64>)
        let p = RnsInt::product();
        let mut num = mag.widening_mul::<8, 16>(BigInt::<8>::from(T as u64));
        num += b16_from_u128((p / 2) as u128);
        let mut q = num;
        for &prime in &RNS_PRIMES {
            q /= prime as u64;
        }
        let v = b16_low_u128(q) as i128;
        let signed = if neg { -v } else { v };
        signed.rem_euclid(p)
    }

    fn rescale_poly(&self, residues: &[[i64; NTT_DEGREE]]) -> RnsPoly {
        let coeffs: [i128; NTT_DEGREE] = core::array::from_fn(|i| self.rescale(residues, i));
        RnsPoly::from_coefficients(&coeffs)
    }
}

/// Fast BFV ciphertext×ciphertext multiply at the 2^88 modulus (extended-basis
/// NTT tensor). Returns a degree-2 ciphertext encrypting `m₁·m₂`.
#[must_use]
pub fn bfv_mul_rns(x: &RnsCt, y: &RnsCt) -> RnsCt2 {
    let xb: [i128; NTT_DEGREE] = core::array::from_fn(|i| x.b.balanced_coefficient(i));
    let xa: [i128; NTT_DEGREE] = core::array::from_fn(|i| x.a.balanced_coefficient(i));
    let yb: [i128; NTT_DEGREE] = core::array::from_fn(|i| y.b.balanced_coefficient(i));
    let ya: [i128; NTT_DEGREE] = core::array::from_fn(|i| y.a.balanced_coefficient(i));

    let t0 = conv_residues(&xb, &yb); // c0·c0'
    let t1 = add_residues(&conv_residues(&xb, &ya), &conv_residues(&xa, &yb)); // c0·c1'+c1·c0'
    let t2 = conv_residues(&xa, &ya); // c1·c1'

    let g = GarnerCtx::new();
    RnsCt2 {
        c0: g.rescale_poly(&t0),
        c1: g.rescale_poly(&t1),
        c2: g.rescale_poly(&t2),
    }
}

// ===========================================================================
// LWE → LWE key-switch (dimension reduction) — bridges sample_extract(Enc(d))
// (an LWE under the dim-N accumulator key) to a small dim-n bootstrap key, the
// input the programmable bootstrap expects. Standard gadget key-switch in Z_P:
// the gadget (GADGET_BITS·GADGET_DIGITS = 92 > log₂P) recomposes each source
// mask coefficient exactly, so the only added noise is the key-switch key's.
// ===========================================================================

/// A key-switching key from a dim-`n_src` LWE key to a dim-`n_dst` LWE key:
/// for each source coordinate and gadget digit, an LWE under the destination
/// key encrypting `z_l · Bʲ`.
pub struct LweKeySwitchKey {
    ksk: Vec<RnsLwe>,
    n_src: usize,
    n_dst: usize,
}

fn lwe_encrypt_under<R: UniformGenerator<Output = u8>>(
    small_key: &[i64],
    value: i128,
    rng: &mut R,
) -> RnsLwe {
    let p = RnsInt::product();
    let mask = RnsPoly::uniform(rng);
    let a: Vec<i128> = (0..small_key.len())
        .map(|i| mask.balanced_coefficient(i))
        .collect();
    let noise = RnsPoly::small(rng, 8);
    let e = noise.balanced_coefficient(0);
    let mut inner: i128 = 0;
    for (ai, &si) in a.iter().zip(small_key.iter()) {
        inner = (inner + ai * i128::from(si)).rem_euclid(p);
    }
    let b = (value - inner + e).rem_euclid(p);
    RnsLwe { a, b }
}

impl RnsRlwe {
    /// Build a key-switch key from this accumulator key's coefficient vector
    /// (the key that `sample_extract` produces LWEs under) to a small LWE
    /// `bootstrap_key`.
    pub fn lwe_keyswitch_keygen<R: UniformGenerator<Output = u8>>(
        &self,
        rng: &mut R,
        bootstrap_key: &[i64],
    ) -> LweKeySwitchKey {
        let z: [i128; NTT_DEGREE] = core::array::from_fn(|l| self.s.balanced_coefficient(l));
        let mut ksk = Vec::with_capacity(NTT_DEGREE * GADGET_DIGITS);
        for &zl in z.iter() {
            for j in 0..GADGET_DIGITS {
                let value = zl * (1i128 << (GADGET_BITS * j as u32));
                ksk.push(lwe_encrypt_under(bootstrap_key, value, rng));
            }
        }
        LweKeySwitchKey {
            ksk,
            n_src: NTT_DEGREE,
            n_dst: bootstrap_key.len(),
        }
    }

    /// Decrypt an LWE produced by [`sample_extract`] from this key, returning
    /// the BALANCED plaintext in `(−t/2, t/2]` (so the band classifier's signed
    /// `±mark` output can be read off directly).
    #[must_use]
    pub fn lwe_decrypt_signed(&self, lwe: &RnsLwe) -> i64 {
        let v = self.lwe_decrypt(lwe);
        if i128::from(v) > i128::from(T) / 2 {
            v - T
        } else {
            v
        }
    }

    /// Decrypt an LWE under a raw `bootstrap_key` (the destination of a
    /// key-switch): `round((b + ⟨a,key⟩)/Δ) mod t`.
    #[must_use]
    pub fn lwe_decrypt_under(bootstrap_key: &[i64], lwe: &RnsLwe) -> i64 {
        let p = RnsInt::product();
        let mut acc = lwe.b.rem_euclid(p);
        for (al, &kl) in lwe.a.iter().zip(bootstrap_key.iter()) {
            acc = (acc + al * i128::from(kl)).rem_euclid(p);
        }
        if acc > p / 2 {
            acc -= p;
        }
        let scaled = ((acc as f64) / (delta() as f64)).round() as i128;
        scaled.rem_euclid(i128::from(T)) as i64
    }
}

/// Key-switch a dim-`n_src` LWE (under the accumulator key) to a dim-`n_dst` LWE
/// (under the bootstrap key), preserving the phase.
#[must_use]
#[allow(clippy::needless_range_loop)]
pub fn lwe_keyswitch(ksk: &LweKeySwitchKey, lwe: &RnsLwe) -> RnsLwe {
    let p = RnsInt::product();
    let mut a = alloc::vec![0i128; ksk.n_dst];
    let mut b = lwe.b.rem_euclid(p);
    for l in 0..ksk.n_src {
        let digits = signed_scalar_digits(lwe.a[l]);
        for j in 0..GADGET_DIGITS {
            let d = i128::from(digits[j]);
            if d == 0 {
                continue;
            }
            let entry = &ksk.ksk[l * GADGET_DIGITS + j];
            for i in 0..ksk.n_dst {
                a[i] = (a[i] + d * entry.a[i]).rem_euclid(p);
            }
            b = (b + d * entry.b).rem_euclid(p);
        }
    }
    RnsLwe { a, b }
}

/// Test vector for the exact BlackLemon band classifier. The phase is pre-shifted
/// by `N/2` (added to the LWE body before the PBS) so the 0-band lands at `N/2`
/// and the 1-band at its negacyclic antipode `3N/2`. `mark` is placed in a window
/// of half-width `half_width` slots around `N/2`. After the bootstrap the constant
/// coefficient is `+mark` for a 0-band coefficient, `−mark` for a 1-band one
/// (the antipode flips the sign), and `0` out of band — so the sign is the
/// BlackLemon payload bit and a non-zero magnitude is the in-band indicator.
#[must_use]
pub fn band_classifier_test_vector(mark: i64, half_width: usize) -> [i64; NTT_DEGREE] {
    let center = NTT_DEGREE / 2;
    core::array::from_fn(|k| {
        if k + half_width >= center && k <= center + half_width {
            mark
        } else {
            0
        }
    })
}

/// The `N/2` phase pre-shift the band classifier expects, to be added to the
/// modulus-switched LWE body before [`programmable_bootstrap`].
pub const BAND_PHASE_SHIFT: i64 = NTT_DEGREE as i64 / 2;
