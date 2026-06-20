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
use crate::rns::{GADGET_BITS, GADGET_DIGITS, NTT_DEGREE, RnsInt, RnsPoly};

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
