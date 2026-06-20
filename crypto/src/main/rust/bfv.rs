/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! BFV ciphertext multiplication — the connector that makes OMR compaction
//! oblivious with a *ciphertext* pertinence bit (not a supplied RGSW).
//!
//! Finding from "wire and assemble": a circuit-bootstrap RGSW uses a coarse
//! gadget (PBS can only emit Δ-multiples), which resolves only down to Δ and so
//! loses the uniform mask of a message-bearing ciphertext — its recomposition
//! error (~2^81) dwarfs the message scale (~2^72). Therefore `PV · payload`
//! cannot be done by an RGSW external product on an obliviously-produced `PV`;
//! it must be a BFV ciphertext×ciphertext multiplication.
//!
//! This module implements that multiplication soundly at a single-prime modulus
//! (`P ≈ 2^60`, degree 64, plaintext modulus 257) where the tensor product fits
//! `i128`, so no RNS basis extension
//! is needed. For a single multiplication the result is kept as a degree-2
//! ciphertext (decrypted with `s²`), so relinearization is unnecessary. The
//! oblivious compaction (PV masking + bucketing + recovery) is assembled and
//! verified on top. At the bootstrap's 2^88 modulus the same multiply needs an
//! RNS basis extension for the rescale — the documented production task; the
//! algorithm and its correctness are what this establishes.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::missing_const_for_fn)]

extern crate alloc;
use alloc::vec::Vec;

use crate::random::{Distribution, UniformGenerator, UniformIntDistribution};

/// Demonstration degree (the OMR payload length here).
pub const NB: usize = 64;
/// Single-prime ciphertext modulus (≈ 2^60; tensor coeff < 2^124 fits i128).
pub const QB: i128 = 1_152_921_504_606_846_883;
/// Plaintext modulus.
pub const TB: i128 = 257;

#[inline]
fn delta() -> i128 {
    QB / TB
}

type Poly = [i128; NB];

fn add(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| (a[i] + b[i]).rem_euclid(QB))
}

fn sub(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| (a[i] - b[i]).rem_euclid(QB))
}

/// Negacyclic schoolbook product mod `QB`.
fn mul(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i128; NB];
    for i in 0..NB {
        if a[i] == 0 {
            continue;
        }
        for j in 0..NB {
            let mut k = i + j;
            let mut prod = (a[i] * b[j]).rem_euclid(QB);
            if k >= NB {
                k -= NB;
                prod = (-prod).rem_euclid(QB);
            }
            out[k] = (out[k] + prod).rem_euclid(QB);
        }
    }
    out
}

fn balanced(x: i128) -> i128 {
    let v = x.rem_euclid(QB);
    if v > QB / 2 { v - QB } else { v }
}

/// A BFV secret key (ternary).
pub struct Bfv {
    s: Poly,
    s2: Poly,
}

/// A degree-1 ciphertext `(c0, c1)` with `c0 + c1·s = Δ·m + e`.
#[derive(Clone)]
pub struct Ct {
    c0: Poly,
    c1: Poly,
}

/// A degree-2 ciphertext `(d0, d1, d2)` with `d0 + d1·s + d2·s² = Δ·m + e`
/// (the product of two degree-1 ciphertexts, before relinearization).
#[derive(Clone)]
pub struct Ct2 {
    d0: Poly,
    d1: Poly,
    d2: Poly,
}

impl Bfv {
    pub fn keygen<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Self {
        let mut tern = UniformIntDistribution::<i64, R>::new(-1..=1);
        let s: Poly = core::array::from_fn(|_| i128::from(tern.sample(rng)));
        let s2 = mul(&s, &s);
        Bfv { s, s2 }
    }

    fn uniform<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Poly {
        let mut uid = UniformIntDistribution::<i64, R>::new(0..(QB as i64));
        core::array::from_fn(|_| i128::from(uid.sample(rng)))
    }

    fn error<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Poly {
        let mut eid = UniformIntDistribution::<i64, R>::new(-1..=1);
        core::array::from_fn(|_| i128::from(eid.sample(rng)))
    }

    /// Encrypt plaintext coefficients (`m ∈ [0,t)`): `c1 = a`, `c0 = Δm + e − a·s`.
    pub fn encrypt<R: UniformGenerator<Output = u8>>(&self, rng: &mut R, m: &[i128; NB]) -> Ct {
        let a = Self::uniform(rng);
        let e = Self::error(rng);
        let scaled: Poly = core::array::from_fn(|i| (delta() * m[i]).rem_euclid(QB));
        let c0 = sub(&add(&scaled, &e), &mul(&a, &self.s));
        Ct { c0, c1: a }
    }

    fn decode(&self, phase: &Poly) -> [i128; NB] {
        core::array::from_fn(|i| {
            let v = balanced(phase[i]);
            let q = ((v as f64) / (delta() as f64)).round() as i128;
            q.rem_euclid(TB)
        })
    }

    /// Decrypt a degree-1 ciphertext.
    #[must_use]
    pub fn decrypt(&self, ct: &Ct) -> [i128; NB] {
        let phase = add(&ct.c0, &mul(&ct.c1, &self.s));
        self.decode(&phase)
    }

    /// Decrypt a degree-2 ciphertext (the product form).
    #[must_use]
    pub fn decrypt2(&self, ct: &Ct2) -> [i128; NB] {
        let phase = add(&add(&ct.d0, &mul(&ct.d1, &self.s)), &mul(&ct.d2, &self.s2));
        self.decode(&phase)
    }
}

/// Multiply a ciphertext by a cleartext scalar (applied per coefficient).
#[must_use]
pub fn scalar_mul2(ct: &Ct2, w: i128) -> Ct2 {
    Ct2 {
        d0: core::array::from_fn(|i| (ct.d0[i] * w).rem_euclid(QB)),
        d1: core::array::from_fn(|i| (ct.d1[i] * w).rem_euclid(QB)),
        d2: core::array::from_fn(|i| (ct.d2[i] * w).rem_euclid(QB)),
    }
}

fn add2(a: &Ct2, b: &Ct2) -> Ct2 {
    Ct2 {
        d0: add(&a.d0, &b.d0),
        d1: add(&a.d1, &b.d1),
        d2: add(&a.d2, &b.d2),
    }
}

/// BFV ciphertext×ciphertext multiplication. Computes the tensor product over
/// the integers (fits i128 at this modulus), divides by Δ with rounding, and
/// returns the degree-2 result encrypting `m1·m2`.
#[must_use]
pub fn bfv_mul(x: &Ct, y: &Ct) -> Ct2 {
    // exact tensor (integer), via negacyclic convolution without mod reduction
    let conv = |a: &Poly, b: &Poly| -> [i128; NB] {
        let mut out = [0i128; NB];
        for i in 0..NB {
            for j in 0..NB {
                let mut k = i + j;
                let mut prod = balanced(a[i]) * balanced(b[j]);
                if k >= NB {
                    k -= NB;
                    prod = -prod;
                }
                out[k] += prod;
            }
        }
        out
    };
    let t00 = conv(&x.c0, &y.c0);
    let t01 = conv(&x.c0, &y.c1);
    let t10 = conv(&x.c1, &y.c0);
    let t11 = conv(&x.c1, &y.c1);

    let d = delta();
    let _ = d;
    // BFV rescale: round(v · t / QB). v is huge (~QB²·N), so v/Δ is NOT a valid
    // approximation; compute v·t/QB exactly via q·t + round(r·t/QB) to avoid
    // both the 1/Δ-vs-t/QB error and i128 overflow of v·t.
    let rescale = |v: i128| -> i128 {
        let q = v.div_euclid(QB);
        let r = v.rem_euclid(QB); // [0, QB)
        let frac = (r * TB + QB / 2) / QB; // round(r·t/QB), r·t < 2^72 fits i128
        (q * TB + frac).rem_euclid(QB)
    };
    Ct2 {
        d0: core::array::from_fn(|i| rescale(t00[i])),
        d1: core::array::from_fn(|i| rescale(t01[i] + t10[i])),
        d2: core::array::from_fn(|i| rescale(t11[i])),
    }
}

// ---- oblivious bandwidth-lite compaction via BFV multiply ------------------

/// Homomorphic, oblivious compaction with an ENCRYPTED pertinence bit:
/// `bucketⱼ = Σᵢ PVᵢ · W[j][i] · payloadᵢ`, each term a BFV multiply of the
/// encrypted pertinence by the (scalar-weighted) encrypted payload. The node
/// holds `Enc(PV)` and `Enc(payload)` only — it learns neither which messages
/// match nor their contents. Output: `m` degree-2 bucket ciphertexts.
#[must_use]
pub fn compact_buckets(pv: &[Ct], payloads: &[Ct], weights: &[Vec<i128>]) -> Vec<Ct2> {
    weights
        .iter()
        .map(|wrow| {
            let mut acc: Option<Ct2> = None;
            for ((pvi, payload), &w) in pv.iter().zip(payloads.iter()).zip(wrow.iter()) {
                let term = scalar_mul2(&bfv_mul(pvi, payload), w);
                acc = Some(match acc {
                    Some(a) => add2(&a, &term),
                    None => term,
                });
            }
            acc.expect("at least one message")
        })
        .collect()
}
