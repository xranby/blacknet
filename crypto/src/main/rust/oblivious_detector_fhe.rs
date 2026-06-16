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
    for &coeff in &d {
        let abs = coeff.abs();
        if !(abs <= r || (delta - abs).abs() <= r) {
            return false;
        }
    }
    for &coeff in d.iter().take(detect_params::KAPPA) {
        if coeff.abs() > r {
            return false;
        }
    }
    true
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
