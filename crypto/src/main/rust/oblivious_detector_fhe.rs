/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! An oblivious detection backend: the homomorphic-decryption step of OMR,
//! implemented for real over BlackLemon clues.
//!
//! This is the FHE backend the `oblivious_retrieval` module leaves as a slot.
//! It implements the part of Oblivious Message Retrieval that *can* be done
//! with a leveled homomorphic scheme and a sound noise budget — and is honest
//! about the part that cannot.
//!
//! ## What this does (correctly, obliviously)
//!
//! BlackLemon's `detect` computes a linear decryption value
//! `d = ct.a + ct.b·s + sk.b` over the clue ring (mod `q = 65537`, degree
//! `D = 1024`), then range-checks `d`'s coefficients to decide pertinence. The
//! linear step is what a detector can evaluate *without learning the secret*:
//!
//!   * the client encrypts its detection material `(s, sk.b)` under a leveled
//!     RLWE scheme ([`Rlwe`]) and sends the ciphertext as the detection key;
//!   * the detector, holding only public clue parts `(ct.a, ct.b)` and the
//!     encrypted key, computes `Enc(d) = ct.a + ct.b ⊛ Enc(s) + Enc(sk.b)`
//!     using homomorphic add and plaintext-polynomial multiplication (the RLWE
//!     operations the InstantOMR paper calls "RLWE plaintext multiplication");
//!   * the client decrypts `Enc(d)` and runs the exact BlackLemon range check.
//!
//! The detector never sees `s`, `sk.b`, `d`, or which clues are pertinent — it
//! performs the identical computation on every clue and outputs only RLWE
//! ciphertexts, which are semantically secure. That is the obliviousness OMR
//! requires for this step.
//!
//! ## What this does NOT do (and why)
//!
//! 1. **The pertinence range-check is not homomorphic here.** Deciding
//!    pertinence from `d` is the non-linear step (absolute value + comparison).
//!    Doing it *under encryption*, so the detector can return a compressed
//!    pertinent-only digest, requires functional bootstrapping (TFHE) — the
//!    core of InstantOMR (ePrint 2025/2317), a substantial separate effort.
//!    Here the client finishes the check after decrypting `Enc(d)`. The
//!    consequence, stated plainly: this backend is *oblivious* but not yet
//!    *bandwidth-lite* — it returns one encrypted `d` per scanned clue rather
//!    than a small pertinent-only digest. Bootstrapping is what closes that gap.
//!
//! 2. **The parameters are for correctness, not 128-bit security.** `Rlwe`
//!    uses a 54-bit modulus sized so the depth-1 decryption circuit decrypts
//!    correctly (the noise budget is real and respected — see the tests). It is
//!    NOT a security-analyzed parameter set; a production deployment needs a
//!    parameter set with a concrete security argument.
//!
//! The scheme is self-contained (its own modular arithmetic) so its
//! correctness does not depend on, and cannot silently break, the consensus
//! lattice code.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::blacklemon::{self, DetectionMaterial, detect_params};
use crate::oblivious_retrieval::Clue;
use crate::random::UniformGenerator;

const N: usize = detect_params::D; // 1024, the clue ring degree
const T: i128 = detect_params::Q as i128; // 65537, plaintext modulus
/// 54-bit ciphertext modulus. Power of two so reduction is a mask; not NTT-
/// friendly, which is fine — multiplication here is schoolbook negacyclic.
const LOG_Q: u32 = 54;
const Q: i128 = 1i128 << LOG_Q;
/// Scaling factor Δ = ⌊Q/t⌋. A plaintext coefficient `m` is carried as `Δ·m`.
const DELTA: i128 = Q / T;

/// Reduce to the balanced range (−Q/2, Q/2].
#[inline]
fn center(x: i128) -> i128 {
    let r = x.rem_euclid(Q);
    if r > Q / 2 { r - Q } else { r }
}

/// A polynomial in `Z_Q[X]/(X^N+1)`, coefficients balanced around zero.
#[derive(Clone)]
struct Poly(Vec<i128>);

impl Poly {
    fn add(&self, o: &Poly) -> Poly {
        Poly((0..N).map(|i| center(self.0[i] + o.0[i])).collect())
    }

    fn sub(&self, o: &Poly) -> Poly {
        Poly((0..N).map(|i| center(self.0[i] - o.0[i])).collect())
    }

    /// Negacyclic product `self · rhs` in `Z_Q[X]/(X^N+1)`.
    fn mul(&self, rhs: &Poly) -> Poly {
        let mut acc = vec![0i128; N];
        for i in 0..N {
            let xi = self.0[i];
            if xi == 0 {
                continue;
            }
            for j in 0..N {
                let prod = xi * rhs.0[j];
                let k = i + j;
                if k < N {
                    acc[k] = center(acc[k] + prod);
                } else {
                    acc[k - N] = center(acc[k - N] - prod); // X^N = -1
                }
            }
        }
        Poly(acc)
    }
}

/// A leveled RLWE (BFV-style, symmetric-key) ciphertext: `(a, b)` with
/// `b = a·s + Δ·m + e`, decrypting via `b − a·s`.
#[derive(Clone)]
pub struct Ct {
    a: Poly,
    b: Poly,
}

/// A leveled RLWE secret key — the client's; used to encrypt the detection
/// material and to decrypt the recovered `d`.
pub struct Rlwe {
    s: Poly,
}

impl Rlwe {
    /// Generate a key with a ternary secret.
    pub fn keygen<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Self {
        let s = Poly((0..N).map(|_| i128::from(rng.generate() % 3) - 1).collect());
        Rlwe { s }
    }

    fn uniform_poly<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Poly {
        Poly(
            (0..N)
                .map(|_| {
                    let mut v = 0i128;
                    for _ in 0..7 {
                        v = (v << 8) | i128::from(rng.generate());
                    }
                    center(v)
                })
                .collect(),
        )
    }

    /// Small centered error in [−B, B], B small relative to Δ.
    fn error_poly<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Poly {
        Poly(
            (0..N)
                .map(|_| i128::from(rng.generate() % 17) - 8) // [-8,8]
                .collect(),
        )
    }

    /// Encrypt a plaintext polynomial (coefficients in `Z_t`, given as i128).
    fn encrypt<R: UniformGenerator<Output = u8>>(&self, rng: &mut R, m: &[i128]) -> Ct {
        let a = Self::uniform_poly(rng);
        let e = Self::error_poly(rng);
        let mut b = a.mul(&self.s);
        for i in 0..N {
            b.0[i] = center(b.0[i] + DELTA * m[i] + e.0[i]);
        }
        Ct { a, b }
    }

    /// Decrypt to plaintext coefficients in the balanced range of `Z_t`.
    fn decrypt(&self, ct: &Ct) -> Vec<i32> {
        let v = ct.b.sub(&ct.a.mul(&self.s));
        (0..N)
            .map(|i| {
                // round(v/Δ) mod t, balanced
                let q = (v.0[i] as f64 / DELTA as f64).round() as i128;
                let m = q.rem_euclid(T);
                if m > T / 2 { (m - T) as i32 } else { m as i32 }
            })
            .collect()
    }
}

/// Homomorphic ops the detector uses — all linear, no bootstrapping.
impl Ct {
    fn add(&self, o: &Ct) -> Ct {
        Ct {
            a: self.a.add(&o.a),
            b: self.b.add(&o.b),
        }
    }

    /// Multiply by a public plaintext polynomial `p` (coeffs as integers):
    /// `(p⊛a, p⊛b)`. Decrypts to `p⊛m`, noise scaled by `‖p‖`.
    fn plain_mul(&self, p: &Poly) -> Ct {
        Ct {
            a: p.mul(&self.a),
            b: p.mul(&self.b),
        }
    }

    /// Add a public plaintext constant polynomial `k`: `(a, b + Δ·k)`.
    fn add_plain(&self, k: &[i128]) -> Ct {
        let mut b = self.b.clone();
        for i in 0..N {
            b.0[i] = center(b.0[i] + DELTA * k[i]);
        }
        Ct {
            a: self.a.clone(),
            b,
        }
    }
}

/// The client's detection key: its detection material encrypted under RLWE.
/// The detector treats this opaquely.
pub struct EncryptedDetectionKey {
    enc_secret: Ct,
    enc_offset: Ct,
}

/// Build an encrypted detection key from BlackLemon detection material. Run by
/// the client; the resulting key reveals nothing about the secret.
pub fn encrypt_detection_key<R: UniformGenerator<Output = u8>>(
    rng: &mut R,
    rlwe: &Rlwe,
    material: &DetectionMaterial,
) -> EncryptedDetectionKey {
    let s: Vec<i128> = material.secret.iter().map(|&x| i128::from(x)).collect();
    let off: Vec<i128> = material.offset.iter().map(|&x| i128::from(x)).collect();
    EncryptedDetectionKey {
        enc_secret: rlwe.encrypt(rng, &s),
        enc_offset: rlwe.encrypt(rng, &off),
    }
}

/// The detector's oblivious step: from the encrypted key and a clue's public
/// parts, compute `Enc(d)` where `d = ct.a + ct.b·s + sk.b`. Learns nothing.
#[must_use]
pub fn homomorphic_decrypt(key: &EncryptedDetectionKey, clue: &Clue) -> Ct {
    let (a, b) = blacklemon::clue_public_parts(clue);
    let a_i: Vec<i128> = a.iter().map(|&x| i128::from(x)).collect();
    let b_poly = Poly(b.iter().map(|&x| i128::from(x)).collect());
    // ct.b ⊛ Enc(s) + Enc(sk.b), then + ct.a (public constant).
    key.enc_secret
        .plain_mul(&b_poly)
        .add(&key.enc_offset)
        .add_plain(&a_i)
}

/// The client decrypts `Enc(d)` and runs BlackLemon's exact pertinence check.
/// Returns whether the clue is pertinent (matching `blacklemon::detect`).
#[must_use]
pub fn client_check_pertinence(rlwe: &Rlwe, enc_d: &Ct) -> bool {
    let d = rlwe.decrypt(enc_d);
    let r = detect_params::R;
    let delta = detect_params::DELTA;
    for &coeff in &d {
        let abs = coeff.abs();
        let near_zero = abs <= r;
        let near_delta = (delta - abs).abs() <= r;
        if !(near_zero || near_delta) {
            return false;
        }
    }
    // Leading KAPPA coefficients must round to zero (the pertinence flag).
    for &coeff in d.iter().take(detect_params::KAPPA) {
        if coeff.abs() > r {
            return false;
        }
    }
    true
}

/// Convenience: the recovered balanced coefficients of `d` (for tests/audit).
#[must_use]
pub fn recover_d(rlwe: &Rlwe, enc_d: &Ct) -> Vec<i32> {
    rlwe.decrypt(enc_d)
}

/// An oblivious scan over a board: for each clue, compute `Enc(d)`. The
/// detector returns these (it cannot compress to pertinent-only without the
/// bootstrapped check). Uniform over all clues — no data-dependent branching.
#[must_use]
pub fn oblivious_scan(key: &EncryptedDetectionKey, board: &[Clue]) -> Vec<Ct> {
    board.iter().map(|c| homomorphic_decrypt(key, c)).collect()
}
