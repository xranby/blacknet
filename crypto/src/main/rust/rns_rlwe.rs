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

use crate::random::UniformGenerator;
use crate::rns::{NTT_DEGREE, RnsInt, RnsPoly};

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
