/*
 * Copyright (c) 2024-2026 Pavel Vasin
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

use crate::algebra::{IntegerRing, One, Zero};
use crate::lpr;
use crate::random::UniformGenerator;
use zeroize::Zeroize;

// https://blacknet.ninja/blacklemon.pdf

const KAPPA: usize = 2;
#[expect(dead_code)]
const ELL: usize = lpr::D;
const R: <lpr::Zq as IntegerRing>::Int = 40;

#[derive(Zeroize)]
pub struct SecretKey {
    a: lpr::SecretKey,
    b: lpr::RqNTT,
}

pub struct PublicKey {
    a: lpr::PublicKey,
    b: lpr::RqNTT,
}

pub type CipherText = lpr::CipherText;

pub type PlainText = lpr::PlainText;

pub fn generate_secret_key<RNG: UniformGenerator<Output = u8>>(rng: &mut RNG) -> SecretKey {
    SecretKey {
        a: lpr::generate_secret_key(rng),
        b: lpr::generate_uniform(rng),
    }
}

pub fn generate_public_key<RNG: UniformGenerator<Output = u8>>(
    rng: &mut RNG,
    sk: &SecretKey,
) -> PublicKey {
    PublicKey {
        a: lpr::generate_public_key(rng, &sk.a),
        b: -sk.b,
    }
}

pub fn encrypt<RNG: UniformGenerator<Output = u8>>(
    rng: &mut RNG,
    pk: &PublicKey,
    pt: &PlainText,
) -> CipherText {
    let mut ct = lpr::encrypt(rng, &pk.a, pt);
    ct.a += pk.b;
    ct
}

pub fn decrypt(sk: &SecretKey, ct: &CipherText) -> PlainText {
    let ct = CipherText {
        a: ct.a + sk.b,
        b: ct.b,
    };
    lpr::decrypt(&sk.a, &ct)
}

pub fn detect(sk: &SecretKey, ct: &CipherText) -> Option<PlainText> {
    let mut m = lpr::Rt::ZERO;
    let d = ct.a + ct.b * sk.a.s + sk.b;
    let coefficients = lpr::Rq::from(d);
    for i in 0..lpr::D {
        if coefficients[i].absolute() <= R {
            m[i] = lpr::Zt::ZERO;
        } else if lpr::DELTA - coefficients[i].absolute() <= R {
            m[i] = lpr::Zt::ONE;
        } else {
            return None;
        }
    }
    if (&m)
        .into_iter()
        .take(KAPPA)
        .any(|coefficient| *coefficient != lpr::Zt::ZERO)
    {
        return None;
    }
    Some(PlainText { m })
}

/// Coefficient-form detection material derived from a recipient's own secret
/// key, for building an *outsourced* (oblivious) detection key.
///
/// This is the recipient-side input to an FHE detection key: the recipient
/// encrypts this material under a leveled homomorphic scheme and hands the
/// ciphertext to a detector, which then evaluates [`detect`]'s linear
/// decryption step homomorphically without learning the secret (see
/// `oblivious_retrieval`). It mirrors OMR's setup, where the recipient
/// publishes `FHE.Enc(sk)` as the detection key.
///
/// It exposes secret coefficients in the clear and MUST stay client-side; it
/// exists only so the client can derive its own detection key.
#[derive(Zeroize)]
pub struct DetectionMaterial {
    /// Coefficients of the LWE secret `s` (the `ct.b · s` multiplier in detect).
    pub secret: [i32; lpr::D],
    /// Coefficients of `sk.b` (the additive term in detect).
    pub offset: [i32; lpr::D],
}

/// Derives the [`DetectionMaterial`] from a secret key. Reveals secret
/// coefficients; keep the result client-side.
#[must_use]
pub fn detection_material(sk: &SecretKey) -> DetectionMaterial {
    use crate::algebra::IntegerRing;
    let s_coeffs = lpr::Rq::from(sk.a.s);
    let b_coeffs = lpr::Rq::from(sk.b);
    DetectionMaterial {
        secret: core::array::from_fn(|i| s_coeffs[i].canonical()),
        offset: core::array::from_fn(|i| b_coeffs[i].canonical()),
    }
}

/// Coefficient-form view of a clue's public ring elements `(ct.a, ct.b)`, the
/// public inputs a detector needs to evaluate [`detect`]'s linear step. No
/// secret content.
#[must_use]
pub fn clue_public_parts(ct: &CipherText) -> ([i32; lpr::D], [i32; lpr::D]) {
    use crate::algebra::IntegerRing;
    let a = lpr::Rq::from(ct.a);
    let b = lpr::Rq::from(ct.b);
    (
        core::array::from_fn(|i| a[i].canonical()),
        core::array::from_fn(|i| b[i].canonical()),
    )
}

/// The detection modulus and per-coefficient tolerance, exposed so an
/// outsourced detector can apply the exact same pertinence check [`detect`]
/// uses, on a homomorphically-recovered `d`.
pub mod detect_params {
    use super::lpr;
    /// Plaintext modulus of the clue ring (`d` lives mod this).
    pub const Q: i32 = <lpr::Zq as crate::algebra::IntegerRing>::MODULUS;
    /// Half-modulus, the "one" target in the rounding check.
    pub const DELTA: i32 = lpr::DELTA;
    /// Per-coefficient tolerance.
    pub const R: i32 = super::R;
    /// Ring degree.
    pub const D: usize = lpr::D;
    /// Number of leading coefficients that must round to zero (pertinence flag).
    pub const KAPPA: usize = super::KAPPA;
}
