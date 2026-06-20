/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Residue-number-system (RNS) integer arithmetic over an NTT-friendly prime
//! set — the integer foundation of the bootstrap accumulator redesign
//! (see blacknet-bootstrap-completion-analysis.md).
//!
//! The bootstrap accumulator must move off the LM ring to a modulus that is
//! both (a) large enough for the circuit-bootstrap fold to be sound (> 2^77) and
//! (b) NTT-friendly per limb. An RNS over several primes `p_i` with
//! `2N | p_i − 1` achieves both: the CRT product is the large modulus, and each
//! limb is independently NTT-accelerable. This module is the RNS *arithmetic*
//! (residues + CRT); the per-limb NTT fields and twiddle tables (rat4's
//! `rings.sage` territory) are the companion build that fuses with it.
//!
//! Each prime here satisfies `2048 | p − 1` (so a length-2048 negacyclic NTT
//! exists over it) and the product is `≈ 2^88 > 2^77`.

use crate::random::{Distribution, UniformGenerator, UniformIntDistribution};

/// NTT-friendly RNS limb primes: each has `2048 | p − 1`; product ≈ 2^88.
pub const RNS_PRIMES: [i64; 3] = [469762049, 754974721, 998244353];

/// An integer represented by its residues modulo each [`RNS_PRIMES`] limb.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RnsInt {
    residues: [i64; 3],
}

#[inline]
fn mulmod(a: i64, b: i64, m: i64) -> i64 {
    ((i128::from(a) * i128::from(b)).rem_euclid(i128::from(m))) as i64
}

#[inline]
fn powmod(mut a: i64, mut e: i64, m: i64) -> i64 {
    let mut r = 1i64;
    a = a.rem_euclid(m);
    while e > 0 {
        if e & 1 == 1 {
            r = mulmod(r, a, m);
        }
        a = mulmod(a, a, m);
        e >>= 1;
    }
    r
}

impl RnsInt {
    /// Decompose an integer into residues.
    #[must_use]
    pub fn from_int(x: i128) -> Self {
        RnsInt {
            residues: core::array::from_fn(|i| x.rem_euclid(i128::from(RNS_PRIMES[i])) as i64),
        }
    }

    pub fn add(&self, o: &RnsInt) -> RnsInt {
        RnsInt {
            residues: core::array::from_fn(|i| {
                (self.residues[i] + o.residues[i]).rem_euclid(RNS_PRIMES[i])
            }),
        }
    }

    pub fn sub(&self, o: &RnsInt) -> RnsInt {
        RnsInt {
            residues: core::array::from_fn(|i| {
                (self.residues[i] - o.residues[i]).rem_euclid(RNS_PRIMES[i])
            }),
        }
    }

    pub fn mul(&self, o: &RnsInt) -> RnsInt {
        RnsInt {
            residues: core::array::from_fn(|i| {
                mulmod(self.residues[i], o.residues[i], RNS_PRIMES[i])
            }),
        }
    }

    /// The CRT product modulus `P = Π p_i`.
    #[must_use]
    pub fn product() -> i128 {
        RNS_PRIMES.iter().map(|&p| i128::from(p)).product()
    }

    /// Reconstruct the represented integer in `[0, P)` via the CRT.
    #[must_use]
    pub fn to_int(&self) -> i128 {
        let p = Self::product();
        let mut acc: i128 = 0;
        for (&prime, &residue) in RNS_PRIMES.iter().zip(self.residues.iter()) {
            let pi = i128::from(prime);
            let mi = p / pi; // Π_{j≠i} p_j
            // inverse of mi modulo pi (pi prime -> Fermat): (mi mod pi)^(pi-2)
            let mi_mod = (mi.rem_euclid(pi)) as i64;
            let inv = powmod(mi_mod, prime - 2, prime);
            // term = residue_i * mi * inv  (mod P), built carefully to fit i128
            let coeff = (mi.rem_euclid(p) * i128::from(inv)).rem_euclid(p);
            let term = (coeff * i128::from(residue)).rem_euclid(p);
            acc = (acc + term).rem_euclid(p);
        }
        acc
    }
}

// ===========================================================================
// NTT-accelerated negacyclic polynomial multiplication over the RNS basis.
//
// This is the arithmetic core of the redesigned bootstrap accumulator: degree-N
// negacyclic multiplication (the dominant cost of blind rotation) done in
// O(N log N) per limb via the number-theoretic transform, then recombined by
// the CRT to give a product modulo P ≈ 2^88 — large enough for the
// circuit-bootstrap fold's soundness AND fast, the single change the
// completion analysis calls for.
//
// It is deliberately self-contained (its own roots and transform), so its
// correctness is established entirely by the `== schoolbook` tests rather than
// by matching any external twiddle convention. The root finder verifies
// ψ^N = −1 (a genuine negacyclic root) rather than assuming a generator.

/// Accumulator ring degree (negacyclic, X^N + 1).
pub const NTT_DEGREE: usize = 1024;

/// Gadget base exponent and digit count for the external product:
/// `B = 2^GADGET_BITS`, `B^GADGET_DIGITS = 2^92 > P`.
pub const GADGET_BITS: u32 = 23;
pub const GADGET_DIGITS: usize = 4;

#[inline]
fn inv_mod(a: i64, p: i64) -> i64 {
    powmod(a, p - 2, p) // p prime
}

/// A primitive `2N`-th root of unity modulo `p` (so `ψ^N = −1`): the twist for
/// negacyclic NTT. Searches small bases and *verifies* the order rather than
/// assuming a generator.
fn negacyclic_root(p: i64) -> i64 {
    let exp = (p - 1) / (2 * NTT_DEGREE as i64);
    for h in 2..1000i64 {
        let psi = powmod(h, exp, p);
        if powmod(psi, NTT_DEGREE as i64, p) == p - 1 {
            return psi;
        }
    }
    panic!("no negacyclic root found for prime {p}");
}

/// In-place iterative radix-2 NTT of length `NTT_DEGREE` with `root` a primitive
/// `N`-th root of unity mod `p`.
fn ntt_inplace(a: &mut [i64; NTT_DEGREE], root: i64, p: i64) {
    let n = NTT_DEGREE;
    // bit-reversal permutation
    let bits = n.trailing_zeros();
    for i in 0..n {
        let j = (i as u32).reverse_bits() >> (32 - bits);
        let j = j as usize;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let wlen = powmod(root, (n / len) as i64, p);
        let mut i = 0;
        while i < n {
            let mut w = 1i64;
            for j in 0..len / 2 {
                let u = a[i + j];
                let v = mulmod(a[i + j + len / 2], w, p);
                a[i + j] = (u + v).rem_euclid(p);
                a[i + j + len / 2] = (u - v).rem_euclid(p);
                w = mulmod(w, wlen, p);
            }
            i += len;
        }
        len <<= 1;
    }
}

/// Negacyclic convolution `a * b mod (X^N + 1, p)` via NTT: ψ-weight, length-N
/// cyclic NTT, pointwise product, inverse NTT, ψ-unweight.
fn negacyclic_mul_mod(a: &[i64; NTT_DEGREE], b: &[i64; NTT_DEGREE], p: i64) -> [i64; NTT_DEGREE] {
    let n = NTT_DEGREE;
    let psi = negacyclic_root(p);
    let psi_inv = inv_mod(psi, p);
    let omega = mulmod(psi, psi, p); // N-th root
    let omega_inv = inv_mod(omega, p);
    let n_inv = inv_mod(n as i64, p);

    let mut fa = [0i64; NTT_DEGREE];
    let mut fb = [0i64; NTT_DEGREE];
    let mut psi_pow = 1i64;
    for i in 0..n {
        fa[i] = mulmod(a[i].rem_euclid(p), psi_pow, p);
        fb[i] = mulmod(b[i].rem_euclid(p), psi_pow, p);
        psi_pow = mulmod(psi_pow, psi, p);
    }
    ntt_inplace(&mut fa, omega, p);
    ntt_inplace(&mut fb, omega, p);
    let mut fc: [i64; NTT_DEGREE] = core::array::from_fn(|k| mulmod(fa[k], fb[k], p));
    ntt_inplace(&mut fc, omega_inv, p);

    let mut psi_inv_pow = 1i64;
    let mut out = [0i64; NTT_DEGREE];
    for i in 0..n {
        let scaled = mulmod(fc[i], n_inv, p);
        out[i] = mulmod(scaled, psi_inv_pow, p);
        psi_inv_pow = mulmod(psi_inv_pow, psi_inv, p);
    }
    out
}

/// A degree-`NTT_DEGREE` polynomial in the RNS basis: one residue vector per
/// limb. The accumulator's element type.
#[derive(Clone)]
pub struct RnsPoly {
    limbs: [[i64; NTT_DEGREE]; 3],
}

impl RnsPoly {
    /// Decompose integer coefficients into the RNS basis.
    #[must_use]
    pub fn from_coefficients(coeffs: &[i128; NTT_DEGREE]) -> Self {
        RnsPoly {
            limbs: core::array::from_fn(|l| {
                let p = i128::from(RNS_PRIMES[l]);
                core::array::from_fn(|i| coeffs[i].rem_euclid(p) as i64)
            }),
        }
    }

    /// NTT-accelerated negacyclic product, per limb.
    #[must_use]
    pub fn negacyclic_mul(&self, other: &RnsPoly) -> RnsPoly {
        RnsPoly {
            limbs: core::array::from_fn(|l| {
                negacyclic_mul_mod(&self.limbs[l], &other.limbs[l], RNS_PRIMES[l])
            }),
        }
    }

    /// Reconstruct the coefficient at `index` in `[0, P)` via the CRT.
    #[must_use]
    pub fn coefficient(&self, index: usize) -> i128 {
        let residues = core::array::from_fn(|l| self.limbs[l][index]);
        RnsInt { residues }.to_int()
    }

    /// The balanced (centered in `(−P/2, P/2]`) coefficient at `index`.
    #[must_use]
    pub fn balanced_coefficient(&self, index: usize) -> i128 {
        let p = RnsInt::product();
        let c = self.coefficient(index);
        if c > p / 2 { c - p } else { c }
    }

    /// The zero polynomial.
    #[must_use]
    pub const fn zero() -> Self {
        RnsPoly {
            limbs: [[0; NTT_DEGREE]; 3],
        }
    }

    /// Coefficient-wise sum.
    #[must_use]
    pub fn add(&self, other: &RnsPoly) -> RnsPoly {
        RnsPoly {
            limbs: core::array::from_fn(|l| {
                let p = RNS_PRIMES[l];
                core::array::from_fn(|i| (self.limbs[l][i] + other.limbs[l][i]).rem_euclid(p))
            }),
        }
    }

    /// Coefficient-wise difference.
    #[must_use]
    pub fn sub(&self, other: &RnsPoly) -> RnsPoly {
        RnsPoly {
            limbs: core::array::from_fn(|l| {
                let p = RNS_PRIMES[l];
                core::array::from_fn(|i| (self.limbs[l][i] - other.limbs[l][i]).rem_euclid(p))
            }),
        }
    }

    /// A polynomial with every coefficient drawn independently and uniformly
    /// from `[0, p)` per limb (a uniform element of the RNS ring).
    pub fn uniform<R: UniformGenerator<Output = u8>>(rng: &mut R) -> Self {
        RnsPoly {
            limbs: core::array::from_fn(|l| {
                let mut uid = UniformIntDistribution::<i64, R>::new(0..RNS_PRIMES[l]);
                core::array::from_fn(|_| uid.sample(rng))
            }),
        }
    }

    /// A polynomial whose integer coefficients are drawn from `[-bound, bound]`
    /// (small error or ternary secret), embedded into every limb.
    pub fn small<R: UniformGenerator<Output = u8>>(rng: &mut R, bound: i64) -> Self {
        let mut sid = UniformIntDistribution::<i64, R>::new(-bound..=bound);
        let coeffs: [i64; NTT_DEGREE] = core::array::from_fn(|_| sid.sample(rng));
        RnsPoly {
            limbs: core::array::from_fn(|l| {
                let p = RNS_PRIMES[l];
                core::array::from_fn(|i| coeffs[i].rem_euclid(p))
            }),
        }
    }

    /// Embed integer plaintext coefficients scaled by `delta` into the ring.
    #[must_use]
    pub fn scale_plaintext(m: &[i64; NTT_DEGREE], delta: i128) -> Self {
        RnsPoly {
            limbs: core::array::from_fn(|l| {
                let p = i128::from(RNS_PRIMES[l]);
                core::array::from_fn(|i| (delta * i128::from(m[i])).rem_euclid(p) as i64)
            }),
        }
    }

    /// Embed (possibly negative) integer coefficients into every limb.
    #[must_use]
    pub fn from_balanced(coeffs: &[i64; NTT_DEGREE]) -> Self {
        RnsPoly {
            limbs: core::array::from_fn(|l| {
                let p = RNS_PRIMES[l];
                core::array::from_fn(|i| coeffs[i].rem_euclid(p))
            }),
        }
    }

    /// A constant polynomial (degree 0) with the given integer value.
    #[must_use]
    pub fn constant(value: i128) -> Self {
        RnsPoly {
            limbs: core::array::from_fn(|l| {
                let p = i128::from(RNS_PRIMES[l]);
                let mut row = [0i64; NTT_DEGREE];
                row[0] = value.rem_euclid(p) as i64;
                row
            }),
        }
    }

    /// Signed gadget decomposition into [`GADGET_DIGITS`] base-`2^GADGET_BITS`
    /// digit polynomials with coefficients in `(−B/2, B/2]`, such that
    /// `Σ digitᵢ · Bⁱ ≡ self (mod P)`. The decomposition the external product
    /// applies to keep multiplier coefficients small.
    #[must_use]
    pub fn gadget_decompose(&self) -> [RnsPoly; GADGET_DIGITS] {
        let base: i128 = 1i128 << GADGET_BITS;
        let mut digit_coeffs = [[0i64; NTT_DEGREE]; GADGET_DIGITS];
        for j in 0..NTT_DEGREE {
            let mut x = self.balanced_coefficient(j);
            for d in digit_coeffs.iter_mut() {
                let mut r = x.rem_euclid(base);
                if r > base / 2 {
                    r -= base;
                }
                d[j] = r as i64;
                x = (x - r) / base;
            }
        }
        core::array::from_fn(|d| RnsPoly::from_balanced(&digit_coeffs[d]))
    }
}
