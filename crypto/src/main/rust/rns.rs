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
        for i in 0..3 {
            let pi = i128::from(RNS_PRIMES[i]);
            let mi = p / pi; // Π_{j≠i} p_j
            // inverse of mi modulo pi (pi prime -> Fermat): (mi mod pi)^(pi-2)
            let mi_mod = (mi.rem_euclid(pi)) as i64;
            let inv = powmod(mi_mod, RNS_PRIMES[i] - 2, RNS_PRIMES[i]);
            // term = residue_i * mi * inv  (mod P), built carefully to fit i128
            let coeff = (mi.rem_euclid(p) * i128::from(inv)).rem_euclid(p);
            let term = (coeff * i128::from(self.residues[i])).rem_euclid(p);
            acc = (acc + term).rem_euclid(p);
        }
        acc
    }
}
