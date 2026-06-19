/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! RNS arithmetic verified against exact integer arithmetic mod P.

use blacknet_crypto::rns::{RNS_PRIMES, RnsInt};

#[test]
fn primes_are_ntt_friendly_and_large_enough() {
    // Each limb supports a length-2048 negacyclic NTT (2048 | p-1), and the
    // product exceeds the 2^77 the circuit-bootstrap fold's soundness needs.
    for &p in &RNS_PRIMES {
        assert_eq!((p - 1) % 2048, 0, "prime {p} must satisfy 2048 | p-1");
    }
    let product = RnsInt::product();
    assert!(product > (1i128 << 77), "CRT product must exceed 2^77");
    assert!(product < (1i128 << 90), "product ~2^88 as expected");
}

#[test]
fn crt_roundtrip() {
    let p = RnsInt::product();
    for &x in &[0i128, 1, 12345, 1 << 40, (1i128 << 80) + 7, p - 1] {
        let r = RnsInt::from_int(x);
        assert_eq!(r.to_int(), x.rem_euclid(p), "CRT round-trip for {x}");
    }
}

#[test]
fn add_matches_integer_arithmetic() {
    let p = RnsInt::product();
    let samples = [
        (3i128, 5i128),
        (1 << 50, 1 << 60),
        (p - 1, p - 1),
        (1 << 80, (1 << 79) + 3),
    ];
    for &(a, b) in &samples {
        let got = RnsInt::from_int(a).add(&RnsInt::from_int(b)).to_int();
        assert_eq!(got, (a + b).rem_euclid(p), "RNS add must match (a+b) mod P");
    }
}

#[test]
fn mul_matches_integer_arithmetic() {
    let p = RnsInt::product();
    // Operands < 2^44 so the exact product < 2^88 fits i128 for cross-check.
    let samples = [
        (3i128, 5i128),
        (1_000_003, 999_983),
        (1i128 << 43, (1i128 << 43) - 1),
        (123456789, 987654321),
    ];
    for &(a, b) in &samples {
        let got = RnsInt::from_int(a).mul(&RnsInt::from_int(b)).to_int();
        assert_eq!(got, (a * b).rem_euclid(p), "RNS mul must match (a*b) mod P");
    }
}

#[test]
fn sub_wraps_correctly() {
    let p = RnsInt::product();
    let got = RnsInt::from_int(5).sub(&RnsInt::from_int(8)).to_int();
    assert_eq!(got, (5i128 - 8).rem_euclid(p), "RNS sub must wrap mod P");
}
