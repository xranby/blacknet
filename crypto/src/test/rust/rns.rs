/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! RNS arithmetic verified against exact integer arithmetic mod P.

#![allow(clippy::needless_range_loop)]

use blacknet_crypto::rns::{NTT_DEGREE, RNS_PRIMES, RnsInt};
use blacknet_crypto::rns_rlwe::T;

#[test]
fn primes_are_ntt_friendly_and_large_enough() {
    // Each limb supports a length-2N negacyclic NTT (2N | p-1) at the chosen
    // degree, and the product is a *secure* modulus at N=4096. Per the
    // fpylll-backed core-SVP oracle (blacknet_lattice_oracle.sage), a ternary
    // ring at N=4096 stays >=128-bit classical for log q up to ~88
    // (beta=462 -> 2^135); we use P ~ 2^60 -> beta=778 -> 2^227 classical /
    // 2^206 quantum, with a large correctness margin to spare. T = 65537 is one
    // of the primes, so T | P exactly: this makes
    // the detection plain-multiply decode exact regardless of product magnitude
    // (the P-mod-T correction term vanishes), which is what lets the secure,
    // small modulus work where it otherwise could not.
    for &p in &RNS_PRIMES {
        assert_eq!(
            (p - 1) % (2 * NTT_DEGREE as i64),
            0,
            "prime {p} must satisfy 2N | p-1 for the length-{} negacyclic NTT",
            2 * NTT_DEGREE
        );
    }
    let product = RnsInt::product();
    assert_eq!(
        product % i128::from(T),
        0,
        "T must divide P (exact detection)"
    );
    assert!(
        product > (1i128 << 48),
        "P must give detection/compaction headroom"
    );
    assert!(
        product < (1i128 << 88),
        "P must stay <= ~2^88 to be >=128-bit at N=4096 (fpylll core-SVP)"
    );
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

// --- NTT-accelerated negacyclic RNS multiply vs schoolbook ------------------

use blacknet_crypto::rns::RnsPoly;

const N: usize = NTT_DEGREE;

/// Schoolbook negacyclic convolution mod P (exact, via i128) for small-ish
/// coefficients so products stay within i128.
fn schoolbook_negacyclic(a: &[i128; N], b: &[i128; N], p: i128) -> [i128; N] {
    let mut out = [0i128; N];
    for i in 0..N {
        for j in 0..N {
            let mut k = i + j;
            let mut sign = 1i128;
            if k >= N {
                k -= N;
                sign = -1; // X^N = -1
            }
            out[k] = (out[k] + sign * (a[i] * b[j])).rem_euclid(p);
        }
    }
    out
}

fn seeded(seed: u64, bound: i128) -> [i128; N] {
    let mut x = seed | 1;
    core::array::from_fn(|_| {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((x >> 40) as i128).rem_euclid(bound)
    })
}

#[test]
fn ntt_rns_negacyclic_mul_equals_schoolbook() {
    // Coefficients up to 2^20 so the schoolbook product (sum of N terms of
    // ~2^40) stays well within i128 for the exact cross-check.
    let bound = 1i128 << 20;
    let a = seeded(11, bound);
    let b = seeded(22, bound);

    let prod = RnsPoly::from_coefficients(&a).negacyclic_mul(&RnsPoly::from_coefficients(&b));
    let p = product_modulus();
    let expect = schoolbook_negacyclic(&a, &b, p);

    for i in 0..N {
        assert_eq!(
            prod.coefficient(i),
            expect[i],
            "NTT-RNS negacyclic product must equal schoolbook at coeff {i}"
        );
    }
}

// helper to reach the product modulus from the test
fn product_modulus() -> i128 {
    use blacknet_crypto::rns::RnsInt;
    RnsInt::product()
}

#[test]
#[ignore = "measurement: NTT-RNS multiply latency at the accumulator modulus"]
fn measure_ntt_rns_speedup() {
    use std::time::Instant;
    let bound = 1i128 << 20;
    let a = RnsPoly::from_coefficients(&seeded(1, bound));
    let b = RnsPoly::from_coefficients(&seeded(2, bound));
    let reps = 100;
    let t0 = Instant::now();
    let mut acc = a.clone();
    for _ in 0..reps {
        acc = acc.negacyclic_mul(&b);
    }
    core::hint::black_box(acc.coefficient(0));
    let per = t0.elapsed().as_secs_f64() / reps as f64;
    println!(
        "MEASURED NTT-RNS negacyclic mul (deg {N}, modulus ~2^60): {:.3} ms",
        per * 1000.0
    );
}
