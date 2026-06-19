/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Validates the foundation the bootstrap-accumulator redesign rests on: that
//! NTT negacyclic multiplication is (a) exactly equal to the schoolbook product
//! and (b) substantially faster — measured on Fermat (65537), which is itself a
//! valid NTT-friendly RNS limb. See blacknet-bootstrap-completion-analysis.md.

use blacknet_crypto::fermat::{FermatField, FermatNTT1024, FermatRing1024};

fn coeffs(seed: u64) -> [FermatField; 1024] {
    let mut x = seed | 1;
    core::array::from_fn(|_| {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        FermatField::from((x >> 56) as u8)
    })
}

#[test]
fn ntt_multiplication_equals_schoolbook() {
    let a = coeffs(1);
    let b = coeffs(2);
    let school: FermatRing1024 = {
        let ra: FermatRing1024 = a.into();
        let rb: FermatRing1024 = b.into();
        ra * rb
    };
    let via_ntt: FermatRing1024 = {
        let na: FermatNTT1024 = a.into();
        let nb: FermatNTT1024 = b.into();
        FermatRing1024::from(na * nb)
    };
    for i in 0..1024 {
        assert_eq!(
            school[i], via_ntt[i],
            "NTT negacyclic product must equal the schoolbook product at coeff {i}"
        );
    }
}

#[test]
#[ignore = "measurement: prints schoolbook vs NTT multiply latency"]
fn measure_ntt_speedup() {
    use std::time::Instant;
    let a = coeffs(1);
    let b = coeffs(2);
    let reps = 200;

    let ra: FermatRing1024 = a.into();
    let rb: FermatRing1024 = b.into();
    let t0 = Instant::now();
    let mut acc = ra;
    for _ in 0..reps {
        acc *= rb;
    }
    let school = t0.elapsed().as_secs_f64() / reps as f64;
    core::hint::black_box(acc);

    let na: FermatNTT1024 = a.into();
    let nb: FermatNTT1024 = b.into();
    let t1 = Instant::now();
    let mut nacc = na;
    for _ in 0..reps {
        nacc *= nb;
    }
    let ntt = t1.elapsed().as_secs_f64() / reps as f64;
    core::hint::black_box(nacc);

    println!(
        "MEASURED schoolbook negacyclic mul: {:.3} ms",
        school * 1000.0
    );
    println!("MEASURED NTT pointwise mul:         {:.4} ms", ntt * 1000.0);
    println!("MEASURED speedup: {:.0}x", school / ntt);
}
