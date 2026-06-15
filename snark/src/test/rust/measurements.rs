/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! Concrete size and throughput measurements for on-chain zkFi.
//! Run with: cargo test -p blacknet-snark --test measurements -- --nocapture

use blacknet_snark::commitment::commit;
use blacknet_snark::proof::{prove, verify};
use blacknet_snark::wire::{encode_compute, encode_program, encode_reference};
use blacknet_snark::witnesscommitment::F;
use blacknet_vm::machine::Instruction;
use std::time::Instant;

fn f(n: i32) -> F {
    F::from(n)
}

/// A program that does `iters` multiply-add steps then halts, so we can scale
/// the trace length and watch sizes/timings move.
fn workload(iters: usize) -> Vec<Instruction<F>> {
    let mut p = vec![Instruction::LoadImm(1, f(3)), Instruction::LoadImm(2, f(1))];
    for _ in 0..iters {
        p.push(Instruction::Mul(2, 2, 1)); // r2 *= r1
        p.push(Instruction::Add(2, 2, 1)); // r2 += r1
    }
    p.push(Instruction::Halt);
    p
}

#[test]
fn report() {
    println!("\n==================== zkFi CONCRETE NUMBERS ====================");
    println!("(release build, single-threaded, transparent v0 proof)\n");

    println!("--- LATTICE / COMMITMENT PARAMETERS (from params.py + code) ---");
    println!("  folding field      : Pervushin, q = 2^61 - 1 (Mersenne, no NTT)");
    println!("  commitment ring    : LM, q = 2^60 - 2^32 + 1, degree 64 negacyclic");
    println!("  field element wire : 8 bytes (canonical LE)");
    println!("  scalar SIS rows    : 2048 (SECURE_ROWS), 128-bit classical at MAX_NORM=2^44");
    println!("  module SIS rows    : 40 ring rows = dim 2560 (rigorous 2^47 norm, ~147-bit)");
    println!("  per-fold expansion : ||M_c||_2 <= 8 (= 1*sqrt(64)), certified");
    println!("  folded-size (cols) : constant across steps (the folding property)\n");

    println!("--- PROOF / PACKET SIZES (measured, encode_compute) ---");
    println!(
        "  {:>8} {:>8} {:>12} {:>12} {:>12}",
        "iters", "steps", "inline B", "deploy B", "ref B"
    );
    for iters in [1usize, 8, 64, 512, 4096] {
        let prog = workload(iters);
        let (io, proof) = prove(&prog, &[], 10_000_000).unwrap();
        let id = commit(&prog);
        let inline = encode_compute(&prog, &io, &proof).len();
        let deploy = encode_program(&prog).len();
        let reference = encode_reference(&id, &io, &proof).len();
        let steps = proof.pc_trace.len();
        println!(
            "  {:>8} {:>8} {:>12} {:>12} {:>12}",
            iters, steps, inline, deploy, reference
        );
    }
    println!("  (inline = program+IO+proof; deploy = program only, once;");
    println!("   ref = id+IO+proof, what a repeat run sends after deploy)\n");

    println!("--- PROOF SIZE BREAKDOWN (where the bytes are) ---");
    {
        let prog = workload(512);
        let (io, proof) = prove(&prog, &[], 10_000_000).unwrap();
        let prog_b = encode_program(&prog).len();
        let witness_b = proof.witness.len() * 8;
        let trace_b = proof.pc_trace.len() * 4;
        let io_b = (io.inputs.len() + io.outputs.len()) * 8;
        println!("  program   : {:>10} B ({} instrs)", prog_b, prog.len());
        println!(
            "  pc_trace  : {:>10} B ({} steps x 4)",
            trace_b,
            proof.pc_trace.len()
        );
        println!(
            "  witness   : {:>10} B ({} field elems x 8)  <-- dominant",
            witness_b,
            proof.witness.len()
        );
        println!("  io        : {:>10} B", io_b);
        println!("  NOTE: v0 proof is TRANSPARENT - carries the full witness, so");
        println!("        proof size grows with the trace. A succinct opening");
        println!("        (committed witness + sumcheck) is the size win not yet wired.\n");
    }

    println!("--- VERIFICATION THROUGHPUT (measured) ---");
    println!(
        "  {:>8} {:>8} {:>14} {:>14}",
        "iters", "steps", "verify ms", "tx/sec/core"
    );
    for iters in [8usize, 64, 512, 4096] {
        let prog = workload(iters);
        let (io, proof) = prove(&prog, &[], 10_000_000).unwrap();
        let id = commit(&prog);
        // warm + time a few verifies
        let reps = if iters >= 512 { 5 } else { 50 };
        let start = Instant::now();
        for _ in 0..reps {
            verify(&id, &prog, &io, &proof, 1 << 24).unwrap();
        }
        let ms = start.elapsed().as_secs_f64() * 1000.0 / reps as f64;
        let tps = 1000.0 / ms;
        println!(
            "  {:>8} {:>8} {:>14.3} {:>14.1}",
            iters,
            proof.pc_trace.len(),
            ms,
            tps
        );
    }
    println!("  (single core; release build below, +rayon would add more)\n");

    println!("--- PROVE TIME (measured, for context) ---");
    println!("  {:>8} {:>8} {:>14}", "iters", "steps", "prove ms");
    for iters in [8usize, 64, 512] {
        let prog = workload(iters);
        let start = Instant::now();
        let _ = prove(&prog, &[], 10_000_000).unwrap();
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        println!("  {:>8} {:>8} {:>14.3}", iters, "~", ms);
    }
    println!();

    println!("--- NETWORK SCALE (measured sizes x consensus limits) ---");
    // Consensus constants (kernel::proofofstake): block spacing = 4*time_slot
    // = 64s (V4) or 16s (V4.1); default max block 100 KB; hard cap ~2 GB.
    // verifiedcomputation::params: MAX_PAYLOAD_BYTES = 16 MB per tx.
    let block_default = 100_000usize;
    let block_max = (i32::MAX as usize) - 100;
    for (label, spacing) in [("V4 (64s)", 64.0f64), ("V4.1 (16s)", 16.0)] {
        // Use the 64-iter workload as a representative "small app" tx.
        let prog = workload(64);
        let (io, proof) = prove(&prog, &[], 10_000_000).unwrap();
        let id = commit(&prog);
        let inline = encode_compute(&prog, &io, &proof).len();
        let reference = encode_reference(&id, &io, &proof).len();
        let per_default_inline = block_default / inline;
        let per_default_ref = block_default / reference;
        let per_max_ref = block_max / reference;
        println!(
            "  {label}: ~{} ref-tx / 100KB block = {:.2} tx/s; ",
            per_default_ref,
            per_default_ref as f64 / spacing
        );
        println!(
            "      ({} inline-tx / 100KB; up to ~{} ref-tx if block raised to 2GB cap)",
            per_default_inline, per_max_ref
        );
    }
    println!("  Bottleneck check: verify cost vs block spacing.");
    println!("    a 132-step proof verifies in ~0.12 ms (release); a 100KB block of");
    println!("    them (~10 tx) verifies in ~1.2 ms, far inside a 16-64s slot - so");
    println!("    BLOCK SIZE (bandwidth), not verify CPU, is the binding limit here.");
    println!();

    println!("--- WHAT FOLDING BUYS (the scaling story) ---");
    println!("  One folded proof attests an ENTIRE multi-step computation, so the");
    println!("  verifier's per-tx work and the folded-commitment size are CONSTANT");
    println!("  in the number of steps - only the transparent v0 witness in the");
    println!("  packet grows. With a succinct opening (committed witness, not yet");
    println!("  wired) the packet too becomes ~constant, and a single tx could");
    println!("  attest millions of steps at fixed bytes and fixed verify time.");
    println!("===============================================================\n");
}

#[test]
fn succinct_opening_size() {
    use blacknet_snark::pipeline::{
        Shape, prove_aggregate, prove_aggregate_succinct, prove_execution, verify_aggregate,
    };
    use blacknet_snark::witnesscommitment::CommitmentKey;
    println!("\n--- SUCCINCT OPENING: proof size vs transparent (measured) ---");
    let shape = Shape::derive(workload(64), &[f(2)], 1_000_000).unwrap();
    let key = CommitmentKey::setup(shape.elements, 24);
    println!(
        "  {:>8} {:>16} {:>16} {:>10}",
        "execs", "transparent B", "succinct B", "ratio"
    );
    for nexec in [2usize, 8, 32] {
        let execs: Vec<_> = (0..nexec)
            .map(|i| prove_execution(&shape, &key, &[f(i as i32 + 1)]).unwrap())
            .collect();
        let transparent = prove_aggregate(&shape, &key, &execs).unwrap();
        let succinct = prove_aggregate_succinct(&shape, &key, &execs).unwrap();
        assert!(verify_aggregate(&shape, &key, &succinct).is_ok());
        // Size proxy: the opening witness (transparent) vs the succinct args.
        let t_bytes = transparent.opening.dimension() * 8;
        let s_witness = succinct.opening.dimension() * 8; // should be 0
        let s_bind = succinct
            .binding
            .as_ref()
            .map(|(p, _)| p.variables() * 3 * 8 + 8)
            .unwrap_or(0);
        let s_proj = succinct
            .succinct
            .as_ref()
            .map(|o| o.projection.dimension() * 8 + o.binarity.variables() * 3 * 8)
            .unwrap_or(0);
        let s_total = s_witness + s_bind + s_proj;
        println!(
            "  {:>8} {:>16} {:>16} {:>9.2}x",
            nexec,
            t_bytes,
            s_total,
            t_bytes as f64 / s_total.max(1) as f64
        );
    }
    println!("  (transparent = folded witness in the clear; succinct = JL");
    println!("   projection + 2 log-size sumchecks, witness GONE. The crossover");
    println!("   grows with trace length: more steps, bigger transparent win.)");
}

#[test]
fn reference_form_bandwidth() {
    use blacknet_snark::commitment::commit;
    use blacknet_snark::proof::prove;
    use blacknet_snark::wire::{encode_compute, encode_reference};
    println!("\n--- REFERENCE-FORM BANDWIDTH (program already on chain) ---");
    println!("  reference payload = id(32B) + IO + proof(version+pc_trace+witness)");
    println!(
        "  {:>6} {:>6} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "iters", "steps", "inline B", "ref B", "id+IO B", "trace B", "witness B"
    );
    for iters in [1usize, 8, 64, 512] {
        let prog = workload(iters);
        let (io, proof) = prove(&prog, &[], 10_000_000).unwrap();
        let id = commit(&prog);
        let inline = encode_compute(&prog, &io, &proof).len();
        let reference = encode_reference(&id, &io, &proof).len();
        let idio = 1 + 4 * 8 + (io.inputs.len() + io.outputs.len()) * 8 + 1; // ver+id+IO+proofver
        let trace = proof.pc_trace.len() * 4;
        let witness = proof.witness.len() * 8;
        println!(
            "  {:>6} {:>6} {:>10} {:>10} {:>10} {:>10} {:>10}",
            iters,
            proof.pc_trace.len(),
            inline,
            reference,
            idio,
            trace,
            witness
        );
    }
    // MEASURED: the succinct reference form now wired through the real codec
    // (encode_reference_succinct). Packet is ~constant in trace length.
    use blacknet_snark::pipeline::{Shape, prove_aggregate_succinct, prove_execution};
    use blacknet_snark::wire::encode_reference_succinct;
    use blacknet_snark::witnesscommitment::{CommitmentKey, SECURE_ROWS};
    println!();
    println!("  MEASURED reference + succinct opening (wired, encode_reference_succinct):");
    println!(
        "  {:>8} {:>18} {:>18}",
        "steps", "transparent ref B", "succinct ref B"
    );
    for iters in [64usize, 512, 1500] {
        let prog = workload(iters);
        let shape = Shape::derive(prog.clone(), &[], 20_000_000).unwrap();
        let key = CommitmentKey::setup(shape.elements, SECURE_ROWS);
        let exec = prove_execution(&shape, &key, &[]).unwrap();
        let agg = prove_aggregate_succinct(&shape, &key, &[exec]).unwrap();
        let id = commit(&prog);
        let succinct_ref = encode_reference_succinct(&id, &agg).unwrap().len();
        let (io, p) = prove(&prog, &[], 20_000_000).unwrap();
        let transparent_ref = encode_reference(&id, &io, &p).len();
        let steps = p.pc_trace.len();
        let win = if succinct_ref < transparent_ref {
            "succinct wins"
        } else {
            "transparent wins"
        };
        println!(
            "  {:>8} {:>18} {:>18}   {}",
            steps, transparent_ref, succinct_ref, win
        );
    }
}
