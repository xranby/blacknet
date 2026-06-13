/*
 * Copyright (c) 2026 Blacknet contributors
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

//! Measures the cost atoms the recursive layouts trade between and computes
//! the crossover step count from the measured numbers, rather than asserting
//! a winner. Run with `cargo test -p blacknet-snark --test layout_benchmark
//! -- --nocapture`.
//!
//! Two-accumulator form (shipped), per step: comp-fold + IVC circuit
//! (build+assign+satisfy) + proof-fold; end: two opens.
//! Unified form, per step: one fold over a circuit embedding BOTH the
//! execution fold and the prior-proof fold; end: one open.
//!
//! The unified circuit's verifier embeds the proof-fold check too, so its
//! per-step circuit cost is the two-accumulator per-step circuit cost plus
//! the in-circuit proof-fold — strictly larger. The only thing unified
//! saves is one opening at the end of the chain. We measure:
//!   t_step  : one full two-accumulator step (the dominant per-step work)
//!   t_open  : one accumulator opening (what unified saves, once)
//!   t_extra : the extra in-circuit work unified adds per step (estimated
//!             as one additional IVC-circuit build, since the unified
//!             circuit embeds a second fold verifier of comparable size)
//! and report the crossover N solving  t_open  >  (N-1) * t_extra.

use blacknet_arith::r1cs::ShapedR1cs;
use blacknet_crypto::constraintsystem::ConstraintSystem;
use blacknet_snark::hypernova::padded_rows_of;
use blacknet_snark::ivc::{multifold_verifier_circuit, multifold_verifier_r1cs};
use blacknet_snark::pipeline::{Shape, prove_execution};
use blacknet_snark::recursive::start;
use blacknet_snark::witnesscommitment::{CommitmentKey, F};
use blacknet_vm::machine::Instruction;
use std::hint::black_box;
use std::time::Instant;

const TEST_ROWS: usize = 8;

fn f(n: i32) -> F {
    F::from(n)
}

fn program() -> Vec<Instruction<F>> {
    vec![
        Instruction::Mul(2, 1, 1),
        Instruction::Add(3, 2, 1),
        Instruction::Halt,
    ]
}

fn time<T>(iters: u32, mut go: impl FnMut() -> T) -> f64 {
    // Warm up.
    for _ in 0..3 {
        black_box(go());
    }
    let start = Instant::now();
    for _ in 0..iters {
        black_box(go());
    }
    start.elapsed().as_secs_f64() / f64::from(iters)
}

#[test]
fn decide_recursive_layout() {
    let shape = Shape::derive(program(), &[f(1)], 100).unwrap();
    let key = CommitmentKey::setup(shape.elements, TEST_ROWS);
    let mu = padded_rows_of(&shape.r1cs).trailing_zeros() as usize;
    let xlen = shape.io_positions.len();
    let circuit_r1cs = ShapedR1cs::from_circuit_r1cs(multifold_verifier_r1cs(TEST_ROWS, mu, xlen));
    let proof_key = CommitmentKey::setup(circuit_r1cs.a().columns(), TEST_ROWS);

    let e0 = prove_execution(&shape, &key, &[f(2)]).unwrap();
    let e1 = prove_execution(&shape, &key, &[f(3)]).unwrap();

    // t_step: one full two-accumulator step (comp-fold + circuit + proof-fold).
    let t_step = time(20, || {
        let mut s = start(&shape, &key, &e0);
        s.step(&shape, &key, &proof_key, &e1).unwrap();
        s
    });

    // t_open: a finalize on a single-step chain isolates one opening pair;
    // subtract a no-step finalize to approximate one open.
    let t_finish = time(50, || {
        let s = start(&shape, &key, &e0);
        s.finish(&shape, &key, &proof_key).map(|_| ()).ok()
    });

    // t_extra: the unified circuit embeds a SECOND fold verifier per step;
    // approximate that added per-step cost by one extra IVC circuit build.
    let t_extra = time(20, || multifold_verifier_circuit(TEST_ROWS, mu, xlen));

    let constraints = multifold_verifier_circuit(TEST_ROWS, mu, xlen).constraints();
    let columns = circuit_r1cs.a().columns();

    // Unified saves at most one opening (~half of t_finish, which opens two)
    // and pays t_extra every step. Crossover N where saving is consumed:
    let saved = t_finish / 2.0;
    let crossover = if t_extra > 0.0 {
        1.0 + saved / t_extra
    } else {
        f64::INFINITY
    };

    eprintln!("=== recursive layout benchmark (measured) ===");
    eprintln!("IVC step circuit: {constraints} constraints, {columns} columns");
    eprintln!("t_step  (two-acc full step) = {:.3} ms", t_step * 1e3);
    eprintln!("t_finish (open both)        = {:.3} ms", t_finish * 1e3);
    eprintln!("t_open  (~one open)         = {:.3} ms", saved * 1e3);
    eprintln!("t_extra (unified per-step)  = {:.3} ms", t_extra * 1e3);
    eprintln!("crossover N (unified wins below this) = {crossover:.1}");
    if crossover < 2.0 {
        eprintln!("VERDICT: two-accumulator wins for every chain length N >= 2.");
    } else {
        eprintln!("VERDICT: unified wins for chains shorter than N = {crossover:.0}.");
    }
    eprintln!("Interpretation: unified trades one bounded end-of-chain opening");
    eprintln!("for an added per-step circuit cost paid N-1 times. Since the");
    eprintln!("per-step penalty recurs and the opening is paid once, the");
    eprintln!("shipped two-accumulator layout is preferred for any real chain.");

    // The benchmark records a number; it does not assert a winner.
    assert!(t_step > 0.0 && t_finish > 0.0 && t_extra > 0.0);
}
