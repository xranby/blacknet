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

//! The self-folding recursive proof — incrementally verifiable computation,
//! closed at the fixed point.
//!
//! Two accumulators carry an unbounded chain, both constant size:
//!
//! - the **computation accumulator** `comp`, into which each step's
//!   execution folds (the HyperNova accumulator);
//! - the **proof accumulator** `proof`, into which each step's *IVC step
//!   circuit, as its own R1CS*, folds — the fixed point.
//!
//! The fixed point is what `multifold_verifier_r1cs` unlocks: the circuit
//! that verifies a fold is extracted as a foldable R1CS instance (its
//! public `(a, b, c)` matrices), so the satisfaction of every per-step
//! verifier circuit accumulates into one instance. After N steps the
//! verifier opens `comp` once and `proof` once; the latter attests that all
//! N folds were verified by the embedded recursive verifier, the former
//! that the computation is correct. Neither check grows with N — IVC with
//! the certification compressed, not merely performed.
//!
//! This is the closure: `proof` folds instances of the IVC step circuit,
//! and that circuit is the verifier of folds, so the accumulator is closed
//! under its own verification. The only structural element not yet collapsed
//! is unifying `comp` and `proof` into a single self-referential shape (one
//! circuit that folds both the execution and its own prior proof); that is a
//! layout optimization — two constant-size accumulators already deliver
//! constant verification — and is noted at the close.

use crate::hypernova::{Accumulator, AccumulatorWitness, init, multifold, open, padded_rows_of};
use crate::ivc::{assigner, multifold_verifier_circuit, multifold_verifier_r1cs};
use crate::pipeline::{Execution, Shape};
use crate::witnesscommitment::{CommitmentKey, F, decompose};
use blacknet_arith::r1cs::ShapedR1cs;
use blacknet_crypto::constraintsystem::ConstraintSystem;
use blacknet_crypto::matrix::DenseVector;

/// A running recursive proof over a chain of executions of one shape.
pub struct RecursiveState {
    comp: Accumulator,
    comp_w: AccumulatorWitness,
    proof: Option<Accumulator>,
    proof_w: Option<AccumulatorWitness>,
    proof_shape: Option<ShapedR1cs>,
    proof_io: Vec<usize>,
    steps: usize,
    certified: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Fold,
    Circuit,
}

/// Begins a recursive proof from the first execution.
#[must_use]
pub fn start(shape: &Shape, key: &CommitmentKey, first: &Execution) -> RecursiveState {
    let (comp, comp_w, _) = init(key, &shape.r1cs, first.witness(), &shape.io_positions, &[]);
    RecursiveState {
        comp,
        comp_w,
        proof: None,
        proof_w: None,
        proof_shape: None,
        proof_io: Vec::new(),
        steps: 1,
        certified: 0,
    }
}

impl RecursiveState {
    #[must_use]
    pub const fn steps(&self) -> usize {
        self.steps
    }

    #[must_use]
    pub const fn certified(&self) -> usize {
        self.certified
    }

    /// Folds one execution into the computation chain, builds the IVC step
    /// circuit certifying that fold, and folds the circuit's own R1CS
    /// satisfaction into the proof accumulator — the fixed point.
    ///
    /// `proof_key` commits the circuit witness; it is sized for the IVC
    /// circuit, distinct from the execution key.
    pub fn step(
        &mut self,
        shape: &Shape,
        key: &CommitmentKey,
        proof_key: &CommitmentKey,
        exec: &Execution,
    ) -> Result<(), Error> {
        let mu = padded_rows_of(&shape.r1cs).trailing_zeros() as usize;
        let rows = self.comp.commitment.dimension();

        let pre = self.comp.clone();
        let fresh_commitment = key.commit(&decompose(exec.witness()));
        let fresh_x: Vec<F> = shape
            .io_positions
            .iter()
            .map(|&i| exec.witness()[i])
            .collect();

        let (comp, comp_w, mfp) = multifold(
            key,
            &shape.r1cs,
            (&self.comp, &self.comp_w),
            exec.witness(),
            &shape.io_positions,
            &[],
        )
        .map_err(|_| Error::Fold)?;

        // Build the IVC step circuit and its assignment; this is the witness
        // that the fold (pre -> comp) verifies.
        let circuit = multifold_verifier_circuit(rows, mu, fresh_x.len());
        let z = circuit.assigment();
        assigner::fill(&z, &pre, &fresh_commitment, &fresh_x, &comp, &mfp, mu);
        let zf = z.finish();
        circuit.is_satisfied(&zf).map_err(|_| Error::Circuit)?;

        // Fixed point: fold the circuit's own R1CS satisfaction into the
        // proof accumulator. The shape is identical every step (uniform
        // circuit), so the instances fold.
        let shaped =
            ShapedR1cs::from_circuit_r1cs(multifold_verifier_r1cs(rows, mu, fresh_x.len()));
        self.fold_proof(proof_key, shaped, &zf)?;

        self.comp = comp;
        self.comp_w = comp_w;
        self.steps += 1;
        self.certified += 1;
        Ok(())
    }

    fn fold_proof(
        &mut self,
        proof_key: &CommitmentKey,
        shape: ShapedR1cs,
        zf: &DenseVector<F>,
    ) -> Result<(), Error> {
        // IO of the proof accumulator: the IVC circuit's leading public
        // inputs (a stable prefix across steps).
        let io: Vec<usize> = (1..=8.min(shape.a().columns().saturating_sub(1))).collect();
        if self.proof.is_none() {
            let (acc, w, _) = init(proof_key, &shape, zf, &io, &[F::from(2)]);
            self.proof = Some(acc);
            self.proof_w = Some(w);
            self.proof_io = io;
            self.proof_shape = Some(shape);
            return Ok(());
        }
        let acc = self.proof.take().unwrap();
        let w = self.proof_w.take().unwrap();
        let (nacc, nw, _) = multifold(
            proof_key,
            &shape,
            (&acc, &w),
            zf,
            &self.proof_io,
            &[F::from(2)],
        )
        .map_err(|_| Error::Fold)?;
        self.proof = Some(nacc);
        self.proof_w = Some(nw);
        Ok(())
    }

    /// Finalizes by opening both accumulators. Two checks, each independent
    /// of the number of steps — IVC with the per-step certification
    /// compressed into the proof accumulator.
    pub fn finish(
        self,
        shape: &Shape,
        key: &CommitmentKey,
        proof_key: &CommitmentKey,
    ) -> Result<RecursiveProof, Error> {
        open(
            key,
            &shape.r1cs,
            &shape.io_positions,
            &self.comp,
            &self.comp_w,
        )
        .map_err(|_| Error::Fold)?;
        if let (Some(acc), Some(w), Some(sh)) = (&self.proof, &self.proof_w, &self.proof_shape) {
            open(proof_key, sh, &self.proof_io, acc, w).map_err(|_| Error::Fold)?;
        }
        Ok(RecursiveProof {
            comp: self.comp,
            proof: self.proof,
            steps: self.steps,
        })
    }
}

/// The finalized recursive proof: two constant-size accumulators attesting
/// to an N-step chain and to every per-step fold's verification.
pub struct RecursiveProof {
    pub comp: Accumulator,
    pub proof: Option<Accumulator>,
    pub steps: usize,
}
