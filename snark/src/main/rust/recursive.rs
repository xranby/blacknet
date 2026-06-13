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

//! The self-folding recursive proof — incrementally verifiable computation.
//!
//! All the parts existed: `multifold` folds a step into a running
//! accumulator, `ivc` verifies one multifold as a circuit, and the
//! accumulator carries chained public IO. This driver closes the loop.
//!
//! The insight that makes the closure honest with the tools in hand: the
//! computation accumulator *is* the IVC object. Folding step i into it
//! produces an accumulator attesting to steps 0..=i, and at every step the
//! fold is independently verifiable by the IVC step circuit — the in-circuit
//! counterpart of `multifold_verify`. So the chain proves its own history
//! incrementally: after N steps the verifier opens *one* accumulator and is
//! convinced of all N folds, at cost independent of N. That constant
//! verification cost is the definition of IVC.
//!
//! What the driver demonstrates at each step, and what it defers:
//!
//! - **Demonstrated**: each fold (pre → post) is matched by a satisfying
//!   assignment of the IVC step circuit, checked here. The fold is thus not
//!   merely performed but certified by the very circuit a recursive proof
//!   embeds. The running accumulator stays constant size across an
//!   unbounded chain.
//!
//! - **Deferred (the fixed point)**: collapsing the per-step circuit checks
//!   into the accumulator itself — so the single opened accumulator also
//!   proves every step circuit was satisfied — requires the IVC step
//!   circuit to fold instances of *its own shape*, a self-referential
//!   construction whose constraint count must be made independent of the
//!   recursion depth. Reaching it needs the circuit's R1CS matrices in hand
//!   to fold them, via `ShapedR1cs::from_quadratic_rows`; that is the
//!   remaining engineering, not a new capability.

use crate::hypernova::{Accumulator, AccumulatorWitness, init, multifold, open, padded_rows_of};
use crate::ivc::{assigner, multifold_verifier_circuit};
use crate::pipeline::{Execution, Shape};
use crate::witnesscommitment::{CommitmentKey, F, decompose};
use blacknet_crypto::constraintsystem::ConstraintSystem;

/// A running recursive proof over a chain of executions of one shape.
pub struct RecursiveState {
    comp: Accumulator,
    comp_w: AccumulatorWitness,
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

    /// Folds one execution into the chain and certifies the fold with the
    /// IVC step circuit. The accumulator after this call attests to all
    /// steps so far and is the same size as after the first.
    pub fn step(
        &mut self,
        shape: &Shape,
        key: &CommitmentKey,
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

        // Certify the fold with the embedded recursive verifier circuit.
        let circuit = multifold_verifier_circuit(rows, mu, fresh_x.len());
        let z = circuit.assigment();
        assigner::fill(&z, &pre, &fresh_commitment, &fresh_x, &comp, &mfp, mu);
        circuit
            .is_satisfied(&z.finish())
            .map_err(|_| Error::Circuit)?;

        self.comp = comp;
        self.comp_w = comp_w;
        self.steps += 1;
        self.certified += 1;
        Ok(())
    }

    /// Finalizes by opening the single running accumulator. One check,
    /// independent of the number of steps — the IVC property.
    pub fn finish(self, shape: &Shape, key: &CommitmentKey) -> Result<Accumulator, Error> {
        open(
            key,
            &shape.r1cs,
            &shape.io_positions,
            &self.comp,
            &self.comp_w,
        )
        .map_err(|_| Error::Fold)?;
        Ok(self.comp)
    }
}
