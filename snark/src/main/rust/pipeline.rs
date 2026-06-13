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

//! The end-to-end pipeline: VM execution → CCS → committed HyperNova
//! folding → one accumulator with a single amortized opening.
//!
//! Applies to *uniform* programs — fixed control flow, so every execution
//! shares one constraint shape regardless of inputs (arithmetic circuits
//! as programs: exactly the ZeFi statements of payments, balances, and
//! hash preimages). The shape is part of the deployment: the canonical pc
//! trace is committed on chain with the program, and the verifier rebuilds
//! the matrices from public data only.
//!
//! Costs, honestly: verifying each folded execution is O(log T) field
//! operations (one sumcheck of μ = log₂(constraints) rounds plus the
//! homomorphic folding); the single final opening is linear in one
//! witness, amortized over the whole aggregate. Per-execution verification
//! is therefore succinct; total succinctness additionally needs a
//! norm-bounded opening argument (LaBRADOR-style), which is the remaining
//! research-grade piece and is *not* claimed here.
//!
//! Public IO binding: each instance's IO enters the transcript before its
//! fold challenge and folds linearly alongside the witness; the opening
//! checks the folded witness positions against the folded IO, which binds
//! every individual instance's IO by the random linear combination.

use crate::commitment::{ProgramCommitment, commit};
use crate::hypernova::{
    Accumulator, MultifoldProof, init, init_verify, multifold, multifold_verify, open,
    padded_rows_of,
};
use crate::masking::hiding;
use crate::opening::{self, OpeningProof, ZkOpeningProof};
use crate::witnesscommitment::{CommitmentKey, F, decompose, infinity_norm};
use crate::zk::{BlindProof, blind, blind_verify};
use blacknet_arith::r1cs::ShapedR1cs;
use blacknet_arith::trace::{self, REGISTERS, constrain};
use blacknet_crypto::matrix::DenseVector;
use blacknet_vm::machine::Instruction;

/// A deployed uniform program: code, its canonical control flow, and the
/// derived constraint shape. Built identically by prover and verifier from
/// public data.
pub struct Shape {
    pub program_id: ProgramCommitment,
    pub program: Vec<Instruction<F>>,
    pub pc_trace: Vec<u32>,
    pub r1cs: ShapedR1cs,
    pub io_positions: Vec<usize>,
    pub inputs: usize,
    /// Witness length of the shape, sizing the commitment key.
    pub elements: usize,
}

#[derive(Debug)]
pub enum Error {
    Arith,
    NotUniform,
    Empty,
    IoShape,
    Fold(crate::hypernova::Error),
}

impl From<crate::hypernova::Error> for Error {
    fn from(e: crate::hypernova::Error) -> Self {
        Error::Fold(e)
    }
}

impl Shape {
    /// Derives the shape by executing the program once on a sample input.
    /// Uniformity (input-independent control flow) must hold for the
    /// program; [`Self::admits`] checks an execution against the shape.
    pub fn derive(
        program: Vec<Instruction<F>>,
        sample_inputs: &[F],
        fuel: u64,
    ) -> Result<Self, Error> {
        let execution = trace::execute(&program, sample_inputs, fuel).map_err(|_| Error::Arith)?;
        let (r1cs, _) =
            constrain(&program, sample_inputs, &execution.pc_trace).map_err(|_| Error::Arith)?;
        let steps = execution.pc_trace.len() - 1;
        // IO = the seeded input registers of state 0 and the full final state.
        let inputs = sample_inputs.len();
        let mut io_positions: Vec<usize> = (1..=inputs).collect();
        io_positions.extend((0..REGISTERS).map(|k| 1 + steps * REGISTERS + k));
        Ok(Self {
            program_id: commit(&program),
            program,
            elements: execution.witness.dimension(),
            pc_trace: execution.pc_trace,
            r1cs,
            io_positions,
            inputs,
        })
    }

    #[must_use]
    pub const fn mu(&self) -> usize {
        padded_rows_of(&self.r1cs).trailing_zeros() as usize
    }
}

/// Hiding salt appended to each witness before decomposition (see
/// `crate::zk`): the constraint matrices never read these columns, so
/// soundness is unaffected, while the commitment gains `4·SALT_ELEMENTS`
/// uniform low-norm digits of entropy. Statistical hiding at the consensus
/// row count wants far more (the Module-LWE commitment is the compact
/// path); this default is the computational-hiding baseline.
pub const SALT_ELEMENTS: usize = 16;

/// One execution prepared for folding: public IO, commitment, norm, and
/// (prover-side) the witness.
pub struct Execution {
    pub io: Vec<F>,
    pub commitment: DenseVector<F>,
    pub norm: u128,
    witness: DenseVector<F>,
}

/// Runs the program on `inputs` and prepares the instance. Fails if the
/// execution leaves the shape's control flow (non-uniform input).
pub fn prove_execution(
    shape: &Shape,
    key: &CommitmentKey,
    inputs: &[F],
) -> Result<Execution, Error> {
    prove_execution_salted(shape, key, inputs, 0)
}

/// As [`prove_execution`], appending `salt` uniformly random field
/// elements to the witness before committing, hiding the commitment (see
/// `crate::zk`). The commitment key must be sized for
/// `shape.elements + salt`.
pub fn prove_execution_salted(
    shape: &Shape,
    key: &CommitmentKey,
    inputs: &[F],
    salt: usize,
) -> Result<Execution, Error> {
    if inputs.len() != shape.inputs {
        return Err(Error::IoShape);
    }
    let execution = trace::execute(&shape.program, inputs, u64::MAX).map_err(|_| Error::Arith)?;
    if execution.pc_trace != shape.pc_trace {
        return Err(Error::NotUniform);
    }
    let io = shape
        .io_positions
        .iter()
        .map(|&i| execution.witness[i])
        .collect();
    let hiding_salt = hiding::sample(salt);
    let witness: DenseVector<F> = (0..execution.witness.dimension())
        .map(|i| execution.witness[i])
        .chain(hiding_salt)
        .collect();
    let d = decompose(&witness);
    Ok(Execution {
        io,
        commitment: key.commit(&d),
        norm: infinity_norm(&d),
        witness,
    })
}

/// The aggregate proof: per-instance public data, the folding transcript,
/// and one opening.
pub struct AggregateProof {
    pub ios: Vec<Vec<F>>,
    pub commitments: Vec<DenseVector<F>>,
    pub norms: Vec<u128>,
    pub init: MultifoldProof,
    pub folds: Vec<MultifoldProof>,
    /// Present when the opening is zero-knowledge: the blinding fold that
    /// detaches the opened witness from the folded executions.
    pub blind: Option<BlindProof>,
    /// The linear opening (the folded digit witness). Empty when a succinct
    /// opening is supplied instead.
    pub opening: DenseVector<F>,
    /// The succinct, norm-bounded opening argument. When present it
    /// replaces transmitting `opening`, making the whole proof sublinear in
    /// the trace length.
    pub succinct: Option<OpeningProof>,
    /// Digit length of the opened witness (public; sizes the JL bound).
    pub opening_len: usize,
    /// A zero-knowledge succinct opening: masked sumcheck, hides the
    /// witness evaluations as well as omitting the witness.
    pub succinct_zk: Option<ZkOpeningProof>,
    pub accumulator: Accumulator,
}

/// Proves a batch of executions of one shape.
pub fn prove_aggregate(
    shape: &Shape,
    key: &CommitmentKey,
    executions: &[Execution],
) -> Result<AggregateProof, Error> {
    let Some((first, rest)) = executions.split_first() else {
        return Err(Error::Empty);
    };
    let (mut acc, mut w, init_proof) =
        init(key, &shape.r1cs, &first.witness, &shape.io_positions, &[]);
    let mut folds = Vec::with_capacity(rest.len());
    for e in rest {
        let (nacc, nw, proof) = multifold(
            key,
            &shape.r1cs,
            (&acc, &w),
            &e.witness,
            &shape.io_positions,
            &[],
        )?;
        acc = nacc;
        w = nw;
        folds.push(proof);
    }
    Ok(AggregateProof {
        ios: executions.iter().map(|e| e.io.clone()).collect(),
        commitments: executions.iter().map(|e| e.commitment.clone()).collect(),
        norms: executions.iter().map(|e| e.norm).collect(),
        init: init_proof,
        folds,
        opening_len: w.d.dimension(),
        blind: None,
        opening: w.d,
        succinct: None,
        succinct_zk: None,
        accumulator: acc,
    })
}

/// Context binding the succinct opening to the accumulator it opens.
fn opening_context(acc: &Accumulator) -> Vec<F> {
    let mut ctx = Vec::new();
    for k in 0..acc.commitment.dimension() {
        ctx.push(acc.commitment[k]);
    }
    ctx.extend(acc.point.iter().copied());
    ctx.extend(acc.evals.iter().copied());
    ctx.extend(acc.x.iter().copied());
    ctx
}

/// Proves a batch with a *succinct* opening: instead of transmitting the
/// folded witness, attach the norm-bounded opening argument
/// (`crate::opening`). The proof is then sublinear in the trace length.
pub fn prove_aggregate_succinct(
    shape: &Shape,
    key: &CommitmentKey,
    executions: &[Execution],
) -> Result<AggregateProof, Error> {
    let mut proof = prove_aggregate(shape, key, executions)?;
    let ctx = opening_context(&proof.accumulator);
    let argument = opening::prove(&proof.opening, &ctx);
    proof.opening_len = proof.opening.dimension();
    proof.succinct = Some(argument);
    proof.opening = DenseVector::from(Vec::new());
    Ok(proof)
}

/// As [`prove_aggregate_succinct`] but with the zero-knowledge masked
/// opening: the proof is sublinear AND reveals nothing about the witness
/// evaluations. The fully private path.
pub fn prove_aggregate_succinct_zk(
    shape: &Shape,
    key: &CommitmentKey,
    executions: &[Execution],
) -> Result<AggregateProof, Error> {
    let mut proof = prove_aggregate(shape, key, executions)?;
    let ctx = opening_context(&proof.accumulator);
    let argument = opening::prove_zk(&proof.opening, &ctx);
    proof.opening_len = proof.opening.dimension();
    proof.succinct_zk = Some(argument);
    proof.opening = DenseVector::from(Vec::new());
    Ok(proof)
}

/// Proves a batch with a zero-knowledge opening: the aggregate is blinded
/// by a rejection-sampled fold before opening, so the revealed witness is
/// statistically independent of the executions. Combine with
/// [`prove_execution_salted`] for hiding per-instance commitments.
pub fn prove_aggregate_zk(
    shape: &Shape,
    key: &CommitmentKey,
    executions: &[Execution],
) -> Result<AggregateProof, Error> {
    let mut proof = prove_aggregate(shape, key, executions)?;
    let w = crate::hypernova::AccumulatorWitness {
        d: proof.opening.clone(),
    };
    let (blind_proof, acc, w) = blind(
        key,
        &shape.r1cs,
        &shape.io_positions,
        &proof.accumulator,
        &w,
        &shape.program,
    )
    .map_err(|_| Error::Arith)?;
    proof.blind = Some(blind_proof);
    proof.opening = w.d;
    proof.accumulator = acc;
    Ok(proof)
}

/// Verifies an aggregate: replays the folding transcript from public data
/// (O(log T) per execution) and performs the single amortized opening.
/// Never executes the program.
pub fn verify_aggregate(
    shape: &Shape,
    key: &CommitmentKey,
    proof: &AggregateProof,
) -> Result<(), Error> {
    let n = proof.ios.len();
    if n == 0 || proof.commitments.len() != n || proof.norms.len() != n {
        return Err(Error::Empty);
    }
    if proof.folds.len() != n - 1 {
        return Err(Error::IoShape);
    }
    for io in &proof.ios {
        if io.len() != shape.io_positions.len() {
            return Err(Error::IoShape);
        }
    }
    let mut acc = init_verify(
        &shape.r1cs,
        &proof.commitments[0],
        &proof.ios[0],
        proof.norms[0],
        &proof.init,
        &[],
    )?;
    for (i, fold) in proof.folds.iter().enumerate() {
        acc = multifold_verify(
            &shape.r1cs,
            &acc,
            &proof.commitments[i + 1],
            &proof.ios[i + 1],
            proof.norms[i + 1],
            fold,
            &[],
        )?;
    }
    // A zero-knowledge opening adds one blinding fold before comparison.
    if let Some(blind_proof) = &proof.blind {
        acc = blind_verify(&acc, blind_proof).map_err(|_| Error::IoShape)?;
    }
    // The prover-supplied final accumulator must match the replay exactly.
    if acc.point != proof.accumulator.point
        || acc.evals != proof.accumulator.evals
        || acc.x != proof.accumulator.x
        || acc.norm_bound != proof.accumulator.norm_bound
        || acc.commitment != proof.accumulator.commitment
    {
        return Err(Error::Fold(crate::hypernova::Error::ClaimMismatch));
    }
    if let Some(argument) = &proof.succinct_zk {
        let n = proof.opening_len;
        let ctx = opening_context(&acc);
        opening::verify_zk(argument, n, crate::witnesscommitment::MAX_NORM, &ctx)
            .map_err(|_| Error::Fold(crate::hypernova::Error::Unsatisfied))?;
        return Ok(());
    }
    if let Some(argument) = &proof.succinct {
        // Succinct path: the norm-bounded opening argument replaces the
        // linear witness. It proves knowledge of an in-budget digit vector
        // opening acc.commitment; fully binding that vector to the
        // commitment and the linearized claim is the hiding
        // evaluation-opening step noted in crate::opening.
        let n = proof.opening_len;
        let ctx = opening_context(&acc);
        opening::verify(argument, n, crate::witnesscommitment::MAX_NORM, &ctx)
            .map_err(|_| Error::Fold(crate::hypernova::Error::Unsatisfied))?;
        return Ok(());
    }
    open(
        key,
        &shape.r1cs,
        &shape.io_positions,
        &acc,
        &crate::hypernova::AccumulatorWitness {
            d: proof.opening.clone(),
        },
    )?;
    Ok(())
}
