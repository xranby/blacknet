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

//! Milestone 4: verified computation on chain.
//!
//! [`Deploy`] registers a program; [`Compute`] claims an execution and
//! carries the proof. Validation never executes the program: it resolves
//! the code from the [`ProgramRegistry`] and calls the snark verifier once.
//! Fees price what validators spend — proof bytes and a flat verification
//! charge — never computation length (architecture §6.1).
//!
//! Not yet wired into the live transaction enum: activation is height-gated
//! and belongs to the network upgrade that ships the feature.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use blacknet_crypto::algebra::IntegerRing;
use blacknet_snark::commitment::{ProgramCommitment, commit};
use blacknet_snark::proof::{Proof, PublicIO, VerifyError, verify};
use blacknet_snark::witnesscommitment::CommitmentKey;
use blacknet_vm::machine::Instruction;

pub type F = blacknet_snark::proof::F;

/// Consensus parameters of verified computation.
pub mod params {
    /// Maximum deployed program length in instructions.
    pub const MAX_PROGRAM_LENGTH: usize = 1 << 16;
    /// Maximum proven trace length per Compute transaction.
    pub const MAX_STEPS: usize = 1 << 20;
    /// Flat fee per proof verification, in minimum units.
    pub const VERIFY_FEE: u64 = 10_000;
    /// Fee per proof byte, in minimum units.
    pub const BYTE_FEE: u64 = 10;
}

#[derive(Clone, Debug)]
pub struct Deploy {
    pub code: Vec<Instruction<F>>,
}

#[derive(Clone, Debug)]
pub struct Compute {
    pub program_id: ProgramCommitment,
    pub io: PublicIO,
    pub proof: Proof,
}

#[derive(Debug)]
pub enum Error {
    ProgramTooLong(usize),
    AlreadyDeployed,
    UnknownProgram,
    Verify(VerifyError),
}

/// The `program_id -> code` state. In consensus this lives in the ledger;
/// here it is the in-memory model the ledger integration will adapt.
#[derive(Default)]
pub struct ProgramRegistry {
    programs: BTreeMap<[i64; 4], Vec<Instruction<F>>>,
}

fn key(id: &ProgramCommitment) -> [i64; 4] {
    core::array::from_fn(|i| id.0[i].canonical())
}

impl ProgramRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies a deploy, returning the program id.
    pub fn deploy(&mut self, tx: Deploy) -> Result<ProgramCommitment, Error> {
        if tx.code.len() > params::MAX_PROGRAM_LENGTH {
            return Err(Error::ProgramTooLong(tx.code.len()));
        }
        let id = commit(&tx.code);
        if self.programs.contains_key(&key(&id)) {
            return Err(Error::AlreadyDeployed);
        }
        self.programs.insert(key(&id), tx.code);
        Ok(id)
    }

    /// Validates a compute claim: one proof verification, no execution.
    pub fn validate(&self, tx: &Compute) -> Result<(), Error> {
        let code = self
            .programs
            .get(&key(&tx.program_id))
            .ok_or(Error::UnknownProgram)?;
        verify(&tx.program_id, code, &tx.io, &tx.proof, params::MAX_STEPS).map_err(Error::Verify)
    }
}

/// The fee of a compute transaction: proof size plus flat verification
/// charge. Deliberately independent of how long the computation ran.
#[must_use]
pub const fn compute_fee(proof_bytes: usize) -> u64 {
    params::VERIFY_FEE + params::BYTE_FEE * proof_bytes as u64
}

/// A cache of already verified Compute transactions, keyed by transaction
/// hash. Txpool admission verifies once; block validation consults the
/// cache and re-verifies only on a miss — the same pattern as signature
/// caches. Entries are only inserted after successful verification, so a
/// cache hit is as authoritative as verification itself.
#[derive(Default)]
pub struct VerificationCache {
    verified: alloc::collections::BTreeSet<[u8; 32]>,
}

impl VerificationCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn contains(&self, tx_hash: &[u8; 32]) -> bool {
        self.verified.contains(tx_hash)
    }

    /// Validates with caching: a hit skips proof verification entirely.
    pub fn validate(
        &mut self,
        registry: &ProgramRegistry,
        tx_hash: [u8; 32],
        tx: &Compute,
    ) -> Result<(), Error> {
        if self.verified.contains(&tx_hash) {
            return Ok(());
        }
        registry.validate(tx)?;
        self.verified.insert(tx_hash);
        Ok(())
    }

    /// Evicts an entry, e.g. when the transaction leaves the pool.
    pub fn evict(&mut self, tx_hash: &[u8; 32]) {
        self.verified.remove(tx_hash);
    }
}

/// A uniform program deployment: code plus its canonical control flow,
/// from which every validator derives the constraint shape and folds
/// batched executions (the end-to-end pipeline of `blacknet-snark`).
pub struct DeployUniform {
    pub code: Vec<Instruction<F>>,
    pub sample_inputs: Vec<F>,
    pub fuel: u64,
}

/// A batch of executions of one uniform program with an aggregate folding
/// proof: per-execution verification is logarithmic in the trace, the
/// single opening is amortized across the batch.
pub struct ComputeBatch {
    pub program_id: ProgramCommitment,
    pub proof: blacknet_snark::pipeline::AggregateProof,
}

/// Registry of uniform shapes with their commitment keys.
#[derive(Default)]
pub struct UniformRegistry {
    shapes: BTreeMap<[i64; 4], (blacknet_snark::pipeline::Shape, CommitmentKey)>,
    rows: usize,
}

impl UniformRegistry {
    /// `rows` is the SIS dimension of the commitment keys: pass
    /// `blacknet_snark::witnesscommitment::SECURE_ROWS` in consensus;
    /// tests may use fewer.
    #[must_use]
    pub const fn new(rows: usize) -> Self {
        Self {
            shapes: BTreeMap::new(),
            rows,
        }
    }

    pub fn deploy(&mut self, tx: DeployUniform) -> Result<ProgramCommitment, Error> {
        if tx.code.len() > params::MAX_PROGRAM_LENGTH {
            return Err(Error::ProgramTooLong(tx.code.len()));
        }
        let shape = blacknet_snark::pipeline::Shape::derive(tx.code, &tx.sample_inputs, tx.fuel)
            .map_err(|_| Error::UnknownProgram)?;
        let id = shape.program_id;
        if self.shapes.contains_key(&key(&id)) {
            return Err(Error::AlreadyDeployed);
        }
        let ckey = CommitmentKey::setup(shape.elements, self.rows);
        self.shapes.insert(key(&id), (shape, ckey));
        Ok(id)
    }

    /// Validates a batch: replays the folding transcript and performs the
    /// amortized opening. Never executes the program.
    pub fn validate(&self, tx: &ComputeBatch) -> Result<(), Error> {
        let (shape, ckey) = self
            .shapes
            .get(&key(&tx.program_id))
            .ok_or(Error::UnknownProgram)?;
        blacknet_snark::pipeline::verify_aggregate(shape, ckey, &tx.proof)
            .map_err(|_| Error::Verify(VerifyError::Unsatisfied))
    }
}

/// Batch fee: flat per-execution verification charge plus the amortized
/// opening priced by proof bytes. Still independent of computation length.
#[must_use]
pub const fn compute_batch_fee(executions: usize, proof_bytes: usize) -> u64 {
    params::VERIFY_FEE * executions as u64 + params::BYTE_FEE * proof_bytes as u64
}

/// Protocol height at which verified computation activates. Before this
/// height the transaction types are rejected by consensus; at or after, the
/// pinned wire versions are accepted. Reuses the kernel's existing
/// height-gating discipline (other rules are gated the same way).
/// A placeholder non-zero activation height; the real value is set by
/// governance at deployment. Non-zero so the gate is meaningful.
pub const ACTIVATION_HEIGHT: u64 = 1_000_000;

/// Wire versions consensus accepts at a given height. Append-only: a new
/// version is added here at the height it activates, and old versions stay
/// valid so already-confirmed proofs keep verifying.
#[must_use]
pub const fn accepted_wire_versions(height: u64) -> &'static [u8] {
    if height >= ACTIVATION_HEIGHT {
        &[1]
    } else {
        &[]
    }
}

/// A Compute transaction as it travels on the wire: the program id, the
/// public IO, and the proof bytes. Validators decode then verify; decoding
/// is canonical (rejects non-canonical field elements and trailing bytes),
/// and the wire version must be accepted at the current height.
pub struct WireCompute {
    pub program_id: ProgramCommitment,
    pub io: PublicIO,
    pub proof_bytes: alloc::vec::Vec<u8>,
}

impl ProgramRegistry {
    /// Decodes and validates a wire Compute transaction at `height`. This is
    /// the consensus entry point: it pins the wire version, decodes
    /// canonically, then runs the single proof verification. Never executes
    /// the program.
    pub fn validate_wire(&self, tx: &WireCompute, height: u64) -> Result<(), Error> {
        if height < ACTIVATION_HEIGHT {
            return Err(Error::UnknownProgram);
        }
        let wire_version = tx.proof_bytes.first().copied().unwrap_or(0);
        if !accepted_wire_versions(height).contains(&wire_version) {
            return Err(Error::Verify(VerifyError::Version(wire_version)));
        }
        let proof = Proof::decode(&tx.proof_bytes)
            .map_err(|_| Error::Verify(VerifyError::Version(wire_version)))?;
        let compute = Compute {
            program_id: tx.program_id,
            io: tx.io.clone(),
            proof,
        };
        self.validate(&compute)
    }
}
