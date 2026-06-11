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
