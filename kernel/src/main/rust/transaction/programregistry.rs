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

//! Registry-referenced programs: deploy a program once, then cite it by id.
//!
//! The inline verified-computation transaction carries the whole program in
//! every proof. For a program run many times — a zkFi app — that is wasteful:
//! the code is identical each time. This pair of transactions amortizes it.
//!
//!   * [`DeployProgram`] publishes a program once. Its canonical bytes are
//!     stored in chain state keyed by the program commitment; re-deploying
//!     the same id is rejected, so an id maps to exactly one program forever.
//!   * [`ComputeReference`] cites a deployed `program_id` and carries only the
//!     public IO and proof. Validation fetches the code from state, checks
//!     the cited id really is its commitment, and runs the same folded
//!     verifier as the inline form.
//!
//! Soundness is identical to the inline form, by construction: the verifier
//! re-derives `commit(code)` from the bytes in state and checks it equals the
//! cited id, so a forged or substituted program cannot be referenced. The fee
//! floor and the determinism argument carry over unchanged. The only new
//! trust surface is the registry itself — and because the id IS the
//! commitment, the registry cannot return a program that does not match the
//! id a proof was made against.

use crate::blake2b::Hash;
use crate::error::{Error, Result};
use crate::transaction::{CoinTx, ProgramId, Transaction, TxData};
use crate::verifiedcomputation::{ACTIVATION_HEIGHT, accepted_wire_versions, compute_fee, params};
use alloc::boxed::Box;
use alloc::format;
use blacknet_snark::commitment::{ProgramCommitment, commit};
use blacknet_snark::proof::verify;
use blacknet_snark::wire::{decode_program, decode_reference};
use serde::{Deserialize, Serialize};

/// The storage id for a program commitment: its four field limbs as
/// little-endian bytes. Deterministic and collision-free with the
/// commitment (the map key in `verifiedcomputation` uses the same limbs).
#[must_use]
pub fn program_id(commitment: &ProgramCommitment) -> ProgramId {
    use blacknet_crypto::algebra::IntegerRing;
    let mut id = [0u8; 32];
    for (k, limb) in commitment.0.iter().enumerate() {
        let bytes = limb.canonical().to_le_bytes();
        id[k * 8..k * 8 + 8].copy_from_slice(&bytes);
    }
    id
}

/// Publishes a program for later reference. Payload: the canonically-encoded
/// program (no proof).
#[derive(Deserialize, Serialize)]
pub struct DeployProgram {
    payload: Box<[u8]>,
}

impl DeployProgram {
    #[must_use]
    pub const fn new(payload: Box<[u8]>) -> Self {
        Self { payload }
    }

    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl TxData for DeployProgram {
    fn process_impl(
        &self,
        tx: &Transaction,
        _hash: Hash,
        _data_index: u32,
        coin_tx: &mut impl CoinTx,
    ) -> Result<()> {
        let height = u64::from(coin_tx.height());
        if height < ACTIVATION_HEIGHT {
            return Err(Error::Invalid("verified computation not active".into()));
        }
        // Bound work and price storage by payload size (cheapest checks
        // first), before decode.
        if self.payload.len() > params::MAX_PAYLOAD_BYTES {
            return Err(Error::Invalid("payload exceeds size cap".into()));
        }
        let required = compute_fee(self.payload.len());
        if tx.fee().value() < required {
            return Err(Error::Invalid(format!(
                "fee {} below deploy cost {required}",
                tx.fee().value()
            )));
        }
        let wire_version = self.payload.first().copied().unwrap_or(0);
        if !accepted_wire_versions(height).contains(&wire_version) {
            return Err(Error::Invalid(format!(
                "unaccepted wire version {wire_version}"
            )));
        }
        let program = decode_program(&self.payload)
            .map_err(|_| Error::Invalid("malformed program".into()))?;
        if program.len() > params::MAX_PROGRAM_LENGTH {
            return Err(Error::Invalid("program too long".into()));
        }
        // The id is the program's own commitment; one id, one program.
        let id = program_id(&commit(&program));
        if coin_tx.has_program(id) {
            return Err(Error::Invalid("program already deployed".into()));
        }
        coin_tx.add_program(id, self.payload.clone());
        Ok(())
    }
}

/// Runs a deployed program by reference. Payload: the cited program id, the
/// public IO, and the proof (no program).
#[derive(Deserialize, Serialize)]
pub struct ComputeReference {
    payload: Box<[u8]>,
}

impl ComputeReference {
    #[must_use]
    pub const fn new(payload: Box<[u8]>) -> Self {
        Self { payload }
    }

    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl TxData for ComputeReference {
    fn process_impl(
        &self,
        tx: &Transaction,
        _hash: Hash,
        _data_index: u32,
        coin_tx: &mut impl CoinTx,
    ) -> Result<()> {
        let height = u64::from(coin_tx.height());
        if height < ACTIVATION_HEIGHT {
            return Err(Error::Invalid("verified computation not active".into()));
        }
        if self.payload.len() > params::MAX_PAYLOAD_BYTES {
            return Err(Error::Invalid("payload exceeds size cap".into()));
        }
        // Fee floor: the referenced program adds the code-fetch and
        // verification cost, priced over the payload (the proof, not the
        // code, which is already paid for at deploy time).
        let required = compute_fee(self.payload.len());
        if tx.fee().value() < required {
            return Err(Error::Invalid(format!(
                "fee {} below verification cost {required}",
                tx.fee().value()
            )));
        }
        let wire_version = self.payload.first().copied().unwrap_or(0);
        if !accepted_wire_versions(height).contains(&wire_version) {
            return Err(Error::Invalid(format!(
                "unaccepted wire version {wire_version}"
            )));
        }
        let (cited_id, io, proof) = decode_reference(&self.payload)
            .map_err(|_| Error::Invalid("malformed reference payload".into()))?;

        // Fetch the deployed program and decode its stored bytes.
        let stored = coin_tx.get_program(program_id(&cited_id))?;
        let program =
            decode_program(&stored).map_err(|_| Error::Invalid("corrupt stored program".into()))?;

        // The cited id must be the program's commitment: this is what makes
        // referencing as sound as inlining. verify also re-checks it, but
        // failing fast here gives a precise error.
        let derived = commit(&program);
        if derived != cited_id {
            return Err(Error::Invalid(
                "cited id is not the program commitment".into(),
            ));
        }
        verify(&derived, &program, &io, &proof, params::MAX_STEPS)
            .map_err(|e| Error::Invalid(format!("proof rejected: {e:?}")))?;
        Ok(())
    }
}

/// A succinct referenced computation: cites a deployed `program_id` and
/// carries a succinct `AggregateProof` (witness omitted) instead of the
/// transparent proof. This is the bandwidth-minimal form — the packet is
/// ~constant in the trace length (~3-4 KB vs tens of KB transparent).
///
/// The verifier reconstructs everything it needs deterministically: the
/// program from the registry (by id), its R1CS `Shape` from the program (the
/// matrices are input-independent, so a canonical dummy input reproduces the
/// prover's shape), and the lattice `CommitmentKey` from the fixed public
/// setup. It then runs `pipeline::verify_aggregate`, never executing the
/// program.
#[derive(Deserialize, Serialize)]
pub struct ComputeReferenceSuccinct {
    pub payload: Box<[u8]>,
}

impl ComputeReferenceSuccinct {
    #[must_use]
    pub const fn new(payload: Box<[u8]>) -> Self {
        Self { payload }
    }

    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl TxData for ComputeReferenceSuccinct {
    fn process_impl(
        &self,
        tx: &Transaction,
        _hash: Hash,
        _data_index: u32,
        coin_tx: &mut impl CoinTx,
    ) -> Result<()> {
        use blacknet_snark::pipeline::{Shape, verify_aggregate};
        use blacknet_snark::wire::decode_reference_succinct;
        use blacknet_snark::witnesscommitment::{CommitmentKey, F, SECURE_ROWS};

        let height = u64::from(coin_tx.height());
        if height < ACTIVATION_HEIGHT {
            return Err(Error::Invalid("verified computation not active".into()));
        }
        if self.payload.len() > params::MAX_PAYLOAD_BYTES {
            return Err(Error::Invalid("payload exceeds size cap".into()));
        }
        // Fee floor priced over the payload (cheapest checks first).
        let required = compute_fee(self.payload.len());
        if tx.fee().value() < required {
            return Err(Error::Invalid(format!(
                "fee {} below verification cost {required}",
                tx.fee().value()
            )));
        }
        let wire_version = self.payload.first().copied().unwrap_or(0);
        if !accepted_wire_versions(height).contains(&wire_version) {
            return Err(Error::Invalid(format!(
                "unaccepted wire version {wire_version}"
            )));
        }

        let (cited_id, proof) = decode_reference_succinct(&self.payload)
            .map_err(|_| Error::Invalid("malformed succinct reference payload".into()))?;

        // Fetch the deployed program; the cited id must be its commitment.
        let stored = coin_tx.get_program(program_id(&cited_id))?;
        let program =
            decode_program(&stored).map_err(|_| Error::Invalid("corrupt stored program".into()))?;
        if commit(&program) != cited_id {
            return Err(Error::Invalid(
                "cited id is not the program commitment".into(),
            ));
        }

        // Reconstruct the R1CS shape from the program. The matrices are
        // input-independent (the foldability invariant), so a canonical dummy
        // input reproduces the prover's shape. The aggregate IO is
        // inputs + REGISTERS (seeded inputs of state 0, plus the full final
        // state), so the input arity is io_len - REGISTERS. Seeding the full
        // IO width instead would over-seed registers and fail arithmetization.
        use blacknet_arith::trace::REGISTERS;
        let io_len = proof.ios.first().map_or(0, |io| io.len());
        let inputs = io_len
            .checked_sub(REGISTERS)
            .ok_or_else(|| Error::Invalid("proof IO smaller than register file".into()))?;
        let dummy = alloc::vec![F::from(0); inputs];
        let shape = Shape::derive(program, &dummy, params::MAX_STEPS as u64)
            .map_err(|_| Error::Invalid("program shape not derivable".into()))?;
        // The lattice commitment key is the fixed public setup at the shape's
        // witness width and the consensus SIS dimension.
        let key = CommitmentKey::setup(shape.elements, SECURE_ROWS);

        verify_aggregate(&shape, &key, &proof)
            .map_err(|e| Error::Invalid(format!("succinct proof rejected: {e:?}")))?;
        Ok(())
    }
}
