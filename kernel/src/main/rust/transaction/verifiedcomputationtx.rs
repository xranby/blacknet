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

//! The on-chain verified-computation transaction — what makes zkFi apps
//! deployable.
//!
//! Until now the proof system (`blacknet-snark`) and the chain's transaction
//! set were on two sides of an unbridged gap: a node could not accept a zkFi
//! proof because no transaction type carried one. This is that transaction.
//!
//! It carries one self-contained, canonically-encoded payload — the program,
//! its public IO, and the proof — produced by `blacknet_snark::wire::
//! encode_compute`. Processing it decodes the payload and runs the standalone
//! verifier, which re-derives the program commitment from the inline program
//! and checks the folded proof against it; nothing off-chain is consulted, so
//! validation is a pure function of the transaction bytes and the activation
//! height. The program rides inline (rather than referencing a deployed
//! registry) so the first deployable form needs no new chain state — a
//! registry-backed form, where the program is committed once and later
//! transactions reference it by id, is the natural follow-on and reuses the
//! same `verify` call.
//!
//! Consensus gating: the type is rejected before `ACTIVATION_HEIGHT` and its
//! wire version must be accepted at the current height, reusing the existing
//! height-gating discipline so older proofs keep verifying across upgrades.

use crate::blake2b::Hash;
use crate::error::{Error, Result};
use crate::transaction::{CoinTx, Transaction, TxData};
use crate::verifiedcomputation::{ACTIVATION_HEIGHT, accepted_wire_versions, compute_fee, params};
use alloc::boxed::Box;
use alloc::format;
use blacknet_snark::commitment::commit;
use blacknet_snark::proof::verify;
use blacknet_snark::wire::decode_compute;
use serde::{Deserialize, Serialize};

/// A verified-computation transaction: a canonically-encoded
/// `(program, io, proof)` payload, verified on acceptance.
#[derive(Deserialize, Serialize)]
pub struct VerifiedComputation {
    payload: Box<[u8]>,
}

impl VerifiedComputation {
    #[must_use]
    pub const fn new(payload: Box<[u8]>) -> Self {
        Self { payload }
    }

    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl TxData for VerifiedComputation {
    fn process_impl(
        &self,
        tx: &Transaction,
        _hash: Hash,
        _data_index: u32,
        coin_tx: &mut impl CoinTx,
    ) -> Result<()> {
        let height = u64::from(coin_tx.height());

        // Consensus gate: not active yet. (Cheapest check first.)
        if height < ACTIVATION_HEIGHT {
            return Err(Error::Invalid(
                "verified computation not active at this height".into(),
            ));
        }

        // DoS / economic soundness: the fee must cover the cost this
        // transaction imposes on every validating node — a fixed verification
        // charge plus a per-byte charge over the payload. Checked BEFORE the
        // expensive decode-and-verify, and against the payload length so the
        // bound is a pure function of the bytes already in hand. Without this
        // an attacker floods minimal-fee transactions that each force every
        // node to run the verifier for free. A payload over the consensus
        // size cap is rejected outright (it could never pay a sane fee and
        // bounds the work before allocation).
        if self.payload.len() > params::MAX_PAYLOAD_BYTES {
            return Err(Error::Invalid("payload exceeds size cap".into()));
        }
        let required = compute_fee(self.payload.len());
        if tx.fee().value() < required {
            return Err(Error::Invalid(format!(
                "fee {} below verification cost {required}",
                tx.fee().value()
            )));
        }

        // Pin the wire version: the first byte of the canonical payload.
        let wire_version = self.payload.first().copied().unwrap_or(0);
        if !accepted_wire_versions(height).contains(&wire_version) {
            return Err(Error::Invalid(format!(
                "unaccepted wire version {wire_version}"
            )));
        }

        // Decode canonically (rejects malformed / non-canonical / trailing).
        let (program, io, proof) = decode_compute(&self.payload)
            .map_err(|_| Error::Invalid("malformed verified-computation payload".into()))?;

        // Bound the program length per consensus parameters.
        if program.len() > params::MAX_PROGRAM_LENGTH {
            return Err(Error::Invalid("program too long".into()));
        }

        // Verify: re-derives the program commitment from the inline program
        // and checks the folded proof against it. Deterministic (Fiat–Shamir
        // challenges are squeezed from the transcript), so every node reaches
        // the same accept/reject decision — a consensus requirement. Never
        // executes the program.
        let program_id = commit(&program);
        verify(&program_id, &program, &io, &proof, params::MAX_STEPS)
            .map_err(|e| Error::Invalid(format!("proof rejected: {e:?}")))?;
        Ok(())
    }
}
