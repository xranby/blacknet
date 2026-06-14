/*
 * Copyright (c) 2018-2026 Pavel Vasin
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

use crate::account::Account;
use crate::amount::Amount;
use crate::blake2b::Hash;
use crate::ed25519::PublicKey;
use crate::error::{Error, Result};
use crate::htlc::HTLC;
use crate::multisig::Multisig;
use crate::transaction::*;
use alloc::borrow::ToOwned;
use blacknet_serialization::format::from_bytes;
use blacknet_time::Seconds;

/// The id under which a deployed program is stored: the canonical bytes of
/// its commitment.
pub type ProgramId = [u8; 32];

pub trait CoinTx: Sized {
    fn add_supply(&mut self, amount: Amount);
    fn sub_supply(&mut self, amount: Amount);
    fn check_anchor(&self, hash: Hash) -> Result<()>;
    fn block_hash(&self) -> Hash;
    fn block_time(&self) -> Seconds;
    fn height(&self) -> u32;
    fn get_account(&mut self, key: PublicKey) -> Result<Account>;
    fn get_or_create(&mut self, key: PublicKey) -> Account;
    fn set_account(&mut self, key: PublicKey, state: Account);
    fn add_htlc(&mut self, id: HashTimeLockContractId, htlc: HTLC);
    fn get_htlc(&mut self, id: HashTimeLockContractId) -> Result<HTLC>;
    fn remove_htlc(&mut self, id: HashTimeLockContractId);
    fn add_multisig(&mut self, id: MultiSignatureLockContractId, multisig: Multisig);
    fn get_multisig(&mut self, id: MultiSignatureLockContractId) -> Result<Multisig>;
    fn remove_multisig(&mut self, id: MultiSignatureLockContractId);
    /// Stores a deployed program by its commitment id. Idempotent at the
    /// caller: a deploy transaction must reject a re-deploy of the same id.
    fn add_program(&mut self, id: ProgramId, code: alloc::boxed::Box<[u8]>);
    /// Whether a program is already deployed under this id.
    fn has_program(&mut self, id: ProgramId) -> bool;
    /// Fetches a deployed program's canonical bytes, or errors if unknown.
    fn get_program(&mut self, id: ProgramId) -> Result<alloc::boxed::Box<[u8]>>;

    fn process_transaction_impl(&mut self, tx: &Transaction, hash: Hash) -> Result<()> {
        tx.verify_signature(hash)?;
        self.check_anchor(tx.anchor())?;
        match tx.kind() {
            TxKind::Transfer => {
                let data = from_bytes::<Transfer>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::Burn => {
                let data = from_bytes::<Burn>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::Lease => {
                let data = from_bytes::<Lease>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::CancelLease => {
                let data = from_bytes::<CancelLease>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::Blob => {
                let data = from_bytes::<Blob>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::CreateHTLC => {
                let data = from_bytes::<CreateHTLC>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::RefundHTLC => {
                let data = from_bytes::<RefundHTLC>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::CreateMultisig => {
                let data = from_bytes::<CreateMultisig>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::SpendMultisig => {
                let data = from_bytes::<SpendMultisig>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::WithdrawFromLease => {
                let data = from_bytes::<WithdrawFromLease>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::ClaimHTLC => {
                let data = from_bytes::<ClaimHTLC>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::Batch => {
                let data = from_bytes::<Batch>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::VerifiedComputation => {
                let data = from_bytes::<VerifiedComputation>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::DeployProgram => {
                let data = from_bytes::<DeployProgram>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::ComputeReference => {
                let data = from_bytes::<ComputeReference>(tx.data_bytes(), false)?;
                data.process(tx, hash, self)
            }
            TxKind::Generated => Err(Error::Invalid("Generated as individual tx".to_owned())),
        }
    }
}
