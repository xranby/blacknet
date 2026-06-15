/*
 * Copyright (c) 2019-2026 Pavel Vasin
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

use crate::blake2b::Hash;
use crate::error::{Error, Result};
use crate::transaction::*;
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::format;
use blacknet_serialization::format::from_bytes;
use serde::{Deserialize, Serialize};

pub const MIN_SIZE: usize = 2;
pub const MAX_SIZE: usize = 20;

#[derive(Deserialize, Serialize)]
pub struct Batchee {
    kind: TxKind,
    data: Box<[u8]>,
}

impl Batchee {
    pub const fn kind(&self) -> TxKind {
        self.kind
    }

    pub const fn data_bytes(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Deserialize, Serialize)]
pub struct Batch {
    multi_data: Box<[Batchee]>,
}

impl Batch {
    pub const fn new(multi_data: Box<[Batchee]>) -> Self {
        Self { multi_data }
    }

    pub const fn is_empty(&self) -> bool {
        self.multi_data.is_empty()
    }

    pub const fn len(&self) -> usize {
        self.multi_data.len()
    }

    pub const fn multi_data(&self) -> &[Batchee] {
        &self.multi_data
    }
}

impl TxData for Batch {
    fn process_impl(
        &self,
        tx: &Transaction,
        hash: Hash,
        data_index: u32,
        coin_tx: &mut impl CoinTx,
    ) -> Result<()> {
        if data_index != 0 {
            return Err(Error::Invalid(
                "Batch is not permitted to contain Batch".to_owned(),
            ));
        }
        let len = self.multi_data.len();
        if !(MIN_SIZE..=MAX_SIZE).contains(&len) {
            return Err(Error::Invalid(format!("Invalid Batch size {len}")));
        }

        for index in 0..len {
            let kind = self.multi_data[index].kind();
            let data_bytes = self.multi_data[index].data_bytes();
            match kind {
                TxKind::Transfer => {
                    let data = from_bytes::<Transfer>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::Burn => {
                    let data = from_bytes::<Burn>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::Lease => {
                    let data = from_bytes::<Lease>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::CancelLease => {
                    let data = from_bytes::<CancelLease>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::Blob => {
                    let data = from_bytes::<Blob>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::CreateHTLC => {
                    let data = from_bytes::<CreateHTLC>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::RefundHTLC => {
                    let data = from_bytes::<RefundHTLC>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::CreateMultisig => {
                    let data = from_bytes::<CreateMultisig>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::SpendMultisig => {
                    let data = from_bytes::<SpendMultisig>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::WithdrawFromLease => {
                    let data = from_bytes::<WithdrawFromLease>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::ClaimHTLC => {
                    let data = from_bytes::<ClaimHTLC>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::Batch => {
                    let data = from_bytes::<Batch>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::VerifiedComputation => {
                    let data = from_bytes::<VerifiedComputation>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::DeployProgram => {
                    let data = from_bytes::<DeployProgram>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::ComputeReference => {
                    let data = from_bytes::<ComputeReference>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::ComputeReferenceSuccinct => {
                    let data = from_bytes::<ComputeReferenceSuccinct>(data_bytes, false)?;
                    data.process_impl(tx, hash, (index + 1) as u32, coin_tx)?;
                }
                TxKind::Generated => {
                    return Err(Error::Invalid("Generated as individual tx".to_owned()));
                }
            }
        }

        Ok(())
    }
}
