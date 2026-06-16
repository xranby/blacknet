/*
 * Copyright (c) 2019-2025 Pavel Vasin
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

use crate::v2::error::Result;
use crate::v2::txdatainfo::*;
use blacknet_kernel::transaction::{Batch, TxKind};
use blacknet_serialization::format::from_bytes;
use blacknet_wallet::address::AddressCodec;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, to_value};

#[derive(Deserialize, Serialize)]
pub struct TxDataInfo {
    r#type: u8,
    dataIndex: u32,
    data: Value,
}

impl TxDataInfo {
    pub fn new(kind: TxKind, data: &[u8], address_codec: &AddressCodec) -> Result<Vec<Self>> {
        if kind == TxKind::Generated {
            Ok(vec![Self {
                r#type: kind as u8,
                dataIndex: 0,
                data: Value::Object(Map::new()),
            }])
        } else if kind != TxKind::Batch {
            Ok(vec![Self::single(kind, 0, data, address_codec)?])
        } else {
            let batch = from_bytes::<Batch>(data, false)?;
            let mut result = Vec::with_capacity(batch.len());
            for (index, batchee) in batch.multi_data().iter().enumerate() {
                result.push(Self::single(
                    batchee.kind(),
                    index + 1,
                    batchee.data_bytes(),
                    address_codec,
                )?);
            }
            Ok(result)
        }
    }

    fn single(
        kind: TxKind,
        data_index: usize,
        data: &[u8],
        address_codec: &AddressCodec,
    ) -> Result<Self> {
        let data = match kind {
            TxKind::Batch => unreachable!(),
            TxKind::Blob => to_value(BlobInfo::new(data, address_codec)?)?,
            TxKind::Burn => to_value(BurnInfo::new(data)?)?,
            TxKind::CancelLease => to_value(CancelLeaseInfo::new(data, address_codec)?)?,
            TxKind::ClaimHTLC => to_value(ClaimHTLCInfo::new(data, address_codec)?)?,
            TxKind::CreateHTLC => to_value(CreateHTLCInfo::new(data, address_codec)?)?,
            TxKind::CreateMultisig => to_value(CreateMultisigInfo::new(data, address_codec)?)?,
            // TxKind::Dispel => to_value(DispelInfo::new(data)?)?,
            TxKind::Generated => unreachable!(),
            TxKind::Lease => to_value(LeaseInfo::new(data, address_codec)?)?,
            TxKind::RefundHTLC => to_value(RefundHTLCInfo::new(data, address_codec)?)?,
            TxKind::SpendMultisig => to_value(SpendMultisigInfo::new(data, address_codec)?)?,
            TxKind::Transfer => to_value(TransferInfo::new(data, address_codec)?)?,
            TxKind::VerifiedComputation => to_value(VerifiedComputationInfo::new(data)?)?,
            TxKind::DeployProgram => to_value(DeployProgramInfo::new(data)?)?,
            TxKind::ComputeReference => to_value(ComputeReferenceInfo::new(data)?)?,
            TxKind::ComputeReferenceSuccinct => to_value(ComputeReferenceSuccinctInfo::new(data)?)?,
            TxKind::WithdrawFromLease => {
                to_value(WithdrawFromLeaseInfo::new(data, address_codec)?)?
            }
        };
        Ok(Self {
            r#type: kind as u8,
            dataIndex: data_index as u32,
            data,
        })
    }
}
