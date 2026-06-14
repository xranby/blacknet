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

use crate::v2::ByteArrayInfo;
use crate::v2::error::Result;
use blacknet_kernel::transaction::DeployProgram;
use blacknet_serialization::format::from_bytes;
use serde::{Deserialize, Serialize};

/// RPC view of a DeployProgram transaction: its canonically-encoded
/// verified-computation payload as a byte array. The payload bundles the
/// program (or cited id), public IO, and proof; clients that wish to inspect
/// its structure decode it with the snark wire codec.
#[derive(Deserialize, Serialize)]
pub struct DeployProgramInfo {
    payload: ByteArrayInfo,
}

impl DeployProgramInfo {
    pub fn new(data: &[u8]) -> Result<Self> {
        let tx = from_bytes::<DeployProgram>(data, false)?;
        Ok(Self {
            payload: tx.payload().into(),
        })
    }
}
