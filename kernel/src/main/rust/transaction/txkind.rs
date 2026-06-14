/*
 * Copyright (c) 2018-2025 Pavel Vasin
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

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u8)]
pub enum TxKind {
    Transfer = 0,
    Burn = 1,
    Lease = 2,
    CancelLease = 3,
    Blob = 4,
    CreateHTLC = 5,
    RefundHTLC = 7,
    CreateMultisig = 9,
    SpendMultisig = 10,
    WithdrawFromLease = 11,
    ClaimHTLC = 12,
    // Dispel = 13,
    Batch = 16,
    VerifiedComputation = 17,
    DeployProgram = 18,
    ComputeReference = 19,
    // Genesis = 125,
    Generated = 254,
}
