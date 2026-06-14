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

use blacknet_crypto::bigint::UInt256;
use blacknet_kernel::amount::Amount;
use blacknet_kernel::blake2b::Hash;
use blacknet_kernel::ed25519::PublicKey;
use blacknet_kernel::transaction::{
    HashTimeLockContractId, MultiSignatureLockContractId, ProgramId,
};
use blacknet_time::Seconds;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct UndoBlock {
    block_time: Seconds,
    difficulty: UInt256,
    cumulative_difficulty: UInt256,
    supply: Amount,
    nxtrng: Hash,
    rolling_checkpoint: Hash,
    upgraded: u16,
    block_size: u32,
    accounts: Vec<(PublicKey, Option<Box<[u8]>>)>,
    htlcs: Vec<(HashTimeLockContractId, Option<Box<[u8]>>)>,
    multisigs: Vec<(MultiSignatureLockContractId, Option<Box<[u8]>>)>,
    programs: Vec<(ProgramId, Option<Box<[u8]>>)>,
    fork_v2: u16,
    blobs: Vec<(Box<[u8]>, Option<Box<[u8]>>)>,
}

impl UndoBlock {
    pub const fn new(
        block_time: Seconds,
        difficulty: UInt256,
        cumulative_difficulty: UInt256,
        supply: Amount,
        nxtrng: Hash,
        rolling_checkpoint: Hash,
        upgraded: u16,
        block_size: u32,
        fork_v2: u16,
    ) -> Self {
        Self {
            block_time,
            difficulty,
            cumulative_difficulty,
            supply,
            nxtrng,
            rolling_checkpoint,
            upgraded,
            block_size,
            accounts: Vec::new(),
            htlcs: Vec::new(),
            multisigs: Vec::new(),
            programs: Vec::new(),
            fork_v2,
            blobs: Vec::new(),
        }
    }

    pub fn add(&mut self, public_key: PublicKey, account: Option<Box<[u8]>>) {
        self.accounts.push((public_key, account));
    }

    pub fn add_htlc(&mut self, id: HashTimeLockContractId, htlc: Option<Box<[u8]>>) {
        self.htlcs.push((id, htlc));
    }

    pub fn add_program(&mut self, id: ProgramId, code: Option<Box<[u8]>>) {
        self.programs.push((id, code));
    }

    pub fn add_multisig(&mut self, id: MultiSignatureLockContractId, multisig: Option<Box<[u8]>>) {
        self.multisigs.push((id, multisig));
    }

    pub fn add_blob(&mut self, key: Box<[u8]>, data: Option<Box<[u8]>>) {
        self.blobs.push((key, data));
    }
}
