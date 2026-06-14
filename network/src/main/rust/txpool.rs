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

use crate::coindb::CoinDB;
use crate::settings::Settings;
use blacknet_kernel::account::Account;
use blacknet_kernel::amount::Amount;
use blacknet_kernel::blake2b::Hash;
use blacknet_kernel::ed25519::PublicKey;
use blacknet_kernel::error::{Error, Result};
use blacknet_kernel::htlc::HTLC;
use blacknet_kernel::multisig::Multisig;
use blacknet_kernel::transaction::{
    CoinTx, HashTimeLockContractId, MultiSignatureLockContractId, ProgramId, Transaction,
};
use blacknet_log::{Error as LogError, LogManager, Logger, debug, warn};
use blacknet_serialization::format::from_bytes;
use blacknet_time::{Milliseconds, Seconds};
use std::collections::{HashMap, HashSet, hash_map::Keys};
use std::sync::Arc;

pub struct TxPool {
    logger: Logger,
    settings: Arc<Settings>,
    map: HashMap<Hash, Box<[u8]>>,
    rejects: HashSet<Hash>,
    data_len: usize,
    accounts: HashMap<PublicKey, Account>,
    htlcs: HashMap<HashTimeLockContractId, Option<HTLC>>,
    multisigs: HashMap<MultiSignatureLockContractId, Option<Multisig>>,
    programs: HashMap<ProgramId, Option<Box<[u8]>>>,
    transactions: Vec<Hash>,
    undo_accounts: HashMap<PublicKey, Option<Account>>,
    undo_htlcs: HashMap<HashTimeLockContractId, (bool, Option<HTLC>)>,
    undo_multisigs: HashMap<MultiSignatureLockContractId, (bool, Option<Multisig>)>,
    coin_db: Arc<CoinDB>,
}

impl TxPool {
    pub fn new(
        log_manager: &LogManager,
        settings: Arc<Settings>,
        coin_db: Arc<CoinDB>,
    ) -> core::result::Result<Self, LogError> {
        Ok(Self {
            logger: log_manager.logger("TxPool")?,
            settings,
            map: HashMap::new(),
            rejects: HashSet::new(),
            data_len: 0,
            accounts: HashMap::new(),
            htlcs: HashMap::new(),
            multisigs: HashMap::new(),
            programs: HashMap::new(),
            transactions: Vec::new(),
            undo_accounts: HashMap::new(),
            undo_htlcs: HashMap::new(),
            undo_multisigs: HashMap::new(),
            coin_db,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub const fn data_len(&self) -> usize {
        self.data_len
    }

    pub fn min_fee_rate(&self) -> Amount {
        self.settings.min_relay_fee_rate
    }

    pub fn hashes(&self) -> Keys<'_, Hash, Box<[u8]>> {
        self.map.keys()
    }

    pub fn get_raw(&self, hash: Hash) -> Option<&[u8]> {
        self.map.get(&hash).map(|x| &**x)
    }

    pub fn is_interesting(&self, hash: Hash) -> bool {
        !self.rejects.contains(&hash) && !self.map.contains_key(&hash)
    }

    pub fn process(
        &mut self,
        hash: Hash,
        bytes: &[u8],
        time: Milliseconds,
        remote: bool,
    ) -> Result<Amount> {
        if self.rejects.contains(&hash) {
            return Err(Error::Invalid("Already rejected tx".to_owned()));
        }
        if self.map.contains_key(&hash) {
            return Err(Error::AlreadyHave(hash.to_string()));
        }
        if self.data_len + bytes.len() > self.settings.tx_pool_size {
            if remote {
                return Err(Error::InFuture("TxPool is full".to_owned()));
            } else {
                warn!(self.logger, "TxPool is full");
            }
        }
        let result = self.process_impl_with_fee(hash, bytes, time);
        if matches!(result, Err(Error::Invalid(_)) | Err(Error::InFuture(_))) {
            self.rejects.insert(hash);
        }
        result
    }

    fn process_impl_with_fee(
        &mut self,
        hash: Hash,
        bytes: &[u8],
        _time: Milliseconds,
    ) -> Result<Amount> {
        let tx = from_bytes::<Transaction>(bytes, false)?;
        let fee = tx.fee();
        self.check_fee(bytes.len() as u32, fee)?;
        let result = self.process_transaction_impl(&tx, hash);
        self.undo_impl(result)?;
        self.map.insert(hash, bytes.into());
        self.data_len += bytes.len();
        self.transactions.push(hash);
        //TODO wallet
        //TODO rpc
        debug!(self.logger, "Accepted {hash}");
        Ok(fee)
    }

    fn check_fee(&self, size: u32, amount: Amount) -> Result<()> {
        if amount >= self.settings.min_relay_fee_rate * (1 + size / 1000).into() {
            Ok(())
        } else {
            Err(Error::Invalid(format!("Too low fee {}", amount)))
        }
    }

    fn undo_impl(&mut self, result: Result<()>) -> Result<()> {
        if result.is_ok() {
            self.undo_accounts.clear();
            self.undo_htlcs.clear();
            self.undo_multisigs.clear();
        } else {
            self.undo_accounts.drain().for_each(|(key, account)| {
                match account {
                    Some(account) => self.accounts.insert(key, account),
                    None => self.accounts.remove(&key),
                };
            });
            self.undo_htlcs.drain().for_each(|(id, (insert, htlc))| {
                if insert {
                    self.htlcs.insert(id, htlc);
                } else {
                    self.htlcs.remove(&id);
                }
            });
            self.undo_multisigs
                .drain()
                .for_each(|(id, (insert, multisig))| {
                    if insert {
                        self.multisigs.insert(id, multisig);
                    } else {
                        self.multisigs.remove(&id);
                    }
                });
        }
        result
    }
}

impl CoinTx for TxPool {
    fn add_supply(&mut self, _amount: Amount) {}

    fn sub_supply(&mut self, _amount: Amount) {}

    fn check_anchor(&self, hash: Hash) -> Result<()> {
        self.coin_db.check_anchor(hash)
    }

    fn block_hash(&self) -> Hash {
        self.coin_db.state().block_hash()
    }

    fn block_time(&self) -> Seconds {
        self.coin_db.state().block_time()
    }

    fn height(&self) -> u32 {
        self.coin_db.state().height()
    }

    fn get_account(&mut self, key: PublicKey) -> Result<Account> {
        match self.accounts.get(&key) {
            Some(account) => {
                self.undo_accounts
                    .entry(key)
                    .or_insert_with(|| Some(account.clone()));
                Ok(account.clone())
            }
            None => {
                let db_account = self.coin_db.account(key);
                self.undo_accounts.insert(key, None);
                db_account.ok_or(Error::Invalid("Account not found".to_owned()))
            }
        }
    }

    fn get_or_create(&mut self, key: PublicKey) -> Account {
        match self.get_account(key) {
            Ok(account) => account,
            Err(_) => {
                self.undo_accounts.insert(key, None);
                Account::new()
            }
        }
    }

    fn set_account(&mut self, key: PublicKey, state: Account) {
        self.accounts.insert(key, state);
    }

    fn add_htlc(&mut self, id: HashTimeLockContractId, htlc: HTLC) {
        self.undo_htlcs.insert(id, (false, None));
        self.htlcs.insert(id, Some(htlc));
    }

    fn get_htlc(&mut self, id: HashTimeLockContractId) -> Result<HTLC> {
        if !self.htlcs.contains_key(&id) {
            self.undo_htlcs.insert(id, (false, None));
            self.coin_db
                .htlc(id)
                .ok_or(Error::Invalid("HTLC not found".to_owned()))
        } else {
            let htlc = self.htlcs.get(&id).cloned().flatten();
            self.undo_htlcs
                .entry(id)
                .or_insert_with(|| (true, htlc.clone()));
            htlc.ok_or(Error::Invalid("HTLC not found".to_owned()))
        }
    }

    fn remove_htlc(&mut self, id: HashTimeLockContractId) {
        self.htlcs.insert(id, None);
    }

    fn add_multisig(&mut self, id: MultiSignatureLockContractId, multisig: Multisig) {
        self.undo_multisigs.insert(id, (false, None));
        self.multisigs.insert(id, Some(multisig));
    }

    fn get_multisig(&mut self, id: MultiSignatureLockContractId) -> Result<Multisig> {
        if !self.multisigs.contains_key(&id) {
            self.undo_multisigs.insert(id, (false, None));
            self.coin_db
                .multisig(id)
                .ok_or(Error::Invalid("Multisig not found".to_owned()))
        } else {
            let multisig = self.multisigs.get(&id).cloned().flatten();
            self.undo_multisigs
                .entry(id)
                .or_insert_with(|| (true, multisig.clone()));
            multisig.ok_or(Error::Invalid("Multisig not found".to_owned()))
        }
    }

    fn remove_multisig(&mut self, id: MultiSignatureLockContractId) {
        self.multisigs.insert(id, None);
    }

    fn add_program(&mut self, id: ProgramId, code: Box<[u8]>) {
        self.programs.insert(id, Some(code));
    }

    fn has_program(&mut self, id: ProgramId) -> bool {
        match self.programs.get(&id) {
            Some(slot) => slot.is_some(),
            None => self.coin_db.program(id).is_some(),
        }
    }

    fn get_program(&mut self, id: ProgramId) -> Result<Box<[u8]>> {
        match self.programs.get(&id) {
            Some(Some(code)) => Ok(code.clone()),
            Some(None) => Err(Error::Invalid("Program not found".to_owned())),
            None => self
                .coin_db
                .program(id)
                .ok_or(Error::Invalid("Program not found".to_owned())),
        }
    }
}
