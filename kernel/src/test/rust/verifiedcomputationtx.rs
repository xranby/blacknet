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

//! End-to-end: a verified-computation transaction validated through the
//! chain's transaction-processing path. This is the proof that zkFi apps are
//! deployable — a real proof, encoded as the on-chain payload, accepted (or
//! rejected) by the same `process_impl` a block would run.

use blacknet_kernel::account::Account;
use blacknet_kernel::amount::Amount;
use blacknet_kernel::amount::Amount as Amt;
use blacknet_kernel::blake2b::Hash;
use blacknet_kernel::ed25519::PublicKey;
use blacknet_kernel::htlc::HTLC;
use blacknet_kernel::multisig::Multisig;
use blacknet_kernel::transaction::{
    CoinTx, HashTimeLockContractId, MultiSignatureLockContractId, Transaction, TxData, TxKind,
    VerifiedComputation,
};
use blacknet_kernel::verifiedcomputation::ACTIVATION_HEIGHT;
use blacknet_snark::proof::prove;
use blacknet_snark::wire::encode_compute;
use blacknet_snark::witnesscommitment::F;
use blacknet_time::Seconds;
use blacknet_vm::machine::Instruction;

fn f(n: i32) -> F {
    F::from(n)
}

fn square_add() -> Vec<Instruction<F>> {
    vec![
        Instruction::Mul(2, 1, 1),
        Instruction::Add(3, 2, 1),
        Instruction::Halt,
    ]
}

/// Minimal CoinTx whose only meaningful field is the block height, which is
/// all the verified-computation `process_impl` consults. Other methods are
/// unreachable on this path and panic if called.
struct HeightOnly {
    height: u32,
}

impl CoinTx for HeightOnly {
    fn add_supply(&mut self, _: Amount) {}
    fn sub_supply(&mut self, _: Amount) {}
    fn check_anchor(&self, _: Hash) -> blacknet_kernel::error::Result<()> {
        Ok(())
    }
    fn block_hash(&self) -> Hash {
        Hash::default()
    }
    fn block_time(&self) -> Seconds {
        Seconds::default()
    }
    fn height(&self) -> u32 {
        self.height
    }
    fn get_account(
        &mut self,
        _: blacknet_kernel::ed25519::PublicKey,
    ) -> blacknet_kernel::error::Result<Account> {
        unreachable!()
    }
    fn get_or_create(&mut self, _: blacknet_kernel::ed25519::PublicKey) -> Account {
        unreachable!()
    }
    fn set_account(&mut self, _: blacknet_kernel::ed25519::PublicKey, _: Account) {
        unreachable!()
    }
    fn add_htlc(&mut self, _: HashTimeLockContractId, _: HTLC) {}
    fn get_htlc(&mut self, _: HashTimeLockContractId) -> blacknet_kernel::error::Result<HTLC> {
        unreachable!()
    }
    fn remove_htlc(&mut self, _: HashTimeLockContractId) {}
    fn add_multisig(&mut self, _: MultiSignatureLockContractId, _: Multisig) {}
    fn get_multisig(
        &mut self,
        _: MultiSignatureLockContractId,
    ) -> blacknet_kernel::error::Result<Multisig> {
        unreachable!()
    }
    fn remove_multisig(&mut self, _: MultiSignatureLockContractId) {}
}

fn payload(program: &[Instruction<F>], input: i32) -> Vec<u8> {
    let (io, proof) = prove(program, &[f(input)], 100).unwrap();
    encode_compute(program, &io, &proof)
}

fn run_at_height(payload: Vec<u8>, height: u32) -> blacknet_kernel::error::Result<()> {
    let data = VerifiedComputation::new(payload.into_boxed_slice());
    let mut state = HeightOnly { height };
    let tx = Transaction::new(
        PublicKey::default(),
        0,
        Hash::default(),
        Amt::default(),
        TxKind::VerifiedComputation,
        Default::default(),
    );
    data.process_impl(&tx, Hash::default(), 0, &mut state)
}

#[test]
fn valid_proof_accepted_after_activation() {
    let p = payload(&square_add(), 6);
    assert!(run_at_height(p, ACTIVATION_HEIGHT as u32).is_ok());
}

#[test]
fn rejected_before_activation() {
    let p = payload(&square_add(), 6);
    assert!(run_at_height(p, (ACTIVATION_HEIGHT as u32).saturating_sub(1)).is_err());
}

#[test]
fn corrupt_payload_rejected() {
    let mut p = payload(&square_add(), 6);
    let n = p.len();
    p[n / 2] ^= 0xFF; // flip a byte in the middle
    assert!(run_at_height(p, ACTIVATION_HEIGHT as u32).is_err());
}

#[test]
fn truncated_payload_rejected() {
    let mut p = payload(&square_add(), 6);
    p.truncate(p.len() - 1);
    assert!(run_at_height(p, ACTIVATION_HEIGHT as u32).is_err());
}

#[test]
fn trailing_bytes_rejected() {
    let mut p = payload(&square_add(), 6);
    p.push(0); // canonical encodings are exact
    assert!(run_at_height(p, ACTIVATION_HEIGHT as u32).is_err());
}

#[test]
fn bad_wire_version_rejected() {
    let mut p = payload(&square_add(), 6);
    p[0] = 0xEE; // unaccepted wire version
    assert!(run_at_height(p, ACTIVATION_HEIGHT as u32).is_err());
}

#[test]
fn forged_proof_rejected() {
    // Tamper a field element deep in the proof body: the folded verification
    // must reject it even though the envelope decodes.
    let mut p = payload(&square_add(), 6);
    let n = p.len();
    // Corrupt near the end (proof witness region) without breaking length.
    p[n - 9] ^= 0x01;
    assert!(run_at_height(p, ACTIVATION_HEIGHT as u32).is_err());
}

#[test]
fn roundtrip_payload_decodes() {
    use blacknet_snark::wire::decode_compute;
    let program = square_add();
    let (io, proof) = prove(&program, &[f(6)], 100).unwrap();
    let bytes = encode_compute(&program, &io, &proof);
    let (dp, dio, dproof) = decode_compute(&bytes).unwrap();
    assert_eq!(dp, program);
    assert_eq!(dio, io);
    assert_eq!(dproof, proof);
}
