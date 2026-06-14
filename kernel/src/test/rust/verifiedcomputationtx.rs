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

extern crate alloc;

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
use blacknet_kernel::verifiedcomputation::{ACTIVATION_HEIGHT, compute_fee};
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
    programs: alloc::collections::BTreeMap<[u8; 32], alloc::boxed::Box<[u8]>>,
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
    fn add_program(
        &mut self,
        id: blacknet_kernel::transaction::ProgramId,
        code: alloc::boxed::Box<[u8]>,
    ) {
        self.programs.insert(id, code);
    }
    fn has_program(&mut self, id: blacknet_kernel::transaction::ProgramId) -> bool {
        self.programs.contains_key(&id)
    }
    fn get_program(
        &mut self,
        id: blacknet_kernel::transaction::ProgramId,
    ) -> blacknet_kernel::error::Result<alloc::boxed::Box<[u8]>> {
        self.programs
            .get(&id)
            .cloned()
            .ok_or_else(|| blacknet_kernel::error::Error::Invalid("unknown program".into()))
    }
}

fn payload(program: &[Instruction<F>], input: i32) -> Vec<u8> {
    let (io, proof) = prove(program, &[f(input)], 100).unwrap();
    encode_compute(program, &io, &proof)
}

fn run_at_height(payload: Vec<u8>, height: u32) -> blacknet_kernel::error::Result<()> {
    let fee = compute_fee(payload.len()); // pay exactly the required floor
    run_with_fee(payload, height, fee)
}

fn run_with_fee(payload: Vec<u8>, height: u32, fee: u64) -> blacknet_kernel::error::Result<()> {
    let data = VerifiedComputation::new(payload.into_boxed_slice());
    let mut state = HeightOnly {
        height,
        programs: Default::default(),
    };
    let tx = Transaction::new(
        PublicKey::default(),
        0,
        Hash::default(),
        Amt::new(fee),
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

#[test]
fn insufficient_fee_rejected() {
    // A fee below the verification cost must be rejected BEFORE the expensive
    // verify - the DoS/economic-soundness guard.
    let p = payload(&square_add(), 6);
    let too_low = compute_fee(p.len()) - 1;
    assert!(run_with_fee(p, ACTIVATION_HEIGHT as u32, too_low).is_err());
}

#[test]
fn exact_fee_accepted() {
    let p = payload(&square_add(), 6);
    let exact = compute_fee(p.len());
    assert!(run_with_fee(p, ACTIVATION_HEIGHT as u32, exact).is_ok());
}

#[test]
fn fee_scales_with_payload() {
    // The required fee grows with payload size, so a larger proof costs more
    // to submit - the per-byte charge that prices verification work.
    let small = payload(&square_add(), 6);
    let big_program = {
        let mut v = vec![Instruction::LoadImm(1, f(1))];
        for _ in 0..50 {
            v.push(Instruction::Add(1, 1, 1));
        }
        v.push(Instruction::Halt);
        v
    };
    let big = payload(&big_program, 1);
    assert!(compute_fee(big.len()) > compute_fee(small.len()));
}

#[test]
fn verification_is_deterministic() {
    // Every validating node must reach the same decision. Verifying the same
    // payload twice yields the same result - Fiat-Shamir makes verification a
    // pure function of the bytes, a consensus requirement.
    let p = payload(&square_add(), 6);
    let a = run_at_height(p.clone(), ACTIVATION_HEIGHT as u32);
    let b = run_at_height(p, ACTIVATION_HEIGHT as u32);
    assert_eq!(a.is_ok(), b.is_ok());
    assert!(a.is_ok());
}

// ---- Registry-referenced flow: deploy once, then cite by id ----

use blacknet_kernel::transaction::{ComputeReference, DeployProgram, program_id};
use blacknet_snark::commitment::commit;
use blacknet_snark::wire::{encode_program, encode_reference};

fn deploy_into(state: &mut HeightOnly, program: &[Instruction<F>], fee: u64) -> Result<()> {
    let payload = encode_program(program);
    let data = DeployProgram::new(payload.into_boxed_slice());
    let tx = Transaction::new(
        PublicKey::default(),
        0,
        Hash::default(),
        Amt::new(fee),
        TxKind::DeployProgram,
        Default::default(),
    );
    data.process_impl(&tx, Hash::default(), 0, state)
}

fn reference_into(state: &mut HeightOnly, payload: Vec<u8>, fee: u64) -> Result<()> {
    let data = ComputeReference::new(payload.into_boxed_slice());
    let tx = Transaction::new(
        PublicKey::default(),
        0,
        Hash::default(),
        Amt::new(fee),
        TxKind::ComputeReference,
        Default::default(),
    );
    data.process_impl(&tx, Hash::default(), 0, state)
}

use blacknet_kernel::error::Result;

#[test]
fn deploy_then_reference_accepted() {
    let mut state = HeightOnly {
        height: ACTIVATION_HEIGHT as u32,
        programs: Default::default(),
    };
    let prog = square_add();
    // Deploy once.
    let dp = encode_program(&prog);
    assert!(deploy_into(&mut state, &prog, compute_fee(dp.len())).is_ok());

    // Reference it: only IO + proof travel, the program is in state.
    let id = commit(&prog);
    let (io, proof) = prove(&prog, &[f(6)], 100).unwrap();
    let payload = encode_reference(&id, &io, &proof);
    assert!(reference_into(&mut state, payload.clone(), compute_fee(payload.len())).is_ok());
}

#[test]
fn reference_before_deploy_rejected() {
    let mut state = HeightOnly {
        height: ACTIVATION_HEIGHT as u32,
        programs: Default::default(),
    };
    let prog = square_add();
    let id = commit(&prog);
    let (io, proof) = prove(&prog, &[f(6)], 100).unwrap();
    let payload = encode_reference(&id, &io, &proof);
    // Never deployed: the lookup fails.
    assert!(reference_into(&mut state, payload.clone(), compute_fee(payload.len())).is_err());
}

#[test]
fn redeploy_rejected() {
    let mut state = HeightOnly {
        height: ACTIVATION_HEIGHT as u32,
        programs: Default::default(),
    };
    let prog = square_add();
    let dp = encode_program(&prog);
    let fee = compute_fee(dp.len());
    assert!(deploy_into(&mut state, &prog, fee).is_ok());
    // Same id again: rejected (one id, one program).
    assert!(deploy_into(&mut state, &prog, fee).is_err());
}

#[test]
fn reference_with_wrong_id_rejected() {
    // Deploy program A, then reference a DIFFERENT id that is not deployed.
    let mut state = HeightOnly {
        height: ACTIVATION_HEIGHT as u32,
        programs: Default::default(),
    };
    let prog = square_add();
    let dp = encode_program(&prog);
    assert!(deploy_into(&mut state, &prog, compute_fee(dp.len())).is_ok());

    // A proof for a different program, cited under that other program's id.
    let other = vec![Instruction::Add(2, 1, 1), Instruction::Halt];
    let other_id = commit(&other);
    let (io, proof) = prove(&other, &[f(3)], 100).unwrap();
    let payload = encode_reference(&other_id, &io, &proof);
    // other_id was never deployed -> rejected.
    assert!(reference_into(&mut state, payload.clone(), compute_fee(payload.len())).is_err());
}

#[test]
fn reference_insufficient_fee_rejected() {
    let mut state = HeightOnly {
        height: ACTIVATION_HEIGHT as u32,
        programs: Default::default(),
    };
    let prog = square_add();
    let dp = encode_program(&prog);
    deploy_into(&mut state, &prog, compute_fee(dp.len())).unwrap();
    let id = commit(&prog);
    let (io, proof) = prove(&prog, &[f(6)], 100).unwrap();
    let payload = encode_reference(&id, &io, &proof);
    let low = compute_fee(payload.len()) - 1;
    assert!(reference_into(&mut state, payload, low).is_err());
}

#[test]
fn program_id_is_deterministic() {
    let prog = square_add();
    assert_eq!(program_id(&commit(&prog)), program_id(&commit(&prog)));
    let other = vec![Instruction::Halt];
    assert_ne!(program_id(&commit(&prog)), program_id(&commit(&other)));
}
