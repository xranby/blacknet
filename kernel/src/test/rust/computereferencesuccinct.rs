/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

//! End-to-end: a SUCCINCT referenced computation validated through the chain's
//! transaction-processing path. The program is deployed once; the tx then
//! carries only a succinct AggregateProof (witness omitted, ~constant size),
//! and the same process_impl a block would run reconstructs the shape + key
//! and verifies it, never executing the program.

extern crate alloc;

use blacknet_kernel::amount::Amount as Amt;
use blacknet_kernel::blake2b::Hash;
use blacknet_kernel::ed25519::PublicKey;
use blacknet_kernel::transaction::{
    CoinTx, ComputeReferenceSuccinct, ProgramId, Transaction, TxData, TxKind, program_id,
};
use blacknet_kernel::verifiedcomputation::{ACTIVATION_HEIGHT, compute_fee};
use blacknet_snark::commitment::commit;
use blacknet_snark::pipeline::{Shape, prove_aggregate_succinct, prove_execution};
use blacknet_snark::wire::{encode_program, encode_reference_succinct};
use blacknet_snark::witnesscommitment::{CommitmentKey, F, SECURE_ROWS};
use blacknet_time::Seconds;
use blacknet_vm::machine::Instruction;

fn f(n: i32) -> F {
    F::from(n)
}

fn square() -> Vec<Instruction<F>> {
    vec![Instruction::Mul(2, 1, 1), Instruction::Halt]
}

struct HeightOnly {
    height: u32,
    programs: alloc::collections::BTreeMap<[u8; 32], alloc::boxed::Box<[u8]>>,
}

impl CoinTx for HeightOnly {
    fn add_supply(&mut self, _: Amt) {}
    fn sub_supply(&mut self, _: Amt) {}
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
        _: PublicKey,
    ) -> blacknet_kernel::error::Result<blacknet_kernel::account::Account> {
        unreachable!()
    }
    fn get_or_create(&mut self, _: PublicKey) -> blacknet_kernel::account::Account {
        unreachable!()
    }
    fn set_account(&mut self, _: PublicKey, _: blacknet_kernel::account::Account) {
        unreachable!()
    }
    fn add_htlc(
        &mut self,
        _: blacknet_kernel::transaction::HashTimeLockContractId,
        _: blacknet_kernel::htlc::HTLC,
    ) {
    }
    fn get_htlc(
        &mut self,
        _: blacknet_kernel::transaction::HashTimeLockContractId,
    ) -> blacknet_kernel::error::Result<blacknet_kernel::htlc::HTLC> {
        unreachable!()
    }
    fn remove_htlc(&mut self, _: blacknet_kernel::transaction::HashTimeLockContractId) {}
    fn add_multisig(
        &mut self,
        _: blacknet_kernel::transaction::MultiSignatureLockContractId,
        _: blacknet_kernel::multisig::Multisig,
    ) {
    }
    fn get_multisig(
        &mut self,
        _: blacknet_kernel::transaction::MultiSignatureLockContractId,
    ) -> blacknet_kernel::error::Result<blacknet_kernel::multisig::Multisig> {
        unreachable!()
    }
    fn remove_multisig(&mut self, _: blacknet_kernel::transaction::MultiSignatureLockContractId) {}
    fn add_program(&mut self, id: ProgramId, code: alloc::boxed::Box<[u8]>) {
        self.programs.insert(id, code);
    }
    fn has_program(&mut self, id: ProgramId) -> bool {
        self.programs.contains_key(&id)
    }
    fn get_program(
        &mut self,
        id: ProgramId,
    ) -> blacknet_kernel::error::Result<alloc::boxed::Box<[u8]>> {
        self.programs
            .get(&id)
            .cloned()
            .ok_or_else(|| blacknet_kernel::error::Error::Invalid("unknown program".into()))
    }
}

/// Build a succinct referenced payload for `square()` over the given inputs,
/// plus the deployed-program code bytes to register.
fn build_payload(inputs: &[i32]) -> (Vec<u8>, Vec<u8>) {
    let shape = Shape::derive(square(), &[f(2)], 10_000).unwrap();
    let key = CommitmentKey::setup(shape.elements, SECURE_ROWS);
    let execs: Vec<_> = inputs
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[f(x)]).unwrap())
        .collect();
    let proof = prove_aggregate_succinct(&shape, &key, &execs).unwrap();
    let id = commit(&square());
    let payload = encode_reference_succinct(&id, &proof).unwrap();
    let code = encode_program(&square());
    (payload, code)
}

fn run(
    payload: Vec<u8>,
    code: Option<Vec<u8>>,
    height: u32,
    fee: u64,
) -> blacknet_kernel::error::Result<()> {
    let mut state = HeightOnly {
        height,
        programs: Default::default(),
    };
    if let Some(code) = code {
        let id = commit(&square());
        state.add_program(program_id(&id), code.into_boxed_slice());
    }
    let data = ComputeReferenceSuccinct::new(payload.into_boxed_slice());
    let tx = Transaction::new(
        PublicKey::default(),
        0,
        Hash::default(),
        Amt::new(fee),
        TxKind::ComputeReferenceSuccinct,
        Default::default(),
    );
    data.process_impl(&tx, Hash::default(), 0, &mut state)
}

#[test]
fn succinct_reference_accepted_after_activation() {
    let (payload, code) = build_payload(&[3, 8]);
    let fee = compute_fee(payload.len());
    assert!(
        run(payload, Some(code), ACTIVATION_HEIGHT as u32, fee).is_ok(),
        "a deployed program + succinct proof must verify through process_impl"
    );
}

#[test]
fn succinct_reference_rejected_before_activation() {
    let (payload, code) = build_payload(&[3, 8]);
    let fee = compute_fee(payload.len());
    assert!(run(payload, Some(code), (ACTIVATION_HEIGHT as u32) - 1, fee).is_err());
}

#[test]
fn succinct_reference_rejected_when_program_not_deployed() {
    let (payload, _code) = build_payload(&[3, 8]);
    let fee = compute_fee(payload.len());
    assert!(run(payload, None, ACTIVATION_HEIGHT as u32, fee).is_err());
}

#[test]
fn succinct_reference_rejected_when_fee_below_floor() {
    let (payload, code) = build_payload(&[3, 8]);
    let fee = compute_fee(payload.len()) - 1;
    assert!(run(payload, Some(code), ACTIVATION_HEIGHT as u32, fee).is_err());
}

#[test]
fn succinct_reference_rejected_when_payload_tampered() {
    let (mut payload, code) = build_payload(&[3, 8]);
    let fee = compute_fee(payload.len());
    // Flip a byte inside the public IO region so the statement is rebound.
    let pos = 1 + 4 * 9 + 4 + 2;
    payload[pos] ^= 0xFF;
    assert!(run(payload, Some(code), ACTIVATION_HEIGHT as u32, fee).is_err());
}
