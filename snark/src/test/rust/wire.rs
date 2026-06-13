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

use blacknet_snark::proof::{Proof, prove};
use blacknet_snark::wire::{Error, Reader, WIRE_VERSION, Writer};
use blacknet_snark::witnesscommitment::F;
use blacknet_vm::machine::Instruction;

fn f(n: i32) -> F {
    F::from(n)
}

fn fib() -> Vec<Instruction<F>> {
    vec![
        Instruction::LoadImm(2, f(0)),
        Instruction::LoadImm(3, f(1)),
        Instruction::LoadImm(4, f(1)),
        Instruction::Add(5, 2, 3),
        Instruction::Mov(2, 3),
        Instruction::Mov(3, 5),
        Instruction::Sub(1, 1, 4),
        Instruction::Bne(1, 0, 3),
        Instruction::Halt,
    ]
}

#[test]
fn field_roundtrip_canonical() {
    let mut w = Writer::new();
    for x in [f(0), f(1), f(-1), f(123456), -f(7)] {
        w.field(x);
    }
    let bytes = w.finish();
    let mut r = Reader::new(&bytes);
    for x in [f(0), f(1), f(-1), f(123456), -f(7)] {
        assert_eq!(r.field().unwrap(), x);
    }
    assert!(r.finish().is_ok());
}

#[test]
fn proof_roundtrip() {
    let program = fib();
    let (_io, proof) = prove(&program, &[f(10)], 1000).unwrap();
    let bytes = proof.encode();
    // Version-prefixed.
    assert_eq!(bytes[0], WIRE_VERSION);
    let decoded = Proof::decode(&bytes).unwrap();
    assert_eq!(decoded.pc_trace, proof.pc_trace);
    assert_eq!(decoded.witness, proof.witness);
}

#[test]
fn encoding_is_deterministic() {
    // The same proof encodes to identical bytes every time - the consensus
    // requirement.
    let (_io, proof) = prove(&fib(), &[f(7)], 1000).unwrap();
    assert_eq!(proof.encode(), proof.encode());
}

#[test]
fn truncated_rejected() {
    let (_io, proof) = prove(&fib(), &[f(5)], 1000).unwrap();
    let bytes = proof.encode();
    assert_eq!(
        Proof::decode(&bytes[..bytes.len() - 1]).unwrap_err(),
        Error::Truncated
    );
}

#[test]
fn trailing_bytes_rejected() {
    let (_io, proof) = prove(&fib(), &[f(5)], 1000).unwrap();
    let mut bytes = proof.encode();
    bytes.push(0);
    assert_eq!(Proof::decode(&bytes).unwrap_err(), Error::Overlong);
}

#[test]
fn bad_version_rejected() {
    let (_io, proof) = prove(&fib(), &[f(5)], 1000).unwrap();
    let mut bytes = proof.encode();
    bytes[0] = 99;
    assert_eq!(Proof::decode(&bytes).unwrap_err(), Error::BadVersion(99));
}

#[test]
fn non_canonical_field_rejected() {
    // A field element >= q must be rejected (canonical encodings only).
    let mut w = Writer::new();
    w.version(WIRE_VERSION);
    w.version(0);
    w.u32_slice(&[0]);
    // hand-write a length-1 field vec with an out-of-range value.
    w.u32(1);
    let mut bytes = w.finish();
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(Proof::decode(&bytes).unwrap_err(), Error::NonCanonical);
}

#[test]
fn overlong_vector_rejected() {
    // A length prefix above the DoS cap is rejected before allocation.
    let mut w = Writer::new();
    w.version(WIRE_VERSION);
    w.version(0);
    w.u32(u32::MAX); // pc_trace length claims 4 billion entries
    let bytes = w.finish();
    assert_eq!(Proof::decode(&bytes).unwrap_err(), Error::Overlong);
}
