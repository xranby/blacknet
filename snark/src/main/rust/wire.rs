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

//! Canonical wire encoding for proofs.
//!
//! Consensus needs a deterministic, versioned byte format — two nodes must
//! agree on the exact bytes, and the format must be pinnable per protocol
//! height. The Pervushin field is not `serde::Serialize`, and serde formats
//! admit non-canonical encodings anyway, so this is an explicit codec:
//! field elements as 8-byte little-endian canonical representatives, vectors
//! length-prefixed with a `u32`, every structure preceded by a version
//! byte. Decoding rejects malformed input rather than silently accepting it.
//!
//! The format is append-only: new versions add fields after a bumped
//! version byte; the kernel pins accepted versions per height, reusing the
//! existing height-gating mechanism.

use crate::witnesscommitment::F;
use blacknet_crypto::algebra::IntegerRing;
use blacknet_crypto::matrix::DenseVector;

/// Current wire version.
pub const WIRE_VERSION: u8 = 1;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    BadVersion(u8),
    NonCanonical,
    Overlong,
    /// Structurally invalid for this codec (e.g. a succinct encoder handed a
    /// transparent or zero-knowledge aggregate it does not serialize).
    Malformed,
}

/// A growable canonical encoder.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn field(&mut self, x: F) {
        // Canonical representative in [0, q); 8 bytes little-endian.
        let c = x.canonical();
        let u = if c < 0 {
            (c + ((1i64 << 61) - 1)) as u64
        } else {
            c as u64
        };
        self.buf.extend_from_slice(&u.to_le_bytes());
    }

    pub fn u32(&mut self, n: u32) {
        self.buf.extend_from_slice(&n.to_le_bytes());
    }

    pub fn u64(&mut self, n: u64) {
        self.buf.extend_from_slice(&n.to_le_bytes());
    }

    pub fn u128(&mut self, n: u128) {
        self.buf.extend_from_slice(&n.to_le_bytes());
    }

    pub fn field_vec(&mut self, v: &DenseVector<F>) {
        self.u32(v.dimension() as u32);
        for i in 0..v.dimension() {
            self.field(v[i]);
        }
    }

    pub fn field_slice(&mut self, v: &[F]) {
        self.u32(v.len() as u32);
        for &x in v {
            self.field(x);
        }
    }

    pub fn u32_slice(&mut self, v: &[u32]) {
        self.u32(v.len() as u32);
        for &n in v {
            self.u32(n);
        }
    }

    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// A canonical decoder over a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

const Q: u64 = (1 << 61) - 1;
/// Maximum vector length accepted, a DoS guard.
const MAX_LEN: u32 = 1 << 26;

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.pos + n > self.buf.len() {
            return Err(Error::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn version(&mut self, expected: u8) -> Result<(), Error> {
        let v = self.take(1)?[0];
        if v != expected {
            return Err(Error::BadVersion(v));
        }
        Ok(())
    }

    /// Reads a single raw byte (e.g. an inner version tag).
    pub fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    pub fn field(&mut self) -> Result<F, Error> {
        let b = self.take(8)?;
        let u = u64::from_le_bytes(b.try_into().expect("8 bytes"));
        if u >= Q {
            return Err(Error::NonCanonical);
        }
        Ok(<F as IntegerRing>::new(u as i64))
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    pub fn u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().expect("8 bytes")))
    }

    pub fn u128(&mut self) -> Result<u128, Error> {
        let b = self.take(16)?;
        Ok(u128::from_le_bytes(b.try_into().expect("16 bytes")))
    }

    fn len_prefix(&mut self) -> Result<usize, Error> {
        let n = self.u32()?;
        if n > MAX_LEN {
            return Err(Error::Overlong);
        }
        Ok(n as usize)
    }

    pub fn field_vec(&mut self) -> Result<DenseVector<F>, Error> {
        let n = self.len_prefix()?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.field()?);
        }
        Ok(DenseVector::from(v))
    }

    pub fn field_slice(&mut self) -> Result<Vec<F>, Error> {
        let n = self.len_prefix()?;
        (0..n).map(|_| self.field()).collect()
    }

    pub fn u32_slice(&mut self) -> Result<Vec<u32>, Error> {
        let n = self.len_prefix()?;
        (0..n).map(|_| self.u32()).collect()
    }

    /// Confirms the whole buffer was consumed — trailing bytes are an error
    /// (canonical encodings are exact).
    pub const fn finish(self) -> Result<(), Error> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::Overlong)
        }
    }
}

/// Canonical encoding of a full verified-computation payload: the program,
/// its public IO, and the proof, as one self-describing byte string. This is
/// what a `VerifiedComputation` transaction carries on-chain; decoding
/// reconstructs exactly the arguments `proof::verify` consumes, so the
/// on-chain verifier needs nothing beyond these bytes (the program is
/// inline, and `verify` re-derives its commitment).
use crate::proof::{Proof, PublicIO};
use blacknet_vm::machine::Instruction;

/// Opcode tags for instruction encoding (stable on the wire).
mod opcode {
    pub const ADD: u8 = 0;
    pub const SUB: u8 = 1;
    pub const MUL: u8 = 2;
    pub const NEG: u8 = 3;
    pub const LOADIMM: u8 = 4;
    pub const MOV: u8 = 5;
    pub const BEQ: u8 = 6;
    pub const BNE: u8 = 7;
    pub const JUMP: u8 = 8;
    pub const HALT: u8 = 9;
}

impl Writer {
    fn instruction(&mut self, i: &Instruction<F>) {
        match *i {
            Instruction::Add(d, a, b) => {
                self.buf.push(opcode::ADD);
                self.buf.extend_from_slice(&[d, a, b]);
            }
            Instruction::Sub(d, a, b) => {
                self.buf.push(opcode::SUB);
                self.buf.extend_from_slice(&[d, a, b]);
            }
            Instruction::Mul(d, a, b) => {
                self.buf.push(opcode::MUL);
                self.buf.extend_from_slice(&[d, a, b]);
            }
            Instruction::Neg(d, a) => {
                self.buf.push(opcode::NEG);
                self.buf.extend_from_slice(&[d, a]);
            }
            Instruction::LoadImm(d, imm) => {
                self.buf.push(opcode::LOADIMM);
                self.buf.push(d);
                self.field(imm);
            }
            Instruction::Mov(d, a) => {
                self.buf.push(opcode::MOV);
                self.buf.extend_from_slice(&[d, a]);
            }
            Instruction::Beq(a, b, t) => {
                self.buf.push(opcode::BEQ);
                self.buf.extend_from_slice(&[a, b]);
                self.u64(t as u64);
            }
            Instruction::Bne(a, b, t) => {
                self.buf.push(opcode::BNE);
                self.buf.extend_from_slice(&[a, b]);
                self.u64(t as u64);
            }
            Instruction::Jump(t) => {
                self.buf.push(opcode::JUMP);
                self.u64(t as u64);
            }
            Instruction::Halt => self.buf.push(opcode::HALT),
        }
    }
}

impl Reader<'_> {
    fn instruction(&mut self) -> Result<Instruction<F>, Error> {
        let tag = self.byte()?;
        let reg = |r: &mut Self| r.byte();
        Ok(match tag {
            opcode::ADD => Instruction::Add(reg(self)?, reg(self)?, reg(self)?),
            opcode::SUB => Instruction::Sub(reg(self)?, reg(self)?, reg(self)?),
            opcode::MUL => Instruction::Mul(reg(self)?, reg(self)?, reg(self)?),
            opcode::NEG => Instruction::Neg(reg(self)?, reg(self)?),
            opcode::LOADIMM => {
                let d = reg(self)?;
                Instruction::LoadImm(d, self.field()?)
            }
            opcode::MOV => Instruction::Mov(reg(self)?, reg(self)?),
            opcode::BEQ => {
                let (a, b) = (reg(self)?, reg(self)?);
                Instruction::Beq(a, b, self.u64()? as usize)
            }
            opcode::BNE => {
                let (a, b) = (reg(self)?, reg(self)?);
                Instruction::Bne(a, b, self.u64()? as usize)
            }
            opcode::JUMP => Instruction::Jump(self.u64()? as usize),
            opcode::HALT => Instruction::Halt,
            _ => return Err(Error::BadVersion(tag)),
        })
    }
}

/// Encodes `(program, io, proof)` as one canonical, versioned byte string.
#[must_use]
pub fn encode_compute(program: &[Instruction<F>], io: &PublicIO, proof: &Proof) -> Vec<u8> {
    let mut w = Writer::new();
    w.version(WIRE_VERSION);
    // Program.
    w.u32(program.len() as u32);
    for i in program {
        w.instruction(i);
    }
    // Public IO.
    w.field_slice(&io.inputs);
    w.field_slice(&io.outputs);
    // Proof (its own version byte, then body).
    w.version(proof.version);
    w.u32_slice(&proof.pc_trace);
    w.field_slice(&proof.witness);
    w.finish()
}

/// Decodes a verified-computation payload, rejecting malformed, non-canonical
/// or trailing input. Returns exactly the `verify` arguments.
pub fn decode_compute(bytes: &[u8]) -> Result<(Vec<Instruction<F>>, PublicIO, Proof), Error> {
    let mut r = Reader::new(bytes);
    r.version(WIRE_VERSION)?;
    let plen = r.u32()? as usize;
    if plen > (MAX_LEN as usize) {
        return Err(Error::Overlong);
    }
    let mut program = Vec::with_capacity(plen);
    for _ in 0..plen {
        program.push(r.instruction()?);
    }
    let inputs = r.field_slice()?;
    let outputs = r.field_slice()?;
    let proof_version = r.byte()?;
    let pc_trace = r.u32_slice()?;
    let witness = r.field_slice()?;
    r.finish()?;
    Ok((
        program,
        PublicIO { inputs, outputs },
        Proof {
            version: proof_version,
            pc_trace,
            witness,
        },
    ))
}

use crate::commitment::{COMMITMENT_WIDTH, ProgramCommitment};

/// Canonically encodes a program alone — the payload of a program-deploy
/// transaction in the registry-referenced flow. The deployed bytes are what
/// `commit` is later re-derived from, so the stored form is exactly this.
#[must_use]
pub fn encode_program(program: &[Instruction<F>]) -> Vec<u8> {
    let mut w = Writer::new();
    w.version(WIRE_VERSION);
    w.u32(program.len() as u32);
    for i in program {
        w.instruction(i);
    }
    w.finish()
}

/// Decodes a program payload, rejecting malformed / non-canonical / trailing
/// input.
pub fn decode_program(bytes: &[u8]) -> Result<Vec<Instruction<F>>, Error> {
    let mut r = Reader::new(bytes);
    r.version(WIRE_VERSION)?;
    let plen = r.u32()? as usize;
    if plen > (MAX_LEN as usize) {
        return Err(Error::Overlong);
    }
    let mut program = Vec::with_capacity(plen);
    for _ in 0..plen {
        program.push(r.instruction()?);
    }
    r.finish()?;
    Ok(program)
}

/// Canonically encodes a registry-referenced computation: the program id
/// (cited, not carried) together with its public IO and proof. The program
/// itself is fetched from chain state by this id at validation time.
#[must_use]
pub fn encode_reference(program_id: &ProgramCommitment, io: &PublicIO, proof: &Proof) -> Vec<u8> {
    let mut w = Writer::new();
    w.version(WIRE_VERSION);
    for k in 0..COMMITMENT_WIDTH {
        w.field(program_id.0[k]);
    }
    w.field_slice(&io.inputs);
    w.field_slice(&io.outputs);
    w.version(proof.version);
    w.u32_slice(&proof.pc_trace);
    w.field_slice(&proof.witness);
    w.finish()
}

/// Decodes a registry-referenced computation payload.
pub fn decode_reference(bytes: &[u8]) -> Result<(ProgramCommitment, PublicIO, Proof), Error> {
    let mut r = Reader::new(bytes);
    r.version(WIRE_VERSION)?;
    let mut id = [F::from(0u32); COMMITMENT_WIDTH];
    for slot in &mut id {
        *slot = r.field()?;
    }
    let inputs = r.field_slice()?;
    let outputs = r.field_slice()?;
    let proof_version = r.byte()?;
    let pc_trace = r.u32_slice()?;
    let witness = r.field_slice()?;
    r.finish()?;
    Ok((
        ProgramCommitment(id),
        PublicIO { inputs, outputs },
        Proof {
            version: proof_version,
            pc_trace,
            witness,
        },
    ))
}

// ===========================================================================
// Succinct wire encoding — the AggregateProof with a succinct opening.
//
// The transparent codec above ships the full witness; this one ships the
// succinct opening instead (binarity + JL projection + the batched binding),
// so a referenced computation's packet is ~constant in the trace length.
// Same canonical discipline: versioned, length-bounded, deterministic, and
// rejecting trailing bytes. The on-chain verifier reconstructs Shape from the
// (referenced) program and the CommitmentKey deterministically, then calls
// `pipeline::verify_aggregate`.
//
// Scope: the non-ZK succinct path (`succinct: Some`, `binding: Some`), which
// is the deployed case. ZK and transparent-aggregate variants are rejected by
// this codec (they have their own paths) rather than silently mis-encoded.
// ===========================================================================

use crate::hypernova::{Accumulator, MultifoldProof};
use crate::opening::OpeningProof;
use crate::pipeline::AggregateProof;
use blacknet_crypto::polynomial::UnivariatePolynomial;
use blacknet_crypto::sumcheck::Proof as SumCheckProof;

impl Writer {
    fn sumcheck(&mut self, p: &SumCheckProof<F>) {
        self.u32(p.variables() as u32);
        for claim in p {
            let coeffs: Vec<F> = claim.clone().into();
            self.field_slice(&coeffs);
        }
    }

    fn multifold(&mut self, m: &MultifoldProof) {
        self.sumcheck(&m.sumcheck);
        for x in &m.sigma {
            self.field(*x);
        }
        for x in &m.theta {
            self.field(*x);
        }
    }

    fn accumulator(&mut self, a: &Accumulator) {
        self.field_vec(&a.commitment);
        self.field_slice(&a.point);
        for x in &a.evals {
            self.field(*x);
        }
        self.field_slice(&a.x);
        self.u128(a.norm_bound);
    }

    fn opening(&mut self, o: &OpeningProof) {
        self.sumcheck(&o.binarity);
        self.field(o.bit_eval);
        self.field_vec(&o.projection);
    }
}

impl Reader<'_> {
    fn sumcheck(&mut self) -> Result<SumCheckProof<F>, Error> {
        let n = self.len_prefix()?;
        let mut claims = Vec::with_capacity(n);
        for _ in 0..n {
            claims.push(UnivariatePolynomial::from(self.field_slice()?));
        }
        Ok(SumCheckProof::new(claims))
    }

    fn multifold(&mut self) -> Result<MultifoldProof, Error> {
        let sumcheck = self.sumcheck()?;
        let mut sigma = [F::from(0); 3];
        let mut theta = [F::from(0); 3];
        for x in &mut sigma {
            *x = self.field()?;
        }
        for x in &mut theta {
            *x = self.field()?;
        }
        Ok(MultifoldProof {
            sumcheck,
            sigma,
            theta,
        })
    }

    fn accumulator(&mut self) -> Result<Accumulator, Error> {
        let commitment = self.field_vec()?;
        let point = self.field_slice()?;
        let mut evals = [F::from(0); 3];
        for x in &mut evals {
            *x = self.field()?;
        }
        let x = self.field_slice()?;
        let norm_bound = self.u128()?;
        Ok(Accumulator {
            commitment,
            point,
            evals,
            x,
            norm_bound,
        })
    }

    fn opening(&mut self) -> Result<OpeningProof, Error> {
        let binarity = self.sumcheck()?;
        let bit_eval = self.field()?;
        let projection = self.field_vec()?;
        Ok(OpeningProof {
            binarity,
            bit_eval,
            projection,
        })
    }
}

/// Canonical body of a succinct `AggregateProof` (non-ZK path). Encodes the
/// public verification data only — no witness. Rejects ZK / transparent-
/// aggregate variants.
fn write_aggregate(w: &mut Writer, p: &AggregateProof) -> Result<(), Error> {
    let succinct = p.succinct.as_ref().ok_or(Error::Malformed)?;
    let (bproof, beval) = p.binding.as_ref().ok_or(Error::Malformed)?;
    if p.succinct_zk.is_some() || p.blind.is_some() || p.opening.dimension() != 0 {
        return Err(Error::Malformed);
    }
    // instances
    w.u32(p.ios.len() as u32);
    for io in &p.ios {
        w.field_slice(io);
    }
    w.u32(p.commitments.len() as u32);
    for c in &p.commitments {
        w.field_vec(c);
    }
    w.u32(p.norms.len() as u32);
    for &n in &p.norms {
        w.u128(n);
    }
    // folds
    w.multifold(&p.init);
    w.u32(p.folds.len() as u32);
    for m in &p.folds {
        w.multifold(m);
    }
    // opening + binding + accumulator
    w.opening(succinct);
    w.u32(p.opening_len as u32);
    w.sumcheck(bproof);
    w.field(*beval);
    w.accumulator(&p.accumulator);
    Ok(())
}

fn read_aggregate(r: &mut Reader) -> Result<AggregateProof, Error> {
    let n_ios = r.len_prefix()?;
    let ios = (0..n_ios)
        .map(|_| r.field_slice())
        .collect::<Result<Vec<_>, _>>()?;
    let n_c = r.len_prefix()?;
    let commitments = (0..n_c)
        .map(|_| r.field_vec())
        .collect::<Result<Vec<_>, _>>()?;
    let n_n = r.len_prefix()?;
    let norms = (0..n_n).map(|_| r.u128()).collect::<Result<Vec<_>, _>>()?;
    let init = r.multifold()?;
    let n_f = r.len_prefix()?;
    let folds = (0..n_f)
        .map(|_| r.multifold())
        .collect::<Result<Vec<_>, _>>()?;
    let succinct = r.opening()?;
    let opening_len = r.u32()? as usize;
    let binding_proof = r.sumcheck()?;
    let binding_eval = r.field()?;
    let accumulator = r.accumulator()?;
    Ok(AggregateProof {
        ios,
        commitments,
        norms,
        init,
        folds,
        blind: None,
        opening: DenseVector::from(Vec::new()),
        succinct: Some(succinct),
        opening_len,
        succinct_zk: None,
        binding: Some((binding_proof, binding_eval)),
        accumulator,
    })
}

/// Encodes a succinct referenced computation: program-id + the succinct
/// aggregate proof. The program is already on chain (by id); this is the
/// bandwidth-minimal form — packet size is ~constant in the trace length.
pub fn encode_reference_succinct(
    program_id: &ProgramCommitment,
    proof: &AggregateProof,
) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    w.version(WIRE_VERSION);
    for k in 0..COMMITMENT_WIDTH {
        w.field(program_id.0[k]);
    }
    write_aggregate(&mut w, proof)?;
    Ok(w.finish())
}

/// Decodes a succinct referenced computation payload.
pub fn decode_reference_succinct(
    bytes: &[u8],
) -> Result<(ProgramCommitment, AggregateProof), Error> {
    let mut r = Reader::new(bytes);
    r.version(WIRE_VERSION)?;
    let mut id = [F::from(0); COMMITMENT_WIDTH];
    for k in id.iter_mut() {
        *k = r.field()?;
    }
    let proof = read_aggregate(&mut r)?;
    r.finish()?;
    Ok((ProgramCommitment(id), proof))
}
