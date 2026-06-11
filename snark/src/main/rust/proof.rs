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

//! Milestone 2: one-shot prove/verify of VM execution.
//!
//! v0 is *transparent*: the proof carries the pc trace and the full witness,
//! so it is sound and complete but neither succinct nor zero-knowledge —
//! proof size is linear in the trace. Succinctness arrives with folding
//! (milestone 3) plus final compression, zero-knowledge with milestone 5.
//! The `verify` entry point is the consensus-critical surface and never
//! re-executes the program: it rebuilds the constraint system from public
//! data and checks satisfaction.

use crate::commitment::{ProgramCommitment, commit};
use blacknet_arith::trace;
use blacknet_crypto::constraintsystem::ConstraintSystem;
use blacknet_crypto::matrix::DenseVector;
use blacknet_crypto::pervushin::PervushinField;
use blacknet_vm::machine::Instruction;

pub type F = PervushinField;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicIO {
    pub inputs: Vec<F>,
    pub outputs: Vec<F>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub version: u8,
    pub pc_trace: Vec<u32>,
    pub witness: Vec<F>,
}

pub const VERSION: u8 = 0;

#[derive(Debug)]
pub enum ProveError {
    Arith(trace::Error),
}

#[derive(Debug)]
pub enum VerifyError {
    Version(u8),
    ProgramCommitment,
    ControlFlow,
    Unsatisfied,
    PublicIO,
    StepBound,
}

/// Runs `program` with `inputs` and produces the IO and the proof.
pub fn prove(
    program: &[Instruction<F>],
    inputs: &[F],
    fuel: u64,
) -> Result<(PublicIO, Proof), ProveError> {
    let execution = trace::execute(program, inputs, fuel).map_err(ProveError::Arith)?;
    let io = PublicIO {
        inputs: inputs.to_vec(),
        outputs: execution.outputs,
    };
    let proof = Proof {
        version: VERSION,
        pc_trace: execution.pc_trace,
        witness: execution.witness.into_iter().collect(),
    };
    Ok((io, proof))
}

/// Verifies a proof against a program commitment without executing the
/// program. `program` is the deployed code resolved from `program_id` by the
/// caller (the on-chain program registry); `step_bound` caps trace length.
pub fn verify(
    program_id: &ProgramCommitment,
    program: &[Instruction<F>],
    io: &PublicIO,
    proof: &Proof,
    step_bound: usize,
) -> Result<(), VerifyError> {
    if proof.version != VERSION {
        return Err(VerifyError::Version(proof.version));
    }
    if commit(program) != *program_id {
        return Err(VerifyError::ProgramCommitment);
    }
    if proof.pc_trace.len() > step_bound.saturating_add(1) {
        return Err(VerifyError::StepBound);
    }
    // The trace must end in Halt: a complete execution, not a prefix.
    let last_pc = *proof.pc_trace.last().ok_or(VerifyError::ControlFlow)? as usize;
    if program.get(last_pc) != Some(&Instruction::Halt) {
        return Err(VerifyError::ControlFlow);
    }
    let (r1cs, _) = trace::constrain(program, &io.inputs, &proof.pc_trace)
        .map_err(|_| VerifyError::ControlFlow)?;
    let z = DenseVector::from(proof.witness.clone());
    r1cs.to_ccs()
        .is_satisfied(&z)
        .map_err(|_| VerifyError::Unsatisfied)?;
    // Bind the public inputs to the initial machine state in the witness
    // (positional binding; the matrices are input-independent so instances
    // of different inputs can be folded).
    if io.inputs.len() > trace::REGISTERS {
        return Err(VerifyError::PublicIO);
    }
    for (k, expected) in io.inputs.iter().enumerate() {
        if proof.witness.get(1 + k) != Some(expected) {
            return Err(VerifyError::PublicIO);
        }
    }
    // Bind the claimed outputs to the final machine state in the witness.
    let steps = proof.pc_trace.len() - 1;
    let base = 1 + steps * trace::REGISTERS;
    if io.outputs.len() != trace::REGISTERS {
        return Err(VerifyError::PublicIO);
    }
    for (k, expected) in io.outputs.iter().enumerate() {
        if proof.witness.get(base + k) != Some(expected) {
            return Err(VerifyError::PublicIO);
        }
    }
    Ok(())
}
