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

//! Binding commitment to a program: the instruction table absorbed into the
//! Poseidon2 duplex over the Pervushin field with an injective encoding.

use blacknet_crypto::pervushin::PervushinField;
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};
use blacknet_vm::machine::Instruction;

pub type F = PervushinField;

pub const COMMITMENT_WIDTH: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramCommitment(pub [F; COMMITMENT_WIDTH]);

/// Domain separation tag, also versioning the encoding.
const TAG: u32 = 0x424c_4b31; // "BLK1"

#[must_use]
pub fn commit(program: &[Instruction<F>]) -> ProgramCommitment {
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(F::from(TAG));
    duplex.absorb(F::from(program.len() as u32));
    for &instruction in program {
        absorb_instruction(&mut duplex, instruction);
    }
    ProgramCommitment(core::array::from_fn(|_| duplex.squeeze()))
}

fn absorb_instruction(duplex: &mut DuplexPoseidon2Pervushin, instruction: Instruction<F>) {
    let reg = |r: u8| F::from(u32::from(r));
    let addr = |t: usize| F::from(t as u32);
    match instruction {
        Instruction::Add(rd, rs1, rs2) => {
            duplex.absorb(F::from(0u32));
            duplex.absorb(reg(rd));
            duplex.absorb(reg(rs1));
            duplex.absorb(reg(rs2));
        }
        Instruction::Sub(rd, rs1, rs2) => {
            duplex.absorb(F::from(1u32));
            duplex.absorb(reg(rd));
            duplex.absorb(reg(rs1));
            duplex.absorb(reg(rs2));
        }
        Instruction::Mul(rd, rs1, rs2) => {
            duplex.absorb(F::from(2u32));
            duplex.absorb(reg(rd));
            duplex.absorb(reg(rs1));
            duplex.absorb(reg(rs2));
        }
        Instruction::Neg(rd, rs1) => {
            duplex.absorb(F::from(3u32));
            duplex.absorb(reg(rd));
            duplex.absorb(reg(rs1));
        }
        Instruction::LoadImm(rd, imm) => {
            duplex.absorb(F::from(4u32));
            duplex.absorb(reg(rd));
            duplex.absorb(imm);
        }
        Instruction::Mov(rd, rs1) => {
            duplex.absorb(F::from(5u32));
            duplex.absorb(reg(rd));
            duplex.absorb(reg(rs1));
        }
        Instruction::Beq(rs1, rs2, target) => {
            duplex.absorb(F::from(6u32));
            duplex.absorb(reg(rs1));
            duplex.absorb(reg(rs2));
            duplex.absorb(addr(target));
        }
        Instruction::Bne(rs1, rs2, target) => {
            duplex.absorb(F::from(7u32));
            duplex.absorb(reg(rs1));
            duplex.absorb(reg(rs2));
            duplex.absorb(addr(target));
        }
        Instruction::Jump(target) => {
            duplex.absorb(F::from(8u32));
            duplex.absorb(addr(target));
        }
        Instruction::Halt => duplex.absorb(F::from(9u32)),
    }
}
