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

use crate::registerfile::{RegisterFile, RegisterIndex};
use blacknet_crypto::algebra::UnitalRing;

/// An instruction of the register machine over a unital ring `R`.
///
/// The arithmetic instructions are exactly the ring operations, so a step
/// of the machine is expressible with a constant number of ring constraints,
/// which is what a customizable constraint system wants to see.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Instruction<R> {
    /// `rd ← rs1 + rs2`
    Add(RegisterIndex, RegisterIndex, RegisterIndex),
    /// `rd ← rs1 - rs2`
    Sub(RegisterIndex, RegisterIndex, RegisterIndex),
    /// `rd ← rs1 * rs2`
    Mul(RegisterIndex, RegisterIndex, RegisterIndex),
    /// `rd ← -rs1`
    Neg(RegisterIndex, RegisterIndex),
    /// `rd ← imm`
    LoadImm(RegisterIndex, R),
    /// `rd ← rs1` (`Mov rd, r0` clears a register)
    Mov(RegisterIndex, RegisterIndex),
    /// `if rs1 == rs2 then pc ← target`
    Beq(RegisterIndex, RegisterIndex, usize),
    /// `if rs1 != rs2 then pc ← target`
    Bne(RegisterIndex, RegisterIndex, usize),
    /// `pc ← target`
    Jump(usize),
    /// Stop the machine.
    Halt,
}

/// Why the machine stopped or refused to step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The program counter left the program. Falling off the end is an
    /// error: well-formed programs halt explicitly.
    InvalidProgramCounter(usize),
    /// A branch or jump targeted an address outside the program.
    InvalidJump(usize),
    /// The fuel budget was exhausted before the program halted.
    OutOfFuel,
    /// The machine has already halted.
    Halted,
}

/// One row of the execution trace: the state transition witnessed at a step.
///
/// The trace is the object that is later arithmetized: proving execution
/// means proving that consecutive rows are related by [`Machine::step`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceRow<R> {
    pub pc: usize,
    pub instruction: Instruction<R>,
    pub next_pc: usize,
}

/// A register machine over a unital ring `R` with `N` general registers,
/// deterministic semantics, and fuel metering.
pub struct Machine<R, const N: usize> {
    registers: RegisterFile<R, N>,
    program: Vec<Instruction<R>>,
    pc: usize,
    fuel: u64,
    halted: bool,
    trace: Vec<TraceRow<R>>,
}

impl<R: UnitalRing + Copy + Default + Eq, const N: usize> Machine<R, N> {
    pub fn new(program: Vec<Instruction<R>>, fuel: u64) -> Self {
        Self {
            registers: RegisterFile::new(),
            program,
            pc: 0,
            fuel,
            halted: false,
            trace: Vec::new(),
        }
    }

    #[must_use]
    pub fn register(&self, index: RegisterIndex) -> R {
        self.registers.read(index)
    }

    /// Seeds a register before or during execution. Used by provers to bind
    /// public inputs to the initial machine state.
    pub fn write_register(&mut self, index: RegisterIndex, value: R) {
        self.registers.write(index, value);
    }

    #[must_use]
    pub const fn halted(&self) -> bool {
        self.halted
    }

    #[must_use]
    pub const fn fuel(&self) -> u64 {
        self.fuel
    }

    #[must_use]
    pub fn trace(&self) -> &[TraceRow<R>] {
        &self.trace
    }

    /// Executes one instruction. Every instruction costs one unit of fuel.
    pub fn step(&mut self) -> Result<(), Error> {
        if self.halted {
            return Err(Error::Halted);
        }
        if self.fuel == 0 {
            return Err(Error::OutOfFuel);
        }
        let Some(&instruction) = self.program.get(self.pc) else {
            return Err(Error::InvalidProgramCounter(self.pc));
        };
        self.fuel -= 1;
        let mut next_pc = self.pc + 1;
        match instruction {
            Instruction::Add(rd, rs1, rs2) => {
                let value = self.registers.read(rs1) + self.registers.read(rs2);
                self.registers.write(rd, value);
            }
            Instruction::Sub(rd, rs1, rs2) => {
                let value = self.registers.read(rs1) - self.registers.read(rs2);
                self.registers.write(rd, value);
            }
            Instruction::Mul(rd, rs1, rs2) => {
                let value = self.registers.read(rs1) * self.registers.read(rs2);
                self.registers.write(rd, value);
            }
            Instruction::Neg(rd, rs1) => {
                let value = -self.registers.read(rs1);
                self.registers.write(rd, value);
            }
            Instruction::LoadImm(rd, imm) => {
                self.registers.write(rd, imm);
            }
            Instruction::Mov(rd, rs1) => {
                let value = self.registers.read(rs1);
                self.registers.write(rd, value);
            }
            Instruction::Beq(rs1, rs2, target) => {
                if self.registers.read(rs1) == self.registers.read(rs2) {
                    next_pc = self.branch_target(target)?;
                }
            }
            Instruction::Bne(rs1, rs2, target) => {
                if self.registers.read(rs1) != self.registers.read(rs2) {
                    next_pc = self.branch_target(target)?;
                }
            }
            Instruction::Jump(target) => {
                next_pc = self.branch_target(target)?;
            }
            Instruction::Halt => {
                self.halted = true;
                next_pc = self.pc;
            }
        }
        self.trace.push(TraceRow {
            pc: self.pc,
            instruction,
            next_pc,
        });
        self.pc = next_pc;
        Ok(())
    }

    /// Runs until the program halts or an error occurs, returning the number
    /// of executed steps.
    pub fn run(&mut self) -> Result<u64, Error> {
        let mut steps: u64 = 0;
        while !self.halted {
            self.step()?;
            steps += 1;
        }
        Ok(steps)
    }

    const fn branch_target(&self, target: usize) -> Result<usize, Error> {
        if target < self.program.len() {
            Ok(target)
        } else {
            Err(Error::InvalidJump(target))
        }
    }
}
