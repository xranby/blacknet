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

//! Milestone 1: arithmetization of `blacknet-vm` execution traces.
//!
//! The trace of a fuel-metered run is compiled into an R1CS-shaped
//! customizable constraint system over the Pervushin field, together with a
//! satisfying witness. The register file is inlined into the step state
//! (architecture §4.3, v1 choice), so no memory-checking argument is needed.
//!
//! The constraint system is a deterministic function of
//! `(program, public inputs, pc trace)`. The verifier rebuilds it from those
//! public values and checks the witness, so prover and verifier are bound to
//! identical semantics by construction.

use crate::r1cs::ShapedR1cs;
use blacknet_crypto::algebra::Inv;
use blacknet_crypto::matrix::{DenseVector, SparseMatrixBuilder};
use blacknet_crypto::pervushin::PervushinField;
use blacknet_vm::machine::{Instruction, Machine};
use blacknet_vm::registerfile::RegisterIndex;

pub type F = PervushinField;

/// The number of general purpose registers of the arithmetized machine.
pub const REGISTERS: usize = 8;

type M = Machine<F, REGISTERS>;

#[derive(Debug)]
pub enum Error {
    Vm(blacknet_vm::machine::Error),
    /// The pc trace disagrees with the program semantics.
    ControlFlow(usize),
    /// A branch divisor was not invertible where it must be.
    Branch(usize),
    TooManyInputs,
}

impl From<blacknet_vm::machine::Error> for Error {
    fn from(e: blacknet_vm::machine::Error) -> Self {
        Error::Vm(e)
    }
}

/// The result of executing and arithmetizing a program.
pub struct Execution {
    pub r1cs: ShapedR1cs,
    pub witness: DenseVector<F>,
    pub pc_trace: Vec<u32>,
    pub outputs: Vec<F>,
}

/// Executes `program` on the VM with `inputs` seeded into registers
/// `r1..`, recording the full state sequence, and arithmetizes the trace.
pub fn execute(program: &[Instruction<F>], inputs: &[F], fuel: u64) -> Result<Execution, Error> {
    if inputs.len() > REGISTERS {
        return Err(Error::TooManyInputs);
    }
    let mut machine = M::new(program.to_vec(), fuel);
    for (i, &v) in inputs.iter().enumerate() {
        machine.write_register((i + 1) as RegisterIndex, v);
    }
    let mut states: Vec<[F; REGISTERS]> = vec![snapshot(&machine)];
    while !machine.halted() {
        machine.step()?;
        states.push(snapshot(&machine));
    }
    let pc_trace: Vec<u32> = machine
        .trace()
        .iter()
        .map(|row| row.pc as u32)
        .chain(core::iter::once(
            machine.trace().last().map_or(0, |row| row.next_pc as u32),
        ))
        .collect();
    let outputs = states.last().expect("nonempty").to_vec();
    let (r1cs, aux) = constrain(program, inputs, &pc_trace)?;
    let witness = assemble_witness(&states, inputs, &aux);
    Ok(Execution {
        r1cs,
        witness,
        pc_trace,
        outputs,
    })
}

/// Rebuilds the constraint system from public data only. This is the
/// verifier's entry point; it must equal the prover's system bit for bit.
pub fn constrain(
    program: &[Instruction<F>],
    inputs: &[F],
    pc_trace: &[u32],
) -> Result<(ShapedR1cs, Vec<BranchAux>), Error> {
    Builder::new(program, inputs, pc_trace)?.build()
}

/// Which auxiliary inverse witnesses the system expects, in order.
/// `step` indexes the trace; the divisor is `rs1 - rs2` at that step.
#[derive(Clone, Copy, Debug)]
pub struct BranchAux {
    pub step: usize,
    pub rs1: RegisterIndex,
    pub rs2: RegisterIndex,
}

fn snapshot(machine: &M) -> [F; REGISTERS] {
    core::array::from_fn(|i| machine.register((i + 1) as RegisterIndex))
}

struct Builder<'a> {
    program: &'a [Instruction<F>],
    pc_trace: &'a [u32],
    steps: usize,
}

/// Variable layout: `z[0] = 1`; register `k` (1-based) of state `t` at
/// `1 + t*REGISTERS + (k-1)` for `t in 0..=steps`; branch inverses appended.
impl<'a> Builder<'a> {
    const fn new(
        program: &'a [Instruction<F>],
        inputs: &'a [F],
        pc_trace: &'a [u32],
    ) -> Result<Self, Error> {
        if pc_trace.is_empty() || inputs.len() > REGISTERS {
            return Err(Error::ControlFlow(0));
        }
        Ok(Self {
            program,
            pc_trace,
            steps: pc_trace.len() - 1,
        })
    }

    fn state_var(&self, t: usize, k: RegisterIndex) -> Option<usize> {
        let k = k as usize;
        if (1..=REGISTERS).contains(&k) {
            Some(1 + t * REGISTERS + (k - 1))
        } else {
            None // the hardwired zero register has no variable
        }
    }

    fn build(self) -> Result<(ShapedR1cs, Vec<BranchAux>), Error> {
        let mut aux = Vec::new();
        let mut constraints = 0usize;
        // First pass: count rows and auxiliary variables.
        for t in 0..self.steps {
            let instruction = self.fetch(t)?;
            constraints += REGISTERS; // one row per register: copy or write
            if let Some(branch) = self.branch_aux(t, instruction)? {
                aux.push(branch);
                constraints += 1;
            }
        }
        // Public inputs are NOT baked into the matrices: the constraint
        // system must depend only on (program, pc trace) so that instances
        // with different inputs share a shape and can be folded. Input
        // binding is positional: the verifier checks the state-0 segment of
        // the witness against the public inputs (see blacknet-snark).
        let variables = 1 + (self.steps + 1) * REGISTERS + aux.len();
        let aux_base = 1 + (self.steps + 1) * REGISTERS;

        let mut a = SparseMatrixBuilder::<F>::new(constraints, variables);
        let mut b = SparseMatrixBuilder::<F>::new(constraints, variables);
        let mut c = SparseMatrixBuilder::<F>::new(constraints, variables);
        let mut aux_cursor = 0usize;

        for t in 0..self.steps {
            let instruction = self.fetch(t)?;
            let written = self.emit_step(t, instruction, &mut a, &mut b, &mut c, || {
                let v = aux_base + aux_cursor;
                aux_cursor += 1;
                v
            })?;
            // Copy constraints for untouched registers.
            for k in 1..=REGISTERS as RegisterIndex {
                if written == Some(k) {
                    continue;
                }
                let prev = self.state_var(t, k).expect("range");
                let next = self.state_var(t + 1, k).expect("range");
                a.column(next, F::from(1));
                a.column(prev, F::from(-1));
                b.column(0, F::from(1));
                a.row();
                b.row();
                c.row();
            }
        }
        debug_assert_eq!(aux_cursor, aux.len());
        Ok((ShapedR1cs::new(a.build(), b.build(), c.build()), aux))
    }

    fn fetch(&self, t: usize) -> Result<Instruction<F>, Error> {
        let pc = self.pc_trace[t] as usize;
        self.program.get(pc).copied().ok_or(Error::ControlFlow(t))
    }

    fn branch_aux(
        &self,
        t: usize,
        instruction: Instruction<F>,
    ) -> Result<Option<BranchAux>, Error> {
        let (taken, fallthrough) = self.edges(t)?;
        Ok(match instruction {
            Instruction::Beq(rs1, rs2, target) => {
                self.check_edge(t, taken, target, fallthrough)?;
                // Untaken Beq and taken Bne need an inverse witness.
                if !taken_edge(self.pc_trace, t, target) {
                    Some(BranchAux { step: t, rs1, rs2 })
                } else {
                    None
                }
            }
            Instruction::Bne(rs1, rs2, target) => {
                self.check_edge(t, taken, target, fallthrough)?;
                if taken_edge(self.pc_trace, t, target) {
                    Some(BranchAux { step: t, rs1, rs2 })
                } else {
                    None
                }
            }
            _ => None,
        })
    }

    /// Returns `(next_is_target_possible, fallthrough_pc)` and validates the
    /// non-branch control flow edges of the pc trace.
    fn edges(&self, t: usize) -> Result<(bool, u32), Error> {
        let pc = self.pc_trace[t];
        let next = self.pc_trace[t + 1];
        let instruction = self.fetch(t)?;
        let fallthrough = pc + 1;
        match instruction {
            Instruction::Jump(target) => {
                if next != target as u32 {
                    return Err(Error::ControlFlow(t));
                }
            }
            Instruction::Halt => {
                if next != pc || t + 1 != self.steps {
                    return Err(Error::ControlFlow(t));
                }
            }
            Instruction::Beq(..) | Instruction::Bne(..) => {}
            _ => {
                if next != fallthrough {
                    return Err(Error::ControlFlow(t));
                }
            }
        }
        Ok((true, fallthrough))
    }

    fn check_edge(&self, t: usize, _: bool, target: usize, fallthrough: u32) -> Result<(), Error> {
        let next = self.pc_trace[t + 1];
        if next != target as u32 && next != fallthrough {
            return Err(Error::ControlFlow(t));
        }
        Ok(())
    }

    /// Emits the data constraint row(s) of one step. Returns which register
    /// was written, if any. Rows are padded so each step has a fixed shape:
    /// the write constraint replaces the copy row of the written register.
    #[allow(clippy::too_many_lines)]
    fn emit_step(
        &self,
        t: usize,
        instruction: Instruction<F>,
        a: &mut SparseMatrixBuilder<F>,
        b: &mut SparseMatrixBuilder<F>,
        c: &mut SparseMatrixBuilder<F>,
        mut next_aux: impl FnMut() -> usize,
    ) -> Result<Option<RegisterIndex>, Error> {
        let read = |k: RegisterIndex| self.state_var(t, k);
        let write = |k: RegisterIndex| self.state_var(t + 1, k);
        let linear = |a: &mut SparseMatrixBuilder<F>,
                      b: &mut SparseMatrixBuilder<F>,
                      c: &mut SparseMatrixBuilder<F>| {
            b.column(0, F::from(1));
            a.row();
            b.row();
            c.row();
        };
        Ok(match instruction {
            Instruction::Add(rd, rs1, rs2) => write(rd).map(|w| {
                if let Some(v) = read(rs1) {
                    a.column(v, F::from(1));
                }
                if let Some(v) = read(rs2) {
                    a.column(v, F::from(1));
                }
                a.column(w, F::from(-1));
                linear(a, b, c);
                rd
            }),
            Instruction::Sub(rd, rs1, rs2) => write(rd).map(|w| {
                if let Some(v) = read(rs1) {
                    a.column(v, F::from(1));
                }
                if let Some(v) = read(rs2) {
                    a.column(v, F::from(-1));
                }
                a.column(w, F::from(-1));
                linear(a, b, c);
                rd
            }),
            Instruction::Neg(rd, rs1) => write(rd).map(|w| {
                if let Some(v) = read(rs1) {
                    a.column(v, F::from(1));
                }
                a.column(w, F::from(1));
                linear(a, b, c);
                rd
            }),
            Instruction::Mul(rd, rs1, rs2) => write(rd).map(|w| {
                if let Some(v) = read(rs1) {
                    a.column(v, F::from(1));
                }
                if let Some(v) = read(rs2) {
                    b.column(v, F::from(1));
                }
                c.column(w, F::from(1));
                a.row();
                b.row();
                c.row();
                rd
            }),
            Instruction::LoadImm(rd, imm) => write(rd).map(|w| {
                a.column(w, F::from(1));
                a.column(0, -imm);
                linear(a, b, c);
                rd
            }),
            Instruction::Mov(rd, rs1) => write(rd).map(|w| {
                if let Some(v) = read(rs1) {
                    a.column(v, F::from(1));
                }
                a.column(w, F::from(-1));
                linear(a, b, c);
                rd
            }),
            Instruction::Beq(rs1, rs2, target) => {
                self.emit_branch(t, rs1, rs2, target, true, a, b, c, &mut next_aux);
                None
            }
            Instruction::Bne(rs1, rs2, target) => {
                self.emit_branch(t, rs1, rs2, target, false, a, b, c, &mut next_aux);
                None
            }
            Instruction::Jump(_) | Instruction::Halt => None,
        })
    }

    /// `equal_when_taken`: Beq takes the edge on equality, Bne on inequality.
    #[allow(clippy::too_many_arguments)]
    fn emit_branch(
        &self,
        t: usize,
        rs1: RegisterIndex,
        rs2: RegisterIndex,
        target: usize,
        equal_when_taken: bool,
        a: &mut SparseMatrixBuilder<F>,
        b: &mut SparseMatrixBuilder<F>,
        c: &mut SparseMatrixBuilder<F>,
        next_aux: &mut impl FnMut() -> usize,
    ) {
        let taken = taken_edge(self.pc_trace, t, target);
        let must_be_equal = taken == equal_when_taken;
        let read = |k: RegisterIndex| self.state_var(t, k);
        if must_be_equal {
            // (rs1 - rs2) * 1 = 0
            if let Some(v) = read(rs1) {
                a.column(v, F::from(1));
            }
            if let Some(v) = read(rs2) {
                a.column(v, F::from(-1));
            }
            b.column(0, F::from(1));
            a.row();
            b.row();
            c.row();
        } else {
            // (rs1 - rs2) * inv = 1
            if let Some(v) = read(rs1) {
                a.column(v, F::from(1));
            }
            if let Some(v) = read(rs2) {
                a.column(v, F::from(-1));
            }
            b.column(next_aux(), F::from(1));
            c.column(0, F::from(1));
            a.row();
            b.row();
            c.row();
        }
    }
}

fn taken_edge(pc_trace: &[u32], t: usize, target: usize) -> bool {
    // Disambiguation: if target == fallthrough both directions coincide and
    // either constraint is satisfied; treating it as taken is consistent.
    pc_trace[t + 1] == target as u32
}

fn assemble_witness(states: &[[F; REGISTERS]], _inputs: &[F], aux: &[BranchAux]) -> DenseVector<F> {
    let mut z = Vec::with_capacity(1 + states.len() * REGISTERS + aux.len());
    z.push(F::from(1));
    for state in states {
        z.extend_from_slice(state);
    }
    for branch in aux {
        let s = &states[branch.step];
        let value = |k: RegisterIndex| {
            let k = k as usize;
            if (1..=REGISTERS).contains(&k) {
                s[k - 1]
            } else {
                F::from(0)
            }
        };
        let diff = value(branch.rs1) - value(branch.rs2);
        z.push(diff.inv().unwrap_or(F::from(0)));
    }
    DenseVector::from(z)
}
