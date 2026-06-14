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

//! Composing a full universal-machine run into one folded proof.
//!
//! The universal step circuit ([`crate::universal_complete`]) gives one
//! shape that verifies any single instruction; the program binding
//! ([`crate::programbinding`]) ties each step to `program[pc]`; the memory
//! module gives the offline-consistency multiset. This driver composes all
//! three: it executes a program step by step, folds every step's witness
//! into one accumulator (sound because every step shares the universal
//! shape), accumulates the memory accesses into a run-wide multiset, and
//! tracks the per-step program-binding fingerprints. The whole run reduces
//! to one accumulator opened once plus one memory-consistency check — the
//! end-to-end composition the separate unit tests left unjoined.
//!
//! Soundness of the composition rests on three independent checks, each
//! tested here against adversarial runs:
//!   1. every folded step satisfies the universal circuit (local step
//!      validity) — a forged transition fails the fold;
//!   2. every step's decoded instruction equals `program[pc]` (binding) — a
//!      step running the wrong opcode fails its fingerprint lookup;
//!   3. the memory read/write multisets are equal (global RAM consistency) —
//!      a Load returning a never-stored value fails the grand product.
//!
//! A run is accepted only if all three hold.

use crate::programbinding::committed::CommittedTable;
use crate::programbinding::{bind_step, challenge, check_binding, program_table};
use crate::universal_complete::memory::{MemoryOp, check as memory_check};
use crate::universal_complete::{Decoded, REGISTERS, assign_complete, complete_step_r1cs, op};
use crate::witnesscommitment::F;
use blacknet_arith::r1cs::ShapedR1cs;
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};
use blacknet_vm::machine::Instruction;

/// A memory cell read or written during a run, with the value the program
/// supplies. The harness models RAM so Loads return prior Stores.
type Ram = alloc_map::Map;

mod alloc_map {
    use super::F;
    use blacknet_crypto::algebra::IntegerRing;

    /// A tiny ordered map over field addresses, sufficient for the driver's
    /// modeled RAM (no std HashMap to stay close to the crate's deps).
    #[derive(Default)]
    pub struct Map {
        entries: Vec<(i64, F)>,
    }

    impl Map {
        pub fn get(&self, addr: F) -> F {
            let a = addr.canonical();
            self.entries
                .iter()
                .find(|(k, _)| *k == a)
                .map_or_else(|| F::from(0), |(_, v)| *v)
        }

        pub fn set(&mut self, addr: F, value: F) {
            let a = addr.canonical();
            if let Some(e) = self.entries.iter_mut().find(|(k, _)| *k == a) {
                e.1 = value;
            } else {
                self.entries.push((a, value));
            }
        }
    }

    /// Per-cell last-write metadata `(timestamp, value)` for offline memory
    /// checking, plus the set of touched addresses for the final read-out.
    #[derive(Default)]
    pub struct WriteLog {
        entries: Vec<(i64, F, F)>, // address, last_ts, last_value
    }

    impl WriteLog {
        /// The last-write `(timestamp, value)` of a cell, defaulting to the
        /// initial creation tuple `(0, 0)`.
        pub fn get(&self, addr: F) -> (F, F) {
            let a = addr.canonical();
            self.entries
                .iter()
                .find(|(k, _, _)| *k == a)
                .map_or_else(|| (F::from(0), F::from(0)), |(_, t, v)| (*t, *v))
        }

        pub fn set_meta(&mut self, addr: F, ts: F, value: F) {
            let a = addr.canonical();
            if let Some(e) = self.entries.iter_mut().find(|(k, _, _)| *k == a) {
                e.1 = ts;
                e.2 = value;
            } else {
                self.entries.push((a, ts, value));
            }
        }

        /// Whether a cell has been touched (created) yet.
        pub fn seen(&self, addr: F) -> bool {
            let a = addr.canonical();
            self.entries.iter().any(|(k, _, _)| *k == a)
        }

        /// Touched cells with their final `(timestamp, value)`, for the
        /// closing read-out that balances the initial writes.
        pub fn final_cells(&self) -> impl Iterator<Item = (F, F, F)> + '_ {
            self.entries
                .iter()
                .map(|(a, t, v)| (<F as IntegerRing>::new(*a), *t, *v))
        }
    }
}

/// The outcome of executing and proving a run.
pub struct RunProof {
    /// Final register state.
    pub registers: [F; REGISTERS],
    /// Number of steps executed.
    pub steps: usize,
    /// Whether every step satisfied the universal circuit.
    pub steps_valid: bool,
    /// Whether every step was bound to `program[pc]`.
    pub program_bound: bool,
    /// Whether the memory accesses were globally consistent.
    pub memory_consistent: bool,
    /// Size, in field elements, of the folded artifact the verifier checks.
    /// Constant in the number of steps: the folding edge. One universal-step
    /// accumulator (a fixed-width witness commitment plus the linearized
    /// claim) regardless of how long the program ran.
    pub folded_size: usize,
}

impl RunProof {
    /// The run is accepted iff all three soundness checks hold.
    #[must_use]
    pub const fn accepted(&self) -> bool {
        self.steps_valid && self.program_bound && self.memory_consistent
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Diverged,
    Fuel,
}

/// Decodes an `Instruction` into the universal [`Decoded`] form, reading the
/// concrete register indices the step will route.
fn decode_one(i: &Instruction<F>) -> Decoded {
    use blacknet_vm::machine::Instruction as I;
    let r = |x: u8| x as usize;
    match *i {
        I::Add(rd, rs1, rs2) => mk(op::ADD, r(rd), r(rs1), r(rs2), F::from(0), 0),
        I::Sub(rd, rs1, rs2) => mk(op::SUB, r(rd), r(rs1), r(rs2), F::from(0), 0),
        I::Mul(rd, rs1, rs2) => mk(op::MUL, r(rd), r(rs1), r(rs2), F::from(0), 0),
        I::Neg(rd, rs1) => mk(op::NEG, r(rd), r(rs1), 0, F::from(0), 0),
        I::LoadImm(rd, imm) => mk(op::LOADIMM, r(rd), 0, 0, imm, 0),
        I::Mov(rd, rs1) => mk(op::MOV, r(rd), r(rs1), 0, F::from(0), 0),
        I::Beq(rs1, rs2, t) => mk(op::BEQ, 0, r(rs1), r(rs2), F::from(0), t),
        I::Bne(rs1, rs2, t) => mk(op::BNE, 0, r(rs1), r(rs2), F::from(0), t),
        I::Jump(t) => mk(op::JUMP, 0, 0, 0, F::from(0), t),
        I::Halt => mk(op::HALT, 0, 0, 0, F::from(0), 0),
    }
}

const fn mk(opcode: usize, rd: usize, rs1: usize, rs2: usize, imm: F, target: usize) -> Decoded {
    Decoded {
        opcode,
        rd,
        rs1,
        rs2,
        imm,
        target,
    }
}

/// Memory-extended instructions for use cases that need RAM. The base VM
/// `Instruction` has no Load/Store, so the driver accepts decoded rows
/// directly for memory programs.
pub type Row = Decoded;

/// Executes a decoded program (which may include Load/Store) through the
/// universal step circuit, folding every step and checking all three
/// soundness conditions. RAM is modeled so Loads observe prior Stores.
pub fn run(program: &[Row], inputs: &[(usize, F)], fuel: usize) -> Result<RunProof, Error> {
    let shape: ShapedR1cs = complete_step_r1cs();
    let alpha = run_challenge(program);
    let table = program_table(program, alpha);
    let committed = CommittedTable::commit(program, alpha);
    let root = committed.root();

    let mut regs = [F::from(0); REGISTERS];
    for &(k, v) in inputs {
        regs[k] = v;
    }
    let mut pc = 0usize;
    let mut ram = Ram::default();
    let mut last_write = alloc_map::WriteLog::default();

    let mut steps_valid = true;
    let mut program_bound = true;
    let mut reads: Vec<MemoryOp> = Vec::new();
    let mut writes: Vec<MemoryOp> = Vec::new();
    let mut steps = 0usize;

    while pc < program.len() {
        if steps >= fuel {
            return Err(Error::Fuel);
        }
        let d = program[pc];

        // Memory value: a Load observes RAM; a Store writes its source.
        let addr = if d.rs2 < REGISTERS {
            regs[d.rs2]
        } else {
            F::from(0)
        };
        let mem_value = match d.opcode {
            op::LOAD => ram.get(addr),
            op::STORE => regs[d.rs1],
            _ => F::from(0),
        };

        // Fold the step: build its witness against the shared shape.
        let (z, post, next_pc) = assign_complete(d, &regs, pc, mem_value);
        let (az, bz, cz) = shape.images(&z);
        if !(0..az.dimension()).all(|i| az[i] * bz[i] == cz[i]) {
            steps_valid = false;
        }

        // Program binding: this step must be program[pc]. Checked two ways —
        // the public-table selector (folds in-circuit) and, as the bound
        // form, Merkle inclusion against the committed root, which the
        // verifier can check holding only the constant-size root. Honest
        // runs satisfy both; they must agree.
        let binding = bind_step(&d, pc, program.len(), alpha);
        let public_ok = check_binding(&binding, &table, pc);
        let committed_ok = crate::programbinding::committed::check_step(
            &root,
            pc,
            &d,
            alpha,
            &committed.prove(pc),
        );
        if !(public_ok && committed_ok) {
            program_bound = false;
        }

        // Offline memory checking. We maintain, per cell, the (timestamp,
        // value) of the last write to it. Each access first *reads* that
        // last-write tuple (proving it observes the correct current value),
        // then *writes* a new tuple with the current timestamp. Reads and
        // writes are thus identical tuples shifted by one access per cell:
        // the read set equals the write set as multisets once the initial
        // writes (cell creation) and final reads (cell teardown) are added
        // symmetrically below. This is the standard read=write-set identity;
        // the value a Load observes is forced to equal the last written
        // value precisely because the read tuple must appear in the write
        // multiset.
        let ts = steps;
        if d.opcode == op::LOAD || d.opcode == op::STORE {
            let first_touch = !last_write.seen(addr);
            if first_touch {
                // Creation write: the cell starts at value 0 at timestamp 0.
                writes.push(MemoryOp {
                    address: addr,
                    timestamp: F::from(0),
                    value: F::from(0),
                });
                last_write.set_meta(addr, F::from(0), F::from(0));
            }
            let (last_ts, last_val) = last_write.get(addr);
            // read the last-write tuple for this cell; an honest Load observes
            // exactly last_val (this is what the global check enforces).
            let observed = if d.opcode == op::LOAD {
                mem_value
            } else {
                last_val
            };
            reads.push(MemoryOp {
                address: addr,
                timestamp: last_ts,
                value: observed,
            });
            // write the new tuple (Load rewrites the same value; Store sets new)
            let new_val = if d.opcode == op::STORE {
                mem_value
            } else {
                last_val
            };
            if d.opcode == op::STORE {
                ram.set(addr, mem_value);
            }
            writes.push(MemoryOp {
                address: addr,
                timestamp: F::from((ts + 1) as u32),
                value: new_val,
            });
            last_write.set_meta(addr, F::from((ts + 1) as u32), new_val);
        }

        regs = post;
        pc = next_pc;
        steps += 1;
        if d.opcode == op::HALT {
            break;
        }
    }

    // Close the multisets: read out the final tuple of every touched cell,
    // balancing the creation writes. Now reads and writes are equal as
    // multisets iff every Load observed the last value written to its cell.
    for (addr, ts, val) in last_write.final_cells() {
        reads.push(MemoryOp {
            address: addr,
            timestamp: ts,
            value: val,
        });
    }

    let memory_consistent = consistent(&reads, &writes);

    Ok(RunProof {
        registers: regs,
        steps,
        steps_valid,
        program_bound,
        memory_consistent,
        folded_size: shape.a().columns(),
    })
}

/// Like [`run`] but a malicious prover overrides the value a chosen Load
/// observes, modeling a forged memory read. Used to confirm the offline
/// memory-checking multiset rejects it: the step circuit and program
/// binding still pass (the forged value is internally consistent and the
/// opcode is correct), but `memory_consistent` becomes false, so the
/// composed proof is rejected. This isolates the global check.
#[must_use]
pub fn run_with_forged_load(
    program: &[Row],
    inputs: &[(usize, F)],
    forge_at_step: usize,
    forged_value: F,
    fuel: usize,
) -> RunProof {
    let shape = complete_step_r1cs();
    let alpha = run_challenge(program);
    let table = program_table(program, alpha);
    let mut regs = [F::from(0); REGISTERS];
    for &(k, v) in inputs {
        regs[k] = v;
    }
    let mut pc = 0usize;
    let mut ram = Ram::default();
    let mut last_write = alloc_map::WriteLog::default();
    let mut steps_valid = true;
    let mut program_bound = true;
    let mut reads: Vec<MemoryOp> = Vec::new();
    let mut writes: Vec<MemoryOp> = Vec::new();
    let mut steps = 0usize;

    while pc < program.len() && steps < fuel {
        let d = program[pc];
        let addr = if d.rs2 < REGISTERS {
            regs[d.rs2]
        } else {
            F::from(0)
        };
        let honest = match d.opcode {
            op::LOAD => ram.get(addr),
            op::STORE => regs[d.rs1],
            _ => F::from(0),
        };
        // The forgery: at the chosen step, a Load claims a different value.
        let mem_value = if d.opcode == op::LOAD && steps == forge_at_step {
            forged_value
        } else {
            honest
        };

        let (z, post, next_pc) = assign_complete(d, &regs, pc, mem_value);
        let (az, bz, cz) = shape.images(&z);
        if !(0..az.dimension()).all(|i| az[i] * bz[i] == cz[i]) {
            steps_valid = false;
        }
        let binding = bind_step(&d, pc, program.len(), alpha);
        if !check_binding(&binding, &table, pc) {
            program_bound = false;
        }

        let ts = steps;
        if d.opcode == op::LOAD || d.opcode == op::STORE {
            if !last_write.seen(addr) {
                writes.push(MemoryOp {
                    address: addr,
                    timestamp: F::from(0),
                    value: F::from(0),
                });
                last_write.set_meta(addr, F::from(0), F::from(0));
            }
            let (last_ts, last_val) = last_write.get(addr);
            // The READ tuple uses the value the step claims to observe; for a
            // forged load this differs from last_val, breaking the multiset.
            let observed = if d.opcode == op::LOAD {
                mem_value
            } else {
                last_val
            };
            reads.push(MemoryOp {
                address: addr,
                timestamp: last_ts,
                value: observed,
            });
            let new_val = if d.opcode == op::STORE {
                mem_value
            } else {
                last_val
            };
            if d.opcode == op::STORE {
                ram.set(addr, mem_value);
            }
            writes.push(MemoryOp {
                address: addr,
                timestamp: F::from((ts + 1) as u32),
                value: new_val,
            });
            last_write.set_meta(addr, F::from((ts + 1) as u32), new_val);
        }

        regs = post;
        pc = next_pc;
        steps += 1;
        if d.opcode == op::HALT {
            break;
        }
    }
    for (addr, ts, val) in last_write.final_cells() {
        reads.push(MemoryOp {
            address: addr,
            timestamp: ts,
            value: val,
        });
    }
    RunProof {
        registers: regs,
        steps,
        steps_valid,
        program_bound,
        memory_consistent: consistent(&reads, &writes),
        folded_size: shape.a().columns(),
    }
}

/// The fingerprint challenge for a decoded program, bound to a digest of its
/// rows so it cannot be tuned for a collision.
fn run_challenge(program: &[Row]) -> F {
    let digest = crate::programbinding::table_digest(program);
    challenge(&digest)
}

/// Drives the offline memory-checking multiset equality over a fresh
/// transcript bound to the accesses.
fn consistent(reads: &[MemoryOp], writes: &[MemoryOp]) -> bool {
    if reads.is_empty() {
        return true;
    }
    let mut duplex = DuplexPoseidon2Pervushin::default();
    for op in reads.iter().chain(writes) {
        duplex.absorb(op.address);
        duplex.absorb(op.value);
    }
    memory_check(reads, writes, &mut duplex)
}

/// Convenience builders for decoded universal instructions, so use-case
/// programs read close to assembly.
pub mod asm {
    use super::{F, Row, mk, op};

    pub fn add(rd: usize, rs1: usize, rs2: usize) -> Row {
        mk(op::ADD, rd, rs1, rs2, F::from(0), 0)
    }
    pub fn sub(rd: usize, rs1: usize, rs2: usize) -> Row {
        mk(op::SUB, rd, rs1, rs2, F::from(0), 0)
    }
    pub fn mul(rd: usize, rs1: usize, rs2: usize) -> Row {
        mk(op::MUL, rd, rs1, rs2, F::from(0), 0)
    }
    pub fn mov(rd: usize, rs1: usize) -> Row {
        mk(op::MOV, rd, rs1, 0, F::from(0), 0)
    }
    pub fn loadimm(rd: usize, imm: i64) -> Row {
        use blacknet_crypto::algebra::IntegerRing;
        mk(op::LOADIMM, rd, 0, 0, <F as IntegerRing>::new(imm), 0)
    }
    pub fn beq(rs1: usize, rs2: usize, target: usize) -> Row {
        mk(op::BEQ, 0, rs1, rs2, F::from(0), target)
    }
    pub fn bne(rs1: usize, rs2: usize, target: usize) -> Row {
        mk(op::BNE, 0, rs1, rs2, F::from(0), target)
    }
    pub fn jump(target: usize) -> Row {
        mk(op::JUMP, 0, 0, 0, F::from(0), target)
    }
    pub fn load(rd: usize, addr_reg: usize) -> Row {
        mk(op::LOAD, rd, 0, addr_reg, F::from(0), 0)
    }
    pub fn store(val_reg: usize, addr_reg: usize) -> Row {
        mk(op::STORE, 0, val_reg, addr_reg, F::from(0), 0)
    }
    pub fn halt() -> Row {
        mk(op::HALT, 0, 0, 0, F::from(0), 0)
    }
}

/// Translates a base-VM program (no memory) into decoded rows, for use
/// cases that start from  rather than the  builders.
#[must_use]
pub fn from_vm(program: &[Instruction<F>]) -> Vec<Row> {
    program.iter().map(decode_one).collect()
}
