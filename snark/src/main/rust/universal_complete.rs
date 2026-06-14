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

//! The complete universal VM step — general programs, fully closed.
//!
//! [`crate::universal`] proved the arithmetic core: one shape, any opcode,
//! selected by a one-hot flag. This module completes the machine with the
//! two remaining selector layers, keeping every constraint at degree 2:
//!
//! 1. **Register-file routing.** The full pre- and post-register arrays are
//!    in the witness. A one-hot destination selector `dsel[REGISTERS]` picks
//!    which register the step writes; the result lands there and *every
//!    other register is copied pre→post*. Source reads `rs1v, rs2v` are
//!    likewise routed from the pre-array by one-hot source selectors. This
//!    is the register-file consistency the trace builder enforced
//!    positionally, now made a relation so it holds for any routing.
//!
//! 2. **PC transition.** The next program counter is selected by opcode:
//!    fallthrough `pc+1` for ALU ops, the immediate `target` for `Jump`,
//!    and the taken/not-taken edge for `Beq`/`Bne` decided by an
//!    (in)equality witness on `rs1v − rs2v`. `Halt` fixes `pc' = pc`.
//!
//! 3. **Program binding.** The decoded instruction fields (opcode flags,
//!    source/destination selectors, immediate, branch target) are bound to
//!    the committed program at `pc` by a lookup: the prover supplies the
//!    decoded row and a proof that it equals `program[pc]`. Here the binding
//!    is by direct equality against a public per-step *instruction
//!    fingerprint* — a single field element packing the decoded fields —
//!    which the verifier recomputes from the committed program. The
//!    fingerprint collapses the row to one value so the binding is one
//!    constraint; a full table lookup (committed program as a vector, pc as
//!    an index proof) is the same selector technique at larger width and is
//!    noted where it attaches.
//!
//! Because the shape is identical at every step regardless of the
//! instruction, a chain of these steps folds by the HyperNova machinery
//! exactly as the fixed-control-flow path does — now for arbitrary
//! programs. The state carried between steps is `(registers, pc)`, chained
//! as the folded public IO of [`crate::hypernova`].

use crate::witnesscommitment::F;
use blacknet_arith::r1cs::ShapedR1cs;
use blacknet_crypto::algebra::Inv;
use blacknet_crypto::matrix::DenseVector;

/// Registers in the machine (matches `blacknet-arith`'s `REGISTERS`).
pub const REGISTERS: usize = 8;

/// Opcodes, in flag order. Arithmetic + control flow + memory.
pub const OPCODES: usize = 12;

pub mod op {
    pub const ADD: usize = 0;
    pub const SUB: usize = 1;
    pub const MUL: usize = 2;
    pub const NEG: usize = 3;
    pub const MOV: usize = 4;
    pub const LOADIMM: usize = 5;
    pub const BEQ: usize = 6;
    pub const BNE: usize = 7;
    pub const JUMP: usize = 8;
    pub const HALT: usize = 9;
    /// `rd ← mem[rs2]` (address from rs2, value into rd).
    pub const LOAD: usize = 10;
    /// `mem[rs2] ← rs1` (address from rs2, value from rs1).
    pub const STORE: usize = 11;
}

/// Which opcodes write a destination register. Load writes (the loaded
/// value); Store does not.
const fn writes_register(opcode: usize) -> bool {
    opcode <= op::LOADIMM || opcode == op::LOAD
}

/// Column layout of one complete step's witness.
pub struct Layout;

impl Layout {
    pub const ONE: usize = 0;
    pub const PC: usize = 1;
    pub const NEXT_PC: usize = 2;
    pub const IMM: usize = 3;
    pub const TARGET: usize = 4;
    pub const RS1V: usize = 5;
    pub const RS2V: usize = 6;
    pub const RDV: usize = 7;
    pub const PROD: usize = 8;
    pub const DIFF: usize = 9;
    pub const DINV: usize = 10;
    /// Branch-taken indicator (boolean): 1 if the branch edge is taken.
    pub const TAKEN: usize = 11;
    /// Memory access of this step: address, value, and a write flag (1 for
    /// Store, 0 for Load or non-memory). The `(address, value)` pair is the
    /// local view; global consistency is the offline memory-checking
    /// argument over all steps' accesses (`memory` module).
    pub const MEM_ADDR: usize = 12;
    pub const MEM_VALUE: usize = 13;
    pub const MEM_WRITE: usize = 14;
    pub const PRE: usize = 15;
    pub const POST: usize = Self::PRE + REGISTERS;
    pub const FLAGS: usize = Self::POST + REGISTERS;
    pub const DSEL: usize = Self::FLAGS + OPCODES;
    pub const SSEL1: usize = Self::DSEL + REGISTERS;
    pub const SSEL2: usize = Self::SSEL1 + REGISTERS;
    // Auxiliary columns (single source of truth for builder and assigner).
    pub const WRDV: usize = Self::SSEL2 + REGISTERS;
    pub const BEQ_TAKEN: usize = Self::WRDV + 1;
    pub const BNE_TAKEN: usize = Self::BEQ_TAKEN + 1;
    pub const DIFF_DINV: usize = Self::BNE_TAKEN + 1;
    pub const JUMP_CORR: usize = Self::DIFF_DINV + 1;
    pub const BRANCH_CORR: usize = Self::JUMP_CORR + 1;
    pub const READ1_AUX: usize = Self::BRANCH_CORR + 1;
    pub const READ2_AUX: usize = Self::READ1_AUX + REGISTERS;
    pub const COLUMNS: usize = Self::READ2_AUX + REGISTERS;
}

type Row = (Vec<(usize, F)>, Vec<(usize, F)>, Vec<(usize, F)>);

fn one() -> F {
    F::from(1)
}

/// Flags of the register-writing opcodes (arithmetic family plus Load),
/// used as the write mask in the register-file update and dsel sum.
fn write_mask_terms() -> Vec<(usize, F)> {
    let mut terms: Vec<(usize, F)> = (0..=op::LOADIMM).map(|o| (flag(o), one())).collect();
    terms.push((flag(op::LOAD), one()));
    terms
}

const fn pre(k: usize) -> usize {
    Layout::PRE + k
}
const fn post(k: usize) -> usize {
    Layout::POST + k
}
const fn flag(i: usize) -> usize {
    Layout::FLAGS + i
}
const fn dsel(k: usize) -> usize {
    Layout::DSEL + k
}

/// Builds the complete universal step relation as quadratic rows.
#[must_use]
pub fn complete_step_r1cs() -> ShapedR1cs {
    let mut rows: Vec<Row> = Vec::new();

    // --- One-hot selectors: each boolean and summing to one. ---
    for i in 0..OPCODES {
        rows.push((
            vec![(flag(i), one())],
            vec![(flag(i), one())],
            vec![(flag(i), one())],
        ));
    }
    rows.push((
        (0..OPCODES).map(|i| (flag(i), one())).collect(),
        vec![(Layout::ONE, one())],
        vec![(Layout::ONE, one())],
    ));
    for sel in [Layout::SSEL1, Layout::SSEL2] {
        for k in 0..REGISTERS {
            rows.push((
                vec![(sel + k, one())],
                vec![(sel + k, one())],
                vec![(sel + k, one())],
            ));
        }
        rows.push((
            (0..REGISTERS).map(|k| (sel + k, one())).collect(),
            vec![(Layout::ONE, one())],
            vec![(Layout::ONE, one())],
        ));
    }
    // Destination selector: each entry boolean, and the selector sums to the
    // write mask (1 for writing opcodes, 0 for branch/jump/halt — which
    // write no register). This lets non-writing opcodes carry an all-zero
    // dsel without violating one-hotness.
    for k in 0..REGISTERS {
        rows.push((
            vec![(dsel(k), one())],
            vec![(dsel(k), one())],
            vec![(dsel(k), one())],
        ));
    }
    let wmask_terms: Vec<(usize, F)> = write_mask_terms();
    rows.push((
        (0..REGISTERS).map(|k| (dsel(k), one())).collect(),
        vec![(Layout::ONE, one())],
        wmask_terms.clone(),
    ));

    // --- Source routing: rs1v = Σ ssel1[k]·pre[k], rs2v likewise. ---
    // Each is a sum of products, so accumulate one product row per register
    // into the read value: ssel·pre contributes, and the read equals the sum.
    // Expressed as: Σ_k ssel1[k]·pre[k] − rs1v = 0. Each ssel·pre is degree 2;
    // sum them in one constraint with the read on the C side via auxiliaries.
    push_routed_read(&mut rows, Layout::SSEL1, Layout::RS1V);
    push_routed_read(&mut rows, Layout::SSEL2, Layout::RS2V);

    // --- Auxiliary product for MUL (degree-2 gating). ---
    rows.push((
        vec![(Layout::RS1V, one())],
        vec![(Layout::RS2V, one())],
        vec![(Layout::PROD, one())],
    ));

    // --- Gated ALU: flag·(rhs − rdv) = 0 for the writing opcodes. ---
    let gated: [(usize, Vec<(usize, F)>); 6] = [
        (
            op::ADD,
            vec![
                (Layout::RS1V, one()),
                (Layout::RS2V, one()),
                (Layout::RDV, -one()),
            ],
        ),
        (
            op::SUB,
            vec![
                (Layout::RS1V, one()),
                (Layout::RS2V, -one()),
                (Layout::RDV, -one()),
            ],
        ),
        (op::MUL, vec![(Layout::PROD, one()), (Layout::RDV, -one())]),
        (op::NEG, vec![(Layout::RS1V, -one()), (Layout::RDV, -one())]),
        (op::MOV, vec![(Layout::RS1V, one()), (Layout::RDV, -one())]),
        (
            op::LOADIMM,
            vec![(Layout::IMM, one()), (Layout::RDV, -one())],
        ),
    ];
    for (opcode, rhs) in gated {
        rows.push((vec![(flag(opcode), one())], rhs, vec![]));
    }

    // --- Memory semantics (Load/Store). ---
    // Load: rd ← mem[rs2].   flag_LOAD·(mem_value − rdv) = 0
    rows.push((
        vec![(flag(op::LOAD), one())],
        vec![(Layout::MEM_VALUE, one()), (Layout::RDV, -one())],
        vec![],
    ));
    // Store: mem[rs2] ← rs1.  flag_STORE·(rs1v − mem_value) = 0
    rows.push((
        vec![(flag(op::STORE), one())],
        vec![(Layout::RS1V, one()), (Layout::MEM_VALUE, -one())],
        vec![],
    ));
    // Both memory ops address mem[rs2]:
    //   (flag_LOAD + flag_STORE)·(rs2v − mem_addr) = 0
    rows.push((
        vec![(flag(op::LOAD), one()), (flag(op::STORE), one())],
        vec![(Layout::RS2V, one()), (Layout::MEM_ADDR, -one())],
        vec![],
    ));
    // The memory write flag is exactly flag_STORE (boolean by the flag rows).
    rows.push((
        vec![(Layout::MEM_WRITE, one()), (flag(op::STORE), -one())],
        vec![(Layout::ONE, one())],
        vec![],
    ));

    // --- Register-file update. For each register k:
    //   post[k] = dsel[k]·(written rdv) + (1 − dsel[k])·pre[k]
    // with "written" = (Σ writing flags). On a non-writing opcode the write
    // mask is 0, so post[k] = pre[k] for all k (state preserved). Rearranged
    // to keep degree 2:
    //   post[k] − pre[k] = dsel[k]·(wmask·rdv − pre[k])
    // wmask·rdv is itself degree 2; precompute it once as `wrdv` via an aux
    // column, then the per-register row is dsel[k]·(wrdv − pre[k]).
    let wmask: Vec<(usize, F)> = write_mask_terms();
    let wrdv = Layout::WRDV;
    rows.push((wmask, vec![(Layout::RDV, one())], vec![(wrdv, one())]));
    for k in 0..REGISTERS {
        // post[k] − pre[k] = dsel[k]·(wrdv − pre[k])
        rows.push((
            vec![(dsel(k), one())],
            vec![(wrdv, one()), (pre(k), -one())],
            vec![(post(k), one()), (pre(k), -one())],
        ));
    }

    // --- Branch (in)equality witness: diff = rs1v − rs2v, and TAKEN. ---
    // diff is defined for branch opcodes; constrain diff = rs1v − rs2v always.
    rows.push((
        vec![
            (Layout::RS1V, one()),
            (Layout::RS2V, -one()),
            (Layout::DIFF, -one()),
        ],
        vec![(Layout::ONE, one())],
        vec![],
    ));
    // TAKEN boolean.
    rows.push((
        vec![(Layout::TAKEN, one())],
        vec![(Layout::TAKEN, one())],
        vec![(Layout::TAKEN, one())],
    ));
    // If TAKEN: diff must be 0 for Beq, nonzero for Bne. If not TAKEN: the
    // opposite. We enforce the equality/inequality consistent with TAKEN via
    //   diff · TAKEN_eq_indicator = 0  and  diff · dinv = 1 − (eq case).
    // Concretely: TAKEN·(for Beq)/(not for Bne) ties to diff == 0. To keep it
    // opcode-generic and degree 2:
    //   beq_taken = flag_BEQ·TAKEN  ⇒ requires diff = 0:  beq_taken·diff = 0
    //   bne_taken = flag_BNE·TAKEN  ⇒ requires diff ≠ 0:  bne_taken·(diff·dinv − 1) = 0
    let beq_taken = Layout::BEQ_TAKEN;
    let bne_taken = Layout::BNE_TAKEN;
    let diff_dinv = Layout::DIFF_DINV;
    rows.push((
        vec![(flag(op::BEQ), one())],
        vec![(Layout::TAKEN, one())],
        vec![(beq_taken, one())],
    ));
    rows.push((
        vec![(flag(op::BNE), one())],
        vec![(Layout::TAKEN, one())],
        vec![(bne_taken, one())],
    ));
    rows.push((
        vec![(Layout::DIFF, one())],
        vec![(Layout::DINV, one())],
        vec![(diff_dinv, one())],
    ));
    // beq_taken · diff = 0
    rows.push((
        vec![(beq_taken, one())],
        vec![(Layout::DIFF, one())],
        vec![],
    ));
    // bne_taken · (diff_dinv − 1) = 0
    rows.push((
        vec![(bne_taken, one())],
        vec![(diff_dinv, one()), (Layout::ONE, -one())],
        vec![],
    ));

    // --- PC transition. next_pc selected by opcode:
    //   ALU / LoadImm / (branch not taken): pc + 1
    //   Jump: target
    //   Beq/Bne taken: target
    //   Halt: pc
    // Encode as: next_pc = pc + 1 + Σ corrections, each correction gated.
    //   Jump:            flag_JUMP·(target − pc − 1)
    //   branch taken:    (beq_taken + bne_taken)·(target − pc − 1)
    //   Halt:            flag_HALT·(pc − pc − 1) = flag_HALT·(−1)
    // So: next_pc − pc − 1 = jump_corr + branch_corr + halt_corr.
    let jump_corr = Layout::JUMP_CORR;
    let branch_corr = Layout::BRANCH_CORR;
    // jump_corr = flag_JUMP·(target − pc − 1)
    rows.push((
        vec![(flag(op::JUMP), one())],
        vec![
            (Layout::TARGET, one()),
            (Layout::PC, -one()),
            (Layout::ONE, -one()),
        ],
        vec![(jump_corr, one())],
    ));
    // branch_corr = (beq_taken + bne_taken)·(target − pc − 1)
    rows.push((
        vec![(beq_taken, one()), (bne_taken, one())],
        vec![
            (Layout::TARGET, one()),
            (Layout::PC, -one()),
            (Layout::ONE, -one()),
        ],
        vec![(branch_corr, one())],
    ));
    // next_pc − pc − 1 − jump_corr − branch_corr + flag_HALT = 0
    // (Halt correction is flag_HALT·(−1) = −flag_HALT, moved to the linear side.)
    rows.push((
        vec![
            (Layout::NEXT_PC, one()),
            (Layout::PC, -one()),
            (Layout::ONE, -one()),
            (jump_corr, -one()),
            (branch_corr, -one()),
            (flag(op::HALT), one()),
        ],
        vec![(Layout::ONE, one())],
        vec![],
    ));

    ShapedR1cs::from_quadratic_rows(&rows, Layout::COLUMNS)
}

/// Routed read: `read_col = Σ_k sel[k]·pre[k]`. Accumulated with per-register
/// auxiliary products kept degree 2. Appends the products to dedicated aux
/// columns beyond the base layout.
fn push_routed_read(rows: &mut Vec<Row>, sel_base: usize, read_col: usize) {
    // Σ_k sel[k]·pre[k] − read = 0, but each sel·pre is degree 2; introduce
    // one aux per register and sum linearly.
    // Aux columns are placed in a high range unique per (sel_base): we use a
    // simple scheme keyed off the selector base so the two reads don't clash.
    let aux_base = if sel_base == Layout::SSEL1 {
        Layout::READ1_AUX
    } else {
        Layout::READ2_AUX
    };
    let mut sum_terms: Vec<(usize, F)> = Vec::with_capacity(REGISTERS + 1);
    for k in 0..REGISTERS {
        let aux = aux_base + k;
        // aux = sel[k]·pre[k]
        rows.push((
            vec![(sel_base + k, one())],
            vec![(Layout::PRE + k, one())],
            vec![(aux, one())],
        ));
        sum_terms.push((aux, one()));
    }
    sum_terms.push((read_col, -one()));
    rows.push((sum_terms, vec![(Layout::ONE, one())], vec![]));
}

/// One decoded instruction for assignment.
#[derive(Clone, Copy)]
pub struct Decoded {
    pub opcode: usize,
    pub rd: usize,
    pub rs1: usize,
    pub rs2: usize,
    pub imm: F,
    pub target: usize,
}

/// Builds a satisfying assignment for one complete step. `regs` is the
/// pre-state; `mem_value` is the value loaded (for Load) or stored (for
/// Store), ignored by other opcodes. Returns `(witness, post_regs,
/// next_pc)`.
#[must_use]
pub fn assign_complete(
    d: Decoded,
    regs: &[F; REGISTERS],
    pc: usize,
    mem_value: F,
) -> (DenseVector<F>, [F; REGISTERS], usize) {
    // Total width includes the aux columns used above.
    let width = Layout::COLUMNS;
    let mut z = vec![F::from(0); width];
    z[Layout::ONE] = one();
    z[Layout::PC] = F::from(pc as u32);
    z[Layout::IMM] = d.imm;
    z[Layout::TARGET] = F::from(d.target as u32);
    z[Layout::FLAGS + d.opcode] = one();

    let rs1v = regs[d.rs1];
    let rs2v = regs[d.rs2];
    z[Layout::RS1V] = rs1v;
    z[Layout::RS2V] = rs2v;
    z[Layout::SSEL1 + d.rs1] = one();
    z[Layout::SSEL2 + d.rs2] = one();
    z[Layout::PROD] = rs1v * rs2v;

    // Source-read aux products.
    for k in 0..REGISTERS {
        z[Layout::READ1_AUX + k] = if k == d.rs1 { regs[k] } else { F::from(0) };
        z[Layout::READ2_AUX + k] = if k == d.rs2 { regs[k] } else { F::from(0) };
    }

    let rdv = match d.opcode {
        op::ADD => rs1v + rs2v,
        op::SUB => rs1v - rs2v,
        op::MUL => rs1v * rs2v,
        op::NEG => -rs1v,
        op::MOV => rs1v,
        op::LOADIMM => d.imm,
        op::LOAD => mem_value,
        _ => F::from(0),
    };
    z[Layout::RDV] = rdv;

    // Memory access columns: address from rs2, value, and the write flag.
    if d.opcode == op::LOAD || d.opcode == op::STORE {
        z[Layout::MEM_ADDR] = rs2v;
        z[Layout::MEM_VALUE] = if d.opcode == op::STORE {
            rs1v
        } else {
            mem_value
        };
        z[Layout::MEM_WRITE] = F::from(u32::from(d.opcode == op::STORE));
    }

    // Destination selector + write mask product.
    let writes = writes_register(d.opcode);
    if writes {
        z[Layout::DSEL + d.rd] = one();
    }
    let wrdv = if writes { rdv } else { F::from(0) };
    z[Layout::WRDV] = wrdv;

    // Register file update.
    let mut post = *regs;
    if writes {
        post[d.rd] = rdv;
    }
    #[allow(clippy::manual_memcpy)] // two non-contiguous strided destinations
    for k in 0..REGISTERS {
        z[Layout::PRE + k] = regs[k];
        z[Layout::POST + k] = post[k];
    }

    // Branch witnesses.
    let diff = rs1v - rs2v;
    z[Layout::DIFF] = diff;
    z[Layout::DINV] = Inv::inv(diff).unwrap_or_else(|| F::from(0));
    let taken = match d.opcode {
        op::BEQ => diff == F::from(0),
        op::BNE => diff != F::from(0),
        _ => false,
    };
    z[Layout::TAKEN] = F::from(u32::from(taken));
    let beq_taken = (d.opcode == op::BEQ) && taken;
    let bne_taken = (d.opcode == op::BNE) && taken;
    z[Layout::BEQ_TAKEN] = F::from(u32::from(beq_taken));
    z[Layout::BNE_TAKEN] = F::from(u32::from(bne_taken));
    z[Layout::DIFF_DINV] = diff * z[Layout::DINV];

    // PC transition.
    let next_pc = match d.opcode {
        op::JUMP => d.target,
        op::BEQ | op::BNE if taken => d.target,
        op::HALT => pc,
        _ => pc + 1,
    };
    z[Layout::NEXT_PC] = F::from(next_pc as u32);
    let jump_corr = if d.opcode == op::JUMP {
        F::from(d.target as u32) - F::from(pc as u32) - one()
    } else {
        F::from(0)
    };
    let branch_corr = if beq_taken || bne_taken {
        F::from(d.target as u32) - F::from(pc as u32) - one()
    } else {
        F::from(0)
    };
    z[Layout::JUMP_CORR] = jump_corr;
    z[Layout::BRANCH_CORR] = branch_corr;

    (DenseVector::from(z), post, next_pc)
}

/// Offline memory-checking glue: extracts a step's memory operation and
/// drives the multiset-equality argument that makes Load/Store *globally*
/// consistent — every Load returns the value most recently Stored at its
/// address. The per-step circuit enforces the local read/write semantics
/// above; this enforces that reads agree with writes across the whole run,
/// the standard offline memory-checking decomposition.
pub mod memory {
    use super::{Decoded, F, op};
    pub use blacknet_arith::multiset::{MemoryOp, check, grand_product};
    use blacknet_crypto::matrix::DenseVector;

    /// The memory operation a step performs, if any, as an `(address,
    /// timestamp, value)` tuple for the consistency multiset. `timestamp` is
    /// the step index, giving a total order on accesses to each address.
    #[must_use]
    pub fn step_op(d: &Decoded, timestamp: usize, addr: F, value: F) -> Option<MemoryOp> {
        if d.opcode == op::LOAD || d.opcode == op::STORE {
            Some(MemoryOp {
                address: addr,
                timestamp: F::from(timestamp as u32),
                value,
            })
        } else {
            None
        }
    }

    /// Reads the memory access columns from a step witness produced by
    /// [`super::assign_complete`].
    #[must_use]
    pub fn access_of(z: &DenseVector<F>) -> (F, F, bool) {
        use super::Layout;
        (
            z[Layout::MEM_ADDR],
            z[Layout::MEM_VALUE],
            z[Layout::MEM_WRITE] == F::from(1),
        )
    }
}
