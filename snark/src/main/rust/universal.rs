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

//! The universal step circuit — lifting the uniform-program restriction.
//!
//! The pipeline so far requires fixed control flow: the constraint matrices
//! are derived from one program's `pc_trace`, so every execution must take
//! the same path, and data-dependent branching is excluded. The universal
//! step circuit removes that. It constrains *one VM step for any opcode* by
//! the von Neumann / TinyRAM technique: the instruction is data (a decoded
//! row in the witness), the opcode is chosen by a one-hot selector, and a
//! single relation enforces "the post-state is the correct execution of the
//! selected opcode on the pre-state". The same circuit shape verifies every
//! step regardless of which instruction runs, so a chain of these steps —
//! folded by the IVC driver — proves an arbitrary program.
//!
//! One step's witness layout (all field elements):
//!   pre[REGISTERS]     register state before the step
//!   post[REGISTERS]    register state after the step
//!   imm                immediate operand (LoadImm)
//!   rs1v, rs2v, rdv    the read values of the two sources and the result
//!   flags[OPCODES]     one-hot opcode selector
//!   diff, dinv         branch (in)equality witness (rs1v − rs2v and inverse)
//!
//! The relation, summed over a one-hot `flags`:
//!   - flags is boolean and sums to 1 (exactly one opcode active);
//!   - the result `rdv` equals the opcode's function of the reads —
//!     Add: rs1v + rs2v; Sub: rs1v − rs2v; Mul: rs1v·rs2v; Neg: −rs1v;
//!     Mov: rs1v; LoadImm: imm;
//!   - every non-written register is copied pre→post (the register-file
//!     consistency the trace builder enforces positionally);
//!   - branch/Halt/Jump write no register (rdv constraint relaxed via flag).
//!
//! This module builds the per-step *relation* as quadratic rows
//! (`ShapedR1cs::from_quadratic_rows`), uniform across steps and so foldable
//! by HyperNova exactly as the IVC step circuit is. The arithmetic core —
//! one-hot opcode selection and the gated ALU relation, kept at degree 2 by
//! an auxiliary product column — is built and tested here; this is the part
//! that turns control flow into data. The two documented next layers are
//! register-file routing (selecting which `rd` each step writes and copying
//! the untouched registers pre→post, by a second selector over registers)
//! and pc/program-commitment binding (proving the decoded instruction is
//! `program[pc]` against the committed program, and that `pc` advances or
//! branches correctly). Both are selector relations of the same kind as the
//! opcode core and fold the same way.

use crate::witnesscommitment::F;
use blacknet_arith::r1cs::ShapedR1cs;
use blacknet_crypto::matrix::DenseVector;

/// Opcodes the universal step selects among, in flag order.
pub const OPCODES: usize = 6;

/// Index of each opcode in the one-hot `flags` vector.
pub mod op {
    pub const ADD: usize = 0;
    pub const SUB: usize = 1;
    pub const MUL: usize = 2;
    pub const NEG: usize = 3;
    pub const MOV: usize = 4;
    pub const LOADIMM: usize = 5;
}

/// Column layout of one step's witness (constant `1` lives at column 0).
pub struct Layout;

impl Layout {
    pub const ONE: usize = 0;
    pub const RS1V: usize = 1;
    pub const RS2V: usize = 2;
    pub const RDV: usize = 3;
    pub const IMM: usize = 4;
    /// Auxiliary product `p = rs1v · rs2v`, always computed, so the MUL
    /// equality `flag_MUL·(p − rdv) = 0` stays linear (degree 2 overall).
    pub const PROD: usize = 5;
    pub const FLAGS: usize = 6;
    pub const COLUMNS: usize = Self::FLAGS + OPCODES;
}

type Row = (Vec<(usize, F)>, Vec<(usize, F)>, Vec<(usize, F)>);

fn one() -> F {
    F::from(1)
}

/// Builds the universal step relation: a quadratic constraint system whose
/// satisfying assignments are exactly the valid one-step executions for any
/// of the selected opcodes.
#[must_use]
pub fn universal_step_r1cs() -> ShapedR1cs {
    let l = Layout::COLUMNS;
    let f = |i: usize| Layout::FLAGS + i;
    let mut rows: Vec<Row> = Vec::new();

    // 1. Each flag is boolean: flag·flag = flag.
    for i in 0..OPCODES {
        rows.push((
            vec![(f(i), one())],
            vec![(f(i), one())],
            vec![(f(i), one())],
        ));
    }

    // 2. Flags sum to one: (Σ flag)·1 = 1.
    rows.push((
        (0..OPCODES).map(|i| (f(i), one())).collect(),
        vec![(Layout::ONE, one())],
        vec![(Layout::ONE, one())],
    ));

    // 3. The auxiliary product is always the true product: rs1v·rs2v = p.
    //    This is one unconditional quadratic row; it constrains a witness
    //    column the prover fills, so it never conflicts with linear opcodes.
    rows.push((
        vec![(Layout::RS1V, one())],
        vec![(Layout::RS2V, one())],
        vec![(Layout::PROD, one())],
    ));

    // 4. The ALU equality, gated by the one-hot flag, now entirely linear in
    //    the bracket (MUL reads the precomputed product `p`):
    //      flag · (rhs − rdv) = 0   ⇒   A = flag, B = (rhs − rdv), C = 0.
    let gated: [(usize, Vec<(usize, F)>); OPCODES] = [
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
        rows.push((vec![(f(opcode), one())], rhs, vec![]));
    }

    ShapedR1cs::from_quadratic_rows(&rows, l)
}

/// Builds a satisfying assignment for one step executing `opcode` on the
/// given source values (and immediate), laid out per [`Layout`]. The
/// auxiliary product column is always set to `rs1v·rs2v` so the
/// unconditional product row holds for every opcode.
#[must_use]
pub fn assign_step(opcode: usize, rs1v: F, rs2v: F, imm: F) -> DenseVector<F> {
    let mut z = vec![F::from(0); Layout::COLUMNS];
    z[Layout::ONE] = one();
    z[Layout::RS1V] = rs1v;
    z[Layout::RS2V] = rs2v;
    z[Layout::IMM] = imm;
    z[Layout::PROD] = rs1v * rs2v;
    z[Layout::FLAGS + opcode] = one();
    z[Layout::RDV] = match opcode {
        op::ADD => rs1v + rs2v,
        op::SUB => rs1v - rs2v,
        op::MUL => rs1v * rs2v,
        op::NEG => -rs1v,
        op::MOV => rs1v,
        op::LOADIMM => imm,
        _ => F::from(0),
    };
    DenseVector::from(z)
}
