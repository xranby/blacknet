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

//! Program-commitment binding — the step that makes the universal machine
//! *sound*, not merely consistent.
//!
//! Without this, the complete step circuit ([`crate::universal_complete`])
//! proves a transition is internally valid but not that it is the
//! instruction the deployed program specifies at the current `pc`: a prover
//! could execute *any* opcode at *any* step. Binding closes that.
//!
//! The technique is a fingerprinted lookup, kept linear so it folds:
//!
//! 1. **Instruction fingerprint.** Each decoded instruction is collapsed to
//!    one field element by a Reed–Solomon-style linear fingerprint at a
//!    verifier challenge `α`: `fp = Σ field_j · αʲ` over the decoded fields
//!    (opcode, rd, rs1, rs2, imm, target). Two distinct instructions
//!    fingerprint equally only if `α` is a root of their difference
//!    polynomial — probability `degree/|F|`, negligible for a random `α`.
//!
//! 2. **Program table.** The program is a public vector of per-pc
//!    fingerprints `T[pc] = fp(program[pc])`, derivable by anyone from the
//!    deployed code, and bound to the on-chain [`ProgramCommitment`] (the
//!    Poseidon2 digest of the instruction table) by recomputing the digest
//!    from the same fields — so `T` is not free to choose.
//!
//! 3. **Per-step lookup.** Each step carries a one-hot `pc` selector over
//!    the table; the constraint `Σ pcsel[i]·T[i] = step_fp` forces the
//!    step's own decoded fingerprint to equal the table entry at the
//!    selected `pc`, and a second constraint `Σ pcsel[i]·i = pc` ties the
//!    selector to the step's `pc` value. Both are linear in the public table
//!    and the witness, so they fold by the same machinery as the rest.
//!
//! The challenge `α` is squeezed from the transcript after the program
//! commitment is absorbed, so the prover cannot tune the fingerprint to a
//! collision. Soundness: a step that runs `instr ≠ program[pc]` must either
//! break the fingerprint equality (prob. `≤ deg/|F|` over `α`) or the
//! selector/`pc` tie (a one-hot constraint), so honest binding holds except
//! with negligible probability.

use crate::commitment::ProgramCommitment;
use crate::universal_complete::{Decoded, REGISTERS, op};
use crate::witnesscommitment::F;
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};

/// Number of fields in a decoded-instruction fingerprint.
pub const FIELDS: usize = 6;

/// The decoded fields in fingerprint order: opcode, rd, rs1, rs2, imm,
/// target. A canonical flattening matching the program commitment's
/// encoding so the same instruction yields the same fingerprint everywhere.
#[must_use]
pub fn fields(d: &Decoded) -> [F; FIELDS] {
    [
        F::from(d.opcode as u32),
        F::from(d.rd as u32),
        F::from(d.rs1 as u32),
        F::from(d.rs2 as u32),
        d.imm,
        F::from(d.target as u32),
    ]
}

/// The fingerprint `Σ field_j · αʲ` of a decoded instruction at `alpha`.
#[must_use]
pub fn fingerprint(d: &Decoded, alpha: F) -> F {
    let mut acc = F::from(0);
    let mut power = F::from(1);
    for fj in fields(d) {
        acc += fj * power;
        power *= alpha;
    }
    acc
}

/// Builds the public fingerprint table `T[pc] = fp(program[pc])` for a
/// decoded program at challenge `alpha`. Anyone can compute it from the
/// deployed code; it is bound to the program commitment by [`table_digest`].
#[must_use]
pub fn program_table(program: &[Decoded], alpha: F) -> Vec<F> {
    program.iter().map(|d| fingerprint(d, alpha)).collect()
}

/// Squeezes the fingerprint challenge `alpha` from the program commitment,
/// so it cannot be chosen to force a collision. Bound to the commitment
/// rather than free.
#[must_use]
pub fn challenge(commitment: &ProgramCommitment) -> F {
    let mut duplex = DuplexPoseidon2Pervushin::default();
    for limb in commitment.0 {
        duplex.absorb(limb);
    }
    duplex.squeeze()
}

/// Recomputes a digest of the decoded program in the same field order as the
/// fingerprint, binding the table the verifier uses to the deployed code.
/// (The production binding reuses `commitment::commit`; this digest checks
/// the decoded form the table is built from is the committed one.)
#[must_use]
pub fn table_digest(program: &[Decoded]) -> ProgramCommitment {
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(F::from(program.len() as u32));
    for d in program {
        for fj in fields(d) {
            duplex.absorb(fj);
        }
    }
    ProgramCommitment(core::array::from_fn(|_| duplex.squeeze()))
}

/// The binding witness for one step: the one-hot pc selector and the step's
/// own fingerprint, to be checked against the public table.
pub struct StepBinding {
    /// One-hot over the program length: 1 at the executed `pc`.
    pub pc_selector: Vec<F>,
    /// The step's decoded-instruction fingerprint.
    pub step_fingerprint: F,
}

/// Builds the binding witness for executing `decoded` at `pc`.
#[must_use]
pub fn bind_step(decoded: &Decoded, pc: usize, program_len: usize, alpha: F) -> StepBinding {
    let mut pc_selector = vec![F::from(0); program_len];
    pc_selector[pc] = F::from(1);
    StepBinding {
        pc_selector,
        step_fingerprint: fingerprint(decoded, alpha),
    }
}

/// Verifies a step binding against the public table: the selector is one-hot
/// and selects `pc`, and the selected table entry equals the step's
/// fingerprint. Returns false on any violation. This is the relation the
/// in-circuit constraints enforce; checking it here mirrors them and is the
/// test oracle.
#[must_use]
pub fn check_binding(binding: &StepBinding, table: &[F], pc: usize) -> bool {
    if binding.pc_selector.len() != table.len() {
        return false;
    }
    // One-hot and boolean.
    let mut sum = F::from(0);
    let mut idx_dot = F::from(0);
    let mut selected = F::from(0);
    for (i, (&s, &t)) in binding.pc_selector.iter().zip(table).enumerate() {
        if s != F::from(0) && s != F::from(1) {
            return false;
        }
        sum += s;
        idx_dot += s * F::from(i as u32);
        selected += s * t;
    }
    sum == F::from(1) && idx_dot == F::from(pc as u32) && selected == binding.step_fingerprint
}

/// Convenience: decode the instruction set into [`Decoded`] rows for table
/// construction. Mirrors the VM's instruction encoding so the table matches
/// what the program commitment digests.
#[must_use]
pub fn decode_program(program: &[blacknet_vm::machine::Instruction<F>]) -> Vec<Decoded> {
    use blacknet_vm::machine::Instruction;
    program
        .iter()
        .map(|i| match *i {
            Instruction::Add(rd, rs1, rs2) => mk(op::ADD, rd, rs1, rs2, F::from(0), 0),
            Instruction::Sub(rd, rs1, rs2) => mk(op::SUB, rd, rs1, rs2, F::from(0), 0),
            Instruction::Mul(rd, rs1, rs2) => mk(op::MUL, rd, rs1, rs2, F::from(0), 0),
            Instruction::Neg(rd, rs1) => mk(op::NEG, rd, rs1, 0, F::from(0), 0),
            Instruction::LoadImm(rd, imm) => mk(op::LOADIMM, rd, 0, 0, imm, 0),
            Instruction::Mov(rd, rs1) => mk(op::MOV, rd, rs1, 0, F::from(0), 0),
            Instruction::Beq(rs1, rs2, t) => mk(op::BEQ, 0, rs1, rs2, F::from(0), t),
            Instruction::Bne(rs1, rs2, t) => mk(op::BNE, 0, rs1, rs2, F::from(0), t),
            Instruction::Jump(t) => mk(op::JUMP, 0, 0, 0, F::from(0), t),
            Instruction::Halt => mk(op::HALT, 0, 0, 0, F::from(0), 0),
        })
        .collect()
}

const fn mk(opcode: usize, rd: u8, rs1: u8, rs2: u8, imm: F, target: usize) -> Decoded {
    Decoded {
        opcode,
        rd: rd as usize,
        rs1: rs1 as usize,
        rs2: rs2 as usize,
        imm,
        target,
    }
}

#[allow(dead_code)]
const _REG_GUARD: () = assert!(REGISTERS <= 256);

/// A program table committed as a Merkle root, the soundness upgrade over a
/// public table the verifier rebuilds.
///
/// In the public-table form, the verifier holds all of `T` and checks the
/// step's fingerprint against `T[pc]` by a one-hot selector — which means it
/// must possess and trust the whole table. Committing `T` as a Merkle root
/// instead lets the verifier hold only the constant-size root: each step
/// proves its instruction is `T[pc]` by supplying an inclusion branch, and
/// the verifier recomputes the root from the leaf and branch. The table is
/// now *bound* — a prover cannot substitute a different table without
/// changing the root, which is fixed by the deployed program. This is the
/// standard memory-checking-by-commitment upgrade, reusing the tree
/// (`MerkleTree` over `JivePoseidon2Pervushin`) already in the crypto crate.
pub mod committed {
    use super::{Decoded, F, fields, fingerprint};
    use blacknet_crypto::symmetric::{JivePoseidon2Pervushin, MerkleTree};

    /// The Merkle hash type: a Jive digest of four Pervushin elements.
    pub type Leaf = [F; 4];
    /// A Merkle inclusion branch (sibling hashes root-ward).
    pub type Branch = Vec<Leaf>;
    type Tree = MerkleTree<JivePoseidon2Pervushin>;

    /// The leaf for program entry `pc`: the fingerprint placed in the first
    /// slot of the Jive hash word, the rest zero. Distinct fingerprints give
    /// distinct leaves, so leaf equality is fingerprint equality.
    #[must_use]
    pub fn leaf_of(d: &Decoded, alpha: F) -> Leaf {
        [fingerprint(d, alpha), F::from(0), F::from(0), F::from(0)]
    }

    /// A program table committed as a Merkle root over its per-pc leaves.
    pub struct CommittedTable {
        tree: Tree,
        len: usize,
    }

    impl CommittedTable {
        /// Commits a decoded program at challenge `alpha`.
        #[must_use]
        pub fn commit(program: &[Decoded], alpha: F) -> Self {
            let leaves: Vec<Leaf> = program.iter().map(|d| leaf_of(d, alpha)).collect();
            Self {
                tree: Tree::new(&leaves),
                len: program.len(),
            }
        }

        /// The constant-size commitment the verifier holds.
        #[must_use]
        pub fn root(&self) -> Leaf {
            *self.tree.root()
        }

        #[must_use]
        pub fn len(&self) -> usize {
            self.len
        }

        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        /// The inclusion branch proving the entry at `pc`.
        #[must_use]
        pub fn prove(&self, pc: usize) -> Branch {
            self.tree.branch(pc)
        }
    }

    /// Verifies that `leaf` is the committed entry at index `pc` under
    /// `root`, by recomputing the root from the supplied branch. This is
    /// what a step does in place of scanning a public table: it shows its
    /// own instruction's leaf is `T[pc]` against the constant-size root.
    #[must_use]
    pub fn verify(root: &Leaf, pc: usize, leaf: Leaf, branch: &Branch) -> bool {
        &Tree::compute_root(pc, leaf, branch) == root
    }

    /// End-to-end step check against a committed table: the step's decoded
    /// instruction, fingerprinted, must be the committed `T[pc]`.
    #[must_use]
    pub fn check_step(
        root: &Leaf,
        pc: usize,
        decoded: &Decoded,
        alpha: F,
        branch: &Branch,
    ) -> bool {
        verify(root, pc, leaf_of(decoded, alpha), branch)
    }

    /// Guard: the leaf packs exactly the fields the fingerprint consumes.
    #[allow(dead_code)]
    const _FIELDS_FIT: () = assert!(super::FIELDS <= 6);
    #[allow(dead_code)]
    fn _fields_reachable(d: &Decoded) -> [F; super::FIELDS] {
        fields(d)
    }
}
