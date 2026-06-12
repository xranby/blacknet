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

//! The folding verifier as constraints, with the challenge derived
//! *in-circuit*: the Poseidon2 duplex circuit absorbs the same public fold
//! data as the plain transcript, the squeezed element is decomposed into
//! bits, and the low [`CHALLENGE_BITS`] bits recompose into the small
//! challenge used by the fold relations
//!
//! `u = u₁ + r·u₂` and, per commitment limb, `c[k] = c₁[k] + r·c₂[k]`.
//!
//! Bit decomposition over the Pervushin field (modulus `2⁶¹ − 1`) is unique
//! on canonical representatives except for zero, which also admits the
//! all-ones pattern; the duplex squeezing zero has negligible probability
//! and an adversarial assigner exploiting it gains only the challenge
//! `2¹⁶ − 1` versus `0`, both inside the exceptional set.
//!
//! Remaining for full IVC: composing this with the sumcheck verifier
//! circuit (already in `blacknet_crypto::circuit::sumcheck`) to express one
//! whole HyperNova multifold, and in-circuit norm accounting.

use crate::witnesscommitment::CHALLENGE_BITS;
use blacknet_crypto::algebra::IntegerRing;
use blacknet_crypto::circuit::builder::{CircuitBuilder, Constant, LinearCombination};
use blacknet_crypto::circuit::logicgate::LogicGate;
use blacknet_crypto::circuit::symmetric::DuplexPoseidon2Pervushin as DuplexCircuit;
use blacknet_crypto::customizableconstraintsystem::CustomizableConstraintSystem;
use blacknet_crypto::pervushin::PervushinField;
use blacknet_crypto::symmetric::Duplexer;

pub type F = PervushinField;

/// Bits of a Pervushin field element.
pub const FIELD_BITS: usize = 61;

/// Public inputs in order: `u1, u2, u, c1[0..rows], c2[0..rows], c[0..rows]`.
#[must_use]
pub const fn public_inputs(rows: usize) -> usize {
    3 + 3 * rows
}

/// Builds the CCS of the fold verifier relation with in-circuit challenge
/// derivation. The duplex and the bit decomposition allocate auxiliary
/// variables; the matching assignment is produced by [`assign`].
#[must_use]
pub fn fold_verifier_circuit(rows: usize) -> CustomizableConstraintSystem<F> {
    let circuit = CircuitBuilder::<F>::new(2);
    {
        let scope = circuit.scope("fold_verifier");
        let u1: LinearCombination<F> = scope.public_input().into();
        let u2: LinearCombination<F> = scope.public_input().into();
        let u: LinearCombination<F> = scope.public_input().into();
        let lc = |_: usize| -> LinearCombination<F> { scope.public_input().into() };
        let c1: Vec<_> = (0..rows).map(lc).collect();
        let c2: Vec<_> = (0..rows).map(lc).collect();
        let c: Vec<_> = (0..rows).map(lc).collect();

        // Transcript: absorb the public fold data, squeeze the challenge.
        let mut duplex = DuplexCircuit::new(&circuit);
        for limbs in [&c1, &c2] {
            for limb in limbs {
                duplex.absorb(limb.clone());
            }
        }
        duplex.absorb(u1.clone());
        duplex.absorb(u2.clone());
        let e: LinearCombination<F> = duplex.squeeze();

        // Truncate: decompose into bits, recompose the low CHALLENGE_BITS.
        let gate = LogicGate::new(&circuit);
        let bits: Vec<LinearCombination<F>> =
            (0..FIELD_BITS).map(|_| scope.auxiliary().into()).collect();
        gate.check_range_slice(&bits);
        let pow = |i: usize| Constant::new(<F as IntegerRing>::new(1i64 << i));
        let recomposed = bits
            .iter()
            .enumerate()
            .fold(LinearCombination::default(), |acc, (i, b)| acc + b * pow(i));
        scope.constrain(recomposed, e);
        let r = bits[..CHALLENGE_BITS as usize]
            .iter()
            .enumerate()
            .fold(LinearCombination::default(), |acc, (i, b)| acc + b * pow(i));

        // Fold relations with the derived challenge.
        scope.constrain(&r * &u2, u - u1);
        for k in 0..rows {
            scope.constrain(&r * &c2[k], &c[k] - &c1[k]);
        }
    }
    circuit.ccs()
}

/// Auxiliary assignment of one fold: mirrors the circuit's allocation
/// order. `e` is the element the plain transcript squeezed.
pub mod assigner {
    use super::{F, FIELD_BITS};
    use blacknet_crypto::algebra::IntegerRing;
    use blacknet_crypto::assigner::assigment::Assigment;
    use blacknet_crypto::assigner::symmetric::DuplexPoseidon2Pervushin as DuplexAssigner;
    use blacknet_crypto::symmetric::Duplexer;

    /// Fills the auxiliary variables (duplex permutations and challenge
    /// bits) into `z`, mirroring [`super::fold_verifier_circuit`]. The
    /// public inputs must already be in `z`. Returns the squeezed element.
    pub fn fill(z: &Assigment<F>, u1: F, u2: F, c1: &[F], c2: &[F]) -> F {
        let mut duplex = DuplexAssigner::new(z);
        for limbs in [c1, c2] {
            for &limb in limbs {
                duplex.absorb(limb);
            }
        }
        duplex.absorb(u1);
        duplex.absorb(u2);
        let e: F = duplex.squeeze();
        let canonical = e.canonical();
        for i in 0..FIELD_BITS {
            z.push(F::from(u32::from((canonical >> i) & 1 == 1)));
        }
        e
    }
}
