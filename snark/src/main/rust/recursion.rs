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

//! The folding verifier as constraints: the in-circuit counterpart of the
//! public computation in [`crate::committedfold::fold`], which is what gets
//! embedded into the step circuit for recursion (IVC). The relations are
//! linear plus one multiplication per limb, since folding was designed to
//! make the verifier homomorphic:
//!
//! `u = u₁ + r·u₂` and, per commitment limb, `c[k] = c₁[k] + r·c₂[k]`.
//!
//! Remaining for full IVC, stated honestly: the challenge `r` is a public
//! input here; deriving it in-circuit needs the Poseidon2 duplex circuit
//! (already in `blacknet_crypto::circuit::symmetric`) absorbed with the
//! same context, and the norm accounting needs in-circuit range gadgets
//! (`blacknet_crypto::circuit::logicgate` decomposition).

use crate::witnesscommitment::ROWS;
use blacknet_crypto::circuit::builder::CircuitBuilder;
use blacknet_crypto::customizableconstraintsystem::CustomizableConstraintSystem;
use blacknet_crypto::pervushin::PervushinField;

pub type F = PervushinField;

/// Variable order of the fold verifier circuit, all public inputs:
/// `r, u1, u2, u, c1[0..ROWS], c2[0..ROWS], c[0..ROWS]`.
pub const PUBLIC_INPUTS: usize = 4 + 3 * ROWS;

/// Builds the CCS of the fold verifier relation.
#[must_use]
pub fn fold_verifier_circuit() -> CustomizableConstraintSystem<F> {
    let circuit = CircuitBuilder::<F>::new(2);
    {
        let scope = circuit.scope("fold_verifier");
        let r = scope.public_input();
        let u1 = scope.public_input();
        let u2 = scope.public_input();
        let u = scope.public_input();
        let c1: Vec<_> = (0..ROWS).map(|_| scope.public_input()).collect();
        let c2: Vec<_> = (0..ROWS).map(|_| scope.public_input()).collect();
        let c: Vec<_> = (0..ROWS).map(|_| scope.public_input()).collect();
        // u - u1 = r * u2
        scope.constrain(r * u2, u - u1);
        // c[k] - c1[k] = r * c2[k]
        for k in 0..ROWS {
            scope.constrain(r * c2[k], c[k] - c1[k]);
        }
    }
    circuit.ccs()
}

/// Assigns the public inputs of one fold in circuit variable order.
#[must_use]
pub fn assign(r: F, u1: F, u2: F, u: F, c1: &[F], c2: &[F], c: &[F]) -> Vec<F> {
    let mut z = Vec::with_capacity(1 + PUBLIC_INPUTS);
    z.push(F::from(1));
    z.extend([r, u1, u2, u]);
    z.extend_from_slice(c1);
    z.extend_from_slice(c2);
    z.extend_from_slice(c);
    z
}
