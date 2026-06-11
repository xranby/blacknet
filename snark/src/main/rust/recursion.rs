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

//! Milestone 5 (stub): the folding verifier expressed as constraints, to be
//! embedded into the step circuit for true IVC. Blocked on porting the fold
//! arithmetic of [`crate::fold`] to `blacknet_crypto::circuit::builder` so
//! the same description yields circuit and assigner, as the crypto crate
//! does for sumcheck and Poseidon2.

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Unimplemented,
}

/// Will return the CCS of the fold verifier relation.
pub const fn fold_verifier_circuit() -> Result<(), Error> {
    Err(Error::Unimplemented)
}
