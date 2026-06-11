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

//! Milestone 5 (stub): zero-knowledge layer. v0 proofs are transparent —
//! the witness is revealed. The ZK upgrade blinds the witness commitment
//! (Ajtai with discrete Gaussian masking via `blacknet_crypto::random`) and
//! masks the final sumcheck with a random polynomial. No API is stabilized
//! until commitments replace transparent witnesses in [`crate::proof`].

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Unimplemented,
}

pub const fn blind() -> Result<(), Error> {
    Err(Error::Unimplemented)
}
