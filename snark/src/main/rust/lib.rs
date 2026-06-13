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

//! Proving and verifying VM execution. The `verify` path in [`proof`] is
//! the consensus-critical surface; everything else is prover-side.

pub mod commitment;
pub mod committedfold;
pub mod fold;
pub mod hypernova;
pub mod ivc;
pub mod masking;
pub mod modulecommitment;
pub mod opening;
pub mod pipeline;
pub mod proof;
pub mod recursion;
pub mod recursive;
pub mod unifiedcommitment;
pub mod witnesscommitment;
pub mod zk;
