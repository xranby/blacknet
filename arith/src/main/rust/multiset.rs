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

//! Milestone 6 seed: probabilistic multiset equality — the primitive behind
//! offline memory checking (program fetch and RAM read/write consistency).
//!
//! Two multisets of tuples are equal iff the grand products
//! `∏ (γ - fingerprint(tuple))` agree, except with probability
//! `|multiset| / |F|` over the challenges `(γ, β)` squeezed from the
//! transcript after both multisets are absorbed.

use blacknet_crypto::pervushin::PervushinField;
use blacknet_crypto::symmetric::{Duplexer, Squeeze};

pub type F = PervushinField;

/// A `(address, timestamp, value)` tuple of a memory operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryOp {
    pub address: F,
    pub timestamp: F,
    pub value: F,
}

impl MemoryOp {
    /// Reed–Solomon fingerprint with challenge `beta`.
    fn fingerprint(&self, beta: F) -> F {
        self.address + beta * self.timestamp + beta * beta * self.value
    }
}

/// The grand product `∏ (gamma - fingerprint_beta(op))`.
#[must_use]
pub fn grand_product(ops: &[MemoryOp], gamma: F, beta: F) -> F {
    ops.iter()
        .map(|op| gamma - op.fingerprint(beta))
        .fold(F::from(1), |acc, e| acc * e)
}

/// Checks multiset equality of `reads` and `writes` with challenges from the
/// caller-prepared transcript. The caller must absorb both multisets (or a
/// binding commitment to them) before invoking, otherwise the challenges are
/// not sound.
pub fn check<D: Duplexer<Msg = F>>(reads: &[MemoryOp], writes: &[MemoryOp], duplex: &mut D) -> bool
where
    F: Squeeze<F>,
{
    if reads.len() != writes.len() {
        return false;
    }
    let gamma: F = duplex.squeeze();
    let beta: F = duplex.squeeze();
    grand_product(reads, gamma, beta) == grand_product(writes, gamma, beta)
}
