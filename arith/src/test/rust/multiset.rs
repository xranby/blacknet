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

use blacknet_arith::multiset::{F, MemoryOp, check};
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};

fn op(a: i32, t: i32, v: i32) -> MemoryOp {
    MemoryOp {
        address: F::from(a),
        timestamp: F::from(t),
        value: F::from(v),
    }
}

#[test]
fn equal_multisets_pass() {
    let reads = [op(1, 0, 5), op(2, 1, 7), op(1, 2, 5)];
    let mut writes = reads;
    writes.swap(0, 2);
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(F::from(reads.len() as u32));
    assert!(check(&reads, &writes, &mut duplex));
}

#[test]
fn unequal_multisets_fail() {
    let reads = [op(1, 0, 5), op(2, 1, 7)];
    let writes = [op(1, 0, 5), op(2, 1, 8)];
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(F::from(reads.len() as u32));
    assert!(!check(&reads, &writes, &mut duplex));
}

#[test]
fn length_mismatch_fails() {
    let reads = [op(1, 0, 5)];
    let writes = [op(1, 0, 5), op(1, 0, 5)];
    let mut duplex = DuplexPoseidon2Pervushin::default();
    assert!(!check(&reads, &writes, &mut duplex));
}
