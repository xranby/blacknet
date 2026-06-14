/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

use blacknet_arith::r1cs::ShapedR1cs;
use blacknet_crypto::symmetric::{JivePoseidon2Pervushin, MerkleTree};
use blacknet_snark::programbinding::merkle_circuit::{RANK, assigner::verifies, inclusion_r1cs};
use blacknet_snark::witnesscommitment::F;

fn f(n: i32) -> F {
    F::from(n)
}

type Tree = MerkleTree<JivePoseidon2Pervushin>;

fn leaves(n: usize) -> Vec<[F; RANK]> {
    (0..n)
        .map(|i| [f((i as i32 + 1) * 1000), f(0), f(0), f(0)])
        .collect()
}

#[test]
fn honest_path_satisfies_circuit() {
    // A tree of 8 leaves; prove inclusion of each leaf in-circuit.
    let ls = leaves(8);
    let tree = Tree::new(&ls);
    let root = *tree.root();
    for pc in 0..ls.len() {
        let branch = tree.branch(pc);
        assert!(
            verifies(ls[pc], root, pc, &branch),
            "honest path at pc {pc} must satisfy"
        );
    }
}

#[test]
fn forged_leaf_fails_circuit() {
    // A leaf that is not the committed one at pc: the computed root will not
    // match, so the in-circuit inclusion is unsatisfied.
    let ls = leaves(8);
    let tree = Tree::new(&ls);
    let root = *tree.root();
    let pc = 3;
    let branch = tree.branch(pc);
    let forged = [f(999_999), f(0), f(0), f(0)];
    assert!(
        !verifies(forged, root, pc, &branch),
        "a forged leaf must fail"
    );
}

#[test]
fn wrong_root_fails_circuit() {
    let ls = leaves(8);
    let tree = Tree::new(&ls);
    let mut root = *tree.root();
    root[0] = root[0] + f(1);
    let pc = 2;
    let branch = tree.branch(pc);
    assert!(
        !verifies(ls[pc], root, pc, &branch),
        "a wrong root must fail"
    );
}

#[test]
fn wrong_sibling_fails_circuit() {
    let ls = leaves(8);
    let tree = Tree::new(&ls);
    let root = *tree.root();
    let pc = 5;
    let mut branch = tree.branch(pc);
    branch[0][0] = branch[0][0] + f(7);
    assert!(
        !verifies(ls[pc], root, pc, &branch),
        "a tampered sibling must fail"
    );
}

#[test]
fn wrong_index_fails_circuit() {
    // An honest leaf and branch but the wrong claimed pc: the index-bit
    // recomposition and the path order no longer match the root.
    let ls = leaves(8);
    let tree = Tree::new(&ls);
    let root = *tree.root();
    let branch = tree.branch(4);
    assert!(verifies(ls[4], root, 4, &branch));
    assert!(
        !verifies(ls[4], root, 5, &branch),
        "claiming the wrong pc must fail"
    );
}

#[test]
fn folds_like_a_step_circuit() {
    // Fixed shape per depth - folds like the universal step.
    let s1 = ShapedR1cs::from_circuit_r1cs(inclusion_r1cs(3));
    let s2 = ShapedR1cs::from_circuit_r1cs(inclusion_r1cs(3));
    assert_eq!(
        s1.a().columns(),
        s2.a().columns(),
        "same depth -> identical shape"
    );
}
