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

use blacknet_arith::trace::execute;
use blacknet_crypto::symmetric::{DuplexPoseidon2Pervushin, Duplexer};
use blacknet_snark::fold::{Error, F, RelaxedInstance, fold, is_satisfied};
use blacknet_vm::machine::Instruction;

fn f(n: i32) -> F {
    F::from(n)
}

// Two executions of the same shape (same program, same control flow) so the
// constraint matrices coincide — the precondition of folding step instances.
fn shaped_pair() -> (
    blacknet_arith::r1cs::ShapedR1cs,
    RelaxedInstance,
    RelaxedInstance,
) {
    let program = vec![
        Instruction::Mul(2, 1, 1),
        Instruction::Add(3, 2, 1),
        Instruction::Halt,
    ];
    let e1 = execute(&program, &[f(3)], 100).unwrap();
    let e2 = execute(&program, &[f(11)], 100).unwrap();
    let i1 = RelaxedInstance::strict(&e1.r1cs, e1.witness, 8);
    let i2 = RelaxedInstance::strict(&e2.r1cs, e2.witness, 8);
    (e1.r1cs, i1, i2)
}

#[test]
fn strict_instances_satisfy() {
    let (r1cs, i1, i2) = shaped_pair();
    assert!(is_satisfied(&r1cs, &i1).is_ok());
    assert!(is_satisfied(&r1cs, &i2).is_ok());
}

#[test]
fn folded_instance_satisfies() {
    let (r1cs, i1, i2) = shaped_pair();
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(f(42)); // context binding stands in for instance absorption
    let folded = fold(&r1cs, &i1, &i2, &mut duplex).unwrap();
    assert!(is_satisfied(&r1cs, &folded).is_ok());
    assert_eq!(folded.budget, 7);
}

#[test]
fn fold_chain_satisfies() {
    let (r1cs, i1, i2) = shaped_pair();
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(f(1));
    let mut acc = fold(&r1cs, &i1, &i2, &mut duplex).unwrap();
    for _ in 0..6 {
        let (_, fresh, _) = shaped_pair();
        acc = fold(&r1cs, &acc, &fresh, &mut duplex).unwrap();
        assert!(is_satisfied(&r1cs, &acc).is_ok());
    }
    assert_eq!(acc.budget, 1);
}

#[test]
fn budget_exhaustion_rejected() {
    let (r1cs, mut i1, i2) = shaped_pair();
    i1.budget = 0;
    let mut duplex = DuplexPoseidon2Pervushin::default();
    assert_eq!(
        fold(&r1cs, &i1, &i2, &mut duplex).unwrap_err(),
        Error::BudgetExhausted
    );
}

#[test]
fn corrupted_fold_rejected() {
    let (r1cs, i1, i2) = shaped_pair();
    let mut duplex = DuplexPoseidon2Pervushin::default();
    duplex.absorb(f(7));
    let mut folded = fold(&r1cs, &i1, &i2, &mut duplex).unwrap();
    folded.u += f(1);
    assert!(is_satisfied(&r1cs, &folded).is_err());
}
