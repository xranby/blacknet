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

use blacknet_crypto::pervushin::PervushinField;
use blacknet_vm::machine::{Error, Instruction, Machine};

type F = PervushinField;
type M = Machine<F, 8>;

fn f(n: i32) -> F {
    F::from(n)
}

#[test]
fn arithmetic() {
    // r1 = 6, r2 = 7, r3 = r1 * r2, r4 = r3 - r1, r5 = -r4
    let program = vec![
        Instruction::LoadImm(1, f(6)),
        Instruction::LoadImm(2, f(7)),
        Instruction::Mul(3, 1, 2),
        Instruction::Sub(4, 3, 1),
        Instruction::Neg(5, 4),
        Instruction::Halt,
    ];
    let mut machine = M::new(program, 100);
    let steps = machine.run().unwrap();
    assert_eq!(steps, 6);
    assert_eq!(machine.register(3), f(42));
    assert_eq!(machine.register(4), f(36));
    assert_eq!(machine.register(5), f(-36));
    assert!(machine.halted());
    assert_eq!(machine.trace().len(), 6);
}

#[test]
fn factorial_loop() {
    // r1 = counter = 5, r2 = accumulator = 1, r3 = one
    // loop: r2 *= r1; r1 -= 1; if r1 != r0 goto loop
    let program = vec![
        Instruction::LoadImm(1, f(5)),
        Instruction::LoadImm(2, f(1)),
        Instruction::LoadImm(3, f(1)),
        Instruction::Mul(2, 2, 1),
        Instruction::Sub(1, 1, 3),
        Instruction::Bne(1, 0, 3),
        Instruction::Halt,
    ];
    let mut machine = M::new(program, 100);
    machine.run().unwrap();
    assert_eq!(machine.register(2), f(120));
}

#[test]
fn zero_register_is_hardwired() {
    let program = vec![Instruction::LoadImm(0, f(99)), Instruction::Halt];
    let mut machine = M::new(program, 10);
    machine.run().unwrap();
    assert_eq!(machine.register(0), f(0));
}

#[test]
fn out_of_fuel() {
    // Infinite loop must be stopped by the fuel meter.
    let program = vec![Instruction::Jump(0)];
    let mut machine = M::new(program, 1000);
    assert_eq!(machine.run(), Err(Error::OutOfFuel));
}

#[test]
fn invalid_jump() {
    let program = vec![Instruction::Jump(7)];
    let mut machine = M::new(program, 10);
    assert_eq!(machine.run(), Err(Error::InvalidJump(7)));
}

#[test]
fn falling_off_the_end() {
    let program = vec![Instruction::LoadImm(1, f(1))];
    let mut machine = M::new(program, 10);
    assert_eq!(machine.run(), Err(Error::InvalidProgramCounter(1)));
}

#[test]
fn step_after_halt() {
    let program = vec![Instruction::Halt];
    let mut machine = M::new(program, 10);
    machine.run().unwrap();
    assert_eq!(machine.step(), Err(Error::Halted));
}

#[test]
fn trace_is_consistent() {
    let program = vec![
        Instruction::LoadImm(1, f(2)),
        Instruction::Add(2, 1, 1),
        Instruction::Halt,
    ];
    let mut machine = M::new(program, 10);
    machine.run().unwrap();
    let trace = machine.trace();
    // Consecutive rows are chained by the program counter.
    for window in trace.windows(2) {
        assert_eq!(window[0].next_pc, window[1].pc);
    }
    assert_eq!(trace[0].pc, 0);
    assert_eq!(trace.last().unwrap().instruction, Instruction::Halt);
}
