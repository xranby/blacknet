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

use crate::register::{General, Register, Zero};

/// An index into a register file. The register `r0` is hardwired to zero.
pub type RegisterIndex = u8;

/// A bank of `N` general purpose registers plus the hardwired zero register.
///
/// Reads and writes of `r0` go to [`Zero`]; reads return the additive
/// identity and writes are discarded, as in the RISC tradition. This keeps
/// every instruction total, which simplifies later arithmetization: a step
/// of the machine is a function, never a partial map.
pub struct RegisterFile<T, const N: usize> {
    zero: Zero,
    general: [General<T>; N],
}

impl<T: Copy + Default, const N: usize> RegisterFile<T, N> {
    pub fn new() -> Self {
        Self {
            zero: Zero {},
            general: core::array::from_fn(|_| General::new(T::default())),
        }
    }

    /// The number of addressable registers, including the zero register.
    #[must_use]
    pub const fn len() -> usize {
        N + 1
    }

    /// Reads a register. Out-of-range indices read as the zero register,
    /// keeping the operation total.
    pub fn read(&self, index: RegisterIndex) -> T {
        match Self::slot(index) {
            Some(i) => self.general[i].read(),
            None => Register::<T>::read(&self.zero),
        }
    }

    /// Writes a register. Writes to `r0` and to out-of-range indices are
    /// discarded.
    pub fn write(&mut self, index: RegisterIndex, value: T) {
        match Self::slot(index) {
            Some(i) => self.general[i].write(value),
            None => self.zero.write(value),
        }
    }

    const fn slot(index: RegisterIndex) -> Option<usize> {
        let index = index as usize;
        if index >= 1 && index <= N {
            Some(index - 1)
        } else {
            None
        }
    }
}

impl<T: Copy + Default, const N: usize> Default for RegisterFile<T, N> {
    fn default() -> Self {
        Self::new()
    }
}
