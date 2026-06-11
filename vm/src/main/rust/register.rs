/*
 * Copyright (c) 2025 Pavel Vasin
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

pub trait Register<T> {
    fn read(&self) -> T;
    fn write(&mut self, value: T);
}

pub struct Zero {}

impl<T: Default> Register<T> for Zero {
    fn read(&self) -> T {
        T::default()
    }

    fn write(&mut self, _: T) {}
}

pub struct General<T> {
    value: T,
}

impl<T> General<T> {
    pub const fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T: Copy> Register<T> for General<T> {
    fn read(&self) -> T {
        self.value
    }

    fn write(&mut self, value: T) {
        self.value = value;
    }
}
