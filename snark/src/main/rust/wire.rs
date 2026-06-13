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

//! Canonical wire encoding for proofs.
//!
//! Consensus needs a deterministic, versioned byte format — two nodes must
//! agree on the exact bytes, and the format must be pinnable per protocol
//! height. The Pervushin field is not `serde::Serialize`, and serde formats
//! admit non-canonical encodings anyway, so this is an explicit codec:
//! field elements as 8-byte little-endian canonical representatives, vectors
//! length-prefixed with a `u32`, every structure preceded by a version
//! byte. Decoding rejects malformed input rather than silently accepting it.
//!
//! The format is append-only: new versions add fields after a bumped
//! version byte; the kernel pins accepted versions per height, reusing the
//! existing height-gating mechanism.

use crate::witnesscommitment::F;
use blacknet_crypto::algebra::IntegerRing;
use blacknet_crypto::matrix::DenseVector;

/// Current wire version.
pub const WIRE_VERSION: u8 = 1;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    BadVersion(u8),
    NonCanonical,
    Overlong,
}

/// A growable canonical encoder.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn field(&mut self, x: F) {
        // Canonical representative in [0, q); 8 bytes little-endian.
        let c = x.canonical();
        let u = if c < 0 {
            (c + ((1i64 << 61) - 1)) as u64
        } else {
            c as u64
        };
        self.buf.extend_from_slice(&u.to_le_bytes());
    }

    pub fn u32(&mut self, n: u32) {
        self.buf.extend_from_slice(&n.to_le_bytes());
    }

    pub fn u64(&mut self, n: u64) {
        self.buf.extend_from_slice(&n.to_le_bytes());
    }

    pub fn field_vec(&mut self, v: &DenseVector<F>) {
        self.u32(v.dimension() as u32);
        for i in 0..v.dimension() {
            self.field(v[i]);
        }
    }

    pub fn field_slice(&mut self, v: &[F]) {
        self.u32(v.len() as u32);
        for &x in v {
            self.field(x);
        }
    }

    pub fn u32_slice(&mut self, v: &[u32]) {
        self.u32(v.len() as u32);
        for &n in v {
            self.u32(n);
        }
    }

    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// A canonical decoder over a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

const Q: u64 = (1 << 61) - 1;
/// Maximum vector length accepted, a DoS guard.
const MAX_LEN: u32 = 1 << 26;

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.pos + n > self.buf.len() {
            return Err(Error::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn version(&mut self, expected: u8) -> Result<(), Error> {
        let v = self.take(1)?[0];
        if v != expected {
            return Err(Error::BadVersion(v));
        }
        Ok(())
    }

    /// Reads a single raw byte (e.g. an inner version tag).
    pub fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    pub fn field(&mut self) -> Result<F, Error> {
        let b = self.take(8)?;
        let u = u64::from_le_bytes(b.try_into().expect("8 bytes"));
        if u >= Q {
            return Err(Error::NonCanonical);
        }
        Ok(<F as IntegerRing>::new(u as i64))
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    pub fn u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().expect("8 bytes")))
    }

    fn len_prefix(&mut self) -> Result<usize, Error> {
        let n = self.u32()?;
        if n > MAX_LEN {
            return Err(Error::Overlong);
        }
        Ok(n as usize)
    }

    pub fn field_vec(&mut self) -> Result<DenseVector<F>, Error> {
        let n = self.len_prefix()?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.field()?);
        }
        Ok(DenseVector::from(v))
    }

    pub fn field_slice(&mut self) -> Result<Vec<F>, Error> {
        let n = self.len_prefix()?;
        (0..n).map(|_| self.field()).collect()
    }

    pub fn u32_slice(&mut self) -> Result<Vec<u32>, Error> {
        let n = self.len_prefix()?;
        (0..n).map(|_| self.u32()).collect()
    }

    /// Confirms the whole buffer was consumed — trailing bytes are an error
    /// (canonical encodings are exact).
    pub const fn finish(self) -> Result<(), Error> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::Overlong)
        }
    }
}
