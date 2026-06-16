/*
 * Copyright (c) 2026 Blacknet contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

use crate::v2::ByteArrayInfo;
use crate::v2::error::Result;
use blacknet_kernel::transaction::ComputeReferenceSuccinct;
use blacknet_serialization::format::from_bytes;
use serde::{Deserialize, Serialize};

/// RPC view of a ComputeReferenceSuccinct transaction: its canonically-encoded
/// succinct verified-computation payload as a byte array. The payload bundles
/// the cited program id and the succinct AggregateProof (witness omitted);
/// clients decode it with the snark wire codec (`decode_reference_succinct`).
#[derive(Deserialize, Serialize)]
pub struct ComputeReferenceSuccinctInfo {
    payload: ByteArrayInfo,
}

impl ComputeReferenceSuccinctInfo {
    pub fn new(data: &[u8]) -> Result<Self> {
        let tx = from_bytes::<ComputeReferenceSuccinct>(data, false)?;
        Ok(Self {
            payload: tx.payload().into(),
        })
    }
}
