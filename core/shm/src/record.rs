// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! Record framing inside a log region.
//!
//! The `u32` at record offset 0 is the total record length (header
//! plus payload, before alignment rounding) and is the commit word: it
//! is release-stored after every other byte of the record, and `0`
//! means "not committed yet". Total lengths are therefore never below
//! [`RECORD_HEADER_SIZE`], which is what makes zero-length payloads
//! distinguishable from unwritten memory.

use crate::layout::{RECORD_ALIGNMENT, RECORD_HEADER_SIZE};

pub const RECORD_TYPE_FRAME: u8 = 1;
/// Closes out a region whose tail cannot fit the next record; the
/// consumer skips it and lands exactly on the next region boundary.
pub const RECORD_TYPE_PADDING: u8 = 2;

/// Byte offsets within a record.
pub const RECORD_LENGTH_OFFSET: usize = 0;
pub const RECORD_TYPE_OFFSET: usize = 4;
pub const RECORD_FLAGS_OFFSET: usize = 5;

/// Space a record with this payload occupies in the region.
#[must_use]
pub const fn aligned_record_len(payload_len: usize) -> usize {
    (RECORD_HEADER_SIZE + payload_len + RECORD_ALIGNMENT - 1) & !(RECORD_ALIGNMENT - 1)
}

/// Total length stored in the commit word for this payload.
#[must_use]
pub const fn total_record_len(payload_len: usize) -> usize {
    RECORD_HEADER_SIZE + payload_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_record_len_rounds_to_alignment() {
        assert_eq!(aligned_record_len(0), 16);
        assert_eq!(aligned_record_len(1), 32);
        assert_eq!(aligned_record_len(16), 32);
        assert_eq!(aligned_record_len(17), 48);
        assert_eq!(aligned_record_len(48), 64);
    }

    #[test]
    fn total_record_len_is_never_zero() {
        assert_eq!(total_record_len(0), RECORD_HEADER_SIZE);
        assert_eq!(total_record_len(100), RECORD_HEADER_SIZE + 100);
    }
}
