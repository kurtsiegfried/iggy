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

//! Wire framing of the unix-socket handshake that bootstraps one
//! shared-memory connection.
//!
//! The server transport encodes what the client decodes and vice
//! versa, so both sides build against this one module instead of
//! mirroring offsets by hand. The client opens with a fixed-size
//! HELLO; the server answers with a fixed-size WELCOME whose
//! `SCM_RIGHTS` ancillary payload carries the sealed segment fd when
//! the status is [`WELCOME_OK`]. Every integer is little-endian.

use thiserror::Error;

use crate::layout::{LAYOUT_VERSION, SEGMENT_MAGIC};

pub const HELLO_LEN: usize = 16;
pub const WELCOME_LEN: usize = 48;

pub const WELCOME_OK: u32 = 0;
/// The client's magic or layout version is not one this build speaks.
pub const WELCOME_UNSUPPORTED: u32 = 1;
/// Segment allocation or mapping failed on the server.
pub const WELCOME_INTERNAL: u32 = 2;

/// Encode the client's opening frame: magic, layout version, and a
/// flags word reserved as zero.
#[must_use]
pub fn encode_hello() -> [u8; HELLO_LEN] {
    let mut hello = [0u8; HELLO_LEN];
    hello[0..8].copy_from_slice(&SEGMENT_MAGIC.to_le_bytes());
    hello[8..12].copy_from_slice(&LAYOUT_VERSION.to_le_bytes());
    hello
}

/// The server's answer to a HELLO, minus the ancillary segment fd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Welcome {
    pub status: u32,
    pub region_capacity: u64,
    pub max_message_size: u64,
    pub client_id: u128,
}

impl Welcome {
    #[must_use]
    pub fn encode(&self) -> [u8; WELCOME_LEN] {
        let mut welcome = [0u8; WELCOME_LEN];
        welcome[0..8].copy_from_slice(&SEGMENT_MAGIC.to_le_bytes());
        welcome[8..12].copy_from_slice(&LAYOUT_VERSION.to_le_bytes());
        welcome[12..16].copy_from_slice(&self.status.to_le_bytes());
        welcome[16..24].copy_from_slice(&self.region_capacity.to_le_bytes());
        welcome[24..32].copy_from_slice(&self.max_message_size.to_le_bytes());
        welcome[32..48].copy_from_slice(&self.client_id.to_le_bytes());
        welcome
    }

    /// Decode a WELCOME, refusing bytes whose magic or layout version
    /// this build does not speak.
    ///
    /// # Errors
    ///
    /// Returns [`WelcomeError::UnrecognizedFrame`] when the magic or
    /// layout version differs from this build's.
    #[allow(
        clippy::missing_panics_doc,
        reason = "the expects re-slice fixed offsets of a fixed-size array"
    )]
    pub fn parse(welcome: &[u8; WELCOME_LEN]) -> Result<Self, WelcomeError> {
        let magic = u64::from_le_bytes(welcome[0..8].try_into().expect("fixed slice"));
        let layout_version = u32::from_le_bytes(welcome[8..12].try_into().expect("fixed slice"));
        if magic != SEGMENT_MAGIC || layout_version != LAYOUT_VERSION {
            return Err(WelcomeError::UnrecognizedFrame {
                magic,
                layout_version,
            });
        }
        Ok(Self {
            status: u32::from_le_bytes(welcome[12..16].try_into().expect("fixed slice")),
            region_capacity: u64::from_le_bytes(welcome[16..24].try_into().expect("fixed slice")),
            max_message_size: u64::from_le_bytes(welcome[24..32].try_into().expect("fixed slice")),
            client_id: u128::from_le_bytes(welcome[32..48].try_into().expect("fixed slice")),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WelcomeError {
    #[error("unrecognized welcome frame: magic {magic:#x}, layout version {layout_version}")]
    UnrecognizedFrame { magic: u64, layout_version: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_welcome_round_trips_through_encode_and_parse() {
        let welcome = Welcome {
            status: WELCOME_OK,
            region_capacity: 8 * 1024 * 1024,
            max_message_size: 4_000_000,
            client_id: 0x00C0_FFEE,
        };
        assert_eq!(Welcome::parse(&welcome.encode()), Ok(welcome));
    }

    #[test]
    fn a_hello_carries_the_magic_and_layout_version() {
        let hello = encode_hello();
        assert_eq!(hello[0..8], SEGMENT_MAGIC.to_le_bytes());
        assert_eq!(hello[8..12], LAYOUT_VERSION.to_le_bytes());
        assert_eq!(hello[12..16], [0u8; 4]);
    }

    #[test]
    fn a_foreign_magic_is_refused() {
        let mut bytes = Welcome {
            status: WELCOME_OK,
            region_capacity: 1024,
            max_message_size: 512,
            client_id: 1,
        }
        .encode();
        bytes[0] ^= 0xFF;
        assert!(matches!(
            Welcome::parse(&bytes),
            Err(WelcomeError::UnrecognizedFrame { .. })
        ));
    }
}
