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

//! Shared-memory listener schema.
//!
//! Local clients connect over a unix socket that carries the
//! handshake, the segment fd, doorbell wakes, and liveness; the data
//! path is the shared-memory log pair. Validation here mirrors the
//! numeric rules of `core/shm/src/layout.rs` (same pattern as the
//! quic section mirroring quinn's limits) so a bad geometry fails
//! config load instead of panicking a constructor at install time.

use super::COMPONENT;
use crate::ConfigurationError;
use configs::ConfigEnv;
use iggy_common::{IggyByteSize, Validatable};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::fmt::{Display, Formatter};

/// Mirrors `core/shm/src/layout.rs`; a drift here fails the log
/// constructors' assertions at install time, so keep them in lockstep.
const MIN_REGION_CAPACITY: u64 = 64 * 1024;
const MAX_REGION_CAPACITY: u64 = 1 << 30;
const RECORD_HEADER_SIZE: u64 = 16;

/// `sun_path` is 104 bytes on macOS and 108 on Linux; leave headroom
/// for the NUL terminator.
const MAX_SOCKET_PATH_LEN: usize = 100;

const MAX_CONNECTIONS_CEILING: u32 = 10_000;

#[serde_as]
#[derive(Debug, Deserialize, Serialize, Clone, ConfigEnv)]
pub struct ShmConfig {
    pub enabled: bool,

    /// Filesystem path of the unix socket clients connect to.
    pub socket: String,

    /// Capacity of one log region. Each connection maps two logs of
    /// three regions each, so per-connection memory is six times this
    /// value plus bookkeeping pages.
    #[config_env(leaf)]
    #[serde_as(as = "DisplayFromStr")]
    pub region_capacity: IggyByteSize,

    /// Largest wire frame accepted over shared memory. A frame must
    /// fit inside half a region, so raising this requires raising
    /// `region_capacity` with it.
    #[config_env(leaf)]
    #[serde_as(as = "DisplayFromStr")]
    pub max_message_size: IggyByteSize,

    /// Cap on concurrent shared-memory connections. Unlike TCP this
    /// transport pins real memory per connection, so accepts beyond
    /// the cap are refused.
    pub max_connections: u32,
}

impl Validatable<ConfigurationError> for ShmConfig {
    fn validate(&self) -> Result<(), ConfigurationError> {
        if !self.enabled {
            return Ok(());
        }
        if self.socket.is_empty() || self.socket.len() > MAX_SOCKET_PATH_LEN {
            eprintln!(
                "{COMPONENT} shm.socket must be 1..={MAX_SOCKET_PATH_LEN} bytes (sun_path limit), got {} bytes",
                self.socket.len()
            );
            return Err(ConfigurationError::InvalidConfigurationValue);
        }
        let region_capacity = self.region_capacity.as_bytes_u64();
        if !region_capacity.is_power_of_two() {
            eprintln!(
                "{COMPONENT} shm.region_capacity ({}) must be a power of two",
                self.region_capacity
            );
            return Err(ConfigurationError::InvalidConfigurationValue);
        }
        if !(MIN_REGION_CAPACITY..=MAX_REGION_CAPACITY).contains(&region_capacity) {
            eprintln!(
                "{COMPONENT} shm.region_capacity ({}) must be within {MIN_REGION_CAPACITY}..={MAX_REGION_CAPACITY} bytes",
                self.region_capacity
            );
            return Err(ConfigurationError::InvalidConfigurationValue);
        }
        let max_payload = region_capacity / 2 - RECORD_HEADER_SIZE;
        let max_message_size = self.max_message_size.as_bytes_u64();
        if max_message_size == 0 || max_message_size > max_payload {
            eprintln!(
                "{COMPONENT} shm.max_message_size ({}) must be within 1..={max_payload} bytes (half a region minus the record header)",
                self.max_message_size
            );
            return Err(ConfigurationError::InvalidConfigurationValue);
        }
        if !(1..=MAX_CONNECTIONS_CEILING).contains(&self.max_connections) {
            eprintln!(
                "{COMPONENT} shm.max_connections ({}) must be within 1..={MAX_CONNECTIONS_CEILING}",
                self.max_connections
            );
            return Err(ConfigurationError::InvalidConfigurationValue);
        }
        Ok(())
    }
}

impl Display for ShmConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ enabled: {}, socket: {}, region_capacity: {}, max_message_size: {}, max_connections: {} }}",
            self.enabled,
            self.socket,
            self.region_capacity,
            self.max_message_size,
            self.max_connections
        )
    }
}
