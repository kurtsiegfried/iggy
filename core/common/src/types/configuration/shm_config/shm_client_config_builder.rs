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

use crate::{AutoLogin, IggyDuration, IggyError, NonZeroIggyDuration, ShmClientConfig};

/// Builder for the shared-memory client configuration.
/// Allows configuring the shared-memory client with custom settings or using defaults:
/// - `server_address`: Default is "local_data/runtime/iggy-shm.sock"
/// - `auto_login`: Default is AutoLogin::Disabled.
/// - `reconnection`: Default is enabled unlimited retries and 1 second interval.
/// - `heartbeat_interval`: Default is 5 seconds.
#[derive(Debug, Default)]
pub struct ShmClientConfigBuilder {
    config: ShmClientConfig,
}

impl ShmClientConfigBuilder {
    pub fn new() -> Self {
        ShmClientConfigBuilder::default()
    }

    /// Sets the server socket path for the shared-memory client.
    pub fn with_server_address(mut self, server_address: String) -> Self {
        self.config.server_address = server_address;
        self
    }

    /// Sets the auto sign in during connection.
    pub fn with_auto_sign_in(mut self, auto_sign_in: AutoLogin) -> Self {
        self.config.auto_login = auto_sign_in;
        self
    }

    pub fn with_enabled_reconnection(mut self) -> Self {
        self.config.reconnection.enabled = true;
        self
    }

    /// Sets the number of retries when connecting to the server.
    pub fn with_reconnection_max_retries(mut self, max_retries: Option<u32>) -> Self {
        self.config.reconnection.max_retries = max_retries;
        self
    }

    /// Sets the interval between retries when connecting to the server.
    pub fn with_reconnection_interval(mut self, interval: NonZeroIggyDuration) -> Self {
        self.config.reconnection.interval = interval;
        self
    }

    /// Sets the time to wait before attempting to reestablish connection.
    pub fn with_reestablish_after(mut self, reestablish_after: IggyDuration) -> Self {
        self.config.reconnection.reestablish_after = reestablish_after;
        self
    }

    /// Sets the heartbeat interval.
    pub fn with_heartbeat_interval(mut self, heartbeat_interval: NonZeroIggyDuration) -> Self {
        self.config.heartbeat_interval = heartbeat_interval;
        self
    }

    /// Builds the shared-memory client configuration.
    ///
    /// # Errors
    ///
    /// Returns [`IggyError::InvalidConfiguration`] when the socket path is
    /// empty after trimming.
    pub fn build(mut self) -> Result<ShmClientConfig, IggyError> {
        let server_address = self.config.server_address.trim().to_string();
        if server_address.is_empty() {
            return Err(IggyError::InvalidConfiguration);
        }
        self.config.server_address = server_address;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_should_trim_the_socket_path() {
        let config = ShmClientConfigBuilder::default()
            .with_server_address(" /tmp/iggy-shm.sock ".to_string())
            .build()
            .expect("expected a valid socket path");

        assert_eq!(config.server_address, "/tmp/iggy-shm.sock");
    }

    #[test]
    fn build_should_fail_for_an_empty_socket_path() {
        let result = ShmClientConfigBuilder::default()
            .with_server_address("  ".to_string())
            .build();

        assert!(result.is_err());
    }
}
