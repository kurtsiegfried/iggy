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

use crate::types::configuration::auth_config::connection_string::ConnectionString;
use crate::types::configuration::shm_config::shm_connection_string_options::ShmConnectionStringOptions;
use crate::{AutoLogin, NonZeroIggyDuration, ShmClientReconnectionConfig};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Configuration for the shared-memory client.
#[derive(Debug, Clone)]
pub struct ShmClientConfig {
    /// Path of the server's shared-memory unix socket.
    pub server_address: String,
    /// Whether to automatically login user after establishing connection.
    pub auto_login: AutoLogin,
    /// Whether to automatically reconnect when disconnected.
    pub reconnection: ShmClientReconnectionConfig,
    /// Interval of heartbeats sent by the client
    pub heartbeat_interval: NonZeroIggyDuration,
}

impl Default for ShmClientConfig {
    fn default() -> Self {
        ShmClientConfig {
            // Mirrors the server's default `[shm]` socket spelling. As
            // client config the path resolves against THIS process's
            // working directory at connect, so the default only lines
            // up when the client runs from the server's directory;
            // connection strings require an absolute path for exactly
            // that reason, and programmatic config is left permissive.
            server_address: "local_data/runtime/iggy-shm.sock".to_string(),
            auto_login: AutoLogin::Disabled,
            reconnection: ShmClientReconnectionConfig::default(),
            heartbeat_interval: NonZeroIggyDuration::from_str("5s").unwrap(),
        }
    }
}

impl From<ConnectionString<ShmConnectionStringOptions>> for ShmClientConfig {
    fn from(connection_string: ConnectionString<ShmConnectionStringOptions>) -> Self {
        ShmClientConfig {
            server_address: connection_string.server_address().into(),
            auto_login: connection_string.auto_login().to_owned(),
            reconnection: connection_string.options().reconnection().to_owned(),
            heartbeat_interval: connection_string.options().heartbeat_interval(),
        }
    }
}

impl Display for ShmClientConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ server_address: {}, reconnection: {}, heartbeat_interval: {} }}",
            self.server_address, self.reconnection, self.heartbeat_interval
        )
    }
}
