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

use crate::{
    ConnectionStringOptions, IggyDuration, IggyError, NonZeroIggyDuration,
    ShmClientReconnectionConfig,
};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct ShmConnectionStringOptions {
    heartbeat_interval: NonZeroIggyDuration,
    reconnection: ShmClientReconnectionConfig,
}

impl ShmConnectionStringOptions {
    pub fn heartbeat_interval(&self) -> NonZeroIggyDuration {
        self.heartbeat_interval
    }

    pub fn reconnection(&self) -> &ShmClientReconnectionConfig {
        &self.reconnection
    }
}

impl ConnectionStringOptions for ShmConnectionStringOptions {
    fn retries(&self) -> Option<u32> {
        self.reconnection.max_retries
    }

    fn heartbeat_interval(&self) -> NonZeroIggyDuration {
        self.heartbeat_interval
    }

    fn parse_options(options_str: &str) -> Result<Self, IggyError> {
        let mut parsed_options = ShmConnectionStringOptions::default();

        if options_str.is_empty() {
            return Ok(parsed_options);
        }

        for option in options_str.split('&') {
            let parts: Vec<&str> = option.split('=').collect();
            if parts.len() != 2 {
                return Err(IggyError::InvalidConnectionString);
            }

            match parts[0] {
                "heartbeat_interval" => {
                    parsed_options.heartbeat_interval = NonZeroIggyDuration::from_str(parts[1])
                        .map_err(|_| IggyError::InvalidConnectionString)?;
                }
                "reconnection_retries" => {
                    let retries = match parts[1] {
                        "unlimited" => None,
                        val => Some(
                            val.parse::<u32>()
                                .map_err(|_| IggyError::InvalidConnectionString)?,
                        ),
                    };
                    parsed_options.reconnection.max_retries = retries;
                }
                "reconnection_interval" => {
                    parsed_options.reconnection.interval = NonZeroIggyDuration::from_str(parts[1])
                        .map_err(|_| IggyError::InvalidConnectionString)?;
                }
                "reestablish_after" => {
                    parsed_options.reconnection.reestablish_after =
                        IggyDuration::from_str(parts[1])
                            .map_err(|_| IggyError::InvalidConnectionString)?;
                }
                _ => return Err(IggyError::InvalidConnectionString),
            }
        }
        Ok(parsed_options)
    }

    /// The address part is a unix socket path, so the network `host:port`
    /// grammar does not apply. Require an absolute path: a relative one
    /// silently depends on the process working directory and would connect
    /// to a different socket than the operator configured on the server.
    fn validate_server_address(server_address: &str) -> Result<(), IggyError> {
        if !server_address.starts_with('/') {
            return Err(IggyError::InvalidConnectionString);
        }
        Ok(())
    }
}

impl Default for ShmConnectionStringOptions {
    fn default() -> Self {
        ShmConnectionStringOptions {
            heartbeat_interval: NonZeroIggyDuration::from_str("5s").unwrap(),
            reconnection: ShmClientReconnectionConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::configuration::auth_config::connection_string::ConnectionString;
    use crate::{AutoLogin, Credentials};
    use secrecy::ExposeSecret;

    #[test]
    fn should_succeed_with_an_absolute_socket_path() {
        let value = "iggy+shm://user:secret@/tmp/iggy-shm.sock";
        let connection_string = ConnectionString::<ShmConnectionStringOptions>::new(value)
            .expect("an absolute socket path must parse");

        assert_eq!(connection_string.server_address(), "/tmp/iggy-shm.sock");
        match connection_string.auto_login() {
            AutoLogin::Enabled(Credentials::UsernamePassword(username, password)) => {
                assert_eq!(username, "user");
                assert_eq!(password.expose_secret(), "secret");
            }
            _ => panic!("expected username and password credentials"),
        }
    }

    #[test]
    fn should_succeed_with_a_personal_access_token() {
        let value = "iggy+shm://iggypat-1234567890abcdef@/tmp/iggy-shm.sock";
        let connection_string = ConnectionString::<ShmConnectionStringOptions>::new(value)
            .expect("a PAT with a socket path must parse");

        assert!(matches!(
            connection_string.auto_login(),
            AutoLogin::Enabled(Credentials::PersonalAccessToken(_))
        ));
    }

    #[test]
    fn should_fail_with_a_relative_socket_path() {
        let value = "iggy+shm://user:secret@local_data/iggy-shm.sock";
        let connection_string = ConnectionString::<ShmConnectionStringOptions>::new(value);
        assert!(connection_string.is_err());
    }

    #[test]
    fn should_succeed_with_options() {
        let value = "iggy+shm://user:secret@/tmp/iggy-shm.sock?heartbeat_interval=10s&reconnection_retries=3";
        let connection_string = ConnectionString::<ShmConnectionStringOptions>::new(value)
            .expect("known options must parse");

        assert_eq!(
            connection_string.options().heartbeat_interval(),
            NonZeroIggyDuration::from_str("10s").unwrap()
        );
        assert_eq!(connection_string.options().retries(), Some(3));
    }

    #[test]
    fn should_fail_with_an_unknown_option() {
        let value = "iggy+shm://user:secret@/tmp/iggy-shm.sock?nodelay=true";
        let connection_string = ConnectionString::<ShmConnectionStringOptions>::new(value);
        assert!(connection_string.is_err());
    }
}
