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

use crate::{IggyError, NonZeroIggyDuration};

pub trait ConnectionStringOptions {
    fn retries(&self) -> Option<u32>;

    fn heartbeat_interval(&self) -> NonZeroIggyDuration;

    fn parse_options(options: &str) -> Result<Self, IggyError>
    where
        Self: Sized;

    /// Validate the address part of a connection string for this transport.
    /// Network transports expect `host:port`; path-addressed transports
    /// override this with their own grammar.
    fn validate_server_address(server_address: &str) -> Result<(), IggyError> {
        if !server_address.contains(':') || server_address.starts_with(':') {
            return Err(IggyError::InvalidConnectionString);
        }

        let port = server_address.split(':').collect::<Vec<&str>>()[1];
        if port.is_empty() {
            return Err(IggyError::InvalidConnectionString);
        }

        if port.parse::<u16>().is_err() {
            return Err(IggyError::InvalidConnectionString);
        }

        Ok(())
    }
}
