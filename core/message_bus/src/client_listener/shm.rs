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

//! Unix-socket listener for shared-memory clients.
//!
//! Runs only on shard 0, like every client listener, and stays
//! authentication-agnostic per the module contract in
//! [`crate::client_listener`]: filesystem permissions on the socket
//! (0600, parent directory 0700 when this listener creates it) are an
//! outer gate for who may attempt a connection, and the application
//! `LOGIN` command remains the only authentication.

use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

use compio::net::UnixListener;
use futures::FutureExt;
use iggy_common::IggyError;
use tracing::{debug, error, info};

use crate::AcceptedShmClientFn;
use crate::lifecycle::ShutdownToken;

/// Bind the unix socket, replacing a stale socket file from a previous
/// run. The parent directory is created with mode 0700 when missing;
/// the socket file itself is restricted to 0600.
///
/// # Errors
///
/// Returns [`IggyError::CannotBindToSocket`] when the path cannot be
/// prepared or bound.
#[allow(clippy::future_not_send)]
pub async fn bind(socket_path: &Path) -> Result<UnixListener, IggyError> {
    prepare_socket_path(socket_path).map_err(|error| {
        IggyError::CannotBindToSocket(format!(
            "cannot prepare shm socket path {}: {error}",
            socket_path.display()
        ))
    })?;
    let listener = UnixListener::bind(socket_path).await.map_err(|error| {
        IggyError::CannotBindToSocket(format!(
            "cannot bind shm socket {}: {error}",
            socket_path.display()
        ))
    })?;
    restrict_socket_permissions(socket_path).map_err(|error| {
        IggyError::CannotBindToSocket(format!(
            "cannot restrict shm socket permissions on {}: {error}",
            socket_path.display()
        ))
    })?;
    Ok(listener)
}

/// Run the accept loop until the shutdown token fires. The
/// `on_accepted` callback owns the accepted stream from that point on.
#[allow(clippy::future_not_send)]
pub async fn run(listener: UnixListener, token: ShutdownToken, on_accepted: AcceptedShmClientFn) {
    info!(
        "Client listener (shm) accepting on {:?}",
        listener.local_addr().ok()
    );

    loop {
        futures::select! {
            () = token.wait().fuse() => {
                debug!("Client listener (shm) shutting down");
                break;
            }
            result = listener.accept().fuse() => {
                match result {
                    Ok((stream, _peer)) => {
                        debug!("shm client accepted");
                        on_accepted(stream);
                    }
                    Err(error) => {
                        error!("Client listener (shm) accept failed: {error}");
                    }
                }
            }
        }
    }
}

fn prepare_socket_path(socket_path: &Path) -> io::Result<()> {
    if let Some(parent) = socket_path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    // A previous run's socket file makes bind fail with EADDRINUSE
    // even though nothing is listening; remove it. A concurrently
    // running server on the same path loses its listener here, which
    // is the standard unix-socket single-owner convention.
    match std::fs::remove_file(socket_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn restrict_socket_permissions(socket_path: &Path) -> io::Result<()> {
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
}
