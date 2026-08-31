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

use crate::leader_aware::{ConnectCoordinator, ConnectOwnerContext};
use crate::session::ConsensusSession;
use crate::shm::session::{ExchangeRequest, ShmSessionHandle};
use crate::vsr::replay_after_session_reset_is_safe;

use crate::prelude::Client;
use async_broadcast::{Receiver, Sender, broadcast};
use async_trait::async_trait;
use bytes::Bytes;
use iggy_binary_protocol::codes::{LOGIN_REGISTER_CODE, LOGIN_REGISTER_WITH_PAT_CODE};
use iggy_common::VsrSessionControl as _;
use iggy_common::{
    AutoLogin, ClientState, ConnectionString, Credentials, DiagnosticEvent, IggyDuration,
    IggyError, IggyTimestamp, NonZeroIggyDuration, ShmClientConfig, ShmConnectionStringOptions,
};
use iggy_common::{BinaryClient, BinaryTransport, PersonalAccessTokenClient, UserClient};
use secrecy::ExposeSecret;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::Mutex;
use tokio::sync::oneshot;
use tokio::time::sleep;
use tracing::{debug, info, trace, warn};

const NAME: &str = "Shm";
/// Bound on how long a single VSR exchange may run on the I/O thread,
/// transient replays included. The connection is lockstep, so an
/// unanswered exchange (lost server reply) would wedge every later
/// request on this client forever. On expiry the session is dropped.
const RESPONSE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A client that talks to a local server over one shared-memory segment
/// bootstrapped through the server's `[shm]` unix socket. Same lockstep
/// request semantics as the network transports; the process must run on
/// the server's host.
///
/// Cluster leader redirection does not apply: the socket addresses one
/// local node, and a request that node keeps refusing surfaces its
/// transient error to the caller instead of walking the roster.
#[derive(Debug)]
pub struct ShmClient {
    session: Mutex<Option<ShmSessionHandle>>,
    pub(crate) config: Arc<ShmClientConfig>,
    pub(crate) state: Mutex<ClientState>,
    events: (Sender<DiagnosticEvent>, Receiver<DiagnosticEvent>),
    pub(crate) connected_at: Mutex<Option<IggyTimestamp>>,
    pub(crate) current_server_address: Mutex<String>,
    // See `core/sdk/src/tcp/tcp_client.rs` for the `tokio::sync::Mutex` ->
    // `std::sync::Mutex` rationale (pure-CPU critical section).
    consensus_session: Arc<StdMutex<ConsensusSession>>,
    skip_auto_login_once: Mutex<bool>,
    connect_coordinator: ConnectCoordinator,
    consumer_group_state: Arc<iggy_common::ConsumerGroupClientState>,
}

impl Default for ShmClient {
    fn default() -> Self {
        ShmClient::create(Arc::new(ShmClientConfig::default())).unwrap()
    }
}

#[async_trait]
impl Client for ShmClient {
    async fn connect(&self) -> Result<(), IggyError> {
        ShmClient::connect(self).await
    }

    async fn disconnect(&self) -> Result<(), IggyError> {
        ShmClient::disconnect(self).await
    }

    async fn shutdown(&self) -> Result<(), IggyError> {
        ShmClient::shutdown(self).await
    }

    async fn subscribe_events(&self) -> Receiver<DiagnosticEvent> {
        self.events.1.clone()
    }
}

#[async_trait]
impl BinaryTransport for ShmClient {
    async fn get_state(&self) -> ClientState {
        *self.state.lock().await
    }

    async fn set_state(&self, state: ClientState) {
        *self.state.lock().await = state;
    }

    async fn publish_event(&self, event: DiagnosticEvent) {
        if let Err(error) = self.events.0.broadcast(event).await {
            warn!("Failed to send a {} diagnostic event: {error}", NAME);
        }
    }

    async fn send_raw_with_response(&self, code: u32, payload: Bytes) -> Result<Bytes, IggyError> {
        let result = self.send_raw(code, payload.clone()).await;
        if result.is_ok() {
            return result;
        }

        let error = result.unwrap_err();
        if !matches!(
            error,
            IggyError::Disconnected
                | IggyError::EmptyResponse
                | IggyError::Unauthenticated
                | IggyError::StaleClient
                | IggyError::NotConnected
                | IggyError::CannotEstablishConnection
                | IggyError::ConnectionClosed
        ) {
            return Err(error);
        }

        if !self.config.reconnection.enabled {
            return Err(IggyError::Disconnected);
        }

        if matches!(self.config.auto_login, AutoLogin::Disabled) && !is_login_register_code(code) {
            return Err(error);
        }

        let replay_after_reconnect = replay_after_session_reset_is_safe(code, &error);
        let skip_auto_login = is_login_register_code(code);
        let owner_context = skip_auto_login
            .then(|| self.connect_coordinator.current_owner_context())
            .flatten();
        let nested_connect = owner_context.is_some();
        if !nested_connect && self.connect_coordinator.is_active() {
            self.connect().await?;
            if !replay_after_reconnect {
                return Err(error);
            }
            return self.send_raw(code, payload).await;
        }
        self.disconnect().await?;

        if skip_auto_login {
            *self.skip_auto_login_once.lock().await = true;
        }

        info!(
            "Reconnecting to the server over shm socket: {}...",
            self.config.server_address
        );

        let reconnect = if nested_connect {
            self.connect_inner(owner_context.expect("owner context checked above"))
                .await
        } else {
            self.connect().await
        };
        if skip_auto_login && reconnect.is_err() {
            *self.skip_auto_login_once.lock().await = false;
        }
        reconnect?;
        if !replay_after_reconnect {
            warn!(
                "Reconnected, but command: {code} may have committed before its reply was lost; \
                 replaying it under the new session could apply it twice."
            );
            return Err(error);
        }
        self.send_raw(code, payload).await
    }

    fn get_heartbeat_interval(&self) -> NonZeroIggyDuration {
        self.config.heartbeat_interval
    }

    fn consumer_group_state(&self) -> Arc<iggy_common::ConsumerGroupClientState> {
        Arc::clone(&self.consumer_group_state)
    }
}

impl iggy_common::VsrSessionSealed for ShmClient {}

#[async_trait::async_trait]
impl iggy_common::VsrSessionControl for ShmClient {
    async fn bind_vsr_session(&self, session: u64) -> Result<(), IggyError> {
        if session == 0 {
            return Err(IggyError::InvalidSession(session));
        }

        let mut consensus_session = self
            .consensus_session
            .lock()
            .expect("consensus session mutex poisoned");
        if consensus_session.is_bound() {
            return Err(IggyError::AlreadyAuthenticated);
        }

        consensus_session.bind(session);
        Ok(())
    }

    async fn reset_vsr_session(&self) -> Result<(), IggyError> {
        *self
            .consensus_session
            .lock()
            .expect("consensus session mutex poisoned") = ConsensusSession::new();
        Ok(())
    }

    fn sdk_version(&self) -> &'static str {
        crate::SDK_VERSION
    }
}

impl BinaryClient for ShmClient {}

impl ShmClient {
    /// Create a new shared-memory client with the provided configuration.
    pub fn create(config: Arc<ShmClientConfig>) -> Result<Self, IggyError> {
        let (sender, receiver) = broadcast(1000);
        let server_address = config.server_address.clone();
        Ok(ShmClient {
            session: Mutex::new(None),
            config,
            state: Mutex::new(ClientState::Disconnected),
            events: (sender, receiver),
            connected_at: Mutex::new(None),
            current_server_address: Mutex::new(server_address),
            consensus_session: Arc::new(StdMutex::new(ConsensusSession::new())),
            skip_auto_login_once: Mutex::new(false),
            connect_coordinator: ConnectCoordinator::new(),
            consumer_group_state: Arc::new(iggy_common::ConsumerGroupClientState::new()),
        })
    }

    /// Create a new shared-memory client from a connection string.
    pub fn from_connection_string(connection_string: &str) -> Result<Self, IggyError> {
        let parsed_connection_string =
            ConnectionString::<ShmConnectionStringOptions>::new(connection_string)?;
        let config = ShmClientConfig::from(parsed_connection_string);
        Self::create(Arc::new(config))
    }

    async fn connect(&self) -> Result<(), IggyError> {
        self.connect_coordinator
            .run(|abandoned, token| async move {
                let context = self.connect_coordinator.owner_context(token, false, false);
                self.connect_coordinator
                    .scope_owner(context, async move {
                        if abandoned {
                            self.clear_abandoned_connect().await?;
                        }
                        self.connect_inner(context).await
                    })
                    .await
            })
            .await
    }

    async fn connect_inner(&self, _context: ConnectOwnerContext) -> Result<(), IggyError> {
        if self.get_state().await == ClientState::Connected {
            return Ok(());
        }

        let mut retry_count = 0;

        loop {
            let socket_path = self.config.server_address.clone();
            info!("{NAME} client is connecting to server socket: {socket_path}...");
            self.set_state(ClientState::Connecting).await;

            if retry_count > 0 {
                let elapsed = self
                    .connected_at
                    .lock()
                    .await
                    .map(|ts| IggyTimestamp::now().as_micros() - ts.as_micros())
                    .unwrap_or(0);

                let interval = self.config.reconnection.reestablish_after.as_micros();
                debug!("Elapsed time since last connection: {}μs", elapsed);

                if elapsed < interval {
                    let remaining =
                        IggyDuration::new(std::time::Duration::from_micros(interval - elapsed));
                    info!("Trying to connect to the server in: {remaining}");
                    sleep(remaining.get_duration()).await;
                }
            }

            let ready =
                crate::shm::session::spawn(PathBuf::from(&socket_path), RESPONSE_READ_TIMEOUT);
            let handle = match ready.await {
                Ok(Ok(handle)) => handle,
                Ok(Err(error)) => {
                    debug!("{NAME} connection attempt failed: {error}");
                    self.handle_connection_error(&mut retry_count).await?;
                    continue;
                }
                Err(_thread_gone) => {
                    self.handle_connection_error(&mut retry_count).await?;
                    continue;
                }
            };

            *self.session.lock().await = Some(handle);
            self.set_state(ClientState::Connected).await;
            *self.connected_at.lock().await = Some(IggyTimestamp::now());
            self.publish_event(DiagnosticEvent::Connected).await;

            let now = IggyTimestamp::now();
            info!("{NAME} client has connected to server socket: {socket_path} at: {now}");

            self.auto_login().await?;
            return Ok(());
        }
    }

    async fn clear_abandoned_connect(&self) -> Result<(), IggyError> {
        self.session.lock().await.take();
        self.reset_vsr_session().await?;
        self.set_state(ClientState::Disconnected).await;
        self.publish_event(DiagnosticEvent::Disconnected).await;
        Ok(())
    }

    async fn handle_connection_error(&self, retry_count: &mut u32) -> Result<(), IggyError> {
        if !self.config.reconnection.enabled {
            warn!("Automatic reconnection is disabled.");
            self.set_state(ClientState::Disconnected).await;
            self.publish_event(DiagnosticEvent::Disconnected).await;
            return Err(IggyError::CannotEstablishConnection);
        }

        let unlimited_retries = self.config.reconnection.max_retries.is_none();
        let max_retries = self.config.reconnection.max_retries.unwrap_or_default();
        let max_retries_str = self
            .config
            .reconnection
            .max_retries
            .map(|retries| retries.to_string())
            .unwrap_or_else(|| "unlimited".to_string());

        let interval_str = self.config.reconnection.interval.as_human_time_string();

        if unlimited_retries || *retry_count < max_retries {
            *retry_count += 1;
            info!(
                "Retrying to connect to server ({}/{}): {} in: {}",
                retry_count, max_retries_str, self.config.server_address, interval_str
            );
            sleep(self.config.reconnection.interval.get_duration()).await;
            return Ok(());
        }

        self.set_state(ClientState::Disconnected).await;
        self.publish_event(DiagnosticEvent::Disconnected).await;
        Err(IggyError::CannotEstablishConnection)
    }

    async fn auto_login(&self) -> Result<(), IggyError> {
        let skip_auto_login = {
            let mut guard = self.skip_auto_login_once.lock().await;
            std::mem::take(&mut *guard)
        };

        match &self.config.auto_login {
            AutoLogin::Disabled => {
                info!("{NAME} client: automatic sign-in is disabled.");
                Ok(())
            }
            AutoLogin::Enabled(credentials) => {
                if skip_auto_login {
                    info!("Skipping automatic sign-in for a retried login/register request.");
                    return Ok(());
                }
                info!("{NAME} client is signing in...");
                self.set_state(ClientState::Authenticating).await;
                match credentials {
                    Credentials::UsernamePassword(username, password) => {
                        self.login_user(username, password.expose_secret()).await?;
                        info!(
                            "{NAME} client has signed in with the user credentials, username: {username}",
                        );
                        Ok(())
                    }
                    Credentials::PersonalAccessToken(token) => {
                        self.login_with_personal_access_token(token.expose_secret())
                            .await?;
                        info!("{NAME} client has signed in with a personal access token.",);
                        Ok(())
                    }
                }
            }
        }
    }

    async fn disconnect(&self) -> Result<(), IggyError> {
        if self.get_state().await == ClientState::Disconnected {
            return Ok(());
        }

        info!("{NAME} client is disconnecting from server...");
        self.set_state(ClientState::Disconnected).await;

        self.session.lock().await.take();
        self.reset_vsr_session().await?;

        self.publish_event(DiagnosticEvent::Disconnected).await;
        let now = IggyTimestamp::now();
        info!("{NAME} client has disconnected from server at: {now}.");
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), IggyError> {
        if self.get_state().await == ClientState::Shutdown {
            return Ok(());
        }

        info!("Shutting down the {NAME} client");

        self.set_state(ClientState::Disconnected).await;
        self.session.lock().await.take();
        self.reset_vsr_session().await?;
        self.set_state(ClientState::Shutdown).await;
        self.publish_event(DiagnosticEvent::Shutdown).await;
        info!("{NAME} client has been shutdown.");
        Ok(())
    }

    async fn send_raw(&self, code: u32, payload: Bytes) -> Result<Bytes, IggyError> {
        match self.get_state().await {
            ClientState::Shutdown => {
                trace!("Cannot send data. Client is shutdown.");
                return Err(IggyError::ClientShutdown);
            }
            ClientState::Disconnected => {
                trace!("Cannot send data. Client is not connected.");
                return Err(IggyError::NotConnected);
            }
            ClientState::Connecting => {
                trace!("Cannot send data. Client is still connecting.");
                return Err(IggyError::NotConnected);
            }
            ClientState::Connected | ClientState::Authenticating | ClientState::Authenticated => {}
        }

        // Encode under the session lock so request-id order matches the
        // order exchanges enter the I/O thread's queue; ids reaching the
        // server out of order would trip its dedup watermark. The lock
        // covers only CPU work, never an await.
        let reply_rx = {
            let session_guard = self.session.lock().await;
            let Some(handle) = session_guard.as_ref() else {
                trace!("Cannot send data. Client is not connected.");
                return Err(IggyError::NotConnected);
            };
            let request = {
                let mut consensus_session = self
                    .consensus_session
                    .lock()
                    .expect("consensus session mutex poisoned");
                crate::vsr::encode_contiguous_request(&mut consensus_session, code, &payload)?
            };
            trace!(
                "Sending {NAME} VSR request of size {} with code: {code}",
                request.len()
            );
            let (reply_tx, reply_rx) = oneshot::channel();
            if !handle.submit(ExchangeRequest {
                frame: request,
                full_not_accepted_budget: is_login_register_code(code),
                reply: reply_tx,
            }) {
                return Err(IggyError::Disconnected);
            }
            reply_rx
        };

        // The I/O thread bounds the exchange with RESPONSE_READ_TIMEOUT
        // and tears the session down on expiry, so this await always
        // resolves: with the reply, or with a closed channel when the
        // thread exited.
        match reply_rx.await {
            Ok(result) => result,
            Err(_io_thread_gone) => Err(IggyError::Disconnected),
        }
    }
}

const fn is_login_register_code(code: u32) -> bool {
    matches!(code, LOGIN_REGISTER_CODE | LOGIN_REGISTER_WITH_PAT_CODE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn should_be_created_with_default_config() {
        let client = ShmClient::default();
        assert_eq!(
            client.config.server_address,
            "local_data/runtime/iggy-shm.sock"
        );
        assert_eq!(
            client.config.heartbeat_interval,
            NonZeroIggyDuration::from_str("5s").unwrap()
        );
        assert!(matches!(client.config.auto_login, AutoLogin::Disabled));
        assert!(client.config.reconnection.enabled);
    }

    #[tokio::test]
    async fn should_be_disconnected_by_default() {
        let client = ShmClient::default();
        assert_eq!(client.get_state().await, ClientState::Disconnected);
    }

    #[tokio::test]
    async fn a_missing_socket_fails_fast_without_reconnection() {
        let mut config = ShmClientConfig {
            server_address: "/tmp/iggy-shm-client-test-missing.sock".to_string(),
            ..ShmClientConfig::default()
        };
        config.reconnection.enabled = false;
        let client = ShmClient::create(Arc::new(config)).expect("create shm client");

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), client.connect())
            .await
            .expect("a single dial must not enter unlimited reconnect");
        assert!(matches!(result, Err(IggyError::CannotEstablishConnection)));
        assert_eq!(client.get_state().await, ClientState::Disconnected);
    }

    #[test]
    fn should_succeed_from_connection_string() {
        let connection_string = "iggy+shm://user:secret@/tmp/iggy-shm.sock";
        let client = ShmClient::from_connection_string(connection_string);
        assert!(client.is_ok());
        assert_eq!(client.unwrap().config.server_address, "/tmp/iggy-shm.sock");
    }

    #[test]
    fn should_fail_from_connection_string_with_a_relative_path() {
        let connection_string = "iggy+shm://user:secret@local_data/iggy-shm.sock";
        let client = ShmClient::from_connection_string(connection_string);
        assert!(client.is_err());
    }

    #[test]
    fn should_fail_with_a_zero_heartbeat_interval() {
        let value = "iggy+shm://user:secret@/tmp/iggy-shm.sock?heartbeat_interval=none";
        let error = ShmClient::from_connection_string(value).err();
        assert!(matches!(error, Some(IggyError::InvalidConnectionString)));
    }

    #[test]
    fn should_fail_with_empty_connection_string() {
        let client = ShmClient::from_connection_string("");
        assert!(client.is_err());
    }

    #[test]
    fn should_fail_with_invalid_options() {
        let connection_string = "iggy+shm://user:secret@/tmp/iggy-shm.sock?invalid_option=1";
        let client = ShmClient::from_connection_string(connection_string);
        assert!(client.is_err());
    }
}
