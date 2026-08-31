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

//! Shared-memory reconnection across a server restart: the server
//! rebinds the same socket path, and the client's reconnect ladder
//! runs a fresh handshake, maps the new segment, and re-signs in. The
//! probe is a ping, which is non-replicated and safe to replay under
//! the new session, so this stays independent of how quickly the
//! partition plane finishes its own post-restart recovery.

use std::time::Duration;

use iggy::prelude::*;
use integration::harness::TestBinary;
use integration::iggy_harness;

#[iggy_harness(test_client_transport = Shm)]
async fn given_a_server_restart_when_pinging_should_reconnect_over_the_same_socket(
    harness: &mut TestHarness,
) {
    let client = harness
        .server()
        .shm_client()
        .unwrap()
        .with_reconnecting_root_login()
        .connect()
        .await
        .unwrap();
    client.ping().await.expect("ping before the restart");

    harness.server_mut().stop().expect("stop the server");
    harness.server_mut().start().expect("restart the server");

    // The first request after the restart finds the old session dead,
    // reconnects through the ladder, signs back in, and replays the
    // ping under the new session.
    let ping = tokio::time::timeout(Duration::from_secs(30), client.ping())
        .await
        .expect("reconnect must finish well inside the ladder budget");
    ping.expect("ping after the restart");
}
