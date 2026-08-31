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

//! Shared-memory client install path.
//!
//! Shard-0 terminal: the accepted unix socket, the segment, and both
//! log endpoints all live on shard 0, like QUIC and the TLS family.
//! The connection cap is enforced at the accept callback (the segment
//! pins real memory, and only a shard-local population can be counted
//! accurately), so this install path assumes admission already
//! happened. The HELLO/WELCOME handshake and segment setup run inside
//! [`ShmTransportConn::run`], bounded by `handshake_grace`, mirroring
//! the WSS in-run handshake pattern.

use std::rc::Rc;

use compio::net::UnixStream;

use crate::IggyMessageBus;
use crate::client_listener::RequestHandler;
use crate::installer::conn_info::ClientConnMeta;
use crate::installer::tcp::install_client_conn;
use crate::transports::shm::ShmTransportConn;

pub fn install_client_shm(
    bus: &Rc<IggyMessageBus>,
    meta: ClientConnMeta,
    stream: UnixStream,
    on_request: RequestHandler,
) {
    let config = bus.config();
    let conn = ShmTransportConn::new_server(stream, config.shm.clone(), meta.client_id)
        .with_handshake_grace(config.handshake_grace);
    install_client_conn(bus, meta, conn, on_request);
}
