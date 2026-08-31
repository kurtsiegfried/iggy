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

//! Concurrency contracts of the shared-memory client's I/O thread,
//! driven against a scripted in-process server: reply correlation
//! survives caller cancellation, concurrent senders each get their own
//! reply, a transient replay reuses the same request id, and the
//! `TransientNotAccepted` budget is short for ordinary requests but
//! full-length for login/register. The script controls every reply, so
//! the windows the real server only opens under restart or election
//! timing are held open deterministically here.

#![cfg(unix)]

use std::io::{Read, Write};
use std::mem::offset_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytes::Bytes;
use iggy::prelude::{Client, IggyError, ShmClient, ShmClientConfig};
use iggy_binary_protocol::HEADER_SIZE;
use iggy_binary_protocol::codes::{LOGIN_REGISTER_CODE, PING_CODE};
use iggy_binary_protocol::consensus::{Command, Operation, ReplyHeader, RequestHeader};
use iggy_common::BinaryTransport;
use shm::consumer::LogConsumer;
use shm::control::{ControlPage, Side};
use shm::handshake::{HELLO_LEN, WELCOME_OK, Welcome};
use shm::layout::{LogGeometry, SegmentLayout};
use shm::mem::RawLogMemory;
use shm::producer::LogProducer;
use shm::segment::{AnonymousSegment, SegmentMapping};

const REGION_CAPACITY: usize = 64 * 1024;
const MAX_MESSAGE_SIZE: u64 = 16 * 1024;
const RECV_BUDGET: Duration = Duration::from_secs(10);

/// Server half of one scripted connection.
struct FakeSession {
    stream: UnixStream,
    producer: LogProducer<RawLogMemory>,
    consumer: LogConsumer<RawLogMemory>,
    _control: ControlPage,
    _mapping: SegmentMapping,
    _segment: AnonymousSegment,
}

impl FakeSession {
    /// Next committed request frame, busy-polled: the script side never
    /// parks, so it does not depend on doorbells for its own wakes.
    fn recv_request(&mut self, budget: Duration) -> Option<Vec<u8>> {
        let deadline = Instant::now() + budget;
        loop {
            if let Some(record) = self.consumer.try_poll().unwrap() {
                let mut frame = vec![0u8; record.payload_len()];
                record.copy_payload_into(&mut frame);
                record.release();
                return Some(frame);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Append one reply frame and ring the doorbell; the client parks
    /// between polls, so every reply is followed by a wake.
    fn send_reply(&mut self, status: u32, operation: Operation, body: &[u8]) {
        let header = ReplyHeader {
            command: Command::Reply,
            operation,
            status,
            size: u32::try_from(HEADER_SIZE + body.len()).unwrap(),
            ..Default::default()
        };
        let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
        frame.extend_from_slice(bytemuck::bytes_of(&header));
        frame.extend_from_slice(body);
        self.producer.try_append(&frame).unwrap();
        self.stream.write_all(&[1u8]).unwrap();
    }

    /// Echo the request payload back as a passthrough reply.
    fn echo(&mut self, request: &[u8]) {
        let body = request[HEADER_SIZE..].to_vec();
        self.send_reply(0, Operation::NonReplicated, &body);
    }
}

/// The `request` field bytes of an encoded request frame, for identity
/// comparison across replays without assuming endianness.
fn request_id_bytes(frame: &[u8]) -> &[u8] {
    const OFFSET: usize = offset_of!(RequestHeader, request);
    &frame[OFFSET..OFFSET + 8]
}

/// Bind the socket, then serve exactly one scripted connection on a
/// background thread. Binding happens before this returns so a client
/// may dial immediately.
fn start_fake_server(
    name: &str,
    script: impl FnOnce(&mut FakeSession) + Send + 'static,
) -> (PathBuf, JoinHandle<()>) {
    let path =
        std::env::temp_dir().join(format!("iggy-shm-sdk-{}-{name}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let handle = std::thread::spawn(move || {
        let (stream, _peer) = listener.accept().unwrap();
        let mut session = handshake(stream);
        script(&mut session);
    });
    (path, handle)
}

fn handshake(mut stream: UnixStream) -> FakeSession {
    stream.set_read_timeout(Some(RECV_BUDGET)).unwrap();
    let mut hello = [0u8; HELLO_LEN];
    stream.read_exact(&mut hello).unwrap();

    let geometry = LogGeometry {
        region_capacity: REGION_CAPACITY,
    };
    let layout = SegmentLayout::compute(geometry, geometry).unwrap();
    let segment = AnonymousSegment::allocate(layout.total_len).unwrap();
    let mapping = SegmentMapping::map(&segment).unwrap();
    // Safety: the control page heads a mapping owned by the session
    // being built; no other references to those bytes exist yet.
    let control = unsafe { ControlPage::new(mapping.as_ptr()) };
    control.initialize(&layout);
    control.record_attach(Side::Server, u64::from(std::process::id()), 1);
    control.store_heartbeat(Side::Server, 1);

    let welcome = Welcome {
        status: WELCOME_OK,
        region_capacity: REGION_CAPACITY as u64,
        max_message_size: MAX_MESSAGE_SIZE,
        client_id: 1,
    }
    .encode();
    send_with_fd(&stream, &welcome, segment.as_fd());

    // Safety: the mapping outlives the views (same struct), and this
    // thread is the only server party on both logs.
    let (producer_memory, consumer_memory) = unsafe {
        (
            mapping.server_to_client_memory(&layout),
            mapping.client_to_server_memory(&layout),
        )
    };
    FakeSession {
        stream,
        producer: LogProducer::new(producer_memory, geometry),
        consumer: LogConsumer::new(consumer_memory, geometry),
        _control: control,
        _mapping: mapping,
        _segment: segment,
    }
}

/// Blocking `sendmsg` of the welcome plus one `SCM_RIGHTS` fd.
fn send_with_fd(stream: &UnixStream, payload: &[u8], fd: BorrowedFd<'_>) {
    // cmsghdr structures are built inside this buffer, so it must carry
    // cmsghdr alignment; a bare byte array only aligns to 1.
    #[repr(C, align(8))]
    struct AlignedCmsgBuffer([u8; 64]);

    let mut control = AlignedCmsgBuffer([0u8; 64]);
    #[allow(clippy::cast_possible_truncation)]
    let control_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) };

    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast::<libc::c_void>();
    message.msg_controllen = control_len as _;

    let header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    assert!(!header.is_null());
    // Safety: CMSG_FIRSTHDR returned a header inside the aligned
    // control buffer sized by CMSG_SPACE above.
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::write_unaligned(
            libc::CMSG_DATA(header).cast::<libc::c_int>(),
            fd.as_raw_fd(),
        );
    }

    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const message, 0) };
    assert_eq!(
        usize::try_from(sent).expect("sendmsg failed"),
        payload.len()
    );
}

async fn connected_client(path: &std::path::Path) -> ShmClient {
    let mut config = ShmClientConfig {
        server_address: path.display().to_string(),
        ..ShmClientConfig::default()
    };
    // Failures must surface, not enter the reconnect ladder.
    config.reconnection.enabled = false;
    let client = ShmClient::create(Arc::new(config)).unwrap();
    Client::connect(&client).await.unwrap();
    client
}

fn finish(path: PathBuf, server: JoinHandle<()>) {
    server.join().expect("the fake server script panicked");
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn a_cancelled_exchange_still_consumes_its_own_reply() {
    let (path, server) = start_fake_server("cancel", |session| {
        let first = session.recv_request(RECV_BUDGET).expect("first request");
        // Reply after the caller has already given up; a desynced
        // client would hand these bytes to the next caller.
        std::thread::sleep(Duration::from_millis(500));
        session.echo(&first);
        let second = session.recv_request(RECV_BUDGET).expect("second request");
        session.echo(&second);
    });

    let client = connected_client(&path).await;
    let cancelled = tokio::time::timeout(
        Duration::from_millis(100),
        client.send_raw_with_response(PING_CODE, Bytes::from_static(b"first-payload")),
    )
    .await;
    assert!(cancelled.is_err(), "the first call must time out");

    let reply = client
        .send_raw_with_response(PING_CODE, Bytes::from_static(b"second-payload"))
        .await
        .expect("the second exchange succeeds");
    assert_eq!(
        reply.as_ref(),
        b"second-payload",
        "the abandoned first reply must be consumed by the actor, never handed to a later caller"
    );

    drop(client);
    finish(path, server);
}

#[tokio::test]
async fn concurrent_senders_each_get_their_own_reply() {
    const SENDERS: usize = 8;
    let (path, server) = start_fake_server("interleave", |session| {
        for _ in 0..SENDERS {
            let request = session.recv_request(RECV_BUDGET).expect("request");
            session.echo(&request);
        }
    });

    let client = Arc::new(connected_client(&path).await);
    let mut tasks = Vec::with_capacity(SENDERS);
    for sender in 0..SENDERS {
        let client = Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            let payload = format!("payload-of-sender-{sender}");
            let reply = client
                .send_raw_with_response(PING_CODE, Bytes::from(payload.clone()))
                .await
                .expect("exchange succeeds");
            assert_eq!(
                reply.as_ref(),
                payload.as_bytes(),
                "a caller must receive the reply to its own request"
            );
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }

    drop(client);
    finish(path, server);
}

#[tokio::test]
async fn a_transient_replay_reuses_the_same_request_id() {
    let (path, server) = start_fake_server("replay", |session| {
        let first = session.recv_request(RECV_BUDGET).expect("first attempt");
        session.send_reply(
            IggyError::TransientNotCommitted.as_code(),
            Operation::NonReplicated,
            &[],
        );
        let replay = session.recv_request(RECV_BUDGET).expect("replayed attempt");
        assert_eq!(
            request_id_bytes(&first),
            request_id_bytes(&replay),
            "a transient replay must reuse the request id so server dedup can match it"
        );
        assert_eq!(first, replay, "the replay must be the identical frame");
        session.echo(&replay);
    });

    let client = connected_client(&path).await;
    let reply = client
        .send_raw_with_response(PING_CODE, Bytes::from_static(b"replayed"))
        .await
        .expect("the exchange succeeds after one transient answer");
    assert_eq!(reply.as_ref(), b"replayed");

    drop(client);
    finish(path, server);
}

#[tokio::test]
async fn login_keeps_replaying_not_accepted_past_the_short_window() {
    // Holds the not-accepted answer open for longer than the 2s window
    // ordinary requests get; login must ride it out on the full budget,
    // the way a reconnect that lands inside an election has to.
    let (path, server) = start_fake_server("login-budget", |session| {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let _login_attempt = session.recv_request(RECV_BUDGET).expect("login attempt");
            if Instant::now() >= deadline {
                // An empty Register body is the terminal-success shape
                // that passes through the result-section decode.
                session.send_reply(0, Operation::Register, &[]);
                return;
            }
            session.send_reply(
                IggyError::TransientNotAccepted.as_code(),
                Operation::Register,
                &[],
            );
        }
    });

    let client = connected_client(&path).await;
    let started = Instant::now();
    let reply = client
        .send_raw_with_response(LOGIN_REGISTER_CODE, Bytes::from_static(b"credentials"))
        .await;
    assert!(
        reply.is_ok(),
        "login must survive a not-accepted window longer than 2s, got {reply:?}"
    );
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "the success reply only exists past the short window; finishing sooner means the \
         script broke, not the client"
    );

    drop(client);
    finish(path, server);
}

#[tokio::test]
async fn an_ordinary_request_surfaces_not_accepted_after_the_short_window() {
    let (path, server) = start_fake_server("surface", |session| {
        // Answer every replay with not-accepted until the client gives
        // up and goes quiet.
        while let Some(_request) = session.recv_request(Duration::from_secs(3)) {
            session.send_reply(
                IggyError::TransientNotAccepted.as_code(),
                Operation::NonReplicated,
                &[],
            );
        }
    });

    let client = connected_client(&path).await;
    let started = Instant::now();
    let reply = client
        .send_raw_with_response(PING_CODE, Bytes::from_static(b"refused"))
        .await;
    assert!(
        matches!(reply, Err(IggyError::TransientNotAccepted)),
        "a persistent not-accepted verdict must surface, got {reply:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the verdict must surface at the short window, not after the full response budget"
    );

    drop(client);
    finish(path, server);
}
