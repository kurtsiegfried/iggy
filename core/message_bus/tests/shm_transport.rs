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

//! Shared-memory transport machinery against a hand-rolled blocking
//! client: handshake with fd passing, frame echo through the install
//! path's dispatch loop, the parked-consumer doorbell, teardown on
//! socket close, and teardown on a poisoned log.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use iggy_binary_protocol::{Command, HEADER_SIZE, SIZE_FIELD_OFFSET};
use message_bus::config::{MessageBusConfig, ShmTuning};
use message_bus::installer::conn_info::{ClientConnMeta, ClientTransportKind};
use message_bus::installer::install_client_shm;
use message_bus::{IggyMessageBus, MessageBus};
use shm::consumer::LogConsumer;
use shm::control::{ControlPage, Side};
use shm::layout::{LAYOUT_VERSION, LogGeometry, SEGMENT_MAGIC, SegmentLayout};
use shm::mem::LogMemory;
use shm::producer::LogProducer;
use shm::segment::{AnonymousSegment, SegmentMapping};

const REGION_CAPACITY: usize = 64 * 1024;
const MAX_MESSAGE_SIZE: usize = 16 * 1024;
const HELLO_LEN: usize = 16;
const WELCOME_LEN: usize = 48;
const CLIENT_ID: u128 = 1;
const WAIT_BUDGET: Duration = Duration::from_secs(10);

fn test_bus() -> Rc<IggyMessageBus> {
    Rc::new(IggyMessageBus::with_tunables(
        0,
        MessageBusConfig {
            shm: ShmTuning {
                region_capacity: REGION_CAPACITY,
                max_message_size: MAX_MESSAGE_SIZE,
                max_connections: 2,
            },
            ..MessageBusConfig::default()
        },
    ))
}

fn socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("iggy-shm-test-{name}-{}.sock", std::process::id()))
}

/// A minimal structurally valid consensus request frame: zeroed
/// 256-byte header with `command = Request` and the size field set,
/// plus `payload_marker` repeated in the body for content assertions.
fn request_frame(body_len: usize, payload_marker: u8) -> Vec<u8> {
    let mut frame = vec![0u8; HEADER_SIZE + body_len];
    let total = u32::try_from(frame.len()).unwrap();
    frame[SIZE_FIELD_OFFSET..SIZE_FIELD_OFFSET + 4].copy_from_slice(&total.to_le_bytes());
    frame[60] = Command::Request as u8;
    for byte in &mut frame[HEADER_SIZE..] {
        *byte = payload_marker;
    }
    frame
}

/// Client-side session over the received segment.
struct RawShmClient {
    stream: StdUnixStream,
    producer: LogProducer<shm::mem::RawLogMemory>,
    consumer: LogConsumer<shm::mem::RawLogMemory>,
    _control: ControlPage,
    mapping: SegmentMapping,
    _segment: AnonymousSegment,
}

impl RawShmClient {
    fn connect(path: &std::path::Path) -> Self {
        let deadline = Instant::now() + WAIT_BUDGET;
        let mut stream = loop {
            match StdUnixStream::connect(path) {
                Ok(stream) => break stream,
                Err(_not_yet) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("cannot connect to shm socket: {error}"),
            }
        };

        let mut hello = [0u8; HELLO_LEN];
        hello[0..8].copy_from_slice(&SEGMENT_MAGIC.to_le_bytes());
        hello[8..12].copy_from_slice(&LAYOUT_VERSION.to_le_bytes());
        stream.write_all(&hello).unwrap();

        let (welcome, fd) = recv_with_fd(&stream, WELCOME_LEN);
        let magic = u64::from_le_bytes(welcome[0..8].try_into().unwrap());
        let status = u32::from_le_bytes(welcome[12..16].try_into().unwrap());
        let region_capacity = u64::from_le_bytes(welcome[16..24].try_into().unwrap());
        assert_eq!(magic, SEGMENT_MAGIC);
        assert_eq!(status, 0, "welcome status");
        let geometry = LogGeometry {
            region_capacity: usize::try_from(region_capacity).unwrap(),
        };
        let layout = SegmentLayout::compute(geometry, geometry).unwrap();

        let segment =
            AnonymousSegment::from_received_fd(fd.expect("welcome carries fd"), layout.total_len)
                .unwrap();
        let mapping = SegmentMapping::map(&segment).unwrap();
        // Safety: the control page heads a mapping owned by this
        // struct; no other references to those bytes exist client-side.
        let control = unsafe { ControlPage::new(mapping.as_ptr()) };
        let (advertised_c2s, _advertised_s2c) = control.validate().unwrap();
        assert_eq!(advertised_c2s.region_capacity, geometry.region_capacity);
        control.record_attach(Side::Client, u64::from(std::process::id()), 1);

        // Safety: the mapping outlives the views (same struct), and
        // this process is the only client party: one producer on the
        // client-to-server log, one consumer on the reverse log.
        let (producer_memory, consumer_memory) = unsafe {
            (
                mapping.client_to_server_memory(&layout),
                mapping.server_to_client_memory(&layout),
            )
        };
        Self {
            stream,
            producer: LogProducer::new(producer_memory, geometry),
            consumer: LogConsumer::new(consumer_memory, geometry),
            _control: control,
            mapping,
            _segment: segment,
        }
    }

    fn send_frame(&mut self, frame: &[u8]) {
        self.producer.try_append(frame).unwrap();
        // The server parks with a fenced flag; ring unconditionally so
        // the test does not depend on catching it awake.
        self.stream.write_all(&[1u8]).unwrap();
    }

    fn recv_frame(&mut self) -> Vec<u8> {
        let deadline = Instant::now() + WAIT_BUDGET;
        loop {
            if let Some(record) = self.consumer.try_poll().unwrap() {
                let mut frame = vec![0u8; record.payload_len()];
                record.copy_payload_into(&mut frame);
                record.release();
                return frame;
            }
            assert!(Instant::now() < deadline, "timed out waiting for a frame");
            std::thread::yield_now();
        }
    }
}

/// Blocking `recvmsg` for the fixed-size welcome plus one optional fd.
fn recv_with_fd(stream: &StdUnixStream, payload_len: usize) -> (Vec<u8>, Option<OwnedFd>) {
    let mut payload = vec![0u8; payload_len];
    let mut control = [0u8; 64];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    #[allow(clippy::cast_possible_truncation)]
    // socklen_t is u32 on some unix targets; 64 always fits.
    {
        message.msg_controllen = control.len() as _;
    }

    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut message, 0) };
    assert!(received >= 0, "recvmsg failed");
    assert_eq!(usize::try_from(received).unwrap(), payload_len);

    let header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    let fd = if header.is_null() {
        None
    } else {
        let header_ref = unsafe { &*header };
        assert_eq!(header_ref.cmsg_level, libc::SOL_SOCKET);
        assert_eq!(header_ref.cmsg_type, libc::SCM_RIGHTS);
        let raw_fd =
            unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>()) };
        // Safety: the kernel installed a fresh fd for this process.
        Some(unsafe { OwnedFd::from_raw_fd(raw_fd) })
    };
    (payload, fd)
}

/// Install path wired the way bootstrap does it, with an echo handler
/// in place of the server's dispatch.
fn install_echo_listener(bus: &Rc<IggyMessageBus>, path: &std::path::Path) {
    let echo_bus = Rc::clone(bus);
    let on_request: message_bus::client_listener::RequestHandler =
        Rc::new(move |client_id, message| {
            let reply_bus = Rc::clone(&echo_bus);
            let tracker = Rc::clone(&echo_bus);
            let handle = compio::runtime::spawn(async move {
                let _ = reply_bus
                    .send_to_client(client_id, message.into_frozen())
                    .await;
            });
            tracker.track_background(handle);
        });

    let install_bus = Rc::clone(bus);
    let on_accepted: message_bus::AcceptedShmClientFn = Rc::new(move |stream| {
        let meta = ClientConnMeta::new(
            CLIENT_ID,
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            ClientTransportKind::Shm,
        );
        install_client_shm(&install_bus, meta, stream, on_request.clone());
    });

    let listener_bus = Rc::clone(bus);
    let listen_path = path.to_path_buf();
    let handle = compio::runtime::spawn(async move {
        let listener = message_bus::client_listener::shm::bind(&listen_path)
            .await
            .unwrap();
        message_bus::client_listener::shm::run(listener, listener_bus.token(), on_accepted).await;
    });
    bus.track_background(handle);
}

#[allow(clippy::future_not_send)]
async fn wait_for_signal(signal: &std::sync::mpsc::Receiver<()>) {
    let deadline = Instant::now() + WAIT_BUDGET;
    loop {
        match signal.try_recv() {
            Ok(()) => return,
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                assert!(Instant::now() < deadline, "client never signalled");
                compio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                panic!("client thread exited before signalling")
            }
        }
    }
}

#[allow(clippy::future_not_send)]
async fn wait_for_meta_present(bus: &Rc<IggyMessageBus>) {
    let deadline = Instant::now() + WAIT_BUDGET;
    while bus.client_meta(CLIENT_ID).is_none() {
        assert!(Instant::now() < deadline, "connection was never installed");
        compio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[allow(clippy::future_not_send)]
async fn wait_for_meta_gone(bus: &Rc<IggyMessageBus>) {
    let deadline = Instant::now() + WAIT_BUDGET;
    while bus.client_meta(CLIENT_ID).is_some() {
        assert!(Instant::now() < deadline, "connection was not torn down");
        compio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Join a client thread without blocking the single-threaded compio
/// runtime, which would starve the listener and pump tasks.
#[allow(clippy::future_not_send)]
async fn join_client(client: std::thread::JoinHandle<()>) {
    while !client.is_finished() {
        compio::time::sleep(Duration::from_millis(5)).await;
    }
    client.join().unwrap();
}

#[compio::test]
async fn frames_echo_through_the_shared_memory_transport() {
    let bus = test_bus();
    let path = socket_path("echo");
    install_echo_listener(&bus, &path);

    let client = std::thread::spawn({
        let path = path.clone();
        move || {
            let mut client = RawShmClient::connect(&path);
            for round in 0..64u8 {
                let frame = request_frame(usize::from(round) * 7, round);
                client.send_frame(&frame);
                let echoed = client.recv_frame();
                assert_eq!(echoed, frame, "echo mismatch at round {round}");
            }
        }
    });

    join_client(client).await;
    let _ = std::fs::remove_file(&path);
}

#[compio::test]
async fn parked_client_is_woken_by_the_doorbell() {
    let bus = test_bus();
    let path = socket_path("doorbell");
    install_echo_listener(&bus, &path);

    let client = std::thread::spawn({
        let path = path.clone();
        move || {
            let mut client = RawShmClient::connect(&path);
            let frame = request_frame(32, 0xAB);
            client.send_frame(&frame);

            // Park for real: declare the flag, recheck, then block on
            // the socket until the server's doorbell byte arrives.
            client.consumer.prepare_park();
            if client.consumer.try_poll().unwrap().is_none() {
                client.stream.set_read_timeout(Some(WAIT_BUDGET)).unwrap();
                let mut doorbell = [0u8; 1];
                client.stream.read_exact(&mut doorbell).unwrap();
            }
            client.consumer.cancel_park();
            assert_eq!(client.recv_frame(), frame);
        }
    });

    join_client(client).await;
    let _ = std::fs::remove_file(&path);
}

#[compio::test]
async fn closing_the_socket_tears_the_connection_down() {
    let bus = test_bus();
    let path = socket_path("teardown");
    install_echo_listener(&bus, &path);

    // Barrier pair: without it the install-then-evict window of an
    // instantly-dropped client can complete between two presence
    // polls and the test races its own subject.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let (proceed_tx, proceed_rx) = std::sync::mpsc::channel::<()>();
    let client = std::thread::spawn({
        let path = path.clone();
        move || {
            let client = RawShmClient::connect(&path);
            ready_tx.send(()).unwrap();
            proceed_rx.recv().unwrap();
            drop(client);
        }
    });

    wait_for_signal(&ready_rx).await;
    wait_for_meta_present(&bus).await;
    proceed_tx.send(()).unwrap();
    join_client(client).await;
    wait_for_meta_gone(&bus).await;
    let _ = std::fs::remove_file(&path);
}

#[compio::test]
async fn a_poisoned_log_tears_the_connection_down() {
    let bus = test_bus();
    let path = socket_path("poison");
    install_echo_listener(&bus, &path);

    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let (proceed_tx, proceed_rx) = std::sync::mpsc::channel::<()>();
    let client = std::thread::spawn({
        let path = path.clone();
        move || {
            let mut client = RawShmClient::connect(&path);
            ready_tx.send(()).unwrap();
            proceed_rx.recv().unwrap();
            // A record whose type byte is garbage: the server consumer
            // must poison and drop the connection, not panic.
            let frame = request_frame(16, 0x11);
            client.producer.try_append(&frame).unwrap();
            let memory = unsafe {
                client.mapping.client_to_server_memory(
                    &SegmentLayout::compute(
                        LogGeometry {
                            region_capacity: REGION_CAPACITY,
                        },
                        LogGeometry {
                            region_capacity: REGION_CAPACITY,
                        },
                    )
                    .unwrap(),
                )
            };
            memory.write_data(4, &[0x77]);
            client.stream.write_all(&[1u8]).unwrap();
            // Hold the socket open: teardown must come from the poison,
            // not from EOF.
            std::thread::sleep(Duration::from_millis(500));
        }
    });

    wait_for_signal(&ready_rx).await;
    wait_for_meta_present(&bus).await;
    proceed_tx.send(()).unwrap();
    wait_for_meta_gone(&bus).await;
    join_client(client).await;
    let _ = std::fs::remove_file(&path);
}
