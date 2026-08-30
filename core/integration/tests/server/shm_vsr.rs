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

//! Shared-memory transport parity against a real server: the same
//! pre-auth ping, login-register, and protocol-version eviction
//! semantics the TCP plane provides, driven by a hand-rolled client
//! over the unix-socket handshake and the shared-memory logs.

use std::io::Write;
use std::mem::offset_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use iggy_binary_protocol::codes::PING_CODE;
use iggy_binary_protocol::consensus::{
    Command, EvictionHeader, Operation, ReplyHeader, RequestHeader,
};
use iggy_binary_protocol::requests::users::LoginRegisterRequest;
use iggy_binary_protocol::{
    ClientVersionInfo, HEADER_SIZE, IGGY_PROTOCOL_VERSION, WireEncode, WireName,
};
use integration::iggy_harness;
use secrecy::SecretString;
use shm::consumer::LogConsumer;
use shm::control::{ControlPage, Side};
use shm::layout::{LAYOUT_VERSION, LogGeometry, SEGMENT_MAGIC, SegmentLayout};
use shm::mem::RawLogMemory;
use shm::producer::LogProducer;
use shm::segment::{AnonymousSegment, SegmentMapping};

const SOCKET_PATH: &str = "/tmp/iggy-shm-vsr.sock";
const HELLO_LEN: usize = 16;
const WELCOME_LEN: usize = 48;
const EVICTION_REASON_INCOMPATIBLE_PROTOCOL: u8 = 14;
const WAIT_BUDGET: Duration = Duration::from_secs(10);

#[iggy_harness(server(shm.enabled = "true", shm.socket = "/tmp/iggy-shm-vsr.sock"))]
async fn given_shm_client_when_ping_login_and_stale_version_should_match_tcp_semantics(
    harness: &integration::harness::TestHarness,
) {
    let _server = harness.server();
    tokio::task::spawn_blocking(|| {
        // Pre-auth ping, then a successful login-register, on one
        // connection: the pre-auth contract and the auth entry path.
        let mut client = RawShmClient::connect();

        let ping = request_frame(ping_header(0xC0FFEE, HEADER_SIZE), &[]);
        client.send_frame(&ping);
        let reply = client.recv_frame();
        assert_eq!(reply[60], Command::Reply as u8, "ping must get a Reply");
        assert_eq!(reply_status(&reply), 0, "pre-auth ping must succeed");

        let login_body = login_register_body(IGGY_PROTOCOL_VERSION);
        let login = request_frame(
            register_header(0xC0FFEE, HEADER_SIZE + login_body.len()),
            &login_body,
        );
        client.send_frame(&login);
        let reply = client.recv_frame();
        assert_eq!(reply[60], Command::Reply as u8, "login must get a Reply");
        assert_eq!(reply_status(&reply), 0, "login-register must succeed");

        // A stale protocol version on a fresh connection: the version
        // gate answers with a typed eviction carrying the accepted
        // window, exactly like TCP.
        let mut stale = RawShmClient::connect();
        let stale_body = login_register_body(1);
        let stale_login = request_frame(
            register_header(0xBEEF, HEADER_SIZE + stale_body.len()),
            &stale_body,
        );
        stale.send_frame(&stale_login);
        let eviction = stale.recv_frame();
        assert_eq!(
            eviction[60],
            Command::Eviction as u8,
            "stale version must get an Eviction"
        );
        assert_eq!(
            eviction[255], EVICTION_REASON_INCOMPATIBLE_PROTOCOL,
            "eviction reason must be the protocol gate"
        );
        let window_min = u32::from_le_bytes(
            eviction[offset_of!(EvictionHeader, server_protocol_version_min)
                ..offset_of!(EvictionHeader, server_protocol_version_min) + 4]
                .try_into()
                .unwrap(),
        );
        assert!(window_min > 0, "eviction must carry the accepted window");
    })
    .await
    .unwrap();
}

fn ping_header(client: u128, total_size: usize) -> RequestHeader {
    let mut header = RequestHeader {
        command: Command::Request,
        operation: Operation::NonReplicated,
        size: u32::try_from(total_size).unwrap(),
        client,
        session: 0,
        request: 0,
        ..Default::default()
    };
    header.reserved[..4].copy_from_slice(&PING_CODE.to_le_bytes());
    header
}

fn register_header(client: u128, total_size: usize) -> RequestHeader {
    RequestHeader {
        command: Command::Request,
        operation: Operation::Register,
        size: u32::try_from(total_size).unwrap(),
        client,
        session: 0,
        request: 0,
        ..Default::default()
    }
}

fn request_frame(header: RequestHeader, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
    frame.extend_from_slice(bytemuck::bytes_of(&header));
    frame.extend_from_slice(body);
    frame
}

fn login_register_body(protocol_version: u32) -> Vec<u8> {
    let request = LoginRegisterRequest {
        version_info: ClientVersionInfo {
            protocol_version,
            sdk_name: WireName::new("rust-sdk").unwrap(),
            sdk_version: WireName::new("0.0.0").unwrap(),
        },
        username: WireName::new("iggy").unwrap(),
        password: SecretString::from("iggy"),
        client_context: None,
    };
    request.to_bytes().to_vec()
}

fn reply_status(reply: &[u8]) -> u32 {
    let offset = offset_of!(ReplyHeader, status);
    u32::from_le_bytes(reply[offset..offset + 4].try_into().unwrap())
}

struct RawShmClient {
    stream: UnixStream,
    producer: LogProducer<RawLogMemory>,
    consumer: LogConsumer<RawLogMemory>,
    _control: ControlPage,
    _mapping: SegmentMapping,
    _segment: AnonymousSegment,
}

impl RawShmClient {
    fn connect() -> Self {
        let deadline = Instant::now() + WAIT_BUDGET;
        let mut stream = loop {
            match UnixStream::connect(SOCKET_PATH) {
                Ok(stream) => break stream,
                Err(_not_yet) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("cannot connect to shm socket: {error}"),
            }
        };

        let mut hello = [0u8; HELLO_LEN];
        hello[0..8].copy_from_slice(&SEGMENT_MAGIC.to_le_bytes());
        hello[8..12].copy_from_slice(&LAYOUT_VERSION.to_le_bytes());
        stream.write_all(&hello).unwrap();

        let (welcome, fd) = recv_with_fd(&stream, WELCOME_LEN);
        assert_eq!(
            u64::from_le_bytes(welcome[0..8].try_into().unwrap()),
            SEGMENT_MAGIC
        );
        assert_eq!(
            u32::from_le_bytes(welcome[12..16].try_into().unwrap()),
            0,
            "welcome status"
        );
        let region_capacity = u64::from_le_bytes(welcome[16..24].try_into().unwrap());
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
        control.validate().unwrap();
        control.record_attach(Side::Client, u64::from(std::process::id()), 1);

        // Safety: the mapping outlives the views (same struct), and
        // this process is the only client party on both logs.
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
            _mapping: mapping,
            _segment: segment,
        }
    }

    fn send_frame(&mut self, frame: &[u8]) {
        self.producer.try_append(frame).unwrap();
        // Ring unconditionally: the server parks with a fenced flag,
        // and a spurious byte is cheaper than a race in a test.
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
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Blocking `recvmsg` for the fixed-size welcome plus one fd.
fn recv_with_fd(stream: &UnixStream, payload_len: usize) -> (Vec<u8>, Option<OwnedFd>) {
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
