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

//! Shared-memory transport: consensus frames ride a per-connection
//! pair of shared-memory logs; the unix socket that accepted the
//! connection stays open as the control channel.
//!
//! # Socket roles
//!
//! The socket carries exactly four things, none of them frames:
//! the fixed-size HELLO/WELCOME handshake, the segment fd (as
//! `SCM_RIGHTS` ancillary data on the WELCOME), doorbell bytes that
//! wake a peer which declared itself parked, and liveness (peer close
//! tears the connection down).
//!
//! # Handshake
//!
//! Client sends `HELLO = [magic: u64][layout_version: u32][flags:
//! u32]`. The server allocates and maps the segment, initializes its
//! control page, and answers `WELCOME = [magic: u64][layout_version:
//! u32][status: u32][region_capacity: u64][max_message_size: u64]
//! [client_id: u128]` with the sealed segment fd attached when
//! `status` is [`WELCOME_OK`]. All integers little-endian. A non-zero
//! status carries no fd and the socket closes after the write, so a
//! rejected client still learns why.
//!
//! # Pump
//!
//! One task per connection drives both directions: drain committed
//! client frames into `in_tx`, append bus replies into the
//! server-to-client log, ring the doorbell when the client flagged
//! itself parked, and park on the socket (with the fenced
//! flag-then-recheck protocol from the `shm` crate) when there is no
//! work. Frame validation reuses the WS message-boundary codec: the
//! embedded size field must equal the record payload exactly.
//!
//! # Ordering
//!
//! The log is FIFO in both directions and the pump preserves arrival
//! order end to end, so replies leave in request order exactly like
//! the TCP plane. There is no per-frame correlation on this
//! transport; like WS, it relies on the caller's lockstep discipline.

use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::ptr::NonNull;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use compio::BufResult;
use compio::io::ancillary::AsyncWriteAncillary;
use compio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use compio::net::UnixStream;
use futures::FutureExt;
use shm::consumer::LogConsumer;
use shm::control::{ControlPage, Side};
use shm::layout::{LAYOUT_VERSION, LogGeometry, SEGMENT_MAGIC, SegmentLayout};
use shm::mem::RawLogMemory;
use shm::producer::{AppendError, LogProducer};
use shm::segment::{AnonymousSegment, SegmentMapping};
use tracing::{debug, warn};

use super::ws::decode_consensus_frame;
use super::{ActorContext, TransportConn};
use crate::config::ShmTuning;

pub const HELLO_LEN: usize = 16;
pub const WELCOME_LEN: usize = 48;

pub const WELCOME_OK: u32 = 0;
/// The client's magic or layout version is not one this build speaks.
pub const WELCOME_UNSUPPORTED: u32 = 1;
/// Segment allocation or mapping failed on the server.
pub const WELCOME_INTERNAL: u32 = 2;

/// Interval between heartbeat stores while parked, and the cadence of
/// the wedged-peer staleness check.
const HEARTBEAT_TICK: Duration = Duration::from_secs(1);
/// A client that once heartbeated and then went silent this long while
/// its socket stays open is treated as wedged and torn down. Clients
/// that never heartbeat are exempt; their liveness is socket EOF only.
const CLIENT_STALE_AFTER: Duration = Duration::from_secs(30);

const DEFAULT_HANDSHAKE_GRACE: Duration = Duration::from_secs(10);

/// A single shared-memory connection, pre-handshake. `run` drives the
/// handshake (bounded by the grace), then the pump.
pub struct ShmTransportConn {
    stream: UnixStream,
    tuning: ShmTuning,
    handshake_grace: Duration,
    client_id: u128,
}

impl ShmTransportConn {
    #[must_use]
    pub const fn new_server(stream: UnixStream, tuning: ShmTuning, client_id: u128) -> Self {
        Self {
            stream,
            tuning,
            handshake_grace: DEFAULT_HANDSHAKE_GRACE,
            client_id,
        }
    }

    #[must_use]
    pub const fn with_handshake_grace(mut self, handshake_grace: Duration) -> Self {
        self.handshake_grace = handshake_grace;
        self
    }
}

impl TransportConn for ShmTransportConn {
    #[allow(clippy::future_not_send)]
    async fn run(self, ctx: ActorContext) {
        let label = ctx.label;
        let peer = ctx.peer.clone();
        let mut stream = self.stream;

        let handshake = compio::time::timeout(
            self.handshake_grace,
            server_handshake(&mut stream, &self.tuning, self.client_id),
        )
        .await;
        let session = match handshake {
            Ok(Ok(session)) => session,
            Ok(Err(error)) => {
                warn!(%label, %peer, "shm handshake failed: {error}");
                return;
            }
            Err(_elapsed) => {
                warn!(
                    %label, %peer, grace = ?self.handshake_grace,
                    "shm handshake exceeded handshake_grace; closing connection"
                );
                return;
            }
        };

        run_pump(stream, session, self.tuning.max_message_size, ctx).await;
    }
}

/// Server-side state over one mapped segment. Field order keeps the
/// log views and control page ahead of the mapping they point into,
/// and the mapping ahead of the segment fd.
struct ShmSession {
    producer: LogProducer<RawLogMemory>,
    consumer: LogConsumer<RawLogMemory>,
    control: ControlPage,
    _mapping: SegmentMapping,
    segment: AnonymousSegment,
}

#[allow(clippy::future_not_send)]
async fn server_handshake(
    stream: &mut UnixStream,
    tuning: &ShmTuning,
    client_id: u128,
) -> std::io::Result<ShmSession> {
    let BufResult(read_result, hello) = stream.read_exact(Vec::with_capacity(HELLO_LEN)).await;
    read_result?;

    let magic = u64::from_le_bytes(hello[0..8].try_into().expect("fixed slice"));
    let layout_version = u32::from_le_bytes(hello[8..12].try_into().expect("fixed slice"));
    if magic != SEGMENT_MAGIC || layout_version != LAYOUT_VERSION {
        send_welcome(stream, WELCOME_UNSUPPORTED, tuning, client_id, None).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported hello: magic {magic:#x}, layout version {layout_version}"),
        ));
    }

    let geometry = LogGeometry {
        region_capacity: tuning.region_capacity,
    };
    let session = match build_session(geometry) {
        Ok(session) => session,
        Err(error) => {
            send_welcome(stream, WELCOME_INTERNAL, tuning, client_id, None).await?;
            return Err(error);
        }
    };

    session
        .control
        .record_attach(Side::Server, u64::from(std::process::id()), now_micros());
    session.control.store_heartbeat(Side::Server, now_micros());

    let segment_fd = session.segment.as_fd().as_raw_fd();
    send_welcome(stream, WELCOME_OK, tuning, client_id, Some(segment_fd)).await?;
    Ok(session)
}

fn build_session(geometry: LogGeometry) -> std::io::Result<ShmSession> {
    let layout = SegmentLayout::compute(geometry, geometry)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let segment = AnonymousSegment::allocate(layout.total_len)?;
    let mapping = SegmentMapping::map(&segment)?;

    let control_base = NonNull::new(mapping.as_ptr().as_ptr())
        .ok_or_else(|| std::io::Error::other("mapping base is null"))?;
    // Safety: the control page occupies the head of a mapping that
    // lives in `ShmSession` alongside this view, and no other Rust
    // references to those bytes exist in this process.
    let control = unsafe { ControlPage::new(control_base) };
    control.initialize(&layout);

    // Safety: the mapping outlives the views (both live in the same
    // `ShmSession`), and this process is the only server party: one
    // producer on the server-to-client log, one consumer on the
    // client-to-server log.
    let (producer_memory, consumer_memory) = unsafe {
        (
            mapping.server_to_client_memory(&layout),
            mapping.client_to_server_memory(&layout),
        )
    };
    Ok(ShmSession {
        producer: LogProducer::new(producer_memory, geometry),
        consumer: LogConsumer::new(consumer_memory, geometry),
        control,
        _mapping: mapping,
        segment,
    })
}

#[allow(clippy::future_not_send)]
async fn send_welcome(
    stream: &mut UnixStream,
    status: u32,
    tuning: &ShmTuning,
    client_id: u128,
    segment_fd: Option<RawFd>,
) -> std::io::Result<()> {
    let mut welcome = Vec::with_capacity(WELCOME_LEN);
    welcome.extend_from_slice(&SEGMENT_MAGIC.to_le_bytes());
    welcome.extend_from_slice(&LAYOUT_VERSION.to_le_bytes());
    welcome.extend_from_slice(&status.to_le_bytes());
    welcome.extend_from_slice(&(tuning.region_capacity as u64).to_le_bytes());
    welcome.extend_from_slice(&(tuning.max_message_size as u64).to_le_bytes());
    welcome.extend_from_slice(&client_id.to_le_bytes());
    debug_assert_eq!(welcome.len(), WELCOME_LEN);

    let written = if let Some(fd) = segment_fd {
        let control_bytes = scm_rights_control(fd);
        let BufResult(write_result, _buffers) =
            stream.write_with_ancillary(welcome, control_bytes).await;
        write_result?
    } else {
        let BufResult(write_result, _buffer) = stream.write(welcome).await;
        write_result?
    };
    if written != WELCOME_LEN {
        return Err(std::io::Error::other(
            "short write on shm welcome; peer socket buffer unexpectedly full",
        ));
    }
    Ok(())
}

/// `SCM_RIGHTS` control message carrying one fd, laid out for the
/// kernel by hand because compio takes the control buffer as raw
/// bytes.
fn scm_rights_control(fd: RawFd) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    let space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0u8; space];
    let header = control.as_mut_ptr().cast::<libc::cmsghdr>();
    // Safety: the buffer is CMSG_SPACE bytes, zeroed, exclusively ours;
    // CMSG_DATA points inside it by construction.
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        #[allow(clippy::cast_possible_truncation)]
        {
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        }
        (*header).cmsg_type = libc::SCM_RIGHTS;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), fd);
    }
    control
}

/// Per-iteration outcome of the parked select.
enum PumpWake {
    Shutdown,
    Outbound(crate::lifecycle::BusMessage),
    MailboxClosed,
    Doorbell,
    PeerClosed,
    SocketError(std::io::Error),
    HeartbeatTick,
}

#[allow(clippy::future_not_send, clippy::too_many_lines)]
async fn run_pump(
    mut stream: UnixStream,
    mut session: ShmSession,
    max_message_size: usize,
    ctx: ActorContext,
) {
    let ActorContext {
        in_tx,
        rx,
        shutdown,
        label,
        peer,
        ..
    } = ctx;
    let mut scratch: Vec<u8> = Vec::new();
    let mut pending_outbound: Option<crate::lifecycle::BusMessage> = None;

    loop {
        // Inbound: drain committed client frames toward dispatch.
        loop {
            let payload_len = match session.consumer.try_poll() {
                Ok(Some(record)) => {
                    let payload_len = record.payload_len();
                    scratch.resize(payload_len, 0);
                    record.copy_payload_into(&mut scratch);
                    record.release();
                    payload_len
                }
                Ok(None) => break,
                Err(poll_error) => {
                    warn!(%label, %peer, "shm log poisoned: {poll_error}");
                    return;
                }
            };
            match decode_consensus_frame(&scratch[..payload_len], max_message_size) {
                Ok(message) => {
                    if in_tx.send(message).await.is_err() {
                        debug!(%label, %peer, "shm dispatch queue closed");
                        return;
                    }
                }
                Err(decode_error) => {
                    warn!(%label, %peer, "shm frame rejected: {decode_error:?}");
                    return;
                }
            }
        }

        // Outbound: append bus replies into the server-to-client log.
        loop {
            let frame = match pending_outbound.take() {
                Some(frame) => frame,
                None => match rx.try_recv() {
                    Ok(frame) => frame,
                    Err(_empty_or_closed) => break,
                },
            };
            if frame.as_slice().len() > max_message_size {
                warn!(
                    %label, %peer,
                    frame_len = frame.as_slice().len(),
                    max_message_size,
                    "reply exceeds the shared-memory frame ceiling; closing connection"
                );
                return;
            }
            match session.producer.try_append(frame.as_slice()) {
                Ok(_position) => {}
                Err(AppendError::WouldBlock) => {
                    pending_outbound = Some(frame);
                    break;
                }
                Err(error @ AppendError::PayloadTooLarge { .. }) => {
                    warn!(%label, %peer, "shm append rejected: {error}");
                    return;
                }
            }
        }

        // Doorbell: one byte wakes the client whichever side it parked.
        if session.producer.consumer_parked() || session.consumer.producer_parked() {
            let BufResult(write_result, _buffer) = stream.write(vec![1u8]).await;
            if let Err(error) = write_result {
                debug!(%label, %peer, "shm doorbell write failed: {error}");
                return;
            }
        }

        // Park: declare, then recheck through the fence so a commit or
        // clean racing the declaration cannot be missed.
        session.consumer.prepare_park();
        if pending_outbound.is_some() {
            session.producer.prepare_park();
        }
        let inbound_ready = match session.consumer.try_poll() {
            // The view is dropped unreleased, so the record is
            // re-polled by the next drain pass.
            Ok(Some(_record)) => true,
            Ok(None) => false,
            Err(_poisoned) => true,
        };
        let outbound_ready = if let Some(frame) = pending_outbound.take() {
            match session.producer.try_append(frame.as_slice()) {
                Ok(_position) => true,
                Err(AppendError::WouldBlock) => {
                    pending_outbound = Some(frame);
                    false
                }
                Err(error @ AppendError::PayloadTooLarge { .. }) => {
                    warn!(%label, %peer, "shm append rejected: {error}");
                    return;
                }
            }
        } else {
            false
        };
        if inbound_ready || outbound_ready {
            session.consumer.cancel_park();
            session.producer.cancel_park();
            continue;
        }

        session.control.store_heartbeat(Side::Server, now_micros());

        let wake = if pending_outbound.is_none() {
            futures::select_biased! {
                () = shutdown.wait().fuse() => PumpWake::Shutdown,
                outbound = rx.recv().fuse() => match outbound {
                    Ok(frame) => PumpWake::Outbound(frame),
                    Err(_closed) => PumpWake::MailboxClosed,
                },
                read = stream.read(Vec::with_capacity(8)).fuse() => socket_wake(read),
                () = compio::time::sleep(HEARTBEAT_TICK).fuse() => PumpWake::HeartbeatTick,
            }
        } else {
            // The outbound log is full: taking more bus frames would
            // need a second stash slot, so the mailbox arm sits out
            // until the client cleans a region.
            futures::select_biased! {
                () = shutdown.wait().fuse() => PumpWake::Shutdown,
                read = stream.read(Vec::with_capacity(8)).fuse() => socket_wake(read),
                () = compio::time::sleep(HEARTBEAT_TICK).fuse() => PumpWake::HeartbeatTick,
            }
        };

        session.consumer.cancel_park();
        session.producer.cancel_park();

        match wake {
            PumpWake::Shutdown => {
                debug!(%label, %peer, "shm pump shutting down");
                return;
            }
            PumpWake::Outbound(frame) => {
                pending_outbound = Some(frame);
            }
            PumpWake::MailboxClosed => {
                debug!(%label, %peer, "shm outbound mailbox closed");
                return;
            }
            PumpWake::Doorbell | PumpWake::HeartbeatTick => {
                if client_is_stale(&session.control) {
                    warn!(%label, %peer, "shm client heartbeat stale; closing connection");
                    return;
                }
            }
            PumpWake::PeerClosed => {
                debug!(%label, %peer, "shm peer closed the control socket");
                return;
            }
            PumpWake::SocketError(error) => {
                debug!(%label, %peer, "shm control socket error: {error}");
                return;
            }
        }
    }
}

fn socket_wake(read: BufResult<usize, Vec<u8>>) -> PumpWake {
    let BufResult(read_result, _buffer) = read;
    match read_result {
        Ok(0) => PumpWake::PeerClosed,
        Ok(_doorbell_bytes) => PumpWake::Doorbell,
        Err(error) => PumpWake::SocketError(error),
    }
}

/// Wedge detection: a client that has stored at least one heartbeat
/// and then stopped for [`CLIENT_STALE_AFTER`] is torn down even
/// though its socket is still open. Clients that never heartbeat opt
/// out and rely on socket EOF alone.
fn client_is_stale(control: &ControlPage) -> bool {
    let client_heartbeat = control.load_heartbeat(Side::Client);
    if client_heartbeat == 0 {
        return false;
    }
    let stale_micros = u64::try_from(CLIENT_STALE_AFTER.as_micros()).unwrap_or(u64::MAX);
    now_micros().saturating_sub(client_heartbeat) > stale_micros
}

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
        })
}
