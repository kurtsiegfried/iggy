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
//!
//! # Liveness contract
//!
//! A connected client must show progress within the tuned deadline:
//! frames in either direction or a change of its control-page
//! heartbeat word all count. A connection past the deadline with none
//! of them is torn down even though its socket is open, because an
//! idle-forever client would otherwise pin its segment and admission
//! slot; genuinely idle clients keep the heartbeat word moving. The
//! doorbell write is timeout-bounded (its trigger is client-writable
//! memory), and doorbell wakes that keep producing no work are paced
//! so a control-socket byte flood buys wall clock, not shard-0 CPU.

use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::ptr::NonNull;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use compio::BufResult;
use compio::buf::IoBuf;
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

pub use shm::handshake::{
    HELLO_LEN, WELCOME_INTERNAL, WELCOME_LEN, WELCOME_OK, WELCOME_UNSUPPORTED,
};

const DEFAULT_HANDSHAKE_GRACE: Duration = Duration::from_secs(10);

/// Bound on a single doorbell write. The park-flag condition that
/// triggers the write lives in client-writable memory, so a client
/// that raises a flag and stops reading its socket could otherwise
/// suspend the pump on this await forever once the send buffer fills.
/// A stuck doorbell is a dead or hostile peer either way: teardown.
const DOORBELL_WRITE_GRACE: Duration = Duration::from_secs(1);

/// Consecutive doorbell wakes that produced no work before the pump
/// starts pacing itself. A byte flood on the control socket otherwise
/// converts directly into empty drain cycles on the shared shard-0
/// executor; past this budget each further empty wake costs the
/// flooder [`FLOOD_BACKOFF`] of wall clock instead.
const EMPTY_WAKE_BUDGET: u32 = 8;
const FLOOD_BACKOFF: Duration = Duration::from_millis(1);

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

        run_pump(stream, session, self.tuning, ctx).await;
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
    let welcome = shm::handshake::Welcome {
        status,
        region_capacity: tuning.region_capacity as u64,
        max_message_size: tuning.max_message_size as u64,
        client_id,
    }
    .encode()
    .to_vec();

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
fn scm_rights_control(fd: RawFd) -> AlignedControl {
    #[allow(clippy::cast_possible_truncation)]
    let space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut control = AlignedControl {
        bytes: [0u8; ALIGNED_CONTROL_CAPACITY],
        len: space,
    };
    assert!(space <= ALIGNED_CONTROL_CAPACITY);
    let header = control.bytes.as_mut_ptr().cast::<libc::cmsghdr>();
    // Safety: the buffer is 8-aligned by its repr, at least CMSG_SPACE
    // bytes, zeroed, and exclusively ours; CMSG_DATA points inside it
    // by construction.
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

/// Covers `CMSG_SPACE` for one fd on every unix target.
const ALIGNED_CONTROL_CAPACITY: usize = 32;

/// `SCM_RIGHTS` control buffer with the `cmsghdr` alignment the
/// kernel and compio assume; a `Vec<u8>` promises only align 1 and
/// would panic compio's alignment check under an allocator that
/// honors it.
#[repr(C, align(8))]
struct AlignedControl {
    bytes: [u8; ALIGNED_CONTROL_CAPACITY],
    /// Exact `CMSG_SPACE`; the initialized view must not include the
    /// tail padding, or the kernel would parse a zero-length second
    /// cmsg and reject the send.
    len: usize,
}

impl IoBuf for AlignedControl {
    fn as_init(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
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
    tuning: ShmTuning,
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
    let max_message_size = tuning.max_message_size;
    let mut scratch: Vec<u8> = Vec::new();
    let mut pending_outbound: Option<crate::lifecycle::BusMessage> = None;
    let mut doorbell_buffer: Option<Vec<u8>> = None;
    let mut read_buffer: Option<Vec<u8>> = None;
    // Client liveness is progress-based and monotonic: frames in
    // either direction and heartbeat-word changes all count, and a
    // connection past the deadline with none of them is torn down.
    // This deliberately includes clients that never heartbeat; an
    // idle-forever connection would otherwise pin its segment and
    // admission slot with no in-band recovery.
    let mut last_progress = Instant::now();
    let mut last_client_heartbeat: u64 = 0;
    let mut empty_doorbell_wakes: u32 = 0;

    loop {
        let mut made_progress = false;

        // Inbound: drain committed client frames toward dispatch.
        loop {
            let payload_len = match session.consumer.try_poll() {
                Ok(Some(record)) => {
                    let payload_len = record.payload_len();
                    // Ceiling before any copy: the record length is
                    // attacker-controlled up to a whole region, and a
                    // large region would otherwise buy a huge
                    // zero-fill + memcpy on the shared executor before
                    // the decoder rejected it.
                    if payload_len > max_message_size {
                        warn!(
                            %label, %peer, payload_len, max_message_size,
                            "shm frame exceeds the frame ceiling; closing connection"
                        );
                        return;
                    }
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
                    made_progress = true;
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
                Ok(_position) => {
                    made_progress = true;
                }
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

        if made_progress {
            last_progress = Instant::now();
            empty_doorbell_wakes = 0;
        }

        // Doorbell: one byte wakes the client whichever side it
        // parked. The write is bounded because its trigger condition
        // is client-writable: a peer that raises a flag and stops
        // reading must not suspend the pump on a full send buffer.
        if session.producer.consumer_parked() || session.consumer.producer_parked() {
            let buffer = doorbell_buffer.take().unwrap_or_else(|| vec![1u8]);
            match compio::time::timeout(DOORBELL_WRITE_GRACE, stream.write(buffer)).await {
                Ok(BufResult(Ok(_written), returned)) => {
                    doorbell_buffer = Some(returned);
                }
                Ok(BufResult(Err(error), _buffer)) => {
                    debug!(%label, %peer, "shm doorbell write failed: {error}");
                    return;
                }
                Err(_elapsed) => {
                    warn!(
                        %label, %peer,
                        "shm doorbell write stuck; peer is not reading its socket"
                    );
                    return;
                }
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
                read = stream.read(take_read_buffer(&mut read_buffer)).fuse() => {
                    let (wake, returned) = socket_wake(read);
                    read_buffer = returned;
                    wake
                }
                () = compio::time::sleep(tuning.heartbeat_tick).fuse() => PumpWake::HeartbeatTick,
            }
        } else {
            // The outbound log is full: taking more bus frames would
            // need a second stash slot, so the mailbox arm sits out
            // until the client cleans a region.
            futures::select_biased! {
                () = shutdown.wait().fuse() => PumpWake::Shutdown,
                read = stream.read(take_read_buffer(&mut read_buffer)).fuse() => {
                    let (wake, returned) = socket_wake(read);
                    read_buffer = returned;
                    wake
                }
                () = compio::time::sleep(tuning.heartbeat_tick).fuse() => PumpWake::HeartbeatTick,
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
            PumpWake::Doorbell => {
                // A doorbell that keeps producing no work is a byte
                // flood on the control socket; pace the pump so the
                // flooder pays wall clock instead of shard-0 CPU. The
                // counter resets on any real progress above.
                empty_doorbell_wakes = empty_doorbell_wakes.saturating_add(1);
                if empty_doorbell_wakes > EMPTY_WAKE_BUDGET {
                    compio::time::sleep(FLOOD_BACKOFF).await;
                }
            }
            PumpWake::HeartbeatTick => {
                let client_heartbeat = session.control.load_heartbeat(Side::Client);
                if client_heartbeat != last_client_heartbeat {
                    last_client_heartbeat = client_heartbeat;
                    last_progress = Instant::now();
                }
                if last_progress.elapsed() > tuning.client_stale_after {
                    warn!(
                        %label, %peer,
                        "shm client showed no progress within the deadline; closing connection"
                    );
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

/// Reuse the parked-read buffer when the previous read completed; a
/// cancelled read's buffer stays with the in-flight op until the
/// kernel finishes, so a fresh allocation covers that case. On the
/// flood path the read always completes, which is exactly when reuse
/// matters. Sized to drain floods in fewer wakes than a 1-byte read
/// would.
fn take_read_buffer(slot: &mut Option<Vec<u8>>) -> Vec<u8> {
    slot.take().map_or_else(
        || Vec::with_capacity(4096),
        |mut buffer| {
            buffer.clear();
            buffer
        },
    )
}

fn socket_wake(read: BufResult<usize, Vec<u8>>) -> (PumpWake, Option<Vec<u8>>) {
    let BufResult(read_result, buffer) = read;
    match read_result {
        Ok(0) => (PumpWake::PeerClosed, Some(buffer)),
        Ok(_doorbell_bytes) => (PumpWake::Doorbell, Some(buffer)),
        Err(error) => (PumpWake::SocketError(error), Some(buffer)),
    }
}

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
        })
}
