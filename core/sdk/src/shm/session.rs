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

//! Dedicated I/O thread behind one shared-memory connection.
//!
//! The log views hold raw pointers into the mapped segment, so they
//! stay on the thread that created them instead of being threaded
//! through the work-stealing runtime; parking on the doorbell socket is
//! a plain blocking read there. The async client submits one encoded
//! request frame at a time over a channel, which also serializes
//! request-id assignment order with log order, and receives each reply
//! on a oneshot. A caller that gives up simply drops its oneshot: the
//! exchange still runs to completion here, so the lockstep logs never
//! desync on cancellation.
//!
//! Between exchanges the thread wakes on a fixed tick to advance the
//! client heartbeat word; the server treats a moving heartbeat as
//! progress and reaps connections that show none for too long.

use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use iggy_binary_protocol::HEADER_SIZE;
use iggy_common::IggyError;
use shm::consumer::LogConsumer;
use shm::control::{ControlPage, Side};
use shm::handshake::{WELCOME_LEN, WELCOME_OK, Welcome, encode_hello};
use shm::layout::{LogGeometry, SegmentLayout};
use shm::mem::RawLogMemory;
use shm::producer::{AppendError, LogProducer};
use shm::segment::{AnonymousSegment, SegmentMapping};
use tokio::sync::oneshot;
use tracing::{debug, warn};

use crate::vsr;

/// Cadence of heartbeat-word stores while the thread has nothing else
/// to do, and the slice length of every blocking doorbell wait. Matches
/// the server pump's own housekeeping tick.
const HEARTBEAT_TICK: Duration = Duration::from_secs(1);

/// Backoff before replaying a request the server answered with an
/// explicit transient frame, mirroring the network transports.
const NOT_READY_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// How long a request replays `TransientNotAccepted` before the error
/// surfaces to the caller. A replica that is not the target group's
/// primary refuses forever, so replaying against that verdict for the
/// whole request budget would only hide it; the network transports use
/// the same window before their leader recheck. There is no other node
/// to walk to over a local socket, so past it the caller owns the
/// retry policy.
const NOT_ACCEPTED_SURFACE_INTERVAL: Duration = Duration::from_secs(2);

/// Bound on the blocking handshake reads while connecting; the server
/// enforces the same grace on its side of the handshake.
const HANDSHAKE_GRACE: Duration = Duration::from_secs(10);

/// One lockstep request submitted by the async client.
pub(crate) struct ExchangeRequest {
    /// A fully encoded consensus frame, appended to the log verbatim.
    pub frame: Bytes,
    /// Whether `TransientNotAccepted` replays for the full response
    /// budget instead of surfacing after
    /// [`NOT_ACCEPTED_SURFACE_INTERVAL`]. Login/register sets this,
    /// mirroring the network transports: during an election the whole
    /// cluster answers not-accepted, and failing the sign-in after 2s
    /// would fail every reconnect that lands inside the election
    /// window.
    pub full_not_accepted_budget: bool,
    pub reply: oneshot::Sender<Result<Bytes, IggyError>>,
}

/// Async-side handle to the I/O thread. Dropping it shuts the doorbell
/// socket down and closes the command channel, which makes the thread
/// exit its current wait and unwind; the server observes the socket EOF
/// and tears the connection down.
#[derive(Debug)]
pub(crate) struct ShmSessionHandle {
    commands: Sender<ExchangeRequest>,
    stream: UnixStream,
}

impl ShmSessionHandle {
    /// Queue one exchange. Returns false when the I/O thread is gone.
    pub(crate) fn submit(&self, request: ExchangeRequest) -> bool {
        self.commands.send(request).is_ok()
    }
}

impl Drop for ShmSessionHandle {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// Dial the socket, run the handshake, and start the serve loop on a
/// dedicated thread. The returned receiver yields the handle once the
/// connection is live, or the handshake error.
pub(crate) fn spawn(
    socket_path: PathBuf,
    response_read_timeout: Duration,
) -> oneshot::Receiver<Result<ShmSessionHandle, IggyError>> {
    let (ready_tx, ready_rx) = oneshot::channel();
    let (command_tx, command_rx) = channel();
    let spawned = std::thread::Builder::new()
        .name("iggy-shm-client".to_string())
        .spawn(move || match connect(&socket_path) {
            Ok(session) => match session.stream.try_clone() {
                Ok(stream) => {
                    let handle = ShmSessionHandle {
                        commands: command_tx,
                        stream,
                    };
                    if ready_tx.send(Ok(handle)).is_err() {
                        return;
                    }
                    serve(session, &command_rx, response_read_timeout);
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(map_io_error(&error)));
                }
            },
            Err(error) => {
                let _ = ready_tx.send(Err(error));
            }
        });
    if let Err(error) = spawned {
        // The ready sender was captured by the never-run closure and
        // drops with it, so the receiver observes the failure as a
        // closed channel.
        warn!("Failed to spawn the shm client I/O thread: {error}");
    }
    ready_rx
}

/// Client-side state over one mapped segment. Field order keeps the log
/// views and control page ahead of the mapping they point into, and the
/// mapping ahead of the segment fd.
struct Session {
    stream: UnixStream,
    producer: LogProducer<RawLogMemory>,
    consumer: LogConsumer<RawLogMemory>,
    control: ControlPage,
    max_message_size: usize,
    _mapping: SegmentMapping,
    _segment: AnonymousSegment,
}

/// How one exchange failed: `Reply` errors surface to the caller with
/// the session intact, `Fatal` errors also end the session because the
/// logs can no longer be trusted to be in lockstep.
enum ExchangeError {
    Reply(IggyError),
    Fatal(IggyError),
}

fn connect(socket_path: &Path) -> Result<Session, IggyError> {
    let mut stream = UnixStream::connect(socket_path).map_err(|error| {
        debug!(
            "Cannot connect to the shm socket {}: {error}",
            socket_path.display()
        );
        IggyError::CannotEstablishConnection
    })?;
    stream
        .set_read_timeout(Some(HANDSHAKE_GRACE))
        .map_err(|_| IggyError::CannotEstablishConnection)?;

    stream
        .write_all(&encode_hello())
        .map_err(|_| IggyError::CannotEstablishConnection)?;

    let (welcome_bytes, segment_fd) = recv_welcome_with_fd(&stream)?;
    let welcome = Welcome::parse(&welcome_bytes).map_err(|error| {
        warn!("The shm server answered with an unrecognized welcome: {error}");
        IggyError::CannotEstablishConnection
    })?;
    if welcome.status != WELCOME_OK {
        warn!(
            "The shm server refused the connection with status {}",
            welcome.status
        );
        return Err(IggyError::CannotEstablishConnection);
    }
    let segment_fd = segment_fd.ok_or_else(|| {
        warn!("The shm welcome carried no segment fd");
        IggyError::CannotEstablishConnection
    })?;

    let geometry = LogGeometry {
        region_capacity: usize::try_from(welcome.region_capacity)
            .map_err(|_| IggyError::CannotEstablishConnection)?,
    };
    let layout = SegmentLayout::compute(geometry, geometry).map_err(|error| {
        warn!("The advertised shm geometry does not compute: {error}");
        IggyError::CannotEstablishConnection
    })?;
    let segment = AnonymousSegment::from_received_fd(segment_fd, layout.total_len)
        .map_err(|_| IggyError::CannotEstablishConnection)?;
    let mapping =
        SegmentMapping::map(&segment).map_err(|_| IggyError::CannotEstablishConnection)?;

    // Safety: the control page heads a mapping owned by the same
    // `Session`, and no other Rust references to those bytes exist on
    // the client side.
    let control = unsafe { ControlPage::new(mapping.as_ptr()) };
    control.validate().map_err(|error| {
        warn!("The received shm segment failed validation: {error}");
        IggyError::CannotEstablishConnection
    })?;
    control.record_attach(Side::Client, u64::from(std::process::id()), now_micros());
    control.store_heartbeat(Side::Client, now_micros());

    // Safety: the mapping outlives the views (same struct), and this
    // process is the only client party: one producer on the
    // client-to-server log, one consumer on the reverse log.
    let (producer_memory, consumer_memory) = unsafe {
        (
            mapping.client_to_server_memory(&layout),
            mapping.server_to_client_memory(&layout),
        )
    };

    // The serve loop paces its own waits; leaving the handshake timeout
    // armed would be harmless but misleading.
    let _ = stream.set_read_timeout(None);

    Ok(Session {
        stream,
        producer: LogProducer::new(producer_memory, geometry),
        consumer: LogConsumer::new(consumer_memory, geometry),
        control,
        max_message_size: usize::try_from(welcome.max_message_size)
            .map_err(|_| IggyError::CannotEstablishConnection)?,
        _mapping: mapping,
        _segment: segment,
    })
}

fn serve(mut session: Session, commands: &Receiver<ExchangeRequest>, response_timeout: Duration) {
    loop {
        match commands.recv_timeout(HEARTBEAT_TICK) {
            Ok(exchange) => match run_exchange(
                &mut session,
                &exchange.frame,
                response_timeout,
                exchange.full_not_accepted_budget,
            ) {
                Ok(reply) => {
                    let _ = exchange.reply.send(Ok(reply));
                }
                Err(ExchangeError::Reply(error)) => {
                    let _ = exchange.reply.send(Err(error));
                }
                Err(ExchangeError::Fatal(error)) => {
                    let _ = exchange.reply.send(Err(error));
                    return;
                }
            },
            Err(RecvTimeoutError::Timeout) => {
                session.control.store_heartbeat(Side::Client, now_micros());
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn run_exchange(
    session: &mut Session,
    frame: &Bytes,
    response_timeout: Duration,
    full_not_accepted_budget: bool,
) -> Result<Bytes, ExchangeError> {
    if frame.len() > session.max_message_size {
        return Err(ExchangeError::Reply(IggyError::TooBigMessagePayload));
    }
    // One deadline bounds the whole exchange including transient
    // replays, mirroring the network transports. Replays reuse the same
    // encoded frame so the request id stays stable for server dedup.
    let deadline = Instant::now() + response_timeout;
    let not_accepted_deadline = if full_not_accepted_budget {
        deadline
    } else {
        Instant::now() + NOT_ACCEPTED_SURFACE_INTERVAL
    };
    loop {
        append_frame(session, frame, deadline)?;
        ring_if_parked(session)?;

        let reply = read_reply(session, deadline)?;
        let header_bytes: &[u8; HEADER_SIZE] = reply[..HEADER_SIZE]
            .try_into()
            .expect("read_reply guarantees at least a header");
        let header = *header_bytes;
        let mut whole = Bytes::from(reply);
        let body = whole.split_off(HEADER_SIZE);

        match vsr::decode_response_split(&header, body) {
            Err(IggyError::TransientNotAccepted) if Instant::now() >= not_accepted_deadline => {
                return Err(ExchangeError::Reply(IggyError::TransientNotAccepted));
            }
            Err(IggyError::TransientNotCommitted | IggyError::TransientNotAccepted)
                if Instant::now() < deadline =>
            {
                session.control.store_heartbeat(Side::Client, now_micros());
                let remaining = deadline.saturating_duration_since(Instant::now());
                std::thread::sleep(NOT_READY_RETRY_INTERVAL.min(remaining));
            }
            Ok(body) => return Ok(body),
            Err(error) => return Err(ExchangeError::Reply(error)),
        }
    }
}

fn append_frame(
    session: &mut Session,
    frame: &Bytes,
    deadline: Instant,
) -> Result<(), ExchangeError> {
    loop {
        match session.producer.try_append(frame) {
            Ok(_position) => return Ok(()),
            Err(AppendError::WouldBlock) => {
                // The outbound log is full until the server consumes and
                // cleans a region. Wake it in case it parked, then park
                // this side and wait for its doorbell.
                ring_if_parked(session)?;
                session.producer.prepare_park();
                match session.producer.try_append(frame) {
                    Ok(_position) => {
                        session.producer.cancel_park();
                        return Ok(());
                    }
                    Err(AppendError::WouldBlock) => {
                        let waited = wait_for_doorbell(session, deadline);
                        session.producer.cancel_park();
                        waited?;
                    }
                    Err(error @ AppendError::PayloadTooLarge { .. }) => {
                        session.producer.cancel_park();
                        debug!("shm append rejected: {error}");
                        return Err(ExchangeError::Reply(IggyError::TooBigMessagePayload));
                    }
                }
            }
            Err(error @ AppendError::PayloadTooLarge { .. }) => {
                debug!("shm append rejected: {error}");
                return Err(ExchangeError::Reply(IggyError::TooBigMessagePayload));
            }
        }
    }
}

/// The next committed frame IS the reply: correlation is by order
/// alone, with no request-id match. This leans on the server pump's
/// contract of exactly one reply frame per request, in order, with no
/// unsolicited frames on this log; a server that ever pushes an
/// asynchronous frame here would silently shift every later reply by
/// one. Revisit with a request-id echo if that contract ever loosens.
fn read_reply(session: &mut Session, deadline: Instant) -> Result<Vec<u8>, ExchangeError> {
    loop {
        if let Some(reply) = spin_for_reply(session)? {
            return Ok(reply);
        }
        session.consumer.prepare_park();
        match poll_one(session) {
            Ok(Some(reply)) => {
                session.consumer.cancel_park();
                return Ok(reply);
            }
            Ok(None) => {
                let waited = wait_for_doorbell(session, deadline);
                session.consumer.cancel_park();
                waited?;
            }
            Err(error) => {
                session.consumer.cancel_park();
                return Err(error);
            }
        }
    }
}

/// How long the I/O thread polls the reply log before declaring itself
/// parked. While it spins, the parked flag stays clear, so a server
/// that commits inside the window skips its doorbell write and this
/// side skips its blocking read: the whole exchange completes without
/// either wake syscall. The thread is dedicated to this connection and
/// only spins while an exchange is in flight, so the budget costs one
/// core for at most this long per reply.
const REPLY_SPIN_BUDGET: Duration = Duration::from_micros(60);
/// Polls between deadline checks; `Instant::now` costs more than the
/// poll itself, so it is amortized across a small batch.
const SPINS_PER_CLOCK_CHECK: u32 = 64;

fn spin_for_reply(session: &mut Session) -> Result<Option<Vec<u8>>, ExchangeError> {
    let spin_deadline = Instant::now() + REPLY_SPIN_BUDGET;
    loop {
        for _ in 0..SPINS_PER_CLOCK_CHECK {
            if let Some(reply) = poll_one(session)? {
                return Ok(Some(reply));
            }
            std::hint::spin_loop();
        }
        if Instant::now() >= spin_deadline {
            return Ok(None);
        }
    }
}

/// One committed record from the server-to-client log, or None when the
/// log is drained. Rings the server back when it parked its producer on
/// this side's cleaning.
fn poll_one(session: &mut Session) -> Result<Option<Vec<u8>>, ExchangeError> {
    match session.consumer.try_poll() {
        Ok(Some(record)) => {
            let payload_len = record.payload_len();
            let mut reply = vec![0u8; payload_len];
            record.copy_payload_into(&mut reply);
            record.release();
            if session.consumer.producer_parked() {
                ring(session)?;
            }
            if payload_len < HEADER_SIZE {
                // The server writes whole consensus frames; a runt means
                // the framing can no longer be trusted.
                warn!("shm reply shorter than a consensus header: {payload_len} bytes");
                return Err(ExchangeError::Fatal(IggyError::Disconnected));
            }
            Ok(Some(reply))
        }
        Ok(None) => Ok(None),
        Err(poll_error) => {
            warn!("shm log poisoned: {poll_error}");
            Err(ExchangeError::Fatal(IggyError::Disconnected))
        }
    }
}

fn ring_if_parked(session: &mut Session) -> Result<(), ExchangeError> {
    if session.producer.consumer_parked() {
        ring(session)?;
    }
    Ok(())
}

fn ring(session: &mut Session) -> Result<(), ExchangeError> {
    match session.stream.write_all(&[1u8]) {
        Ok(()) => Ok(()),
        Err(error) => {
            debug!("shm doorbell write failed: {error}");
            Err(ExchangeError::Fatal(IggyError::Disconnected))
        }
    }
}

/// Block on the doorbell socket in heartbeat-sized slices until a byte
/// arrives or the exchange deadline passes. EOF means the server tore
/// the connection down; a passed deadline is fatal too, because a reply
/// arriving after the caller gave up would desync the next exchange.
fn wait_for_doorbell(session: &mut Session, deadline: Instant) -> Result<(), ExchangeError> {
    let mut doorbell = [0u8; 8];
    loop {
        session.control.store_heartbeat(Side::Client, now_micros());
        let now = Instant::now();
        if now >= deadline {
            warn!("shm exchange timed out waiting for the server");
            return Err(ExchangeError::Fatal(IggyError::Disconnected));
        }
        let slice = HEARTBEAT_TICK.min(deadline - now);
        if session.stream.set_read_timeout(Some(slice)).is_err() {
            return Err(ExchangeError::Fatal(IggyError::Disconnected));
        }
        match session.stream.read(&mut doorbell) {
            Ok(0) => {
                debug!("shm server closed the control socket");
                return Err(ExchangeError::Fatal(IggyError::Disconnected));
            }
            Ok(_doorbell_bytes) => return Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(error) => {
                debug!("shm control socket error: {error}");
                return Err(ExchangeError::Fatal(IggyError::Disconnected));
            }
        }
    }
}

/// Blocking `recvmsg` for the fixed-size welcome plus its ancillary
/// segment fd.
fn recv_welcome_with_fd(
    stream: &UnixStream,
) -> Result<([u8; WELCOME_LEN], Option<OwnedFd>), IggyError> {
    // The kernel writes cmsghdr structures into this buffer and the
    // parse below forms references to them, so it must carry cmsghdr
    // alignment; a bare byte array only aligns to 1. Same reasoning as
    // the server's aligned SCM_RIGHTS send buffer.
    #[repr(C, align(8))]
    struct AlignedCmsgBuffer([u8; 64]);

    // Linux can suppress fd inheritance atomically at receive time;
    // elsewhere `from_received_fd` sets FD_CLOEXEC right after, with
    // the unavoidable fork+exec window in between.
    #[cfg(target_os = "linux")]
    const RECV_FLAGS: libc::c_int = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    const RECV_FLAGS: libc::c_int = 0;

    let mut payload = [0u8; WELCOME_LEN];
    let mut control = AlignedCmsgBuffer([0u8; 64]);
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast::<libc::c_void>();
    #[allow(clippy::cast_possible_truncation)]
    // socklen_t is u32 on some unix targets; 64 always fits.
    {
        message.msg_controllen = control.0.len() as _;
    }

    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut message, RECV_FLAGS) };
    if received < 0 {
        debug!(
            "recvmsg on the shm welcome failed: {}",
            std::io::Error::last_os_error()
        );
        return Err(IggyError::CannotEstablishConnection);
    }
    if received as usize != WELCOME_LEN {
        debug!("short shm welcome: {received} of {WELCOME_LEN} bytes");
        return Err(IggyError::CannotEstablishConnection);
    }

    let header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    let fd = if header.is_null() {
        None
    } else {
        // Safety: CMSG_FIRSTHDR returned a non-null header at the start
        // of the control buffer the kernel just filled, and the buffer
        // carries cmsghdr alignment.
        let header_ref = unsafe { &*header };
        if header_ref.cmsg_level != libc::SOL_SOCKET || header_ref.cmsg_type != libc::SCM_RIGHTS {
            return Err(IggyError::CannotEstablishConnection);
        }
        let raw_fd =
            unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>()) };
        // Safety: the kernel installed a fresh fd for this process.
        Some(unsafe { OwnedFd::from_raw_fd(raw_fd) })
    };
    Ok((payload, fd))
}

fn map_io_error(error: &std::io::Error) -> IggyError {
    debug!("shm session setup failed: {error}");
    IggyError::CannotEstablishConnection
}

fn now_micros() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(u64::MAX)
}
