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

//! Lock-free shared-memory log primitives for a local client transport.
//!
//! A connection maps one segment holding a control page and two
//! independent one-way logs (client to server, server to client). Each
//! log is [`layout::REGION_COUNT`] fixed-size regions plus a counters
//! block, addressed by a monotonic `u64` stream position.
//!
//! Per log there is exactly one producer and exactly one consumer,
//! typically in different processes. The types enforce the single-party
//! rule by ownership: [`LogProducer`] and [`LogConsumer`] take `&mut
//! self` and are `Send` but not cloneable.
//!
//! Protocol invariants:
//!
//! - A record is `[total_len: u32][record_type: u8][flags: u8][reserved:
//!   10][payload]`, claims rounded up to [`layout::RECORD_ALIGNMENT`].
//!   `total_len` is release-stored last and doubles as the commit flag;
//!   `0` means not yet committed, which is why regions must start (and
//!   be returned to) all-zero.
//! - A record never spans regions. The producer closes a region with a
//!   padding record and rotates; the consumer skips padding, zeroes each
//!   region it leaves, and publishes the count of cleaned cycles. The
//!   producer refuses to rotate into a region whose previous cycle has
//!   not been cleaned, which bounds it to under [`layout::REGION_COUNT`]
//!   regions ahead of the consumer and is the transport's backpressure.
//! - Park/wake handshakes use a flag-store then fence then recheck on
//!   the sleeping side, and a commit then fence then flag-load on the
//!   waking side, so a wake can never be lost between poll and park.

mod sync;
#[cfg(all(test, not(loom)))]
mod test_support;

pub mod layout;
pub mod record;

pub mod consumer;
pub mod idle;
pub mod mem;
pub mod producer;

#[cfg(not(loom))]
pub mod control;
#[cfg(all(unix, not(loom)))]
pub mod segment;

pub use consumer::{LogConsumer, PollError, RecordView};
#[cfg(not(loom))]
pub use control::{ControlError, ControlPage, Side};
pub use idle::{IdleAdvice, IdleState, IdleStrategy};
pub use layout::{LayoutError, LogGeometry, SegmentLayout};
pub use mem::LogMemory;
#[cfg(not(loom))]
pub use mem::RawLogMemory;
pub use producer::{AppendError, LogProducer};
#[cfg(all(unix, not(loom)))]
pub use segment::{AnonymousSegment, SegmentMapping};
