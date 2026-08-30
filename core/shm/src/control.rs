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

//! The segment's control page: layout identification, geometry echo,
//! and per-side liveness words.
//!
//! Initialization publishes the magic word last, with release
//! ordering, so a peer that observes the magic is guaranteed to see
//! the version and geometry it gates. The pid, start, and heartbeat
//! words are raw material for the transport layer: storing and
//! loading them is this crate's job, while the staleness policy that
//! turns them into wedged-peer detection (and the teardown decision)
//! belongs to the caller.

use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use thiserror::Error;

use crate::layout::{LAYOUT_VERSION, LayoutError, LogGeometry, SEGMENT_MAGIC, SegmentLayout};

pub const MAGIC_OFFSET: usize = 0;
pub const LAYOUT_VERSION_OFFSET: usize = 8;
pub const CLIENT_TO_SERVER_REGION_CAPACITY_OFFSET: usize = 16;
pub const SERVER_TO_CLIENT_REGION_CAPACITY_OFFSET: usize = 24;
pub const SERVER_PID_OFFSET: usize = 64;
pub const SERVER_START_MICROS_OFFSET: usize = 72;
pub const SERVER_HEARTBEAT_MICROS_OFFSET: usize = 128;
pub const CLIENT_PID_OFFSET: usize = 192;
pub const CLIENT_START_MICROS_OFFSET: usize = 200;
pub const CLIENT_HEARTBEAT_MICROS_OFFSET: usize = 256;
pub const CONTROL_PAGE_MIN_LEN: usize = 320;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Server,
    Client,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlError {
    #[error("segment magic {found:#018x} does not match {SEGMENT_MAGIC:#018x}")]
    BadMagic { found: u64 },
    #[error("layout version {found} is not supported (this build speaks {LAYOUT_VERSION})")]
    UnsupportedLayoutVersion { found: u32 },
    #[error("control page advertises an invalid geometry: {source}")]
    InvalidGeometry { source: LayoutError },
}

/// View over the control page of a mapped segment.
#[derive(Debug)]
pub struct ControlPage {
    base: NonNull<u8>,
}

// The pointer targets a shared mapping that outlives the value per the
// constructor contract, so moving it across threads is sound.
unsafe impl Send for ControlPage {}

impl ControlPage {
    /// # Safety
    ///
    /// `base` must point at a control page of at least
    /// [`CONTROL_PAGE_MIN_LEN`] bytes, 8-byte aligned, valid for reads
    /// and writes for the lifetime of the returned value, with no Rust
    /// references to those bytes existing elsewhere.
    #[must_use]
    pub const unsafe fn new(base: NonNull<u8>) -> Self {
        Self { base }
    }

    /// Server-side initialization of a fresh (all-zero) control page.
    /// The magic is published last so a validating peer can never
    /// observe it ahead of the fields it vouches for.
    pub fn initialize(&self, layout: &SegmentLayout) {
        self.word(CLIENT_TO_SERVER_REGION_CAPACITY_OFFSET).store(
            layout.client_to_server.region_capacity as u64,
            Ordering::Relaxed,
        );
        self.word(SERVER_TO_CLIENT_REGION_CAPACITY_OFFSET).store(
            layout.server_to_client.region_capacity as u64,
            Ordering::Relaxed,
        );
        self.version_word().store(LAYOUT_VERSION, Ordering::Relaxed);
        self.word(MAGIC_OFFSET)
            .store(SEGMENT_MAGIC, Ordering::Release);
    }

    /// Client-side validation; returns the geometries the server
    /// published. The page is peer-written, so the geometries are
    /// re-validated here rather than trusted; a value that survives
    /// this call is safe to hand to the log constructors.
    ///
    /// # Errors
    ///
    /// [`ControlError::BadMagic`] when the magic word is absent or
    /// wrong, [`ControlError::UnsupportedLayoutVersion`] on a version
    /// this build does not speak, [`ControlError::InvalidGeometry`]
    /// when an advertised capacity fails [`LogGeometry::validate`].
    pub fn validate(&self) -> Result<(LogGeometry, LogGeometry), ControlError> {
        let found = self.word(MAGIC_OFFSET).load(Ordering::Acquire);
        if found != SEGMENT_MAGIC {
            return Err(ControlError::BadMagic { found });
        }
        let version = self.version_word().load(Ordering::Relaxed);
        if version != LAYOUT_VERSION {
            return Err(ControlError::UnsupportedLayoutVersion { found: version });
        }
        let client_to_server = self.advertised_geometry(CLIENT_TO_SERVER_REGION_CAPACITY_OFFSET)?;
        let server_to_client = self.advertised_geometry(SERVER_TO_CLIENT_REGION_CAPACITY_OFFSET)?;
        Ok((client_to_server, server_to_client))
    }

    fn advertised_geometry(&self, offset: usize) -> Result<LogGeometry, ControlError> {
        let advertised = self.word(offset).load(Ordering::Relaxed);
        let region_capacity =
            usize::try_from(advertised).map_err(|_| ControlError::InvalidGeometry {
                source: LayoutError::RegionCapacityTooLarge {
                    region_capacity: usize::MAX,
                },
            })?;
        let geometry = LogGeometry { region_capacity };
        geometry
            .validate()
            .map_err(|source| ControlError::InvalidGeometry { source })?;
        Ok(geometry)
    }

    /// Records this side's identity once, right after it maps the
    /// segment.
    pub fn record_attach(&self, side: Side, pid: u64, start_micros: u64) {
        let (pid_offset, start_offset) = match side {
            Side::Server => (SERVER_PID_OFFSET, SERVER_START_MICROS_OFFSET),
            Side::Client => (CLIENT_PID_OFFSET, CLIENT_START_MICROS_OFFSET),
        };
        self.word(pid_offset).store(pid, Ordering::Relaxed);
        self.word(start_offset)
            .store(start_micros, Ordering::Release);
    }

    pub fn store_heartbeat(&self, side: Side, now_micros: u64) {
        self.word(heartbeat_offset(side))
            .store(now_micros, Ordering::Release);
    }

    #[must_use]
    pub fn load_heartbeat(&self, side: Side) -> u64 {
        self.word(heartbeat_offset(side)).load(Ordering::Acquire)
    }

    #[allow(clippy::cast_ptr_alignment)]
    // Alignment is asserted; the constructor requires an 8-aligned base.
    fn word(&self, offset: usize) -> &AtomicU64 {
        debug_assert!(offset.is_multiple_of(8) && offset + 8 <= CONTROL_PAGE_MIN_LEN);
        // Safety: in-bounds and 8-aligned per the constructor contract
        // and the assert; atomics allow shared mutation.
        unsafe { &*self.base.as_ptr().add(offset).cast::<AtomicU64>() }
    }

    #[allow(clippy::cast_ptr_alignment)]
    // LAYOUT_VERSION_OFFSET is 8; the constructor requires an 8-aligned base.
    fn version_word(&self) -> &AtomicU32 {
        // Safety: LAYOUT_VERSION_OFFSET is in-bounds and 4-aligned per
        // the constructor contract.
        unsafe {
            &*self
                .base
                .as_ptr()
                .add(LAYOUT_VERSION_OFFSET)
                .cast::<AtomicU32>()
        }
    }
}

const fn heartbeat_offset(side: Side) -> usize {
    match side {
        Side::Server => SERVER_HEARTBEAT_MICROS_OFFSET,
        Side::Client => CLIENT_HEARTBEAT_MICROS_OFFSET,
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::{Layout, alloc_zeroed, dealloc};

    use super::*;
    use crate::layout::MIN_REGION_CAPACITY;

    struct Page {
        base: NonNull<u8>,
        layout: Layout,
    }

    impl Page {
        fn new() -> Self {
            let layout = Layout::from_size_align(CONTROL_PAGE_MIN_LEN, 8).unwrap();
            // Safety: layout has a non-zero size.
            let base = unsafe { alloc_zeroed(layout) };
            Self {
                base: NonNull::new(base).unwrap(),
                layout,
            }
        }
    }

    impl Drop for Page {
        fn drop(&mut self) {
            // Safety: allocated with exactly this layout in `new`.
            unsafe { dealloc(self.base.as_ptr(), self.layout) };
        }
    }

    fn segment_layout() -> SegmentLayout {
        let geometry = LogGeometry {
            region_capacity: MIN_REGION_CAPACITY,
        };
        SegmentLayout::compute(geometry, geometry).unwrap()
    }

    #[test]
    fn validate_rejects_an_uninitialized_page() {
        let page = Page::new();
        // Safety: fresh zeroed allocation, no other references exist.
        let control = unsafe { ControlPage::new(page.base) };
        assert_eq!(control.validate(), Err(ControlError::BadMagic { found: 0 }));
    }

    #[test]
    fn initialize_then_validate_round_trips_geometry() {
        let page = Page::new();
        // Safety: fresh zeroed allocation, no other references exist.
        let control = unsafe { ControlPage::new(page.base) };
        control.initialize(&segment_layout());
        let (client_to_server, server_to_client) = control.validate().unwrap();
        assert_eq!(client_to_server.region_capacity, MIN_REGION_CAPACITY);
        assert_eq!(server_to_client.region_capacity, MIN_REGION_CAPACITY);
    }

    #[test]
    fn heartbeats_are_tracked_per_side() {
        let page = Page::new();
        // Safety: fresh zeroed allocation, no other references exist.
        let control = unsafe { ControlPage::new(page.base) };
        control.store_heartbeat(Side::Server, 111);
        control.store_heartbeat(Side::Client, 222);
        assert_eq!(control.load_heartbeat(Side::Server), 111);
        assert_eq!(control.load_heartbeat(Side::Client), 222);
    }
}
