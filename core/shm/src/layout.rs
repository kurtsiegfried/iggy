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

//! Segment geometry: region sizing rules, counter offsets, and the
//! placement of both logs plus the control page inside one segment.
//!
//! Pure math, shared verbatim by both processes, so every offset here
//! is wire-stable once a layout version ships.

use thiserror::Error;

/// Regions per log. The producer can be at most this many regions
/// ahead of the consumer's cleaning, which bounds memory and provides
/// backpressure.
pub const REGION_COUNT: u64 = 3;

/// Record claims are rounded up to this, which keeps every record
/// header naturally aligned for a `u32` commit word and leaves payload
/// starts aligned for future in-place header casts.
pub const RECORD_ALIGNMENT: usize = 16;

/// Fixed per-record header: `[total_len: u32][record_type: u8]
/// [flags: u8][reserved: 10]`.
pub const RECORD_HEADER_SIZE: usize = 16;

/// Counters are spaced one per cache line so the producer and consumer
/// never false-share.
pub const CACHE_LINE_SIZE: usize = 64;

/// Sections inside the segment start on page boundaries.
pub const SEGMENT_PAGE_SIZE: usize = 4096;

pub const MIN_REGION_CAPACITY: usize = 64 * 1024;
pub const MAX_REGION_CAPACITY: usize = 1 << 30;

pub const SEGMENT_MAGIC: u64 = u64::from_le_bytes(*b"IGGYSHM1");
pub const LAYOUT_VERSION: u32 = 1;

/// Byte offsets of the per-log counters inside that log's counters
/// block. Each holds a `u64` and owns its cache line.
pub const RAW_TAIL_OFFSETS: [usize; 3] = [0, 64, 128];
pub const ACTIVE_COUNT_OFFSET: usize = 192;
pub const HEAD_OFFSET: usize = 256;
pub const CLEANED_CYCLES_OFFSET: usize = 320;
pub const CONSUMER_PARKED_OFFSET: usize = 384;
pub const PRODUCER_PARKED_OFFSET: usize = 448;
pub const COUNTERS_BLOCK_SIZE: usize = 512;

/// Sizing for one one-way log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogGeometry {
    pub region_capacity: usize,
}

impl LogGeometry {
    /// # Errors
    ///
    /// Returns a [`LayoutError`] when the region capacity is not a
    /// power of two or falls outside
    /// [`MIN_REGION_CAPACITY`]..=[`MAX_REGION_CAPACITY`].
    pub const fn validate(&self) -> Result<(), LayoutError> {
        if !self.region_capacity.is_power_of_two() {
            return Err(LayoutError::RegionCapacityNotPowerOfTwo {
                region_capacity: self.region_capacity,
            });
        }
        if self.region_capacity < MIN_REGION_CAPACITY {
            return Err(LayoutError::RegionCapacityTooSmall {
                region_capacity: self.region_capacity,
            });
        }
        if self.region_capacity > MAX_REGION_CAPACITY {
            return Err(LayoutError::RegionCapacityTooLarge {
                region_capacity: self.region_capacity,
            });
        }
        Ok(())
    }

    /// Largest payload a single record may carry. Half a region bounds
    /// the space a boundary padding record can waste.
    #[must_use]
    pub const fn max_payload_len(&self) -> usize {
        self.region_capacity / 2 - RECORD_HEADER_SIZE
    }

    /// Total data bytes for one log: all regions, contiguous.
    #[must_use]
    pub const fn data_len(&self) -> usize {
        #[allow(clippy::cast_possible_truncation)]
        // REGION_COUNT is 3; it is u64 only for stream-position math.
        let region_count = REGION_COUNT as usize;
        self.region_capacity * region_count
    }

    /// [`LogGeometry::data_len`] without the assumption that it fits;
    /// `None` means the address space cannot hold this log at all
    /// (reachable on 32-bit targets with capacities `validate`
    /// otherwise accepts).
    #[must_use]
    pub const fn checked_data_len(&self) -> Option<usize> {
        #[allow(clippy::cast_possible_truncation)]
        // REGION_COUNT is 3; it is u64 only for stream-position math.
        let region_count = REGION_COUNT as usize;
        self.region_capacity.checked_mul(region_count)
    }
}

/// Constructor guard shared by the producer and consumer: the subset
/// of validity a log cannot be sound without. Looser than
/// [`LogGeometry::validate`] (no production minimum), so tests can
/// exercise boundaries with tiny regions.
pub(crate) fn assert_sound_geometry(geometry: LogGeometry) {
    assert!(
        geometry.region_capacity.is_power_of_two(),
        "region capacity must be a power of two",
    );
    assert!(
        geometry.region_capacity >= 2 * RECORD_HEADER_SIZE,
        "region capacity cannot hold a record",
    );
    assert!(
        geometry.region_capacity <= MAX_REGION_CAPACITY,
        "region capacity above the maximum would let a commit word truncate to zero",
    );
    assert!(
        geometry.checked_data_len().is_some(),
        "log does not fit this platform's address space",
    );
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LayoutError {
    #[error("region capacity {region_capacity} is not a power of two")]
    RegionCapacityNotPowerOfTwo { region_capacity: usize },
    #[error("region capacity {region_capacity} is below the minimum {MIN_REGION_CAPACITY}")]
    RegionCapacityTooSmall { region_capacity: usize },
    #[error("region capacity {region_capacity} is above the maximum {MAX_REGION_CAPACITY}")]
    RegionCapacityTooLarge { region_capacity: usize },
    #[error("segment layout does not fit this platform's address space")]
    SegmentTooLarge,
}

/// Byte placement of every section inside the shared segment.
///
/// Order: control page, client-to-server counters, server-to-client
/// counters, client-to-server data, server-to-client data. All offsets
/// are [`SEGMENT_PAGE_SIZE`]-aligned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentLayout {
    pub client_to_server: LogGeometry,
    pub server_to_client: LogGeometry,
    pub control_offset: usize,
    pub client_to_server_counters_offset: usize,
    pub server_to_client_counters_offset: usize,
    pub client_to_server_data_offset: usize,
    pub server_to_client_data_offset: usize,
    pub total_len: usize,
}

impl SegmentLayout {
    /// # Errors
    ///
    /// Returns a [`LayoutError`] when either log's geometry is
    /// invalid, or when the combined segment does not fit the
    /// platform's address space (the checked arithmetic here is the
    /// guard 32-bit targets rely on; per-region validation alone
    /// cannot bound the sum).
    pub fn compute(
        client_to_server: LogGeometry,
        server_to_client: LogGeometry,
    ) -> Result<Self, LayoutError> {
        client_to_server.validate()?;
        server_to_client.validate()?;

        let control_offset = 0;
        let client_to_server_counters_offset = control_offset + SEGMENT_PAGE_SIZE;
        let server_to_client_counters_offset = client_to_server_counters_offset
            .checked_add(page_rounded(COUNTERS_BLOCK_SIZE))
            .ok_or(LayoutError::SegmentTooLarge)?;
        let client_to_server_data_offset = server_to_client_counters_offset
            .checked_add(page_rounded(COUNTERS_BLOCK_SIZE))
            .ok_or(LayoutError::SegmentTooLarge)?;
        let server_to_client_data_offset = client_to_server_data_offset
            .checked_add(
                client_to_server
                    .checked_data_len()
                    .ok_or(LayoutError::SegmentTooLarge)?,
            )
            .ok_or(LayoutError::SegmentTooLarge)?;
        let total_len = server_to_client_data_offset
            .checked_add(
                server_to_client
                    .checked_data_len()
                    .ok_or(LayoutError::SegmentTooLarge)?,
            )
            .ok_or(LayoutError::SegmentTooLarge)?;

        Ok(Self {
            client_to_server,
            server_to_client,
            control_offset,
            client_to_server_counters_offset,
            server_to_client_counters_offset,
            client_to_server_data_offset,
            server_to_client_data_offset,
            total_len,
        })
    }
}

const fn page_rounded(len: usize) -> usize {
    (len + SEGMENT_PAGE_SIZE - 1) & !(SEGMENT_PAGE_SIZE - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_rejects_non_power_of_two() {
        let geometry = LogGeometry {
            region_capacity: 96 * 1024,
        };
        assert_eq!(
            geometry.validate(),
            Err(LayoutError::RegionCapacityNotPowerOfTwo {
                region_capacity: 96 * 1024
            })
        );
    }

    #[test]
    fn geometry_rejects_out_of_range_capacities() {
        let too_small = LogGeometry {
            region_capacity: MIN_REGION_CAPACITY / 2,
        };
        let too_large = LogGeometry {
            region_capacity: MAX_REGION_CAPACITY * 2,
        };
        assert!(matches!(
            too_small.validate(),
            Err(LayoutError::RegionCapacityTooSmall { .. })
        ));
        assert!(matches!(
            too_large.validate(),
            Err(LayoutError::RegionCapacityTooLarge { .. })
        ));
    }

    #[test]
    fn counters_do_not_share_cache_lines() {
        let mut offsets = vec![
            ACTIVE_COUNT_OFFSET,
            HEAD_OFFSET,
            CLEANED_CYCLES_OFFSET,
            CONSUMER_PARKED_OFFSET,
            PRODUCER_PARKED_OFFSET,
        ];
        offsets.extend(RAW_TAIL_OFFSETS);
        offsets.sort_unstable();
        for pair in offsets.windows(2) {
            assert!(pair[1] - pair[0] >= CACHE_LINE_SIZE);
        }
        assert!(
            offsets
                .iter()
                .all(|offset| offset + 8 <= COUNTERS_BLOCK_SIZE)
        );
    }

    #[test]
    fn segment_layout_is_page_aligned_and_non_overlapping() {
        let geometry = LogGeometry {
            region_capacity: MIN_REGION_CAPACITY,
        };
        let layout = SegmentLayout::compute(geometry, geometry).unwrap();

        let sections = [
            (layout.control_offset, SEGMENT_PAGE_SIZE),
            (layout.client_to_server_counters_offset, COUNTERS_BLOCK_SIZE),
            (layout.server_to_client_counters_offset, COUNTERS_BLOCK_SIZE),
            (layout.client_to_server_data_offset, geometry.data_len()),
            (layout.server_to_client_data_offset, geometry.data_len()),
        ];
        for (offset, len) in sections {
            assert_eq!(offset % SEGMENT_PAGE_SIZE, 0);
            assert!(offset + len <= layout.total_len);
        }
        for pair in sections.windows(2) {
            let (first_offset, first_len) = pair[0];
            let (second_offset, _) = pair[1];
            assert!(first_offset + first_len <= second_offset);
        }
    }
}
