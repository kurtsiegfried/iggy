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

//! The single-producer side of one log.
//!
//! Appends claim space in the active region, write the record body,
//! then release-store the commit word. Region rotation is admitted
//! only once the consumer has cleaned the target region's previous
//! cycle; a refused rotation surfaces as [`AppendError::WouldBlock`],
//! which is the transport's backpressure.
//!
//! The packed `raw_tail` counters (`cycle << 32 | offset`) and the
//! active-count counter are written through for observability and for
//! a future multi-producer claim protocol; correctness for the current
//! single producer rests on local state plus the cleaned-cycles
//! counter alone.

use thiserror::Error;

use crate::layout::{
    ACTIVE_COUNT_OFFSET, CLEANED_CYCLES_OFFSET, CONSUMER_PARKED_OFFSET, LogGeometry,
    PRODUCER_PARKED_OFFSET, RAW_TAIL_OFFSETS, RECORD_HEADER_SIZE, REGION_COUNT,
};
use crate::mem::LogMemory;
use crate::record::{
    RECORD_TYPE_FRAME, RECORD_TYPE_OFFSET, RECORD_TYPE_PADDING, aligned_record_len,
    total_record_len,
};
use crate::sync::{Ordering, fence};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AppendError {
    /// Every region ahead is still awaiting the consumer's cleaning;
    /// retry after the consumer makes progress.
    #[error("log is full: the next region has not been cleaned yet")]
    WouldBlock,
    #[error("payload of {payload_len} bytes exceeds the maximum of {max_payload_len}")]
    PayloadTooLarge {
        payload_len: usize,
        max_payload_len: usize,
    },
}

#[derive(Debug)]
pub struct LogProducer<M: LogMemory> {
    memory: M,
    region_capacity: usize,
    max_payload_len: usize,
    cycle: u64,
    tail_offset: usize,
    cached_cleaned_cycles: u64,
}

impl<M: LogMemory> LogProducer<M> {
    /// The memory must satisfy the [`LogMemory`] contract for
    /// `geometry` and be all-zero (a fresh log); resuming an existing
    /// log is not supported.
    pub fn new(memory: M, geometry: LogGeometry) -> Self {
        debug_assert!(geometry.region_capacity.is_power_of_two());
        debug_assert_eq!(memory.data_len(), geometry.data_len());
        Self {
            memory,
            region_capacity: geometry.region_capacity,
            max_payload_len: geometry.max_payload_len(),
            cycle: 0,
            tail_offset: 0,
            cached_cleaned_cycles: 0,
        }
    }

    /// Appends one frame record and returns its stream position.
    ///
    /// # Errors
    ///
    /// [`AppendError::PayloadTooLarge`] when the payload exceeds
    /// [`LogGeometry::max_payload_len`]; [`AppendError::WouldBlock`]
    /// when rotation is required but the target region has not been
    /// cleaned yet. `WouldBlock` leaves the log untouched, so the call
    /// can simply be retried later.
    pub fn try_append(&mut self, payload: &[u8]) -> Result<u64, AppendError> {
        if payload.len() > self.max_payload_len {
            return Err(AppendError::PayloadTooLarge {
                payload_len: payload.len(),
                max_payload_len: self.max_payload_len,
            });
        }
        let claimed_len = aligned_record_len(payload.len());

        loop {
            let offset = self.tail_offset;
            if offset + claimed_len <= self.region_capacity {
                let data_offset = self.active_region() * self.region_capacity + offset;
                self.memory
                    .write_data(data_offset + RECORD_TYPE_OFFSET, &[RECORD_TYPE_FRAME]);
                if !payload.is_empty() {
                    self.memory
                        .write_data(data_offset + RECORD_HEADER_SIZE, payload);
                }
                #[allow(clippy::cast_possible_truncation)]
                // Bounded by max_payload_len, itself bounded by the
                // region capacity ceiling of 1 GiB.
                let commit_word = total_record_len(payload.len()) as u32;
                self.memory
                    .record_length_word(data_offset)
                    .store(commit_word, Ordering::Release);

                #[allow(clippy::cast_possible_truncation)]
                let position = self.cycle * self.region_capacity as u64 + offset as u64;
                self.tail_offset = offset + claimed_len;
                self.publish_tail();
                return Ok(position);
            }

            // Admission before any write: a refused rotation must leave
            // no trace, or a retried padding write could land in a
            // region the consumer has cleaned in the meantime.
            let next_cycle = self.cycle + 1;
            if !self.next_region_cleaned(next_cycle) {
                return Err(AppendError::WouldBlock);
            }

            let remaining = self.region_capacity - offset;
            if remaining > 0 {
                let data_offset = self.active_region() * self.region_capacity + offset;
                self.memory
                    .write_data(data_offset + RECORD_TYPE_OFFSET, &[RECORD_TYPE_PADDING]);
                #[allow(clippy::cast_possible_truncation)]
                // Bounded by the region capacity ceiling of 1 GiB.
                let padding_word = remaining as u32;
                self.memory
                    .record_length_word(data_offset)
                    .store(padding_word, Ordering::Release);
            }

            self.cycle = next_cycle;
            self.tail_offset = 0;
            debug_assert_eq!(
                self.memory
                    .record_length_word(self.active_region() * self.region_capacity)
                    .load(Ordering::Relaxed),
                0,
                "rotated into a region that was not cleaned",
            );
            self.publish_tail();
            self.memory
                .counter(ACTIVE_COUNT_OFFSET)
                .store(self.cycle, Ordering::Relaxed);
        }
    }

    /// Whether the consumer has declared itself parked; when true the
    /// caller must ring the doorbell after its append batch. Pairs
    /// with the consumer's store-then-fence-then-recheck park entry.
    pub fn consumer_parked(&self) -> bool {
        fence(Ordering::SeqCst);
        self.memory
            .counter(CONSUMER_PARKED_OFFSET)
            .load(Ordering::Relaxed)
            == 1
    }

    /// Declares this producer parked before sleeping on backpressure.
    /// The caller must retry the append after this and only sleep if
    /// it still would block.
    pub fn prepare_park(&self) {
        self.memory
            .counter(PRODUCER_PARKED_OFFSET)
            .store(1, Ordering::Relaxed);
        fence(Ordering::SeqCst);
    }

    pub fn cancel_park(&self) {
        self.memory
            .counter(PRODUCER_PARKED_OFFSET)
            .store(0, Ordering::Relaxed);
    }

    const fn active_region(&self) -> usize {
        #[allow(clippy::cast_possible_truncation)]
        let region = (self.cycle % REGION_COUNT) as usize;
        region
    }

    fn next_region_cleaned(&mut self, next_cycle: u64) -> bool {
        if next_cycle < REGION_COUNT {
            return true;
        }
        // The target region was last used REGION_COUNT cycles ago and
        // must be zeroed before reuse, else stale commit words would
        // read as committed records.
        let required_cleaned_cycles = next_cycle - REGION_COUNT + 1;
        if self.cached_cleaned_cycles >= required_cleaned_cycles {
            return true;
        }
        self.cached_cleaned_cycles = self
            .memory
            .counter(CLEANED_CYCLES_OFFSET)
            .load(Ordering::Acquire);
        self.cached_cleaned_cycles >= required_cleaned_cycles
    }

    fn publish_tail(&self) {
        #[allow(clippy::cast_possible_truncation)]
        let packed = u64::from(self.cycle as u32) << 32 | self.tail_offset as u64;
        self.memory
            .counter(RAW_TAIL_OFFSETS[self.active_region()])
            .store(packed, Ordering::Relaxed);
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::test_support::HeapLog;

    #[test]
    fn append_rejects_oversized_payload() {
        let log = HeapLog::new(1024);
        let mut producer = LogProducer::new(log.memory(), log.geometry());
        let payload = vec![0u8; log.geometry().max_payload_len() + 1];
        assert_eq!(
            producer.try_append(&payload),
            Err(AppendError::PayloadTooLarge {
                payload_len: payload.len(),
                max_payload_len: log.geometry().max_payload_len(),
            })
        );
    }

    #[test]
    fn append_reports_would_block_when_all_regions_are_dirty() {
        let log = HeapLog::new(64);
        let mut producer = LogProducer::new(log.memory(), log.geometry());
        // Each 16-byte payload claims 32 bytes: two records per region.
        let payload = [7u8; 16];
        for _ in 0..6 {
            producer.try_append(&payload).unwrap();
        }
        assert_eq!(producer.try_append(&payload), Err(AppendError::WouldBlock));
        // A refused rotation leaves state untouched: still refused.
        assert_eq!(producer.try_append(&payload), Err(AppendError::WouldBlock));
    }

    #[test]
    fn positions_are_monotonic_across_rotation() {
        let log = HeapLog::new(64);
        let mut producer = LogProducer::new(log.memory(), log.geometry());
        let first = producer.try_append(&[1u8; 16]).unwrap();
        let second = producer.try_append(&[2u8; 16]).unwrap();
        let third = producer.try_append(&[3u8; 16]).unwrap();
        assert_eq!(first, 0);
        assert_eq!(second, 32);
        // Third record rotated into the next region.
        assert_eq!(third, 64);
    }
}
