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

//! The single-consumer side of one log.
//!
//! Polling acquire-loads the commit word at the head position, skips
//! padding records, and hands frames out as borrowed views; releasing
//! a view advances the head. Leaving a region zeroes it and publishes
//! the cleaned-cycles counter that admits the producer's rotation.
//!
//! The producer lives in another process and is untrusted: every
//! structural violation surfaces as [`PollError`] instead of a panic,
//! and the caller is expected to tear the connection down.

use thiserror::Error;

use crate::layout::{
    CLEANED_CYCLES_OFFSET, CONSUMER_PARKED_OFFSET, HEAD_OFFSET, LogGeometry,
    PRODUCER_PARKED_OFFSET, RECORD_HEADER_SIZE, REGION_COUNT,
};
use crate::mem::LogMemory;
use crate::record::{RECORD_TYPE_FRAME, RECORD_TYPE_OFFSET, RECORD_TYPE_PADDING};
use crate::sync::{Ordering, fence};

/// Structural violations in the shared log. All of them mean the
/// producer is broken or hostile; the log must not be read further.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PollError {
    #[error("commit word {committed} is below the record header size")]
    CommitBelowHeader { committed: u32 },
    #[error("commit word {committed} overruns the {remaining} bytes left in the region")]
    CommitOverrunsRegion { committed: u32, remaining: usize },
    #[error("unknown record type {record_type}")]
    UnknownRecordType { record_type: u8 },
    #[error("padding record of {committed} bytes does not close the region ({remaining} left)")]
    MisplacedPadding { committed: u32, remaining: usize },
}

#[derive(Debug)]
pub struct LogConsumer<M: LogMemory> {
    memory: M,
    region_capacity: usize,
    head: u64,
    cleaned_cycles: u64,
}

/// One committed frame, borrowed from the log until released.
///
/// Dropping the view without [`RecordView::release`] leaves the head
/// in place, so the same record is returned by the next poll.
#[derive(Debug)]
pub struct RecordView<'a, M: LogMemory> {
    consumer: &'a mut LogConsumer<M>,
    payload_offset: usize,
    payload_len: usize,
    position: u64,
}

impl<M: LogMemory> LogConsumer<M> {
    /// The memory must satisfy the [`LogMemory`] contract for
    /// `geometry` and be the same log the producer was created over.
    pub fn new(memory: M, geometry: LogGeometry) -> Self {
        debug_assert!(geometry.region_capacity.is_power_of_two());
        debug_assert_eq!(memory.data_len(), geometry.data_len());
        Self {
            memory,
            region_capacity: geometry.region_capacity,
            head: 0,
            cleaned_cycles: 0,
        }
    }

    /// Returns the next committed frame, or `None` when the log is
    /// drained up to the producer's commits.
    ///
    /// # Errors
    ///
    /// Returns [`PollError`] on a structurally invalid record; the log
    /// is unusable afterwards and the connection must be torn down.
    pub fn try_poll(&mut self) -> Result<Option<RecordView<'_, M>>, PollError> {
        loop {
            let offset = self.head_offset();
            let data_offset = self.active_region() * self.region_capacity + offset;
            let committed = self
                .memory
                .record_length_word(data_offset)
                .load(Ordering::Acquire);
            if committed == 0 {
                return Ok(None);
            }

            let remaining = self.region_capacity - offset;
            if (committed as usize) < RECORD_HEADER_SIZE {
                return Err(PollError::CommitBelowHeader { committed });
            }
            if committed as usize > remaining {
                return Err(PollError::CommitOverrunsRegion {
                    committed,
                    remaining,
                });
            }

            let mut record_type = [0u8; 1];
            self.memory
                .read_data(data_offset + RECORD_TYPE_OFFSET, &mut record_type);
            match record_type[0] {
                RECORD_TYPE_FRAME => {
                    let position = self.head;
                    return Ok(Some(RecordView {
                        payload_offset: data_offset + RECORD_HEADER_SIZE,
                        payload_len: committed as usize - RECORD_HEADER_SIZE,
                        position,
                        consumer: self,
                    }));
                }
                RECORD_TYPE_PADDING => {
                    if committed as usize != remaining {
                        return Err(PollError::MisplacedPadding {
                            committed,
                            remaining,
                        });
                    }
                    self.advance(remaining);
                }
                record_type => return Err(PollError::UnknownRecordType { record_type }),
            }
        }
    }

    /// Declares this consumer parked before sleeping. The caller must
    /// poll once more after this and only sleep if the log is still
    /// drained; that recheck closes the race against a producer that
    /// committed between the last poll and the park.
    pub fn prepare_park(&self) {
        self.memory
            .counter(CONSUMER_PARKED_OFFSET)
            .store(1, Ordering::Relaxed);
        fence(Ordering::SeqCst);
    }

    pub fn cancel_park(&self) {
        self.memory
            .counter(CONSUMER_PARKED_OFFSET)
            .store(0, Ordering::Relaxed);
    }

    /// Whether the producer has declared itself parked on
    /// backpressure; when true the caller must ring the doorbell after
    /// releasing records. Pairs with the producer's
    /// store-then-fence-then-retry park entry.
    pub fn producer_parked(&self) -> bool {
        fence(Ordering::SeqCst);
        self.memory
            .counter(PRODUCER_PARKED_OFFSET)
            .load(Ordering::Relaxed)
            == 1
    }

    fn advance(&mut self, claimed_len: usize) {
        self.head += claimed_len as u64;
        if self.head_offset() == 0 {
            // The head just left a region: zero it so its commit words
            // read as "not committed" on the region's next cycle, then
            // admit the producer by publishing the cleaned count.
            let departed_cycle = self.head / self.region_capacity as u64 - 1;
            #[allow(clippy::cast_possible_truncation)]
            let departed_region = (departed_cycle % REGION_COUNT) as usize;
            self.memory
                .zero_data(departed_region * self.region_capacity, self.region_capacity);
            self.cleaned_cycles += 1;
            self.memory
                .counter(CLEANED_CYCLES_OFFSET)
                .store(self.cleaned_cycles, Ordering::Release);
        }
        self.memory
            .counter(HEAD_OFFSET)
            .store(self.head, Ordering::Relaxed);
    }

    const fn head_offset(&self) -> usize {
        #[allow(clippy::cast_possible_truncation)]
        let offset = (self.head % self.region_capacity as u64) as usize;
        offset
    }

    const fn active_region(&self) -> usize {
        #[allow(clippy::cast_possible_truncation)]
        let region = ((self.head / self.region_capacity as u64) % REGION_COUNT) as usize;
        region
    }
}

impl<M: LogMemory> RecordView<'_, M> {
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// Stream position of this record, monotonic across regions.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// # Panics
    ///
    /// Panics when `destination` is not exactly
    /// [`RecordView::payload_len`] bytes.
    pub fn copy_payload_into(&self, destination: &mut [u8]) {
        assert_eq!(destination.len(), self.payload_len);
        self.consumer
            .memory
            .read_data(self.payload_offset, destination);
    }

    /// Consumes the record: advances the head past it and, when it was
    /// the last record in its region, zeroes that region and admits
    /// the producer's next rotation.
    pub fn release(self) {
        let claimed_len = crate::record::aligned_record_len(self.payload_len);
        self.consumer.advance(claimed_len);
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::producer::{AppendError, LogProducer};
    use crate::test_support::HeapLog;

    #[test]
    fn poll_returns_none_on_a_fresh_log() {
        let log = HeapLog::new(64);
        let mut consumer = LogConsumer::new(log.memory(), log.geometry());
        assert!(consumer.try_poll().unwrap().is_none());
    }

    #[test]
    fn poll_round_trips_payloads_in_order() {
        let log = HeapLog::new(64);
        let mut producer = LogProducer::new(log.memory(), log.geometry());
        let mut consumer = LogConsumer::new(log.memory(), log.geometry());

        producer.try_append(&[1, 2, 3]).unwrap();
        producer.try_append(&[]).unwrap();

        let record = consumer.try_poll().unwrap().unwrap();
        assert_eq!(record.payload_len(), 3);
        assert_eq!(record.position(), 0);
        let mut payload = [0u8; 3];
        record.copy_payload_into(&mut payload);
        assert_eq!(payload, [1, 2, 3]);
        record.release();

        let empty = consumer.try_poll().unwrap().unwrap();
        assert_eq!(empty.payload_len(), 0);
        empty.release();

        assert!(consumer.try_poll().unwrap().is_none());
    }

    #[test]
    fn unreleased_record_is_polled_again() {
        let log = HeapLog::new(64);
        let mut producer = LogProducer::new(log.memory(), log.geometry());
        let mut consumer = LogConsumer::new(log.memory(), log.geometry());
        producer.try_append(&[9; 4]).unwrap();

        let first_position = consumer.try_poll().unwrap().unwrap().position();
        let second_position = consumer.try_poll().unwrap().unwrap().position();
        assert_eq!(first_position, second_position);
    }

    #[test]
    fn consuming_a_region_unblocks_the_producer() {
        let log = HeapLog::new(64);
        let mut producer = LogProducer::new(log.memory(), log.geometry());
        let mut consumer = LogConsumer::new(log.memory(), log.geometry());

        let payload = [7u8; 16];
        for _ in 0..6 {
            producer.try_append(&payload).unwrap();
        }
        assert_eq!(producer.try_append(&payload), Err(AppendError::WouldBlock));

        // Draining the first region (two records) cleans it and admits
        // exactly one more rotation.
        for _ in 0..2 {
            consumer.try_poll().unwrap().unwrap().release();
        }
        producer.try_append(&payload).unwrap();
    }
}
