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

//! End-to-end log behavior through the public API: sustained
//! wraparound integrity, backpressure, and poison detection, over the
//! same raw memory accessor production uses (heap-backed here).

#![cfg(not(loom))]

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;
use std::sync::atomic::Ordering;

use shm::consumer::{LogConsumer, PollError};
use shm::layout::{COUNTERS_BLOCK_SIZE, LogGeometry, RECORD_HEADER_SIZE};
use shm::mem::{LogMemory, RawLogMemory};
use shm::producer::{AppendError, LogProducer};
use shm::record::{RECORD_TYPE_FRAME, RECORD_TYPE_OFFSET, RECORD_TYPE_PADDING};

struct HeapLog {
    counters: NonNull<u8>,
    counters_layout: Layout,
    data: NonNull<u8>,
    data_layout: Layout,
    geometry: LogGeometry,
}

impl HeapLog {
    fn new(region_capacity: usize) -> Self {
        let geometry = LogGeometry { region_capacity };
        let counters_layout = Layout::from_size_align(COUNTERS_BLOCK_SIZE, 64).unwrap();
        let data_layout = Layout::from_size_align(geometry.data_len(), 64).unwrap();
        // Safety: both layouts have non-zero sizes.
        let counters = unsafe { alloc_zeroed(counters_layout) };
        let data = unsafe { alloc_zeroed(data_layout) };
        Self {
            counters: NonNull::new(counters).unwrap(),
            counters_layout,
            data: NonNull::new(data).unwrap(),
            data_layout,
            geometry,
        }
    }

    const fn memory(&self) -> RawLogMemory {
        // Safety: zero-initialized allocations that outlive the views;
        // the tests run one producer and one consumer over them.
        unsafe {
            RawLogMemory::new(
                self.counters,
                COUNTERS_BLOCK_SIZE,
                self.data,
                self.geometry.data_len(),
            )
        }
    }
}

impl Drop for HeapLog {
    fn drop(&mut self) {
        // Safety: allocated with exactly these layouts in `new`.
        unsafe {
            dealloc(self.counters.as_ptr(), self.counters_layout);
            dealloc(self.data.as_ptr(), self.data_layout);
        }
    }
}

/// Deterministic pseudo-random sizes without a rand dependency.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }
}

fn payload_for(record_index: u64, payload_len: usize) -> Vec<u8> {
    let mut payload = vec![0u8; payload_len];
    let mut generator = SplitMix64 {
        state: record_index.wrapping_mul(0x2545_F491_4F6C_DD1D),
    };
    for chunk in payload.chunks_mut(8) {
        let word = generator.next().to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    payload
}

#[test]
fn sustained_wraparound_preserves_every_payload() {
    let log = HeapLog::new(1024);
    let geometry = log.geometry;
    let mut producer = LogProducer::new(log.memory(), geometry);
    let mut consumer = LogConsumer::new(log.memory(), geometry);

    let total_records: u64 = if cfg!(miri) { 300 } else { 10_000 };
    let mut sizes = SplitMix64 { state: 7 };
    let mut appended: u64 = 0;
    let mut records_consumed: u64 = 0;
    let mut last_position: Option<u64> = None;

    while records_consumed < total_records {
        // Interleave bursts of appends and drains so the log crosses
        // region boundaries in many different phases.
        let burst = sizes.next() % 7 + 1;
        for _ in 0..burst {
            if appended == total_records {
                break;
            }
            #[allow(clippy::cast_possible_truncation)]
            let payload_len = (sizes.next() % (geometry.max_payload_len() as u64 + 1)) as usize;
            match producer.try_append(&payload_for(appended, payload_len)) {
                Ok(_) => appended += 1,
                Err(AppendError::WouldBlock) => break,
                Err(error) => panic!("unexpected append error: {error}"),
            }
        }
        while let Some(record) = consumer.try_poll().unwrap() {
            if let Some(previous) = last_position {
                assert!(record.position() > previous, "positions must be monotonic");
            }
            last_position = Some(record.position());
            let mut payload = vec![0u8; record.payload_len()];
            record.copy_payload_into(&mut payload);
            assert_eq!(
                payload,
                payload_for(records_consumed, payload.len()),
                "payload corrupted at record {records_consumed}",
            );
            record.release();
            records_consumed += 1;
        }
    }
    assert_eq!(records_consumed, total_records);
}

#[test]
fn producer_is_bounded_by_uncleaned_regions() {
    let log = HeapLog::new(1024);
    let mut producer = LogProducer::new(log.memory(), log.geometry);

    let mut appended_bytes = 0usize;
    let payload = vec![0xABu8; 100];
    loop {
        match producer.try_append(&payload) {
            Ok(_) => appended_bytes += payload.len(),
            Err(AppendError::WouldBlock) => break,
            Err(error) => panic!("unexpected append error: {error}"),
        }
    }
    // Structural bound: nothing can be admitted past the three regions.
    assert!(appended_bytes <= 3 * log.geometry.region_capacity);
    assert!(appended_bytes >= 2 * log.geometry.region_capacity);
}

#[test]
fn corrupted_record_type_poisons_the_log() {
    let log = HeapLog::new(1024);
    let mut producer = LogProducer::new(log.memory(), log.geometry);
    let mut consumer = LogConsumer::new(log.memory(), log.geometry);
    producer.try_append(&[1, 2, 3]).unwrap();

    // A hostile peer scribbles an unknown type on a committed record.
    log.memory().write_data(RECORD_TYPE_OFFSET, &[0x77]);

    assert!(matches!(
        consumer.try_poll(),
        Err(PollError::UnknownRecordType { record_type: 0x77 })
    ));
}

#[test]
fn oversized_commit_word_poisons_the_log() {
    let log = HeapLog::new(1024);
    let mut producer = LogProducer::new(log.memory(), log.geometry);
    let mut consumer = LogConsumer::new(log.memory(), log.geometry);
    producer.try_append(&[0u8; 8]).unwrap();

    #[allow(clippy::cast_possible_truncation)]
    let overrun = (log.geometry.region_capacity + 1) as u32;
    log.memory()
        .record_length_word(0)
        .store(overrun, Ordering::Release);

    let poll_error = consumer.try_poll().unwrap_err();
    assert_eq!(
        poll_error,
        PollError::CommitOverrunsRegion {
            committed: overrun,
            remaining: log.geometry.region_capacity,
        }
    );
}

#[test]
fn undersized_commit_word_poisons_the_log() {
    let log = HeapLog::new(1024);
    let mut consumer = LogConsumer::new(log.memory(), log.geometry);

    #[allow(clippy::cast_possible_truncation)]
    let below_header = (RECORD_HEADER_SIZE - 1) as u32;
    log.memory()
        .record_length_word(0)
        .store(below_header, Ordering::Release);

    let poll_error = consumer.try_poll().unwrap_err();
    assert_eq!(
        poll_error,
        PollError::CommitBelowHeader {
            committed: below_header,
        }
    );
}

#[test]
fn padding_at_region_start_poisons_the_log() {
    let log = HeapLog::new(1024);
    let mut consumer = LogConsumer::new(log.memory(), log.geometry);

    // A whole-region padding record at a region base is the hostile
    // shape that would otherwise spin the consumer forever.
    log.memory()
        .write_data(RECORD_TYPE_OFFSET, &[RECORD_TYPE_PADDING]);
    #[allow(clippy::cast_possible_truncation)]
    let whole_region = log.geometry.region_capacity as u32;
    log.memory()
        .record_length_word(0)
        .store(whole_region, Ordering::Release);

    assert_eq!(
        consumer.try_poll().unwrap_err(),
        PollError::PaddingAtRegionStart
    );
}

#[test]
fn misplaced_padding_poisons_the_log() {
    let log = HeapLog::new(1024);
    let mut producer = LogProducer::new(log.memory(), log.geometry);
    let mut consumer = LogConsumer::new(log.memory(), log.geometry);

    producer.try_append(&[5u8; 16]).unwrap();
    consumer.try_poll().unwrap().unwrap().release();

    // Hostile padding past the region start whose length does not
    // close the region.
    log.memory()
        .write_data(32 + RECORD_TYPE_OFFSET, &[RECORD_TYPE_PADDING]);
    #[allow(clippy::cast_possible_truncation)]
    let short_padding = (log.geometry.region_capacity - 48) as u32;
    log.memory()
        .record_length_word(32)
        .store(short_padding, Ordering::Release);

    assert_eq!(
        consumer.try_poll().unwrap_err(),
        PollError::MisplacedPadding {
            committed: short_padding,
            remaining: log.geometry.region_capacity - 32,
        }
    );
}

#[test]
fn poll_errors_are_sticky() {
    let log = HeapLog::new(1024);
    let mut producer = LogProducer::new(log.memory(), log.geometry);
    let mut consumer = LogConsumer::new(log.memory(), log.geometry);
    producer.try_append(&[1, 2, 3]).unwrap();

    log.memory().write_data(RECORD_TYPE_OFFSET, &[0x77]);
    let first = consumer.try_poll().unwrap_err();
    assert_eq!(first, PollError::UnknownRecordType { record_type: 0x77 });

    // A hostile producer repairing the record afterwards must not
    // flip the log back to making progress.
    log.memory()
        .write_data(RECORD_TYPE_OFFSET, &[RECORD_TYPE_FRAME]);
    assert_eq!(consumer.try_poll().unwrap_err(), first);
}

#[test]
fn max_payload_and_exact_region_fill_round_trip() {
    let log = HeapLog::new(1024);
    let mut producer = LogProducer::new(log.memory(), log.geometry);
    let mut consumer = LogConsumer::new(log.memory(), log.geometry);

    // Two maximum-size records tile a region exactly, so the third
    // append rotates with no padding record in between.
    let max_payload = vec![0xC3u8; log.geometry.max_payload_len()];
    let first = producer.try_append(&max_payload).unwrap();
    let second = producer.try_append(&max_payload).unwrap();
    let third = producer.try_append(&[9u8; 4]).unwrap();
    assert_eq!(first, 0);
    assert_eq!(second, 512);
    assert_eq!(third, 1024);

    for expected_len in [max_payload.len(), max_payload.len(), 4] {
        let record = consumer.try_poll().unwrap().unwrap();
        assert_eq!(record.payload_len(), expected_len);
        record.release();
    }
    assert!(consumer.try_poll().unwrap().is_none());
}

/// Two real threads over the production raw-pointer accessor. Under
/// Miri this is the one schedule where its data-race detector can see
/// the plain data copies and the atomics interact; under plain cargo
/// test it doubles as a cross-thread smoke test.
#[test]
fn two_threads_round_trip_over_raw_memory() {
    let log = HeapLog::new(256);
    let geometry = log.geometry;
    let producer_memory = log.memory();
    let consumer_memory = log.memory();
    let total_records: u64 = if cfg!(miri) { 64 } else { 4096 };

    let producer_thread = std::thread::spawn(move || {
        let mut producer = LogProducer::new(producer_memory, geometry);
        for record_index in 0..total_records {
            let payload = payload_for(record_index, usize::try_from(record_index % 64).unwrap());
            loop {
                match producer.try_append(&payload) {
                    Ok(_) => break,
                    Err(AppendError::WouldBlock) => std::thread::yield_now(),
                    Err(error) => panic!("unexpected append error: {error}"),
                }
            }
        }
    });

    let mut consumer = LogConsumer::new(consumer_memory, geometry);
    let mut records_consumed: u64 = 0;
    while records_consumed < total_records {
        match consumer.try_poll().unwrap() {
            Some(record) => {
                let mut payload = vec![0u8; record.payload_len()];
                record.copy_payload_into(&mut payload);
                assert_eq!(payload, payload_for(records_consumed, payload.len()));
                record.release();
                records_consumed += 1;
            }
            None => std::thread::yield_now(),
        }
    }
    producer_thread.join().unwrap();
}

#[test]
fn park_flags_are_visible_to_the_other_party() {
    let log = HeapLog::new(1024);
    let producer = LogProducer::new(log.memory(), log.geometry);
    let consumer = LogConsumer::new(log.memory(), log.geometry);

    assert!(!producer.consumer_parked());
    consumer.prepare_park();
    assert!(producer.consumer_parked());
    consumer.cancel_park();
    assert!(!producer.consumer_parked());

    assert!(!consumer.producer_parked());
    producer.prepare_park();
    assert!(consumer.producer_parked());
    producer.cancel_park();
    assert!(!consumer.producer_parked());
}
