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

//! Model-checked concurrency suite. Runs the production producer and
//! consumer, unchanged, over loom-tracked memory:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p shm --release --test loom
//! ```
//!
//! Covered races: commit visibility, rotation against cleaning,
//! padding at region boundaries, and the park/doorbell lost-wake
//! window.

#![cfg(loom)]

use std::sync::Arc;

use loom::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use loom::sync::{Condvar, Mutex};

use shm::consumer::LogConsumer;
use shm::layout::{COUNTERS_BLOCK_SIZE, LogGeometry};
use shm::mem::LogMemory;
use shm::producer::{AppendError, LogProducer};

const REGION_CAPACITY: usize = 64;

/// Loom-tracked log memory: counters and every 32-bit data word are
/// loom atomics, so the model checker observes all cross-thread
/// traffic the production accessor performs through raw pointers.
#[derive(Clone)]
struct LoomLogMemory {
    inner: Arc<LoomLogMemoryInner>,
}

struct LoomLogMemoryInner {
    counters: Vec<AtomicU64>,
    data_words: Vec<AtomicU32>,
    data_len: usize,
}

impl LoomLogMemory {
    fn new(geometry: LogGeometry) -> Self {
        let data_len = geometry.data_len();
        Self {
            inner: Arc::new(LoomLogMemoryInner {
                counters: (0..COUNTERS_BLOCK_SIZE / 8)
                    .map(|_| AtomicU64::new(0))
                    .collect(),
                data_words: (0..data_len / 4).map(|_| AtomicU32::new(0)).collect(),
                data_len,
            }),
        }
    }
}

impl LogMemory for LoomLogMemory {
    fn counter(&self, offset: usize) -> &AtomicU64 {
        &self.inner.counters[offset / 8]
    }

    fn record_length_word(&self, data_offset: usize) -> &AtomicU32 {
        &self.inner.data_words[data_offset / 4]
    }

    fn write_data(&self, data_offset: usize, source: &[u8]) {
        for (index, byte) in source.iter().enumerate() {
            let offset = data_offset + index;
            let word = &self.inner.data_words[offset / 4];
            let shift = (offset % 4) * 8;
            let mask = 0xFFu32 << shift;
            let current = word.load(Ordering::Relaxed);
            word.store(
                (current & !mask) | (u32::from(*byte) << shift),
                Ordering::Relaxed,
            );
        }
    }

    fn read_data(&self, data_offset: usize, destination: &mut [u8]) {
        for (index, slot) in destination.iter_mut().enumerate() {
            let offset = data_offset + index;
            let word = self.inner.data_words[offset / 4].load(Ordering::Relaxed);
            let shift = (offset % 4) * 8;
            #[allow(clippy::cast_possible_truncation)]
            let byte = ((word >> shift) & 0xFF) as u8;
            *slot = byte;
        }
    }

    fn zero_data(&self, data_offset: usize, len: usize) {
        debug_assert!(data_offset.is_multiple_of(4) && len.is_multiple_of(4));
        for word_index in data_offset / 4..(data_offset + len) / 4 {
            self.inner.data_words[word_index].store(0, Ordering::Relaxed);
        }
    }

    fn data_len(&self) -> usize {
        self.inner.data_len
    }
}

fn geometry() -> LogGeometry {
    LogGeometry {
        region_capacity: REGION_CAPACITY,
    }
}

fn payload_for(record_index: usize, payload_len: usize) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    let fill = (record_index % 251) as u8 + 1;
    vec![fill; payload_len]
}

fn run_pair(payload_lens: &'static [usize], preemption_bound: Option<usize>) {
    // None explores the full DPOR-reduced schedule space; a bound is
    // a measured cost/coverage tradeoff, stated at the call site.
    let mut model = loom::model::Builder::new();
    model.preemption_bound = preemption_bound;
    model.check(move || {
        let memory = LoomLogMemory::new(geometry());
        let mut producer = LogProducer::new(memory.clone(), geometry());
        let mut consumer = LogConsumer::new(memory, geometry());

        let producer_thread = loom::thread::spawn(move || {
            for (record_index, payload_len) in payload_lens.iter().enumerate() {
                let payload = payload_for(record_index, *payload_len);
                loop {
                    match producer.try_append(&payload) {
                        Ok(_) => break,
                        Err(AppendError::WouldBlock) => loom::thread::yield_now(),
                        Err(error) => panic!("unexpected append error: {error}"),
                    }
                }
            }
        });

        let mut records_consumed = 0;
        let mut last_position = None;
        while records_consumed < payload_lens.len() {
            match consumer.try_poll().unwrap() {
                Some(record) => {
                    if let Some(previous) = last_position {
                        assert!(record.position() > previous);
                    }
                    last_position = Some(record.position());
                    assert_eq!(record.payload_len(), payload_lens[records_consumed]);
                    let mut payload = vec![0u8; record.payload_len()];
                    record.copy_payload_into(&mut payload);
                    assert_eq!(payload, payload_for(records_consumed, payload.len()));
                    record.release();
                    records_consumed += 1;
                }
                None => loom::thread::yield_now(),
            }
        }
        producer_thread.join().unwrap();
    });
}

/// Commit visibility: a record handed out by poll always carries the
/// exact bytes the producer wrote, under every interleaving.
#[test]
fn loom_commit_visibility() {
    run_pair(&[16, 16], None);
}

/// Rotation against cleaning, through the admission edge: eight
/// records at two per region push the producer into cycle 3, whose
/// entry is the first to require the consumer's cleaned-cycles
/// publication (cycles 0..3 are admitted unconditionally). The
/// producer observes WouldBlock and retries while the consumer is
/// zeroing concurrently, so the release/acquire edge that orders
/// zero_data before region reuse is exercised, not just declared.
#[test]
fn loom_rotation_clean_handoff() {
    // Bound 4: unbounded takes ~2 minutes at this depth, and four
    // preemptions is calibrated against the known kill: the admission
    // off-by-one mutation fails this test at this bound.
    run_pair(&[16, 16, 16, 16, 16, 16, 16, 16], Some(4));
}

/// Padding boundary: the 32 + 16 byte claims leave a 16-byte remainder
/// in the first region, so rotation goes through the padding path
/// while the consumer is skipping concurrently.
#[test]
fn loom_padding_boundary() {
    run_pair(&[16, 0, 16, 16], None);
}

/// The backpressure mirror of the lost-wake test, with the doorbell
/// modeled faithfully: once the producer's post-park recheck fails it
/// sleeps on a doorbell that only the consumer rings, and the
/// consumer rings only when a post-release check observes the parked
/// flag, exactly like the transport. A lost wake is then an
/// every-thread-yields livelock, which loom reports; termination
/// under every interleaving is the liveness proof for the park
/// protocol's producer direction.
#[test]
fn loom_producer_park_never_loses_a_wake() {
    // Bound 3: the lost-wake class needs two preemptions (store
    // buffering), and unbounded exploration of this seven-record
    // model exceeds loom's branch budget. Calibrated against the
    // known kill: removing the fence from the consumer's parked-flag
    // check deadlocks this test at this bound.
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(3);
    model.check(|| {
        let memory = LoomLogMemory::new(geometry());
        let mut producer = LogProducer::new(memory.clone(), geometry());
        let mut consumer = LogConsumer::new(memory, geometry());

        let doorbell = Arc::new((Mutex::new(false), Condvar::new()));
        let doorbell_for_producer = Arc::clone(&doorbell);

        const RECORD_COUNT: usize = 7;

        let producer_thread = loom::thread::spawn(move || {
            for record_index in 0..RECORD_COUNT {
                let payload = payload_for(record_index, 16);
                let mut parked = false;
                loop {
                    match producer.try_append(&payload) {
                        Ok(_) => {
                            if parked {
                                producer.cancel_park();
                            }
                            break;
                        }
                        Err(AppendError::WouldBlock) => {
                            if !parked {
                                // First refusal: declare the park, then
                                // the next loop iteration is the fenced
                                // recheck.
                                producer.prepare_park();
                                parked = true;
                                continue;
                            }
                            // Recheck failed: block until the consumer
                            // rings, as the transport would on its
                            // socket. A lost wake leaves this thread
                            // waiting forever, which loom reports as a
                            // deadlock.
                            let (rung, bell) = &*doorbell_for_producer;
                            let mut rung_guard = rung.lock().unwrap();
                            while !*rung_guard {
                                rung_guard = bell.wait(rung_guard).unwrap();
                            }
                            *rung_guard = false;
                        }
                        Err(error) => panic!("unexpected append error: {error}"),
                    }
                }
            }
        });

        let mut records_consumed = 0;
        while records_consumed < RECORD_COUNT {
            match consumer.try_poll().unwrap() {
                Some(record) => {
                    record.release();
                    records_consumed += 1;
                    if consumer.producer_parked() {
                        let (rung, bell) = &*doorbell;
                        *rung.lock().unwrap() = true;
                        bell.notify_one();
                    }
                }
                None => loom::thread::yield_now(),
            }
        }

        producer_thread.join().unwrap();
    });
}

/// The park handshake cannot lose a wake: if the consumer decides to
/// sleep while a committed record exists, the producer must have
/// observed the parked flag (and would therefore ring the doorbell).
#[test]
fn loom_park_never_loses_a_wake() {
    loom::model(|| {
        let memory = LoomLogMemory::new(geometry());
        let mut producer = LogProducer::new(memory.clone(), geometry());
        let mut consumer = LogConsumer::new(memory, geometry());

        let producer_saw_parked = Arc::new(AtomicUsize::new(0));
        let saw_parked_recorder = Arc::clone(&producer_saw_parked);

        let producer_thread = loom::thread::spawn(move || {
            producer.try_append(&[42u8; 8]).unwrap();
            if producer.consumer_parked() {
                saw_parked_recorder.store(1, Ordering::SeqCst);
            }
        });

        let mut slept_with_pending_record = false;
        if consumer.try_poll().unwrap().is_none() {
            consumer.prepare_park();
            if consumer.try_poll().unwrap().is_none() {
                slept_with_pending_record = true;
            } else {
                consumer.cancel_park();
            }
        }

        producer_thread.join().unwrap();

        if slept_with_pending_record {
            assert_eq!(
                producer_saw_parked.load(Ordering::SeqCst),
                1,
                "consumer parked with a commit in flight but the producer missed the flag",
            );
        }
    });
}
