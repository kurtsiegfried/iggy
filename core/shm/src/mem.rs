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

//! Memory access seam between the log algorithm and its backing bytes.
//!
//! Production backs this with raw pointers into a mapped segment
//! ([`RawLogMemory`]). The loom test suite substitutes a model-checked
//! implementation, which is why the producer and consumer only ever
//! touch memory through this trait.

use crate::sync::{AtomicU32, AtomicU64};

/// One log's backing memory: a counters block and a data area.
///
/// Contract for implementations and callers:
///
/// - `counter` is called only with 8-aligned offsets inside the
///   counters block; `record_length_word` only with
///   [`crate::layout::RECORD_ALIGNMENT`]-aligned offsets inside the
///   data area.
/// - The four bytes addressed by `record_length_word` are never
///   touched through `write_data` / `read_data` / `zero_data` except
///   by `zero_data` during region cleaning, when the algorithm
///   guarantees no concurrent access to that region.
/// - Data bytes are only read after an acquire load of the covering
///   record's commit word observed the producer's release store, so
///   plain (non-atomic) data access is race-free by protocol, not by
///   type.
pub trait LogMemory {
    fn counter(&self, offset: usize) -> &AtomicU64;
    fn record_length_word(&self, data_offset: usize) -> &AtomicU32;
    fn write_data(&self, data_offset: usize, source: &[u8]);
    fn read_data(&self, data_offset: usize, destination: &mut [u8]);
    fn zero_data(&self, data_offset: usize, len: usize);
    fn data_len(&self) -> usize;
}

#[cfg(not(loom))]
pub use raw::RawLogMemory;

#[cfg(not(loom))]
mod raw {
    use std::ptr::NonNull;
    use std::sync::atomic::{AtomicU32, AtomicU64};

    use crate::layout::RECORD_ALIGNMENT;
    use crate::mem::LogMemory;

    /// Raw-pointer log memory over a mapped (or heap) allocation.
    ///
    /// Constructed once per party per log; the producer and consumer
    /// processes each hold their own instance over the same physical
    /// bytes.
    #[derive(Debug)]
    pub struct RawLogMemory {
        counters: NonNull<u8>,
        counters_len: usize,
        data: NonNull<u8>,
        data_len: usize,
    }

    impl RawLogMemory {
        /// # Safety
        ///
        /// - Both ranges must be valid for reads and writes for the
        ///   lifetime of the returned value and 8-byte aligned.
        /// - The ranges must not overlap each other, and no Rust
        ///   reference (`&` or `&mut`) to any part of them may exist
        ///   elsewhere while this value is alive; all other access must
        ///   go through `LogMemory` implementations over the same
        ///   ranges.
        /// - The bytes must be zero on first use of a fresh log, since
        ///   a zero commit word is the "not committed" marker.
        /// - At most one producer and one consumer party may operate
        ///   over the same physical ranges.
        #[must_use]
        pub const unsafe fn new(
            counters: NonNull<u8>,
            counters_len: usize,
            data: NonNull<u8>,
            data_len: usize,
        ) -> Self {
            Self {
                counters,
                counters_len,
                data,
                data_len,
            }
        }
    }

    // The pointers target shared mappings that outlive the value per
    // the constructor contract, so moving it across threads is sound.
    unsafe impl Send for RawLogMemory {}

    impl LogMemory for RawLogMemory {
        #[allow(clippy::cast_ptr_alignment)]
        // Alignment is asserted; the constructor requires 8-aligned bases.
        fn counter(&self, offset: usize) -> &AtomicU64 {
            assert!(offset.is_multiple_of(8) && offset + 8 <= self.counters_len);
            // Safety: in-bounds and 8-aligned per the assert and the
            // constructor contract; atomics allow shared mutation.
            unsafe { &*self.counters.as_ptr().add(offset).cast::<AtomicU64>() }
        }

        #[allow(clippy::cast_ptr_alignment)]
        // Alignment is asserted; the constructor requires 8-aligned bases.
        fn record_length_word(&self, data_offset: usize) -> &AtomicU32 {
            assert!(
                data_offset.is_multiple_of(RECORD_ALIGNMENT) && data_offset + 4 <= self.data_len
            );
            // Safety: in-bounds and 16-aligned per the assert and the
            // constructor contract; atomics allow shared mutation.
            unsafe { &*self.data.as_ptr().add(data_offset).cast::<AtomicU32>() }
        }

        fn write_data(&self, data_offset: usize, source: &[u8]) {
            assert!(data_offset + source.len() <= self.data_len);
            // Safety: in-bounds per the assert; the protocol guarantees
            // no concurrent access to these bytes (see trait contract).
            unsafe {
                std::ptr::copy_nonoverlapping(
                    source.as_ptr(),
                    self.data.as_ptr().add(data_offset),
                    source.len(),
                );
            }
        }

        fn read_data(&self, data_offset: usize, destination: &mut [u8]) {
            assert!(data_offset + destination.len() <= self.data_len);
            // Safety: in-bounds per the assert; commit-word acquire
            // ordering makes these bytes stable before any read.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.data.as_ptr().add(data_offset),
                    destination.as_mut_ptr(),
                    destination.len(),
                );
            }
        }

        fn zero_data(&self, data_offset: usize, len: usize) {
            assert!(data_offset + len <= self.data_len);
            // Safety: in-bounds per the assert; cleaning only runs on a
            // region the producer cannot re-enter until the cleaned
            // counter is published afterwards.
            unsafe {
                std::ptr::write_bytes(self.data.as_ptr().add(data_offset), 0, len);
            }
        }

        fn data_len(&self) -> usize {
            self.data_len
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::ptr::NonNull;
    use std::sync::atomic::Ordering;

    use crate::layout::COUNTERS_BLOCK_SIZE;
    use crate::mem::{LogMemory, RawLogMemory};

    struct Arena {
        base: NonNull<u8>,
        layout: Layout,
    }

    impl Arena {
        fn new(len: usize) -> Self {
            let layout = Layout::from_size_align(len, 16).unwrap();
            // Safety: layout has non-zero size.
            let base = unsafe { alloc_zeroed(layout) };
            Self {
                base: NonNull::new(base).unwrap(),
                layout,
            }
        }
    }

    impl Drop for Arena {
        fn drop(&mut self) {
            // Safety: allocated with exactly this layout in `new`.
            unsafe { dealloc(self.base.as_ptr(), self.layout) };
        }
    }

    #[test]
    fn raw_memory_round_trips_counters_and_data() {
        let counters = Arena::new(COUNTERS_BLOCK_SIZE);
        let data = Arena::new(256);
        // Safety: fresh zeroed allocations, no other references exist.
        let memory =
            unsafe { RawLogMemory::new(counters.base, COUNTERS_BLOCK_SIZE, data.base, 256) };

        memory.counter(64).store(7, Ordering::Release);
        assert_eq!(memory.counter(64).load(Ordering::Acquire), 7);

        memory.write_data(36, &[1, 2, 3]);
        let mut readback = [0u8; 3];
        memory.read_data(36, &mut readback);
        assert_eq!(readback, [1, 2, 3]);

        memory.record_length_word(32).store(19, Ordering::Release);
        assert_eq!(memory.record_length_word(32).load(Ordering::Acquire), 19);

        memory.zero_data(32, 32);
        assert_eq!(memory.record_length_word(32).load(Ordering::Acquire), 0);
        memory.read_data(36, &mut readback);
        assert_eq!(readback, [0, 0, 0]);
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn raw_memory_rejects_out_of_bounds_data() {
        let counters = Arena::new(COUNTERS_BLOCK_SIZE);
        let data = Arena::new(64);
        // Safety: fresh zeroed allocations, no other references exist.
        let memory =
            unsafe { RawLogMemory::new(counters.base, COUNTERS_BLOCK_SIZE, data.base, 64) };
        memory.write_data(60, &[0u8; 8]);
    }
}
