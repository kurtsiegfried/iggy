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

//! Heap-backed log memory for unit tests: same raw accessor as
//! production, minus the mapping.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;

use crate::layout::{COUNTERS_BLOCK_SIZE, LogGeometry};
use crate::mem::RawLogMemory;

pub struct HeapLog {
    counters: NonNull<u8>,
    counters_layout: Layout,
    data: NonNull<u8>,
    data_layout: Layout,
    geometry: LogGeometry,
}

impl HeapLog {
    /// Region capacities below the production minimum are deliberately
    /// accepted here so boundary cases stay cheap to exercise.
    pub(crate) fn new(region_capacity: usize) -> Self {
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

    pub(crate) const fn memory(&self) -> RawLogMemory {
        // Safety: the allocations are zero-initialized, outlive every
        // view (tests keep the `HeapLog` binding alive), and are only
        // touched through `LogMemory` implementations.
        unsafe {
            RawLogMemory::new(
                self.counters,
                COUNTERS_BLOCK_SIZE,
                self.data,
                self.geometry.data_len(),
            )
        }
    }

    pub(crate) const fn geometry(&self) -> LogGeometry {
        self.geometry
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
