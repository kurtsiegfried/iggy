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

//! Anonymous shared segments and their mappings.
//!
//! A segment never has a filesystem name another process could open:
//! `memfd_create` on Linux, an unlinked tmpfile elsewhere. The only
//! way in is the fd, passed over the connection's unix socket, so
//! segment lifetime is exactly fd lifetime and a crashed peer leaks
//! nothing.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;

use crate::layout::SegmentLayout;
use crate::mem::RawLogMemory;

#[cfg(not(target_os = "linux"))]
use std::env;

#[derive(Debug)]
pub struct AnonymousSegment {
    fd: OwnedFd,
    len: usize,
}

impl AnonymousSegment {
    /// Creates a fresh zero-filled segment of `len` bytes.
    ///
    /// # Errors
    ///
    /// Returns the underlying OS error when the backing fd cannot be
    /// created or sized.
    pub fn allocate(len: usize) -> io::Result<Self> {
        let fd = create_anonymous_fd()?;
        #[allow(clippy::cast_possible_wrap)]
        // Segment sizes are far below off_t's positive range.
        let truncated = unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) };
        if truncated < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, len })
    }

    /// Adopts an fd received from the peer, refusing one whose size
    /// disagrees with the negotiated layout.
    ///
    /// # Errors
    ///
    /// Returns the underlying OS error when the fd cannot be stat'ed,
    /// or [`io::ErrorKind::InvalidData`] on a size mismatch.
    pub fn from_received_fd(fd: OwnedFd, expected_len: usize) -> io::Result<Self> {
        // Safety: zeroed stat buffer is a valid out-parameter.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &raw mut stat) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(stat.st_size) != Ok(expected_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "segment fd holds {} bytes, expected {expected_len}",
                    stat.st_size
                ),
            ));
        }
        Ok(Self {
            fd,
            len: expected_len,
        })
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsFd for AnonymousSegment {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// A shared mapping of one segment. Unmapped on drop; the backing
/// memory itself lives until the last fd and mapping are gone.
#[derive(Debug)]
pub struct SegmentMapping {
    base: NonNull<u8>,
    len: usize,
}

// The mapping is process-private state over shared memory; moving the
// handle between threads is sound.
unsafe impl Send for SegmentMapping {}

impl SegmentMapping {
    /// # Errors
    ///
    /// Returns the underlying OS error when the mapping fails.
    pub fn map(segment: &AnonymousSegment) -> io::Result<Self> {
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                segment.len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                segment.fd.as_raw_fd(),
                0,
            )
        };
        if std::ptr::eq(base, libc::MAP_FAILED) {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            base: NonNull::new(base.cast::<u8>())
                .ok_or_else(|| io::Error::other("mmap returned a null mapping"))?,
            len: segment.len,
        })
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Base pointer of the mapping; valid while `self` is alive.
    #[must_use]
    pub const fn as_ptr(&self) -> NonNull<u8> {
        self.base
    }

    /// Raw log memory for the client-to-server log of this segment.
    ///
    /// # Safety
    ///
    /// The caller must uphold the [`RawLogMemory::new`] contract: the
    /// mapping must outlive the returned value, and across both
    /// processes at most one producer and one consumer may operate on
    /// this log.
    #[must_use]
    pub unsafe fn client_to_server_memory(&self, layout: &SegmentLayout) -> RawLogMemory {
        // Safety: offsets come from the validated layout and are
        // in-bounds for a mapping of layout.total_len bytes.
        unsafe {
            self.log_memory(
                layout.client_to_server_counters_offset,
                layout.client_to_server_data_offset,
                layout.client_to_server.data_len(),
            )
        }
    }

    /// Raw log memory for the server-to-client log of this segment.
    ///
    /// # Safety
    ///
    /// Same contract as [`SegmentMapping::client_to_server_memory`].
    #[must_use]
    pub unsafe fn server_to_client_memory(&self, layout: &SegmentLayout) -> RawLogMemory {
        // Safety: offsets come from the validated layout and are
        // in-bounds for a mapping of layout.total_len bytes.
        unsafe {
            self.log_memory(
                layout.server_to_client_counters_offset,
                layout.server_to_client_data_offset,
                layout.server_to_client.data_len(),
            )
        }
    }

    unsafe fn log_memory(
        &self,
        counters_offset: usize,
        data_offset: usize,
        data_len: usize,
    ) -> RawLogMemory {
        assert!(counters_offset + crate::layout::COUNTERS_BLOCK_SIZE <= self.len);
        assert!(data_offset + data_len <= self.len);
        // Safety: in-bounds per the asserts; validity and exclusivity
        // are the caller's contract, forwarded from the public unsafe
        // constructors.
        unsafe {
            RawLogMemory::new(
                NonNull::new_unchecked(self.base.as_ptr().add(counters_offset)),
                crate::layout::COUNTERS_BLOCK_SIZE,
                NonNull::new_unchecked(self.base.as_ptr().add(data_offset)),
                data_len,
            )
        }
    }
}

impl Drop for SegmentMapping {
    fn drop(&mut self) {
        // Safety: base/len came from a successful mmap of exactly this
        // range and nothing else unmaps it.
        unsafe {
            libc::munmap(self.base.as_ptr().cast::<libc::c_void>(), self.len);
        }
    }
}

#[cfg(target_os = "linux")]
fn create_anonymous_fd() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::memfd_create(c"iggy-shm".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Safety: memfd_create returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(not(target_os = "linux"))]
fn create_anonymous_fd() -> io::Result<OwnedFd> {
    let template = env::temp_dir().join("iggy-shm-XXXXXX");
    let mut template_bytes = template.into_os_string().into_encoded_bytes();
    template_bytes.push(0);
    let fd = unsafe { libc::mkstemp(template_bytes.as_mut_ptr().cast::<libc::c_char>()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Safety: mkstemp returned a fresh owned fd.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // Unlink immediately: the segment must never be openable by name,
    // and the kernel reclaims it once the last fd and mapping close.
    if unsafe { libc::unlink(template_bytes.as_ptr().cast::<libc::c_char>()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{LogGeometry, MIN_REGION_CAPACITY, SEGMENT_PAGE_SIZE};
    use crate::mem::LogMemory;

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot map file-backed segments")]
    fn two_mappings_of_one_segment_share_writes() {
        let segment = AnonymousSegment::allocate(SEGMENT_PAGE_SIZE).unwrap();
        let first = SegmentMapping::map(&segment).unwrap();
        let second = SegmentMapping::map(&segment).unwrap();

        // Safety: in-bounds write through one mapping, read through
        // the other; no aliasing references exist.
        unsafe {
            first.as_ptr().as_ptr().add(100).write(42);
            assert_eq!(second.as_ptr().as_ptr().add(100).read(), 42);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot map file-backed segments")]
    fn fresh_segments_are_zero_filled() {
        let segment = AnonymousSegment::allocate(SEGMENT_PAGE_SIZE).unwrap();
        let mapping = SegmentMapping::map(&segment).unwrap();
        let mut contents = vec![0xFFu8; SEGMENT_PAGE_SIZE];
        // Safety: in-bounds read of the whole fresh mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(
                mapping.as_ptr().as_ptr(),
                contents.as_mut_ptr(),
                SEGMENT_PAGE_SIZE,
            );
        }
        assert!(contents.iter().all(|byte| *byte == 0));
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot map file-backed segments")]
    fn received_fd_size_is_validated() {
        let segment = AnonymousSegment::allocate(SEGMENT_PAGE_SIZE).unwrap();
        let error =
            AnonymousSegment::from_received_fd(segment.fd, 2 * SEGMENT_PAGE_SIZE).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot map file-backed segments")]
    fn segment_layout_views_are_disjoint() {
        let geometry = LogGeometry {
            region_capacity: MIN_REGION_CAPACITY,
        };
        let layout = SegmentLayout::compute(geometry, geometry).unwrap();
        let segment = AnonymousSegment::allocate(layout.total_len).unwrap();
        let mapping = SegmentMapping::map(&segment).unwrap();
        // Safety: single-threaded test, one logical party per view.
        let client_to_server = unsafe { mapping.client_to_server_memory(&layout) };
        let server_to_client = unsafe { mapping.server_to_client_memory(&layout) };

        client_to_server.write_data(32, &[1, 2, 3]);
        let mut readback = [9u8; 3];
        server_to_client.read_data(32, &mut readback);
        assert_eq!(readback, [0, 0, 0]);
    }
}
