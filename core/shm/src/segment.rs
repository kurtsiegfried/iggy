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
//! A segment is reachable only through its fd, passed over the
//! connection's unix socket, so segment lifetime is exactly fd
//! lifetime and a crashed peer leaks nothing. On Linux the backing is
//! `memfd_create` (nameless from birth) with shrink and grow sealed at
//! creation, so a hostile peer holding the same fd cannot resize the
//! backing pages out from under the honest side's mapping. Elsewhere
//! the backing is a tmpfile in the per-user temp directory, unlinked
//! immediately after creation; that platform has no sealing API, which
//! is one of the reasons non-Linux targets are a development platform,
//! not a hardened deployment target.

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
    /// Creates a fresh zero-filled segment of `len` bytes, fully
    /// provisioned, and (on Linux) sealed against resizing.
    ///
    /// # Errors
    ///
    /// Returns the underlying OS error when the backing fd cannot be
    /// created, sized, provisioned, or sealed, or
    /// [`io::ErrorKind::InvalidInput`] when `len` does not fit the
    /// platform's `off_t`.
    pub fn allocate(len: usize) -> io::Result<Self> {
        let fd = create_anonymous_fd()?;
        let file_len = off_t_len(len)?;
        if unsafe { libc::ftruncate(fd.as_raw_fd(), file_len) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // Provision the pages now so exhaustion surfaces here as an
        // error instead of as SIGBUS on the first touch of a sparse
        // hole mid-append.
        preallocate(&fd, file_len)?;
        seal_resizing(&fd)?;
        Ok(Self { fd, len })
    }

    /// Adopts an fd received from the peer, refusing one whose size
    /// disagrees with the negotiated layout or (on Linux) one whose
    /// backing is not sealed against resizing.
    ///
    /// The seal requirement doubles as a provenance check on Linux:
    /// only memfd-style backings support seals at all, so a regular
    /// file or a fd from a hostile filesystem is rejected outright.
    /// The size check alone is inherently TOCTOU; the seals are what
    /// make it durable.
    ///
    /// # Errors
    ///
    /// Returns the underlying OS error when the fd cannot be
    /// inspected, or [`io::ErrorKind::InvalidData`] on a size
    /// mismatch or missing seals.
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
        require_resize_seals(&fd)?;
        // recvmsg installs the fd without close-on-exec unless the
        // receiver asked for it, and only Linux can ask atomically
        // (MSG_CMSG_CLOEXEC). Set it here so every adopted segment
        // honors the same no-inherit invariant the creating side
        // establishes with MFD_CLOEXEC: a child of a fork+exec must
        // not keep the segment, and the admission slot it pins, alive
        // past the parent's disconnect. On platforms without the
        // atomic receive flag a thread racing fork+exec between
        // recvmsg and this call can still leak; that residual window
        // is the platform's, not this adopter's.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
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
        let mapping = Self {
            base: NonNull::new(base.cast::<u8>())
                .ok_or_else(|| io::Error::other("mmap returned a null mapping"))?,
            len: segment.len,
        };
        // A forked child inheriting this writable mapping would be a
        // third party on a log whose contract allows exactly two;
        // exclude the range from fork inheritance.
        exclude_from_fork(&mapping)?;
        Ok(mapping)
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
        // Subtraction form so a huge offset cannot wrap the addition
        // into a passing comparison on 32-bit targets.
        assert!(crate::layout::COUNTERS_BLOCK_SIZE <= self.len);
        assert!(counters_offset <= self.len - crate::layout::COUNTERS_BLOCK_SIZE);
        assert!(data_len <= self.len);
        assert!(data_offset <= self.len - data_len);
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

fn off_t_len(len: usize) -> io::Result<libc::off_t> {
    libc::off_t::try_from(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("segment of {len} bytes exceeds this platform's file offset range"),
        )
    })
}

#[cfg(target_os = "linux")]
fn create_anonymous_fd() -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::memfd_create(
            c"iggy-shm".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Safety: memfd_create returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// No memfd outside Linux: an unlinked tmpfile gives the same
/// anonymous lifetime after a brief named window in the per-user temp
/// directory (0700, same uid), which is why this stays the
/// development path rather than a hardened one.
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
    if unsafe { libc::unlink(template_bytes.as_ptr().cast::<libc::c_char>()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // The libc crate binds no mkostemp on this platform, so
    // close-on-exec arrives one call late; a fork+exec racing this
    // window inherits the fd. Accepted on the development platform.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Pre-fault the whole backing so ENOSPC/ENOMEM surface at allocation
/// time as an error instead of as SIGBUS on first touch.
#[cfg(target_os = "linux")]
fn preallocate(fd: &OwnedFd, file_len: libc::off_t) -> io::Result<()> {
    if unsafe { libc::fallocate(fd.as_raw_fd(), 0, 0, file_len) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// No fallocate outside Linux; the tmpfile stays sparse and pressure
/// surfaces as SIGBUS on first touch, accepted on the development
/// platform.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
// Signature parity with the Linux implementation.
fn preallocate(_fd: &OwnedFd, _file_len: libc::off_t) -> io::Result<()> {
    Ok(())
}

/// Seal the backing against resizing, and against further seals, so
/// the peer holding the same fd can neither shrink the pages out from
/// under the honest side's mapping (SIGBUS) nor add a write seal of
/// its own.
#[cfg(target_os = "linux")]
fn seal_resizing(fd: &OwnedFd) -> io::Result<()> {
    let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
// Signature parity with the Linux implementation.
fn seal_resizing(_fd: &OwnedFd) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_resize_seals(fd: &OwnedFd) -> io::Result<()> {
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 {
        // Regular files and most filesystems do not support seals at
        // all, so this branch also rejects an fd of the wrong kind.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "segment fd does not support seals; not an acceptable backing",
        ));
    }
    if seals & (libc::F_SEAL_SHRINK | libc::F_SEAL_GROW) != libc::F_SEAL_SHRINK | libc::F_SEAL_GROW
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("segment fd is not sealed against resizing (seals {seals:#x})"),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
// Signature parity with the Linux implementation.
fn require_resize_seals(_fd: &OwnedFd) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn exclude_from_fork(mapping: &SegmentMapping) -> io::Result<()> {
    let advised = unsafe {
        libc::madvise(
            mapping.base.as_ptr().cast::<libc::c_void>(),
            mapping.len,
            libc::MADV_DONTFORK,
        )
    };
    if advised < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The libc crate binds no minherit on this platform, so a forked
/// child does inherit the mapping here. Accepted on the development
/// platform; the two-party contract is enforced by `MADV_DONTFORK`
/// only on Linux.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
// Signature parity with the Linux implementation.
fn exclude_from_fork(_mapping: &SegmentMapping) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{LogGeometry, MIN_REGION_CAPACITY, SEGMENT_PAGE_SIZE};
    use crate::mem::LogMemory;

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot map file-backed segments")]
    fn received_fd_with_matching_size_is_adopted() {
        let segment = AnonymousSegment::allocate(SEGMENT_PAGE_SIZE).unwrap();
        let cloned = segment.as_fd().try_clone_to_owned().unwrap();
        let adopted = AnonymousSegment::from_received_fd(cloned, SEGMENT_PAGE_SIZE).unwrap();
        assert_eq!(adopted.len(), SEGMENT_PAGE_SIZE);
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot operate on file-backed segments")]
    fn an_adopted_fd_is_close_on_exec() {
        let segment = AnonymousSegment::allocate(SEGMENT_PAGE_SIZE).unwrap();
        // A plain dup drops FD_CLOEXEC, exactly like an fd freshly
        // installed by a recvmsg without MSG_CMSG_CLOEXEC.
        let raw = unsafe { libc::dup(segment.as_fd().as_raw_fd()) };
        assert!(raw >= 0, "dup failed");
        // Safety: dup just returned this fd; nothing else owns it.
        let received = unsafe { OwnedFd::from_raw_fd(raw) };
        let flags = unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            0,
            "the dup must start without close-on-exec for this test to prove anything"
        );

        let adopted = AnonymousSegment::from_received_fd(received, SEGMENT_PAGE_SIZE).unwrap();
        let flags = unsafe { libc::fcntl(adopted.as_fd().as_raw_fd(), libc::F_GETFD) };
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "adoption must set close-on-exec so a fork+exec child cannot keep the segment"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore = "miri cannot operate on file-backed segments")]
    fn seals_block_peer_resizing() {
        let segment = AnonymousSegment::allocate(SEGMENT_PAGE_SIZE).unwrap();
        let _mapping = SegmentMapping::map(&segment).unwrap();

        // The hostile-peer move: shrink the backing after both sides
        // mapped. The creation-time seal must refuse it.
        let shrunk = unsafe { libc::ftruncate(segment.as_fd().as_raw_fd(), 0) };
        assert_eq!(shrunk, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore = "miri cannot operate on file-backed segments")]
    fn unsealed_fd_is_rejected_on_adoption() {
        let raw_fd =
            unsafe { libc::memfd_create(c"iggy-shm-unsealed".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(raw_fd >= 0);
        // Safety: memfd_create returned a fresh owned fd.
        let unsealed = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let file_len = libc::off_t::try_from(SEGMENT_PAGE_SIZE).unwrap();
        assert_eq!(
            unsafe { libc::ftruncate(unsealed.as_raw_fd(), file_len) },
            0
        );

        let error = AnonymousSegment::from_received_fd(unsealed, SEGMENT_PAGE_SIZE).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

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
