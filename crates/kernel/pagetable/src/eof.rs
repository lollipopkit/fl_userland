//! A file mapping's pages past the end of its file, which raise `SIGBUS`.
//!
//! Linux decides at fault time: a page whose file offset is at or past
//! `i_size` rounded up to a page has nothing to map, and the access gets
//! `SIGBUS`/`BUS_ADRERR` (a syscall reaching it gets `EFAULT`). A truncation
//! unmaps the pages it cut off, private copies included, so the next touch
//! faults again and asks again.
//!
//! The host cannot answer that question for the guest. Its page is 16 KB on
//! Apple silicon, so up to three guest pages past the end sit in the host page
//! that holds the end and read as zeroes; a host `MAP_PRIVATE` mapping keeps
//! answering after a truncation; and realfs backed every page past the end at
//! map time with anonymous memory until 2026-11-12. So the TLB miss asks:
//! [`Eof::past`] runs in `mem_ptr` for every page of a file mapping, which is
//! the miss path and never the hit.
//!
//! What it costs there, for a page that is not anonymous, is one load of
//! [`SHRINKS`] and one of the mapping's cached bound. The bound is a page count the file was known to reach at a
//! shrink generation; a page below it at the same generation needs nothing
//! more, and anything else asks the host for the size once and stores the
//! answer. A grown file is seen the first time a page past the old bound is
//! touched, because a page past the bound always asks.
//!
//! A shrink is the one change that has to reach the mapping, and it does
//! through [`file_shrunk`], which every truncation in this kernel calls when
//! it made a file shorter (realfs's, which fakefs and memfd forward to,
//! fakefs's by-path one, and tmpfs's for a file something has mapped). When
//! the file is mapped anywhere -- [`MAPPED`] counts mappings by host file --
//! it moves [`SHRINKS`], so every bound goes stale, and bumps every address
//! space's `mmu.changes`, so every cached translation goes too and the next
//! access misses. A truncation made by the host behind this kernel's back is
//! not seen until something else moves the generation.
//!
//! # Private copies are zapped
//!
//! Linux's truncation also drops the private copies of the pages it cut off
//! (`truncate_pagecache` unmaps with `even_cows`), so a page written through
//! a `MAP_PRIVATE` mapping, cut off and then grown back reads the file again
//! -- zeroes -- and not what was written. Asking the size at the next touch
//! cannot tell that a shrink and a growth both happened in between, so the
//! shrink says so itself: every copy registers a [`Zap`] under its file, and
//! [`file_shrunk`] sets the ones at or past the new end. The fault path finds
//! the mark and puts the file's page back (`SpaceMut::revert_copy`).

use std::collections::BTreeMap;
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use crate::ffi;

/// How many times a mapped file has shrunk. Compared for equality only,
/// so wrapping is harmless short of exactly 2^32 shrinks between two touches.
static SHRINKS: AtomicU32 = AtomicU32::new(0);

/// What is known about one mapped host file.
#[derive(Default)]
struct File {
    /// Live [`Eof`]s for it.
    eofs: usize,
    /// The private copies of its pages that no shrink has zapped yet.
    copies: Vec<Weak<Zap>>,
}

/// Mapped host files by `(st_dev, st_ino)`: what lets a truncation of a file
/// nothing maps cost nothing beyond a lookup.
static MAPPED: Mutex<BTreeMap<(u64, u64), File>> = Mutex::new(BTreeMap::new());

/// A private copy of one file page, which a shrink past it marks.
#[derive(Debug)]
pub(crate) struct Zap {
    /// The file page the copy was made from.
    page: u64,
    zapped: AtomicBool,
}

impl Zap {
    /// A shrink has cut the page off since the copy was made.
    pub(crate) fn zapped(&self) -> bool {
        self.zapped.load(Ordering::Acquire)
    }
}

/// Every live address space's `mmu`, for a shrink to invalidate. `mem_init`
/// adds one and `mem_destroy` removes it before the space is torn down, under
/// this lock, which is what keeps the pointers here live.
static SPACES: Mutex<Vec<SpacePtr>> = Mutex::new(Vec::new());

struct SpacePtr(*const ffi::mmu);

// SAFETY: only its `changes` atomic is touched, and only under `SPACES`,
// which `mem_destroy` takes to remove it before the `mmu` goes.
unsafe impl Send for SpacePtr {}

pub(crate) fn space_created(mmu: *const ffi::mmu) {
    SPACES.lock().unwrap_or_else(PoisonError::into_inner).push(SpacePtr(mmu));
}

pub(crate) fn space_destroyed(mmu: *const ffi::mmu) {
    SPACES.lock().unwrap_or_else(PoisonError::into_inner).retain(|s| s.0 != mmu);
}

/// The host file a mapping of `fd` shows; see `FdOps::mapped_file`.
fn host_of(fd: &ffi::fd) -> Option<BorrowedFd<'_>> {
    fd.ops.and_then(|ops| ops.mapped_file(fd))
}

/// The host file a descriptor is open on.
fn identity(host: BorrowedFd<'_>) -> Option<(u64, u64)> {
    let st = rustix::fs::fstat(host).ok()?;
    Some((st.st_dev as u64, st.st_ino))
}

/// The host file `(st_dev, st_ino)` has been made `size` bytes long, shorter
/// than it was, through this kernel.
///
/// Cheap when nothing maps it; when something does, every page of every file
/// mapping asks again on its next touch, and every private copy of a page at
/// or past the new end is marked to be dropped.
pub fn file_shrunk(dev: u64, ino: u64, size: u64) {
    {
        let mut mapped = MAPPED.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(file) = mapped.get_mut(&(dev, ino)) else {
            return;
        };
        let end = size.div_ceil(ffi::PAGE_SIZE as u64);
        file.copies.retain(|copy| {
            let Some(copy) = copy.upgrade() else {
                return false;
            };
            let cut = copy.page >= end;
            if cut {
                copy.zapped.store(true, Ordering::Release);
            }
            !cut
        });
    }
    // Before the TLBs: a miss that follows the bump below must find the
    // bounds stale.
    SHRINKS.fetch_add(1, Ordering::AcqRel);
    for space in SPACES.lock().unwrap_or_else(PoisonError::into_inner).iter() {
        // SAFETY: see `SPACES`.
        unsafe { (*space.0).changes.fetch_add(1, Ordering::Release) };
    }
}

/// The file whose size bounds a mapping's pages, and what is known of it.
#[derive(Debug)]
pub(crate) struct Eof {
    /// The mapping's file. A private copy of one of its pages is bounded
    /// through the mapping it was copied from, which it keeps alive.
    fd: fs_fdobj::Owned,
    /// The file offset of the mapping's first host byte.
    file_offset: usize,
    id: (u64, u64),
    /// `SHRINKS << 32 | pages`: the file was at least `pages` guest pages long
    /// at that generation. Zero pages, the start, is "ask".
    known: AtomicU64,
}

impl Eof {
    /// `None` for a descriptor with no host file behind it, which cannot be
    /// asked and is never past its end.
    pub(crate) fn new(fd: fs_fdobj::Owned, file_offset: usize) -> Option<Eof> {
        let id = identity(host_of(&fd)?)?;
        MAPPED.lock().unwrap_or_else(PoisonError::into_inner).entry(id).or_default().eofs += 1;
        Some(Eof { fd, file_offset, id, known: AtomicU64::new(0) })
    }

    /// The mark for a private copy of the page `offset` bytes into this
    /// mapping. The copy keeps this mapping alive, and so the file's entry.
    pub(crate) fn copy(&self, offset: usize) -> Arc<Zap> {
        let page = ((self.file_offset + offset) as u64) >> ffi::PAGE_BITS;
        let zap = Arc::new(Zap { page, zapped: AtomicBool::new(false) });
        let mut mapped = MAPPED.lock().unwrap_or_else(PoisonError::into_inner);
        let copies = &mut mapped.entry(self.id).or_default().copies;
        // Dead marks are swept when the list would grow, so it stays within
        // twice the live copies.
        if copies.len() == copies.capacity() {
            copies.retain(|c| c.strong_count() > 0);
        }
        copies.push(Arc::downgrade(&zap));
        zap
    }

    /// Is the page `offset` bytes into the mapping wholly past the end of the
    /// file? A host that cannot say is taken to mean no.
    pub(crate) fn past(&self, offset: usize) -> bool {
        let page = ((self.file_offset + offset) as u64) >> ffi::PAGE_BITS;
        let generation = SHRINKS.load(Ordering::Acquire);
        let known = self.known.load(Ordering::Acquire);
        if (known >> 32) as u32 == generation && page < known & 0xffff_ffff {
            return false;
        }
        let Some(size) = host_of(&self.fd).and_then(|h| rustix::fs::fstat(h).ok()).map(|st| st.st_size as u64)
        else {
            return false;
        };
        let pages = size.div_ceil(ffi::PAGE_SIZE as u64);
        // The generation read before the size: a shrink in between leaves a
        // bound that is already stale, never one that is newer than it says.
        self.known.store(u64::from(generation) << 32 | pages.min(u64::from(u32::MAX)), Ordering::Release);
        page >= pages
    }
}

impl Drop for Eof {
    fn drop(&mut self) {
        let mut mapped = MAPPED.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(file) = mapped.get_mut(&self.id) {
            file.eofs -= 1;
            if file.eofs == 0 {
                mapped.remove(&self.id);
            }
        }
    }
}
