//! The kernel's own mapping of a context's ring.
//!
//! The ring is a kernel memfd, mapped shared into the guest at the context id
//! and, here, into the emulator. The second mapping is what Linux's
//! `ring_folios` are: completions are written through it from whichever thread
//! completes them -- the `IOCB_CMD_POLL` service thread has no address space
//! at all -- and they are visible at once to a guest that reaps from the ring
//! without a syscall, which libaio and fio both do. It also keeps working after
//! the guest makes its mapping read-only, as Linux's does.
//!
//! The guest writes `head` (and may scribble on anything else) while this
//! reads it, so every access is an atomic on the shared page; there is no
//! reference to plain memory a guest store could race.

use std::ffi::c_void;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use guest_errno::Errno;

use crate::abi::{self, IoEvent, header};

pub(crate) struct Ring {
    base: NonNull<c_void>,
    len: usize,
    nr: u32,
}

// SAFETY: the mapping is shared memory reached only through atomics, and it is
// unmapped once, by `Drop`, when nothing can reach it any more.
unsafe impl Send for Ring {}
// SAFETY: as `Send`.
unsafe impl Sync for Ring {}

impl Ring {
    /// Map `pages` pages of the ring file read-write and shared.
    pub fn map(file: BorrowedFd<'_>, pages: u64, nr: u32) -> Result<Ring, Errno> {
        let len = usize::try_from(pages * abi::PAGE).map_err(|_| Errno::ENOMEM)?;
        // SAFETY: a fresh shared mapping of a file this crate owns, at an
        // address the host picks; nothing aliases it until it is returned.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(Errno::ENOMEM);
        }
        let base = NonNull::new(p).ok_or(Errno::ENOMEM)?;
        Ok(Ring { base, len, nr })
    }

    fn word(&self, i: usize) -> &AtomicU32 {
        debug_assert!(i < header::BYTES / 4);
        // SAFETY: inside the first page of a live mapping, four-byte aligned,
        // and only ever accessed atomically.
        unsafe { &*self.base.as_ptr().cast::<AtomicU32>().add(i) }
    }

    fn slot(&self, i: u32) -> &[AtomicU64; 4] {
        assert!(i < self.nr, "a ring slot past nr");
        let at = header::BYTES + i as usize * abi::EVENT_SIZE;
        debug_assert!(at + abi::EVENT_SIZE <= self.len);
        // SAFETY: `nr` slots fit in `len` by construction (`abi::geometry`),
        // each eight-byte aligned, only ever accessed atomically.
        unsafe { &*self.base.as_ptr().cast::<u8>().add(at).cast::<[AtomicU64; 4]>() }
    }

    /// `aio_setup_ring`'s header, and `ioctx_add_table`'s id.
    pub fn init(&self, id: u32) {
        self.word(header::ID).store(id, Ordering::Relaxed);
        self.word(header::NR).store(self.nr, Ordering::Relaxed);
        self.word(header::HEAD).store(0, Ordering::Relaxed);
        self.word(header::TAIL).store(0, Ordering::Relaxed);
        self.word(header::MAGIC).store(abi::RING_MAGIC, Ordering::Relaxed);
        self.word(header::COMPAT_FEATURES).store(abi::RING_COMPAT_FEATURES, Ordering::Relaxed);
        self.word(header::INCOMPAT_FEATURES).store(abi::RING_INCOMPAT_FEATURES, Ordering::Relaxed);
        self.word(header::HEADER_LENGTH).store(header::BYTES as u32, Ordering::Release);
    }

    pub fn nr(&self) -> u32 {
        self.nr
    }

    /// The guest's `head`, which the guest owns.
    pub fn head(&self) -> u32 {
        self.word(header::HEAD).load(Ordering::Acquire)
    }

    pub fn set_head(&self, head: u32) {
        self.word(header::HEAD).store(head, Ordering::Release);
    }

    /// The `tail` the guest sees. Linux reads this one back when it reaps,
    /// not its private copy, so a guest that scribbles on it is answered from
    /// the scribble; `aio_probe` measures it.
    pub fn tail(&self) -> u32 {
        self.word(header::TAIL).load(Ordering::Acquire)
    }

    /// Write one event at `at` and then publish `tail`: the event before the
    /// index, which is the order a reader on another CPU relies on.
    pub fn push(&self, at: u32, ev: &IoEvent, tail: u32) {
        for (w, v) in self.slot(at).iter().zip(ev.words()) {
            w.store(v, Ordering::Relaxed);
        }
        self.word(header::TAIL).store(tail, Ordering::Release);
    }

    pub fn get(&self, at: u32) -> IoEvent {
        let s = self.slot(at);
        IoEvent::from_words(std::array::from_fn(|i| s[i].load(Ordering::Relaxed)))
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: the mapping `map` made, unmapped once.
        unsafe { libc::munmap(self.base.as_ptr(), self.len) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    fn file(pages: u64) -> std::fs::File {
        let f = tempfile();
        f.set_len(pages * abi::PAGE).unwrap();
        f
    }

    fn tempfile() -> std::fs::File {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("aio-ring-test-{}-{:?}", std::process::id(), std::thread::current().id()));
        let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        f
    }

    /// The header the guest reads, word by word: what `aio_probe` printed on a
    /// real kernel.
    #[test]
    fn the_header_is_linuxs() {
        let f = file(1);
        let r = Ring::map(f.as_fd(), 1, 127).unwrap();
        r.init(3);
        let words: Vec<u32> = (0..8).map(|i| r.word(i).load(Ordering::Relaxed)).collect();
        assert_eq!(words, [3, 127, 0, 0, 0xa10a10a1, 1, 0, 32]);
    }

    /// A second mapping of the file sees an event and the new tail: the guest's
    /// view is one of those.
    #[test]
    fn a_push_is_visible_through_another_mapping() {
        let f = file(1);
        let a = Ring::map(f.as_fd(), 1, 127).unwrap();
        let b = Ring::map(f.as_fd(), 1, 127).unwrap();
        a.init(0);
        let ev = IoEvent { data: 7, obj: 8, res: 9, res2: 0 };
        a.push(0, &ev, 1);
        assert_eq!(b.tail(), 1);
        assert_eq!(b.get(0), ev);
    }

    #[test]
    #[should_panic(expected = "past nr")]
    fn a_slot_past_nr_is_refused() {
        let f = file(1);
        let r = Ring::map(f.as_fd(), 1, 127).unwrap();
        r.get(127);
    }
}
