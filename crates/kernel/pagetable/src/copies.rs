//! Where copy-on-write copies live: guest-page slots carved out of host pages.
//!
//! A copy is one guest page, 4 KB, and a host page is 16 KB on Apple silicon.
//! Each copy was an `mmap` of its own until 2026-11-12, which held four times
//! the memory the copy needed and cost a host map, a zero-fill fault and an
//! unmap per page. That mattered once a private file mapping became
//! copy-on-write from the start (realfs's `map_host`): every page an `execve`
//! relocates is a copy, and 300 runs of `apk --version` took 6.1% longer with
//! one host page per copy, against no measurable difference with slots
//! (interleaved release runs, 2026-11-12). Slots are handed out in order from
//! the current host page, and a host page is unmapped when the last copy in it
//! goes.
//!
//! A slot is never reused while its host page lives, so one long-lived copy
//! can keep a host page of dead ones: at worst what one `mmap` per copy cost.
//!
//! **The host page stays read-write.** Its slots belong to different
//! mappings, and to different processes after a fork, so a host `mprotect` of
//! one would change its neighbours; the page table keeps a copy's protection
//! in its flags alone (`SpaceMut::change_protection`).

use std::sync::{Arc, Mutex, PoisonError};

use crate::ffi;
use crate::memlock::host_page_size;

const PAGE: usize = ffi::PAGE_SIZE as usize;

/// One host page of slots, unmapped with the last [`Slot`] in it.
#[derive(Debug)]
pub(crate) struct Chunk(*mut u8);

// SAFETY: a host mapping owned by this value; its contents are guest memory,
// guarded by the `mem->lock` of each address space a slot is mapped in.
unsafe impl Send for Chunk {}
// SAFETY: as `Send`; nothing here is written through `&Chunk`.
unsafe impl Sync for Chunk {}

impl Drop for Chunk {
    fn drop(&mut self) {
        // SAFETY: the host page `alloc` mapped, which no slot reaches now.
        unsafe { libc::munmap(self.0.cast(), host_page_size()) };
    }
}

/// One guest page of a [`Chunk`].
pub(crate) struct Slot {
    pub(crate) chunk: Arc<Chunk>,
    pub(crate) host: *mut u8,
}

/// The host page slots are being handed out from, and how many it has given.
struct Current(Option<(Arc<Chunk>, usize)>);

// SAFETY: as `Chunk`.
unsafe impl Send for Current {}

static CURRENT: Mutex<Current> = Mutex::new(Current(None));

/// A fresh slot, or `None` when the host will not map another page.
pub(crate) fn alloc() -> Option<Slot> {
    let slots = host_page_size() / PAGE;
    let mut current = CURRENT.lock().unwrap_or_else(PoisonError::into_inner);
    if !matches!(&current.0, Some((_, used)) if *used < slots) {
        // SAFETY: a fresh anonymous mapping, which aliases nothing.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                host_page_size(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            crate::note_host_map_failure(host_page_size());
            return None;
        }
        current.0 = Some((Arc::new(Chunk(base.cast())), 0));
    }
    let (chunk, used) = current.0.as_mut().expect("a host page with a free slot is current");
    let host = chunk.0.wrapping_add(*used * PAGE);
    *used += 1;
    Some(Slot { chunk: Arc::clone(chunk), host })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_distinct_guest_pages_and_share_host_pages() {
        let a = alloc().unwrap();
        let b = alloc().unwrap();
        assert_ne!(a.host, b.host);
        assert_eq!((a.host as usize) % PAGE, 0);
        if host_page_size() > PAGE && Arc::ptr_eq(&a.chunk, &b.chunk) {
            assert_eq!(b.host as usize - a.host as usize, PAGE);
        }
        // Writable, and the write stays in its slot.
        unsafe {
            a.host.write_bytes(1, PAGE);
            b.host.write_bytes(2, PAGE);
            assert_eq!(*a.host.add(PAGE - 1), 1);
        }
    }
}
