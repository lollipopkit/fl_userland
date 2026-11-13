//! Mapping a host file into guest memory, and polling a host descriptor.
//!
//! The guest's page size is 4 KB and the host's, on Apple silicon, is 16 KB.
//! Everything awkward here comes from that: a guest mapping can start at an
//! offset the host cannot be asked to map from, and the host page that holds
//! a file's end can hold guest pages wholly past it.

use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::raw::c_int;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::OFlags;

use crate::errno;
use crate::ffi;

/// The guest page size, which is not the host's. `emu/mmu.h`.
const GUEST_PAGE: u64 = 1 << ffi::PAGE_BITS;

/// The host page size.
fn host_page() -> u64 {
    pagetable::memlock::host_page_size() as u64
}

/// What the guest asked for, resolved against the host's page size.
struct Window {
    /// Where the host mapping starts: the guest's offset rounded down to a
    /// host page.
    offset: i64,
    /// How far into that mapping the guest's data begins.
    correction: usize,
    /// Total bytes to map.
    size: usize,
}

fn window(offset: i64, pages: u64) -> Window {
    let host_page = host_page() as i64;
    let aligned = (offset / host_page) * host_page;
    let correction = (offset - aligned) as usize;
    Window {
        offset: aligned,
        correction,
        size: (pages * GUEST_PAGE) as usize + correction,
    }
}

/// Whether a mapping is private, and so shown through a read-only shared
/// host mapping and copied on the guest's first store (below).
fn private(flags: c_int) -> bool {
    flags as u32 & ffi::MMAP_PRIVATE != 0
}

fn host_prot(prot: c_int, flags: c_int) -> c_int {
    // Always readable: the interpreter reads guest memory it has mapped even
    // where the guest itself may not.
    let mut host = libc::PROT_READ;
    if prot as u32 & ffi::P_WRITE != 0 && !private(flags) {
        host |= libc::PROT_WRITE;
    }
    host
}

/// Hand a host mapping to the guest page tables, undoing it if they will not
/// take it.
///
/// `pt_map` allocates, so it can fail after the host mapping succeeded.
/// Returning its error straight out left the mapping with nothing holding a
/// reference to it, so repeated attempts under the memory pressure that caused
/// the failure consumed host address space that could not be reclaimed until
/// the process exited.
///
/// # Safety
/// `memory` must be a live mapping of `size` bytes.
unsafe fn publish(
    mem: *mut ffi::mem,
    start: ffi::page_t,
    pages: ffi::pages_t,
    memory: *mut u8,
    correction: usize,
    prot: c_int,
    size: usize,
) -> c_int {
    unsafe {
        let err = pagetable::pt_map(mem, start, pages, memory.cast(), correction, prot as u32);
        if err < 0 {
            libc::munmap(memory.cast(), size);
        }
        err
    }
}

/// The whole window is the host file's, past its end included.
///
/// A page wholly past the end is the page table's to refuse, at the touch, as
/// Linux does (`crates/kernel/pagetable`'s `eof` module). Until 2026-11-12 this
/// backed every such page with anonymous memory at map time, so the guest
/// read zeroes where Linux raises `SIGBUS`, and a file grown after the `mmap`
/// never showed its new pages there. The host maps past the end without
/// complaint; its own fault beyond the end-of-file page cannot be reached
/// while the page table refuses first, and within that page it fills with
/// zeroes, which is what the guest's last partial page reads on Linux too.
///
/// # Safety
/// Called by the VFS with a live descriptor and memory map.
pub unsafe fn realfs_mmap(fd: &ffi::fd,
    mem: *mut ffi::mem,
    start: ffi::page_t,
    pages: ffi::pages_t,
    offset: i64,
    prot: c_int,
    flags: c_int,
) -> c_int {
    let Some(host) = fd.host() else {
        return errno::EBADF;
    };
    // SAFETY: the caller's contract.
    unsafe { map_host(host, mem, start, pages, offset, prot, flags) }
}

/// Map `pages` of the host file `host` from `offset` at guest page `start`.
///
/// **A private mapping is the host's shared one, read-only, with every page
/// copy-on-write.** A page the guest has not written is then the file's, as
/// on Linux, where it is the page cache's: a `pwrite` shows through it and a
/// truncation zeroes the tail of the page that holds the new end. Darwin's
/// own `MAP_PRIVATE` cannot give that. It keeps whatever a page held when
/// first touched, and a store copies the whole 16 KB host page, so one
/// guest page written froze the three beside it (`mmfault_probe`: a page
/// truncated to 100 bytes still read its old byte 200, and a later `pwrite`
/// never showed). The first store to a page is the page table's copy, one
/// guest page at a time (`crates/kernel/pagetable`'s `break_cow`); a read
/// costs nothing more than it did.
///
/// # Safety
/// `mem` is live and its lock is held for writing.
#[allow(clippy::too_many_arguments)]
pub unsafe fn map_host(host: BorrowedFd<'_>,
    mem: *mut ffi::mem,
    start: ffi::page_t,
    pages: ffi::pages_t,
    offset: i64,
    prot: c_int,
    flags: c_int,
) -> c_int {
    let w = window(offset, pages);
    // SAFETY: a fresh mapping of a host descriptor the caller holds.
    let memory = unsafe {
        libc::mmap(std::ptr::null_mut(), w.size, host_prot(prot, flags), libc::MAP_SHARED, host.as_raw_fd(), w.offset)
    };
    if memory == libc::MAP_FAILED {
        return errno::ENOMEM;
    }
    let prot = if private(flags) { prot | ffi::P_COW as c_int } else { prot };
    // SAFETY: `memory` is the `w.size` bytes just mapped.
    unsafe { publish(mem, start, pages, memory.cast(), w.correction, prot, w.size) }
}

/// The host events worth asking about for this descriptor.
///
/// The guest's `EPOLLRDHUP`. Not a host constant: Darwin has no such bit, and
/// on Linux it is `0x2000` — the same value, because both took it from the
/// same header.
const POLL_RDHUP: c_int = 1 << 13;

/// Asking for readability on a write-only descriptor, or the reverse, is what
/// produces `POLLNVAL`, so ask only for what the descriptor can do. An
/// availableable `F_GETFL` leaves both in, which is what the call would have
/// asked for anyway.
///
/// Separate from [`realfs_poll`] so that `fs/poll.c` can ask about a whole set
/// in one host call instead of one call per descriptor.
///
/// **Safe.** Its `# Safety` section said "called by the VFS with a live
/// descriptor", which is what the `&ffi::fd` says -- and the body dereferences
/// no pointer: it reads fields through the borrow and calls `fcntl` on an
/// integer, which answers `EBADF` rather than doing anything undefined. The
/// `unsafe` came off on 2026-09-16, with the caller that stopped having a
/// pointer to give it.
pub fn realfs_poll_events(fd: &ffi::fd) -> c_int {
    let access = fd.host().and_then(|host| rustix::fs::fcntl_getfl(host).ok());
    let access = access.map(|flags| flags & OFlags::RWMODE);
    let mut events = libc::POLLPRI;
    if access != Some(OFlags::WRONLY) {
        events |= libc::POLLIN;
    }
    if access != Some(OFlags::RDONLY) {
        events |= libc::POLLOUT;
    }
    events as c_int
}

/// Ask the host once, without waiting: `(ready, revents)`.
fn poll_now(host: BorrowedFd<'_>, events: libc::c_short) -> (bool, libc::c_short) {
    let mut p = [PollFd::from_borrowed_fd(host, PollFlags::from_bits_retain(events as _))];
    let ready = matches!(poll(&mut p, Some(&Timespec::default())), Ok(n) if n > 0);
    (ready, p[0].revents().bits() as libc::c_short)
}

/// What the host said about a descriptor, corrected for what a guest expects.
///
/// Answers -1 when the host reported `POLLNVAL`, which Darwin uses for almost
/// any error while saying nothing about the bits that are in fact set. A
/// caller that gets -1 asks about that one descriptor on its own, through
/// [`realfs_poll`], which re-probes each bit separately.
///
/// **Safe**, for the reason [`realfs_poll_events`] is.
pub fn realfs_poll_fixup(fd: &ffi::fd, revents: c_int) -> c_int {
    let revents = fd.ops.map_or(revents, |ops| ops.host_revents(fd, revents));
    {
        let mut revents = revents as libc::c_short;
        {
            // Darwin reports a hung-up descriptor as writable, and the guest
            // needs to hear that so a write can fail with EPIPE rather than
            // blocking for ever.
            // darwin-xnu bsd/kern/sys_generic.c, sys_generic.c:1856.
            if revents & libc::POLLHUP != 0 {
                revents |= libc::POLLOUT;
            }
            // A pipe can come back with POLLPRI set, which it has no business
            // having: the guest would take it for out-of-band data.
            if fs_adhoc::is_adhoc_fd(fd)
                && fd.stat.mode & libc::S_IFMT as u32 == libc::S_IFIFO as u32
            {
                revents &= !libc::POLLPRI;
            }
            if revents & libc::POLLNVAL != 0 {
                return -1;
            }
        }
        // A peer that shut down its writing end is EPOLLRDHUP on Linux, and
        // *not* EPOLLHUP -- which means the connection is finished in both
        // directions. Darwin has no POLLRDHUP and reports POLLHUP for the
        // half-close, so a guest server was told the connection was dead and
        // stopped writing its reply.
        //
        // Synthesised rather than translated, and only for sockets: a pipe
        // whose writer closed is POLLHUP on Linux too, and adding a bit there
        // would be inventing one.
        //
        // POLLHUP is left in place. A caller that already keys on it behaves
        // as it did; one that asked for EPOLLRDHUP now hears about the case it
        // asked about. Reporting the half-close as *only* RDHUP would need to
        // know whether the local end is also finished, which Darwin does not
        // say.
        if revents & libc::POLLHUP != 0
            && fd.stat.mode & libc::S_IFMT as u32 == libc::S_IFSOCK as u32
        {
            {
                // Darwin uses HUP for both a peer half-close and a full close.
                // The local socket is still writable after SHUT_WR, which
                // distinguishes the half-close and matches Linux's RDHUP-only
                // result. A full close loses POLLOUT and keeps HUP.
                let writable = fd.host().map(|host| poll_now(host, libc::POLLOUT));
                if let Some((true, got)) = writable
                    && got & libc::POLLOUT != 0
                {
                    return (revents as c_int & !(libc::POLLHUP as c_int)) | POLL_RDHUP;
                }
            }
            return revents as c_int | POLL_RDHUP;
        }
        if revents & libc::POLLHUP != 0
            && fd.stat.mode & libc::S_IFMT as u32 == libc::S_IFIFO as u32
        {
            // Darwin reports both broken pipe directions as HUP. Linux reports
            // HUP for the read end and ERR for the write end. F_GETFL carries
            // the direction for anonymous pipes, so normalize it here for both
            // transient poll and Rust epoll's synchronous readiness check.
            let host = fd.host();
            let access = host
                .and_then(|host| rustix::fs::fcntl_getfl(host).ok())
                .map(|flags| flags & OFlags::RWMODE);
            if access == Some(OFlags::WRONLY) {
                return (revents as c_int & !(libc::POLLHUP as c_int)) | libc::POLLERR as c_int;
            }
            if access == Some(OFlags::RDONLY)
                && host.and_then(|host| rustix::io::ioctl_fionread(host).ok()) == Some(0)
            {
                return libc::POLLHUP as c_int;
            }
        }
        revents as c_int
    }
}

pub fn realfs_poll(fd: &ffi::fd) -> c_int {
    let Some(host) = fd.host() else {
        return 0;
    };
    let (ready, revents) = poll_now(host, realfs_poll_events(fd) as libc::c_short);
    if !ready {
        return 0;
    }

    let fixed = realfs_poll_fixup(fd, revents as c_int);
    if fixed >= 0 {
        return fixed;
    }

    // Only reachable on Darwin, where the fixup answers -1 for POLLNVAL: it
    // is used for almost any error and says nothing about the bits that are
    // in fact set, so ask for each separately and ignore the ones that come
    // back invalid. Not atomic, which cannot be helped.
    let mut events = 0;
    for bit in [libc::POLLIN, libc::POLLOUT, libc::POLLPRI] {
        let (ready, got) = poll_now(host, bit);
        if ready && got & libc::POLLNVAL == 0 {
            events |= got;
        }
    }
    (events & !libc::POLLNVAL) as c_int
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_aligned_offset_needs_no_correction() {
        let page = host_page() as i64;
        let w = window(page * 3, 2);
        assert_eq!(w.offset, page * 3);
        assert_eq!(w.correction, 0);
        assert_eq!(w.size, 2 * GUEST_PAGE as usize);
    }

    #[test]
    fn a_guest_offset_the_host_cannot_map_from_is_rounded_down() {
        // On a 16 KB host page, a guest mapping at 4 KB has to start the host
        // mapping at 0 and remember that the data is 4 KB in. On a host whose
        // pages are also 4 KB there is nothing to correct.
        let page = host_page();
        let w = window(GUEST_PAGE as i64, 1);
        if page > GUEST_PAGE {
            assert_eq!(w.offset, 0);
            assert_eq!(w.correction, GUEST_PAGE as usize);
            assert_eq!(w.size, GUEST_PAGE as usize * 2);
        } else {
            assert_eq!(w.offset, GUEST_PAGE as i64);
            assert_eq!(w.correction, 0);
        }
    }

    #[test]
    fn the_window_always_covers_every_page_asked_for() {
        for pages in [1u64, 2, 17] {
            for off in [0i64, 1, 4095, 4096, 100_000] {
                let w = window(off, pages);
                assert!(
                    w.offset + w.size as i64 >= off + (pages * GUEST_PAGE) as i64,
                    "window({off}, {pages}) stops short of the last page"
                );
                assert_eq!(w.offset + w.correction as i64, off);
            }
        }
    }

    #[test]
    fn prot_is_always_readable() {
        let shared = ffi::MMAP_SHARED as c_int;
        assert_eq!(host_prot(0, shared), libc::PROT_READ);
        assert_eq!(
            host_prot(ffi::P_WRITE as c_int, shared),
            libc::PROT_READ | libc::PROT_WRITE
        );
    }

    #[test]
    fn a_private_mapping_is_never_writable_on_the_host() {
        // Its stores are the page table's copies; the host mapping is the
        // file's own pages.
        let private = ffi::MMAP_PRIVATE as c_int;
        assert_eq!(host_prot(ffi::P_WRITE as c_int, private), libc::PROT_READ);
    }
}
