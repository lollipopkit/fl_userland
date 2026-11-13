//! `cachestat(2)`, Linux 6.5: how much of a file's range is in the page cache.
//!
//! # Whose page cache
//!
//! A file on realfs or fakefs, and a memfd, is a host file, and its pages are
//! the host's: the answer is the host's residency, asked with `mincore` over a
//! read-only mapping of the host descriptor. A host page is four guest pages
//! on Apple silicon, so one resident host page answers for the four guest
//! pages it holds, clamped to the end of the file. A tmpfs file is this
//! process's memory, so every page it has is cached. Anything else -- a pipe,
//! a socket, a procfs file, a directory -- has no pages, which is what Linux
//! answers for those too (measured: a pipe and a directory are 0 everywhere).
//!
//! `nr_dirty` is a modified host page, except on a tmpfs-like filesystem:
//! shmem has no writeback, so Linux tags none of its pages dirty and a
//! freshly written memfd answers `nr_dirty` 0 (measured). `nr_writeback`,
//! `nr_evicted` and `nr_recently_evicted` are 0: the host does not say.

use super::*;

use usercopy::GuestMem;

/// `struct cachestat_range { __u64 off; __u64 len; }`.
const RANGE_BYTES: usize = 16;
/// `struct cachestat`: five `__u64` counters.
const CACHESTAT_BYTES: usize = 40;

const PAGE_SHIFT: u32 = 12;
/// tmpfs's `f_type`, which memfd's descriptor reports too.
const TMPFS_MAGIC: u32 = 0x0102_1994;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    cache: u64,
    dirty: u64,
}

/// The pages `[first, last]` names, clamped to the file: `None` when the
/// range starts past its end.
fn pages_in(off: u64, len: u64, size: u64) -> Option<(u64, u64)> {
    let first = off >> PAGE_SHIFT;
    // `len` 0 is "to the end", as Linux reads it; a sum that wraps is the
    // same arithmetic Linux does on an unsigned long.
    let last = if len == 0 {
        u64::MAX
    } else {
        off.wrapping_add(len).wrapping_sub(1) >> PAGE_SHIFT
    };
    let pages = size.div_ceil(1 << PAGE_SHIFT);
    if pages == 0 || first >= pages || last < first {
        return None;
    }
    Some((first, last.min(pages - 1)))
}

pub fn sys_cachestat(num: c_uint, range_addr: u64, out_addr: u64, flags: c_uint) -> Result<(), Errno> {
    strace!("cachestat({num}, {range_addr:#x}, {out_addr:#x}, {flags:#x})");
    // Linux's order: the descriptor, the range, who may ask, then the flags.
    let fd = Fd::get(num as c_int)?;
    if fd.is_path_only() {
        return Err(Errno::EBADF);
    }
    let mut range = [0u8; RANGE_BYTES];
    if GuestMem.read(range_addr, &mut range) != 0 {
        return Err(Errno::EFAULT);
    }
    let off = u64::from_le_bytes(range[0..8].try_into().expect("eight bytes"));
    let len = u64::from_le_bytes(range[8..16].try_into().expect("eight bytes"));
    let st = fs_fdobj::fd_fstat(&fd).map_err(Errno::from_negative_or_eio)?;
    may_ask(&fd, &st)?;
    if flags != 0 {
        return Err(Errno::EINVAL);
    }

    let counts = match pages_in(off, len, st.size) {
        Some((first, last)) if st.mode & S_IFMT == S_IFREG => residency(&fd, first, last)?,
        _ => Counts::default(),
    };
    let mut out = [0u8; CACHESTAT_BYTES];
    out[0..8].copy_from_slice(&counts.cache.to_le_bytes());
    out[8..16].copy_from_slice(&counts.dirty.to_le_bytes());
    if GuestMem.write(out_addr, &out) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// Linux's `can_do_cachestat`: residency is a side channel -- whether
/// somebody else read a file recently -- so it is answered only to a caller
/// who could write the file anyway. Measured: an unprivileged reader of a
/// root-owned 0644 file is EPERM.
fn may_ask(fd: &Fd, st: &ffi::statbuf) -> Result<(), Errno> {
    if fd.flags() & (ffi::O_WRONLY_ | ffi::O_RDWR_) != 0 {
        return Ok(());
    }
    if taskview::with_current_creds(|c| c.owner_or_capable(st.uid)).unwrap_or(false) {
        return Ok(());
    }
    fs_perm::access_check(st, ffi::AC_W as c_int).map_err(|_| Errno::EPERM)
}

/// How many of pages `[first, last]` are cached, and how many dirty.
fn residency(fd: &Fd, first: u64, last: u64) -> Result<Counts, Errno> {
    let count = last - first + 1;
    let no_writeback = fd.fs().is_some_and(|fs| fs.magic() == TMPFS_MAGIC);
    let Some(host) = fd.host() else {
        // In this process's memory: every page the file has is cached, and a
        // tmpfs page is never dirty in Linux's accounting.
        return Ok(Counts { cache: count, dirty: 0 });
    };
    let mut counts = host_residency(host, first, last)?;
    if no_writeback {
        counts.dirty = 0;
    }
    Ok(counts)
}

/// The host's answer for the guest pages `[first, last]` of `host`.
///
/// Mapped a window at a time so that a range over a large file maps a
/// bounded amount of address space.
fn host_residency(host: std::os::fd::BorrowedFd<'_>, first: u64, last: u64) -> Result<Counts, Errno> {
    use std::os::fd::AsRawFd as _;
    const WINDOW: u64 = 64 << 20;
    // SAFETY: sysconf has no preconditions.
    let host_page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let guest_page = 1u64 << PAGE_SHIFT;
    let start = first * guest_page;
    let end = (last + 1) * guest_page;
    let mut counts = Counts::default();
    let mut at = start - start % host_page;
    while at < end {
        let len = WINDOW.min(end - at).div_ceil(host_page) * host_page;
        // SAFETY: a fresh read-only shared mapping of a descriptor the caller
        // holds, unmapped below before anything else can see it; nothing reads
        // through it -- `mincore` only asks the VM about it.
        let map = unsafe {
            libc::mmap(std::ptr::null_mut(), len as usize, libc::PROT_READ, libc::MAP_SHARED, host.as_raw_fd(), at as libc::off_t)
        };
        if map == libc::MAP_FAILED {
            return Err(Errno::ENOMEM);
        }
        let mut vec = vec![0u8; (len / host_page) as usize];
        // SAFETY: `map` is `len` bytes of this process's mapping and `vec` has
        // one byte per host page of it.
        let err = unsafe { libc::mincore(map, len as usize, vec.as_mut_ptr().cast()) };
        // SAFETY: the mapping made above, which nothing else refers to.
        unsafe { libc::munmap(map, len as usize) };
        if err != 0 {
            return Err(Errno::ENOMEM);
        }
        for (i, state) in vec.iter().enumerate() {
            let page_start = at + i as u64 * host_page;
            // The guest pages of the asked range that this host page holds.
            let lo = page_start.max(start);
            let hi = (page_start + host_page).min(end);
            if hi <= lo {
                continue;
            }
            let guest_pages = (hi - lo).div_ceil(guest_page);
            let state = c_int::from(*state);
            if state & libc::MINCORE_INCORE != 0 {
                counts.cache += guest_pages;
                if state & (libc::MINCORE_MODIFIED | libc::MINCORE_MODIFIED_OTHER) != 0 {
                    counts.dirty += guest_pages;
                }
            }
        }
        at += len;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_range_is_clamped_to_the_file() {
        // An 8192-byte file is two pages, whatever the range says past them.
        assert_eq!(pages_in(0, 0, 8192), Some((0, 1)));
        assert_eq!(pages_in(4096, 1, 8192), Some((1, 1)));
        assert_eq!(pages_in(0, u64::MAX, 8192), Some((0, 1)));
        assert_eq!(pages_in(8192, 4096, 8192), None);
        assert_eq!(pages_in(0, 0, 0), None);
        // A partial last page is a page.
        assert_eq!(pages_in(0, 0, 4097), Some((0, 1)));
        // A sum that wraps names pages up to where it wrapped to.
        assert_eq!(pages_in(4096, u64::MAX, 3 << 12), None);
    }

    /// A real host file, so the host's `mincore` is what answers: pages just
    /// written are resident, and the count is in guest pages whatever the
    /// host's page size is.
    #[test]
    fn a_host_file_just_written_is_resident() {
        use std::io::Write as _;
        let path = std::env::temp_dir().join(format!("iul-cachestat-{}", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&[7u8; 3 * 4096]).unwrap();
        drop(f);
        let f = std::fs::File::open(&path).unwrap();
        // Reading it is what makes it resident for certain.
        let _ = std::fs::read(&path).unwrap();
        use std::os::fd::AsFd as _;
        let counts = host_residency(f.as_fd(), 0, 2).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(counts.cache, 3);
    }
}
