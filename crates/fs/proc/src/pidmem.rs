//! The address-space half of `/proc/<pid>`: `maps`, `statm`, the VM fields of
//! `status`, `auxv`, `cmdline`, `environ`, `comm` and `mem`.
//!
//! This is a **reader** of `struct mem`. Owning it is step 6 of the migration —
//! its layout is a contract with `emu/tlb.h`'s inline lookup — but reading it
//! costs nothing that was not already true of the C, and the alternative was an
//! accessor per field.
//!
//! # Nothing is formatted under the address-space lock
//!
//! `mem->lock` is what every `mmap`, `munmap`, `mprotect` and `brk` needs to
//! write. The C used to format each region as it found it — a `proc_printf` per
//! region, each of which can reallocate the output buffer, plus a
//! `generic_getpath` for every file-backed one — with that lock held throughout.
//! Measured with 1500 file-backed mappings and one thread reading
//! `/proc/self/maps` in a loop, `mmap`+`munmap` latency went from a median of
//! 20 µs to a median of **12 ms**.
//!
//! So the walk records raw regions and nothing else, and the paths are resolved
//! after the lock is gone. What crosses that boundary is a descriptor with a
//! **reference taken under the lock**, because `generic_getpath` needs one that
//! cannot be closed underneath it.
//!
//! # And nothing walks under `pids_lock`
//!
//! Every entry here takes a *reference to the address space* and gives the pid
//! table back before walking. Measured, with 2000 mappings: a fork behind a
//! concurrent read of `/proc/self/maps` waited 4378 µs, against 439 µs for the
//! worst unobstructed one.
//!
//! An `Arc` count is atomic, so retaining does not race the fork and exit paths,
//! which touch it under no shared lock. The matching release may be the last
//! reference and tear the space down — which is exactly the work that must not
//! happen under `pids_lock` either.
//!
//! # The classification is by page flag
//!
//! This kernel has page flags rather than per-region VMAs, so `status`'s segment
//! breakdown is derived: the stack is what `mmap` marked `P_GROWSDOWN`, text is
//! executable and backed by the file `execve` loaded, a library is executable
//! and backed by something else, and data is writable and neither.

use std::ffi::c_int;

use crate::ffi;
use crate::pidsnap::{Found, general_of};
use pagetable::memlock::Held;

use guest_errno::c_int_::{EINVAL, EIO, ENOMEM, ESRCH};

/// The most `auxv`, `cmdline` or `environ` will report.
///
/// Linux does not truncate these at all; the cap is here because the size is a
/// `malloc` argument taken from the mm, and a bogus pair should cost something
/// bounded. It was `PAGE_SIZE`, which is not a bound so much as a guess: an
/// environment larger than 4 KB is ordinary — a shell with a few dozen variables
/// passes it — and `ps` reads `cmdline`, so a long build command was shown cut
/// in half. One megabyte is above anything `execve` will accept and still
/// bounded.
const RANGE_MAX: usize = 1024 * 1024;

/// An address space, with a reference held, and the pid table given back.
///
/// Why there is no address space to read: the task is gone, or it is a zombie
/// and has given its address space up. The readers answer the two differently
/// -- and differently from each other, the way Linux does: for a zombie
/// `cmdline` and `maps` are empty where `environ`, `auxv` and `mem` are
/// `ESRCH`, all measured against a real kernel by `procfs_probe`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Missing {
    Task,
    Memory,
}

/// A retained address space.
struct Space(mmapcalls::mm::MmRef);

impl Space {
    /// Under `general_lock`, because that is the lock `execve` holds while it
    /// swaps `task->mm` and releases the old one. Reading `task->mm` without it
    /// and then retaining is a resurrection: the refcount may already have
    /// reached zero and `mm_release` be inside `mem_destroy`. Reproduced as
    /// `mm_release -> mem_destroy -> wrlock_destroy` on a probe reading
    /// `/proc/<pid>/statm` while other threads fork and exec.
    fn take(entry: &mut ffi::proc_entry) -> Result<Space, Missing> {
        let found = Found::get(entry).ok_or(Missing::Task)?;
        let mm = general_of(&found).mm();
        // The pid table is given back here, before any walk: see `collect`.
        drop(found);
        mm.map(Space).ok_or(Missing::Memory)
    }

    fn read(&self) -> pagetable::memlock::ReadGuard<'_> {
        self.0.read()
    }
}

/// What `statm` and `status` count. Every field is a page count.
#[derive(Default)]
pub struct VmCounts {
    pub total: u64,
    pub resident: u64,
    pub shared: u64,
    pub data: u64,
    pub stack: u64,
    pub exe: u64,
    pub lib: u64,
    pub rss_anon: u64,
    pub rss_file: u64,
    pub rss_shmem: u64,
}

/// Walk the address space and count. `Err` when there is no such task, or no
/// address space -- and the two are told apart, because a zombie's `statm` is
/// all zeroes on Linux where a vanished task's is `ESRCH`.
///
/// Reporting all zeroes for a *live* task breaks runtimes that size pools and
/// locks from the reported VM size — JavaScriptCore rejects it outright, with
/// "Invalid value for lock: 0".
pub(crate) fn vm_counts(entry: &mut ffi::proc_entry) -> Result<VmCounts, Missing> {
    let space = Space::take(entry)?;
    let mut c = VmCounts::default();

    let held = space.read();
    // For identity: compared, never dereferenced.
    let exefile: *mut ffi::fd =
        held.image().exefile.as_ref().map_or(std::ptr::null_mut(), |f| f.as_ptr());
    let mut page: u64 = 0;
    while page < ffi::MEM_PAGES {
        if let Some(pt) = held.pt(page) {
            c.total += 1;
            let data = pt.data();
            let flags = pt.flags();
            // Backed by real data, rather than a PROT_NONE reservation or a
            // lazy anonymous page, is what counts as resident.
            if let Some(data) = data {
                c.resident += 1;
                if flags & ffi::P_SHARED != 0 {
                    c.shared += 1;
                    // Shared first, because a shared file mapping is shmem to a
                    // reader and counting it as file as well would make the
                    // three overshoot the total.
                    c.rss_shmem += 1;
                } else if data.fd().is_some() {
                    c.rss_file += 1;
                } else {
                    c.rss_anon += 1;
                }
            }
            // See the module comment on the classification.
            if flags & ffi::P_GROWSDOWN != 0 {
                c.stack += 1;
            } else if flags & ffi::P_EXEC != 0 {
                let is_exe = data
                    .is_some_and(|d| d.fd().is_some_and(|fd| fd.as_ptr() == exefile));
                if is_exe {
                    c.exe += 1;
                } else {
                    c.lib += 1;
                }
            } else if flags & ffi::P_WRITE != 0 {
                c.data += 1;
            }
        }
        held.next_page(&mut page);
    }
    Ok(c)
}

/// Mapped, resident and shared page counts. `None` when there is no such
/// task; zeroes for a zombie, which is what Linux's `statm` prints for one.
///
/// Three nullable `*mut u64` out-parameters and a `bool` until 2026-09-16,
/// over a `VmCounts` this module already had and its one caller wanted three
/// fields of.
pub(crate) fn proc_pid_statm_counts(entry: &mut ffi::proc_entry) -> Option<VmCounts> {
    match vm_counts(entry) {
        Ok(c) => Some(c),
        // A task with no address space reports zeroes; a task that is gone
        // reports nothing, which is `ESRCH` at the caller.
        Err(Missing::Memory) => Some(VmCounts::default()),
        Err(Missing::Task) => None,
    }
}

// -------------------------------------------------------------- flat ranges

/// Which of the three single-range files this is.
#[derive(Clone, Copy)]
enum Range {
    Auxv,
    Cmdline,
    Environ,
}

/// One range of the address space, copied out whole.
///
/// A zombie has no address space, and Linux answers the three files
/// differently for one: `cmdline` reads as empty, because `proc_pid_cmdline`
/// takes the mm itself and treats none as nothing to print, while `environ`
/// and `auxv` open through `mm_access`, which answers `ESRCH`. Measured, not
/// read; `procfs_probe` has the three lines.
fn range_show(entry: &mut ffi::proc_entry, buf: &mut ffi::proc_data, which: Range) -> c_int {
    let space = match Space::take(entry) {
        Ok(space) => space,
        Err(Missing::Memory) if matches!(which, Range::Cmdline) => return 0,
        Err(_) => return ESRCH,
    };
    // `space` holds a reference to the address space, so it cannot be freed
    // while this reads two words out of it -- `MmRef::layout` reads them
    // through the pointer, because the owning thread writes the struct.
    //
    // **And under the lock their writers hold**, which this did not do until
    // 2026-09-12. `crates/kernel/execcalls`' `place_image` and `finish_stack`
    // write all six of these holding `mem->lock` for writing -- `finish_stack`
    // only since 2026-10-16, through `mmapcalls::mm::record_stack_ranges` --
    // and they run
    // *after* `execve` has published the space -- so an unlocked reader could
    // catch `argv_start` from the new image with `argv_end` still zero, and the
    // pair is a **range** that the lines below turn into a read of that much of
    // another process's memory. The `end < start` guard below is what kept that
    // from being an unbounded allocation, and the sentence above it said the
    // mismatch "should not happen".
    //
    // `Space::take` has already released `general_lock`, so this nests inside
    // nothing; see `read_mm_fields` in `pidsnap` for why that matters.
    let (start, end) = {
        let held = space.read();
        let image = held.image();
        match which {
            Range::Cmdline => image.argv,
            Range::Environ => image.env,
            Range::Auxv => image.auxv,
        }
    };
    // `end < start` would underflow to something enormous. With the read lock
    // above it should no longer be reachable -- both pairs are written together
    // under the write lock when the stack is laid out at execve -- but it stays,
    // because it was the only thing standing between a torn pair and an
    // unbounded allocation and a guard that has been load-bearing once is not
    // something to remove on the strength of an argument: what it stood between
    // was a bad pair and asking for sixteen exabytes.
    if end < start {
        return 0;
    }
    let mut size = (end - start) as usize;
    if size == 0 {
        return 0;
    }
    size = std::cmp::min(size, RANGE_MAX);

    let mut data: Vec<u8> = Vec::new();
    if data.try_reserve(size).is_err() {
        return ENOMEM;
    }
    data.resize(size, 0);
    if mmapcalls::usermem::read_held(&mut space.read(), start, &mut data) == 0
    {
        buf.append(&data);
    }
    0
}

pub(crate) fn proc_pid_auxv_show(
    entry: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    range_show(entry, buf, Range::Auxv)
}

pub(crate) fn proc_pid_cmdline_show(
    entry: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    range_show(entry, buf, Range::Cmdline)
}

pub(crate) fn proc_pid_environ_show(
    entry: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    range_show(entry, buf, Range::Environ)
}

/// The thread name, which is sixteen bytes and not necessarily terminated.
///
pub(crate) fn proc_pid_comm_show(
    entry: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    let Some(found) = Found::get(entry) else {
        return ESRCH;
    };
    let comm = found.task().comm();
    drop(found);
    let line = format!("{comm}\n");
    buf.append(line.as_bytes());
    0
}

/// Linux's `comm_write`: a thread of the same process may rename any of its
/// threads, anyone else is `EINVAL`. The bytes are the name, the newline
/// `echo` adds included, cut at fifteen or at a NUL; `procaccess_probe`.
pub(crate) fn proc_pid_comm_update(
    entry: &mut ffi::proc_entry,
    data: &mut ffi::proc_data,
) -> c_int {
    let Some(found) = Found::get(entry) else {
        return ESRCH;
    };
    if !crate::pidentry::is_callers_group(&found) {
        return EINVAL;
    }
    found.task().with_attr_mut(|a| a.set_comm(data.as_slice()));
    drop(found);
    if entry.pid == taskview::current_pid() {
        taskcalls::update_thread_name();
    }
    0
}

/// `/proc/<pid>/mem` needs no set-up: the read and write operations call into
/// the address space directly.
///
pub(crate) fn proc_pid_mem_show(
    _entry: &mut ffi::proc_entry,
    _buf: &mut ffi::proc_data,
) -> c_int {
    0
}

pub(crate) fn proc_pid_mem_pread(
    entry: &mut ffi::proc_entry,
    buf: &mut [u8],
    offset: i64,
) -> isize {
    let len = buf.len();
    // Retained, under `general_lock`, like every other reader here: this read
    // `task->mm` and locked the space inside it with no reference until
    // 2026-10-17, which is the resurrection `Space::take` describes. A zombie
    // has no address space, and Linux's `mm_access` answers ESRCH for it
    // rather than a short read.
    let Ok(space) = Space::take(entry) else {
        return ESRCH as isize;
    };
    let mut held = space.read();
    by_page(offset as u64, len, |at, range| {
        mmapcalls::usermem::read_held(&mut held, at, &mut buf[range]) == 0
    })
}

/// Linux's `mem_rw`: page by page, stopping at the first page that cannot be
/// reached, and `EIO` only when that is the first. One failing page anywhere
/// failed the whole transfer here, with `-1`, which a guest read as `EPERM`.
fn by_page(offset: u64, len: usize, mut step: impl FnMut(u64, std::ops::Range<usize>) -> bool) -> isize {
    let page = ffi::PAGE_SIZE as u64;
    let mut done = 0usize;
    while done < len {
        let at = offset.wrapping_add(done as u64);
        let n = ((page - at % page) as usize).min(len - done);
        if !step(at, done..done + n) {
            break;
        }
        done += n;
    }
    if done == 0 && len > 0 { EIO as isize } else { done as isize }
}

/// Writes ignore the page protections, which is what a debugger setting a
/// breakpoint in read-only text needs.
///
pub(crate) fn proc_pid_mem_pwrite(
    entry: &mut ffi::proc_entry,
    buf: &[u8],
    offset: i64,
) -> isize {
    let len = buf.len();
    // As the read.
    let Ok(space) = Space::take(entry) else {
        return ESRCH as isize;
    };
    let mut held = space.read();
    by_page(offset as u64, len, |at, range| {
        mmapcalls::usermem::write_held_ptrace(&mut held, at, &buf[range]) == 0
    })
}

#[path = "pidmaps.rs"]
mod pidmaps;
pub use pidmaps::{Counts, Region, collect, proc_maps_dump};
pub(crate) use pidmaps::file_regions;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_range_cap_is_a_bound_and_not_a_guess() {
        // It was PAGE_SIZE, which cut a shell's environment and a long build
        // command in half. One megabyte is above anything execve will accept.
        assert_eq!(RANGE_MAX, 1024 * 1024);
        const {
            assert!(RANGE_MAX > 4096);
        }
    }

    /// Whole pages until the first that fails, which is a short count, or
    /// `EIO` when nothing was reached.
    #[test]
    fn mem_moves_whole_pages_until_one_fails() {
        let page = ffi::PAGE_SIZE as u64;
        let mut seen = Vec::new();
        let n = by_page(page - 10, 30 + page as usize, |at, r| {
            seen.push((at, r.clone()));
            at < 2 * page
        });
        assert_eq!(n, 10 + page as isize, "the first two pieces, then a stop");
        assert_eq!(seen[0], (page - 10, 0..10));
        assert_eq!(seen[1], (page, 10..10 + page as usize));
        assert_eq!(by_page(0, 8, |_, _| false), EIO as isize);
        assert_eq!(by_page(0, 0, |_, _| false), 0);
    }

    #[test]
    fn the_three_rss_kinds_sum_to_the_resident_count() {
        // Which is the property the "shared first" ordering exists for: a
        // shared file mapping is shmem to a reader, and counting it as file as
        // well would make the three overshoot.
        let c = VmCounts {
            resident: 6,
            rss_shmem: 1,
            rss_file: 2,
            rss_anon: 3,
            ..Default::default()
        };
        assert_eq!(c.rss_shmem + c.rss_file + c.rss_anon, c.resident);
    }
}
