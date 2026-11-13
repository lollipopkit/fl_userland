//! Non-mapping memory syscalls: locking, `msync`, and `membarrier`.

use super::*;

// ---------------------------------------------------------------------------
// Locking pages, which means nothing here
// ---------------------------------------------------------------------------

// What backs a guest page is host memory this process already manages, and the
// host is free to page it either way. `mlock` has always claimed success on
// that basis; its partners answered `ENOSYS`, so a program could lock and not
// unlock, which is worse than either answer on its own.

/// The range still has to exist. Linux answers `ENOMEM` for a range with an
/// unmapped page in it, and this answered success for any address at all —
/// the same shape as the `madvise` defect above: a program that uses the call
/// to ask a *question* about its address space gets the wrong answer, and a
/// program that uses it to lock gets what it always got.
///
/// The start is rounded down to its page and the length grows by as much:
/// `do_mlock`'s `start &= PAGE_MASK`, measured -- an unaligned `mlock` is a
/// success on Linux, and was `EINVAL` here until 2026-11-13.
fn mlock_range(addr: u64, len: u64) -> Result<(u64, u64), Errno> {
    let off = page_offset(addr);
    let (addr, len) = (addr - off, len.checked_add(off).ok_or(Errno::ENOMEM)?);
    mlock_range_ok(addr, len)?;
    Ok((addr, len))
}

fn mlock_range_ok(addr: u64, len: u64) -> Result<(), Errno> {
    if len == 0 {
        return Ok(());
    }
    if !user_range_ok(addr, len) {
        return Err(Errno::ENOMEM);
    }
    if !range_is_mapped(addr, len) {
        return Err(Errno::ENOMEM);
    }
    Ok(())
}

/// Mark the range locked or not, once [`mlock_range_ok`] has accepted it.
///
/// Nothing here is paged out, so locking changes no residency. What it does
/// change is `madvise`: DONTNEED, FREE and GUARD_INSTALL refuse locked memory
/// with `EINVAL`, which is how a program that `mlock`s a secret and then
/// `madvise`s it learns that the advice was not taken. Recorded as `P_LOCKED`
/// since 2026-11-11; until then the lock was success and nothing.
fn set_locked(addr: u64, len: u64, locked: bool) -> Result<(), Errno> {
    let (addr, len) = mlock_range(addr, len)?;
    if locked {
        can_do_mlock()?;
    }
    let (first, pages) = (page_of(addr), page_round_up(len));
    if pages != 0 {
        let (set, clear) = if locked { (ffi::P_LOCKED, 0) } else { (0, ffi::P_LOCKED) };
        mem_write().change_meta(first, pages, set, clear);
    }
    Ok(())
}

/// `can_do_mlock`: a `RLIMIT_MEMLOCK` of 0 leaves locking to
/// `CAP_IPC_LOCK`, measured. The amount a non-zero limit allows is not
/// enforced: nothing is paged out here either way.
fn can_do_mlock() -> Result<(), Errno> {
    let limit = taskview::with_current_group(|g| g.limits.soft(ffi::RLIMIT_MEMLOCK_)).flatten()
        .unwrap_or(u64::MAX);
    if limit == 0 && !taskview::capable(taskview::caps::CAP_IPC_LOCK) {
        return Err(Errno::EPERM);
    }
    Ok(())
}

pub fn sys_mlock(addr: u64, len: u64) -> Result<(), Errno> {
    set_locked(addr, len, true)
}

pub fn sys_munlock(addr: u64, len: u64) -> Result<(), Errno> {
    set_locked(addr, len, false)
}

/// `MLOCK_ONFAULT`, the only flag `mlock2` has.
pub(super) const MLOCK_ONFAULT: c_uint = 0x01;

/// The flag is checked even though the lock is not performed. A program passing
/// a flag the kernel does not know is asking a question, and "success" is the
/// wrong answer to it.
pub fn sys_mlock2(addr: u64, len: u64, flags: c_uint) -> Result<(), Errno> {
    if flags & !MLOCK_ONFAULT != 0 {
        return Err(Errno::EINVAL);
    }
    set_locked(addr, len, true)
}

pub(super) const MCL_CURRENT: c_uint = 1;
pub(super) const MCL_FUTURE: c_uint = 2;
pub(super) const MCL_ONFAULT: c_uint = 4;

/// `mlockall`'s argument rules, apart from the address space they apply to.
pub(super) fn mlockall_flags_ok(flags: c_uint) -> Result<(), Errno> {
    if flags == 0 {
        return Err(Errno::EINVAL);
    }
    if flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & MCL_ONFAULT != 0 && flags & (MCL_CURRENT | MCL_FUTURE) == 0 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Same, and one more rule: `mlockall(0)` is `EINVAL` because locking nothing
/// is not something to ask for, and `MCL_ONFAULT` on its own is `EINVAL`
/// because it qualifies the other two rather than standing alone. Both used to
/// answer 0, so a caller was told it had locked something.
pub fn sys_mlockall(flags: c_uint) -> Result<(), Errno> {
    mlockall_flags_ok(flags)?;
    can_do_mlock()?;
    // MCL_CURRENT locks what is mapped now. MCL_FUTURE -- lock what is mapped
    // later -- is accepted and not applied: it would have to reach every
    // place a page is mapped, and what it would change is only which later
    // DONTNEEDs answer EINVAL.
    // TODO: MCL_FUTURE as a per-mm default that `map_nothing` and the file
    // mappings apply.
    if flags & MCL_CURRENT != 0 {
        mem_write().change_meta(0, USER_ADDR_MAX_PAGE + 1, ffi::P_LOCKED, 0);
    }
    Ok(())
}

/// Unlock everything. No argument to get wrong.
pub fn sys_munlockall() {
    mem_write().change_meta(0, USER_ADDR_MAX_PAGE + 1, 0, ffi::P_LOCKED);
}

// ---------------------------------------------------------------------------
// msync
// ---------------------------------------------------------------------------

pub(super) const MS_ASYNC: c_int = 1;
pub(super) const MS_INVALIDATE: c_int = 2;
pub(super) const MS_SYNC: c_int = 4;

/// The guest page is 4 KB and the host page may be larger — 16 KB on Apple
/// silicon — and `msync` wants a host-page-aligned address. Rounding the start
/// down and the length up flushes a little more than was asked for, which is
/// harmless: the extra is the rest of the host page the mapping is in.
fn msync_host(start: *mut u8, len: usize, flags: c_int) -> c_int {
    // The host page size, which may be larger than the guest's.
    let hp = pagetable::memlock::host_page_size();
    let begin = (start as usize) & !(hp - 1);
    let end = ((start as usize) + len + hp - 1) & !(hp - 1);
    unsafe { libc::msync(begin as *mut c_void, end - begin, flags) }
}

/// `msync(2)`.
///
/// Used to return 0 without doing anything, which is a lie a program cannot
/// detect until the data is not there: anything that writes through a
/// `MAP_SHARED` file mapping and calls `msync` to make it durable — an embedded
/// database is the usual one — was told the flush had happened.
///
/// A shared file mapping is a host `mmap` of the host file, so flushing it is a
/// host `msync` of the same pages. Private and anonymous mappings have nothing
/// to flush, exactly as on Linux.
pub fn sys_msync(addr: u64, len: u64, flags: c_int) -> Result<(), Errno> {
    strace!("msync({addr:#x}, {len:#x}, {flags})");
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0 {
        return Err(Errno::EINVAL);
    }
    // Asking for both is a contradiction, and Linux says so.
    if flags & MS_ASYNC != 0 && flags & MS_SYNC != 0 {
        return Err(Errno::EINVAL);
    }
    if page_offset(addr) != 0 {
        return Err(Errno::EINVAL);
    }
    if !user_range_ok(addr, len) {
        return Err(Errno::ENOMEM);
    }
    if len == 0 {
        return Ok(());
    }

    let mut host_flags = if flags & MS_SYNC != 0 {
        libc::MS_SYNC
    } else {
        libc::MS_ASYNC
    };
    if flags & MS_INVALIDATE != 0 {
        host_flags |= libc::MS_INVALIDATE;
    }

    let guard = mem_read();
    // Coalesce runs whose host pages are contiguous, so a large mapping is one
    // host call rather than one per guest page -- the host page is 16 KB on
    // Apple silicon, so per-page calls would also flush each host page four
    // times over.
    let mut err: Option<Errno> = None;
    let mut run_start: *mut u8 = std::ptr::null_mut();
    let mut run_len = 0usize;
    let mut p = addr;
    while p < addr + len {
        let host = match mmap_msync_page(&guard, page_of(p)) {
            // Not mapped. Linux reports a range that is not entirely mapped,
            // and does not flush any of it -- so this stops rather than
            // flushing what it has already coalesced.
            MsyncPage::Unmapped => {
                err = Some(Errno::ENOMEM);
                break;
            }
            // Mapped and flushable, and contiguous with the run so far.
            MsyncPage::Flush(host) if !run_start.is_null() && host.addr() == run_start.addr() + run_len => {
                run_len += PAGE_SIZE as usize;
                p += PAGE_SIZE;
                continue;
            }
            MsyncPage::Flush(host) => host,
            MsyncPage::Nothing => std::ptr::null_mut(),
        };
        if !run_start.is_null() && msync_host(run_start, run_len, host_flags) < 0 {
            err = Some(Errno::EIO);
        }
        // A page with nothing to flush ends the run rather than extending it.
        run_start = host;
        run_len = if host.is_null() {
            0
        } else {
            PAGE_SIZE as usize
        };
        p += PAGE_SIZE;
    }
    if err.is_none() && !run_start.is_null() && msync_host(run_start, run_len, host_flags) < 0 {
        err = Some(Errno::EIO);
    }
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// membarrier
// ---------------------------------------------------------------------------

pub(super) const MEMBARRIER_CMD_QUERY: c_int = 0;
pub(super) const MEMBARRIER_CMD_GLOBAL: c_int = 1 << 0;
pub(super) const MEMBARRIER_CMD_GLOBAL_EXPEDITED: c_int = 1 << 1;
pub(super) const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: c_int = 1 << 2;
pub(super) const MEMBARRIER_CMD_PRIVATE_EXPEDITED: c_int = 1 << 3;
pub(super) const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: c_int = 1 << 4;
pub(super) const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: c_int = 1 << 5;
pub(super) const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: c_int = 1 << 6;

/// `membarrier(2)`.
///
/// Every guest thread here is a native host thread over shared native memory,
/// so a host fence plus the ordering already present on the *other* threads'
/// next memory operation gives most of what the call promises.
///
/// **The barrier commands are a fence on this thread only**, and that is not
/// what they promise. Linux's expedited membarrier IPIs every CPU running a
/// thread of the process, so the caller's fence is paired with one on every
/// other thread; a local fence pairs with nothing. What the caller gets is the
/// half of the guarantee that does not need the other threads' cooperation.
///
/// Left as it is rather than made accurate, because making it accurate means
/// interrupting every guest thread on every call, and the asymmetric-fence
/// algorithms that use this — a seqlock's fast path, a JIT's code-patching
/// handshake — would be slower than the symmetric ones they replaced.
/// `SYNC_CORE` is separately moot: it is about instruction-cache coherence
/// after patching code, and guest code is not executed by the host's
/// instruction fetch at all.
///
/// Recorded rather than fixed. If a guest is ever seen missing a write
/// published by another thread across one of these, this is the line.
pub fn sys_membarrier(cmd: c_int, flags: c_uint, _cpu_id: c_int) -> Result<i64, Errno> {
    strace!("membarrier({cmd}, {flags:#x})");
    // The only defined flag is MEMBARRIER_CMD_FLAG_CPU, valid solely with the
    // CPU-targeted variants this does not implement. For every command it does
    // handle, a non-zero flags argument is invalid -- as on Linux.
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    match cmd {
        MEMBARRIER_CMD_QUERY => Ok(
            (MEMBARRIER_CMD_GLOBAL
                | MEMBARRIER_CMD_GLOBAL_EXPEDITED
                | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
                | MEMBARRIER_CMD_PRIVATE_EXPEDITED
                | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
                | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
                | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE) as i64,
        ),

        // Registration: nothing to set up, since any thread may issue the
        // expedited barrier. Native Linux requires prior registration, so JSC
        // always calls these first.
        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
        | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
        | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => Ok(0),

        MEMBARRIER_CMD_GLOBAL
        | MEMBARRIER_CMD_GLOBAL_EXPEDITED
        | MEMBARRIER_CMD_PRIVATE_EXPEDITED
        | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            Ok(0)
        }

        _ => Err(Errno::EINVAL),
    }
}
