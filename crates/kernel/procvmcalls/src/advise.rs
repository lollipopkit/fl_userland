//! `process_madvise` and `process_mrelease`: memory advice through a pidfd.
//!
//! Both were stubs. The rules are the reference kernel's, measured by
//! `tests/guest/src/bin/mm_modern_probe.rs` on 7.2:
//!
//! - `process_madvise` checks `flags`, then reads the iovec array (`EINVAL`
//!   past `IOV_MAX`, `EFAULT` for an unreadable one), then resolves the pidfd
//!   (`EBADF`; the `PIDFD_SELF_*` sentinels are accepted), and then the target's
//!   address space: `ESRCH` once the process has exited, zombie included.
//! - On the caller's own address space every `madvise` advice is allowed. On
//!   another's only the four that change no contents -- `COLD`, `PAGEOUT`,
//!   `WILLNEED`, `COLLAPSE` -- and the rest are `EINVAL`.
//! - The answer is the bytes advised, and a failure part-way answers the bytes
//!   before it, or the errno if there were none.
//! - `process_mrelease` reaps the memory of a process that is already dying.
//!   A live process that is not is `EINVAL`, the caller itself included, and
//!   one that has exited is `ESRCH`.

use std::ffi::{c_int, c_uint};

use kernel_pids::PidsGuard;
use strace::strace;

use crate::plan::Errno;

const MADV_WILLNEED: c_uint = 3;
const MADV_COLD: c_uint = 20;
const MADV_PAGEOUT: c_uint = 21;
const MADV_COLLAPSE: c_uint = 25;

/// Linux's `process_madvise_remote_valid`.
fn remote_valid(advice: c_uint) -> bool {
    matches!(advice, MADV_COLD | MADV_PAGEOUT | MADV_WILLNEED | MADV_COLLAPSE)
}

/// The target's address space, and whether it is the caller's own.
///
/// `ESRCH` for a task that has exited -- the pidfd's own record says so before
/// the registry is asked -- and for one with no address space, which is a task
/// mid-exit. The lookup and the retain are one hold of `pids_lock`, as in
/// [`crate::PinnedMm::of`], and `general_lock` is what `task->mm` is read
/// under.
fn target_mm(pidfd: c_int) -> Result<(mmapcalls::mm::MmRef, bool), Errno> {
    let target = pidfdcalls::pidfd_get(pidfd, true)?;
    if target.exited {
        return Err(Errno::ESRCH);
    }
    let guard = PidsGuard::take();
    let task = guard.find_by_ref(target.task).filter(|t| !t.is_zombie()).ok_or(Errno::ESRCH)?;
    let mm = taskcalls::GeneralGuard::of(task.task()).mm().ok_or(Errno::ESRCH)?;
    let mine = taskview::with_current_mm(std::ptr::from_ref).unwrap_or(std::ptr::null());
    let own = std::ptr::eq(mm.as_ptr().cast_const(), mine);
    // `mm_access`: EACCES, which `process_vm_rw` turns into EPERM and
    // `process_madvise` does not.
    if !own && !task.may_ptrace(kernel_creds::PtraceMode::ReadFs) {
        return Err(Errno::EACCES);
    }
    drop(guard);
    Ok((mm, own))
}

pub fn sys_process_madvise(pidfd: c_int, vec: u64, vlen: u64, advice: c_int, flags: c_uint) -> Result<i64, Errno> {
    strace!("process_madvise({pidfd}, {vec:#x}, {vlen}, {advice}, {flags:#x})");
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let iovs = crate::read_iovs(vec, vlen)?;
    let (mm, own) = target_mm(pidfd)?;
    let advice = advice as c_uint;
    if !own {
        if !remote_valid(advice) {
            return Err(Errno::EINVAL);
        }
        // Linux asks `capable(CAP_SYS_NICE)` for another process's memory.
        if !taskview::capable(taskview::caps::CAP_SYS_NICE) {
            return Err(Errno::EPERM);
        }
    }
    let mut done: u64 = 0;
    for iov in &iovs {
        let r = if own {
            mmapcalls::sys_madvise(iov.base, iov.len, advice)
        } else {
            mmapcalls::advise_remote(&mm, iov.base, iov.len, advice)
        };
        if let Err(e) = r {
            return if done > 0 { Ok(done as i64) } else { Err(e) };
        }
        done += iov.len;
    }
    Ok(done as i64)
}

pub fn sys_process_mrelease(pidfd: c_int, flags: c_uint) -> Result<(), Errno> {
    strace!("process_mrelease({pidfd}, {flags:#x})");
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let target = pidfdcalls::pidfd_get(pidfd, true)?;
    if target.exited {
        return Err(Errno::ESRCH);
    }
    let guard = PidsGuard::take();
    let task = guard.find_by_ref(target.task).filter(|t| !t.is_zombie()).ok_or(Errno::ESRCH)?;
    // `task_will_free_mem`: the whole group is on its way out. Its memory is
    // released by that exit, here as soon as the last thread goes, so there is
    // nothing to reap ahead of it and the answer is that it will be.
    let dying = task.is_exiting() || task.group().is_some_and(|g| g.exit_pending().is_some());
    if dying { Ok(()) } else { Err(Errno::EINVAL) }
}
