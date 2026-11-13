//! Guest-facing rlimit syscalls and guarded task lookup.

use super::*;
use kernel_pids::{Group, Task};

/// A task's limits, `None` for a task with no group -- `EINVAL`, as a
/// resource number that is not one is.
///
/// The handle holds `pids_lock`, which is what makes a `get` then `set` one
/// step -- every writer holds it too. There is no limits lock; the table is
/// atomic for its lock-free readers, which is why a shared reference is the
/// right one. Two `unsafe fn`s over a `*mut task` until 2026-09-30.
fn limits_of(task: Option<Task<'_>>) -> Result<&kernel_rlimit::Limits, Errno> {
    task.and_then(|t| t.group()).map(Group::limits).ok_or(Errno::EINVAL)
}

/// The soft limit for the calling task, for the C that still asks:
/// `tests/integration/sbm_api_test.c` is the one caller, and it is the
/// embedder example.
///
/// Every Rust caller uses `kernel_rlimit::current_soft`, which is the same
/// thing without this crate in the way -- `fs-fdobj` asking the resource
/// *syscalls* how many descriptors it may open was a cycle.
///
/// **Not a leftover**, though it said `TODO(migration): delete with the C
/// example's use of it` until 2026-09-09. An embedder that points a session's
/// descriptors 0, 1 and 2 at its own pty has to open the slave itself — which
/// is what routes through `dev_open` and `tty_open`, and so what claims a
/// controlling terminal and makes `isatty` true — and then hand
/// `fdtable_replace_range` the descriptor limit. Both the example and
/// ServerBox do exactly that, and neither is going to stop. A marker that will
/// never fire reads as "this is temporary" about something that is not.
#[unsafe(no_mangle)]
pub extern "C" fn rlimit(resource: c_int) -> u64 {
    kernel_rlimit::current_soft(resource as u32)
}

/// The guest's `struct rlimit`: two 64-bit words, soft then hard.
fn read_rlimit(addr: u64) -> Result<(u64, u64), Errno> {
    let mut b = [0u8; 16];
    if GuestMem.read(addr, &mut b) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok((
        u64::from_le_bytes(b[..8].try_into().unwrap()),
        u64::from_le_bytes(b[8..].try_into().unwrap()),
    ))
}

fn write_rlimit(addr: u64, cur: u64, max: u64) -> Result<(), Errno> {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&cur.to_le_bytes());
    b[8..].copy_from_slice(&max.to_le_bytes());
    if GuestMem.write(addr, &b) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

pub fn sys_getrlimit64(resource: c_uint, rlim_addr: u64) -> Result<(), Errno> {
    strace!("getrlimit64({resource})");
    let limit = limits_of(PidsGuard::take().me())?.get(resource).ok_or(Errno::EINVAL)?;
    strace!(" {{cur={:#x}, max={:#x}}}", limit.cur, limit.max);
    write_rlimit(rlim_addr, limit.cur, limit.max)
}

pub fn sys_setrlimit64(resource: c_uint, rlim_addr: u64) -> Result<(), Errno> {
    let (cur, max) = read_rlimit(rlim_addr)?;
    strace!("setrlimit64({resource}, {{cur={cur:#x}, max={max:#x}}})");
    let privileged = taskview::capable(taskview::caps::CAP_SYS_RESOURCE);
    let guard = PidsGuard::take();
    let limits = limits_of(guard.me())?;
    let old = limits.get(resource).ok_or(Errno::EINVAL)?;
    rlimit::check_set(privileged, rlimit::Rlimit { cur, max }, old)
        .map_err(Errno::from_negative_or_eio)?;
    if limits.set(resource, rlimit::Rlimit { cur, max }) {
        Ok(())
    } else {
        Err(Errno::EINVAL)
    }
}

pub fn sys_prlimit64(
    pid: c_int,
    resource: c_uint,
    new_limit_addr: u64,
    old_limit_addr: u64,
) -> Result<(), Errno> {
    strace!("prlimit64({pid}, {resource})");
    if !rlimit::resource_valid(resource) {
        return Err(Errno::EINVAL);
    }
    if pid < 0 {
        return Err(Errno::ESRCH);
    }

    // Read before the lock: a copy can fault, and pids_lock is not a lock to be
    // holding when it does.
    let new_limit = if new_limit_addr != 0 {
        let v = read_rlimit(new_limit_addr)?;
        strace!(" new={{cur={:#x}, max={:#x}}}", v.0, v.1);
        Some(v)
    } else {
        None
    };

    let privileged = taskview::capable(taskview::caps::CAP_SYS_RESOURCE);
    let (old_cur, old_max) = {
        let guard = PidsGuard::take();
        // A pid of 0 means the caller, but `prlimit(getpid(), ...)` is the
        // ordinary spelling -- util-linux's prlimit(1) writes it that way, and
        // so does anything raising its own NOFILE. Every pid but 0 used to be
        // EINVAL, which is the answer for a bad resource number, not for a
        // process that is simply not this one.
        let task = if pid == 0 {
            guard.me()
        } else {
            let Some(t) = guard.find_live(pid) else {
                return Err(Errno::ESRCH);
            };
            // Another task: `check_prlimit_permission`, which compares tasks
            // and not thread groups.
            if t.pid() != taskview::current_pid()
                && !taskview::with_current_creds(|m| m.may_prlimit(t.creds())).unwrap_or(false)
            {
                return Err(Errno::EPERM);
            }
            Some(t)
        };

        let limits = limits_of(task)?;
        let old = limits.get(resource).ok_or(Errno::EINVAL)?;
        if let Some((new_cur, new_max)) = new_limit {
            rlimit::check_set(
                privileged,
                rlimit::Rlimit {
                    cur: new_cur,
                    max: new_max,
                },
                old,
            )
            .map_err(Errno::from_negative_or_eio)?;
            if !limits.set(resource, rlimit::Rlimit { cur: new_cur, max: new_max }) {
                return Err(Errno::EINVAL);
            }
        }
        (old.cur, old.max)
    };

    // The old value is the one from before the new one was applied, which is
    // what Linux reports when both pointers are given. Written outside the
    // lock, as it was read outside it.
    if old_limit_addr != 0 {
        write_rlimit(old_limit_addr, old_cur, old_max)?;
    }
    Ok(())
}
