//! Who the calling process is, and what it may become.
//!
//! `getpid` and its neighbours, the eleven uid/gid calls, the supplementary
//! groups, `capget`/`capset` and `personality`, from `kernel/getset.c`.
//!
//! Almost every one is a single call into `crates/kernel/creds`, which owns the
//! rules *and* the state: nothing here assembles a triple, writes one back, or
//! has to remember that the fs ids follow the effective ones. That last was
//! three separate assignments in C — two setters and the `execve` transition —
//! and missing one leaves a process making file decisions with the id it had
//! before its last `setuid`.
//!
//! Privilege is `CAP_SETUID` for the uid calls and `CAP_SETGID` for the gid
//! ones, which the crate asks for itself rather than taking as a parameter.

use std::ffi::{c_int, c_uint};

use guest_errno::Errno;
use kernel_pids::PidsGuard;
use strace::strace;
use usercopy::GuestMem;

// `crates/kernel/creds` and `crates/kernel/procattr` were reached through
// twenty-one `extern "C"` declarations here until 2026-09-05. Both are leaf
// crates in this workspace and `struct task` holds their types by value, so
// they are ordinary Rust calls now: checked against the real signature, and
// small enough to inline.
use kernel_creds::{
    Creds,
};

/// The supplementary group limit, from `struct task`.
const MAX_GROUPS: usize = 32;

/// Change this task's credentials with `pids_lock` held.
///
/// **Every reader of *another* task's `Creds` holds that lock** — above all
/// `signaldeliver::signal_kill_task_for_rs`, which reads the target's whole
/// credential set for `creds_may_signal`, Linux's `kill_ok_by_cred`. Until
/// 2026-09-15 the writers held nothing: a `set*id` ran on the task's own
/// thread and wrote `uid.real`, `uid.eff` and `uid.saved` in turn while
/// another thread could be comparing them.
///
/// `Creds` is plain data — there is no atomic and no lock anywhere in
/// `crates/kernel/creds` — so the reader could see a **mix**: a process
/// dropping privilege with `setresuid(1000, 1000, 1000)` presents `uid == 0`
/// beside `suid == 1000` for the width of three stores, and the permission
/// answer then matches neither the state before nor the state after.
/// `struct task`'s field comment already said "Locked by pids_lock"; this is
/// what makes that true.
///
/// The guard wraps the **change only**, never a guest-memory read:
/// `setgroups` copies its list in first, because holding a global lock across
/// a page fault is how lock-order inversions get made.
/// A `&mut Creds` rather than a `*mut Creds` since 2026-09-16, which is what
/// took the `unsafe` off all nine callers; since 2026-10-16 the borrow comes
/// from the guard (now [`PidsGuard::commit_current_creds`]), so this has none
/// either.
///
/// Through [`PidsGuard::commit_current_creds`], which is also what takes
/// `dumpable` away from a process whose effective or fs ids moved.
fn with_creds_locked<R>(f: impl FnOnce(&mut Creds) -> R) -> R {
    PidsGuard::take().commit_current_creds(f).expect("a syscall runs in a task")
}

/// The calling task's credential set, read on its own thread; see
/// [`taskview::with_current_creds`].
fn read_creds<R>(f: impl FnOnce(&Creds) -> R) -> R {
    taskview::with_current_creds(f).expect("a syscall runs in a task")
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

pub fn sys_getpid() -> i64 {
    strace!("getpid()");
    taskview::current_tgid() as i64
}

pub fn sys_gettid() -> i64 {
    strace!("gettid()");
    taskview::current_pid() as i64
}

pub fn sys_getppid() -> i64 {
    strace!("getppid()");
    // The parent's pid, or 0 for a task whose parent has been reaped.
    //
    // One function in `kernel/task.c` until 2026-09-03, and it is here for the
    // reason every one of these moves: the lookup and the field read have to be
    // one hold of `pids_lock`, because a parent found through the tree can be
    // freed the moment it is dropped, and `PidsGuard` is what makes holding it
    // across both the only shape a Rust caller can write.
    //
    // The parent's *process*: Linux's `task_tgid_vnr(real_parent)`. The
    // parent is the thread that forked, which is not the process's leader
    // when a thread forks; this answered that thread's tid (`fork_probe`).
    let guard = PidsGuard::take();
    guard.me().and_then(kernel_pids::Task::parent).map_or(0, |p| p.tgid() as i64)
}

// There is no 16-bit variant here. `sys_getuid`, `sys_geteuid`, `sys_getgid`
// and `sys_getegid` masked their answer to 0xffff and were dispatched from
// nowhere: on i386 they were separate syscall numbers, and on aarch64
// __NR_getuid *is* the 32-bit one. They went with the rest of the x86 backend.

pub fn sys_getuid32() -> i64 {
    strace!("getuid32()");
    i64::from(read_creds(Creds::uid))
}

pub fn sys_geteuid32() -> i64 {
    strace!("geteuid32()");
    i64::from(read_creds(Creds::euid))
}

pub fn sys_getgid32() -> i64 {
    strace!("getgid32()");
    i64::from(read_creds(Creds::gid))
}

pub fn sys_getegid32() -> i64 {
    strace!("getegid32()");
    i64::from(read_creds(Creds::egid))
}

// ---------------------------------------------------------------------------
// Changing them
// ---------------------------------------------------------------------------

/// The two errno widths, met once.
///
/// `crates/kernel/creds` says errno in a `c_int` and this file answers an
/// `Errno`; that is the whole of what sits between them, because that crate
/// owns both the rules and the state and nothing here decides anything about a
/// triple. It took `0, or a negative errno` until 2026-09-16, because the
/// wrapper layer it called had flattened the `Result` the rules already
/// answered.
fn done<T>(r: Result<T, c_int>) -> Result<T, Errno> {
    r.map_err(Errno::from_negative_or_eio)
}

pub fn sys_setuid(uid: c_uint) -> Result<(), Errno> {
    strace!("setuid({uid})");
    done(with_creds_locked(|c| c.setuid(uid)))
}

pub fn sys_setgid(gid: c_uint) -> Result<(), Errno> {
    strace!("setgid({gid})");
    done(with_creds_locked(|c| c.setgid(gid)))
}

pub fn sys_setresuid(r: c_uint, e: c_uint, s: c_uint) -> Result<(), Errno> {
    strace!("setresuid({r}, {e}, {s})");
    done(with_creds_locked(|c| c.setresuid(r, e, s)))
}

pub fn sys_setresgid(r: c_uint, e: c_uint, s: c_uint) -> Result<(), Errno> {
    strace!("setresgid({r}, {e}, {s})");
    done(with_creds_locked(|c| c.setresgid(r, e, s)))
}

pub fn sys_setreuid(r: c_uint, e: c_uint) -> Result<(), Errno> {
    strace!("setreuid({r}, {e})");
    done(with_creds_locked(|c| c.setreuid(r, e)))
}

pub fn sys_setregid(r: c_uint, e: c_uint) -> Result<(), Errno> {
    strace!("setregid({r}, {e})");
    done(with_creds_locked(|c| c.setregid(r, e)))
}

/// The **previous** fsid, and no failure return: unsigned, because every uid
/// is a legal answer and a signed one would report `0xffffffff` as an errno.
pub fn sys_setfsuid(fsuid: c_uint) -> u32 {
    strace!("setfsuid({fsuid})");
    with_creds_locked(|c| c.setfsuid(fsuid))
}

/// As [`sys_setfsuid`]: the previous fsid, unsigned for the same reason.
pub fn sys_setfsgid(fsgid: c_uint) -> u32 {
    strace!("setfsgid({fsgid})");
    with_creds_locked(|c| c.setfsgid(fsgid))
}

/// Writes three ids to three addresses, stopping at the first that faults.
fn put3(a: u64, b: u64, c: u64, v: (u32, u32, u32)) -> Result<(), Errno> {
    for (addr, value) in [(a, v.0), (b, v.1), (c, v.2)] {
        if GuestMem.write(addr, &value.to_le_bytes()) != 0 {
            return Err(Errno::EFAULT);
        }
    }
    Ok(())
}

pub fn sys_getresuid(r_addr: u64, e_addr: u64, s_addr: u64) -> Result<(), Errno> {
    strace!("getresuid({r_addr:#x}, {e_addr:#x}, {s_addr:#x})");
    let ids = read_creds(|c| (c.uid(), c.euid(), c.suid()));
    put3(r_addr, e_addr, s_addr, ids)
}

pub fn sys_getresgid(r_addr: u64, e_addr: u64, s_addr: u64) -> Result<(), Errno> {
    strace!("getresgid({r_addr:#x}, {e_addr:#x}, {s_addr:#x})");
    let ids = read_creds(|c| (c.gid(), c.egid(), c.sgid()));
    put3(r_addr, e_addr, s_addr, ids)
}

// ---------------------------------------------------------------------------
// Supplementary groups
// ---------------------------------------------------------------------------

pub fn sys_getgroups(size: c_uint, list: u64) -> Result<i64, Errno> {
    strace!("getgroups({size}, {list:#x})");
    // The rules are crates/kernel/creds: 0 asks the count, a size below it is
    // EINVAL because a short answer would look like a complete one. `size`
    // arrives as a 32-bit word and is read *signed*, which is what makes -1
    // EINVAL rather than "room for four billion".
    //
    // `get` answers the **slice**, where a wrapper answered its length and a
    // second call answered a pointer for `from_raw_parts` to put back
    // together.
    //
    // Said rather than reinterpreted. This was
    // `from_raw_parts(ptr.cast::<u8>(), n * 4)` over the list's own storage,
    // which writes the *host's* byte order and happens to be the guest's; the
    // guest's `gid_t` is little-endian and that is now what the code says. A
    // stack buffer, because `MAX_GROUPS` is 32 and this is 128 bytes. Encoded
    // inside the borrow and written to the guest after it.
    let (bytes, n) = read_creds(|c| -> Result<_, Errno> {
        let groups = c.groups();
        let list_out = done(groups.get(size as c_int))?;
        let mut bytes = [0u8; MAX_GROUPS * 4];
        for (chunk, id) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(list_out) {
            *chunk = id.to_le_bytes();
        }
        Ok((bytes, if size == 0 { groups.len() as usize } else { list_out.len() }))
    })?;
    if size == 0 {
        return Ok(n as i64);
    }
    if GuestMem.write(list, &bytes[..n * 4]) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(n as i64)
}

pub fn sys_setgroups(size: c_uint, list: u64) -> Result<(), Errno> {
    strace!("setgroups({size}, {list:#x})");
    if size as usize > MAX_GROUPS {
        return Err(Errno::EINVAL);
    }
    // Linux wants CAP_SETGID for this, before the list is read. Without the
    // check any process could give itself whatever supplementary groups it
    // liked, which is the whole of what setgroups controls; `Creds::setgroups`
    // asks again under the lock.
    if !taskview::capable(taskview::caps::CAP_SETGID) {
        return Err(Errno::EPERM);
    }
    // Read aside first: on EFAULT the guest's list is left as it was, rather
    // than half overwritten with a group count that no longer describes it.
    let mut groups = [0u32; MAX_GROUPS];
    if GuestMem.read(list, plain::slice_bytes_mut(&mut groups[..size as usize])) != 0 {
        return Err(Errno::EFAULT);
    }
    // The guest read is above and outside the lock, deliberately. See
    // `with_creds_locked`.
    done(with_creds_locked(|c| c.setgroups(&groups[..size as usize])))
}

mod capabilities;
pub use capabilities::{sys_capget, sys_capset};
mod lsm;
pub use lsm::{sys_lsm_get_self_attr, sys_lsm_list_modules, sys_lsm_set_self_attr};

// ---------------------------------------------------------------------------
// personality
// ---------------------------------------------------------------------------

/// The rule is `crates/kernel/procattr`; what is here is the lock and the
/// return.
///
/// Two things this used to get wrong, both of which a caller depends on: every
/// value except `ADDR_NO_RANDOMIZE` was `EINVAL` where Linux refuses exactly
/// one, and the answer was the *new* personality where Linux returns the old —
/// so the save-and-restore the return value exists for restored nothing.
///
/// **The return is 64 bits wide**, and that is not a detail. Any `u32` is a
/// legal personality, so `personality(0xfffffffe)` has to answer `0xfffffffe` —
/// and the dispatcher reads a 32-bit return of `-1..-4095` as an errno and
/// sign-extends it, which would turn that answer into `-2`. Linux has the same
/// values and no such problem because its syscalls return `long`.
pub fn sys_personality(persona: c_uint) -> Result<i64, Errno> {
    strace!("personality({persona:#x})");
    // The old personality, which is what Linux answers and what a caller
    // saving-and-restoring around a child needs. It used to go out through a
    // wrapper that flattened this `Result` into an `i64` errno for `split` to
    // take apart again.
    taskview::with_current_attr(|attr| attr.set_personality(persona))
        .ok_or(Errno::EINVAL)?
        .map(i64::from)
        .map_err(Errno::from_negative_or_eio)
}
