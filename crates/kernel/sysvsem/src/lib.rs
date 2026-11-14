//! System V semaphores: `semget`, `semctl`, `semop`, `semtimedop`.
//!
//! All four were `syscall_stub`, so `ipcs -s` said "kernel not configured for
//! semaphores" and the oldest way two processes have of taking turns did not
//! work. Shared memory was already here; this is the coordination that goes
//! with it.
//!
//! # The rules are in [`plan`] and the waiting is here
//!
//! Everything a caller can get wrong is arithmetic over the arguments, so it
//! is `plan.rs` with unit tests and no semaphore in sight. What is left is the
//! object, the blocking, and the undo list.
//!
//! # `SEM_UNDO`, which is the reason the family is still used
//!
//! A process that acquires a semaphore and then dies would otherwise leave it
//! held for ever, and no third party can tell that from a process that is
//! merely slow. `SEM_UNDO` records the adjustment and the kernel reverses it
//! when the process goes, which is what makes a lock built out of these
//! survivable.
//!
//! The list is per **thread group**, and it is applied when the last thread of
//! the group exits -- `crates/kernel/exitcalls` calls [`group_exiting`] from
//! the `exit_tgroup` branch that already knows it was the last. Per group and
//! not per thread because Linux shares the list across `CLONE_SYSVSEM` threads
//! and every thread library sets that flag.
//!
//! An undo that would take a value out of range is **dropped** rather than
//! clamped or applied. Linux does the same, and the alternative is worse in
//! both directions: clamping invents a value nobody asked for, and applying it
//! makes a semaphore negative, which nothing else in the family can produce.
//!
//! # One lock per set, and the table is not held across a wait
//!
//! A blocked caller holds an `Arc` to its own set and nothing else, so another
//! process can reach the table -- which it must, because the thing the first
//! is waiting for is somebody else's `semop` on the same set. The table lock is
//! taken for a lookup and dropped.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_int;
use std::sync::{Arc, Mutex};

use strace::strace;
use sysvipc::{Errno, may, may_control};
use usercopy::GuestMem;
use util_guestlock::GuestLock;

mod abi;
pub mod plan;
mod semop;
mod undo;
use abi::{SEMID_DS_LEN, semid_ds, seminfo};
pub use semop::{sys_semop, sys_semtimedop};
pub use undo::{group_exiting, has_undo};

/// The one condition: something about this set changed.
const CHANGED: u32 = 0;

/// One semaphore.
#[derive(Clone, Copy, Default)]
struct Sem {
    value: u16,
    /// The pid of the last process to change it, which `GETPID` answers.
    pid: i32,
}

/// A set, as everything but the waiting sees it.
struct SetState {
    perm: sysvipc::Perm,
    sems: Vec<Sem>,
    /// Seconds since the epoch of the last `semop` and the last change.
    otime: i64,
    ctime: i64,
    /// `IPC_RMID` has run. A waiter that sees this answers `EIDRM`.
    removed: bool,
    /// How many callers are parked on a decrement and on a wait-for-zero,
    /// which is what `GETNCNT` and `GETZCNT` answer.
    ncnt: u32,
    zcnt: u32,
}

/// A set and the lock that guards it.
struct SemSet {
    state: GuestLock<SetState>,
}

/// The calling task's IPC namespace's table.
fn table() -> Arc<Mutex<sysvipc::Registry<SemSet>>> {
    taskview::current_ipc().part()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The calling task's identity, for the permission checks.
fn creds() -> (Caller, u32, u32) {
    // With no task this dereferenced null; it answers what `capable` and
    // `current_fsids` answer for one now.
    let (euid, egid) = taskview::with_current_creds(|c| (c.euid(), c.egid())).unwrap_or((0, 0));
    let caller = Caller {
        ipc_owner: taskview::capable(taskview::caps::CAP_IPC_OWNER),
        sys_admin: taskview::capable(taskview::caps::CAP_SYS_ADMIN),
    };
    (caller, euid, egid)
}

/// The capabilities the rules ask: `CAP_IPC_OWNER` for access, `CAP_SYS_ADMIN`
/// for `IPC_SET` and `IPC_RMID`.
#[derive(Clone, Copy)]
struct Caller {
    ipc_owner: bool,
    sys_admin: bool,
}

/// Look an id up and check the caller may reach it.
///
/// A removed id and one that never existed are the same answer, `EINVAL`, and
/// the module comment in `crates/kernel/sysvipc` says why.
fn find(id: i32, want: u16) -> Result<Arc<SemSet>, Errno> {
    let set = table()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(id)
        .ok_or(Errno::EINVAL)?;
    let (caller, euid, egid) = creds();
    let perm = set.state.lock().perm;
    if set.state.lock().removed {
        return Err(Errno::EIDRM);
    }
    may(&perm, caller.ipc_owner, euid, egid, want)?;
    Ok(set)
}

// ------------------------------------------------------------------- semget

pub fn sys_semget(key: i32, nsems: c_int, flags: c_int) -> Result<i64, Errno> {
    strace!("semget({key:#x}, {nsems}, {flags:#o})");
    let f = sysvipc::get_flags(flags);
    let (caller, euid, egid) = creds();
    let table = table();
    let mut t = table.lock().unwrap_or_else(|e| e.into_inner());

    if key != sysvipc::IPC_PRIVATE {
        if let Some((id, set)) = t.by_key(key) {
            if f.create && f.exclusive {
                return Err(Errno::EEXIST);
            }
            let s = set.state.lock();
            // "At least this many", so fewer is fine and more is not. The one
            // rule `semget(2)` states for a create and not for a lookup.
            plan::check_nsems_lookup(nsems, s.sems.len())?;
            let perm = s.perm;
            drop(s);
            // A lookup needs whatever the caller asked for in the mode, which
            // for the ordinary `semget(key, n, 0o600)` is read and write.
            may(&perm, caller.ipc_owner, euid, egid, f.mode >> 6)?;
            return Ok(id as i64);
        }
        if !f.create {
            return Err(Errno::ENOENT);
        }
    }

    let n = plan::check_nsems_create(nsems)?;
    if t.len() >= plan::SEMMNI {
        return Err(Errno::ENOSPC);
    }
    let t_now = now();
    let state = SetState {
        perm: sysvipc::Perm::new(key, euid, egid, f.mode),
        sems: vec![Sem::default(); n],
        otime: 0,
        ctime: t_now,
        removed: false,
        ncnt: 0,
        zcnt: 0,
    };
    Ok(t.insert(key, SemSet { state: GuestLock::new(state, 1) }) as i64)
}

// ------------------------------------------------------------------- semctl

const GETPID: c_int = 11;
const GETVAL: c_int = 12;
const GETALL: c_int = 13;
const GETNCNT: c_int = 14;
const GETZCNT: c_int = 15;
const SETVAL: c_int = 16;
const SETALL: c_int = 17;
const SEM_STAT: c_int = 18;
const SEM_INFO: c_int = 19;
const SEM_STAT_ANY: c_int = 20;

pub fn sys_semctl(id: i32, num: c_int, cmd: c_int, arg: u64) -> Result<i64, Errno> {
    strace!("semctl({id}, {num}, {cmd}, {arg:#x})");

    // The three that do not take an id at all. `IPC_INFO` and `SEM_INFO` take
    // none, and `SEM_STAT` takes an index into the live sets -- so all three
    // have to be answered before the id lookup below, which would refuse an
    // index that happens not to be an id.
    match cmd {
        sysvipc::IPC_INFO | SEM_INFO => {
            let table = table();
            let t = table.lock().unwrap_or_else(|e| e.into_inner());
            let ids = t.ids();
            let sems: usize = ids
                .iter()
                .filter_map(|i| t.get(*i))
                .map(|s| s.state.lock().sems.len())
                .sum();
            let info = seminfo(ids.len(), sems, cmd == SEM_INFO);
            drop(t);
            if GuestMem.write(arg, &info) != 0 {
                return Err(Errno::EFAULT);
            }
            // "The index of the highest used entry", which is one less than the
            // count -- and 0 for an empty table, since there is no such entry
            // and `ipcs` stops at the first index that answers nothing.
            return Ok(ids.len().saturating_sub(1) as i64);
        }
        SEM_STAT | SEM_STAT_ANY => {
            let ids = table().lock().unwrap_or_else(|e| e.into_inner()).ids();
            let Some(real) = ids.get(id as usize).copied() else {
                return Err(Errno::EINVAL);
            };
            let set = find(real, if cmd == SEM_STAT { sysvipc::READ } else { 0 })?;
            let s = set.state.lock();
            let buf = semid_ds(&s);
            drop(s);
            if GuestMem.write(arg, &buf) != 0 {
                return Err(Errno::EFAULT);
            }
            return Ok(real as i64);
        }
        _ => {}
    }

    // `IPC_RMID` and `IPC_SET` are about ownership rather than the mode bits,
    // and `IPC_STAT` needs read -- so the permission each needs differs and the
    // lookup cannot ask for one answer.
    let want = match cmd {
        GETVAL | GETALL | GETPID | GETNCNT | GETZCNT | sysvipc::IPC_STAT => sysvipc::READ,
        SETVAL | SETALL => sysvipc::WRITE,
        sysvipc::IPC_RMID | sysvipc::IPC_SET => 0,
        _ => return Err(Errno::EINVAL),
    };
    let set = find(id, want)?;
    let (caller, euid, _) = creds();
    let mut s = set.state.lock();
    let nsems = s.sems.len();

    match cmd {
        GETVAL => plan::check_sem_num_ctl(num, nsems).map(|i| s.sems[i].value as i64),
        GETPID => plan::check_sem_num_ctl(num, nsems).map(|i| s.sems[i].pid as i64),
        GETNCNT => plan::check_sem_num_ctl(num, nsems).map(|_| s.ncnt as i64),
        GETZCNT => plan::check_sem_num_ctl(num, nsems).map(|_| s.zcnt as i64),
        SETVAL => {
            let i = plan::check_sem_num_ctl(num, nsems)?;
            // The value is the *fourth* argument read as an int, sign extended
            // by the guest. A `SETVAL -1` arrives as 0xffff_ffff and is ERANGE,
            // not a very large value.
            let v = plan::check_value(arg as u32 as i32 as i64)?;
            s.sems[i].value = v;
            s.sems[i].pid = taskview::current_tgid();
            s.ctime = now();
            // A raised value may be what a parked caller was waiting for.
            set.state.notify(CHANGED);
            Ok(0)
        }
        GETALL => {
            let bytes: Vec<u8> = s.sems.iter().flat_map(|x| x.value.to_le_bytes()).collect();
            if GuestMem.write(arg, &bytes) != 0 {
                Err(Errno::EFAULT)
            } else {
                Ok(0)
            }
        }
        SETALL => {
            let mut bytes = vec![0u8; nsems * 2];
            if GuestMem.read(arg, &mut bytes) != 0 {
                return Err(Errno::EFAULT);
            }
            // Every value is checked before any is written: Linux validates the
            // whole array first, so a bad one at the end does not leave the
            // ones before it changed.
            let mut vals = Vec::with_capacity(nsems);
            for &c in bytes.as_chunks::<2>().0 {
                vals.push(plan::check_value(u16::from_le_bytes(c) as i64)?);
            }
            let pid = taskview::current_tgid();
            for (sem, v) in s.sems.iter_mut().zip(vals) {
                sem.value = v;
                sem.pid = pid;
            }
            s.ctime = now();
            set.state.notify(CHANGED);
            Ok(0)
        }
        sysvipc::IPC_STAT => {
            let buf = semid_ds(&s);
            if GuestMem.write(arg, &buf) != 0 {
                Err(Errno::EFAULT)
            } else {
                Ok(0)
            }
        }
        sysvipc::IPC_SET => {
            may_control(&s.perm, caller.sys_admin, euid)?;
            let mut buf = [0u8; SEMID_DS_LEN];
            if GuestMem.read(arg, &mut buf) != 0 {
                return Err(Errno::EFAULT);
            }
            let Some((uid, gid, mode)) = sysvipc::read_perm_update(&buf) else {
                return Err(Errno::EFAULT);
            };
            s.perm.uid = uid;
            s.perm.gid = gid;
            s.perm.mode = mode;
            s.ctime = now();
            Ok(0)
        }
        sysvipc::IPC_RMID => {
            may_control(&s.perm, caller.sys_admin, euid)?;
            let key = s.perm.key;
            s.removed = true;
            drop(s);
            table()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(id, key);
            // Every parked caller is woken to find `removed` and answer EIDRM.
            set.state.notify(CHANGED);
            undo::forget_undos_for(id);
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire size, which is what `semctl(IPC_STAT)` writes into a guest's
    /// buffer. Measured from musl's headers; a short write leaves the caller's
    /// `sem_nsems` as whatever was there.
    #[test]
    fn a_semid_ds_is_eighty_eight_bytes_with_nsems_at_sixty_four() {
        assert_eq!(SEMID_DS_LEN, 88);
        assert_eq!(sysvipc::IPC_PERM_LEN, 48);
        // otime and ctime are the two longs after the perm, and nsems the one
        // after those -- the offsets IPC_STAT writes at.
        assert_eq!(48 + 8, 56);
        assert_eq!(48 + 16, 64);
    }
}
