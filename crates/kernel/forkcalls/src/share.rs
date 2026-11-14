//! What two tasks share, asked after the fact (`kcmp`) and undone after the
//! fact (`unshare`, `setns`).
//!
//! The same resources `clone`'s flags decide at creation -- the address space,
//! the descriptor table, the filesystem context, the disposition table, the
//! SysV undo list -- so the three live beside the code that hands them out.
//!
//! # Namespaces
//!
//! `crates/kernel/nsproxy` holds which namespace of each kind a task is in.
//! Only the UTS and IPC kinds can be made new; a request for a new one of any other
//! kind is answered as a kernel built without it does: `EINVAL` -- after
//! `EPERM` for an unprivileged caller, because Linux checks `CAP_SYS_ADMIN`
//! before it would find the namespace code missing. Joining a namespace of
//! such a kind joins the initial one, which every task is already in.

use std::sync::OnceLock;

use taskview::nsproxy::{Kind, Ns};

use super::*;

// ---------------------------------------------------------------------------
// kcmp
// ---------------------------------------------------------------------------

const KCMP_FILE: c_int = 0;
const KCMP_VM: c_int = 1;
const KCMP_FILES: c_int = 2;
const KCMP_FS: c_int = 3;
const KCMP_SIGHAND: c_int = 4;
const KCMP_IO: c_int = 5;
const KCMP_SYSVSEM: c_int = 6;
const KCMP_EPOLL_TFD: c_int = 7;

/// Linux's `kptr_obfuscate`: an ordering over objects that says nothing about
/// where they are. `kcmp` answers 1 or 2 for "different" so that a caller can
/// sort, and ordering raw addresses would hand a guest the host's heap layout.
/// Per type, as Linux's cookies are, so two answers cannot be related.
fn obfuscate(v: usize, ty: c_int) -> usize {
    static COOKIES: OnceLock<[[usize; 2]; 8]> = OnceLock::new();
    let c = COOKIES.get_or_init(|| {
        let mut words = [[0usize; 2]; 8];
        for w in words.iter_mut().flatten() {
            let mut b = [0u8; 8];
            // A failed read leaves a fixed cookie, which still orders without
            // revealing an address.
            let _ = getrandom_bytes(&mut b);
            // Odd, so the multiply is a bijection.
            *w = usize::from_ne_bytes(b) | 1;
        }
        words
    });
    let [x, m] = c[ty as usize];
    (v ^ x).wrapping_mul(m)
}

fn getrandom_bytes(b: &mut [u8]) -> bool {
    // SAFETY: `b` is valid for `b.len()` bytes of writes.
    unsafe { libc::getentropy(b.as_mut_ptr().cast(), b.len()) == 0 }
}

/// `kcmp_ptr`: 0 equal, 1 and 2 an order.
fn kcmp_ptr(a: usize, b: usize, ty: c_int) -> i64 {
    match obfuscate(a, ty).cmp(&obfuscate(b, ty)) {
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Less => 1,
        std::cmp::Ordering::Greater => 2,
    }
}

/// `kcmp(2)`: whether two tasks share one kernel object of a type.
///
/// Every comparison is of the object's identity -- the address of the
/// description, the address space, the table -- which is what Linux compares.
/// Two of them have nothing behind them here and answer as a task that never
/// made one does on Linux, where the pointer is still NULL:
///
/// - `KCMP_IO`: there is no I/O context, so every task's is the same null one
///   (Linux allocates one on a task's first block I/O).
/// - `KCMP_SYSVSEM`: the undo list is per thread group and exists while it
///   holds adjustments.
///
/// `KCMP_EPOLL_TFD` answers `EOPNOTSUPP`, a kernel built without epoll's half
/// of it: looking a target up by descriptor number and position inside an
/// epoll set is not something `crates/kernel/epoll` can answer, and a guess
/// would tell a checkpointer two files are the same when they are not.
///
/// The order of the errors is Linux's: the tasks first (`ESRCH`, a zombie
/// included -- it is still found), then permission (`EPERM`), then the type.
pub fn sys_kcmp(pid1: c_int, pid2: c_int, ty: c_int, idx1: u64, idx2: u64) -> Result<i64, Errno> {
    strace!("kcmp({pid1}, {pid2}, {ty}, {idx1:#x}, {idx2:#x})");
    let guard = Pids::take();
    let (Some(t1), Some(t2)) = (guard.find(pid1), guard.find(pid2)) else {
        return Err(Errno::ESRCH);
    };
    let mode = kernel_creds::PtraceMode::ReadReal;
    if !t1.may_ptrace(mode) || !t2.may_ptrace(mode) {
        return Err(Errno::EPERM);
    }
    let addr = |p: *const u8| p as usize;
    let (a, b) = match ty {
        KCMP_FILE => {
            // The tables under `pids_lock`, the descriptions after it: a
            // lookup takes the table's lock, and the reference it answers can
            // be the last one, whose release closes the file -- neither of
            // which belongs under `pids_lock`.
            let (f1, f2) = (t1.files(), t2.files());
            drop(guard);
            let file = |t: Option<std::sync::Arc<ffi::fdtable>>, idx: u64| {
                t?.lookup_retain(c_int::try_from(idx).ok()?)
            };
            return match (file(f1, idx1), file(f2, idx2)) {
                (Some(a), Some(b)) => Ok(kcmp_ptr(a.as_ptr() as usize, b.as_ptr() as usize, ty)),
                _ => Err(Errno::EBADF),
            };
        }
        KCMP_VM => (addr(t1.mm().cast()), addr(t2.mm().cast())),
        KCMP_FILES => {
            // Compared and dropped under the lock, and a table's last
            // reference is never the one a lookup through a live task holds.
            let table = |t: &kernel_pids::Task<'_>| t.files().map_or(0, |f| std::sync::Arc::as_ptr(&f) as usize);
            (table(&t1), table(&t2))
        }
        KCMP_FS => {
            let fs = |t: &kernel_pids::Task<'_>| t.fs().map_or(0, |f| std::ptr::from_ref(f) as usize);
            (fs(&t1), fs(&t2))
        }
        KCMP_SIGHAND => {
            let hand = |t: &kernel_pids::Task<'_>| t.sighand().map_or(0, |h| std::ptr::from_ref(h) as usize);
            (hand(&t1), hand(&t2))
        }
        KCMP_IO => (0, 0),
        KCMP_SYSVSEM => {
            let undo = |t: &kernel_pids::Task<'_>| {
                let tgid = t.tgid();
                if sysvsem::has_undo(&t.task().nsproxy().ipc, tgid) { tgid as usize } else { 0 }
            };
            (undo(&t1), undo(&t2))
        }
        KCMP_EPOLL_TFD => return Err(Errno::EOPNOTSUPP),
        _ => return Err(Errno::EINVAL),
    };
    Ok(kcmp_ptr(a, b, ty))
}

// ---------------------------------------------------------------------------
// unshare and setns
// ---------------------------------------------------------------------------

/// Every namespace flag `unshare` and `setns` know, `CLONE_NEWTIME` included.
const NAMESPACES: u64 = clone::NEWNS
    | clone::NEWCGROUP
    | clone::NEWUTS
    | clone::NEWIPC
    | clone::NEWUSER
    | clone::NEWPID
    | clone::NEWNET
    | NEWTIME;
/// `CLONE_NEWTIME`, which shares its bit with `CSIGNAL`'s 0x80 and so is only
/// a namespace flag to `unshare`, `setns` and `clone3`.
const NEWTIME: u64 = 0x80;

/// `unshare(2)`.
///
/// `CLONE_FILES` and `CLONE_FS` give the caller its own copy of a table it
/// shares, as `fork` would have; `CLONE_SYSVSEM` gives back the caller's undo
/// list. `CLONE_VM`, `CLONE_SIGHAND` and `CLONE_THREAD` cannot be undone and
/// are accepted only where there is nothing to undo, which is Linux's rule: a
/// single-threaded process. `CLONE_NEWUTS` gives the calling thread a copy
/// of its UTS namespace and `CLONE_NEWIPC` an empty IPC namespace, which
/// implies `CLONE_SYSVSEM`; see the module comment for the other kinds.
///
/// Every refusal is decided before anything changes, as Linux's
/// `bad_unshare_cleanup` arranges, so a call that fails has done nothing.
///
/// `CLONE_SYSVSEM` in a process with more than one thread: Linux detaches
/// only the calling thread from the shared list, and the list here is the
/// thread group's, so there is nothing to detach it from. That case does
/// nothing, and is the one place this differs.
pub fn sys_unshare(flags: u64) -> Result<(), Errno> {
    strace!("unshare({flags:#x})");
    // The whole word: Linux's `ksys_unshare` takes an `unsigned long` and
    // refuses any bit it does not know, the top half included.
    let allowed = clone::THREAD
        | clone::FS
        | clone::SIGHAND
        | clone::VM
        | clone::FILES
        | clone::SYSVSEM
        | NAMESPACES;
    if flags & !allowed != 0 {
        return Err(Errno::EINVAL);
    }
    // Linux's implications: a new mount namespace needs its own fs context,
    // and the address space cannot be unshared without the dispositions, nor
    // those without the thread group.
    let mut flags = flags;
    if flags & clone::NEWUSER != 0 {
        flags |= clone::THREAD | clone::FS;
    }
    if flags & clone::VM != 0 {
        flags |= clone::SIGHAND;
    }
    if flags & clone::SIGHAND != 0 {
        flags |= clone::THREAD;
    }
    if flags & clone::NEWNS != 0 {
        flags |= clone::FS;
    }
    // The undo list's sets are the namespace being left: applied now.
    if flags & clone::NEWIPC != 0 {
        flags |= clone::SYSVSEM;
    }
    let threads = {
        let pids = Pids::take();
        pids.me().and_then(|me| me.group()).map_or(1, kernel_pids::Group::thread_count)
    };
    if flags & (clone::THREAD | clone::SIGHAND | clone::VM) != 0 && threads > 1 {
        return Err(Errno::EINVAL);
    }
    if flags & NAMESPACES != 0 {
        // CAP_SYS_ADMIN for everything but a user namespace, which needs no
        // privilege -- and then the namespace code that is not there.
        if flags & NAMESPACES & !clone::NEWUSER != 0 && !taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
            return Err(Errno::EPERM);
        }
        if flags & NAMESPACES & !Kind::BUILT != 0 {
            return Err(Errno::EINVAL);
        }
    }

    if flags & clone::FS != 0 {
        let pids = Pids::take();
        let me = pids.me().ok_or(Errno::ESRCH)?;
        // Shared when another task holds it: a thread, or a CLONE_FS child.
        // SAFETY: every taker of the slot holds `pids_lock`, which is held.
        let fs = unsafe { me.task().fs.clone_arc() };
        // Two counts are the slot's and this one: anything more is a sharer.
        if let Some(fs) = fs.filter(|fs| std::sync::Arc::strong_count(fs) > 2) {
            let copy = std::sync::Arc::new(fs.duplicate());
            // SAFETY: no borrow of this task's context is alive, and
            // `pids_lock` is held.
            let old = unsafe { taskview::replace_current_fs(copy) };
            drop(pids);
            drop(old);
            drop(fs);
        }
    }
    if flags & clone::FILES != 0 {
        fdcalls::unshare_files()?;
    }
    if flags & clone::SYSVSEM != 0 && threads == 1 {
        // Linux's exit_sem: the adjustments are applied, and the list goes.
        sysvsem::group_exiting(taskview::current_tgid());
    }
    if flags & Kind::BUILT != 0 {
        taskview::with_current_task(|t| t.set_nsproxy(t.nsproxy().unshare(flags))).ok_or(Errno::ESRCH)?;
    }
    Ok(())
}

/// `setns(2)`.
///
/// Through a namespace descriptor (`/proc/<pid>/ns/*`): `nstype` is 0 or that
/// namespace's kind. Through a pidfd: `nstype` names the kinds to take from
/// the task, at least one. Anything else is `EINVAL`, a descriptor not open
/// `EBADF`; then `CAP_SYS_ADMIN`, and joining one's own user namespace is
/// `EINVAL` (`userns_install`). Measured by `utsns_probe`.
pub fn sys_setns(fd: c_int, nstype: c_int) -> Result<(), Errno> {
    strace!("setns({fd}, {nstype:#x})");
    let nstype = nstype as u32 as u64;
    let join: Vec<Ns> = if let Ok(target) = pidfdcalls::pidfd_get(fd, false) {
        if nstype == 0 || nstype & !NAMESPACES != 0 {
            return Err(Errno::EINVAL);
        }
        let theirs = {
            let pids = Pids::take();
            pids.find_by_ref(target.task).ok_or(Errno::ESRCH)?.task().nsproxy()
        };
        Kind::ALL.into_iter().filter(|k| nstype & k.flag() != 0).map(|k| theirs.get(k)).collect()
    } else if let Some(file) = fs_fdobj::f_get(fd) {
        let ns = file.driver_state::<Ns>().ok_or(Errno::EINVAL)?;
        if nstype != 0 && nstype != ns.kind().flag() {
            return Err(Errno::EINVAL);
        }
        vec![ns.clone()]
    } else {
        return Err(Errno::EBADF);
    };
    if !taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    if join.iter().any(|ns| ns.kind() == Kind::User) {
        return Err(Errno::EINVAL);
    }
    // As `unshare`: the undo list's sets are the namespace being left
    // (Linux's `commit_nsset`), and a thread group's list is shared by all of
    // it, as in `unshare`'s `CLONE_SYSVSEM`.
    if join.iter().any(|ns| ns.kind() == Kind::Ipc) {
        let threads = {
            let pids = Pids::take();
            pids.me().and_then(|me| me.group()).map_or(1, kernel_pids::Group::thread_count)
        };
        if threads == 1 {
            sysvsem::group_exiting(taskview::current_tgid());
        }
    }
    taskview::with_current_task(|t| {
        let mut proxy = t.nsproxy();
        for ns in &join {
            proxy = proxy.with(ns);
        }
        t.set_nsproxy(proxy);
    })
    .ok_or(Errno::ESRCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_order_over_objects_is_consistent_and_not_the_addresses() {
        assert_eq!(kcmp_ptr(0x1000, 0x1000, KCMP_VM), 0);
        let ab = kcmp_ptr(0x1000, 0x2000, KCMP_VM);
        let ba = kcmp_ptr(0x2000, 0x1000, KCMP_VM);
        assert!(ab == 1 || ab == 2);
        assert_eq!(ab + ba, 3, "the order is antisymmetric");
    }

    #[test]
    fn newtime_is_csignals_0x80_and_no_other_flag() {
        assert_eq!(NEWTIME & !clone::CSIGNAL, 0);
        assert_eq!(NAMESPACES & (clone::VM | clone::FS | clone::FILES | clone::SIGHAND), 0);
    }
}
