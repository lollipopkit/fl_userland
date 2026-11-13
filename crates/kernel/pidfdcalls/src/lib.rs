//! `pidfd_open`, `pidfd_send_signal`, `pidfd_getfd`, and the descriptor they
//! work on: its poll, its `PIDFD_GET_INFO` ioctl, and the lookup
//! `waitid(P_PIDFD)`, `process_madvise` and `process_mrelease` share.
//!
//! A pidfd names a task without the race a pid has: a pid can be reused
//! between looking it up and using it, and a descriptor cannot. The state and
//! the registry that finds one by pid are `crates/kernel/pidfd`; what is here
//! is the descriptor, the syscalls, and the lookup each needs.
//!
//! `bun` uses pidfds to reap the helpers it spawns — the `git` it runs at
//! startup among them — and with the old `ENOSYS` stub it fell back to a path
//! that deadlocked its worker pool.
//!
//! # A zombie counts
//!
//! Linux detaches a pid's `PIDTYPE_TGID` at `release_task`, which is *reaping*
//! and not exiting, so `pidfd_open` on a child that has exited and not been
//! waited for succeeds — and that is the case `P_PIDFD` exists for: open a
//! descriptor naming the process, then wait on it, with no window for a reused
//! pid in between.
//!
//! Asking for a live task instead answered `ESRCH` for a child that got to exit
//! first, which showed up as `wait_threads` failing about one release-build run
//! in ten.
//!
//! # What 6.9 to 7.2 added, and what is measured
//!
//! Every answer below was read off a 7.2 kernel by
//! `tests/guest/src/bin/pidfd_modern_probe.rs` rather than from a header:
//!
//! - `PIDFD_THREAD` names one thread. Without it a non-leader tid is `ENOENT`
//!   (it was `EINVAL` here, which a caller reads as a bad flag).
//! - `PIDFD_NONBLOCK` makes `waitid(P_PIDFD)` answer `EAGAIN` for a child that
//!   has not exited. It was accepted and ignored, so that wait blocked.
//! - `pidfd_send_signal` takes `PIDFD_SIGNAL_THREAD`, `_THREAD_GROUP` and
//!   `_PROCESS_GROUP` (one at most) and the `PIDFD_SELF_*` sentinels;
//!   `pidfd_getfd`, `waitid` and an ioctl do **not** take the sentinels.
//! - `PIDFD_GET_INFO` reports a live or zombie task's ids, and once it is
//!   reaped only its exit status, and only when asked for it.
//! - A reaped task's descriptor polls `POLLIN | POLLHUP`, an exited one's
//!   `POLLIN`.
//! - The namespace ioctls answer `EOPNOTSUPP`, which is a kernel with that
//!   namespace configured out: there are no namespaces here and no nsfs to
//!   hand a descriptor onto.

use std::ffi::c_int;

use kernel_pidfd as pidfd;
use kernel_pids::{PidsGuard, TaskRef};
use strace::strace;

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

use guest_errno::Errno;
use guest_errno::c_int_::{EOPNOTSUPP, ESRCH};

/// `PIDFD_NONBLOCK`, which is `O_NONBLOCK`.
pub const PIDFD_NONBLOCK: u32 = ffi::O_NONBLOCK_;
/// `PIDFD_THREAD`, which is `O_EXCL`.
pub const PIDFD_THREAD: u32 = ffi::O_EXCL_;
/// `PIDFD_SELF_THREAD`, from `linux/fcntl.h`: the calling thread.
pub const PIDFD_SELF_THREAD: c_int = -10000;
/// `PIDFD_SELF_THREAD_GROUP`: the calling thread's process.
pub const PIDFD_SELF_THREAD_GROUP: c_int = -10001;

const PIDFD_SIGNAL_THREAD: u32 = 1;
const PIDFD_SIGNAL_THREAD_GROUP: u32 = 2;
const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 4;

/// A pidfd's driver: a poll, an ioctl and a close.
///
/// No read or write: Linux has neither, and answers `EINVAL` for both, which
/// is what a driver with no stream operations answers here once the
/// description is `O_RDWR`.
struct PidfdOps;

static PIDFD_FDOPS: PidfdOps = PidfdOps;

fn pidfd_fdops() -> Option<&'static dyn ffi::FdOps> {
    Some(&PIDFD_FDOPS)
}

/// `PIDFS_IOCTL_MAGIC`.
const IOCTL_MAGIC: u32 = 0xFF;
/// `_IOC_NR` of `PIDFD_GET_INFO`; 1 to 10 are the namespace ioctls.
const NR_GET_INFO: u32 = 11;

/// The three parts of an ioctl number: direction, size, type and number.
fn ioc(cmd: c_int) -> (u32, usize, u32, u32) {
    let c = cmd as u32;
    (c >> 30, ((c >> 16) & 0x3fff) as usize, (c >> 8) & 0xff, c & 0xff)
}

impl ffi::FdOps for PidfdOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::NONE
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        // Lock-free: see the note in crates/kernel/pidfd about why this must
        // not take the registry lock.
        Some(state_of(fd).map_or(0, pidfd::PidFd::poll_bits))
    }
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        drop(fd.take_driver_state::<pidfd::PidFd>());
        0
    }
    /// `pidfd_show_fdinfo`: the pid, or -1 once nothing has it -- a zombie
    /// still does, a reaped process does not (`fdinfo_probe`). `NSpid` is the
    /// same number, there being one pid namespace. glibc's `pidfd_getpid`
    /// reads the first line.
    fn show_fdinfo(&self, fd: &ffi::fd, out: &mut String) {
        let Some(state) = state_of(fd) else {
            return;
        };
        let pid = PidsGuard::take()
            .find_by_ref(state.target)
            .filter(|_| !state.is_reaped())
            .map_or(-1, |task| task.pid());
        out.push_str(&format!("Pid:\t{pid}\nNSpid:\t{pid}\n"));
    }
    fn ioctl_size(&self, cmd: c_int) -> isize {
        let (dir, size, ty, nr) = ioc(cmd);
        if ty != IOCTL_MAGIC {
            return -1;
        }
        match nr {
            // `_IOWR`, and at least the first published struct. Measured: a
            // 56-byte or zero-byte `PIDFD_GET_INFO` is `ENOTTY`, not `EINVAL`.
            NR_GET_INFO if dir == 3 && size >= info::SIZE_VER0 => size as isize,
            1..=10 if dir == 0 && size == 0 => 0,
            _ => -1,
        }
    }
    fn ioctl(&self, fd: &ffi::fd, cmd: c_int, arg: ffi::IoctlArg<'_>) -> c_int {
        let Some(state) = state_of(fd) else {
            return guest_errno::c_int_::ENOTTY;
        };
        match (ioc(cmd).3, arg) {
            (NR_GET_INFO, ffi::IoctlArg::Buf(buf)) => match info::fill(state, buf) {
                Ok(()) => 0,
                Err(e) => e.as_c_int(),
            },
            // There are no namespaces here, so no nsfs descriptor to hand back:
            // a kernel with the namespace configured out answers this.
            _ => EOPNOTSUPP,
        }
    }
}

/// The state behind this descriptor, or `None` if it is not a pidfd.
fn state_of(fd: &ffi::fd) -> Option<&pidfd::PidFd> {
    fd.driver_state()
}

/// The status a wait would report for a zombie leader: what `PIDFD_INFO_EXIT`
/// reports once it is reaped. `crates/kernel/waitcalls` reads the same two.
fn zombie_status(task: &kernel_pids::Task<'_>) -> i32 {
    task.group()
        .and_then(|g| g.exit_pending())
        .unwrap_or(task.exit_code()) as i32
}

pub fn sys_pidfd_open(pid: c_int, flags: u32) -> Result<c_int, Errno> {
    strace!("pidfd_open({pid}, {flags:#x})");
    if flags & !(PIDFD_NONBLOCK | PIDFD_THREAD) != 0 {
        return Err(Errno::EINVAL);
    }
    // A pid that is not a pid is `EINVAL`, not `ESRCH`: `pidfd_open(0, 0)` and
    // `pidfd_open(-1, 0)` are refused for being nonsense rather than searched
    // for and not found. This answered `ESRCH` for both, which reads as "that
    // process has exited" -- a caller retrying on `ESRCH` would have looped.
    if pid <= 0 {
        return Err(Errno::EINVAL);
    }
    let thread = flags & PIDFD_THREAD != 0;

    // The lookup and the leader test under one hold of the registry: a task
    // found through it can be freed the moment the guard is dropped. What the
    // descriptor keeps is a reference to the task and not its number, so a
    // later task handed the same number is not the one it names.
    let (target, zombie) = {
        let pids = PidsGuard::take();
        let Some(task) = pids.find(pid) else {
            return Err(Errno::ESRCH);
        };
        // A thread without PIDFD_THREAD: `ENOENT`, measured on 7.2 -- the pid
        // has no thread-group leader's struct behind it.
        if !thread && !task.is_leader() {
            return Err(Errno::ENOENT);
        }
        let Some(target) = pids.refer(pid) else {
            return Err(Errno::ESRCH);
        };
        (target, task.is_zombie().then(|| zombie_status(&task)))
    };
    Errno::split(open_for(target, flags, zombie) as i64).map(|n| n as c_int)
}

/// A pidfd on `target`, installed in the caller's table: the descriptor
/// number, or a negative errno. `zombie` is the status of a target that had
/// already exited, whose exit nothing will announce again.
///
/// Linux always creates pidfds with O_CLOEXEC -- there is no way to get a
/// non-cloexec one from `pidfd_open`, and `clone(CLONE_PIDFD)` installs its
/// with `O_CLOEXEC` too. `PIDFD_NONBLOCK` and `PIDFD_THREAD` are the
/// description's flags, and `F_GETFL` reports both.
fn open_for(target: TaskRef, flags: u32, zombie: Option<i32>) -> c_int {
    // The exit path wakes pollers through this; installed here rather than at
    // boot because this is the only place a pidfd is made, so nothing can be
    // waiting before the first call. The first call wins.
    pidfd::set_wake_hook(wake);
    let mut fd = fs_adhoc::adhoc_anon(pidfd_fdops(), Some(c"[pidfd]"));
    // `fstat` on a pidfd answers mode 0700 with no file type, measured on 7.2.
    fd.stat.mode = 0o700;
    // pidfs gives each process its own inode, which every pidfd on it shares:
    // two pidfds name the same process exactly when `st_ino` agrees, which is
    // how systemd compares them. The task's identity, never zero since a pid
    // is not. It was the anonymous inode's 0.
    fd.stat.inode = u64::from(target.generation) << 32 | u64::from(target.pid as u32);
    // Registered first, so an exit from here on sets the flag; the
    // description it wakes is attached once there is an `Arc` to take a
    // `Weak` of.
    let state = pidfd::pidfd_new(target, flags & PIDFD_THREAD != 0);
    if let Some(status) = zombie {
        state.mark_exited(status);
    }
    let registration = state.registration();
    fd.set_driver_state(state);
    // **Added to** the `O_RDWR` `adhoc_anon` gave it. This replaced the flags
    // until 2026-11-11, so a pidfd was `O_RDONLY` and a `write` to one
    // answered `EBADF` where Linux answers `EINVAL`.
    fd.set_flags(fd.flags() | flags);
    let fd = fd.into_owned();
    registration.attach(fd.downgrade());
    fs_fdobj::f_install(fd, ffi::O_CLOEXEC_ as c_int)
}

/// `clone(CLONE_PIDFD)`'s half: a pidfd on a child that has just been made
/// and not yet started. `crates/kernel/forkcalls` is the caller; the child is
/// in the registry, because `publish` put it there just before. A thread's is
/// a `PIDFD_THREAD` one, which is what Linux 6.9 made `CLONE_PIDFD |
/// CLONE_THREAD` mean.
///
/// Called on a guest thread; `pid` names a task in the registry.
pub fn pidfd_open_for_clone(pid: c_int, thread: bool) -> c_int {
    let target = {
        let pids = PidsGuard::take();
        match pids.refer(pid) {
            Some(t) => t,
            None => return ESRCH,
        }
    };
    open_for(target, if thread { PIDFD_THREAD } else { 0 }, None)
}

/// What a pidfd argument names.
#[derive(Clone, Copy, Debug)]
pub struct Target {
    pub task: TaskRef,
    /// `PIDFD_THREAD`, or `PIDFD_SELF_THREAD`.
    pub thread: bool,
    /// `PIDFD_NONBLOCK` on the description.
    pub nonblock: bool,
    /// The task has exited: the process for a process pidfd, the thread for a
    /// thread one.
    pub exited: bool,
}

/// The task a pidfd names, with the `PIDFD_SELF_*` sentinels when `sentinels`
/// is set -- `pidfd_send_signal` and `process_madvise` take them and
/// `pidfd_getfd`, `waitid` and an ioctl answer `EBADF` or `EINVAL` for them,
/// measured on 7.2.
///
/// `EBADF` for a number that is not a descriptor **and** for one that is not a
/// pidfd, which is what Linux answers for both. Whether the task is still
/// there is the caller's question, asked under `pids_lock`.
pub fn pidfd_get(pidfd_no: c_int, sentinels: bool) -> Result<Target, Errno> {
    if sentinels && (pidfd_no == PIDFD_SELF_THREAD || pidfd_no == PIDFD_SELF_THREAD_GROUP) {
        let thread = pidfd_no == PIDFD_SELF_THREAD;
        let pids = PidsGuard::take();
        let me = pids.me().ok_or(Errno::ESRCH)?;
        let pid = if thread { me.pid() } else { me.tgid() };
        let task = pids.refer(pid).ok_or(Errno::ESRCH)?;
        return Ok(Target { task, thread, nonblock: false, exited: false });
    }
    let Some(fd) = fs_fdobj::f_get(pidfd_no) else {
        return Err(Errno::EBADF);
    };
    let fd = &*fd;
    let Some(state) = state_of(fd) else {
        return Err(Errno::EBADF);
    };
    Ok(Target {
        task: state.target,
        thread: state.thread,
        nonblock: fd.flags() & PIDFD_NONBLOCK != 0,
        exited: state.has_exited(),
    })
}

/// The task a pidfd names, sentinels included: `process_madvise` and
/// `process_mrelease` use this and look the task up themselves.
pub fn pidfd_target(pidfd_no: c_int) -> Result<TaskRef, Errno> {
    pidfd_get(pidfd_no, true).map(|t| t.task)
}

/// Signal the task a pidfd refers to.
///
/// Opening one worked; this, which is what one is for, answered `ENOSYS`.
pub fn sys_pidfd_send_signal(
    pidfd_no: c_int,
    sig: u32,
    info_addr: u64,
    flags: u32,
) -> Result<(), Errno> {
    strace!("pidfd_send_signal({pidfd_no}, {sig}, {info_addr:#x}, {flags:#x})");
    // Linux 6.9's three scopes, at most one of them. They choose what the
    // descriptor names rather than how the signal is sent; with none, a
    // thread pidfd names its thread and a process pidfd its process.
    let scope = flags & (PIDFD_SIGNAL_THREAD | PIDFD_SIGNAL_THREAD_GROUP | PIDFD_SIGNAL_PROCESS_GROUP);
    if flags != scope || scope.count_ones() > 1 {
        return Err(Errno::EINVAL);
    }
    let target = pidfd_get(pidfd_no, true)?;
    let scope = match scope {
        0 if target.thread => PIDFD_SIGNAL_THREAD,
        0 => PIDFD_SIGNAL_THREAD_GROUP,
        s => s,
    };
    // The process may already be gone: a pidfd stays valid after its process
    // exits, which is the other half of what it is for, and Linux answers
    // ESRCH for a signal to one.
    if target.exited {
        return Err(Errno::ESRCH);
    }
    let pid = target.task.pid;
    let tgid = {
        let pids = PidsGuard::take();
        match pids.find_by_ref(target.task) {
            Some(t) if !t.is_zombie() => t.tgid(),
            _ => return Err(Errno::ESRCH),
        }
    };
    // A `siginfo_t` the caller filled in, which is what `pidfd_send_signal` is
    // for beyond avoiding the pid-reuse race: a value carried to the receiver.
    // Its `si_signo` must be the signal asked for, which `rt_sigqueueinfo`
    // does not require and this does (`EINVAL` on 7.2). The si_code rule --
    // a code a kernel would have produced is the caller's own business only --
    // is the one `rt_sigqueueinfo` applies, so a guest cannot tell another
    // process a signal came from a fault.
    if info_addr != 0 {
        let mut signo = [0u8; 4];
        if usercopy::GuestMem.read(info_addr, &mut signo) != 0 {
            return Err(Errno::EFAULT);
        }
        if i32::from_le_bytes(signo) as u32 != sig {
            return Err(Errno::EINVAL);
        }
    }
    match (scope, info_addr != 0) {
        (PIDFD_SIGNAL_THREAD, false) => kernel_signalcalls::sys_tgkill(tgid, pid, sig),
        (PIDFD_SIGNAL_THREAD, true) => kernel_signalcalls::sys_rt_tgsigqueueinfo(tgid, pid, sig, info_addr),
        (PIDFD_SIGNAL_THREAD_GROUP, false) => kernel_signalcalls::sys_kill(tgid, sig),
        (PIDFD_SIGNAL_THREAD_GROUP, true) => kernel_signalcalls::sys_rt_sigqueueinfo(tgid, sig, info_addr),
        (_, info) => {
            let pgid = {
                let pids = PidsGuard::take();
                pids.find_by_ref(target.task)
                    .and_then(|t| t.group())
                    .map(kernel_pids::Group::pgid)
                    .ok_or(Errno::ESRCH)?
            };
            if info {
                kernel_signalcalls::pgrp_sigqueueinfo(pgid, sig, info_addr)
            } else {
                kernel_signalcalls::kill_pgrp(pgid, sig)
            }
        }
    }
}

/// `pidfd_getfd(2)`: a duplicate, in the caller's table, of descriptor
/// `targetfd` in the process `pidfd_no` names.
///
/// The new descriptor shares the open file description -- it is the same
/// object `SCM_RIGHTS` would have carried -- and is always close-on-exec.
/// Linux asks `PTRACE_MODE_ATTACH_REALCREDS`, as `process_vm_readv` does.
///
/// Measured on 7.2: `flags` must be 0; the `PIDFD_SELF_*` sentinels are
/// `EBADF`; a process that has exited is `ESRCH` whether or not it has been
/// reaped; a number that is not open there is `EBADF`.
pub fn sys_pidfd_getfd(pidfd_no: c_int, targetfd: c_int, flags: u32) -> Result<c_int, Errno> {
    strace!("pidfd_getfd({pidfd_no}, {targetfd}, {flags:#x})");
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let target = pidfd_get(pidfd_no, false)?;
    let table = {
        let pids = PidsGuard::take();
        let Some(task) = pids.find_by_ref(target.task).filter(|t| !t.is_zombie()) else {
            return Err(Errno::ESRCH);
        };
        if !task.may_ptrace(kernel_creds::PtraceMode::AttachReal) {
            return Err(Errno::EPERM);
        }
        task.files().ok_or(Errno::ESRCH)?
    };
    // The table's own lock, with `pids_lock` released: the `Arc` keeps the
    // table, and the lookup's reference keeps the description.
    let Some(file) = table.lookup_retain(targetfd) else {
        return Err(Errno::EBADF);
    };
    drop(table);
    Errno::split(fs_fdobj::f_install_start(file, 0, true) as i64).map(|n| n as c_int)
}

/// The process a pidfd names, for `waitid(P_PIDFD, ...)`: its pid and whether
/// the description is `PIDFD_NONBLOCK`.
///
/// Linux resolves the descriptor in `pidfd_get_pid` before `do_wait` runs, and
/// so does this: `f_get` takes the descriptor table's lock and `do_wait` takes
/// `pids_lock`, and doing them in that order is what keeps them apart. The
/// registry is asked here too, and released again before `do_wait` takes it.
///
/// `EINVAL` for a negative number, the sentinels included (`kernel_waitid`
/// refuses `upid < 0` before it looks); `EBADF` for a number that is not a
/// pidfd; `ECHILD` for a process that has been reaped -- the descriptor's
/// reference names *no* task rather than whichever one has since been handed
/// the number, which is `do_wait`'s answer for a `struct pid` with no task.
pub fn pidfd_resolve(pidfd_no: c_int) -> Result<(c_int, bool), Errno> {
    if pidfd_no < 0 {
        return Err(Errno::EINVAL);
    }
    let target = pidfd_get(pidfd_no, false)?;
    if PidsGuard::take().find_by_ref(target.task).is_none() {
        return Err(Errno::ECHILD);
    }
    Ok((target.task.pid, target.nonblock))
}

/// `pollset`'s callback table takes a `*mut c_void` context — that crate is a
/// leaf and genuinely does not know what a watcher is watching — so the cast
/// back to a descriptor happens here, where it is known.
fn wake(fd: &ffi::fd, types: c_int) {
    fs_poll::poll_wakeup(fd, types);
}

/// `PIDFD_GET_INFO` and `struct pidfd_info`.
mod info {
    use super::*;

    pub(super) const SIZE_VER0: usize = 64;
    /// Through `supported_mask`: the fourth published size, and 7.2's.
    const SIZE_VER3: usize = 88;

    const PID: u64 = 1;
    const CREDS: u64 = 2;
    const EXIT: u64 = 8;
    const COREDUMP: u64 = 16;
    const SUPPORTED_MASK: u64 = 32;
    /// What `supported_mask` reports: every flag 7.2 defines. A kernel built
    /// without cgroups or core dumps reports the same constant -- the field
    /// says which requests this kernel understands, and the mask in the
    /// answer says which it could fill, which here never includes
    /// `PIDFD_INFO_CGROUPID` or `PIDFD_INFO_COREDUMP`.
    const SUPPORTED: u64 = 0xff;

    /// Field offsets, from `linux/pidfd.h`.
    mod at {
        pub const MASK: usize = 0;
        pub const PID: usize = 16;
        pub const TGID: usize = 20;
        pub const PPID: usize = 24;
        pub const RUID: usize = 28;
        pub const EXIT_CODE: usize = 60;
        pub const SUPPORTED_MASK: usize = 80;
    }

    fn put(buf: &mut [u8], at: usize, v: &[u8]) {
        if let Some(dst) = buf.get_mut(at..at + v.len()) {
            dst.copy_from_slice(v);
        }
    }

    /// Fill `buf`, which holds the caller's struct, from `state`. Only the
    /// request mask is read; the answer goes in the caller's bytes, and a
    /// field past the end of a short struct is not written -- nor is its bit
    /// set, which is the struct's rule.
    pub(super) fn fill(state: &pidfd::PidFd, buf: &mut [u8]) -> Result<(), Errno> {
        let want = u64::from_le_bytes(buf[..8].try_into().unwrap());
        let mut out = [0u8; SIZE_VER3];
        let mut mask = 0;
        {
            let pids = PidsGuard::take();
            match pids.find_by_ref(state.target).filter(|_| !state.is_reaped()) {
                Some(task) => {
                    let c = task.creds();
                    let ppid = task.parent().map_or(0, |p| p.tgid());
                    put(&mut out, at::PID, &(task.pid() as u32).to_le_bytes());
                    put(&mut out, at::TGID, &(task.tgid() as u32).to_le_bytes());
                    put(&mut out, at::PPID, &(ppid as u32).to_le_bytes());
                    let ids = [
                        c.uid(), c.gid(), c.euid(), c.egid(), c.suid(), c.sgid(), c.fsuid(), c.fsgid(),
                    ];
                    for (i, id) in ids.iter().enumerate() {
                        put(&mut out, at::RUID + 4 * i, &id.to_le_bytes());
                    }
                    mask |= PID | CREDS;
                }
                // Gone: only the exit status is left, and only for a caller
                // that asked for it. Measured: `ESRCH` otherwise.
                None => {
                    let status = state.exit_status().filter(|_| want & EXIT != 0).ok_or(Errno::ESRCH)?;
                    put(&mut out, at::EXIT_CODE, &status.to_le_bytes());
                    mask |= EXIT;
                }
            }
        }
        // Nothing here dumps core, so a request for the coredump fields is
        // answered with them zero -- "did not dump" -- and its bit, which is
        // what 7.2 does for a process that did not.
        if want & COREDUMP != 0 {
            mask |= COREDUMP;
        }
        // The bit whenever it is asked for and the field only where it fits:
        // measured, a 72-byte request gets `PIDFD_INFO_SUPPORTED_MASK` in the
        // mask and its struct left alone past byte 72.
        if want & SUPPORTED_MASK != 0 {
            put(&mut out, at::SUPPORTED_MASK, &SUPPORTED.to_le_bytes());
            mask |= SUPPORTED_MASK;
        }
        put(&mut out, at::MASK, &mask.to_le_bytes());
        // `copy_struct_to_user`: as much of this kernel's struct as fits, and
        // zeroes past it for a caller that knows a longer one.
        let n = buf.len().min(SIZE_VER3);
        buf[..n].copy_from_slice(&out[..n]);
        buf[n..].fill(0);
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn the_offsets_are_linuxs() {
            // mask, cgroupid, then eleven u32 from pid to fsgid, then exit_code.
            assert_eq!(super::at::PID, 16);
            assert_eq!(super::at::RUID + 4 * 8, 60);
            assert_eq!(super::at::EXIT_CODE, 60);
            // exit_code, four coredump words, then supported_mask.
            assert_eq!(super::at::EXIT_CODE + 4 + 16, super::at::SUPPORTED_MASK);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_numbers_split_as_linux_encodes_them() {
        // _IOWR(0xFF, 11, 64)
        let cmd = ((3u32 << 30) | (64 << 16) | (0xFF << 8) | 11) as c_int;
        assert_eq!(ioc(cmd), (3, 64, 0xFF, 11));
        assert_eq!(ffi::FdOps::ioctl_size(&PidfdOps, cmd), 64);
        // 56 bytes is below the first published struct: ENOTTY, measured.
        let short = ((3u32 << 30) | (56 << 16) | (0xFF << 8) | 11) as c_int;
        assert_eq!(ffi::FdOps::ioctl_size(&PidfdOps, short), -1);
        // _IO(0xFF, 3), PIDFD_GET_MNT_NAMESPACE.
        assert_eq!(ffi::FdOps::ioctl_size(&PidfdOps, (0xFF << 8) | 3), 0);
        assert_eq!(ffi::FdOps::ioctl_size(&PidfdOps, (0xFF << 8) | 12), -1);
    }
}
