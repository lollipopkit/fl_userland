//! What `clone(2)` answers for a set of flags.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Every thread and every process in every guest comes through this call, and
//! its flag rules are the ones a libc is written against: `CLONE_THREAD` needs
//! `CLONE_SIGHAND`, which needs `CLONE_VM`; a namespace flag with the thing it
//! would unshare is `EINVAL`; an exit signal above 64 is `EINVAL`; and the
//! legacy call reads only the low 32 bits of the flags, so `clone3`'s
//! `CLONE_CLEAR_SIGHAND` is silently nothing. `clone3_abi` checks the
//! structured call; this asks the legacy one.
//!
//! # Which combinations may run
//!
//! A case whose flags include `CLONE_VM` is only issued when both kernels
//! refuse it: a child sharing this process's memory *and* its stack — the
//! stack argument is 0 throughout — would run over the parent's frames.
//! Every combination that can succeed is fork-shaped, and the child exits
//! at once.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<58} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::EFAULT => "EFAULT",
        libc::ENOSYS => "ENOSYS",
        libc::EAGAIN => "EAGAIN",
        libc::ENOMEM => "ENOMEM",
        libc::EUSERS => "EUSERS",
        libc::EBADF => "EBADF",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

const CLONE_VM: u64 = 0x100;
const CLONE_FS: u64 = 0x200;
const CLONE_FILES: u64 = 0x400;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_PTRACE: u64 = 0x2000;
const CLONE_VFORK: u64 = 0x4000;
const CLONE_PARENT: u64 = 0x8000;
const CLONE_THREAD: u64 = 0x10000;
const CLONE_NEWNS: u64 = 0x20000;
const CLONE_SYSVSEM: u64 = 0x40000;
const CLONE_SETTLS: u64 = 0x80000;
const CLONE_PARENT_SETTID: u64 = 0x100000;
const CLONE_CHILD_CLEARTID: u64 = 0x200000;
const CLONE_DETACHED: u64 = 0x400000;
const CLONE_UNTRACED: u64 = 0x800000;
const CLONE_CHILD_SETTID: u64 = 0x1000000;
const CLONE_NEWCGROUP: u64 = 0x2000000;
const CLONE_NEWUTS: u64 = 0x4000000;
const CLONE_NEWIPC: u64 = 0x8000000;
const CLONE_NEWUSER: u64 = 0x10000000;
const CLONE_NEWPID: u64 = 0x20000000;
const CLONE_IO: u64 = 0x80000000;
const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

const SIGCHLD: u64 = 17;

/// `clone(flags, stack = 0, ptid, tls, ctid)`: the child, if there is one,
/// exits at once with status 7; the parent reaps it and reports.
fn clone(flags: u64, ptid: u64, tls: u64, ctid: u64) -> String {
    let _ = std::io::stdout().flush();
    let r = unsafe { libc::syscall(libc::SYS_clone, flags, 0u64, ptid, tls, ctid) };
    if r == 0 {
        unsafe { libc::_exit(7) };
    }
    if r < 0 {
        return named(errno());
    }
    let pid = r as i32;
    let mut status = 0;
    // The child's exit signal is whatever the flags said, and a child with
    // none is only reapable with __WALL.
    let w = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
    if w != pid {
        return format!("child {pid}, waitpid {w} ({})", named(errno()));
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 7 {
        "child ran".to_string()
    } else {
        format!("child status {status:#x}")
    }
}

/// A case whose flags include CLONE_VM, issued from a forked child so that a
/// kernel which *accepts* it — a thread sharing the child's stack — takes the
/// child down and not the probe. The line is the child's.
fn clone_vm(what: &str, flags: u64) {
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        line(what, clone(flags, 0, 0, 0));
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        line(what, format!("the child died, status {status:#x}"));
    }
}

fn main() {
    // A child's exit signal is delivered to *this* process, and the default
    // action of SIGUSR1 and of signal 64 is to terminate it. The container's
    // probe survived because it is pid 1 there, which the kernel does not
    // kill with a default-action signal; here it is not. Ignore them, which
    // is the same outcome on both sides -- the child is still reapable.
    unsafe {
        libc::signal(libc::SIGUSR1, libc::SIG_IGN);
        libc::signal(64, libc::SIG_IGN);
    }
    println!("## the fork shapes");
    line("SIGCHLD alone", clone(SIGCHLD, 0, 0, 0));
    line("no exit signal", clone(0, 0, 0, 0));
    line("exit signal SIGUSR1", clone(10, 0, 0, 0));
    line("exit signal 64", clone(64, 0, 0, 0));
    line("exit signal 65", clone(65, 0, 0, 0));
    line("exit signal 255", clone(255, 0, 0, 0));
    line("CLONE_FS", clone(SIGCHLD | CLONE_FS, 0, 0, 0));
    line("CLONE_FILES", clone(SIGCHLD | CLONE_FILES, 0, 0, 0));
    line("CLONE_SYSVSEM", clone(SIGCHLD | CLONE_SYSVSEM, 0, 0, 0));
    line("CLONE_PTRACE", clone(SIGCHLD | CLONE_PTRACE, 0, 0, 0));
    line("CLONE_UNTRACED", clone(SIGCHLD | CLONE_UNTRACED, 0, 0, 0));
    line("CLONE_IO", clone(SIGCHLD | CLONE_IO, 0, 0, 0));
    line("CLONE_DETACHED", clone(SIGCHLD | CLONE_DETACHED, 0, 0, 0));
    line("CLONE_VFORK", clone(SIGCHLD | CLONE_VFORK, 0, 0, 0));
    line("CLONE_PARENT", clone(SIGCHLD | CLONE_PARENT, 0, 0, 0));
    line("CLONE_CLEAR_SIGHAND, bit 32", clone(SIGCHLD | CLONE_CLEAR_SIGHAND, 0, 0, 0));
    line("CLONE_INTO_CGROUP, bit 33", clone(SIGCHLD | CLONE_INTO_CGROUP, 0, 0, 0));
    line("every bit above 33", clone(SIGCHLD | !0xf_ffff_ffff, 0, 0, 0));
    line("an unused bit, 0x40", clone(SIGCHLD | 0x40, 0, 0, 0));

    println!("## the thread rules");
    line("CLONE_THREAD alone", clone(SIGCHLD | CLONE_THREAD, 0, 0, 0));
    line("CLONE_THREAD | CLONE_SIGHAND, no VM", clone(SIGCHLD | CLONE_THREAD | CLONE_SIGHAND, 0, 0, 0));
    line("CLONE_SIGHAND, no VM", clone(SIGCHLD | CLONE_SIGHAND, 0, 0, 0));
    clone_vm("CLONE_THREAD | CLONE_VM, no SIGHAND", SIGCHLD | CLONE_THREAD | CLONE_VM);
    clone_vm("CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | CLONE_PIDFD", CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | CLONE_PIDFD);
    clone_vm("CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | CLONE_NEWPID", CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | CLONE_NEWPID);
    clone_vm("CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | CLONE_NEWUSER", CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | CLONE_NEWUSER);
    clone_vm("CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_NEWNS | CLONE_FS", CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_NEWNS | CLONE_FS);

    println!("## the pidfd rules");
    line("CLONE_PIDFD | CLONE_DETACHED", clone(SIGCHLD | CLONE_PIDFD | CLONE_DETACHED, 0, 0, 0));
    line("CLONE_PIDFD | CLONE_PARENT_SETTID", clone(SIGCHLD | CLONE_PIDFD | CLONE_PARENT_SETTID, 0, 0, 0));
    line("CLONE_PIDFD with a NULL ptid", clone(SIGCHLD | CLONE_PIDFD, 0, 0, 0));
    line("CLONE_PIDFD with a bad ptid", clone(SIGCHLD | CLONE_PIDFD, 1, 0, 0));
    {
        let mut fd: i32 = -1;
        let r = clone(SIGCHLD | CLONE_PIDFD, &mut fd as *mut i32 as u64, 0, 0);
        line("CLONE_PIDFD", format!("{r}, fd {}", if fd >= 0 { "set" } else { "unset" }));
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    println!("## the namespace rules");
    line("CLONE_NEWNS | CLONE_FS", clone(SIGCHLD | CLONE_NEWNS | CLONE_FS, 0, 0, 0));
    line("CLONE_NEWUSER | CLONE_FS", clone(SIGCHLD | CLONE_NEWUSER | CLONE_FS, 0, 0, 0));
    line("CLONE_NEWIPC | CLONE_SYSVSEM", clone(SIGCHLD | CLONE_NEWIPC | CLONE_SYSVSEM, 0, 0, 0));
    line("CLONE_NEWPID | CLONE_PARENT", clone(SIGCHLD | CLONE_NEWPID | CLONE_PARENT, 0, 0, 0));
    line("CLONE_NEWUSER | CLONE_PARENT", clone(SIGCHLD | CLONE_NEWUSER | CLONE_PARENT, 0, 0, 0));
    line("CLONE_NEWCGROUP", clone(SIGCHLD | CLONE_NEWCGROUP, 0, 0, 0));
    line("CLONE_NEWUTS", clone(SIGCHLD | CLONE_NEWUTS, 0, 0, 0));

    println!("## the tid pointers");
    line("CLONE_PARENT_SETTID with a NULL ptid", clone(SIGCHLD | CLONE_PARENT_SETTID, 0, 0, 0));
    line("CLONE_PARENT_SETTID with a bad ptid", clone(SIGCHLD | CLONE_PARENT_SETTID, 1, 0, 0));
    {
        let mut tid: i32 = -1;
        let r = clone(SIGCHLD | CLONE_PARENT_SETTID, &mut tid as *mut i32 as u64, 0, 0);
        line("CLONE_PARENT_SETTID", format!("{r}, tid {}", if tid > 0 { "set" } else { "unset" }));
    }
    line("CLONE_CHILD_SETTID with a bad ctid", clone(SIGCHLD | CLONE_CHILD_SETTID, 0, 0, 1));
    line("CLONE_CHILD_CLEARTID with a bad ctid", clone(SIGCHLD | CLONE_CHILD_CLEARTID, 0, 0, 1));
    line("CLONE_SETTLS with tls 0", clone(SIGCHLD | CLONE_SETTLS, 0, 0, 0));
    line("CLONE_SETTLS with an unmapped tls", clone(SIGCHLD | CLONE_SETTLS, 0, 0xdead_0000, 0));
}
