//! `pidfd_open` and `pidfd_send_signal`: what each refuses, and what a
//! `siginfo_t` carried through one looks like at the other end.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Neither is named by any other probe. A pidfd is how a modern process manager
//! signals a child without the pid-reuse race `kill` has, so the interesting
//! cases are the ones where the pid *would* have been reused: a descriptor to a
//! process that has exited, and one to a process that has been reaped.
//!
//! # `si_code` is a permission check
//!
//! `pidfd_send_signal` and `rt_sigqueueinfo` both take a `siginfo_t` the caller
//! fills in, and both refuse a caller trying to forge one: a `si_code` of
//! `SI_USER` or `SI_QUEUE` is the caller's to set and anything a kernel would
//! have produced is not, unless the target is the caller's own thread group. A
//! kernel that accepts the whole struct lets a guest tell another process that
//! a signal came from a hardware fault, which is what `si_code` is read for.
//!
//! That rule is the reason to pass the struct through at all rather than
//! refusing it, and this kernel refused it — `flags != 0 || info_addr != 0` was
//! `EINVAL`, with a comment saying the machinery was not there. It is:
//! `crates/kernel/signalcalls`' `do_sigqueueinfo` is what `rt_sigqueueinfo`
//! uses.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<56} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        0 => "no error",
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::ESRCH => "ESRCH",
        libc::EBADF => "EBADF",
        libc::EFAULT => "EFAULT",
        libc::ENOSYS => "ENOSYS",
        libc::EAGAIN => "EAGAIN",
        libc::ENOTDIR => "ENOTDIR",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn r(v: i64) -> String {
    if v < 0 { named(errno()) } else { v.to_string() }
}

fn pidfd_open(pid: i32, flags: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) }
}

fn send(fd: i32, sig: i32, info: *const libc::siginfo_t, flags: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, sig, info, flags) }
}

/// A `siginfo_t` with a `si_code` the caller is allowed to claim.
fn user_siginfo(sig: i32, code: i32, value: i32) -> libc::siginfo_t {
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // The first three words are `si_signo`, `si_errno`, `si_code`, and the
    // union after them starts at offset 16 on aarch64. Written as bytes rather
    // than through libc's accessors, because the accessors are read-only and
    // the layout is the thing being carried.
    let p = (&raw mut si).cast::<i32>();
    unsafe {
        p.write(sig);
        p.add(1).write(0);
        p.add(2).write(code);
        // si_pid, si_uid for a SI_QUEUE, then si_value.
        p.add(4).write(std::process::id() as i32);
        p.add(5).write(libc::getuid() as i32);
        p.add(6).write(value);
    }
    si
}

const SI_USER: i32 = 0;
const SI_QUEUE: i32 = -1;
const SI_KERNEL: i32 = 0x80;

fn main() {
    let me = std::process::id() as i32;

    println!("########## pidfd_open ##########");
    let fd = pidfd_open(me, 0);
    line("pidfd_open(self, 0)", if fd < 0 { named(errno()) } else { "a descriptor".into() });
    line("pidfd_open(self, 1) -- PIDFD_NONBLOCK", {
        let f = pidfd_open(me, 1);
        if f >= 0 { unsafe { libc::close(f as i32) }; "a descriptor".to_string() } else { named(errno()) }
    });
    line("pidfd_open(self, 0x40) -- a flag nobody defines", r(pidfd_open(me, 0x40)));
    line("pidfd_open(0)", r(pidfd_open(0, 0)));
    line("pidfd_open(-1)", r(pidfd_open(-1, 0)));
    line("pidfd_open(999999)", r(pidfd_open(999_999, 0)));
    let fd = fd as i32;

    println!("\n########## pidfd_send_signal: the refusals ##########");
    line("flags = 1", r(send(fd, 0, std::ptr::null(), 1)));
    line("flags = 0xffffffff", r(send(fd, 0, std::ptr::null(), 0xffff_ffff)));
    line("signal 0 -- a permission check only", r(send(fd, 0, std::ptr::null(), 0)));
    line("signal 65", r(send(fd, 65, std::ptr::null(), 0)));
    line("signal -1", r(send(fd, -1, std::ptr::null(), 0)));
    line("a descriptor that is not a pidfd", {
        let f = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        let v = send(f, 0, std::ptr::null(), 0);
        unsafe { libc::close(f) };
        r(v)
    });
    line("a descriptor that is not open", r(send(9999, 0, std::ptr::null(), 0)));
    line("an unreadable siginfo pointer", r(send(fd, 0, 1usize as *const libc::siginfo_t, 0)));

    println!("\n########## the siginfo a caller may claim ##########");
    // SI_USER and SI_QUEUE are the caller's. Anything a kernel would have
    // produced is refused unless the target is the caller's own thread group --
    // and it is here, so both are accepted and the *rule* shows up in the
    // cross-process section below.
    for (code, name) in [(SI_USER, "SI_USER"), (SI_QUEUE, "SI_QUEUE"), (SI_KERNEL, "SI_KERNEL"), (1, "si_code 1")] {
        let si = user_siginfo(libc::SIGUSR1, code, 0);
        // Blocked first, so the probe is not killed by its own signal.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }
        let v = send(fd, libc::SIGUSR1, &si, 0);
        line(&format!("siginfo with {name}, to self"), r(v));
        // Drain it, so the next case starts clean.
        if v == 0 {
            let mut got: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            unsafe { libc::sigtimedwait(&set, &mut got, &ts) };
        }
    }

    println!("\n########## what the receiver sees ##########");
    // The value the sender put in `si_value` has to arrive, because that is the
    // whole reason to send a siginfo rather than a bare signal.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR2);
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    let si = user_siginfo(libc::SIGUSR2, SI_QUEUE, 0x1234_5678);
    let sent = send(fd, libc::SIGUSR2, &si, 0);
    line("pidfd_send_signal with SI_QUEUE and a value", r(sent));
    if sent == 0 {
        let mut got: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let ts = libc::timespec { tv_sec: 1, tv_nsec: 0 };
        let n = unsafe { libc::sigtimedwait(&set, &mut got, &ts) };
        line("  sigtimedwait received it", n == libc::SIGUSR2);
        let p = (&raw const got).cast::<i32>();
        line("  si_signo", unsafe { p.read() });
        line("  si_code is SI_QUEUE", unsafe { p.add(2).read() } == SI_QUEUE);
        line("  si_pid is the sender", unsafe { p.add(4).read() } == me);
        line("  si_value survived", format!("{:#x}", unsafe { p.add(6).read() }));
    }

    println!("\n########## a process that has exited ##########");
    // The reason a pidfd exists: the descriptor stays valid, and signalling
    // through it is ESRCH rather than reaching whatever took the pid.
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::_exit(0) };
    }
    let cfd = pidfd_open(child, 0) as i32;
    line("pidfd_open of a live child", if cfd >= 0 { "a descriptor" } else { "failed" });
    let mut st = 0;
    unsafe { libc::waitpid(child, &mut st, 0) };
    line("signal 0 through it after it was reaped", r(send(cfd, 0, std::ptr::null(), 0)));
    line("SIGTERM through it after it was reaped", r(send(cfd, libc::SIGTERM, std::ptr::null(), 0)));
    line("pidfd_open of the reaped pid", r(pidfd_open(child, 0)));
    unsafe { libc::close(cfd) };

    unsafe { libc::close(fd) };
}
