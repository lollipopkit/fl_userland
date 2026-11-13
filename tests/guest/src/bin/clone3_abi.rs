//! `clone3`'s argument struct, which is an *extensible* one.
//!
//! `clone3(args, size)` is the first syscall here whose argument struct is
//! versioned: the caller says how big its copy is, and the kernel is required
//! to tell the difference between a caller older than itself (short struct,
//! zero-fill the rest) and one newer than itself (long struct — accept it only
//! if every byte the kernel does not understand is zero, and answer `E2BIG`
//! otherwise). Getting the second half wrong is silent: a program compiled
//! against a newer kernel sets a field, this one drops it, and the program
//! runs with a flag it believes it asked for.
//!
//! Linux's rules, from `copy_clone_args_from_user` and `clone3_args_valid`:
//!
//! - `size > PAGE_SIZE` is `E2BIG` before anything else is looked at.
//! - `size < CLONE_ARGS_SIZE_VER0` (64) is `EINVAL`.
//! - `size` above the kernel's own struct is `E2BIG` if the tail is not all
//!   zero, and accepted if it is.
//! - `exit_signal` is a whole `u64` and must be a valid signal number with no
//!   bits above `CSIGNAL`.
//! - `set_tid` and `set_tid_size` must be both set or both clear.
//! - The signal does **not** go in `flags` here: `clone3` reuses the `CSIGNAL`
//!   bits and `CLONE_DETACHED`, so either in `flags` is `EINVAL`.
//!
//! Every check that is meant to fail reaps a process if it unexpectedly
//! succeeds, so a regression leaves nothing behind to confuse the next one.

use guest_tests::{Harness, check, check_fails, sys};

const SYS_CLONE3: libc::c_long = 435;

/// 88 bytes: eleven `u64`s, through `cgroup`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

const VER0: usize = 64;
const VER2: usize = 88;

/// The call, plus the cleanup a call that should not have succeeded needs.
///
/// A struct the kernel might read past the end of is not a `CloneArgs`: the
/// buffer is `bytes`, and `size` may name more of it than the struct occupies.
unsafe fn clone3_raw(bytes: &[u8], size: usize) -> i64 {
    sys::clear_errno();
    let r = unsafe { libc::syscall(SYS_CLONE3, bytes.as_ptr(), size) };
    if r == 0 {
        // The child of a call that was supposed to fail. Nothing here is safe
        // to run twice; leave immediately.
        unsafe { libc::_exit(7) };
    }
    if r > 0 {
        let mut status = 0;
        unsafe { libc::waitpid(r as i32, &mut status, 0) };
    }
    r
}

/// `args` laid out in a buffer big enough to describe more than it holds.
fn buffer(args: &CloneArgs, extra: usize) -> Vec<u8> {
    let mut v = vec![0u8; VER2 + extra];
    unsafe {
        std::ptr::copy_nonoverlapping(
            (args as *const CloneArgs).cast::<u8>(),
            v.as_mut_ptr(),
            VER2,
        );
    }
    v
}

fn t_size(h: &mut Harness) {
    h.group("clone3-size");
    let args = CloneArgs {
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };

    // Below the first version of the struct.
    let b = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&b, VER0 - 8) }, libc::EINVAL, "a size below CLONE_ARGS_SIZE_VER0");
    check_fails!(h, unsafe { clone3_raw(&b, 0) }, libc::EINVAL, "a size of zero");

    // Exactly the first version: everything past `tls` is the kernel's to
    // treat as zero.
    let r = unsafe { clone3_raw(&b, VER0) };
    check!(h, r > 0, "CLONE_ARGS_SIZE_VER0 alone is enough: {r} errno {}", sys::errno());

    // Larger than any struct: refused before the contents matter. A page is
    // the bound and this is far above one whatever the page size is.
    let big = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&big, 1 << 20) }, libc::E2BIG, "a size above a page");

    // Longer than this kernel's struct, all zero past the end: accepted, and
    // the caller is a newer program that asked for nothing new.
    let b = buffer(&args, 16);
    let r = unsafe { clone3_raw(&b, VER2 + 16) };
    check!(h, r > 0, "a longer struct whose tail is zero is accepted: {r} errno {}", sys::errno());

    // The same, with one bit set in the part this kernel does not understand.
    let mut b = buffer(&args, 16);
    b[VER2 + 9] = 1;
    check_fails!(
        h,
        unsafe { clone3_raw(&b, VER2 + 16) },
        libc::E2BIG,
        "a longer struct with a non-zero tail"
    );
}

fn t_exit_signal(h: &mut Harness) {
    h.group("clone3-exit-signal");

    // `exit_signal` is a u64 and every bit of it is checked.
    let args = CloneArgs {
        exit_signal: (1u64 << 32) | libc::SIGCHLD as u64,
        ..Default::default()
    };
    let b = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&b, VER2) }, libc::EINVAL, "a bit above CSIGNAL in exit_signal");

    // A number in range for the field and not a signal.
    let args = CloneArgs { exit_signal: 100, ..Default::default() };
    let b = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&b, VER2) }, libc::EINVAL, "exit_signal 100, which is not a signal");

    // Zero is allowed: it means no signal on exit.
    let args = CloneArgs::default();
    let b = buffer(&args, 0);
    let r = unsafe { clone3_raw(&b, VER2) };
    check!(h, r > 0, "exit_signal 0 means no signal, not an error: {r} errno {}", sys::errno());
}

fn t_flags(h: &mut Harness) {
    h.group("clone3-flags");

    // clone3 took the CSIGNAL bits back. The legacy way of asking -- the
    // signal OR'd into flags -- is an error here, not a second spelling.
    let args = CloneArgs {
        flags: libc::SIGCHLD as u64,
        ..Default::default()
    };
    let b = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&b, VER2) }, libc::EINVAL, "a signal in flags");

    // CLONE_DETACHED, likewise reclaimed.
    let args = CloneArgs {
        flags: 0x0040_0000,
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };
    let b = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&b, VER2) }, libc::EINVAL, "CLONE_DETACHED");

    // And a flag no kernel has.
    let args = CloneArgs {
        flags: 1u64 << 63,
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };
    let b = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&b, VER2) }, libc::EINVAL, "an unknown flag");
}

fn t_set_tid(h: &mut Harness) {
    h.group("clone3-set-tid");
    let mut tid: libc::pid_t = 4242;

    // A size with no array.
    let args = CloneArgs {
        exit_signal: libc::SIGCHLD as u64,
        set_tid_size: 1,
        ..Default::default()
    };
    let b = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&b, VER2) }, libc::EINVAL, "set_tid_size with no set_tid");

    // An array with no size.
    let args = CloneArgs {
        exit_signal: libc::SIGCHLD as u64,
        set_tid: (&raw mut tid) as u64,
        ..Default::default()
    };
    let b = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&b, VER2) }, libc::EINVAL, "set_tid with no set_tid_size");

    // A size above `MAX_PID_NS_LEVEL`, which is the one bound on this field
    // that does not depend on how deep the caller's namespace is. Asking with
    // 2 is not comparable: the container has a pid namespace of its own, so
    // it answers EPERM for the level it may not set, where a single-namespace
    // kernel answers EINVAL for a level that does not exist.
    let args = CloneArgs {
        exit_signal: libc::SIGCHLD as u64,
        set_tid: (&raw mut tid) as u64,
        set_tid_size: 33,
        ..Default::default()
    };
    let b = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&b, VER2) }, libc::EINVAL, "set_tid_size above MAX_PID_NS_LEVEL");

    // What it is for: a child at the pid the caller names. It was EPERM for
    // every request until 2026-11-11 -- the container's answer, for want of
    // CAP_CHECKPOINT_RESTORE, and not the answer to a root that has it.
    let mut want: libc::pid_t = 31000;
    let args = CloneArgs {
        exit_signal: libc::SIGCHLD as u64,
        set_tid: (&raw mut want) as u64,
        set_tid_size: 1,
        ..Default::default()
    };
    let b = buffer(&args, 0);
    let r = unsafe { clone3_raw(&b, VER2) };
    check!(h, r == 31000, "set_tid = [31000] makes the child 31000: {r} errno {}", sys::errno());
    let mut mine = unsafe { libc::getpid() };
    let args = CloneArgs { set_tid: (&raw mut mine) as u64, ..args };
    let b = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&b, VER2) }, libc::EEXIST, "set_tid naming a pid in use");
    let mut zero: libc::pid_t = 0;
    let args = CloneArgs { set_tid: (&raw mut zero) as u64, ..args };
    let b = buffer(&args, 0);
    check_fails!(h, unsafe { clone3_raw(&b, VER2) }, libc::EINVAL, "set_tid = [0]");
}

fn t_child(h: &mut Harness) {
    h.group("clone3-child");

    // The one that has to work, and the reason the rest is worth checking:
    // the child runs, and its exit is reported to the parent.
    let args = CloneArgs {
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };
    let b = buffer(&args, 0);
    sys::clear_errno();
    let pid = unsafe { libc::syscall(SYS_CLONE3, b.as_ptr(), VER2) };
    if pid == 0 {
        unsafe { libc::_exit(42) };
    }
    check!(h, pid > 0, "clone3 returns a pid to the parent: {pid} errno {}", sys::errno());
    let mut status = 0;
    let w = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    check!(h, w == pid as i32, "and the child is waitable: {w}");
    check!(
        h,
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 42,
        "with the status it exited with: {status:#x}"
    );

    // parent_tid, which is where clone3 differs from clone least and is the
    // cheapest way to know the struct was read at the offsets it says.
    let mut ptid: libc::pid_t = -1;
    let args = CloneArgs {
        flags: libc::CLONE_PARENT_SETTID as u64,
        exit_signal: libc::SIGCHLD as u64,
        parent_tid: (&raw mut ptid) as u64,
        ..Default::default()
    };
    let b = buffer(&args, 0);
    let pid = unsafe { libc::syscall(SYS_CLONE3, b.as_ptr(), VER2) };
    if pid == 0 {
        unsafe { libc::_exit(0) };
    }
    check!(h, pid > 0, "CLONE_PARENT_SETTID clone3: {pid} errno {}", sys::errno());
    let mut status = 0;
    unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    check!(
        h,
        ptid == pid as i32,
        "and parent_tid was written with the child's pid: {ptid} vs {pid}"
    );
}

/// `CLONE_CLEAR_SIGHAND`, which only `clone3` can ask for: it is bit 32, above
/// everything the legacy call's `int` can hold. The child gets a disposition
/// table at its defaults instead of a copy of the parent's — what `posix_spawn`
/// wants, and what it otherwise does with one `sigaction` per signal.
fn t_clear_sighand(h: &mut Harness) {
    h.group("clone3-clear-sighand");
    const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;

    extern "C" fn handler(_: libc::c_int) {}

    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handler as *const () as usize;
        libc::sigaction(libc::SIGUSR1, &raw const act, std::ptr::null_mut());

        // An ordinary child keeps it; the cleared one does not. Both are asked
        // the same question, so a child that cannot read its own disposition
        // at all fails the first rather than passing the second.
        for (clear, want_default) in [(0u64, false), (CLONE_CLEAR_SIGHAND, true)] {
            let args = CloneArgs {
                flags: clear,
                exit_signal: libc::SIGCHLD as u64,
                ..Default::default()
            };
            let b = buffer(&args, 0);
            sys::clear_errno();
            let pid = libc::syscall(SYS_CLONE3, b.as_ptr(), VER2);
            if pid == 0 {
                let mut cur: libc::sigaction = std::mem::zeroed();
                let r = libc::sigaction(libc::SIGUSR1, std::ptr::null(), &raw mut cur);
                let is_default = cur.sa_sigaction == libc::SIG_DFL;
                libc::_exit(if r == 0 && is_default == want_default { 0 } else { 1 });
            }
            check!(
                h,
                pid > 0,
                "clone3 with clear_sighand={clear:#x}: {pid} errno {}",
                sys::errno()
            );
            let mut status = 0;
            libc::waitpid(pid as i32, &mut status, 0);
            check!(
                h,
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "the child sees SIGUSR1 {} its handler: status {status:#x}",
                if want_default { "without" } else { "with" }
            );
        }

        // Asking to share the table and to clear it at once is a contradiction.
        let args = CloneArgs {
            flags: CLONE_CLEAR_SIGHAND | libc::CLONE_SIGHAND as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..Default::default()
        };
        let b = buffer(&args, 0);
        check_fails!(
            h,
            clone3_raw(&b, VER2),
            libc::EINVAL,
            "CLONE_CLEAR_SIGHAND together with CLONE_SIGHAND"
        );

        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGUSR1, &raw const act, std::ptr::null_mut());
    }
}

/// `CLONE_PIDFD`, whose descriptor `clone3` stores in its own `pidfd` field
/// rather than where `CLONE_PARENT_SETTID` stores the tid -- so the two flags,
/// which exclude each other in the legacy call, go together here. Linux has
/// taken it in `clone3` since 5.2; this kernel answered `EINVAL` until
/// 2026-09-30. The container's seccomp profile blocks `clone3`, so no probe
/// could compare it.
fn t_pidfd(h: &mut Harness) {
    h.group("clone3-pidfd");
    let mut pidfd: i32 = -1;
    let mut ptid: libc::pid_t = -1;
    let args = CloneArgs {
        flags: (libc::CLONE_PIDFD | libc::CLONE_PARENT_SETTID) as u64,
        pidfd: (&raw mut pidfd) as u64,
        parent_tid: (&raw mut ptid) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };
    let b = buffer(&args, 0);
    sys::clear_errno();
    let pid = unsafe { libc::syscall(SYS_CLONE3, b.as_ptr(), VER2) };
    if pid == 0 {
        unsafe { libc::_exit(3) };
    }
    check!(h, pid > 0, "clone3 with CLONE_PIDFD and CLONE_PARENT_SETTID: {pid} errno {}", sys::errno());
    check!(h, pidfd >= 0, "the pidfd is in args.pidfd: {pidfd}");
    check!(h, ptid == pid as i32, "and the tid in args.parent_tid: {ptid} vs {pid}");
    if pidfd >= 0 {
        let flags = unsafe { libc::fcntl(pidfd, libc::F_GETFD) };
        check!(h, flags & libc::FD_CLOEXEC != 0, "close-on-exec: {flags}");
        let mut p = libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut p, 1, 5000) };
        check!(h, ready == 1, "and it becomes readable when the child exits: {ready}");
        unsafe { libc::close(pidfd) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid as i32, &mut status, 0) };
    check!(h, libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 3, "status {status:#x}");

    // `CLONE_PIDFD | CLONE_THREAD` is 6.9's thread pidfd, and it was EINVAL
    // here -- the pre-6.9 answer -- until the pidfd could name a thread. It
    // makes a thread, which this harness cannot run safely without a stack
    // of its own; `pidfd_semantics` checks thread pidfds through
    // `pidfd_open(PIDFD_THREAD)` instead.
}

fn main() {
    let mut h = Harness::new();
    t_size(&mut h);
    t_exit_signal(&mut h);
    t_flags(&mut h);
    t_set_tid(&mut h);
    t_child(&mut h);
    t_clear_sighand(&mut h);
    t_pidfd(&mut h);
    std::process::exit(h.finish());
}
