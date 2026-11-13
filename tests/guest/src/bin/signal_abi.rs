//! `rt_sigprocmask` and `rt_sigaction` at the syscall boundary.
//!
//! Through `syscall(2)` rather than libc, because libc validates the arguments
//! that are interesting here — a `how` it does not recognise, a `sigsetsize`
//! that is not 8 — and answers them itself without reaching the kernel.
//!
//! What this pins is the order the kernel does things in, which is observable
//! whenever two of them could fail:
//!
//! - An unreadable `set` faults **before** a bad `how` is judged. Linux copies
//!   first and validates second, so `rt_sigprocmask(99, <unmapped>, ...)` is
//!   `EFAULT` and not `EINVAL`.
//! - `oldset` is the mask from **before** the change, not after.
//! - A bad `how` with no `set` is not an error at all, because nothing looks at
//!   it: `if (nset) { ... sigprocmask(how, ...) }`.
//!
//! Compared against a real kernel by `differential.sh`.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// What the last SA_SIGINFO handler read out of `si_code`.
static SEEN_CODE: AtomicI32 = AtomicI32::new(0);

extern "C" fn code_handler(
    _sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    // Read at offset 8 rather than through an accessor: which offset the value
    // comes from is half the question a siginfo test is asking.
    let code = if info.is_null() {
        0
    } else {
        let raw = unsafe { std::slice::from_raw_parts(info.cast::<u8>(), 128) };
        i32::from_ne_bytes(raw[8..12].try_into().unwrap())
    };
    SEEN_CODE.store(code, Ordering::SeqCst);
}

const SIG_BLOCK: i64 = 0;
const SIG_UNBLOCK: i64 = 1;
const SIG_SETMASK: i64 = 2;

/// An address no process has mapped. High enough to be nowhere, low enough to
/// be inside the address space a guest may name.
const UNMAPPED: i64 = 0x3000_0000_0000;

fn sigprocmask(how: i64, set: i64, oldset: i64, size: i64) -> i64 {
    unsafe { libc::syscall(libc::SYS_rt_sigprocmask, how, set, oldset, size) }
}

fn sigaction(sig: i64, act: i64, oldact: i64, size: i64) -> i64 {
    unsafe { libc::syscall(libc::SYS_rt_sigaction, sig, act, oldact, size) }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// The kernel's `struct sigaction`: handler, flags, restorer, mask — eight
/// bytes each. Not libc's, whose `sa_flags` is four.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KernelSigaction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

static KILL0_SEEN: AtomicBool = AtomicBool::new(false);

extern "C" fn kill0_handler(_sig: i32) {
    KILL0_SEEN.store(true, Ordering::SeqCst);
}

fn main() {
    let mut h = Harness::new();

    h.group("sigprocmask-reports-the-mask-from-before-the-change");
    let mut set: u64 = 1 << (libc::SIGUSR1 - 1);
    let mut old: u64 = 0;
    check!(
        h,
        sigprocmask(SIG_SETMASK, &mut set as *mut u64 as i64, &mut old as *mut u64 as i64, 8) == 0,
        "SIG_SETMASK with both pointers"
    );
    let before = old;
    let mut set2: u64 = 1 << (libc::SIGUSR2 - 1);
    check!(
        h,
        sigprocmask(SIG_SETMASK, &mut set2 as *mut u64 as i64, &mut old as *mut u64 as i64, 8) == 0,
        "and again"
    );
    check!(
        h,
        old == 1 << (libc::SIGUSR1 - 1),
        "oldset is what was blocked before this call: {old:#x}"
    );
    check!(h, before == 0 || before != old, "the two reports differ");

    h.group("block-and-unblock-are-relative-to-what-is-there");
    let mut m: u64 = 1 << (libc::SIGUSR1 - 1);
    sigprocmask(SIG_SETMASK, &mut m as *mut u64 as i64, 0, 8);
    let mut add: u64 = 1 << (libc::SIGUSR2 - 1);
    check!(
        h,
        sigprocmask(SIG_BLOCK, &mut add as *mut u64 as i64, 0, 8) == 0,
        "SIG_BLOCK"
    );
    check!(h, sigprocmask(0, 0, &mut old as *mut u64 as i64, 8) == 0, "read it back");
    check!(
        h,
        old == (1 << (libc::SIGUSR1 - 1)) | (1 << (libc::SIGUSR2 - 1)),
        "both are blocked now: {old:#x}"
    );
    check!(
        h,
        sigprocmask(SIG_UNBLOCK, &mut add as *mut u64 as i64, 0, 8) == 0,
        "SIG_UNBLOCK"
    );
    sigprocmask(0, 0, &mut old as *mut u64 as i64, 8);
    check!(
        h,
        old == 1 << (libc::SIGUSR1 - 1),
        "and only the first is left: {old:#x}"
    );

    h.group("an-unreadable-set-faults-before-a-bad-how-is-judged");
    check!(
        h,
        sigprocmask(99, UNMAPPED, 0, 8) == -1 && errno() == libc::EFAULT,
        "a bad how and an unmapped set is EFAULT: errno {}",
        errno()
    );
    check!(
        h,
        sigprocmask(SIG_SETMASK, UNMAPPED, 0, 8) == -1 && errno() == libc::EFAULT,
        "and so is a good how with one"
    );

    h.group("a-bad-how-with-a-readable-set-is-einval");
    let mut any: u64 = 0;
    check!(
        h,
        sigprocmask(99, &mut any as *mut u64 as i64, 0, 8) == -1 && errno() == libc::EINVAL,
        "errno {}",
        errno()
    );

    h.group("a-bad-how-with-no-set-is-not-an-error");
    // Nothing looks at `how` when there is nothing to apply it to.
    check!(
        h,
        sigprocmask(99, 0, &mut old as *mut u64 as i64, 8) == 0,
        "and the mask still comes back"
    );

    h.group("a-sigsetsize-that-is-not-eight-is-einval");
    for size in [0i64, 4, 12, 16, 128] {
        check!(
            h,
            sigprocmask(SIG_SETMASK, &mut any as *mut u64 as i64, 0, size) == -1
                && errno() == libc::EINVAL,
            "size {size}: errno {}",
            errno()
        );
    }
    check!(
        h,
        sigaction(libc::SIGUSR1 as i64, 0, 0, 16) == -1 && errno() == libc::EINVAL,
        "rt_sigaction too: errno {}",
        errno()
    );

    h.group("sigaction-reports-the-disposition-being-replaced");
    let mut act = KernelSigaction {
        handler: libc::SIG_IGN as u64,
        ..Default::default()
    };
    let mut got = KernelSigaction::default();
    check!(
        h,
        sigaction(
            libc::SIGUSR1 as i64,
            &mut act as *mut _ as i64,
            &mut got as *mut _ as i64,
            8
        ) == 0,
        "install SIG_IGN"
    );
    let was = got.handler;
    check!(h, was == 0, "the old one was SIG_DFL: {was:#x}");

    act.handler = libc::SIG_DFL as u64;
    check!(
        h,
        sigaction(
            libc::SIGUSR1 as i64,
            &mut act as *mut _ as i64,
            &mut got as *mut _ as i64,
            8
        ) == 0,
        "put it back"
    );
    let was = got.handler;
    check!(h, was == libc::SIG_IGN as u64, "and the old one was SIG_IGN: {was:#x}");

    h.group("sigkill-and-sigstop-may-be-read-and-not-written");
    for sig in [libc::SIGKILL, libc::SIGSTOP] {
        let mut probe = KernelSigaction::default();
        check!(
            h,
            sigaction(sig as i64, 0, &mut probe as *mut _ as i64, 8) == 0,
            "signal {sig} may be asked about"
        );
        let mut install = KernelSigaction {
            handler: libc::SIG_IGN as u64,
            ..Default::default()
        };
        check!(
            h,
            sigaction(sig as i64, &mut install as *mut _ as i64, 0, 8) == -1
                && errno() == libc::EINVAL,
            "and not set: errno {}",
            errno()
        );
    }

    h.group("a-signal-number-that-is-not-a-signal");
    // 0x80000000 as an `int` is a large negative number, which is how this
    // indexed a disposition table backwards and crashed the emulator.
    for sig in [0i64, 65, 0x8000_0000, -1] {
        let mut probe = KernelSigaction::default();
        check!(
            h,
            sigaction(sig, 0, &mut probe as *mut _ as i64, 8) == -1 && errno() == libc::EINVAL,
            "sigaction({sig:#x}) is EINVAL: errno {}",
            errno()
        );
    }

    h.group("kill-0-is-my-own-group");
    // `kill(0, sig)` means this process's *group*, and this process is in it --
    // so the signal has to come back to the caller.
    //
    // The C re-encoded it as `kill(-pgid, sig)`, and **-1 is not a process
    // group, it is every process**. A guest whose process group is 1 -- which
    // the first process's is, and which is what a program started by this
    // kernel's init runs with -- therefore turned `kill(0, SIGTERM)` into a
    // broadcast. What hid it is that the broadcast path skips the caller and
    // then answers EPERM when it finds nothing else, so the call *failed*
    // rather than killing the machine.
    //
    // Which is exactly what this checks: the handler running is the difference
    // between "my group" and "everyone but me".
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = kill0_handler as *const () as usize;
        libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());
    }
    KILL0_SEEN.store(false, Ordering::SeqCst);
    let r = unsafe { libc::kill(0, libc::SIGUSR2) };
    check!(
        h,
        r == 0,
        "kill(0, SIGUSR2) succeeds: r={r} errno={}",
        errno()
    );
    check!(
        h,
        KILL0_SEEN.load(Ordering::SeqCst),
        "and the caller is in the group it signalled"
    );

    // SA_RESETHAND is a *one-shot* handler: the disposition goes back to
    // SIG_DFL when it runs. It was written into the copy sigdisp_get filled
    // rather than into the table, so it was thrown away and the handler ran
    // every time -- a program that handles the first ^C and dies on the second
    // never died.
    //
    // Raised with the signal blocked and then taken with sigtimedwait, because
    // an unblocked second one would reach the restored SIG_DFL and end this
    // process. What is checked is the disposition, which is where the defect
    // was.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = kill0_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESETHAND;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());
    }
    KILL0_SEEN.store(false, Ordering::SeqCst);
    unsafe { libc::raise(libc::SIGUSR2) };
    check!(h, KILL0_SEEN.load(Ordering::SeqCst), "a SA_RESETHAND handler runs");
    let mut back: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe { libc::sigaction(libc::SIGUSR2, std::ptr::null(), &mut back) };
    check!(
        h,
        back.sa_sigaction == libc::SIG_DFL,
        "and the disposition is SIG_DFL afterwards: {:#x}",
        back.sa_sigaction
    );

    // si_code says which call sent it. tkill and tgkill are SI_TKILL (-6) and
    // kill is SI_USER (0); this reported SI_USER for all three, so a program
    // asking whether a signal was thread-directed was told no.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = code_handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());
    }
    SEEN_CODE.store(1234, Ordering::SeqCst);
    unsafe { libc::kill(libc::getpid(), libc::SIGUSR2) };
    check!(
        h,
        SEEN_CODE.load(Ordering::SeqCst) == 0,
        "kill sets si_code to SI_USER: {}",
        SEEN_CODE.load(Ordering::SeqCst)
    );
    SEEN_CODE.store(1234, Ordering::SeqCst);
    // musl's raise() is tkill on the calling thread.
    unsafe { libc::raise(libc::SIGUSR2) };
    check!(
        h,
        SEEN_CODE.load(Ordering::SeqCst) == -6,
        "raise, which is tkill, sets SI_TKILL: {}",
        SEEN_CODE.load(Ordering::SeqCst)
    );
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());
    }

    // ------------------------------------------------------------------
    // A siginfo carried through a pidfd.
    //
    // `pidfd_send_signal` refused a non-null `info` with EINVAL until
    // 2026-09-07, under a comment saying the machinery `rt_sigqueueinfo` has
    // was not there -- it was, and this is that call with the target already
    // resolved. Carrying a value is the reason to send a siginfo rather than a
    // bare signal, so the value arriving is what the check is about.
    h.group("a-siginfo-through-a-pidfd");
    let pidfd = unsafe {
        libc::syscall(libc::SYS_pidfd_open, std::process::id() as i32, 0)
    };
    if pidfd < 0 {
        check!(h, false, "pidfd_open on self");
    } else {
        let pidfd = pidfd as i32;
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR2);
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }
        // signo, errno, code, then si_pid, si_uid, si_value.
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let w = (&raw mut si).cast::<i32>();
        unsafe {
            w.write(libc::SIGUSR2);
            w.add(2).write(-1); // SI_QUEUE, which a caller may claim
            w.add(4).write(std::process::id() as i32);
            w.add(6).write(0x5a5a_1234);
        }
        let sent = unsafe {
            libc::syscall(libc::SYS_pidfd_send_signal, pidfd, libc::SIGUSR2, &si, 0u32)
        };
        check!(h, sent == 0, "pidfd_send_signal with a siginfo: got {sent}");

        let mut got: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let ts = libc::timespec { tv_sec: 1, tv_nsec: 0 };
        let n = unsafe { libc::sigtimedwait(&set, &mut got, &ts) };
        check!(h, n == libc::SIGUSR2, "and it arrived: got {n}");
        let r = (&raw const got).cast::<i32>();
        // The value, which is the whole point -- a kernel that accepted the
        // struct and dropped its contents would pass the two checks above.
        check!(
            h,
            unsafe { r.add(6).read() } == 0x5a5a_1234,
            "si_value survived, got {:#x}",
            unsafe { r.add(6).read() }
        );
        check!(h, unsafe { r.add(2).read() } == -1, "and si_code is still SI_QUEUE");

        // A flags word is still refused: Linux 6.9 defined three and this
        // kernel has none of them, so an older kernel's answer is the honest
        // one -- and refusing an unknown flag is what lets a caller find out.
        guest_tests::sys::clear_errno();
        let bad = unsafe {
            libc::syscall(libc::SYS_pidfd_send_signal, pidfd, 0, std::ptr::null::<u8>(), 0xffffu32)
        };
        check!(
            h,
            bad == -1 && guest_tests::sys::errno() == libc::EINVAL,
            "an unknown flags word is EINVAL, got {bad} errno {}",
            guest_tests::sys::errno()
        );
        unsafe {
            libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            libc::close(pidfd);
        }
    }

        // Leave the process as it was found, so a harness that runs more after this
    // is not looking at a blocked SIGUSR1.
    let mut none: u64 = 0;
    sigprocmask(SIG_SETMASK, &mut none as *mut u64 as i64, 0, 8);

    std::process::exit(h.finish());
}
