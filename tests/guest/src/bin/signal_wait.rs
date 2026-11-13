//! The signal-wait family, and what `sigaction` will answer about.
//!
//! `rt_sigsuspend`, `rt_sigtimedwait` and `rt_sigpending` are the three calls a
//! program uses to take a signal deliberately rather than be interrupted by
//! one, and none of them was named anywhere in the tests. A wrong answer is a
//! hang or a signal that never arrives, so nothing about them is checked
//! without a deadline here.
//!
//! `sigaction` is here for one rule that is easy to get backwards: `SIGKILL`
//! and `SIGSTOP` may not be *installed*, and may perfectly well be *asked
//! about*. Linux's `do_sigaction` says so in one line —
//!
//! ```c
//! if (!valid_signal(sig) || sig < 1 || (act && sig_kernel_only(sig)))
//!     return -EINVAL;
//! ```
//!
//! — where `act &&` is the whole difference.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

static GOT: AtomicI32 = AtomicI32::new(0);

extern "C" fn handler(sig: i32) {
    GOT.store(sig, Ordering::SeqCst);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn one(sig: i32) -> libc::sigset_t {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    unsafe { libc::sigaddset(&mut set, sig) };
    set
}

fn main() {
    let mut h = Harness::new();

    h.group("sigaction-may-be-asked-about-any-signal");
    // Installing one for SIGKILL is refused; reading the one that is there is
    // not. A kernel that refuses both looks stricter and breaks every program
    // that enumerates its dispositions -- which is what a shell does when it
    // restores them for a child.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::sigaction(libc::SIGKILL, std::ptr::null(), &mut old) };
    let e = errno();
    check!(h, r == 0, "sigaction(SIGKILL, NULL, &old) succeeds: r={r} errno={e}");
    check!(h, old.sa_sigaction == libc::SIG_DFL, "and reports the default: {:#x}",
        old.sa_sigaction);
    let r = unsafe { libc::sigaction(libc::SIGSTOP, std::ptr::null(), &mut old) };
    check!(h, r == 0, "and the same for SIGSTOP: r={r} errno={}", errno());

    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = handler as *const () as usize;
    unsafe { libc::sigemptyset(&mut act.sa_mask) };
    let r = unsafe { libc::sigaction(libc::SIGKILL, &act, std::ptr::null_mut()) };
    let e = errno();
    check!(h, r == -1 && e == libc::EINVAL,
        "installing one for SIGKILL is EINVAL: r={r} errno={e}");
    let r = unsafe { libc::sigaction(libc::SIGSTOP, &act, std::ptr::null_mut()) };
    let e = errno();
    check!(h, r == -1 && e == libc::EINVAL,
        "and for SIGSTOP: r={r} errno={e}");

    h.group("sigaction-signal-numbers");
    for bad in [0i32, 65, 100] {
        let r = unsafe { libc::syscall(libc::SYS_rt_sigaction, bad, std::ptr::null::<u8>(),
                                       &raw mut old, 8usize) };
        let e = errno();
        check!(h, r == -1 && e == libc::EINVAL, "signal {bad} is EINVAL: r={r} errno={e}");
    }
    // 64 is SIGRTMAX and is a real signal.
    let r = unsafe { libc::syscall(libc::SYS_rt_sigaction, 64, std::ptr::null::<u8>(),
                                   &raw mut old, 8usize) };
    check!(h, r == 0, "and 64 is not: r={r} errno={}", errno());

    h.group("sigprocmask-cannot-block-the-unblockable");
    // No error: the two are dropped from the set silently, and reading the mask
    // back is how a caller finds out.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    unsafe { libc::sigaddset(&mut set, libc::SIGKILL) };
    unsafe { libc::sigaddset(&mut set, libc::SIGSTOP) };
    unsafe { libc::sigaddset(&mut set, libc::SIGUSR1) };
    let r = unsafe { libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    check!(h, r == 0, "blocking a set containing SIGKILL is not an error: r={r}");
    let mut back: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut back) };
    check!(h, unsafe { libc::sigismember(&back, libc::SIGUSR1) } == 1, "SIGUSR1 is blocked");
    check!(h, unsafe { libc::sigismember(&back, libc::SIGKILL) } == 0, "SIGKILL is not");
    check!(h, unsafe { libc::sigismember(&back, libc::SIGSTOP) } == 0, "nor SIGSTOP");

    h.group("sigpending");
    // SIGUSR1 is blocked from the group above.
    let me = unsafe { libc::getpid() };
    check!(h, unsafe { libc::kill(me, libc::SIGUSR1) } == 0, "sending it to ourselves");
    let mut pend: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut pend) };
    check!(h, unsafe { libc::sigpending(&mut pend) } == 0, "sigpending");
    check!(h, unsafe { libc::sigismember(&pend, libc::SIGUSR1) } == 1, "reports it");
    check!(h, unsafe { libc::sigismember(&pend, libc::SIGUSR2) } == 0, "and not one that is not");

    h.group("sigtimedwait-takes-it");
    let want = one(libc::SIGUSR1);
    // Filled rather than zeroed, so a byte the kernel does not write is seen.
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe { std::ptr::write_bytes(&raw mut si, 0xa5, 1) };
    let ts = libc::timespec { tv_sec: 2, tv_nsec: 0 };
    let start = Instant::now();
    let r = unsafe { libc::sigtimedwait(&want, &mut si, &ts) };
    let ms = start.elapsed().as_millis();
    check!(h, r == libc::SIGUSR1, "sigtimedwait returns the signal: r={r} errno={}", errno());
    check!(h, si.si_signo == libc::SIGUSR1, "and fills in siginfo: si_signo={}", si.si_signo);
    // Bytes 12..16 sit between si_code and the union, which is 8-aligned.
    // Linux clears the whole siginfo; this emulator handed the guest four
    // bytes of host stack there until 2026-09-30.
    let raw: [u8; 128] = unsafe { std::mem::transmute(si) };
    check!(h, raw[12..16] == [0; 4], "and the bytes after si_code are zero: {:?}", &raw[12..16]);
    check!(h, ms < 500, "without waiting, since it was already pending: {ms}ms");
    // Taking it consumed it.
    unsafe { libc::sigemptyset(&mut pend) };
    unsafe { libc::sigpending(&mut pend) };
    check!(h, unsafe { libc::sigismember(&pend, libc::SIGUSR1) } == 0, "and it is no longer pending");

    h.group("sigtimedwait-times-out");
    let ts = libc::timespec { tv_sec: 0, tv_nsec: 150_000_000 };
    let start = Instant::now();
    let r = unsafe { libc::sigtimedwait(&want, &mut si, &ts) };
    let e = errno();
    let ms = start.elapsed().as_millis();
    check!(h, r == -1 && e == libc::EAGAIN, "with nothing pending it is EAGAIN: r={r} errno={e}");
    check!(h, ms >= 140, "after waiting: {ms}ms");
    check!(h, ms < 1500, "and not much longer: {ms}ms");

    h.group("sigtimedwait-rejects-a-bad-timeout");
    for (sec, nsec) in [(0i64, 1_000_000_000i64), (0, -1), (-1, 0)] {
        let ts = libc::timespec { tv_sec: sec as _, tv_nsec: nsec as libc::c_long };
        let r = unsafe { libc::sigtimedwait(&want, &mut si, &ts) };
        let e = errno();
        check!(h, r == -1 && e == libc::EINVAL,
            "a timeout of {{{sec}, {nsec}}} is EINVAL: r={r} errno={e}");
    }

    h.group("sigsuspend");
    // The mask is replaced for the duration and put back after. SIGUSR2 is
    // delivered by a thread while this one waits with it unblocked.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = handler as *const () as usize;
    unsafe { libc::sigemptyset(&mut act.sa_mask) };
    unsafe { libc::sigaction(libc::SIGUSR2, &act, std::ptr::null_mut()) };
    // Blocked here, so nothing arrives before the wait starts.
    let u2 = one(libc::SIGUSR2);
    unsafe { libc::sigprocmask(libc::SIG_BLOCK, &u2, std::ptr::null_mut()) };
    GOT.store(0, Ordering::SeqCst);
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(80));
        unsafe { libc::kill(me, libc::SIGUSR2) };
    });
    // Everything blocked except SIGUSR2.
    let mut suspend_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigfillset(&mut suspend_mask) };
    unsafe { libc::sigdelset(&mut suspend_mask, libc::SIGUSR2) };
    let start = Instant::now();
    let r = unsafe { libc::sigsuspend(&suspend_mask) };
    let e = errno();
    let ms = start.elapsed().as_millis();
    check!(h, r == -1 && e == libc::EINTR, "sigsuspend always returns EINTR: r={r} errno={e}");
    check!(h, GOT.load(Ordering::SeqCst) == libc::SIGUSR2, "the handler ran: {}",
        GOT.load(Ordering::SeqCst));
    check!(h, ms < 2000, "promptly: {ms}ms");
    // And the mask it was called with is gone: SIGUSR2 is blocked again.
    let mut back: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut back) };
    check!(h, unsafe { libc::sigismember(&back, libc::SIGUSR2) } == 1,
        "and the old mask is back");
    check!(h, unsafe { libc::sigismember(&back, libc::SIGUSR1) } == 1,
        "including what was blocked before it");
    t.join().ok();

    std::process::exit(h.finish());
}
