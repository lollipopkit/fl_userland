//! `pselect6` and `ppoll`: the signal mask, and the timeout.
//!
//! Both take a mask that is applied for the duration of the wait and restored
//! afterwards — that atomicity is the whole reason they exist, the race being
//! that a signal arriving between `sigprocmask` and `select` is lost. Both also
//! take a `timespec` rather than a millisecond count.
//!
//! Three things are easy to get wrong and quiet when you do:
//!
//! - **The mask argument may be null**, and usually is. `pselect(…, NULL)` is
//!   how you ask for the timeout without touching the mask.
//! - **`pselect6`'s sixth argument is a pointer to a `{ mask, size }` pair**,
//!   not to the mask, because a syscall takes six arguments and this one needs
//!   seven. A null *pair* and a pair holding a null *mask* are different
//!   things and both are legal.
//! - **A `timespec` that is not a time is `EINVAL`**, not a wait of some
//!   length nobody asked for.
//!
//! Established by running against a real arm64 kernel; `select(2)` describes
//! none of it.

use guest_tests::{Harness, check, check_fails, sys};
use std::time::Instant;

/// `pselect6`'s sixth argument.
#[repr(C)]
struct SigmaskArg {
    mask: u64,
    size: u64,
}

fn pselect(nfds: i32, timeout: *const libc::timespec, sig: *const SigmaskArg) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_pselect6,
            nfds,
            std::ptr::null_mut::<libc::fd_set>(),
            std::ptr::null_mut::<libc::fd_set>(),
            std::ptr::null_mut::<libc::fd_set>(),
            timeout,
            sig,
        )
    }
}

fn ppoll(fds: *mut libc::pollfd, n: u64, timeout: *const libc::timespec, mask: *const u64) -> i64 {
    unsafe {
        libc::syscall(libc::SYS_ppoll, fds, n, timeout, mask, 8usize)
    }
}

fn main() {
    let mut h = Harness::new();

    h.group("pselect-null-sigmask");
    // The common case: no mask at all. The sixth argument is a null pointer,
    // and this answered EFAULT for it -- it read the pair unconditionally,
    // from guest address zero.
    let ts = libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 };
    let r = pselect(0, &ts, std::ptr::null());
    check!(
        h,
        r == 0,
        "pselect with a null sigmask argument: {r} errno {}",
        sys::errno()
    );

    // And with no timeout at all, waiting on a descriptor that is already
    // readable so the call has something to return.
    //
    // Not on an empty set: `pselect(0, NULL, NULL, NULL, NULL)` waits for ever
    // and is right to, which is how the first version of this check hung
    // against a real kernel rather than telling me anything.
    let mut fds = [0i32; 2];
    check!(h, unsafe { libc::pipe(fds.as_mut_ptr()) } == 0, "a pipe to wait on");
    unsafe { libc::write(fds[1], c"x".as_ptr().cast(), 1) };
    let mut set: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe { libc::FD_SET(fds[0], &mut set) };
    let r = unsafe {
        libc::syscall(
            libc::SYS_pselect6,
            fds[0] + 1,
            &raw mut set,
            std::ptr::null_mut::<libc::fd_set>(),
            std::ptr::null_mut::<libc::fd_set>(),
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<SigmaskArg>(),
        )
    };
    check!(h, r == 1, "pselect with no timeout and no sigmask: {r} errno {}", sys::errno());
    check!(
        h,
        unsafe { libc::FD_ISSET(fds[0], &set) },
        "and reports the descriptor that was ready"
    );
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }

    // A pair that exists but whose mask is null is a third legal spelling, and
    // it is the one musl's own select() uses on this architecture.
    let arg = SigmaskArg { mask: 0, size: 8 };
    let r = pselect(0, &ts, &arg);
    check!(h, r == 0, "pselect with a pair holding a null mask: {r} errno {}", sys::errno());

    h.group("pselect-real-sigmask");
    // A mask that is actually applied. SIGUSR1 blocked for the duration, so
    // raising it during the wait does not cut it short.
    let mut block: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut block);
        libc::sigaddset(&mut block, libc::SIGUSR1);
    }
    let arg = SigmaskArg { mask: &raw const block as u64, size: 8 };
    let ts = libc::timespec { tv_sec: 0, tv_nsec: 50_000_000 };
    let start = Instant::now();
    let r = pselect(0, &ts, &arg);
    let waited = start.elapsed().as_millis();
    check!(h, r == 0, "pselect with a mask completes: {r} errno {}", sys::errno());
    check!(h, waited >= 30, "and waited for the timeout: {waited} ms");

    // The mask is restored afterwards: it applied to the wait, not to us.
    let mut now: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut now) };
    check!(
        h,
        unsafe { libc::sigismember(&now, libc::SIGUSR1) } == 0,
        "and the mask went back to what it was"
    );

    h.group("timeouts");
    // A timespec that is not a time. Linux checks; a wait of some length
    // nobody asked for is worse than an error.
    for (sec, nsec, what) in [
        (0i64, -1i64, "a negative nanosecond field"),
        (0, 1_000_000_000, "a nanosecond field of a whole second"),
        (-1, 0, "a negative second field"),
    ] {
        let bad = libc::timespec { tv_sec: sec as _, tv_nsec: nsec as _ };
        check_fails!(h, pselect(0, &bad, std::ptr::null()), libc::EINVAL,
            "pselect with {what}");
        check_fails!(h, ppoll(std::ptr::null_mut(), 0, &bad, std::ptr::null()), libc::EINVAL,
            "ppoll with {what}");
    }

    // A timeout below a millisecond is still a timeout, not zero. Measured on
    // an empty set so nothing can become ready and the wait must run out.
    let ts = libc::timespec { tv_sec: 0, tv_nsec: 20_000_000 };
    let start = Instant::now();
    let r = ppoll(std::ptr::null_mut(), 0, &ts, std::ptr::null());
    let waited = start.elapsed().as_millis();
    check!(h, r == 0, "ppoll with a 20 ms timeout: {r} errno {}", sys::errno());
    check!(h, waited >= 10, "waited for it: {waited} ms");
    check!(h, waited < 2000, "and did not overshoot: {waited} ms");

    // Zero is "return now", and must not be read as "wait for ever".
    let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let start = Instant::now();
    let r = ppoll(std::ptr::null_mut(), 0, &zero, std::ptr::null());
    let waited = start.elapsed().as_millis();
    check!(h, r == 0, "ppoll with a zero timeout returns: {r}");
    check!(h, waited < 500, "at once: {waited} ms");

    let start = Instant::now();
    let r = pselect(0, &zero, std::ptr::null());
    let waited = start.elapsed().as_millis();
    check!(h, r == 0, "pselect with a zero timeout returns: {r}");
    check!(h, waited < 500, "at once: {waited} ms");

    std::process::exit(h.finish());
}
