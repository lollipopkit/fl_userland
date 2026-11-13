//! A timeout at the far end of what a `timespec` can say.
//!
//! # Why this exists
//!
//! `timespec_valid` is Linux's rule and puts **no upper bound on `tv_sec`**:
//! Linux saturates, so `LLONG_MAX` is a request a real kernel accepts and turns
//! into "effectively for ever". A kernel that computes its deadline as
//! `sec * 1_000_000_000 + nsec` in an `i64` does not have that number.
//!
//! What the overflow costs depends on the build, and both answers are bad:
//!
//! - With overflow checks on it is a **panic inside an `extern "C"` function**,
//!   which cannot unwind — so the whole emulator aborts. One syscall, one
//!   argument, from any guest.
//! - Without them it wraps, and a wait meant to last for ever ends at whatever
//!   time the wrapped number happens to name.
//!
//! `poll_probe` found the first one of these in `ppoll` on 2026-09-03 and it was
//! fixed in `timeabi::timespec_to_poll_ms`. **The same line was written out by
//! hand in four other syscalls**, which is what this probe is for: the shape is
//! a family, not a site, and the only way to know how many members it has is to
//! ask each one. `rt_sigtimedwait` aborted the emulator; `futex`, `recvmmsg`
//! and `clock_nanosleep` were the others.
//!
//! # How it asks
//!
//! Each case waits with a huge timeout and no reason to wake, in a child with a
//! one-second alarm. `blocked (alarmed)` is the right answer and means the
//! deadline was far away; anything else means it overflowed into something
//! small. A case that returns *before* the alarm has answered the question.
//!
//! It is deliberately not a test of the timeout's accuracy. Whether a one-second
//! sleep takes a second is `time_semantics`'s; this asks only whether a deadline
//! at the end of time is one.

use std::io::Write;

unsafe fn sys(n: i64, a: i64, b: i64, c: i64, d: i64, e: i64, f: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b, in("x2") c, in("x3") d, in("x4") e, in("x5") f,
            options(nostack)
        );
    }
    ret
}

/// Run `f` in a child with a one-second alarm and say how it ended.
///
/// A child because several of these succeed at blocking, and because the defect
/// they are looking for *aborts the process* — which in a single-process probe
/// would take every later case with it, and would read as a hang rather than as
/// a finding.
fn timed(name: &str, f: impl FnOnce()) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::alarm(1);
            f();
            libc::_exit(0);
        }
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let how = if libc::WIFSIGNALED(status) {
        if libc::WTERMSIG(status) == libc::SIGALRM {
            "blocked (alarmed)".to_string()
        } else {
            format!("signal {}", libc::WTERMSIG(status))
        }
    } else {
        format!("returned {}", libc::WEXITSTATUS(status))
    };
    println!("{name:<46} {how}");
    let _ = std::io::stdout().flush();
}

/// The largest `tv_sec` there is. Not a plausible timeout — the point is that
/// it is a *valid* one, and that nothing in `timespec_valid` says otherwise.
const HUGE: [i64; 2] = [i64::MAX, 0];

/// One second short of it, so a kernel that saturates and a kernel that has the
/// number both answer the same thing. A difference here would be a bound
/// somebody added rather than an overflow.
const NEARLY: [i64; 2] = [i64::MAX - 1, 999_999_999];

fn exit_with(r: i64) -> ! {
    unsafe { libc::_exit(if r < 0 { (-r).min(120) as i32 } else { 100 }) }
}

fn main() {
    println!("## a timeout at the far end of a timespec");

    for (label, ts) in [("LLONG_MAX", &HUGE), ("LLONG_MAX-1", &NEARLY)] {
        // rt_sigtimedwait with nothing pending.
        timed(&format!("  rt_sigtimedwait({label})"), || unsafe {
            let mut set = [0u64; 1];
            set[0] = 1 << 9; // SIGUSR1 - 1
            exit_with(sys(137, set.as_mut_ptr() as i64, 0, ts.as_ptr() as i64, 8, 0, 0));
        });

        // futex FUTEX_WAIT on a word that matches, so it parks.
        timed(&format!("  futex(FUTEX_WAIT, {label})"), || unsafe {
            let word: u32 = 0;
            exit_with(sys(98, &word as *const u32 as i64, 0, 0, ts.as_ptr() as i64, 0, 0));
        });

        // recvmmsg on a socket with nothing on it.
        timed(&format!("  recvmmsg({label})"), || unsafe {
            let mut sv = [0i32; 2];
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());
            let mut buf = [0u8; 64];
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            // `struct mmsghdr` is a `msghdr` and a `u32` length.
            let mut mmsg = [0u8; 64];
            let hdr = mmsg.as_mut_ptr().cast::<libc::msghdr>();
            (*hdr).msg_iov = &mut iov;
            (*hdr).msg_iovlen = 1;
            exit_with(sys(243, sv[0] as i64, mmsg.as_mut_ptr() as i64, 1, 0, ts.as_ptr() as i64, 0));
        });

        // clock_nanosleep, relative, which adds the request to `now`.
        timed(&format!("  clock_nanosleep(relative, {label})"), || unsafe {
            exit_with(sys(115, 1 /* CLOCK_MONOTONIC */, 0, ts.as_ptr() as i64, 0, 0, 0));
        });

        // And absolute, which does not add anything -- the control for the one
        // above: it takes the same number down a path with no arithmetic in it.
        timed(&format!("  clock_nanosleep(absolute, {label})"), || unsafe {
            exit_with(sys(115, 1, 1 /* TIMER_ABSTIME */, ts.as_ptr() as i64, 0, 0, 0));
        });

        // ppoll, the one this family was found through.
        timed(&format!("  ppoll({label})"), || unsafe {
            let pfd = [0i32; 2]; // fd 0, no events
            exit_with(sys(73, pfd.as_ptr() as i64, 1, ts.as_ptr() as i64, 0, 0, 0));
        });

        // pselect6, which reads its timeout through a different path.
        timed(&format!("  pselect6({label})"), || unsafe {
            exit_with(sys(72, 0, 0, 0, 0, ts.as_ptr() as i64, 0));
        });

        // `SO_RCVTIMEO` is the same number arriving by a different route: the
        // guest sets it once and every later `recv` on that socket converts it.
        // Whether it can *be* huge is the host's decision -- the value comes
        // back out of `getsockopt` -- so this asks both halves at once, and a
        // difference could be either the setsockopt or the conversion.
        timed(&format!("  recv after SO_RCVTIMEO({label})"), || unsafe {
            let mut sv = [0i32; 2];
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());
            let tv = libc::timeval {
                tv_sec: ts[0],
                tv_usec: 0,
            };
            let set = libc::setsockopt(
                sv[0],
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            );
            if set < 0 {
                // Refused, which is an answer: print it rather than blocking on
                // a socket whose timeout is whatever it was before.
                libc::_exit(101);
            }
            let mut buf = [0u8; 1];
            exit_with(libc::recv(sv[0], buf.as_mut_ptr().cast(), 1, 0) as i64);
        });
    }
}
