//! Waiting for a socket to become ready, and who the caller is.
//!
//! This is *task* policy rather than socket policy, which is why it was the last
//! thing left in `fs/sock.c`: it asks whether a guest signal is pending, and it
//! sets `blocking` so the futex-stall diagnostic can say what this thread is
//! doing.
//!
//! # The poll is bounded even when the wait is not
//!
//! Each pass waits at most a second. A guest signal has to be able to interrupt
//! the wait, and on iOS the host thread can be suspended briefly — so the loop
//! comes back and asks rather than sleeping in the host indefinitely.
//!
//! # `SO_RCVTIMEO` is rounded up
//!
//! Zero is this function's "no timeout set", so truncating a sub-millisecond
//! timeout to zero turned it into an **indefinite wait** — the opposite of what
//! was asked for. It rounds up.

//! # `as i64` on a host `libc` field is not redundant
//!
//! `clippy::unnecessary_cast` reports the `time_t` and `suseconds_t` casts
//! here because those are already `i64` on this target. They are `i32` on a
//! 32-bit host, which this tree compiles on — `differential.sh` runs the
//! guest tests in a Linux container and the host tools build wherever they
//! are. The lint sees one target.
#![allow(clippy::unnecessary_cast)]

use std::ffi::c_int;
use std::os::fd::{AsRawFd, BorrowedFd};

use kernel_syscallrestart::Restart;
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno as HostErrno;
use rustix::net::sockopt::Timeout;


use guest_errno::c_int_::{EAGAIN, EINTR};

/// `EINTR`, and whether the syscall it interrupts may be restarted: Linux's
/// `sock_intr_errno`, which is `ERESTARTSYS` for a wait with no timeout and
/// `EINTR` for one with, because a timed wait restarted from the top would
/// never time out.
///
/// The dispatcher classes every socket call as never restarting -- it sees
/// the arguments and the timeout is the socket's -- so this is where the
/// socket corrects it. Until 2026-09-04 nothing did, and a `recv` under an
/// `SA_RESTART` handler answered `EINTR` where Linux went on waiting;
/// `sock_probe` measured a `recv` with no `SO_RCVTIMEO` interrupted by an
/// alarm and then written to.
fn interrupted(no_timeout: bool) -> c_int {
    if no_timeout {
        taskview::with_current_restart(|restart| restart.reclassify(Restart::IfHandlerAsks));
    }
    EINTR
}

/// `accept` was interrupted by a guest signal. It waits in the host's
/// `accept` rather than in [`wait_for`], and its timeout is `SO_RCVTIMEO`'s,
/// as Linux's `inet_csk_accept` uses `sock_rcvtimeo`.
pub(crate) fn interrupted_accept(real_fd: BorrowedFd<'_>) -> c_int {
    interrupted(timeout_ms(real_fd, Timeout::Recv) == 0)
}

// Whether a guest signal ends a wait for this task is asked through
// `taskview::with_current_queue`. It was a hand-written `extern "C"` block
// until 2026-09-06 -- `fs/sock` already depended on `kernel/sighand`
// transitively and `kernel/sighand` does not reach back, so the C ABI bought
// nothing -- and a raw `Queue::from_raw` until 2026-09-30.

/// The `sock` channel: the NETDIAG lines a blocking wait prints.
///
/// A `cfg` since 2026-09-06, where it was a pair of calls into `kernel/log.c`
/// — the crate could not see `#if DEBUG_sock` and asked C for it at runtime.
fn trace(text: &str) {
    logchan::line(logchan::Channel::Sock, text);
}


fn monotonic_ms() -> i64 {
    (util_timeabi::monotonic_ns() / 1_000_000) as i64
}

/// A socket timeout option as milliseconds, **rounded up**. 0 for unset or for
/// an error; see the module comment on why the rounding direction matters.
fn timeout_ms(real_fd: BorrowedFd<'_>, which: Timeout) -> i64 {
    let Ok(Some(timeout)) = rustix::net::sockopt::socket_timeout(real_fd, which) else {
        return 0;
    };
    // Saturating. The value comes back out of the *host*, but the guest is what
    // put it there -- `setsockopt(SO_RCVTIMEO, {LLONG_MAX, 0})` is accepted --
    // so a plain conversion overflowed, and the panic is inside an
    // `extern "C"` function, which aborts. It is the worst-placed member of
    // that family: the guest sets the option once and then **any later `recv`
    // on that socket** takes the emulator down, rather than the call that
    // named the number.
    i64::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(i64::MAX)
}

/// Wait for a descriptor to become ready. 0 when it is, `EINTR` on a guest
/// signal, `EAGAIN` when the socket's own timeout expires, or a guest errno.
///
/// `poll` **through** `rustix`, which is what took the last `unsafe` out of
/// this file: the host's `errno` had to be saved across the trace and written
/// back with `*__error() = saved` before `errno_map` read it.
fn wait_for(real: BorrowedFd<'_>, events: PollFlags, timeout_opt: Timeout) -> c_int {
    let real_fd = real.as_raw_fd();
    let limit = timeout_ms(real, timeout_opt);
    let start = monotonic_ms();
    // Saturating for the same reason `timeout_ms` above is: `limit` can now be
    // `i64::MAX` milliseconds, and a deadline past the end of time is one that
    // never arrives, which is what the caller asked for.
    let deadline = if limit > 0 {
        start.saturating_add(limit)
    } else {
        0
    };
    let mut slow_logged = false;
    loop {
        // `current_sighand()` rather than `(*task).sighand`: this loop runs on
        // the task's own thread holding no lock, and the group-exit valve
        // stores to that field from another thread. A thread parked here --
        // blocked in a host `poll` on a socket -- is exactly the population the
        // valve gives up on, so the plain load this used to be was the same
        // data race `taskview::signal_pending` had. The accessor is where the
        // atomic is written.
        if taskview::with_current_queue(|queue| queue.interrupts_a_wait()).unwrap_or(false) {
            return interrupted(limit == 0);
        }

        let mut poll_ms: c_int = 1000;
        if deadline > 0 {
            let remaining = deadline - monotonic_ms();
            if remaining <= 0 {
                trace(&format!(
                    "NETDIAG sock_wait(pid={} comm={} fd={real_fd} ev={events:#x}) \
                     deadline-expired after {limit}ms",
                    taskview::current_pid(),
                    taskview::current_comm()
                ));
                return EAGAIN;
            }
            if remaining < poll_ms as i64 {
                poll_ms = remaining as c_int;
            }
        }

        taskview::set_blocking(true);
        let tick = Timespec {
            tv_sec: (poll_ms / 1000) as _,
            tv_nsec: ((poll_ms % 1000) * 1_000_000) as _,
        };
        let pr = rustix::event::poll(&mut [PollFd::from_borrowed_fd(real, events)], Some(&tick));
        taskview::set_blocking(false);

        let saved = match pr {
            Ok(n) if n > 0 => return 0,
            Ok(_) => None,
            Err(e) => Some(e),
        };
        let Some(saved) = saved else {
            // Once, if this has gone three seconds with no ready event.
            if !slow_logged && monotonic_ms() - start >= 3000 {
                trace(&format!(
                    "NETDIAG sock_wait(pid={} comm={} fd={real_fd} ev={events:#x}) \
                     no-event for 3s (timeout_opt_ms={limit})",
                    taskview::current_pid(),
                    taskview::current_comm()
                ));
                slow_logged = true;
            }
            continue;
        };
        if saved == HostErrno::INTR {
            continue;
        }
        trace(&format!(
            "NETDIAG sock_wait(pid={} comm={} fd={real_fd} ev={events:?}) poll err={}",
            taskview::current_pid(),
            taskview::current_comm(),
            saved.raw_os_error()
        ));
        // The errno is a value now, so the trace's allocations cannot move it
        // -- which is what the host's thread-local `errno` had to be restored
        // around.
        return kernel_errno::raised(saved.raw_os_error());
    }
}

/// Wait for a socket to become readable, honouring `SO_RCVTIMEO`.
pub fn sock_wait_readable_for_rs(real: BorrowedFd<'_>) -> c_int {
    wait_for(real, PollFlags::IN, Timeout::Recv)
}

/// The calling task's identity, for `SO_PEERCRED` and the credentials a unix
/// socket carries.
///
/// Three `*mut` out-parameters until 2026-09-16, whose one caller wrote the
/// three locals and then assembled exactly this struct from them --
/// `unixpeer::Ucred` is the shape the answer already had.
pub(crate) fn caller_cred() -> unixpeer::Ucred {
    taskview::with_current_creds(|creds| unixpeer::Ucred {
        pid: taskview::current_pid(),
        uid: creds.euid(),
        gid: creds.egid(),
    })
    .expect("a socket call runs on a guest thread")
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_sub_millisecond_timeout_rounds_up_rather_than_to_never() {
        // 0 is "no timeout set" here, so truncation turns a 500 us SO_RCVTIMEO
        // into an indefinite wait -- the opposite of what was asked for. The
        // arithmetic is asserted directly because getsockopt needs a socket.
        let round = |sec: i64, usec: i64| sec * 1000 + (usec + 999) / 1000;
        assert_eq!(round(0, 1), 1);
        assert_eq!(round(0, 500), 1);
        assert_eq!(round(0, 999), 1);
        assert_eq!(round(0, 1000), 1);
        assert_eq!(round(0, 1001), 2);
        assert_eq!(round(2, 0), 2000);
        assert_eq!(round(0, 0), 0, "unset stays unset");
    }
}
