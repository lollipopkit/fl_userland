//! Epoll wait loop, reusable output storage, and guest event encoding.

use super::*;
use std::time::Duration;

/// The most events one thread keeps its output array sized for between calls.
///
/// `EPOLL_MAX_EVENTS` entries is 16 KiB, which is small enough to hold for the
/// life of a thread that has asked for it once.
const READY_RETAIN: usize = EPOLL_MAX_EVENTS as usize;

thread_local! {
    /// One output array per thread, grown to the largest `max_events` it has
    /// seen and reused. Taken rather than borrowed, so a nested wait would get
    /// its own instead of aliasing.
    static READY: std::cell::Cell<Vec<kernel_epoll::Event>> =
        const { std::cell::Cell::new(Vec::new()) };
}

/// The array `epoll_copy_ready` fills, **not zeroed on every call**.
///
/// This was `Vec::new()` + `try_reserve(n)` + `resize(n, zeroed)`, which memsets
/// the caller's whole `max_events` once per `epoll_wait` — and `max_events` is
/// what a caller is *willing* to handle, not what it gets. libuv and Go both
/// pass 1024 and almost always get one event back, so every wakeup of every
/// event loop paid a 16 KiB memset to deliver sixteen bytes. Measured with
/// `epoll_bench`'s `max_events` column: flat at 0.94 us in the C this replaced,
/// and 0.94 -> 1.30 us across 8 to 1024 in the first Rust version.
///
/// Reused per thread, `resize` only ever zeroes the newly grown tail, so a
/// steady 1024 costs no memset at all — and no malloc/free pair per call
/// either, which the C avoided with a stack VLA.
struct Ready {
    buf: Vec<kernel_epoll::Event>,
    want: usize,
}

impl Ready {
    fn new(want: usize) -> Result<Ready, Errno> {
        let mut buf = READY.with(|r| r.take());
        if buf.len() < want {
            if buf.try_reserve(want - buf.len()).is_err() {
                READY.with(|r| r.set(buf));
                return Err(Errno::ENOMEM);
            }
            buf.resize(
                want,
                kernel_epoll::Event {
                    events: 0,
                    _pad: 0,
                    data: 0,
                },
            );
        }
        Ok(Ready { buf, want })
    }

    /// The `want` events a wait may fill.
    fn slots(&mut self) -> &mut [kernel_epoll::Event] {
        &mut self.buf[..self.want]
    }
}

impl Drop for Ready {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.buf);
        if buf.capacity() <= READY_RETAIN {
            READY.with(|r| r.set(buf));
        }
    }
}

impl std::ops::Deref for Ready {
    type Target = [kernel_epoll::Event];
    fn deref(&self) -> &[kernel_epoll::Event] {
        &self.buf[..self.want]
    }
}

/* `now_ns` was defined here until 2026-09-15 — one of five private copies,
 * all asking `CLOCK_MONOTONIC` and answering `u64` nanoseconds. It is
 * `util_timeabi::monotonic_ns` now, which saturates where three of the five
 * multiplied plainly. */
use util_timeabi::monotonic_ns as now_ns;

/// The wait both `epoll_pwait` and `epoll_pwait2` are. `None` waits for ever.
///
/// A `Duration` since 2026-11-11, when `epoll_pwait2` arrived with a
/// nanosecond timeout. `epoll_pwait`'s milliseconds convert exactly; going the
/// other way would round a 300 us wait up to a millisecond.
pub(super) fn epoll_wait(
    epoll_f: c_int,
    events_addr: u64,
    max_events: c_int,
    timeout: Option<Duration>,
) -> Result<i64, Errno> {
    strace!("epoll_wait({epoll_f}, {events_addr:#x}, {max_events}, {timeout:?})");
    let Some(epoll) = fs_fdobj::f_get(epoll_f) else {
        return Err(Errno::EBADF);
    };
    let epoll = &*epoll;
    let Some(state) = state_of(epoll) else {
        return Err(Errno::EINVAL);
    };

    // The bound is checked **before** the clamp. It was the other way round, so
    // a `max_events` above the cap was quietly clamped to 1024 and accepted
    // where Linux answers `EINVAL` -- and a caller passing a computed size that
    // has overflowed was told its call was fine.
    //
    // The cap is `INT_MAX / sizeof(struct epoll_event)`, which is
    // architecture-dependent because that struct is packed to 12 bytes on
    // x86-64 and is 16 everywhere else. Computed from the size this kernel
    // uses rather than written down; measured at 134217727 against a real
    // arm64 kernel by `tests/guest/src/bin/epoll_probe.rs`.
    if max_events <= 0 || max_events as usize > c_int::MAX as usize / EPOLL_EVENT_SIZE {
        return Err(Errno::EINVAL);
    }
    // Linux checks the *whole span* the caller says it can take, up front and
    // whether or not anything is ready -- `access_ok(events, maxevents *
    // sizeof(struct epoll_event))`. That is arithmetic, not a page walk: the
    // question is only whether the range wraps or leaves the address space.
    //
    // It was not checked at all, so a caller whose `max_events` had been
    // computed from a buffer size and overflowed was told the call was fine and
    // handed zero events. Only a wait that *delivers* something would have
    // faulted, which is the wrong time to find out.
    if !usercopy::range_ok(
        events_addr,
        max_events as usize * EPOLL_EVENT_SIZE,
        ffi::USER_ADDR_MAX_PAGE,
    ) {
        return Err(Errno::EFAULT);
    }
    let max_events = max_events.min(EPOLL_MAX_EVENTS);
    let mut events = Ready::new(max_events as usize)?;

    let deadline_ns = timeout.map(|t| {
        now_ns().saturating_add(u64::try_from(t.as_nanos()).unwrap_or(u64::MAX))
    });

    // Asked once without waiting first, so a set that is already ready costs
    // no host round trip and no blocking flag.
    let res = fs_poll::epoll_copy_ready(state, events.slots(), Duration::ZERO);
    if res < 0 {
        return Err(Errno::from_negative_or_eio(res));
    }
    if res > 0 {
        return report(events_addr, &events, res);
    }

    loop {
        // The deadline **before** the signal, which is Linux's `ep_poll` order:
        // a wait that has timed out answers 0 with a signal pending, so a zero
        // timeout never answers EINTR -- and the temporary mask is then put
        // back with the signal still pending rather than delivered. This
        // answered EINTR, and ran the handler under the temporary mask, until
        // 2026-11-11 (`epoll2_probe`, "then a zero wait with it unblocked").
        //
        // Bounded at a second even when the caller asked for longer, so a guest
        // signal is noticed by the check below rather than at the deadline.
        let mut wait = Duration::from_secs(1);
        if let Some(deadline) = deadline_ns {
            let now = now_ns();
            if now >= deadline {
                return Ok(0);
            }
            wait = wait.min(Duration::from_nanos(deadline - now));
        }
        if taskview::current_signal_pending() {
            return Err(Errno::EINTR);
        }

        let bracketed = kernel_epoll::epoll_has_socket(state);
        if bracketed {
            sockrestart::sockrestart_begin_listen_wait_bare();
        }
        taskview::set_blocking(true);
        let mut res;
        loop {
            res = fs_poll::epoll_copy_ready(state, events.slots(), wait);
            if res != Errno::EINTR.as_c_int()
                || !sockrestart::sockrestart_should_restart_listen_wait()
            {
                break;
            }
        }
        taskview::set_blocking(false);
        if bracketed {
            sockrestart::sockrestart_end_listen_wait_bare();
        }

        if res < 0 {
            if res == Errno::EINTR.as_c_int() {
                continue;
            }
            // Anything else from the host wait is reported as an interruption
            // rather than passed through: the errno would be the host's, and
            // a guest that sees EINTR retries, which is the right thing for a
            // wait that did not complete.
            printk(&format!("epoll_wait: converting error {res} to EINTR"));
            return Err(Errno::EINTR);
        }
        if res > 0 {
            return report(events_addr, &events, res);
        }
    }
}

fn report(events_addr: u64, events: &[kernel_epoll::Event], count: c_int) -> Result<i64, Errno> {
    let n = count as usize;
    let mut raw = vec![0u8; n * EPOLL_EVENT_SIZE];
    for (i, e) in events[..n].iter().enumerate() {
        let at = i * EPOLL_EVENT_SIZE;
        raw[at..at + 4].copy_from_slice(&e.events.to_le_bytes());
        raw[at + 8..at + 16].copy_from_slice(&e.data.to_le_bytes());
    }
    if GuestMem.write(events_addr, &raw) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(count as i64)
}
