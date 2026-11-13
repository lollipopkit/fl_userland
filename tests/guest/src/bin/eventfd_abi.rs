//! `eventfd`: a counter you can wait on, and the two modes it has.
//!
//! Used as a wakeup channel by every event loop that has to be poked from
//! another thread — libuv's `uv_async_send`, Go's netpoller, and glib's — so a
//! counter that coalesces when it should not, or blocks when it should not, is
//! a loop that misses work or a thread that never wakes.
//!
//! What is easy to get wrong:
//!
//! - **The two modes.** A plain read takes the whole counter and leaves zero; a
//!   `EFD_SEMAPHORE` read takes exactly one. That is the difference between an
//!   event flag and a counting semaphore, and a program picks one deliberately.
//! - **The ceiling.** The counter's maximum is `u64::MAX - 1`. A write that
//!   would reach `u64::MAX` blocks — it does not saturate, because saturating
//!   would report a count nobody wrote — and `u64::MAX` itself is `EINVAL`.
//! - **Short buffers.** A read or write of fewer than eight bytes is `EINVAL`,
//!   whatever else is true.
//!
//! Established against a real arm64 kernel. The close path's leak check
//! lives in `eventfd_leak.rs`, because `/proc/iul/objects` is this emulator's
//! and a test that reads it is not comparable to anything.

use guest_tests::{Harness, check, check_fails, sys};

const EFD_SEMAPHORE: i32 = 1;
const EFD_NONBLOCK: i32 = 0o4000;
const EFD_CLOEXEC: i32 = 0o2000000;

fn eventfd(initval: u32, flags: i32) -> i32 {
    unsafe { libc::syscall(libc::SYS_eventfd2, initval, flags) as i32 }
}

fn read_u64(fd: i32) -> Result<u64, i32> {
    let mut v = 0u64;
    let n = unsafe { libc::read(fd, (&raw mut v).cast(), 8) };
    if n == 8 { Ok(v) } else { Err(sys::errno()) }
}

fn write_u64(fd: i32, v: u64) -> Result<(), i32> {
    let n = unsafe { libc::write(fd, (&raw const v).cast(), 8) };
    if n == 8 { Ok(()) } else { Err(sys::errno()) }
}

fn main() {
    let mut h = Harness::new();

    h.group("flags");
    let fd = eventfd(0, 0);
    check!(h, fd >= 0, "eventfd with no flags: {fd} errno {}", sys::errno());
    check_fails!(h, eventfd(0, 0x40) as i64, libc::EINVAL, "an undefined flag");
    for (flags, what) in [
        (EFD_CLOEXEC, "EFD_CLOEXEC"),
        (EFD_NONBLOCK, "EFD_NONBLOCK"),
        (EFD_SEMAPHORE, "EFD_SEMAPHORE"),
        (EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC, "all three together"),
    ] {
        let f = eventfd(0, flags);
        check!(h, f >= 0, "{what} is accepted: {f} errno {}", sys::errno());
        if f >= 0 {
            unsafe { libc::close(f) };
        }
    }

    h.group("counter");
    // A plain read takes everything and leaves nothing.
    check!(h, write_u64(fd, 5).is_ok(), "write 5");
    check!(h, write_u64(fd, 6).is_ok(), "write 6");
    let got = read_u64(fd);
    check!(h, got == Ok(11), "a read takes the whole counter: {got:?}");

    // Now empty and non-blocking, so a read reports EAGAIN rather than waiting
    // for a writer that is not coming.
    let nb = eventfd(0, EFD_NONBLOCK);
    check!(h, nb >= 0, "a non-blocking eventfd");
    let got = read_u64(nb);
    check!(h, got == Err(libc::EAGAIN), "an empty one is EAGAIN, not zero: {got:?}");
    // A read of zero would be indistinguishable from end-of-file, which is
    // what makes returning it instead of EAGAIN a bug that stops a loop.

    h.group("semaphore");
    let sem = eventfd(3, EFD_SEMAPHORE | EFD_NONBLOCK);
    check!(h, sem >= 0, "a semaphore eventfd starting at 3");
    for expect in 1..=3 {
        let got = read_u64(sem);
        check!(h, got == Ok(1), "read {expect} of 3 takes exactly one: {got:?}");
    }
    let got = read_u64(sem);
    check!(h, got == Err(libc::EAGAIN), "and the fourth finds it empty: {got:?}");

    h.group("ceiling");
    let big = eventfd(0, EFD_NONBLOCK);
    check!(h, big >= 0, "an eventfd for the ceiling checks");
    // u64::MAX is never a value the counter may take.
    check!(
        h,
        write_u64(big, u64::MAX) == Err(libc::EINVAL),
        "writing u64::MAX is EINVAL"
    );
    // The maximum the counter reaches is u64::MAX - 1.
    check!(
        h,
        write_u64(big, u64::MAX - 1).is_ok(),
        "writing u64::MAX - 1 fits: errno {}",
        sys::errno()
    );
    // One more would reach the reserved value, so it waits -- and being
    // non-blocking, reports EAGAIN. Saturating instead would report a count
    // nobody wrote.
    check!(
        h,
        write_u64(big, 1) == Err(libc::EAGAIN),
        "and one more would overflow: EAGAIN"
    );
    // Adding nothing always fits, even at the ceiling.
    check!(h, write_u64(big, 0).is_ok(), "adding zero at the ceiling still works");
    let got = read_u64(big);
    check!(h, got == Ok(u64::MAX - 1), "and the counter held what was put in: {got:?}");

    // The addition must not wrap on the way to deciding: val + increment in
    // 64-bit arithmetic overflows and comes out small, which reads as room.
    let wrap = eventfd(0, EFD_NONBLOCK);
    check!(h, write_u64(wrap, u64::MAX - 10).is_ok(), "start near the ceiling");
    check!(
        h,
        write_u64(wrap, 100) == Err(libc::EAGAIN),
        "an addition that would wrap is refused, not accepted"
    );
    let got = read_u64(wrap);
    check!(h, got == Ok(u64::MAX - 10), "and the counter is unchanged: {got:?}");

    h.group("short-buffers");
    // Fewer than eight bytes is EINVAL either way.
    let small = eventfd(1, EFD_NONBLOCK);
    let mut four = [0u8; 4];
    let n = unsafe { libc::read(small, four.as_mut_ptr().cast(), 4) };
    check!(h, n == -1 && sys::errno() == libc::EINVAL,
        "a four-byte read is EINVAL: {n} errno {}", sys::errno());
    let n = unsafe { libc::write(small, four.as_ptr().cast(), 4) };
    check!(h, n == -1 && sys::errno() == libc::EINVAL,
        "a four-byte write is EINVAL: {n} errno {}", sys::errno());
    // And the counter was not disturbed by either.
    let got = read_u64(small);
    check!(h, got == Ok(1), "the counter survived both: {got:?}");

    h.group("poll");
    // An empty eventfd is writable and not readable; one with a count is both.
    let p = eventfd(0, EFD_NONBLOCK);
    let mut pfd = libc::pollfd { fd: p, events: (libc::POLLIN | libc::POLLOUT) as i16, revents: 0 };
    let r = unsafe { libc::poll(&raw mut pfd, 1, 0) };
    check!(h, r == 1, "poll on an empty eventfd returns: {r}");
    check!(h, pfd.revents & libc::POLLOUT as i16 != 0, "it is writable");
    check!(h, pfd.revents & libc::POLLIN as i16 == 0, "and not readable");

    write_u64(p, 1).ok();
    pfd.revents = 0;
    let r = unsafe { libc::poll(&raw mut pfd, 1, 0) };
    check!(h, r == 1, "poll after a write returns: {r}");
    check!(h, pfd.revents & libc::POLLIN as i16 != 0, "now it is readable");

    unsafe {
        for f in [fd, nb, sem, big, wrap, small, p] {
            libc::close(f);
        }
    }

    std::process::exit(h.finish());
}
