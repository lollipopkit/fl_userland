//! `syslog(2)` must not write past what it read.
//!
//! The kernel log is a megabyte-long fifo. `syslog_read` clamped the caller's
//! length to the fifo's **capacity** rather than its **contents**, and
//! `fifo_read` reads nothing at all and reports failure when asked for more
//! than it holds — a return the caller ignored. So the `malloc` buffer went to
//! the guest with whatever was in it, and the call reported that many bytes
//! read.
//!
//! `syslog(SYSLOG_ACTION_READ, buf, 1 << 20)` on a guest that had produced no
//! log output was a megabyte of the emulator's heap. Every guest can make that
//! call: processes here run as root, where Linux requires `CAP_SYSLOG`.
//!
//! The probe fills the destination with a pattern and checks that every byte
//! past the returned count still holds it. That is the assertion the defect
//! fails, and it does not depend on the heap containing anything recognisable.

use guest_tests::{Harness, check, check_fails, sys};

const READ: i32 = 2;
const READ_ALL: i32 = 3;
const READ_CLEAR: i32 = 4;
const CONSOLE_OFF: i32 = 6;
const CONSOLE_LEVEL: i32 = 8;
const SIZE_UNREAD: i32 = 9;
const SIZE_BUFFER: i32 = 10;

const PATTERN: u8 = 0xA5;

fn syslog(action: i32, buf: &mut [u8], len: i32) -> isize {
    sys::clear_errno();
    unsafe { libc::syscall(libc::SYS_syslog, action, buf.as_mut_ptr(), len) as isize }
}

/// The same, with the buffer given as a bare address — so a null one can be
/// asked for, which is a case of its own.
fn syslog_at(action: i32, addr: usize, len: i32) -> isize {
    sys::clear_errno();
    unsafe { libc::syscall(libc::SYS_syslog, action, addr, len) as isize }
}

/// Puts a line in the kernel log, and answers whether it managed to.
///
/// There is no way for a guest to print into this kernel's log on purpose, so
/// what is used is a side effect: an unimplemented syscall makes the emulator
/// report itself, **once per syscall number** for the life of the process. So
/// one number is not enough — a test that ran earlier in the same emulator may
/// have spent it — and the list is walked until the log grows.
fn put_a_line_in_the_log(scratch: &mut [u8]) -> bool {
    let before = syslog(SIZE_UNREAD, scratch, 0);
    // Numbers that are still reported stubs: 104-106 became `not_configured`
    // on 2026-11-11, which is silent, and the list ran dry.
    for nr in [41i64, 58, 471, 162, 171, 180, 181, 182, 183, 184] {
        unsafe { libc::syscall(nr, 0, 0, 0) };
        if syslog(SIZE_UNREAD, scratch, 0) > before {
            return true;
        }
    }
    false
}

/// Reads `action` into a buffer painted with [`PATTERN`] and reports the return
/// value together with how many bytes were actually disturbed.
fn read_into(action: i32, ask: i32, buf: &mut [u8]) -> (isize, usize) {
    buf.fill(PATTERN);
    let r = syslog(action, buf, ask);
    let touched = buf.iter().rposition(|b| *b != PATTERN).map_or(0, |i| i + 1);
    (r, touched)
}

fn main() {
    let mut h = Harness::new();
    h.group("syslog-read");

    let mut buf = vec![0u8; 1 << 16];

    let capacity = syslog(SIZE_BUFFER, &mut buf, 0);
    let unread = syslog(SIZE_UNREAD, &mut buf, 0);
    check!(h, capacity > 0, "the log has a capacity: {capacity}");
    check!(
        h,
        unread >= 0 && unread <= capacity,
        "and holds no more than that: {unread} of {capacity}"
    );

    // ---- what READ_CLEAR answers ---------------------------------------
    //
    // It read into the caller's buffer and then fell through to the clear arm,
    // whose `return 0` it inherited, so `dmesg -c` was told nothing had been
    // read while the log was consumed underneath it.
    //
    // This needs the log to be non-empty, which is asserted rather than
    // assumed: with an empty log the defect and the fix both answer 0, and the
    // check would pass against either.
    let got_one = put_a_line_in_the_log(&mut buf);
    check!(h, got_one, "the log can be made non-empty, so the next checks mean something");
    if got_one {
        let ask = buf.len() as i32;
        let peeked = syslog(READ_ALL, &mut buf, ask);
        let (cleared, touched) = read_into(READ_CLEAR, ask, &mut buf);
        check!(
            h,
            cleared > 0,
            "READ_CLEAR answers how many bytes it read: {cleared}"
        );
        check!(
            h,
            cleared == peeked,
            "and the same count READ_ALL just reported: {cleared} against {peeked}"
        );
        check!(
            h,
            touched == cleared.max(0) as usize,
            "having written exactly that many: {touched} for {cleared}"
        );
        let again = syslog(READ_ALL, &mut buf, ask);
        check!(h, again == 0, "and it cleared: a second READ_ALL is {again}");
    }

    // ---- the arguments -------------------------------------------------
    //
    // Five of the eleven commands do nothing at all here, so their argument
    // handling is the whole of what a caller can observe about them.

    // A null destination is refused before the address is looked at. It used to
    // reach the copy, where the answer depended on how much the emulator had
    // printed: EFAULT once there was something to copy, 0 while empty.
    for action in [READ, READ_ALL, READ_CLEAR] {
        check_fails!(
            h,
            syslog_at(action, 0, 64),
            libc::EINVAL,
            "action {action} with a null buffer"
        );
    }

    // The console level is 1 to 8. Nothing here has a console level, so being
    // told that level 99 was set is the entire defect.
    for level in [1, 4, 8] {
        let r = syslog_at(CONSOLE_LEVEL, 0, level);
        check!(h, r == 0, "console level {level} is accepted: r={r}");
    }
    for level in [-1, 0, 9, 99] {
        check_fails!(
            h,
            syslog_at(CONSOLE_LEVEL, 0, level),
            libc::EINVAL,
            "console level {level}"
        );
    }
    // ...and it is that command alone. The neighbours take any length, which is
    // what made the missing check easy to write.
    let r = syslog_at(CONSOLE_OFF, 0, 99);
    check!(h, r == 0, "a length means nothing to CONSOLE_OFF: r={r}");

    // Eleven commands, and nothing else.
    for action in [-1, 11, 12, 99] {
        check_fails!(h, syslog_at(action, 0, 0), libc::EINVAL, "action {action}");
    }

    // The one that mattered: ask for far more than the log holds.
    //
    // `unread` is re-read here rather than reused from the top: the block above
    // deliberately puts a line in the log, so the number sampled before it
    // describes a log that no longer exists. Comparing against the stale one
    // reported a failure that was the test's own doing.
    let unread = syslog(SIZE_UNREAD, &mut buf, 0);
    let ask = buf.len() as i32;
    let (r, touched) = read_into(READ, ask, &mut buf);
    check!(
        h,
        r >= 0,
        "reading {ask} bytes is allowed: r={r} errno={}",
        sys::errno()
    );
    if r >= 0 {
        check!(
            h,
            r <= unread.max(0),
            "and returns no more than the log holds: {r} of {unread}"
        );
        check!(
            h,
            touched <= r as usize,
            "nothing was written past what it says it read: {touched} bytes \
             disturbed for a return of {r}"
        );
    }

    // The same for the tail-reading action.
    let (r, touched) = read_into(READ_ALL, ask, &mut buf);
    check!(h, r >= 0, "READ_ALL is allowed: r={r} errno={}", sys::errno());
    if r >= 0 {
        check!(
            h,
            touched <= r as usize,
            "READ_ALL writes nothing past its return: {touched} for {r}"
        );
    }

    // Zero is a legal request and reads nothing.
    let (r, touched) = read_into(READ, 0, &mut buf);
    check!(h, r == 0 && touched == 0, "a zero-length read: r={r} touched={touched}");

    // A negative length is EINVAL, which is the one refusal.
    check_fails!(
        h,
        syslog(READ, &mut buf, -1),
        libc::EINVAL,
        "a negative length"
    );

    // The log has to actually work, or every check above is about an empty
    // buffer and would pass against a fifo that never stores anything. There
    // is no way to make this kernel print from inside the guest, so what is
    // asserted is the weaker thing the guest can see: the capacity is the
    // buffer's real size and SIZE_UNREAD never exceeds it.
    check!(
        h,
        capacity >= (1 << 16),
        "the log buffer is a real size: {capacity}"
    );

    // And an unmapped destination faults rather than being written to. Asked
    // after something is in the log, so the call has bytes to copy.
    let r = unsafe {
        libc::syscall(libc::SYS_syslog, READ_ALL, 0x7fff_0000_0000usize, 64)
    };
    check!(
        h,
        r == -1 || r == 0,
        "an unmapped destination is refused or reads nothing: r={r} errno={}",
        sys::errno()
    );

    std::process::exit(h.finish());
}
