//! `prctl(2)`: the process and thread attributes a guest sets and reads back.
//!
//! None of these attributes *does* anything in this emulator. There is no core
//! dump for `PR_SET_DUMPABLE` to suppress, no capability set for
//! `PR_SET_KEEPCAPS` to keep, and no privileged execve for `PR_SET_NO_NEW_PRIVS`
//! to stop. What they do is get remembered and reported, and that is not a
//! formality: a runtime that sets one and reads it back is checking what it is
//! running under, and an answer that contradicts the request is worse than an
//! honest `EINVAL`.
//!
//! So this file asserts three things per option, and the third is the one that
//! keeps being wrong:
//!
//! 1. an accepted value is accepted,
//! 2. a refused value is refused,
//! 3. **the boundary between them is where Linux puts it** -- including the
//!    arguments Linux requires to be zero, and the fact that its arguments are
//!    `unsigned long`, so a value that is only wrong in the high 32 bits is
//!    still wrong.
//!
//! That last one is the class `tools/syscall-abi.py` gates against: a syscall
//! parameter narrowed to `int` before it is bounded lets `0x1_0000_0009`
//! through as `9`.
//!
//! Every answer here was taken from a real arm64 kernel through
//! `differential.sh`, not from the man page -- the page is silent about the
//! zero-argument requirements and wrong about `PR_SET_DUMPABLE`.

use guest_tests::{Harness, check, sys};

const SET_PDEATHSIG: i32 = 1;
const GET_PDEATHSIG: i32 = 2;
const GET_DUMPABLE: i32 = 3;
const SET_DUMPABLE: i32 = 4;
const GET_KEEPCAPS: i32 = 7;
const SET_KEEPCAPS: i32 = 8;
const SET_NAME: i32 = 15;
const GET_NAME: i32 = 16;
const SET_CHILD_SUBREAPER: i32 = 36;
const GET_CHILD_SUBREAPER: i32 = 37;
const SET_NO_NEW_PRIVS: i32 = 38;
const GET_NO_NEW_PRIVS: i32 = 39;

fn prctl(option: i32, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    sys::clear_errno();
    unsafe { libc::syscall(libc::SYS_prctl, option, a2, a3, a4, a5) as i64 }
}

fn p1(option: i32, a2: u64) -> i64 {
    prctl(option, a2, 0, 0, 0)
}

fn main() {
    let mut h = Harness::new();

    h.group("comm");
    // Linux truncates a long name rather than refusing it: the copy is bounded
    // at 15 and the sixteenth byte was already zeroed.
    let long = b"0123456789abcdefghij\0";
    check!(h, p1(SET_NAME, long.as_ptr() as u64) == 0, "a 20-character name is accepted");
    // PR_GET_NAME writes sizeof(comm) == 16 bytes, always -- not strlen+1. A
    // caller with a 16-byte buffer is entitled to have all of it written, and
    // the bytes past the terminator are the kernel's zeroes rather than
    // whatever was on the caller's stack.
    let mut buf = [0xA5u8; 32];
    let r = p1(GET_NAME, buf.as_mut_ptr() as u64);
    check!(h, r == 0, "PR_GET_NAME is answered: r={r} errno={}", sys::errno());
    let name = std::str::from_utf8(&buf[..buf.iter().position(|b| *b == 0).unwrap_or(0)])
        .unwrap_or("?")
        .to_string();
    check!(h, name == "0123456789abcde", "and truncated to 15 characters: {name:?}");
    check!(
        h,
        buf[..16].iter().all(|b| *b != 0xA5),
        "and wrote all 16 bytes, not strlen+1: {:?}",
        &buf[..17]
    );
    check!(h, buf[16] == 0xA5, "and no more than 16");

    // A name that fits is not truncated, and the check above is not vacuous.
    check!(h, p1(SET_NAME, b"short\0".as_ptr() as u64) == 0, "a short name is accepted");
    let mut buf = [0xA5u8; 32];
    p1(GET_NAME, buf.as_mut_ptr() as u64);
    let name = std::str::from_utf8(&buf[..buf.iter().position(|b| *b == 0).unwrap_or(0)])
        .unwrap_or("?")
        .to_string();
    check!(h, name == "short", "and comes back whole: {name:?}");
    check!(h, buf[..16].iter().all(|b| *b != 0xA5), "with 16 bytes written for it too");

    h.group("pdeath-signal");
    check!(h, p1(SET_PDEATHSIG, 9) == 0, "SIGKILL is a valid pdeath signal");
    let mut got: i32 = -1;
    check!(h, p1(GET_PDEATHSIG, &mut got as *mut i32 as u64) == 0, "and is read back");
    check!(h, got == 9, "as the same number: {got}");
    check!(h, p1(SET_PDEATHSIG, 0) == 0, "0 disarms it");
    p1(GET_PDEATHSIG, &mut got as *mut i32 as u64);
    check!(h, got == 0, "and reads back as 0: {got}");
    // The bound, on both sides of it. Linux's valid_signal takes an unsigned
    // long and is `sig <= _NSIG`, so 64 is *inside* the range even though no
    // signal 64 is ever delivered -- a check that only tried 65 would pass
    // against an implementation that refused 64 as well.
    check!(
        h,
        p1(SET_PDEATHSIG, 64) == 0,
        "64 is the last valid signal number: errno={}",
        sys::errno()
    );
    check!(
        h,
        p1(SET_PDEATHSIG, 65) == -1 && sys::errno() == libc::EINVAL,
        "65 is past the last signal"
    );
    p1(SET_PDEATHSIG, 0);
    let r = p1(SET_PDEATHSIG, 0x1_0000_0009);
    check!(
        h,
        r == -1 && sys::errno() == libc::EINVAL,
        "and 0x100000009 is not SIGKILL: r={r} errno={}",
        sys::errno()
    );
    p1(GET_PDEATHSIG, &mut got as *mut i32 as u64);
    check!(h, got == 0, "a refused pdeath signal changes nothing: {got}");

    h.group("dumpable");
    check!(h, p1(SET_DUMPABLE, 1) == 0, "SUID_DUMP_USER is accepted");
    check!(h, p1(GET_DUMPABLE, 0) == 1, "and reads back as 1");
    check!(h, p1(SET_DUMPABLE, 0) == 0, "SUID_DUMP_DISABLE is accepted");
    check!(h, p1(GET_DUMPABLE, 0) == 0, "and reads back as 0");
    // SUID_DUMP_ROOT is a *value the kernel sets itself*, not one a process may
    // ask for: Linux's PR_SET_DUMPABLE compares against DISABLE and USER only.
    let r = p1(SET_DUMPABLE, 2);
    check!(
        h,
        r == -1 && sys::errno() == libc::EINVAL,
        "SUID_DUMP_ROOT is not settable by a process: r={r} errno={}",
        sys::errno()
    );
    check!(h, p1(SET_DUMPABLE, 3) == -1, "and 3 is not a value at all");
    let r = p1(SET_DUMPABLE, 0x1_0000_0001);
    check!(
        h,
        r == -1 && sys::errno() == libc::EINVAL,
        "nor is 0x100000001, whose low half is 1: r={r} errno={}",
        sys::errno()
    );
    check!(h, p1(GET_DUMPABLE, 0) == 0, "and none of those changed it");
    // Restore, so nothing downstream inherits a non-default.
    p1(SET_DUMPABLE, 1);

    h.group("keepcaps");
    check!(h, p1(SET_KEEPCAPS, 0) == 0, "0 is accepted");
    check!(h, p1(GET_KEEPCAPS, 0) == 0, "and reads back as 0");
    check!(h, p1(SET_KEEPCAPS, 1) == 0, "1 is accepted");
    check!(h, p1(GET_KEEPCAPS, 0) == 1, "and reads back as 1");
    let r = p1(SET_KEEPCAPS, 2);
    check!(
        h,
        r == -1 && sys::errno() == libc::EINVAL,
        "2 is neither: r={r} errno={}",
        sys::errno()
    );
    check!(h, p1(SET_KEEPCAPS, 0) == 0, "restored");

    h.group("child-subreaper");
    check!(h, p1(SET_CHILD_SUBREAPER, 1) == 0, "setting it is accepted");
    let mut got: i32 = -1;
    check!(h, p1(GET_CHILD_SUBREAPER, &mut got as *mut i32 as u64) == 0, "and read back");
    check!(h, got == 1, "as 1: {got}");
    // Any non-zero, not just 1 -- Linux stores `!!arg2`.
    check!(h, p1(SET_CHILD_SUBREAPER, 7) == 0, "any non-zero sets it");
    p1(GET_CHILD_SUBREAPER, &mut got as *mut i32 as u64);
    check!(h, got == 1, "and it still reads back as exactly 1: {got}");
    check!(h, p1(SET_CHILD_SUBREAPER, 0) == 0, "and 0 clears it");
    p1(GET_CHILD_SUBREAPER, &mut got as *mut i32 as u64);
    check!(h, got == 0, "reading back as 0: {got}");

    h.group("unknown-options");
    // An option the kernel does not know is EINVAL, which is how a program
    // tells "not implemented" from "implemented and refused".
    for option in [0, 9999, 0x7fff_ffff] {
        let r = p1(option, 0);
        check!(
            h,
            r == -1 && sys::errno() == libc::EINVAL,
            "prctl({option}) is EINVAL: r={r} errno={}",
            sys::errno()
        );
    }

    // Last, because it cannot be undone: Linux refuses to clear no_new_privs,
    // and anything after this would be running under it.
    h.group("no-new-privs");
    check!(h, p1(GET_NO_NEW_PRIVS, 0) == 0, "it starts clear");
    // The arguments Linux requires to be zero. Nothing in the man page says
    // so; both of these are read straight out of kernel/sys.c.
    let r = prctl(SET_NO_NEW_PRIVS, 1, 1, 0, 0);
    check!(
        h,
        r == -1 && sys::errno() == libc::EINVAL,
        "PR_SET_NO_NEW_PRIVS with a non-zero arg3 is EINVAL: r={r} errno={}",
        sys::errno()
    );
    let r = prctl(GET_NO_NEW_PRIVS, 0, 0, 0, 1);
    check!(
        h,
        r == -1 && sys::errno() == libc::EINVAL,
        "PR_GET_NO_NEW_PRIVS with a non-zero arg5 is EINVAL: r={r} errno={}",
        sys::errno()
    );
    check!(h, p1(GET_NO_NEW_PRIVS, 0) == 0, "and neither of those set it");
    // Only 1. Setting it to 0 is not "clear it", it is a refusal.
    let r = p1(SET_NO_NEW_PRIVS, 0);
    check!(
        h,
        r == -1 && sys::errno() == libc::EINVAL,
        "asking for 0 is EINVAL rather than a clear: r={r} errno={}",
        sys::errno()
    );
    check!(h, p1(SET_NO_NEW_PRIVS, 1) == 0, "and 1 sets it");
    check!(h, p1(GET_NO_NEW_PRIVS, 0) == 1, "which reads back as 1");
    let r = p1(SET_NO_NEW_PRIVS, 0);
    check!(
        h,
        r == -1 && sys::errno() == libc::EINVAL,
        "and it still cannot be cleared: r={r} errno={}",
        sys::errno()
    );
    check!(h, p1(GET_NO_NEW_PRIVS, 0) == 1, "so it is still set");

    std::process::exit(h.finish());
}
