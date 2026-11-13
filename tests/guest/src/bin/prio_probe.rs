//! What this kernel answers about scheduling priority: `getpriority`,
//! `setpriority`, the nine `sched_*` calls, and `ioprio_get`/`ioprio_set`.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Eleven of these twelve syscalls are named by no other probe. They are a
//! family for one reason: **a wrong answer is silent.** A nice value that does
//! not round-trip, an affinity mask that comes back with the wrong number of
//! bits set, a policy the kernel says it accepted and did not — none of them
//! makes a program stop, and none of them makes a test fail unless a test asks
//! the exact question.
//!
//! `getpriority` is the sharpest of them. It answers `20 - nice`, so a legal
//! answer is `-1` for nice 21 — a value no guest can set, but the reason the
//! call's contract says a caller must clear `errno` first and check *that*.
//! An implementation that returned the raw nice would put every value out by
//! twenty and be visible to nothing.
//!
//! # What this kernel does not implement, and how that is reported
//!
//! It has one scheduling policy, `SCHED_OTHER`, so every realtime call answers
//! an error where Linux answers a value. That is one difference and it is in
//! `probe_diff.sh`'s KNOWN — the probe prints the *errno*, so a change from
//! `EINVAL` to `EPERM` is a change this catches, and only the presence of the
//! policies is suppressed.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

fn named(e: i32) -> String {
    match e {
        0 => "no error",
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::ESRCH => "ESRCH",
        libc::EFAULT => "EFAULT",
        libc::ENOSYS => "ENOSYS",
        libc::EAGAIN => "EAGAIN",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

const PRIO_PROCESS: i32 = 0;
const PRIO_PGRP: i32 = 1;
const PRIO_USER: i32 = 2;

const SCHED_OTHER: i32 = 0;
const SCHED_FIFO: i32 = 1;
const SCHED_RR: i32 = 2;
const SCHED_BATCH: i32 = 3;
const SCHED_IDLE: i32 = 5;
const SCHED_DEADLINE: i32 = 6;

fn sys(n: i64, a: i64, b: i64, c: i64) -> i64 {
    clear_errno();
    unsafe { libc::syscall(n, a, b, c) }
}

/// `getpriority` cannot report failure by its return value: `-1` is a legal
/// answer. So the convention is to clear `errno`, call, and read `errno` —
/// which is what this prints, both halves.
fn getprio(which: i32, who: i32) -> String {
    clear_errno();
    let r = unsafe { libc::syscall(libc::SYS_getpriority, which, who) };
    let e = errno();
    if e != 0 {
        format!("{} (errno {})", r, named(e))
    } else {
        format!("{r} (errno clear)")
    }
}

fn r(v: i64) -> String {
    if v < 0 { named(errno()) } else { v.to_string() }
}

fn main() {
    println!("########## getpriority: which and who ##########");
    for (w, name) in [(PRIO_PROCESS, "PRIO_PROCESS"), (PRIO_PGRP, "PRIO_PGRP"), (PRIO_USER, "PRIO_USER")] {
        line(&format!("getpriority({name}, 0)"), getprio(w, 0));
    }
    line("getpriority(PRIO_PROCESS, self)", getprio(PRIO_PROCESS, std::process::id() as i32));
    line("getpriority(PRIO_PROCESS, 999999)", getprio(PRIO_PROCESS, 999_999));
    line("getpriority(PRIO_PROCESS, -1)", getprio(PRIO_PROCESS, -1));
    line("getpriority(3, 0) -- no such `which`", getprio(3, 0));
    line("getpriority(-1, 0)", getprio(-1, 0));

    println!("\n########## setpriority: the range and the clamp ##########");
    // Linux clamps rather than refusing: -20..19 is the range, and anything
    // outside it is pulled to the nearest end. `getpriority` then reports
    // `20 - nice`, so nice -20 reads as 40 and nice 19 reads as 1.
    for prio in [0i64, 5, 19, 20, 100, -1, -20, -21, -100, i64::from(i32::MIN)] {
        let set = sys(libc::SYS_setpriority, PRIO_PROCESS as i64, 0, prio);
        // `r(set)` **before** `getprio`, which clears errno: reading the errno
        // of one call after making another is how this printed "no error" for a
        // call that had failed. `getpriority`'s own contract is the same
        // hazard from the other end.
        let said = r(set);
        let got = getprio(PRIO_PROCESS, 0);
        line(&format!("setpriority(PRIO_PROCESS, 0, {prio})"), format!("{said} then {got}"));
        // Back to where it started, so the next case is not measuring the last.
        sys(libc::SYS_setpriority, PRIO_PROCESS as i64, 0, 0);
    }
    line(
        "setpriority(3, 0, 0) -- no such `which`",
        r(sys(libc::SYS_setpriority, 3, 0, 0)),
    );
    line(
        "setpriority(PRIO_PROCESS, 999999, 0)",
        r(sys(libc::SYS_setpriority, PRIO_PROCESS as i64, 999_999, 0)),
    );

    println!("\n########## sched policies ##########");
    line(
        "sched_getscheduler(0)",
        r(sys(libc::SYS_sched_getscheduler, 0, 0, 0)),
    );
    line(
        "sched_getscheduler(999999)",
        r(sys(libc::SYS_sched_getscheduler, 999_999, 0, 0)),
    );
    line(
        "sched_getscheduler(-1)",
        r(sys(libc::SYS_sched_getscheduler, -1, 0, 0)),
    );

    // `sched_setscheduler` takes a `struct sched_param`, which is one int.
    // Each in a child, so one accepted policy does not change the answer to the
    // next: on Linux a thread that has entered `SCHED_IDLE` needs
    // `CAP_SYS_NICE` to leave it, so a sweep in place is a sweep over a moving
    // target and only on one of the two sides.
    let mut param: [i32; 1] = [0];
    for (p, name) in [
        (SCHED_OTHER, "SCHED_OTHER"),
        (SCHED_BATCH, "SCHED_BATCH"),
        (SCHED_IDLE, "SCHED_IDLE"),
        (SCHED_FIFO, "SCHED_FIFO"),
        (SCHED_RR, "SCHED_RR"),
        (SCHED_DEADLINE, "SCHED_DEADLINE"),
        (99, "policy 99"),
        (-1, "policy -1"),
    ] {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let mut pa: [i32; 1] = [0];
            let v = sys(libc::SYS_sched_setscheduler, 0, p as i64, pa.as_mut_ptr() as i64);
            line(&format!("sched_setscheduler(0, {name}, prio 0)"), r(v));
            unsafe { libc::_exit(0) };
        }
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
    }
    // A realtime policy with a realtime priority, which is the combination a
    // program that wants one actually asks for.
    param[0] = 50;
    line(
        "sched_setscheduler(0, SCHED_FIFO, prio 50)",
        r(sys(libc::SYS_sched_setscheduler, 0, SCHED_FIFO as i64, param.as_mut_ptr() as i64)),
    );
    // And SCHED_OTHER with a non-zero priority, which Linux refuses: the only
    // legal `sched_priority` for a non-realtime policy is 0.
    param[0] = 1;
    line(
        "sched_setscheduler(0, SCHED_OTHER, prio 1)",
        r(sys(libc::SYS_sched_setscheduler, 0, SCHED_OTHER as i64, param.as_mut_ptr() as i64)),
    );

    // The round trip, which is the half a kernel that accepts and forgets would
    // pass without: set a policy, ask for it back. Each in a **child**, because
    // Linux will not let an unprivileged thread leave `SCHED_IDLE` again -- so
    // doing this in place leaves the two sides on different policies and every
    // later case compares two tasks rather than two kernels. A child also means
    // the order of the three does not matter.
    for (p, name) in [(SCHED_BATCH, "SCHED_BATCH"), (SCHED_IDLE, "SCHED_IDLE"), (SCHED_OTHER, "SCHED_OTHER")] {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let mut pa: [i32; 1] = [0];
            let set = sys(libc::SYS_sched_setscheduler, 0, p as i64, pa.as_mut_ptr() as i64);
            let said = r(set);
            let back = sys(libc::SYS_sched_getscheduler, 0, 0, 0);
            line(
                &format!("set {name} then getscheduler"),
                format!("{said} then {}", r(back)),
            );
            unsafe { libc::_exit(0) };
        }
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
    }

    println!("\n########## the priority range of each policy ##########");
    for (p, name) in [
        (SCHED_OTHER, "SCHED_OTHER"),
        (SCHED_FIFO, "SCHED_FIFO"),
        (SCHED_RR, "SCHED_RR"),
        (SCHED_BATCH, "SCHED_BATCH"),
        (SCHED_IDLE, "SCHED_IDLE"),
        (SCHED_DEADLINE, "SCHED_DEADLINE"),
        (99, "policy 99"),
    ] {
        // The two are read from one table and differ by which element they
        // take, which is the shape a swapped index hides in: for SCHED_OTHER
        // both answer 0.
        let max = sys(libc::SYS_sched_get_priority_max, p as i64, 0, 0);
        let min = sys(libc::SYS_sched_get_priority_min, p as i64, 0, 0);
        line(&format!("sched_get_priority_max({name})"), r(max));
        line(&format!("sched_get_priority_min({name})"), r(min));
    }

    println!("\n########## sched_getparam and sched_setparam ##########");
    param[0] = -1;
    let v = sys(libc::SYS_sched_getparam, 0, param.as_mut_ptr() as i64, 0);
    line("sched_getparam(0)", r(v));
    line("  its sched_priority", param[0]);
    line(
        "sched_getparam(999999)",
        r(sys(libc::SYS_sched_getparam, 999_999, param.as_mut_ptr() as i64, 0)),
    );
    line(
        "sched_getparam(0, NULL)",
        r(sys(libc::SYS_sched_getparam, 0, 0, 0)),
    );
    param[0] = 0;
    line(
        "sched_setparam(0, prio 0)",
        r(sys(libc::SYS_sched_setparam, 0, param.as_mut_ptr() as i64, 0)),
    );
    param[0] = 1;
    line(
        "sched_setparam(0, prio 1) under SCHED_OTHER",
        r(sys(libc::SYS_sched_setparam, 0, param.as_mut_ptr() as i64, 0)),
    );

    println!("\n########## affinity ##########");
    // The size is in *bytes* on the wire and Linux requires a multiple of the
    // word size, not merely enough room -- `sched_getaffinity` answers EINVAL
    // for anything that is not.
    let mut mask = [0u8; 128];
    for size in [0usize, 1, 4, 7, 8, 16, 128] {
        let v = sys(libc::SYS_sched_getaffinity, 0, size as i64, mask.as_mut_ptr() as i64);
        line(
            &format!("sched_getaffinity(0, size {size})"),
            if v < 0 { named(errno()) } else { format!("wrote {v} bytes") },
        );
    }
    // How many processors are in the answer -- comparable, because both sides
    // are the same machine. Printed as "at least one", because a container may
    // be pinned and this emulator reports its own set.
    mask.fill(0);
    let v = sys(libc::SYS_sched_getaffinity, 0, 128, mask.as_mut_ptr() as i64);
    if v > 0 {
        let bits: u32 = mask.iter().map(|b| b.count_ones()).sum();
        line("at least one processor in the mask", bits >= 1);
        line("the mask is not every bit of the buffer", bits < 128 * 8);
    }
    line(
        "sched_getaffinity(999999, size 128)",
        r(sys(libc::SYS_sched_getaffinity, 999_999, 128, mask.as_mut_ptr() as i64)),
    );
    line(
        "sched_getaffinity(0, size 128, NULL)",
        r(sys(libc::SYS_sched_getaffinity, 0, 128, 0)),
    );

    // Setting it back to what it already is must be accepted; setting it to
    // nothing must not, because a thread with no processor cannot run.
    let mut set = [0u8; 128];
    let _ = sys(libc::SYS_sched_getaffinity, 0, 128, set.as_mut_ptr() as i64);
    line(
        "sched_setaffinity(0, the mask it already has)",
        r(sys(libc::SYS_sched_setaffinity, 0, 128, set.as_mut_ptr() as i64)),
    );
    let empty = [0u8; 128];
    line(
        "sched_setaffinity(0, an empty mask)",
        r(sys(libc::SYS_sched_setaffinity, 0, 128, empty.as_ptr() as i64)),
    );
    line(
        "sched_setaffinity(0, size 0)",
        r(sys(libc::SYS_sched_setaffinity, 0, 0, set.as_ptr() as i64)),
    );

    println!("\n########## sched_yield and rr_get_interval ##########");
    line("sched_yield()", r(sys(libc::SYS_sched_yield, 0, 0, 0)));
    let mut ts = [0i64; 2];
    let v = sys(libc::SYS_sched_rr_get_interval, 0, ts.as_mut_ptr() as i64, 0);
    line("sched_rr_get_interval(0)", r(v));
    if v == 0 {
        // Under SCHED_OTHER Linux answers the timeslice, which is not zero.
        line("  the interval is not zero", ts[0] != 0 || ts[1] != 0);
        line("  tv_nsec is in range", ts[1] >= 0 && ts[1] < 1_000_000_000);
    }
    line(
        "sched_rr_get_interval(999999)",
        r(sys(libc::SYS_sched_rr_get_interval, 999_999, ts.as_mut_ptr() as i64, 0)),
    );

    println!("\n########## ioprio ##########");
    const IOPRIO_WHO_PROCESS: i64 = 1;
    const IOPRIO_WHO_PGRP: i64 = 2;
    const IOPRIO_WHO_USER: i64 = 3;
    // Only the process's own is a value: `IOPRIO_WHO_PGRP` and
    // `IOPRIO_WHO_USER` aggregate over every other process in the group or
    // owned by the user, so what comes back depends on what else is running --
    // which is not a question about this kernel. Whether the call is *accepted*
    // is, so those two print that instead.
    line(
        "ioprio_get(IOPRIO_WHO_PROCESS, 0)",
        r(sys(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0, 0)),
    );
    for (w, name) in [(IOPRIO_WHO_PGRP, "IOPRIO_WHO_PGRP"), (IOPRIO_WHO_USER, "IOPRIO_WHO_USER")] {
        let v = sys(libc::SYS_ioprio_get, w, 0, 0);
        line(
            &format!("ioprio_get({name}, 0) accepted"),
            if v < 0 { named(errno()) } else { "yes".into() },
        );
    }
    for (w, name) in [(0i64, "who 0"), (4, "who 4")] {
        line(
            &format!("ioprio_get({name}, 0)"),
            r(sys(libc::SYS_ioprio_get, w, 0, 0)),
        );
    }
    // class in 13..16, level in 0..13. The man page says the level is three
    // bits; a 6.x kernel takes ten, so 8 is accepted and 15 is not -- which is
    // the boundary this prints rather than asserts.
    for (class, level) in [(0i64, 0i64), (1, 0), (1, 4), (1, 7), (1, 8), (1, 15), (2, 4), (3, 0), (4, 0)] {
        let v = sys(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, (class << 13) | level);
        line(&format!("ioprio_set(class {class}, level {level})"), r(v));
    }
}
