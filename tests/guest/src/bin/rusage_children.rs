//! What a reaped child's CPU time is credited to.
//!
//! `getrusage(RUSAGE_CHILDREN)` and `times()`'s `tms_cutime` are the same
//! accumulator: every `wait` that reaps a child adds that child's totals to its
//! parent's, and they only ever go up. `getrusage(RUSAGE_SELF)` is a different
//! one and must not move when a child is reaped.
//!
//! Nothing tested the accumulator before 2026-08-31 — `abi_structs.rs` checks
//! that both calls answer and that the structs are the right shape, which
//! passes against an implementation that always answers zero.
//!
//! # Why the assertions are about ordering and not about values
//!
//! How much CPU a loop takes is the host's business and differs by two orders
//! of magnitude between an emulator and a real kernel, so `differential.sh`
//! can only compare the two sides if the checks are about *relations*: this is
//! at least that, this did not go down, this is not zero after work that
//! certainly used time. Every check here is one of those.

use std::time::Instant;

use guest_tests::{Harness, check};

/// Microseconds, as one number — which is what the kernel stores and what the
/// pair means.
fn micros(t: libc::timeval) -> i64 {
    t.tv_sec as i64 * 1_000_000 + t.tv_usec as i64
}

fn children() -> (i64, i64) {
    let mut r: libc::rusage = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut r) };
    assert_eq!(ok, 0, "getrusage(RUSAGE_CHILDREN)");
    (micros(r.ru_utime), micros(r.ru_stime))
}

fn own() -> (i64, i64) {
    let mut r: libc::rusage = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut r) };
    assert_eq!(ok, 0, "getrusage(RUSAGE_SELF)");
    (micros(r.ru_utime), micros(r.ru_stime))
}

/// `tms_cutime + tms_cstime`, in clock ticks.
fn times_children() -> i64 {
    let mut t: libc::tms = unsafe { std::mem::zeroed() };
    unsafe { libc::times(&mut t) };
    t.tms_cutime as i64 + t.tms_cstime as i64
}

/// A child that certainly uses CPU, reaped.
fn burn_a_child(ms: u64) {
    // SAFETY: the child only computes and calls _exit, both async-signal-safe.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let start = Instant::now();
        let mut x = 0u64;
        while start.elapsed().as_millis() < ms as u128 {
            for i in 0..10_000u64 {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(i);
            }
        }
        // Keep the compiler from deciding the loop was pointless.
        unsafe { libc::_exit((x & 1) as i32) };
    }
    assert!(pid > 0, "fork");
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

fn main() {
    let mut h = Harness::new();

    h.group("a-fresh-process");
    let (cu0, cs0) = children();
    check!(h, cu0 >= 0 && cs0 >= 0, "children's time starts at or above zero: {cu0}us user, {cs0}us system");
    let ticks0 = times_children();
    check!(h, ticks0 >= 0, "and times() agrees it is not negative: {ticks0} ticks");

    h.group("one-child");
    let (su0, _) = own();
    burn_a_child(120);
    let (cu1, cs1) = children();
    check!(h, cu1 + cs1 > cu0 + cs0,
        "reaping a child that burned CPU moves RUSAGE_CHILDREN: {}us -> {}us",
        cu0 + cs0, cu1 + cs1);
    check!(h, cu1 >= cu0 && cs1 >= cs0, "and neither half went backwards");
    let ticks1 = times_children();
    check!(h, ticks1 >= ticks0, "times()'s cutime does not go backwards: {ticks0} -> {ticks1}");

    // RUSAGE_SELF is a different accumulator. It moves on its own — this
    // process is running — so the check is that the *child's* time did not land
    // in it: the parent did almost nothing while the child burned 120ms.
    let (su1, _) = own();
    check!(h, su1 - su0 < (cu1 - cu0) + (cs1 - cs0) + 100_000,
        "and the child's time did not land in RUSAGE_SELF: self +{}us, child +{}us",
        su1 - su0, (cu1 - cu0) + (cs1 - cs0));

    h.group("accumulates");
    burn_a_child(120);
    let (cu2, cs2) = children();
    check!(h, cu2 + cs2 > cu1 + cs1,
        "a second child adds to the first rather than replacing it: {}us -> {}us",
        cu1 + cs1, cu2 + cs2);
    check!(h, cu2 >= cu1 && cs2 >= cs1, "and neither half went backwards");

    h.group("normalised");
    // The microseconds half of every pair is in range. It is the field an
    // add-with-carry gets wrong, and a guest libc doing arithmetic on a pair
    // where it is not is wrong by whole seconds.
    let mut r: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut r) };
    check!(h, (0..1_000_000).contains(&(r.ru_utime.tv_usec as i64)),
        "RUSAGE_CHILDREN's utime usec is in range: {}", r.ru_utime.tv_usec);
    check!(h, (0..1_000_000).contains(&(r.ru_stime.tv_usec as i64)),
        "and its stime usec: {}", r.ru_stime.tv_usec);
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut r) };
    check!(h, (0..1_000_000).contains(&(r.ru_utime.tv_usec as i64)),
        "RUSAGE_SELF's utime usec is in range: {}", r.ru_utime.tv_usec);
    check!(h, (0..1_000_000).contains(&(r.ru_stime.tv_usec as i64)),
        "and its stime usec: {}", r.ru_stime.tv_usec);

    h.group("wait4");
    // wait4's own rusage argument reports the child that was just reaped, not
    // the accumulated total.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let start = Instant::now();
        let mut x = 0u64;
        while start.elapsed().as_millis() < 120 {
            for i in 0..10_000u64 {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(i);
            }
        }
        unsafe { libc::_exit((x & 1) as i32) };
    }
    let mut status = 0;
    let mut r4: libc::rusage = unsafe { std::mem::zeroed() };
    let got = unsafe { libc::wait4(pid, &mut status, 0, &mut r4) };
    check!(h, got == pid, "wait4 reaped the child: {got}");
    let one = micros(r4.ru_utime) + micros(r4.ru_stime);
    check!(h, one > 0, "and reported the time it used: {one}us");
    let (cu3, cs3) = children();
    check!(h, cu3 + cs3 >= cu2 + cs2 + one,
        "which is also added to RUSAGE_CHILDREN: {}us + {}us <= {}us",
        cu2 + cs2, one, cu3 + cs3);

    std::process::exit(h.finish());
}
