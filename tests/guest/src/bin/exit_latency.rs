//! How long a multithreaded process takes to exit.
//!
//! A deadline rather than a comparison, and one about this emulator: on a real
//! kernel `exit_group` tears down the other threads with no wait a userspace
//! program can observe, so Linux answers every shape here in under 150 µs and
//! there is nothing to learn from running it there.
//!
//! What it guards is a regression that cost **69 ms per exit**. `do_exit_group`
//! waited for the other threads twice in a row: a 10 ms poll of the group's
//! thread list, and then
//!
//! ```c
//! // Give extra time for pthread cleanup on host system
//! struct timespec extra_delay = {0, 50 * 1000000L};
//! nanosleep(&extra_delay, NULL);
//! ```
//!
//! unconditionally, on the path every multithreaded process takes to exit. A
//! thread leaves the group's thread list partway through `do_exit` and its host
//! pthread keeps unwinding afterwards, so the poll was watching the wrong event
//! and the sleep was there to cover the gap. Neither is the event;
//! `crates/kernel/hostthreads` is, and it is waited on.
//!
//! Measured before and after, one extra thread, `fork` to `waitpid` returning:
//! **69 411 µs → 150 µs**. A real arm64 kernel does it in 78 µs.
//!
//! The five modes are what the other thread is doing when the process exits.
//! They matter because a sleep is uniform and a real wait is not: before the
//! fix every one of them cost the same 69 ms, which is itself the sign that
//! nothing was being waited *for*.

use guest_tests::{Harness, check};
use std::time::Instant;

extern "C" fn spin(_: *mut libc::c_void) -> *mut libc::c_void {
    loop {
        std::hint::spin_loop();
    }
}
extern "C" fn paused(_: *mut libc::c_void) -> *mut libc::c_void {
    loop {
        unsafe { libc::pause() };
    }
}
extern "C" fn sleeper(_: *mut libc::c_void) -> *mut libc::c_void {
    loop {
        unsafe { libc::usleep(1000) };
    }
}
extern "C" fn reader(_: *mut libc::c_void) -> *mut libc::c_void {
    let mut b = [0u8; 1];
    loop {
        unsafe { libc::read(0, b.as_mut_ptr().cast(), 1) };
    }
}

/// Average microseconds for fork → n threads → `_exit` → `waitpid` returning.
fn round_trip(body: extern "C" fn(*mut libc::c_void) -> *mut libc::c_void, n: usize, rounds: usize) -> u128 {
    let mut total = 0u128;
    for _ in 0..rounds {
        let t0 = Instant::now();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            for _ in 0..n {
                let mut t: libc::pthread_t = unsafe { std::mem::zeroed() };
                unsafe {
                    libc::pthread_create(&mut t, std::ptr::null(), body, std::ptr::null_mut())
                };
            }
            unsafe { libc::_exit(0) };
        }
        let mut st = 0i32;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        total += t0.elapsed().as_micros();
    }
    total / rounds as u128
}

fn main() {
    let mut h = Harness::new();
    let rounds = 20;

    // Generous: the measured figure is 130-250 µs and the defect this guards
    // was 69 000 µs, so there is no threshold in between that a slow machine
    // could cross by accident.
    const DEADLINE_US: u128 = 10_000;

    h.group("a-multithreaded-process-exits-promptly");
    // The control first: one thread, no wait at all to do. If this is slow the
    // rest says nothing, because the cost is somewhere else entirely.
    let base = round_trip(paused, 0, rounds);
    println!("  no extra threads:   {base:>6} us");
    check!(h, base < DEADLINE_US, "a single-threaded exit is prompt: {base} us");

    for (name, body) in [
        ("spinning", spin as extern "C" fn(*mut libc::c_void) -> *mut libc::c_void),
        ("in pause()", paused),
        ("in usleep()", sleeper),
        ("in read()", reader),
    ] {
        let us = round_trip(body, 1, rounds);
        println!("  one thread {name:<12} {us:>6} us");
        check!(
            h,
            us < DEADLINE_US,
            "exiting past a thread {name} takes {us} us, over the {DEADLINE_US} us deadline"
        );
    }

    h.group("and-the-cost-scales-with-the-threads-there-are");
    // Not a deadline: the point is that it is *proportional*. A fixed sleep
    // gives the same number for 1 and for 16, which is what it looked like.
    let mut last = 0u128;
    for n in [1usize, 4, 16] {
        let us = round_trip(paused, n, rounds);
        println!("  {n:>2} threads:         {us:>6} us");
        check!(h, us < DEADLINE_US * 4, "{n} threads: {us} us");
        last = us;
    }
    let _ = last;

    std::process::exit(h.finish());
}
