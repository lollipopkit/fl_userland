//! The half a `GuestLock` mediates: the blocking read and the fire that ends it.
//!
//! The tests in `lib.rs` construct a [`TimerFd`] and exercise its rules. These
//! go through `Descriptor::read_count` and `Descriptor::fire`, which is where the wait
//! loop is — and that loop is where the defect recorded above it was:
//!
//! > an earlier version of this loop held a `&mut` across the wait, and the
//! > release profile's LTO acted on the `noalias` that implies. Every blocking
//! > read hung while the debug build was fine.
//!
//! **So run these with `--release` as well as without.** A debug run does not
//! reach the condition that produced that hang; `cargo test --release -p
//! kernel-timerfd` does. Neither profile was covered before, because
//! `GuestLock`'s primitive is C and did not link into a test binary — see
//! `util_guestlock_teststub`.
//!
//! Each test owns a private reverse edge; the syscall crate clones the
//! descriptor's edge into its timer state in the same way.

use kernel_sighand as _;
use kernel_sigqueue as _;

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// `Descriptor::new` answers an `Arc` since 2026-09-16, so these tests hand
/// the state to a thread by cloning it rather than by `Box::into_raw` and a
/// `usize` round trip. That removed all eighteen `unsafe` blocks in this file
/// and, with them, the reason a reader thread had to be told an address: the
/// thing being shared between threads is now shared in the type.
fn make() -> Arc<Descriptor> {
    Descriptor::new(Arc::new(Watchers::default()))
}

fn read(state: &Descriptor, nonblock: bool) -> (isize, u64) {
    let mut out = 0u64;
    let rc = state.read_count(nonblock as i32, &mut out);
    (rc, out)
}

#[test]
fn a_nonblocking_read_before_any_expiry_is_eagain() {
    let t = make();
    assert_eq!(read(&t, true).0, EAGAIN);
}

#[test]
fn a_blocking_read_waits_for_the_timer_to_fire() {
    let t = make();
    let firing = Arc::clone(&t);
    let started = Instant::now();
    let firer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(80));
        firing.fire();
    });
    let (rc, count) = read(&t, false);
    assert_eq!(rc, 8);
    assert_eq!(count, 1);
    assert!(
        started.elapsed() >= Duration::from_millis(70),
        "returned after {:?}, before the timer fired",
        started.elapsed()
    );
    firer.join().unwrap();
}

#[test]
fn expirations_accumulate_and_one_read_takes_them_all() {
    // What `read(2)` on a timerfd returns is the number of expirations since
    // the last read, not one per read. A reader that fell behind gets the
    // backlog in one number.
    let t = make();
    for _ in 0..5 {
        t.fire();
    }
    assert_eq!(read(&t, true), (8, 5));
    assert_eq!(
        read(&t, true).0,
        EAGAIN,
        "the count was not cleared by the read"
    );
}

#[test]
fn poll_says_readable_exactly_when_a_read_would_not_block() {
    let t = make();
    assert_eq!(t.poll_types() & POLL_READ, 0);
    t.fire();
    assert_ne!(t.poll_types() & POLL_READ, 0);
    assert_eq!(read(&t, true), (8, 1));
    assert_eq!(
        t.poll_types() & POLL_READ,
        0,
        "still readable after draining"
    );
}

#[test]
fn one_expiry_satisfies_exactly_one_of_two_blocked_readers() {
    // The wake is a broadcast, so both readers run. Only one can have the
    // count; the other has to find it zero and wait again rather than
    // returning a zero expiry count, which no timerfd read is allowed to do.
    let t = make();
    let done = Arc::new(AtomicUsize::new(0));

    let readers: Vec<_> = (0..2)
        .map(|_| {
            let done = Arc::clone(&done);
            let state = Arc::clone(&t);
            thread::spawn(move || {
                let mut out = 0u64;
                let rc = state.read_count(0, &mut out);
                assert_eq!(rc, 8);
                assert_ne!(out, 0, "woken and returned zero expirations");
                done.fetch_add(1, Ordering::SeqCst);
                out
            })
        })
        .collect();

    thread::sleep(Duration::from_millis(50));
    assert_eq!(
        done.load(Ordering::SeqCst),
        0,
        "a reader returned before any expiry"
    );

    t.fire();
    thread::sleep(Duration::from_millis(50));
    assert_eq!(
        done.load(Ordering::SeqCst),
        1,
        "one expiry satisfied more than one reader"
    );

    t.fire();
    let counts: Vec<u64> = readers.into_iter().map(|r| r.join().unwrap()).collect();
    assert_eq!(counts, vec![1, 1]);
}

#[test]
fn firing_while_a_reader_is_draining_is_not_lost() {
    // A fire that lands between one read taking the count and the next read
    // asking for it has to still be there. Not a race this can force, so it is
    // driven a thousand times and counted: every fire is either read or still
    // pending, and none is dropped.
    let t = make();
    let firing = Arc::clone(&t);
    const FIRES: usize = 1000;

    let firer = thread::spawn(move || {
        for _ in 0..FIRES {
            firing.fire();
        }
    });

    let mut seen = 0u64;
    while seen < FIRES as u64 {
        let (rc, count) = read(&t, true);
        if rc == 8 {
            seen += count;
        }
    }
    firer.join().unwrap();
    assert_eq!(seen, FIRES as u64, "expirations went missing");
}
