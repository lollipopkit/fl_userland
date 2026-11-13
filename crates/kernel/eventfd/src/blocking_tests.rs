//! The half a `GuestLock` mediates: blocking, waking, and who gets the value.
//!
//! The tests in `lib.rs` construct an [`EventFd`] and exercise its rules. These
//! go through `Descriptor::read`/`Descriptor::write` — the entry points the guest
//! actually reaches — so what they cover is the loop around `try_read`, the
//! wait, and the notify that ends it. None of that had a test, because
//! `GuestLock`'s primitive is C and does not link into a test binary; see
//! `util_guestlock_teststub`.
//!
//! Each test owns a private reverse edge, as the descriptor does in production.

use kernel_sighand as _;
use kernel_sigqueue as _;

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// A live descriptor with no poll watchers.
fn make(initval: u64, semaphore: bool) -> Box<Descriptor> {
    Descriptor::new(initval, semaphore, Arc::new(Watchers::default()))
}

/// A read as the descriptor callback reports it: the byte count and value, or
/// the error.
fn read(state: &Descriptor, nonblock: bool) -> (isize, u64) {
    let rc = match state.read(nonblock) {
        Ok(value) => return (8, value),
        Err(err) => err,
    };
    (rc, 0)
}

#[test]
fn a_nonblocking_read_of_an_empty_counter_is_eagain() {
    let ev = make(0, false);
    assert_eq!(read(&ev, true).0, EAGAIN);
}

#[test]
fn a_blocking_read_waits_for_a_write() {
    let ev = make(0, false);
    let ev = &*ev;
    let started = Instant::now();
    thread::scope(|s| {
        s.spawn(|| {
            thread::sleep(Duration::from_millis(80));
            assert_eq!(ev.write(false, 42), Ok(()));
        });
        let (rc, value) = read(ev, false);
        assert_eq!(rc, 8);
        assert_eq!(value, 42);
        assert!(
            started.elapsed() >= Duration::from_millis(70),
            "returned after {:?}, before the write",
            started.elapsed()
        );
    });
}

#[test]
fn a_blocking_write_waits_for_a_read() {
    // The counter's ceiling is u64::MAX - 1, so a write that would pass it
    // blocks rather than failing -- and is only unblocked by a read.
    let ev = make(u64::MAX - 1, false);
    let ev = &*ev;
    assert_eq!(ev.write(true, 1), Err(EAGAIN));

    let started = Instant::now();
    thread::scope(|s| {
        let reader = s.spawn(|| {
            thread::sleep(Duration::from_millis(80));
            ev.read(false)
        });
        assert_eq!(ev.write(false, 5), Ok(()));
        assert!(
            started.elapsed() >= Duration::from_millis(70),
            "the write returned after {:?}, before the read drained it",
            started.elapsed()
        );
        assert_eq!(reader.join().unwrap(), Ok(u64::MAX - 1));
    });
}

#[test]
fn u64_max_is_einval_and_not_a_wait() {
    // No amount of waiting makes u64::MAX a legal value, so it must not block.
    // A loop that treated "try_write said no" as "wait" would hang here.
    let ev = make(0, false);
    let started = Instant::now();
    assert_eq!(ev.write(false, u64::MAX), Err(EINVAL));
    assert!(started.elapsed() < Duration::from_millis(50));
}

#[test]
fn one_write_satisfies_exactly_one_of_two_blocked_readers() {
    // The notify is a broadcast, so both readers wake. Only one can have the
    // value; the other has to find the counter empty and go back to sleep
    // rather than returning zero, which is what a `read` that took the wake as
    // the answer would do.
    let ev = make(0, false);
    let ev = &*ev;
    let got = AtomicUsize::new(0);
    thread::scope(|s| {
        let readers: Vec<_> = (0..2)
            .map(|_| {
                s.spawn(|| {
                    let value = ev.read(false).unwrap();
                    assert_ne!(value, 0, "woken and returned an empty counter");
                    got.fetch_add(1, Ordering::SeqCst);
                    value
                })
            })
            .collect();

        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            got.load(Ordering::SeqCst),
            0,
            "a reader returned before any write"
        );

        // One write, then a second so both threads can finish and be joined.
        assert_eq!(ev.write(false, 7), Ok(()));
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            got.load(Ordering::SeqCst),
            1,
            "one write satisfied more than one reader"
        );

        assert_eq!(ev.write(false, 9), Ok(()));
        let mut values: Vec<u64> = readers.into_iter().map(|r| r.join().unwrap()).collect();
        values.sort();
        assert_eq!(values, vec![7, 9]);
    });
}

#[test]
fn a_semaphore_read_takes_one_and_leaves_the_rest_readable() {
    let ev = make(3, true);
    for remaining in [2, 1, 0] {
        let (rc, value) = read(&ev, true);
        assert_eq!(rc, 8);
        assert_eq!(value, 1, "semaphore mode returns 1, not the counter");
        // Readable exactly while something is left, which is the part that
        // distinguishes "took one" from "took the lot and returned 1".
        let readable = ev.poll_types() & POLL_READ != 0;
        assert_eq!(
            readable,
            remaining > 0,
            "{remaining} left, readable={readable}"
        );
    }
    // Drained: the fourth is EAGAIN rather than a fourth 1.
    assert_eq!(read(&ev, true).0, EAGAIN);
}

#[test]
fn a_blocking_semaphore_read_wakes_one_per_write() {
    let ev = make(0, true);
    thread::scope(|s| {
        let reader = s.spawn(|| ev.read(false));
        thread::sleep(Duration::from_millis(40));
        assert_eq!(ev.write(false, 2), Ok(()));
        assert_eq!(reader.join().unwrap(), Ok(1));
    });
    // One of the two is left.
    assert_eq!(read(&ev, true), (8, 1));
    assert_eq!(read(&ev, true).0, EAGAIN);
}

#[test]
fn poll_reports_what_a_read_and_a_write_would_do() {
    let empty = make(0, false);
    let poll = empty.poll_types();
    assert_eq!(poll & POLL_READ, 0, "an empty counter is not readable");
    assert_ne!(poll & POLL_WRITE, 0, "an empty counter is writable");

    let full = make(u64::MAX - 1, false);
    let poll = full.poll_types();
    assert_ne!(poll & POLL_READ, 0, "a full counter is readable");
    assert_eq!(poll & POLL_WRITE, 0, "a full counter is not writable");

}
