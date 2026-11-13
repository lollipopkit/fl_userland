//! What a vfork handoff has to get right, and one thing the C could not.

// Names the stub so the linker keeps it: GuestLock's primitive is C, and a
// test binary has none. See that crate for why it is a dev-dependency.
use kernel_sighand as _;
use kernel_sigqueue as _;

use crate::Handoff;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn a_fresh_handoff_is_not_done() {
    let h = Handoff::new();
    assert!(!h.is_done());
}

#[test]
fn wait_returns_at_once_when_the_child_was_first() {
    // The common case, and the one the old code got wrong: a child that exits
    // immediately sets `done` before the parent reaches the wait at all, so the
    // parent never blocks -- and went straight on to dereference a task the
    // child had already freed.
    let h = Handoff::new();
    h.notify();
    let started = Instant::now();
    h.wait();
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "waited {:?} for something already done",
        started.elapsed()
    );
}

#[test]
fn wait_blocks_until_notified() {
    let h = Handoff::new();
    let child = Arc::clone(&h);
    let started = Instant::now();
    let t = thread::spawn(move || {
        thread::sleep(Duration::from_millis(80));
        child.notify();
    });
    h.wait();
    assert!(h.is_done());
    assert!(
        started.elapsed() >= Duration::from_millis(70),
        "returned after {:?}, before the notify",
        started.elapsed()
    );
    t.join().unwrap();
}

#[test]
fn notify_is_idempotent() {
    // execve notifies, and so does the do_exit that follows it. Under the C
    // this was safe only because the parent had cleared the pointer in between,
    // and the pointer was into a stack frame that by then may not exist.
    let h = Handoff::new();
    h.notify();
    h.notify();
    h.notify();
    assert!(h.is_done());
    h.wait();
}

#[test]
fn the_state_outlives_whichever_side_drops_first() {
    // The whole reason this is an Arc. Under the C the state was the parent's
    // stack frame, so "the parent returns first" was a use-after-free rather
    // than a case.
    let parent = Handoff::new();
    let child = Arc::clone(&parent);
    drop(parent);
    child.notify();
    assert!(child.is_done());
}

#[test]
fn the_child_may_drop_before_the_parent_waits() {
    let parent = Handoff::new();
    let child = Arc::clone(&parent);
    child.notify();
    drop(child);
    parent.wait();
    assert!(parent.is_done());
}

#[test]
fn many_waiters_all_wake() {
    // Not a shape vfork produces -- there is one parent -- but the notify has
    // to be a broadcast rather than a signal, or a spurious wake could leave
    // the real waiter asleep for ever.
    let h = Handoff::new();
    let waiters: Vec<_> = (0..8)
        .map(|_| {
            let h = Arc::clone(&h);
            thread::spawn(move || {
                h.wait();
                h.is_done()
            })
        })
        .collect();
    thread::sleep(Duration::from_millis(30));
    h.notify();
    for w in waiters {
        assert!(w.join().unwrap());
    }
}

#[test]
fn a_wait_after_the_notifier_is_gone_still_returns() {
    let parent = Handoff::new();
    let child = Arc::clone(&parent);
    let t = thread::spawn(move || {
        child.notify();
        // The child's handle goes here, while the parent is still inside wait.
    });
    parent.wait();
    t.join().unwrap();
    assert!(parent.is_done());
}
