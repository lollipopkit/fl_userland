//! The primitive: a wait ends when notified, a timeout is a timeout and not a
//! hang, and the object survives being freed with nobody waiting.
//!
//! `tests/unit/guestlock_test.c` until 2026-09-08, where it lived because "the
//! C half links against the whole kernel". There is no C half.
//!
//! An **integration** test because the crate is `no_std`, while these tests
//! spawn a thread and sleep. Keeping the tests outside the library also keeps
//! the production target free of their thread and timing helpers.

use std::sync::Arc;
use std::time::Duration;
use util_guestlock::Primitive;

/// The two errnos the wait can answer.
use guest_errno::c_int_::{EINVAL, ETIMEDOUT};

// ------------------------------------------------------- the primitive
//
// `tests/unit/guestlock_test.c` until 2026-09-08, where it lived because
// "the C half links against the whole kernel, so these run only where that
// is linked". There is no C half: the typed `Primitive` API is used directly,
// and `wait_for` is a normal dependency of this crate.

use std::sync::atomic::{AtomicBool, Ordering};

static READY: AtomicBool = AtomicBool::new(false);

/// A wait ends when another thread notifies.
#[test]
fn a_wait_ends_when_another_thread_notifies() {
    let l = Arc::new(Primitive::new(2));
    READY.store(false, Ordering::SeqCst);

    let notifier_lock = Arc::clone(&l);
    let notifier = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        let held = notifier_lock.lock();
        READY.store(true, Ordering::SeqCst);
        held.notify(0);
    });

    let mut held = l.lock();
    // Bounded, and with a timeout on each pass. A wait that does not
    // release the lock spins here *while holding it*, so the notifier can
    // never get in -- and an unbounded loop would hang the whole suite
    // instead of failing one check, which is what happened when this was
    // written the obvious way and the wait was then deliberately broken.
    let mut rounds = 0;
    while !READY.load(Ordering::SeqCst) && rounds < 100 {
        rounds += 1;
        held.wait(0, 50 * 1000 * 1000, false);
    }
    assert!(
        READY.load(Ordering::SeqCst),
        "notified after {rounds} rounds"
    );
    drop(held);
    notifier.join().unwrap();
}

/// A timeout is a timeout and not a hang.
#[test]
fn a_wait_with_a_timeout_gives_up() {
    let l = Primitive::new(1);
    let mut held = l.lock();
    // Nobody will notify. 30ms, so a slow machine does not make this flaky
    // and a broken timeout does not make it hang.
    assert_eq!(held.wait(0, 30 * 1000 * 1000, false), ETIMEDOUT);
}

/// A condition variable this object does not have is a caller error, not
/// an index into whatever follows the array.
#[test]
fn a_condition_that_does_not_exist_is_einval() {
    let l = Primitive::new(1);
    let mut held = l.lock();
    assert_eq!(held.wait(1, 0, false), EINVAL);
    assert_eq!(held.wait(1000, 0, false), EINVAL);
    drop(held);
    // And notifying one is a no-op rather than a write past the end.
    l.notify(1000);
}

#[test]
fn trylock_answers_who_has_it() {
    let l = Primitive::new(1);
    let held = l.try_lock();
    assert!(held.is_some());
    assert!(l.try_lock().is_none(), "and nobody else while it is held");
}

#[test]
fn a_null_lock_is_freed_without_incident() {
    // A typed API has no null handle to release.
}
