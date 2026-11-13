//! Tests for descriptor table ownership, locking, and close semantics.

use super::*;
use std::sync::{Arc, Condvar};
use std::sync::atomic::AtomicI64;

static LOCK: Mutex<()> = Mutex::new(());
static RELEASES: AtomicI64 = AtomicI64::new(0);

#[derive(Default)]
struct CloseRangeSync {
    old_detached: bool,
    allow_old_release: bool,
    new_releases: usize,
}

static CLOSE_RANGE_SYNC: (Mutex<CloseRangeSync>, Condvar) = (
    Mutex::new(CloseRangeSync {
        old_detached: false,
        allow_old_release: false,
        new_releases: 0,
    }),
    Condvar::new(),
);

/// The finalizer for an ordinary fixture descriptor: it counts.
///
/// **`RETAINS` is gone with the `retain` callback.** A retain is `Owned::clone`
/// now and reaches no callback, so counting them would need a second control
/// block wrapping the first -- and what these tests are about is that the
/// table gives back what it takes, which the release count answers on its own.
fn release(_: usize) -> c_int {
    RELEASES.fetch_add(1, Ordering::Relaxed);
    0
}

fn blocking_release(fd: usize) -> c_int {
    let (sync_state, changed) = &CLOSE_RANGE_SYNC;
    let mut state = sync_state.lock().unwrap_or_else(|e| e.into_inner());
    if fd == fake(1) {
        state.old_detached = true;
        changed.notify_all();
        state = changed
            .wait_while(state, |state| !state.allow_old_release)
            .unwrap_or_else(|e| e.into_inner());
        drop(state);
    } else if fd == fake(2) {
        state.new_releases += 1;
        changed.notify_all();
    }
    0
}

/// A fixture description: a tag, and what to run when its last reference
/// goes -- the finalizer, as `Drop for fd` runs the descriptor layer's.
struct Fake {
    n: usize,
    release: fn(usize) -> c_int,
}

/// The table's entry type here: a counted reference to a fixture, as the
/// product's is an `Arc<fd>`.
#[derive(Clone)]
struct Fd(std::sync::Arc<Fake>);

impl Fd {
    fn payload(&self) -> usize {
        self.0.n
    }
}

impl crate::Descriptor for Fd {
    fn close(self) -> c_int {
        // The last reference reports the finalizer's answer, which is what
        // `close(2)` hands the guest.
        match std::sync::Arc::try_unwrap(self.0) {
            Ok(fake) => {
                // Not dropped as well: that would release it twice.
                let fake = std::mem::ManuallyDrop::new(fake);
                (fake.release)(fake.n)
            }
            Err(_) => 0,
        }
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        // Reached only when nothing called `close` on the last reference --
        // a table dropped whole -- since `close` takes the value apart.
        (self.release)(self.n);
    }
}

/// One field since 2026-09-12; an entry owns its reference.
fn ops() -> Ops<Fd> {
    Ops { remove_locks: None }
}

/// A real reference to a fake descriptor, whose finalizer is `f`.
///
/// The payload address is never dereferenced -- the finalizers here ignore it
/// or compare it -- but the control block is real, because the table holds a
/// handle now rather than a word.
fn owned(n: usize, f: fn(usize) -> c_int) -> Fd {
    Fd(std::sync::Arc::new(Fake { n: fake(n), release: f }))
}

fn fake(n: usize) -> usize {
    n * 8 + 8
}

/// **These three asserted a `RETAINS` counter until 2026-09-12**, which was the
/// `retain` callback firing. A retain is `Owned::clone` now and reaches no
/// callback, so what they assert instead is the **finalizer**: how many
/// references exist is only interesting through the one question that has a
/// consequence, which is when the last one goes. That is a stronger assertion
/// and it is what a leak would break.
#[test]
fn lookup_retain_and_take_transfer_owned_references() {
    let _serial = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    RELEASES.store(0, Ordering::Relaxed);
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    assert!(matches!(
        table.install_lowest(owned(1, release), 0, false, 32),
        Ok(0)
    ));
    let looked = table.lookup_retain(0).expect("slot 0 is occupied");
    assert_eq!(looked.payload(), fake(1));
    let taken = table.take(0).expect("take answers what the slot held");
    assert_eq!(taken.payload(), fake(1));
    drop(table);
    assert_eq!(
        RELEASES.load(Ordering::Relaxed),
        0,
        "the lookup and the take each hold one, so the table dropping frees nothing"
    );
    drop(looked);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 0, "one left");
    drop(taken);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 1, "and the last one finalizes, once");
}

#[test]
fn copy_retains_every_occupied_slot_and_is_independent() {
    let _serial = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    RELEASES.store(0, Ordering::Relaxed);
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    let _ = table.install_lowest(owned(1, release), 0, true, 32);
    let _ = table.install_lowest(owned(2, release), 0, false, 32);
    let copy = table.copy().expect("the copy allocates");
    let taken = copy.take(0).expect("the copy has slot 0");
    assert_eq!(taken.payload(), fake(1), "and it is the same description");
    drop(table);
    assert_eq!(
        RELEASES.load(Ordering::Relaxed),
        0,
        "the copy took one per slot, so the original dropping frees nothing"
    );
    drop(taken);
    drop(copy);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 2, "both, once each");
}

#[test]
fn replace_is_atomic_storage_and_returns_the_displaced_owner() {
    let _serial = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    RELEASES.store(0, Ordering::Relaxed);
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    let _ = table.install_lowest(owned(1, release), 4, false, 32);
    let displaced = match table.replace(owned(2, release), 4, true, 32) {
        Ok(displaced) => displaced.expect("slot 4 was occupied"),
        Err(_) => panic!("slot 4 is under the limit"),
    };
    assert_eq!(displaced.payload(), fake(1));
    assert_eq!(
        RELEASES.load(Ordering::Relaxed),
        0,
        "the displaced reference is handed out, not released under the mutex"
    );
    assert_eq!(table.cloexec(4), Some(true));
    drop(displaced);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 1);
    drop(table);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 2);
}

#[test]
fn final_table_release_is_linear_in_the_number_of_slots() {
    let _serial = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    RELEASES.store(0, Ordering::Relaxed);
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    for fd in 0..4096 {
        let at = table.install_lowest(owned(fd + 1, release), fd as c_int, false, 4096);
        assert!(matches!(at, Ok(n) if n == fd as c_int));
    }
    drop(table);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 4096);
}

#[test]
fn last_table_release_runs_callbacks_after_unlock() {
    let _serial = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    RELEASES.store(0, Ordering::Relaxed);
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    // Asserted rather than discarded: if the install refused, `RELEASES` stays
    // at 0 and the count below reads as "the callback did not run", which is
    // the thing this test is about. Same shape as the test above.
    let at = table.install_lowest(owned(1, release), 0, false, 32);
    assert!(matches!(at, Ok(0)), "installed at the lowest free slot");
    drop(table);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 1);
}

#[test]
fn replace_range_publishes_all_slots_and_returns_displaced_owners() {
    let _serial = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    RELEASES.store(0, Ordering::Relaxed);
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    let _ = table.install_lowest(owned(1, release), 0, false, 32);
    let _ = table.install_lowest(owned(2, release), 0, false, 32);
    let mut displaced = Vec::new();
    assert!(
        table
            .replace_range(owned(9, release), 0, 3, true, 32, &mut displaced)
            .is_ok()
    );
    let payloads: Vec<_> = displaced.iter().map(|d| d.as_ref().map(|o| o.payload())).collect();
    assert_eq!(payloads, vec![Some(fake(1)), Some(fake(2)), None]);
    assert_eq!(
        RELEASES.load(Ordering::Relaxed),
        0,
        "the displaced references are handed out, not released under the mutex"
    );
    for number in 0..3 {
        let held = table.lookup_retain(number).expect("published");
        assert_eq!(held.payload(), fake(9), "every slot names the new description");
        assert_eq!(table.cloexec(number), Some(true));
    }
    drop(displaced);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 2, "the two it replaced");
    drop(table);
    // Three slots held one reference each and the caller's own went with the
    // call, so the new description finalizes exactly once.
    assert_eq!(RELEASES.load(Ordering::Relaxed), 3);
}

/// The open numbers, ascending, and nothing else.
///
/// This was `a_short_snapshot_still_initializes_its_capacity`, about the C
/// shape it replaced: a caller-sized buffer that could be shorter than the
/// table, and the count answered anyway so the caller could retry.
#[test]
fn numbers_lists_the_open_descriptors_in_order() {
    let _serial = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    assert!(matches!(table.install_lowest(owned(1, release), 9, false, 32), Ok(9)));
    assert!(matches!(table.install_lowest(owned(2, release), 4, false, 32), Ok(4)));
    assert_eq!(table.numbers().expect("two numbers fit"), vec![4, 9]);
    drop(table);
}

#[test]
fn close_range_does_not_revisit_a_reused_number() {
    let _serial = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let table = Table::new(
        0,
        Ops { remove_locks: None },
    )
    .expect("a table with no slots allocates");
    // **`blocking_release` is the finalizer now, not a table callback.** It was
    // `Ops { release: Some(blocking_release) }` until 2026-09-12, and that field
    // is gone -- an entry owns its reference and releases it itself. Passing the
    // blocker as the *descriptor's* finalizer is the same thing one layer down,
    // and it is what makes this test still about what it says: that
    // `close_range` detaches a slot before the release, so a number freed by one
    // thread can be reused by another while the old description is still being
    // torn down.
    //
    // Getting this wrong is silent and slow: with the finalizer left as
    // `release`, nothing ever sets `old_detached` and the wait below never
    // returns. The suite hung rather than failing, which is how it was found.
    assert!(matches!(
        table.install_lowest(owned(1, blocking_release), 0, false, 32),
        Ok(0)
    ));
    {
        let (sync_state, _) = &CLOSE_RANGE_SYNC;
        *sync_state.lock().unwrap_or_else(|e| e.into_inner()) = CloseRangeSync::default();
    }

    // A share of its own, as a second thread of the process would have.
    let shared = Arc::clone(&table);
    let closer = std::thread::spawn(move || shared.close_range(0, 0, false));

    let (sync_state, changed) = &CLOSE_RANGE_SYNC;
    let mut state = sync_state.lock().unwrap_or_else(|e| e.into_inner());
    state = changed
        .wait_while(state, |state| !state.old_detached)
        .unwrap_or_else(|e| e.into_inner());
    drop(state);

    assert!(matches!(
        table.install_lowest(owned(2, blocking_release), 0, false, 32),
        Ok(0)
    ));
    let mut state = sync_state.lock().unwrap_or_else(|e| e.into_inner());
    state.allow_old_release = true;
    changed.notify_all();
    drop(state);

    assert_eq!(closer.join().unwrap(), 0);
    let held = table.lookup_retain(0).expect("slot 0 is the new one");
    assert_eq!(held.payload(), fake(2));
    let state = sync_state.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(state.new_releases, 0);
    drop(state);
    drop(held);
    let _ = table.take(0);
    drop(table);
}
