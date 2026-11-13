//! Per-syscall descriptor reference tracking.
//!
//! The references `f_get` takes during a syscall, released in one place when
//! it returns. Deduplicated, so a syscall looking one descriptor up repeatedly
//! cannot grow the set without bound.
//!
//! **A thread-local since 2026-10-16**, where it was `struct task`'s
//! `syscall_refs`: an `AtomicPtr` to a `Box` that only this thread ever stored
//! a set into, that the group-exit valve exchanged into the thread's cleanup
//! record, and that the cleanup then drained -- on this same thread, in its
//! `pthread_exit` handler. Every party was this host thread, so the set is its
//! state. The field, the exchange, the `Box::into_raw`/`from_raw` pair and the
//! null re-check that once dereferenced the valve's null are gone, and the
//! thread-local's destructor drains whatever a thread leaves behind.

use super::*;
use std::cell::RefCell;

/// Each entry is the reference itself, keyed by the description's address:
/// dropping it is releasing it. It was the bare pointer, with `fd_retain` on
/// the way in and `fd_close` on the way out, until 2026-10-16.
type Set = kernel_syscallrefs::Refs<*mut ffi::fd, Owned>;

thread_local! {
    /// `None` until the first `f_get`, because `Refs::new` allocates and a
    /// `const` thread-local cannot. Its destructor releases whatever a thread
    /// leaves behind.
    static HELD: RefCell<Option<Set>> = const { RefCell::new(None) };
}

/// Keep `held` for the rest of the calling thread's syscall, unless this
/// syscall already holds a reference to the same description -- in which case
/// `held` is dropped here and the one already kept stands.
pub(crate) fn syscall_ref_hold(held: Owned) {
    let key: *mut ffi::fd = held.as_ptr();
    HELD.with_borrow_mut(|h| h.get_or_insert_with(Set::new).hold_with(key, || held));
}

/// Give back everything the calling thread's syscall took.
///
/// The set is emptied and the borrow released **before** anything is
/// released, so an entry is never visible while it is being closed and a close
/// that reached back into `f_get` would find an empty set rather than a held
/// `RefCell`. `try_with`, because `crates/kernel/taskcalls`' exit cleanup is
/// itself a thread-local destructor and may run after this one, which has
/// released them already.
pub fn syscall_refs_drain() {
    let taken = HELD
        .try_with(|h| h.borrow_mut().as_mut().filter(|r| !r.is_empty()).map(Set::take_all))
        .ok()
        .flatten();
    drop(taken);
}
