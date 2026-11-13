//! The one-shot a `vfork` parent waits on.
//!
//! `vfork` suspends the parent until the child either execs or exits, because
//! until then the two share an address space and a stack. The kernel side of
//! that is a single edge: one waiter, one waker, one event, delivered once.
//!
//! # What this replaces
//!
//! `struct vfork_info` lived **on the parent's own stack frame**, and the child
//! held a raw pointer to it through `task->vfork`:
//!
//! ```c
//! // this structure is allocated on the stack of the parent's clone() call
//! struct vfork_info {
//!     bool done;
//!     cond_t cond;
//!     lock_t lock;
//! } *vfork;
//! ```
//!
//! Nothing enforced that the frame outlived the pointer. What was supposed to
//! was the parent clearing `task->vfork` after it woke — which meant reaching
//! into a `struct task` the child may already have freed, and that was a
//! use-after-free of its own (see
//! `docs/changelog/2026-08-29-a-vfork-parent-wrote-into-its-freed-childs-task.md`).
//! Fixing it moved the clear to the child, which is correct but still leaves a
//! design where two threads share a stack frame and a comment is the proof.
//!
//! An `Arc` on both sides has no such proof obligation. The parent holds one
//! handle and the child holds another; whichever goes last frees the state, and
//! neither can observe the other's frame at all. The child does not have to
//! clear anything for correctness, only to keep from notifying twice — and
//! notifying twice is harmless here, because [`Handoff::notify`] is idempotent.
//!
//! # Why it is not a `std::sync::Condvar`
//!
//! Because a guest thread asleep on one is invisible to signal delivery and
//! could not be killed. [`guestlock::GuestLock`] is the primitive that can be
//! woken; see that module for why the mutex itself stays C.

use core::time::Duration;
use std::sync::Arc;
use util_guestlock::{GuestLock, Woke};

/// The single condition variable a handoff needs.
const DONE: u32 = 0;

/// How long a wait may sit before it is rechecked.
///
/// The wait is not interruptible — a vfork parent that took `EINTR` would
/// return to a guest whose address space is still shared with a running child,
/// which is the one thing vfork exists to prevent. But an uninterruptible sleep
/// with no timeout is also how a hang becomes indistinguishable from a
/// deadlock, so it wakes periodically and rechecks.
///
/// It is a recheck, not a deadline: nothing gives up when it expires.
const RECHECK: Duration = Duration::from_millis(200);

/// One `vfork` edge. Shared by exactly two tasks.
pub struct Handoff {
    /// Whether the child has reached exec or exit. Never goes back to false: a
    /// vfork happens once, and a parent that has already resumed must not be
    /// made to wait again by anything.
    done: GuestLock<bool>,
}

impl Handoff {
    pub fn new() -> Arc<Handoff> {
        Arc::new(Handoff {
            done: GuestLock::new(false, 1),
        })
    }

    /// The child has released the address space. Wakes the parent.
    ///
    /// Idempotent, and deliberately so. It is called from `execve`, from
    /// `do_exit` and from the native-offload handoff, and a child reaches at
    /// least two of those in a normal life. The old code needed the pointer
    /// cleared before the second call because the second call would have
    /// written through a dangling one; here the second call sets a `true` that
    /// is already `true`.
    pub fn notify(&self) {
        let mut done = self.done.lock();
        *done = true;
        drop(done);
        // After the guard, not under it: notify does not need the lock, and a
        // waiter woken while the waker still holds it goes straight back to
        // sleep on the mutex.
        self.done.notify(DONE);
    }

    /// Block until [`notify`](Self::notify) has been called, then return.
    ///
    /// Returns immediately if it already has, which is the common case: a child
    /// that exits at once is done before the parent reaches this at all.
    pub fn wait(&self) {
        let mut done = self.done.lock();
        while !*done {
            // Signals ignored: see RECHECK. The return says why the sleep
            // ended and there is nothing to do differently for any of them --
            // the loop condition is the only thing that decides.
            let _: Woke = done.wait_ignoring_signals(DONE, Some(RECHECK));
        }
    }

    /// Whether the child has reported in. For tests and for a caller that wants
    /// to know without blocking.
    pub fn is_done(&self) -> bool {
        *self.done.lock()
    }
}

// `abi` -- `vfork_handoff_new`, `_share`, `_release`, `_notify` and `_wait`
// over an `Arc::into_raw` handle -- went on 2026-09-30: `struct task` holds an
// `Option<Arc<Handoff>>` and the parent keeps its own, so the counts are the
// `Arc`'s.

#[cfg(test)]
mod tests;
