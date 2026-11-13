//! The signal state a thread group shares: the disposition table, the lock over
//! it, and the lifetime.
//!
//! `struct sighand` was three fields — `atomic_uint refcount`, a `struct sigdisp *`
//! that was already Rust, and a `lock_t`. What made it worth moving is not its
//! size but what the lock covers: **the dispositions and every thread's queue at
//! once**. That is Linux's rule too (`sighand_struct.siglock` guards
//! `task_struct.pending`), and in C it was written down only in a comment on
//! `struct task`:
//!
//! ```text
//! // Which signals are blocked, which have arrived, and what arrived: the
//! // four masks and the queue, in crates/kernel/sigqueue. Opaque here, and
//! // locked by sighand->lock like the dispositions beside it.
//! ```
//!
//! Nothing checked it. Twelve C files took `sighand->lock` directly and every
//! one of them was trusted to have read that comment. Here the queue operations
//! that need the lock take a [`SigHandGuard`], so asking for one is how you get
//! the other, and a caller that has not taken the lock cannot reach the state.
//!
//! ## Why the operations are named rather than the lock
//!
//! Most of those twelve sites were the same three lines: take the lock, ask one
//! question, drop it. Four of them were *identical* —
//!
//! ```c
//! lock(&current->sighand->lock);
//! bool pending = sigqueue_interrupts_a_wait(current->signals);
//! unlock(&current->sighand->lock);
//! ```
//!
//! — in `kernel/futex.c`, `fs/sock.c`, `util/sync.c` and, with a different
//! predicate, `kernel/task.c`. They are one function now. What is left holding
//! the lock across more than one operation is `kernel/signal.c`, which is the
//! next thing to move; the lock identity check is exposed as [`SigHand::owns_lock`].

use std::ffi::c_int;
use std::ptr::NonNull;
use std::sync::Arc;

use kernel_sigdisp::{Disposition, Table};
use kernel_sigqueue::{Pending, Signals};
use util_guestlock::{GuestGuard, GuestLock};

pub use util_guestlock::Woke;

// `abi.rs` was here until 2026-10-17. It had been six entry points that kept
// the strong count by hand while `struct task` held a `*mut SigHand`; the field
// became an `Arc` and they went one by one, and the last, `from_raw`, was
// `&*p` under a name.

#[cfg(test)]
mod tests;

/// The state the lock covers. The per-task queues are not here — there is one
/// `SigHand` per thread group and one queue per thread — but they are covered by
/// the same lock, which is why every entry point that touches one takes a
/// [`SigHandGuard`].
pub struct Dispositions {
    pub table: Table,
}

/// One thread group's shared signal state.
///
/// Cloned with [`Arc`], which is what `CLONE_SIGHAND` asks for. The C had
/// `atomic_uint refcount` with `task->sighand->refcount++` at the sharing site
/// in `kernel/fork.c` — a **non-atomic** increment of an atomic field, which is
/// two threads forking at once away from a lost count.
pub struct SigHand {
    state: GuestLock<Dispositions>,
}

/// Proof that the caller holds the lock, and the way to reach what it covers.
pub struct SigHandGuard<'a> {
    guard: GuestGuard<'a, Dispositions>,
}

impl SigHandGuard<'_> {
    pub fn table(&self) -> &Table {
        &self.guard.table
    }

    pub fn table_mut(&mut self) -> &mut Table {
        &mut self.guard.table
    }

    /// Park until a signal arrives, this thread is woken, or `timeout` runs
    /// out. The lock is released while parked and held again on return, so the
    /// queue is safe to re-read — and must be: [`Woke::Notified`] is also what
    /// a spurious wakeup looks like.
    ///
    /// [`Woke::Interrupted`] is a signal the thread should act on, which is not
    /// the same as one it was waiting *for*: `sigtimedwait` blocks the signal
    /// it wants and names it in the queue's `waiting` set, which wakes the
    /// thread without interrupting it. See `Signals::interrupts_a_wait`.
    ///
    /// A `pause` that no signal ever reaches waits for ever, which is what
    /// `pause(2)` is.
    pub fn wait(&mut self, timeout: Option<core::time::Duration>) -> Woke {
        self.guard.wait(SIGNAL_ARRIVED, timeout)
    }
}

/// [`SigHandGuard`] with one task's queue: the lock, and the proof that the
/// queue is the one it covers.
///
/// # Why the queue is reached through the guard
///
/// `SigHandGuard` had `unsafe fn queue(&self, q)` and `queue_mut(&mut self, q)`,
/// each answering a reference **with a lifetime the caller chose** -- nothing
/// tied it to the guard. Fifty-seven call sites wrote `unsafe` for the same
/// obligation, and nothing stopped a caller holding the reference across
/// [`SigHandGuard::wait`], which releases the lock: exactly when a sender on
/// another thread writes the queue. `crates/kernel/signalcalls` went further
/// and took the queue as a `&mut Signals` *parameter* across the wait, which
/// is a `noalias` claim over memory other threads were writing.
///
/// Here the obligation is stated once, at [`SigHand::lock_queue`], and every
/// reference borrows the guard -- so holding one across `wait(&mut self)` does
/// not compile.
pub struct QueueGuard<'a> {
    guard: SigHandGuard<'a>,
    queue: NonNull<Signals>,
    shared: NonNull<Pending>,
}

impl QueueGuard<'_> {
    pub fn queue(&self) -> &Signals {
        // SAFETY: `lock_queue`'s contract -- live, and covered by the lock this
        // guard holds.
        unsafe { self.queue.as_ref() }
    }

    pub fn queue_mut(&mut self) -> &mut Signals {
        // SAFETY: as above; `&mut self` is the exclusivity, since every access
        // to this queue is under this lock.
        unsafe { self.queue.as_mut() }
    }

    /// The thread's process's shared pending set, which the same lock covers.
    pub fn shared(&self) -> &Pending {
        // SAFETY: `lock_queue`'s contract, as for the queue.
        unsafe { self.shared.as_ref() }
    }

    /// The thread's queue and its process's set at once, for the operations
    /// that move a signal out of either.
    pub fn both_mut(&mut self) -> (&mut Signals, &mut Pending) {
        // SAFETY: as above. Two distinct objects -- one in the task, one in
        // its group -- so the two borrows do not overlap.
        unsafe { (self.queue.as_mut(), self.shared.as_mut()) }
    }

    pub fn table(&self) -> &Table {
        self.guard.table()
    }

    pub fn table_mut(&mut self) -> &mut Table {
        self.guard.table_mut()
    }

    /// [`SigHandGuard::wait`]. No reference from this guard can be alive
    /// across it.
    pub fn wait(&mut self, timeout: Option<core::time::Duration>) -> Woke {
        self.guard.wait(timeout)
    }
}

/// A thread group's signal state and one of its tasks' queues, not locked:
/// what a signal syscall is handed, and [`Queue::lock`] is how it reaches the
/// queue.
///
/// `crates/kernel/signalcalls` took these as `sh: &SigHand, q: &mut Signals`,
/// and the `&mut` lived for the whole call -- across the lock being released
/// in a wait, while senders on other threads wrote the queue. The obligation
/// that a queue belongs to this group and outlives the call is made once, at
/// [`Queue::new`].
#[derive(Clone, Copy)]
pub struct Queue<'a> {
    hand: &'a SigHand,
    queue: NonNull<Signals>,
    shared: NonNull<Pending>,
}

impl<'a> Queue<'a> {
    /// # Safety
    ///
    /// As [`SigHand::lock_queue`], for `'a`: `q` is a live `Signals` of a task
    /// whose table is `hand`, `shared` is its thread group's shared set, and
    /// both stay live for as long as the result is used.
    pub unsafe fn new(hand: &'a SigHand, q: *mut Signals, shared: *mut Pending) -> Queue<'a> {
        Queue {
            hand,
            queue: NonNull::new(q).expect("a live queue is not null"),
            shared: NonNull::new(shared).expect("a live group's set is not null"),
        }
    }

    /// A handle, a queue and a shared set from their raw fields, or `None`
    /// when any is null -- a task on its way out, whose `sighand` the
    /// group-exit valve has taken, or one with no group. Every operation used
    /// to test for that itself and answer its own default; the caller says
    /// what `None` means now.
    ///
    /// # Safety
    ///
    /// Each is null or live for `'a`: `p` a handle the caller holds a
    /// reference to, `q` a queue of a task whose table it is, and `shared`
    /// that task's group's set.
    pub unsafe fn from_raw(p: *mut SigHand, q: *mut Signals, shared: *mut Pending) -> Option<Queue<'a>> {
        if p.is_null() || q.is_null() || shared.is_null() {
            return None;
        }
        // SAFETY: the caller's contract.
        Some(unsafe { Queue::new(&*p, q, shared) })
    }

    pub fn hand(&self) -> &'a SigHand {
        self.hand
    }

    pub fn lock(&self) -> QueueGuard<'a> {
        // SAFETY: `Queue::new`'s contract.
        unsafe { self.hand.lock_queue(self.queue.as_ptr(), self.shared.as_ptr()) }
    }
}

impl SigHand {
    /// One condition variable: the queue a thread parks on while waiting for a
    /// signal it has named, which `signalfd` and `sigtimedwait` both use. It
    /// belongs to the lock because that is what a condition variable is.
    pub fn new() -> Arc<SigHand> {
        Arc::new(SigHand {
            state: GuestLock::new(
                Dispositions {
                    table: Table::new(),
                },
                1,
            ),
        })
    }

    pub fn lock(&self) -> SigHandGuard<'_> {
        SigHandGuard {
            guard: self.state.lock(),
        }
    }

    /// The lock, and one task's queue and its process's shared set under it.
    ///
    /// # Safety
    ///
    /// `q` is a live `Signals` of a task whose table this is -- which is what
    /// makes this lock the one that covers it -- `shared` is that task's
    /// thread group's set, and both stay live while the guard does.
    pub unsafe fn lock_queue(&self, q: *mut Signals, shared: *mut Pending) -> QueueGuard<'_> {
        QueueGuard {
            guard: self.lock(),
            queue: NonNull::new(q).expect("a live queue is not null"),
            shared: NonNull::new(shared).expect("a live group's set is not null"),
        }
    }

    /// Whether `lock` is this signal hand's mutex.
    ///
    /// The caller uses this only to avoid recursively taking a lock while
    /// checking whether a queued signal interrupts a wait.
    pub fn owns_lock(&self, lock: &util_synctypes::lock_t) -> bool {
        self.state.owns_lock(lock)
    }

    /// `rt_sigaction`'s read-then-write, under one acquisition.
    ///
    /// Two would let another thread install something in between, and the value
    /// reported as "what it was" would be one that never was.
    ///
    /// 0, or `_EINVAL` for a signal that may not be changed — which is not the
    /// same set as the signals that may not be *read*: `SIGKILL` may be asked
    /// about, and a shell enumerating a child's dispositions depends on it.
    pub fn get_set(
        &self,
        sig: c_int,
        old: Option<&mut Disposition>,
        new: Option<&Disposition>,
    ) -> c_int {
        if !Table::may_change(sig, new.is_some()) {
            return -22; // _EINVAL
        }
        let mut guard = self.lock();
        if let Some(old) = old
            && let Some(d) = guard.table().get(sig)
        {
            *old = d;
        }
        if let Some(new) = new {
            guard.table_mut().set(sig, *new);
        }
        0
    }

    /// Return the action currently installed for `sig`.
    pub fn action(&self, sig: c_int) -> kernel_sigdisp::Action {
        let guard = self.lock();
        guard.table().action(sig)
    }

    /// Read a signal's handler and flags under one lock acquisition.
    pub fn handler_and_flags(&self, sig: c_int) -> (u64, u32) {
        let guard = self.lock();
        (guard.table().handler(sig), guard.table().flags(sig))
    }

    /// Wake every thread parked in [`SigHandGuard`]-held waits on this object.
    pub fn notify(&self) {
        self.state.notify(SIGNAL_ARRIVED);
    }

    /// A new group's table, copied from this one. `fork` without `CLONE_SIGHAND`.
    pub fn fork_copy(&self) -> Arc<SigHand> {
        let new = SigHand::new();
        {
            let src = self.lock();
            let mut dst = new.lock();
            *dst.table_mut() = *src.table();
        }
        new
    }

    /// `CLONE_CLEAR_SIGHAND`: every handler at its default.
    ///
    /// Linux's `CLONE_CLEAR_SIGHAND` resets the handlers and nothing else —
    /// this is a fork with the handlers dropped, not a fresh process. The
    /// alternate stack is not touched, and since 2026-09-04 that is not a
    /// decision made here at all: it is the **task's**, in
    /// `crates/kernel/sigqueue`, and the child's copy of that is what carries
    /// it across.
    ///
    /// A caller asks for this so it can `exec` without first walking 64 signals
    /// to reset them, which is what `posix_spawn` used to do and is a syscall
    /// per signal.
    pub fn fork_cleared(&self) -> Arc<SigHand> {
        SigHand::new()
    }
}

/// The condition index a thread waiting for a signal parks on.
const SIGNAL_ARRIVED: u32 = 0;

#[path = "ops.rs"]
mod ops;
pub use ops::{Recipient, SignalStatus};
