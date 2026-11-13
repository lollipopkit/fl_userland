//! One task's signals: which are blocked, which have arrived, and what arrived.
//!
//! This is the first slice of `struct task` to move. It is a state machine over
//! four bitmasks and a queue, with one lock — the task's `sighand->lock`, which
//! stays in C because several files take it directly and the *delivery* of a
//! signal (a host `pthread_kill`, a condition variable) needs a task this crate
//! deliberately knows nothing about.
//!
//! What it owns is the part that has rules, and every rule here has been got
//! wrong at least once:
//!
//! - **Standard signals coalesce; real-time signals queue.** A second `SIGINT`
//!   before the first is taken is the same `SIGINT`. A second `SIGRTMIN` is a
//!   second delivery, and dropping it as "already pending" loses a JSC thread
//!   resume and wedges its GC handshake.
//! - **The bitmask and the queue are one fact in two places.** The bit says a
//!   signal of that number is queued and is what coalescing consults, so a
//!   dequeue that removes the entry and leaves the bit stops that signal ever
//!   being queued again. They are updated together here, and cannot be updated
//!   separately.
//! - **"Is a signal waiting" is two different questions.** Whether a *wait*
//!   should be interrupted excludes blocked signals outright; whether a signal
//!   can be *delivered* makes an exception for the ones a `sigtimedwait` has
//!   asked for. Four files each wrote one of the two out by hand.

use std::collections::VecDeque;
use std::ffi::c_int;

/// AArch64 Linux has signals 1..64, and a `sigset_t_` is a `u64` — so signal
/// `n` is bit `n - 1` and there is no spare bit. `MAX_SIG` as a *count* rather
/// than a highest-number made the usable range 1..63 and answered EINVAL for
/// the one signal a program asking for `SIGRTMAX` names first.
pub const MAX_SIG: c_int = 64;
/// Signals at or above this queue rather than coalesce.
pub const SIGRTMIN: c_int = 32;

/// Linux's `SYNCHRONOUS_MASK`: the signals a fault raises, which are delivered
/// ahead of any other because the instruction that raised one cannot be
/// resumed until it has been dealt with. `SIGSEGV`, `SIGBUS`, `SIGILL`,
/// `SIGTRAP`, `SIGFPE` and `SIGSYS`.
fn synchronous(sig: c_int) -> bool {
    matches!(sig, 11 | 7 | 4 | 5 | 8 | 31)
}

pub fn mask_of(sig: c_int) -> u64 {
    if !(1..=MAX_SIG).contains(&sig) {
        return 0;
    }
    1u64 << (sig - 1)
}

/// The guest's `siginfo_t`, 128 bytes.
///
/// **One rendering, `crates/kernel/siginfo`'s.** It used to be an opaque
/// `[u8; 128]` here, on the argument that only the signal number is read and
/// the layout belongs to `kernel/signal.h`. That was true of this crate and
/// false of the tree: every caller builds the *structured* `struct siginfo_`,
/// `crates/kernel/errno` had a third copy called `SigInfoNil`, and the three
/// met through a C ABI that reinterprets rather than checks — with a
/// `transmute` between two of them in `crates/kernel/signaldeliver`. Sharing
/// the type is what makes a wrong field a compile error.
///
/// Only `sig` is read here, and only to keep the queue and the mask in step.
pub use kernel_siginfo::siginfo_ as SigInfo;

/// The 128-byte layout a wait or an exit fills, and the status decode.
pub mod childinfo;

/// The queue orders by signal number, so it needs one field of it.
fn sig_of(info: &SigInfo) -> c_int {
    info.sig
}

const _: () = assert!(std::mem::size_of::<SigInfo>() == 128);
const _: () = assert!(std::mem::align_of::<SigInfo>() == 8);

/// The 128 bytes a guest sees.
///
/// `signalfd` formats a record from them and `sigtimedwait` copies them into
/// guest memory, and neither wants the fields. Safe because every arm of the
/// union is plain integers, the size is asserted above, and `siginfo_` has no
/// padding -- `crates/kernel/siginfo` asserts that too. A `SigInfo` is made
/// from [`Default`], which zeroes what no arm names.
///
/// "No padding" was not true until 2026-09-30: bytes 12..16 were padding, and
/// no construction initialises padding, so this handed four bytes of host
/// stack to the guest. See `siginfo_::_pad0`.
pub fn as_bytes(info: &SigInfo) -> &[u8; 128] {
    // SAFETY: same size, same alignment, no invalid bit patterns in either.
    unsafe { &*(info as *const SigInfo).cast::<[u8; 128]>() }
}

/// [`as_bytes`], writable. `waitid`'s status decode rewrites three fields
/// through their offsets, which is the wire format's own view of the struct.
pub fn as_bytes_mut(info: &mut SigInfo) -> &mut [u8; 128] {
    // SAFETY: as `as_bytes`.
    unsafe { &mut *(info as *mut SigInfo).cast::<[u8; 128]>() }
}

/// What the caller must do about a signal that has just arrived.
#[repr(C)]
#[derive(Clone, Copy, Default, Eq, PartialEq, Debug)]
pub struct Arrival {
    /// It was recorded. False means a standard signal of that number was
    /// already queued, or the queue could not grow.
    pub queued: bool,
    /// The thread has to be woken — it may be inside a host call that only a
    /// signal can interrupt. False for a blocked signal that no `signalfd` of
    /// this task is watching: nothing can observe it yet.
    pub wake: bool,
    /// The signal is fatal to the whole process and its exit has been
    /// started: every thread is to be killed and woken, which the caller
    /// does. Linux's `complete_signal`; set by `crates/kernel/sighand`, which
    /// sees the dispositions.
    pub ends_group: bool,
}

use kernel_sigdisp::AltStack;

/// Signals that have arrived and not been taken: a thread's own, or its
/// process's shared set. The mask and the queue are one fact in two places;
/// see the module comment.
#[derive(Default)]
pub struct Pending {
    mask: u64,
    queue: VecDeque<SigInfo>,
}

impl Pending {
    /// Which signals are in it: `SigPnd` or `ShdPnd`.
    pub fn mask(&self) -> u64 {
        self.mask
    }

    /// Record `info` as signal `sig`. False when it was not: a standard signal
    /// of that number is already here, `sig` is not a signal, or the queue
    /// could not grow.
    pub fn push(&mut self, sig: c_int, info: SigInfo) -> bool {
        let bit = mask_of(sig);
        if bit == 0 {
            return false;
        }
        // A standard signal already queued is the same signal. A real-time one
        // is a separate delivery and must not be folded into the first.
        if sig < SIGRTMIN && self.mask & bit != 0 {
            return false;
        }
        if self.queue.try_reserve(1).is_err() {
            return false;
        }
        let mut info = info;
        info.sig = sig;
        self.mask |= bit;
        self.queue.push_back(info);
        true
    }

    /// Take the next signal in `set`.
    ///
    /// **Next is not first.** Linux's `next_signal` delivers the synchronous
    /// signals -- the ones a fault raises -- ahead of everything, and then the
    /// lowest-numbered pending signal, in either case oldest first among
    /// entries of one number. This took the oldest entry of any number, so
    /// two signals pending at once were delivered in the order they arrived,
    /// which for a program that unblocks both is the order it happened to
    /// raise them in; a real kernel delivers `SIGUSR1` before `SIGUSR2`
    /// whichever came first. The order is observable, and observed: it is
    /// which handler runs first.
    ///
    /// The bit outlives the first entry for a real-time signal, so it is
    /// cleared only once the last one of that number is gone -- and it has to
    /// be cleared then, because delivery drops a *standard* signal whose bit
    /// is already set, so a dequeue that left it would stop that signal being
    /// queued ever again.
    pub fn dequeue(&mut self, set: u64) -> Option<SigInfo> {
        if self.mask & set == 0 {
            return None;
        }
        let index = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, info)| set & mask_of(sig_of(info)) != 0)
            // `min_by_key` answers the first of equals, which is the oldest.
            .min_by_key(|(_, info)| (!synchronous(sig_of(info)), sig_of(info)))
            .map(|(i, _)| i)?;
        let found = self.queue.remove(index)?;
        let sig = sig_of(&found);
        if !self.queue.iter().any(|info| sig_of(info) == sig) {
            self.mask &= !mask_of(sig);
        }
        Some(found)
    }

    /// Drop every entry that `keep` does not select, and rebuild the mask from
    /// what is left.
    pub fn retain(&mut self, keep: impl Fn(&SigInfo) -> bool) {
        self.queue.retain(|info| keep(info));
        self.mask = self.queue.iter().fold(0, |mask, info| mask | mask_of(sig_of(info)));
    }

    pub fn clear(&mut self) {
        self.mask = 0;
        self.queue.clear();
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[derive(Default)]
pub struct Signals {
    blocked: u64,
    /// This thread's own pending set: what was sent to *it* -- `tgkill`, a
    /// fault, `SIGPIPE`. What was sent to the process is the group's
    /// [`Pending`], which every method that needs it is handed.
    own: Pending,
    /// Whether this thread is to look at its process's shared set: Linux's
    /// `TIF_SIGPENDING` as far as that set goes. Set when a process-directed
    /// signal chose this thread, when the thread unblocked something, and
    /// when it took a signal of its own; recomputed when a delivery pass ends.
    ///
    /// Every thread looking at every syscall would answer a different
    /// question from Linux's: the thread that called `kill(getpid())` would
    /// take the signal on its way out of the call, where Linux delivers to the
    /// thread it chose -- the leader, when it can (`sigshared_probe`).
    shared_hint: bool,
    /// What [`Signals::set_blocked`] has blocked since the last delivery pass:
    /// a process-directed signal in it may have been meant for this thread,
    /// and another has to be told (Linux's `retarget_shared_pending`).
    newly_blocked: u64,
    /// **`CLONE_VM` without `CLONE_VFORK` resets it.** A new thread has no
    /// alternate signal stack whatever the thread that made it had; Linux's
    /// `copy_process` calls `sas_ss_reset` under exactly that condition.
    /// This thread's alternate signal stack. Here and not in the disposition
    /// table because `sigaltstack` is per **thread** -- Linux keeps it in
    /// `task_struct` -- and a runtime that gives every thread one, as Go does,
    /// has two threads in a handler at the same instant.
    altstack: AltStack,
    /// A `sigtimedwait` or `signalfd` read's set. A signal in here is delivered
    /// even when it is blocked, because the thread has asked to be woken for it.
    waiting: u64,
    /// The union of the masks of every `signalfd` this task has made. It only
    /// grows: recomputing it on close would mean walking the descriptor table
    /// from `fd_close`, and a stale bit costs one spurious wakeup that the
    /// waiter rechecks and ignores.
    signalfd_mask: u64,
    /// `sigsuspend` and `pselect` install a mask for one call and want the old
    /// one back at the next delivery.
    saved_mask: Option<u64>,
}

impl Signals {
    pub fn blocked(&self) -> u64 {
        self.blocked
    }

    /// Unblocking anything sends the thread to look at its process's shared
    /// set: Linux's `set_current_blocked` ends in `recalc_sigpending`, so a
    /// thread that unblocks a signal another thread was chosen for, or that
    /// nobody could take, takes it.
    pub fn set_blocked(&mut self, mask: u64) {
        if self.blocked & !mask != 0 {
            self.shared_hint = true;
        }
        self.newly_blocked |= mask & !self.blocked;
        self.blocked = mask;
    }

    /// This thread's own pending set, `SigPnd`.
    pub fn pending(&self) -> u64 {
        self.own.mask()
    }

    pub fn waiting(&self) -> u64 {
        self.waiting
    }

    pub fn set_waiting(&mut self, mask: u64) {
        self.waiting = mask;
    }

    pub fn signalfd_mask(&self) -> u64 {
        self.signalfd_mask
    }

    pub fn watch_signalfd(&mut self, mask: u64) {
        self.signalfd_mask |= mask;
    }

    /// This thread's alternate signal stack.
    pub fn altstack(&self) -> &AltStack {
        &self.altstack
    }

    pub fn altstack_mut(&mut self) -> &mut AltStack {
        &mut self.altstack
    }

    /// What of the shared set this thread is to consider now.
    fn shared_seen(&self, shared: &Pending) -> u64 {
        if self.shared_hint { shared.mask() } else { 0 }
    }

    /// Whether a signal can be *delivered* — the test a blocking read or a
    /// wait uses to decide it has something to hand back.
    ///
    /// The `waiting` term is what makes it different from
    /// [`Signals::interrupts_a_wait`]: a thread in `sigtimedwait` has asked to
    /// be woken for a signal it has blocked.
    pub fn deliverable(&self, shared: &Pending) -> bool {
        (self.own.mask() | self.shared_seen(shared)) & !(self.blocked & !self.waiting) != 0
    }

    /// Whether a wait should answer `EINTR`.
    ///
    /// Deliberately *not* [`Signals::deliverable`]. `sigtimedwait` is itself a
    /// caller of the interruptible wait, and counting the signal it is waiting
    /// *for* as a reason to interrupt would make `sigwaitinfo` return `EINTR`
    /// instead of the signal it was called to collect. It is woken anyway —
    /// [`Signals::arrive`] says so — and its own loop then dequeues.
    pub fn interrupts_a_wait(&self, shared: &Pending) -> bool {
        (self.own.mask() | self.shared_seen(shared)) & !self.blocked != 0
    }

    /// Whether this thread would take `sig` if it were sent to the group.
    pub fn wants(&self, sig: c_int) -> bool {
        self.blocked & !self.waiting & mask_of(sig) == 0
    }

    /// Record an arriving signal of this thread's own.
    ///
    /// `blockable` is false for `SIGKILL` and `SIGSTOP`, which no mask stops.
    pub fn arrive(&mut self, sig: c_int, info: SigInfo, blockable: bool) -> Arrival {
        if !self.own.push(sig, info) {
            return Arrival::default();
        }
        Arrival { queued: true, wake: self.would_wake(mask_of(sig), blockable), ends_group: false }
    }

    /// Whether a signal `bit` that has just become pending must wake this
    /// thread. A blocked signal is not delivered — but it still has to wake a
    /// thread watching for it through a signalfd, because that descriptor
    /// becomes readable exactly when the signal becomes pending and nothing
    /// else would tell a poll loop.
    fn would_wake(&self, bit: u64, blockable: bool) -> bool {
        let held = self.blocked & !self.waiting & bit != 0 && blockable;
        !held || self.signalfd_mask & bit != 0
    }

    /// A process-directed signal has just become pending in `shared` and this
    /// thread was chosen to take it: Linux's `complete_signal` and the
    /// `signal_wake_up` that follows. Answers whether it has to be woken.
    pub fn chosen_for(&mut self, sig: c_int, blockable: bool) -> bool {
        self.shared_hint = true;
        self.would_wake(mask_of(sig), blockable)
    }

    /// Take the next signal in `set` off this thread's own set.
    pub fn dequeue(&mut self, set: u64) -> Option<SigInfo> {
        self.own.dequeue(set)
    }

    /// Linux's `dequeue_signal`: this thread's own set first, then the
    /// process's. `sigtimedwait` and a `signalfd` read take from both whatever
    /// the thread was told, as Linux's do.
    pub fn dequeue_either(&mut self, set: u64, shared: &mut Pending) -> Option<SigInfo> {
        self.own.dequeue(set).or_else(|| shared.dequeue(set))
    }

    /// What a delivery pass takes next: this thread's own first, then -- if
    /// this thread is to look -- the process's. Taking one of its own makes it
    /// look, since Linux's `get_signal` recomputes the flag after each and a
    /// thread that is delivering anyway takes what the process has too.
    pub fn take_next(&mut self, set: u64, shared: &mut Pending) -> Option<SigInfo> {
        if let Some(info) = self.own.dequeue(set) {
            self.shared_hint = true;
            return Some(info);
        }
        if self.shared_hint { shared.dequeue(set) } else { None }
    }

    /// The end of a delivery pass: Linux's `recalc_sigpending`, for the shared
    /// set. Whatever this thread could take of it has been taken, so it is
    /// told to look again only by a signal that it can still take.
    ///
    /// Answers what of the shared set this thread has blocked since the last
    /// pass and still blocks, which another thread has to be told about.
    pub fn recalc(&mut self, shared: &Pending) -> u64 {
        self.shared_hint = shared.mask() & !self.blocked != 0;
        std::mem::take(&mut self.newly_blocked) & self.blocked & shared.mask()
    }

    /// Drop every queued signal of this thread's own that `keep` does not
    /// select, and rebuild the pending mask from what is left.
    pub fn retain(&mut self, keep: impl Fn(&SigInfo) -> bool) {
        self.own.retain(keep);
    }

    /// Install a mask for one call, remembering the current one.
    pub fn save_mask(&mut self) {
        self.saved_mask = Some(self.blocked);
    }

    /// Restore what [`Signals::save_mask`] remembered, if anything, and answer
    /// the mask a handler should run under — the union of the two, because a
    /// signal taken while the temporary mask was installed was blocked by both.
    pub fn take_saved_mask(&mut self) -> Option<u64> {
        self.saved_mask.take()
    }

    pub fn has_saved_mask(&self) -> bool {
        self.saved_mask.is_some()
    }

    /// What a new task takes from the one it was cloned from: every mask, and
    /// nothing that has arrived.
    ///
    /// `*task = *parent` used to do this by not mentioning it, which is the
    /// shape `tools/fork-inherit.py` existed to catch until a fork became a struct literal — and which left the
    /// child sharing the parent's queue *list head* until two lines later
    /// re-initialised it. Named here so that what is inherited is a decision
    /// rather than a side effect.
    ///
    /// `saved_mask` is inherited because it was, not because it should be: a
    /// child forked from a handler during `sigsuspend` has no call to restore
    /// a mask for. Left as it was so that this migration changes no behaviour;
    /// it needs a test against a real kernel before it changes.
    pub fn inherit(&mut self, parent: &Signals) {
        self.blocked = parent.blocked;
        self.waiting = parent.waiting;
        self.signalfd_mask = parent.signalfd_mask;
        self.saved_mask = parent.saved_mask;
        // fork(2)'s rule: a child inherits the calling thread's. A new *thread*
        // does not, and the caller that knows the clone flags says so with
        // [`Signals::on_new_thread`] afterwards -- this crate does not see them.
        self.altstack = parent.altstack;
        // A new thread looks at its process's set once, as Linux's
        // `copy_process` ends in `recalc_sigpending` for it.
        self.shared_hint = true;
        self.own.clear();
    }

    /// What `CLONE_VM` without `CLONE_VFORK` undoes after [`Signals::inherit`]:
    /// a thread starts with no alternate stack, whatever the thread that made
    /// it had. The masks it inherited stay.
    pub fn on_new_thread(&mut self) {
        self.altstack.on_new_thread();
    }

    /// What `execve` undoes: the alternate stack belongs to the image that is
    /// gone. The masks survive an exec, which is Linux's rule, and so does
    /// what is pending, this thread's and the process's (`sigshared_probe`).
    pub fn on_exec(&mut self) {
        self.altstack.on_exec();
    }

    /// Everything the task has, for a fresh thread or a task that is exiting.
    pub fn clear(&mut self) {
        self.blocked = 0;
        self.waiting = 0;
        self.saved_mask = None;
        self.shared_hint = false;
        self.newly_blocked = 0;
        self.altstack = AltStack::default();
        self.own.clear();
    }

    /// How many of this thread's own are queued.
    pub fn queued(&self) -> usize {
        self.own.len()
    }
}

// `abi.rs` was here until 2026-11-12: ten `#[no_mangle] extern "C"` getters
// and setters over a `*const Signals` for a C caller that no longer exists.
// Nothing named them -- not C, not the assembly, not `iul.h` -- and two of the
// questions they answered need the process's shared set now.

#[cfg(test)]
mod tests;
