//! Signal queue operations, as methods on [`Queue`]: the thread group's lock
//! and one task's queue.
//!
//! **Methods since 2026-09-30.** Each was a `pub unsafe fn sighand_*(p:
//! *mut SigHand, q: *mut Signals, ...)`, testing both for null, borrowing the
//! `Arc` out of `p` and taking the lock -- and a `*const SigInfo` for the
//! record, dereferenced inside. The two pointers are one obligation, made once
//! where the [`Queue`] is; the null test is [`Queue::from_raw`]'s; the record
//! is a value.
//!
//! `sighand_try_self_signal` went with the conversion: its one caller had been
//! replaced by [`Queue::is_ignored_or_blocked`], and `pub` kept `dead_code`
//! from saying so.

use std::ffi::c_int;

use kernel_sigdisp::Disposition;
use kernel_sigqueue::{Arrival, SigInfo};

use super::Queue;

/* `signal_pending` was here until 2026-09-09: the hook `crates/util/waitfor`
 * calls to ask whether a signal should end a wait. It is
 * `crates/kernel/taskview`'s now, and the move is not tidying — it read
 * `current()` and `(*task).sighand`, and *that* was this crate's only reason to
 * depend on the accessors crate. With it gone the dependency runs the other
 * way, which is what lets `struct task` hold an `Arc<SigHand>` instead of an
 * erased pointer. */

/* `current_signal_pending` moved to `crates/kernel/taskview` on 2026-09-09,
 * with `signal_pending` and for the same reason: it is two field reads of the
 * calling task, and reading the calling task is what that crate is. */

/// What `/proc/<pid>/stat` and `status` say about one thread's signals:
/// `SigPnd`, `ShdPnd`, `SigBlk`, `SigIgn` and `SigCgt`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignalStatus {
    pub pending: u64,
    pub shared: u64,
    pub blocked: u64,
    pub ignored: u64,
    pub caught: u64,
}

/// What a sender knows about the task a signal is for that its queue does not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recipient {
    /// It has a tracer, which sees every signal but `SIGKILL` first.
    pub traced: bool,
    /// Its process is its namespace's init and this sender cannot override
    /// that: Linux's `SIGNAL_UNKILLABLE` without `force`. A signal it has not
    /// blocked and has not caught is discarded.
    pub unkillable: bool,
    /// Its process is stopped. Linux's `wants_signal` passes over a stopped
    /// thread for anything but `SIGKILL`, so nothing else is fatal to it
    /// until it is continued.
    pub stopped: bool,
}

/// Whether a signal arriving for the guarded task is discarded at generation:
/// Linux's `sig_ignored`. **A blocked signal never is**: the task can unblock
/// it, `sigwait` for it, or read it from a `signalfd`, and the disposition it
/// would be judged against may have changed by then. **Nor is any for a
/// traced task**, whose tracer sees every signal, `SIGKILL` aside. Then
/// `sig_task_ignored`: init discards what it has not caught, and everyone
/// discards what it ignores.
fn discards(guard: &super::QueueGuard<'_>, sig: c_int, blockable: bool, to: Recipient) -> bool {
    let held_pending = blockable && (guard.queue().blocked() & kernel_sigqueue::mask_of(sig)) != 0;
    if held_pending || (to.traced && sig != kernel_sigdisp::SIGKILL) {
        return false;
    }
    (to.unkillable && guard.table().handler(sig) == kernel_sigdisp::SIG_DFL)
        || guard.table().action(sig) == kernel_sigdisp::Action::Ignore
}

/// Whether a signal just recorded for the guarded task ends its whole process
/// now: the test at the end of Linux's `complete_signal`. The disposition is
/// the default and terminates without a core, the task does not block it, and
/// neither a tracer (which sees it first) nor a stop (which holds everything
/// but `SIGKILL`) is in the way. `SIGNAL_UNKILLABLE` is not asked: init dies
/// here when the thread chosen does not block what the one named did
/// (`sigfatal_probe`).
fn ends_group(guard: &super::QueueGuard<'_>, sig: c_int, blockable: bool, to: Recipient) -> bool {
    let blocked = blockable && guard.queue().blocked() & kernel_sigqueue::mask_of(sig) != 0;
    guard.table().action(sig) == kernel_sigdisp::Action::Terminate
        && !kernel_sigdisp::dumps_core(sig)
        && !blocked
        && !(blockable && (to.traced || to.stopped))
}

impl Queue<'_> {
    /// `execve`: every caught signal back to the default, and the calling thread's
    /// alternate stack dropped. One acquisition for both, because the stack is
    /// read under this lock at every delivery.
    ///
    /// The three lines above this one described `rt_sigaction`'s read-then-write,
    /// which is [`SigHand::get_set`](super::SigHand::get_set) and moved to `lib.rs`
    /// with the type; the `# Safety` heading they carried stayed behind and made
    /// the prose below it read as part of a contract.
    ///
    /// **Null does nothing**: [`Queue::from_raw`] answers `None` for it, and every
    /// caller now spells what that means. This was the one entry point without
    /// the guard, and its two callers disagreed about whose job it was:
    /// `crates/kernel/offloadexec` tested the pointer and `crates/kernel/execcalls`
    /// did not. A task whose `sighand` the group-exit valve has just taken away
    /// reaches the second with null and dereferences it — unlikely, because the
    /// valve only gives up on a thread that ignored three rounds of `SIGUSR1`, and
    /// a crash rather than a wrong answer if it happens. Found by reading, not
    /// observed.
    pub fn on_exec(&self) {
        let mut guard = self.lock();
        guard.table_mut().on_exec();
        guard.queue_mut().on_exec();
    }

    /// Linux's `force_sig_fault`: a signal the process cannot decline.
    ///
    /// The disposition goes back to `SIG_DFL` **and** the signal is unblocked, so
    /// the default action runs however the process had it configured. Both under
    /// one acquisition, which is also the reason this is one call: they are two
    /// halves of one decision, and the C did them as two statements between the
    /// same `lock`/`unlock` pair with no name saying why.
    pub fn force_default(&self, sig: c_int) {
        let mut guard = self.lock();
        guard.table_mut().set(sig, Disposition::default());
        let queue = guard.queue_mut();
        let blocked = queue.blocked();
        queue.set_blocked(blocked & !kernel_sigqueue::mask_of(sig));
    }

    /// Everything `/proc/<pid>/stat` and `/proc/<pid>/status` report about signals,
    /// in one acquisition.
    ///
    /// One call rather than four because the four are one answer: a reader that saw
    /// `pending` from before a signal arrived and `blocked` from after would be
    /// told a process is ignoring something it is not. The C held the lock across
    /// the whole snapshot to get that, which also meant holding it *above*
    /// `group->lock` — the opposite of the order the signal path takes them, and a
    /// deadlock a guest could reach by reading `/proc` while a process was being
    /// stopped
    /// (`docs/changelog/2026-08-22-signal-delivery-and-proc-stat-deadlocked.md`).
    /// Taking it here and dropping it before `group->lock` keeps the atomicity and
    /// removes the inversion.
    pub fn status_snapshot(&self) -> SignalStatus {
        let guard = self.lock();
        let queue = guard.queue();
        let (ignored, caught) = guard.table().ignored_and_caught();
        SignalStatus {
            pending: queue.pending(),
            shared: guard.shared().mask(),
            blocked: queue.blocked(),
            ignored,
            caught,
        }
    }

    /// Record a signal on a task's queue, unconditionally.
    ///
    /// The disposition is not consulted: `deliver_signal`'s callers are the
    /// emulator's own faults — a `SIGSEGV` for an address the guest cannot reach, a
    /// `SIGKILL` from the exit path — and those are not a process's to decline.
    ///
    /// **The wakeup is the caller's**, and happens after this returns. It needs a
    /// task: `pthread_kill` to interrupt a host call, and a broadcast on whatever
    /// condition variable the target is parked on. The C did it from inside this
    /// lock and had to drop and retake the lock around it —
    ///
    /// ```c
    /// // must release the sighand lock while going insane, to avoid a deadlock
    /// unlock(&task->sighand->lock);
    /// ```
    ///
    /// — a window in which the queue it had just written could change under the
    /// caller that was mid-decision. Returning what to do instead removes both the
    /// window and the dance.
    pub fn deliver(&self, sig: c_int, info: SigInfo, blockable: bool) -> Arrival {
        self.lock().queue_mut().arrive(sig, info, blockable)
    }

    /// Record a signal a *process* sent, which the target's disposition may
    /// discard.
    ///
    /// The two questions are one acquisition because they are one decision, and the
    /// order between them is the interesting part: **a blocked signal is never
    /// discarded for being ignored**. The task can unblock it, `sigwait` for it, or
    /// read it from a `signalfd`, and the disposition it would be judged against
    /// may have changed by then — Linux's `sig_ignored()` returns false for a
    /// blocked signal for exactly this reason.
    ///
    /// Without it the canonical `signalfd` loop does not work at all: `SIGCHLD`'s
    /// default action is to ignore, so every child exit was dropped at generation
    /// and the descriptor never became readable.
    ///
    /// **A traced task ignores nothing.** Linux's `sig_ignored()` answers false
    /// for a task with a tracer, `SIGKILL` aside, because the tracer is entitled
    /// to see every signal in a signal-delivery-stop -- `strace` prints the
    /// `SIGCHLD` a program gets from its own child. Until 2026-09-04 that
    /// `SIGCHLD` was discarded here as ignored before the tracer could see it;
    /// `ptrace_probe` measured a traced child that forks and waits.
    ///
    /// **And it may end the process.** A signal that [`ends_group`] says is
    /// fatal runs `start_exit` under this lock -- the group's exit word, set
    /// once -- and the answer says so if that started it: Linux decides at
    /// send time, so a disposition installed after this cannot save the
    /// process and an `exit_group` that follows does not change its status.
    /// The killing and waking is the caller's, outside the lock.
    pub fn send(
        &self,
        sig: c_int,
        info: SigInfo,
        blockable: bool,
        to: Recipient,
        start_exit: impl FnOnce() -> bool,
    ) -> Arrival {
        let mut guard = self.lock();
        if discards(&guard, sig, blockable, to) {
            return Arrival::default();
        }
        let mut arrival = guard.queue_mut().arrive(sig, info, blockable);
        arrival.ends_group = arrival.queued && ends_group(&guard, sig, blockable, to) && start_exit();
        arrival
    }

    /// [`Queue::send`] for a signal sent to the **process**: Linux's
    /// `__send_signal_locked` with `PIDTYPE_TGID`. The disposition is judged
    /// against this task -- the one the sender named, as Linux's `sig_ignored`
    /// judges `p` -- and the signal goes into the shared set, where any thread
    /// of the process that does not block it may take it. Answers whether it
    /// was recorded; [`Queue::chosen`] is the other half.
    pub fn send_shared(&self, sig: c_int, info: SigInfo, blockable: bool, to: Recipient) -> bool {
        let mut guard = self.lock();
        if discards(&guard, sig, blockable, to) {
            return false;
        }
        guard.both_mut().1.push(sig, info)
    }

    /// This thread was chosen to take a process-directed signal just recorded
    /// with [`Queue::send_shared`]: the rest of Linux's `complete_signal`.
    /// Either the signal ends the process -- judged against this thread's
    /// mask, with `start_exit` run under the lock as [`Queue::send`] runs it
    /// -- or the thread is told to look, and the answer says whether it has
    /// to be woken.
    pub fn chosen(&self, sig: c_int, blockable: bool, to: Recipient, start_exit: impl FnOnce() -> bool) -> Arrival {
        let mut guard = self.lock();
        if ends_group(&guard, sig, blockable, to) && start_exit() {
            return Arrival { queued: true, wake: true, ends_group: true };
        }
        let wake = guard.queue_mut().chosen_for(sig, blockable);
        Arrival { queued: true, wake, ends_group: false }
    }

    /// A process-directed signal another thread could not take is this
    /// thread's to look at: Linux's `retarget_shared_pending`, which wakes and
    /// decides nothing. Answers whether it has to be woken.
    pub fn choose(&self, sig: c_int, blockable: bool) -> bool {
        self.lock().queue_mut().chosen_for(sig, blockable)
    }

    /// Whether a signal is waiting that should make an interruptible wait answer
    /// `EINTR`.
    ///
    /// This was the same three lines in four files. It is not the same question as
    /// [`Queue::deliverable`] and the difference is `sigtimedwait`'s set: a thread
    /// that has asked for a signal it has blocked wants to be *woken* for it, but
    /// must not be told `EINTR` for it — that would make `sigwaitinfo` fail instead
    /// of returning the signal it was called to collect.
    pub fn interrupts_a_wait(&self) -> bool {
        let guard = self.lock();
        guard.queue().interrupts_a_wait(guard.shared())
    }

    /// [`Queue::interrupts_a_wait`] for a waiter parked on `lock`. When that is
    /// this hand's own lock the waiter already holds it, so the queue is read
    /// in place rather than locked a second time; any other lock means this
    /// one is taken.
    ///
    /// # Safety
    /// The caller holds `lock`.
    pub unsafe fn interrupts_a_wait_under(&self, lock: &util_synctypes::lock_t) -> bool {
        if self.hand.owns_lock(lock) {
            // SAFETY: `lock` is this hand's, and the caller holds it.
            unsafe { self.queue.as_ref().interrupts_a_wait(self.shared.as_ref()) }
        } else {
            self.interrupts_a_wait()
        }
    }

    /// Whether a signal is waiting that this thread should act on.
    pub fn deliverable(&self) -> bool {
        let guard = self.lock();
        guard.queue().deliverable(guard.shared())
    }

    /// Swap the blocked mask and remember the old one, for `pselect` and `ppoll`.
    ///
    /// For a call returning `EINTR` the restore is not a matching call: the
    /// delivery path takes the saved mask back with `take_saved_mask` once a
    /// handler has run, because a handler has to run under the temporary mask —
    /// which is what these calls are for. Any other answer restores it first,
    /// with [`Queue::restore_temporary_mask`]. `rt_sigsuspend` is the same
    /// operation with a wait after it, and always answers `EINTR`.
    pub fn set_mask_temporarily(&self, mask: u64) {
        let mut guard = self.lock();
        let queue = guard.queue_mut();
        queue.save_mask();
        queue.set_blocked(kernel_sigdisp::maskable(mask));
    }

    /// Put back the mask [`Queue::set_mask_temporarily`] replaced, now, with
    /// nothing delivered under the temporary one.
    ///
    /// For a call that is *not* returning `EINTR`: Linux's
    /// `restore_saved_sigmask_unless(ret == -EINTR)`. A signal the temporary
    /// mask admitted and the old one blocks then stays pending, where the
    /// delivery path would have run its handler under the temporary mask.
    pub fn restore_temporary_mask(&self) {
        let mut guard = self.lock();
        let queue = guard.queue_mut();
        if let Some(saved) = queue.take_saved_mask() {
            queue.set_blocked(saved);
        }
    }

    /// Has this task ignored or blocked `sig`?
    ///
    /// Linux's `is_ignored()`. One acquisition, because the two halves are one
    /// answer: the terminal's background rules ask it *before* asking whether the
    /// process group is orphaned, so a group that ignores `SIGTTOU` proceeds even
    /// when it is orphaned.
    pub fn is_ignored_or_blocked(&self, sig: c_int) -> bool {
        let guard = self.lock();
        guard.table().action(sig) == kernel_sigdisp::Action::Ignore
            || (guard.queue().blocked() & kernel_sigqueue::mask_of(sig)) != 0
    }

    /// Widen the mask a thread is woken for, so that a signal it has *blocked*
    /// still announces itself to a `signalfd`.
    ///
    /// Null sighand does nothing, which is what the C's `!= NULL` guard did.
    pub fn watch_signalfd(&self, mask: u64) {
        self.lock().queue_mut().watch_signalfd(mask);
    }

    /// Whether `signalfd`'s poll should report readable: a signal in `mask`
    /// pending for this thread or for its process, as Linux's `signalfd_poll`
    /// asks both.
    pub fn pending_in(&self, mask: u64) -> bool {
        let guard = self.lock();
        (guard.queue().pending() | guard.shared().mask()) & mask != 0
    }

    /// `sigpending(2)`: what is pending for this thread or its process and
    /// blocked here.
    pub fn sigpending(&self) -> u64 {
        let guard = self.lock();
        (guard.queue().pending() | guard.shared().mask()) & guard.queue().blocked()
    }
}
