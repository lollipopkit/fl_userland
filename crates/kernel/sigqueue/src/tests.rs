//! Tests for signal masks, queue ordering, and task signal inheritance.

use super::*;

const SIGINT: c_int = 2;
const SIGKILL: c_int = 9;
const SIGCHLD: c_int = 17;
const SIGRT1: c_int = SIGRTMIN + 1;

fn info(sig: c_int, code: i32) -> SigInfo {
    // Used here only to tell two entries apart.
    SigInfo {
        sig,
        code,
        ..Default::default()
    }
}

fn code(info: &SigInfo) -> i32 {
    info.code
}

#[test]
fn a_standard_signal_arriving_twice_is_one_signal() {
    let mut signals = Signals::default();
    assert!(signals.arrive(SIGINT, info(SIGINT, 1), true).queued);
    assert!(!signals.arrive(SIGINT, info(SIGINT, 2), true).queued);
    assert_eq!(signals.queued(), 1);
    assert_eq!(code(&signals.dequeue(!0).unwrap()), 1);
    assert_eq!(signals.pending(), 0);
}

/// The one that wedged a JSC GC handshake: its thread resume uses an RT
/// signal, and dropping the second as "already pending" loses a resume.
#[test]
fn a_real_time_signal_arriving_twice_is_two_signals() {
    let mut signals = Signals::default();
    assert!(signals.arrive(SIGRT1, info(SIGRT1, 1), true).queued);
    assert!(signals.arrive(SIGRT1, info(SIGRT1, 2), true).queued);
    assert_eq!(signals.queued(), 2);
    assert_eq!(code(&signals.dequeue(!0).unwrap()), 1);
    // Still pending: the bit describes the queue, and one is left.
    assert_ne!(signals.pending() & mask_of(SIGRT1), 0);
    assert_eq!(code(&signals.dequeue(!0).unwrap()), 2);
    assert_eq!(signals.pending(), 0);
}

/// Linux's `next_signal`: the lowest number first, and a fault's signal
/// ahead of every other, whatever order they arrived in. Arrival order is
/// what this used to answer, and it is observable -- it decides which
/// handler runs first when a program unblocks two pending signals.
#[test]
fn two_pending_signals_leave_lowest_first_and_a_fault_ahead_of_both() {
    const SIGUSR1: c_int = 10;
    const SIGSEGV: c_int = 11;
    const SIGUSR2: c_int = 12;
    let mut signals = Signals::default();
    signals.arrive(SIGUSR2, info(SIGUSR2, 1), true);
    signals.arrive(SIGUSR1, info(SIGUSR1, 2), true);
    signals.arrive(SIGSEGV, info(SIGSEGV, 3), true);
    assert_eq!(signals.dequeue(!0).unwrap().sig, SIGSEGV);
    assert_eq!(signals.dequeue(!0).unwrap().sig, SIGUSR1);
    assert_eq!(signals.dequeue(!0).unwrap().sig, SIGUSR2);
    assert!(signals.dequeue(!0).is_none());
    assert_eq!(signals.pending(), 0);
}

/// By number between numbers and by age within one: a lower real-time
/// number that arrived later still leaves first, and two of one number
/// leave oldest first.
#[test]
fn real_time_signals_leave_by_number_then_by_age() {
    let mut signals = Signals::default();
    signals.arrive(SIGRT1 + 1, info(SIGRT1 + 1, 1), true);
    signals.arrive(SIGRT1, info(SIGRT1, 2), true);
    signals.arrive(SIGRT1, info(SIGRT1, 3), true);
    assert_eq!(code(&signals.dequeue(!0).unwrap()), 2);
    assert_eq!(code(&signals.dequeue(!0).unwrap()), 3);
    assert_eq!(code(&signals.dequeue(!0).unwrap()), 1);
}

#[test]
fn dequeuing_takes_only_what_the_set_names() {
    let mut signals = Signals::default();
    signals.arrive(SIGINT, info(SIGINT, 1), true);
    signals.arrive(SIGCHLD, info(SIGCHLD, 2), true);
    let got = signals.dequeue(mask_of(SIGCHLD)).unwrap();
    assert_eq!(got.sig, SIGCHLD);
    assert_eq!(signals.pending(), mask_of(SIGINT));
    assert!(signals.dequeue(mask_of(SIGCHLD)).is_none());
}

/// The bit and the queue are one fact. A dequeue that cleared the entry and
/// left the bit would make that signal uncoalescable for ever.
#[test]
fn a_dequeued_signal_can_arrive_again() {
    let mut signals = Signals::default();
    signals.arrive(SIGINT, info(SIGINT, 1), true);
    signals.dequeue(!0);
    assert!(signals.arrive(SIGINT, info(SIGINT, 2), true).queued);
    assert_eq!(code(&signals.dequeue(!0).unwrap()), 2);
}

#[test]
fn a_blocked_signal_is_pending_but_neither_delivered_nor_interrupting() {
    let mut signals = Signals::default();
    signals.set_blocked(mask_of(SIGINT));
    let arrival = signals.arrive(SIGINT, info(SIGINT, 1), true);
    assert_eq!(
        arrival,
        Arrival {
            queued: true,
            wake: false,
            ends_group: false
        }
    );
    assert_ne!(signals.pending(), 0);
    assert!(!signals.deliverable(&Pending::default()));
    assert!(!signals.interrupts_a_wait(&Pending::default()));
    // Unblocking is what makes it both.
    signals.set_blocked(0);
    assert!(signals.deliverable(&Pending::default()));
    assert!(signals.interrupts_a_wait(&Pending::default()));
}

/// SIGKILL and SIGSTOP are not blockable, so a mask does not hold them.
#[test]
fn an_unblockable_signal_wakes_through_a_full_mask() {
    let mut signals = Signals::default();
    signals.set_blocked(!0);
    assert!(signals.arrive(SIGKILL, info(SIGKILL, 1), false).wake);
}

/// The two questions this crate exists to keep apart.
#[test]
fn a_signal_being_waited_for_is_deliverable_without_interrupting() {
    let mut signals = Signals::default();
    signals.set_blocked(mask_of(SIGCHLD));
    signals.set_waiting(mask_of(SIGCHLD));
    assert!(signals.arrive(SIGCHLD, info(SIGCHLD, 1), true).wake);
    assert!(
        signals.deliverable(&Pending::default()),
        "sigtimedwait has something to return"
    );
    assert!(
        !signals.interrupts_a_wait(&Pending::default()),
        "and must not be told its own wait was interrupted"
    );
}

/// A blocked signal wakes nobody — unless a signalfd is watching, because
/// that descriptor becomes readable exactly when the signal becomes
/// pending and nothing else would tell a poll loop.
#[test]
fn a_signalfd_makes_a_blocked_signal_wake_the_thread() {
    let mut signals = Signals::default();
    signals.set_blocked(mask_of(SIGCHLD));
    assert!(!signals.arrive(SIGCHLD, info(SIGCHLD, 1), true).wake);
    signals.dequeue(!0);
    signals.watch_signalfd(mask_of(SIGCHLD));
    assert!(signals.arrive(SIGCHLD, info(SIGCHLD, 2), true).wake);
}

#[test]
fn a_thread_wants_a_signal_it_has_not_blocked_or_is_waiting_for() {
    let mut signals = Signals::default();
    assert!(signals.wants(SIGINT));
    signals.set_blocked(mask_of(SIGINT));
    assert!(!signals.wants(SIGINT));
    signals.set_waiting(mask_of(SIGINT));
    assert!(signals.wants(SIGINT));
}

#[test]
fn retaining_rebuilds_the_pending_mask_from_the_queue() {
    let mut signals = Signals::default();
    signals.arrive(SIGINT, info(SIGINT, 1), true);
    signals.arrive(SIGCHLD, info(SIGCHLD, 2), true);
    signals.arrive(SIGRT1, info(SIGRT1, 3), true);
    signals.arrive(SIGRT1, info(SIGRT1, 4), true);
    signals.retain(|info| sig_of(info) == SIGRT1);
    assert_eq!(signals.queued(), 2);
    assert_eq!(signals.pending(), mask_of(SIGRT1));
}

#[test]
fn a_saved_mask_is_returned_once() {
    let mut signals = Signals::default();
    signals.set_blocked(mask_of(SIGINT));
    assert!(!signals.has_saved_mask());
    signals.save_mask();
    signals.set_blocked(mask_of(SIGCHLD));
    assert!(signals.has_saved_mask());
    assert_eq!(signals.take_saved_mask(), Some(mask_of(SIGINT)));
    assert_eq!(signals.take_saved_mask(), None);
    assert!(!signals.has_saved_mask());
}

#[test]
fn a_child_inherits_the_masks_and_nothing_that_has_arrived() {
    let mut parent = Signals::default();
    parent.set_blocked(mask_of(SIGINT));
    parent.set_waiting(mask_of(SIGCHLD));
    parent.watch_signalfd(mask_of(SIGKILL));
    parent.arrive(SIGINT, info(SIGINT, 1), true);
    let mut child = Signals::default();
    child.inherit(&parent);
    assert_eq!(child.blocked(), mask_of(SIGINT));
    assert_eq!(child.waiting(), mask_of(SIGCHLD));
    assert_eq!(child.signalfd_mask(), mask_of(SIGKILL));
    assert_eq!(child.pending(), 0);
    assert_eq!(child.queued(), 0);
    // And the parent still has its own.
    assert_eq!(parent.queued(), 1);
}

/// Three answers for the alternate stack, and each is a different call:
/// fork(2) copies it, a new thread starts with none, and exec drops it.
/// It was the process's disposition table's until 2026-09-04, so a thread
/// setting its own replaced every other thread's.
#[test]
fn a_fork_child_inherits_the_alternate_stack_and_a_thread_and_an_exec_do_not() {
    let mut parent = Signals::default();
    parent.set_blocked(mask_of(SIGINT));
    parent.altstack_mut().set(0x9000, 64 * 1024, 0, 0).unwrap();

    let mut child = Signals::default();
    child.inherit(&parent);
    assert_eq!(child.altstack().bounds(), (0x9000, 64 * 1024), "fork(2)");

    child.on_new_thread();
    assert_eq!(
        child.altstack().bounds(),
        (0, 0),
        "CLONE_VM without CLONE_VFORK"
    );
    assert_eq!(
        child.blocked(),
        mask_of(SIGINT),
        "and the masks it inherited stay"
    );

    child.inherit(&parent);
    child.on_exec();
    assert_eq!(child.altstack().bounds(), (0, 0), "execve");
    assert_eq!(
        child.blocked(),
        mask_of(SIGINT),
        "the mask survives an exec"
    );

    assert_eq!(
        parent.altstack().bounds(),
        (0x9000, 64 * 1024),
        "the parent's is its own"
    );
}

#[test]
fn signal_zero_and_out_of_range_numbers_are_not_signals() {
    let mut signals = Signals::default();
    // sig_mask asserts on these in C, and `kill(pid, 0)` took the emulator
    // down once by reaching it.
    for sig in [0, -1, MAX_SIG + 1, 1000] {
        assert_eq!(mask_of(sig), 0);
        assert!(!signals.arrive(sig, info(sig, 1), true).queued);
    }
    assert_eq!(signals.queued(), 0);
}

/// A process-directed signal is the thread's to take only once it has been
/// told -- chosen for it, or by unblocking something -- which is Linux's
/// `TIF_SIGPENDING`. Every thread taking it at its next syscall ran the
/// handler on the thread that called `kill(getpid())` instead of the one
/// chosen (`sigshared_probe`).
#[test]
fn a_shared_signal_is_taken_by_a_thread_that_was_told() {
    let mut shared = Pending::default();
    let mut t = Signals::default();
    t.recalc(&shared);
    assert!(shared.push(SIGINT, info(SIGINT, 1)));
    assert!(!t.deliverable(&shared), "not told yet");
    assert!(t.take_next(!0, &mut shared).is_none());
    assert!(t.chosen_for(SIGINT, true), "chosen, and not blocking it: woken");
    assert!(t.deliverable(&shared) && t.interrupts_a_wait(&shared));
    assert_eq!(t.take_next(!0, &mut shared).map(|i| i.sig), Some(SIGINT));
    assert_eq!(shared.mask(), 0);
    assert_eq!(t.recalc(&shared), 0);
    assert!(!t.deliverable(&shared), "told again only by the next one");
}

/// Unblocking is a reason to look, as Linux's `set_current_blocked` ends in
/// `recalc_sigpending`: a signal every thread blocked goes to whichever
/// unblocks it.
#[test]
fn unblocking_makes_a_thread_look_at_the_shared_set() {
    let mut shared = Pending::default();
    let mut t = Signals::default();
    t.set_blocked(mask_of(SIGINT));
    t.recalc(&shared);
    shared.push(SIGINT, info(SIGINT, 1));
    assert!(!t.chosen_for(SIGINT, true), "chosen while blocking it: nothing to wake for");
    t.recalc(&shared);
    assert!(!t.deliverable(&shared));
    t.set_blocked(0);
    assert!(t.deliverable(&shared));
    assert!(t.take_next(!0, &mut shared).is_some());
}

/// `sigtimedwait` and a `signalfd` read take from both sets whether or not
/// the thread was told, its own first.
#[test]
fn dequeue_either_takes_the_threads_own_first() {
    let mut shared = Pending::default();
    let mut t = Signals::default();
    t.recalc(&shared);
    shared.push(SIGINT, info(SIGINT, 1));
    t.arrive(SIGINT, info(SIGINT, 2), true);
    assert_eq!(t.dequeue_either(!0, &mut shared).map(|i| code(&i)), Some(2));
    assert_eq!(t.dequeue_either(!0, &mut shared).map(|i| code(&i)), Some(1));
    assert!(t.dequeue_either(!0, &mut shared).is_none());
}

/// Taking one of its own makes a thread look at the process's too, as a
/// thread inside Linux's `get_signal` does.
#[test]
fn a_thread_delivering_its_own_takes_the_processs_as_well() {
    let mut shared = Pending::default();
    let mut t = Signals::default();
    t.recalc(&shared);
    shared.push(SIGCHLD, info(SIGCHLD, 1));
    t.arrive(SIGINT, info(SIGINT, 2), true);
    assert_eq!(t.take_next(!0, &mut shared).map(|i| i.sig), Some(SIGINT));
    assert_eq!(t.take_next(!0, &mut shared).map(|i| i.sig), Some(SIGCHLD));
}

/// What a thread blocks while the process has it pending is reported once,
/// for another thread to be told -- Linux's `retarget_shared_pending`.
#[test]
fn blocking_a_pending_shared_signal_is_reported_for_retargeting() {
    let mut shared = Pending::default();
    let mut t = Signals::default();
    shared.push(SIGINT, info(SIGINT, 1));
    t.set_blocked(mask_of(SIGINT) | mask_of(SIGCHLD));
    assert_eq!(t.recalc(&shared), mask_of(SIGINT), "SIGCHLD is not pending");
    assert_eq!(t.recalc(&shared), 0, "once");
}

/// The shared set coalesces a standard signal and queues a real-time one,
/// by the same rule as a thread's own.
#[test]
fn the_shared_set_coalesces_as_a_threads_own_does() {
    let mut shared = Pending::default();
    assert!(shared.push(SIGINT, info(SIGINT, 1)));
    assert!(!shared.push(SIGINT, info(SIGINT, 2)));
    assert!(shared.push(SIGRT1, info(SIGRT1, 3)));
    assert!(shared.push(SIGRT1, info(SIGRT1, 4)));
    assert_eq!(shared.len(), 3);
    shared.retain(|i| sig_of(i) != SIGINT);
    assert_eq!(shared.mask(), mask_of(SIGRT1));
}
