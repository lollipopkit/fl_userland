use super::*;
use kernel_sigdisp::{Action, SIG_DFL, SIG_IGN};

/// Links the six C symbols `GuestLock` needs. Without it this crate has no
/// tests at all, which is what
/// `docs/changelog/2026-08-29-the-blocking-half-of-eventfd-and-timerfd-had-no-tests.md`
/// is about.
use kernel_sighand as _;
use kernel_sigqueue as _;

/// `q` under the handle `sh`, as the operations take them.
fn qu<'a>(sh: &'a SigHand, q: *mut Signals) -> Queue<'a> {
    // SAFETY: every test here owns `q` for the length of the call.
    unsafe { Queue::new(sh, q, Box::leak(Box::default())) }
}

/// A `start_exit` that is never asked: the signal is not fatal.
fn never() -> bool {
    panic!("start_exit asked for a signal that is not fatal")
}

fn handler(addr: u64) -> Disposition {
    Disposition {
        handler: addr,
        flags: 0,
        restorer: 0,
        mask: 0,
    }
}

#[test]
fn a_new_sighand_has_nothing_installed() {
    let sh = SigHand::new();
    let guard = sh.lock();
    for sig in 1..=64 {
        assert_eq!(guard.table().handler(sig), SIG_DFL, "signal {sig}");
    }
}

#[test]
fn clone_sighand_shares_one_table() {
    let sh = SigHand::new();
    let shared = Arc::clone(&sh);
    sh.lock().table_mut().set(10, handler(0x1000));
    assert_eq!(shared.lock().table().handler(10), 0x1000);
}

#[test]
fn a_forked_copy_is_independent() {
    let parent = SigHand::new();
    parent.lock().table_mut().set(10, handler(0x1000));

    let child = parent.fork_copy();
    assert_eq!(child.lock().table().handler(10), 0x1000, "inherited");

    child.lock().table_mut().set(10, handler(0x2000));
    assert_eq!(
        parent.lock().table().handler(10),
        0x1000,
        "parent unchanged"
    );
    assert_eq!(child.lock().table().handler(10), 0x2000);
}

#[test]
fn clear_sighand_inherits_nothing() {
    let parent = SigHand::new();
    parent.lock().table_mut().set(10, handler(0x1000));
    parent.lock().table_mut().set(11, handler(SIG_IGN));

    let child = parent.fork_cleared();
    assert_eq!(child.lock().table().handler(10), SIG_DFL);
    // Even an ignore, which `on_exec` keeps. CLONE_CLEAR_SIGHAND is documented
    // as "all signals are reset to their default action", and Linux's
    // `flush_signal_handlers(tsk, /* force_default */ true)` clears the ignores
    // too.
    assert_eq!(child.lock().table().handler(11), SIG_DFL);
}

// `a_cleared_fork_keeps_the_alternate_stack` and its two neighbours were here
// until 2026-09-04. The property they checked -- that a fork child carries the
// alternate stack whether or not the handlers are cleared -- is
// `Signals::inherit`'s now, because the stack is the thread's and not the
// table's, and is tested in crates/kernel/sigqueue.

/// `execve` resets the calling thread's alternate stack in the same
/// acquisition as the handlers.
#[test]
fn exec_drops_the_callers_alternate_stack_with_the_handlers() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    q.altstack_mut().set(0x9000, 64 * 1024, 0, 0).unwrap();
    sh.lock().table_mut().set(10, handler(0x1000));

    qu(&sh, &raw mut q).on_exec();
    assert_eq!(sh.lock().table().handler(10), SIG_DFL);
    assert_eq!(q.altstack().bounds(), (0, 0));
}

/// A null table, or a null queue, is no [`Queue`] at all.
///
/// `sighand_on_exec` was the one entry point without the null guard, and the
/// two callers disagreed about whose job it was: `crates/kernel/offloadexec`
/// checked and `crates/kernel/execcalls` did not, so the ordinary `execve` of a
/// task whose `sighand` the group-exit valve had just taken away dereferenced
/// null. Every operation is a method on a `Queue` now, and this is where one is
/// refused.
#[test]
fn a_task_with_no_table_has_no_queue() {
    let mut q = Signals::default();
    let mut shared = kernel_sigqueue::Pending::default();
    assert!(unsafe { Queue::from_raw(std::ptr::null_mut(), &raw mut q, &raw mut shared) }.is_none());
    let sh = SigHand::new();
    let hand = Arc::as_ptr(&sh) as *mut SigHand;
    assert!(unsafe { Queue::from_raw(hand, std::ptr::null_mut(), &raw mut shared) }.is_none());
    assert!(unsafe { Queue::from_raw(hand, &raw mut q, std::ptr::null_mut()) }.is_none(), "a task with no group");
}

/// The bit convention, which the C got wrong in two ways at once.
#[test]
fn the_reported_masks_are_bit_n_minus_one() {
    let sh = SigHand::new();
    {
        let mut g = sh.lock();
        g.table_mut().set(1, handler(SIG_IGN)); // SIGHUP ignored
        g.table_mut().set(2, handler(0x4000)); // SIGINT caught
        g.table_mut().set(64, handler(0x5000)); // the last realtime signal
    }
    let g = sh.lock();
    let (ignored, caught) = g.table().ignored_and_caught();
    assert_eq!(ignored, 1 << 0, "SIGHUP is bit 0, not bit 1");
    assert_eq!(
        caught,
        (1 << 1) | (1u64 << 63),
        "SIGINT is bit 1 and signal 64 is bit 63"
    );
}

/// Signals above 32 were not looked at at all.
#[test]
fn a_realtime_signal_is_reported() {
    let sh = SigHand::new();
    sh.lock().table_mut().set(34, handler(SIG_IGN));
    let g = sh.lock();
    let (ignored, _) = g.table().ignored_and_caught();
    assert_eq!(ignored, 1u64 << 33);
}

#[test]
fn signal_zero_is_not_a_signal() {
    let sh = SigHand::new();
    // `set` refuses it, so nothing can make it appear in either mask.
    assert!(!sh.lock().table_mut().set(0, handler(SIG_IGN)));
    let g = sh.lock();
    let (ignored, caught) = g.table().ignored_and_caught();
    assert_eq!(ignored, 0);
    assert_eq!(caught, 0);
}

#[test]
fn kill_and_stop_cannot_be_installed_but_can_be_read() {
    let sh = SigHand::new();

    let mut old = Disposition::default();
    let new = handler(0x1000);
    // SIGKILL
    assert_eq!(sh.get_set(9, None, Some(&new)), -22);
    assert_eq!(sh.get_set(9, Some(&mut old), None), 0);
    // Copied out first: `Disposition` is `repr(C, packed)` because it is a
    // guest ABI struct, so a reference to a field of it is unaligned.
    let got = old.handler;
    assert_eq!(got, SIG_DFL);

}

/// The raw boundary that is left: a handle carrying a transferred count, given
/// back exactly once.
///
/// This used to exercise `sighand_new`/`sighand_retain`/`sighand_release`, the
/// three-function facade `struct task` needed while it held a `*mut SigHand`.
/// Two of those went on 2026-09-12 with the field; what stays is the shape
/// `struct task_cleanup` really uses — an `Arc::as_ptr` the group-exit valve
/// publishes and `run_tlb_cleanup` releases — so this asserts the *product's*
/// pairing rather than a facade's.
#[test]
fn a_transferred_count_is_given_back_exactly_once() {
    let owner = SigHand::new();
    // What `ArcSlot::move_to` publishes: the pointer, with the count moved to it.
    let handed = Arc::as_ptr(&owner).cast_mut();
    std::mem::forget(Arc::clone(&owner));
    assert_eq!(Arc::strong_count(&owner), 2);

    // Still alive on the transferred count after this scope's own release.
    drop(unsafe { Arc::from_raw(handed.cast_const()) });
    assert_eq!(Arc::strong_count(&owner), 1);
    assert_eq!(unsafe { &*handed }.action(9), Action::Terminate);
}

#[test]
fn an_action_reads_the_table_and_the_defaults() {
    let sh = SigHand::new();
    // SIGCHLD's default is to be discarded; SIGTERM's is to die.
    assert_eq!(sh.action(17), Action::Ignore);
    assert_eq!(sh.action(15), Action::Terminate);
    assert_eq!(sh.action(19), Action::Stop);

    let h = handler(0x1000);
    assert_eq!(sh.get_set(15, None, Some(&h)), 0);
    assert_eq!(sh.action(15), Action::Handler);

    // SIGKILL ignores whatever is in the table.
    assert_eq!(sh.action(9), Action::Terminate);
}

#[test]
fn the_two_unblockable_signals_are_dropped_from_a_mask_without_an_error() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    let all = !0u64;
    {
        let mut guard = qu(&sh, &raw mut q).lock();
        guard.queue_mut().set_blocked(kernel_sigdisp::maskable(all));
    }
    let blocked = {
        let guard = qu(&sh, &raw mut q).lock();
        guard.queue().blocked()
    };
    assert_eq!(blocked & (1 << 8), 0, "SIGKILL is not blockable");
    assert_eq!(blocked & (1 << 18), 0, "SIGSTOP is not blockable");
    assert_eq!(blocked | (1 << 8) | (1 << 18), all);
}

// --- delivery -----------------------------------------------------------

fn info_for(sig: c_int) -> kernel_sigqueue::SigInfo {
    kernel_sigqueue::SigInfo {
        sig,
        ..Default::default()
    }
}

/// The rule the whole ordering exists for: **a blocked signal is never
/// discarded for being ignored.**
///
/// `SIGCHLD`'s default action is to ignore, and watching child exits through a
/// `signalfd` is the single most common use of one. Without this every child
/// exit was dropped at generation and the descriptor never became readable.
#[test]
fn a_blocked_signal_is_kept_even_though_its_disposition_ignores_it() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    // SIGCHLD, default action ignore.
    let sig = 17;
    {
        let mut guard = qu(&sh, &raw mut q).lock();
        guard.queue_mut()
            .set_blocked(kernel_sigdisp::maskable(kernel_sigqueue::mask_of(sig)));
    }

    let info = info_for(sig);
    let a = qu(&sh, &raw mut q).send(sig, info, true, Recipient::default(), never);
    assert!(a.queued, "queued despite the disposition");
    assert_eq!(
        q.pending() & kernel_sigqueue::mask_of(sig),
        kernel_sigqueue::mask_of(sig)
    );
}

#[test]
fn an_unblocked_ignored_signal_is_discarded() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    let sig = 17; // SIGCHLD again, this time not blocked
    let info = info_for(sig);
    let a = qu(&sh, &raw mut q).send(sig, info, true, Recipient::default(), never);
    assert!(!a.queued, "nothing to observe it, so it is dropped");
    assert_eq!(q.pending(), 0);
}

#[test]
fn a_signal_with_a_handler_is_queued() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    let sig = 17;
    let h = handler(0x400abc);
    assert_eq!(sh.get_set(sig, None, Some(&h)), 0);
    let info = info_for(sig);
    assert!(qu(&sh, &raw mut q).send(sig, info, true, Recipient::default(), never).queued);
}

/// `deliver` does not consult the disposition at all: its callers are the
/// emulator's own faults and the exit path.
#[test]
fn deliver_ignores_the_disposition() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    let sig = 17;
    let ign = handler(kernel_sigdisp::SIG_IGN);
    assert_eq!(sh.get_set(sig, None, Some(&ign)), 0);

    let info = info_for(sig);
    assert!(
        !qu(&sh, &raw mut q).send(sig, info, true, Recipient::default(), never).queued,
        "send drops it"
    );
    assert!(
        qu(&sh, &raw mut q).deliver(sig, info, true).queued,
        "deliver does not"
    );
}

#[test]
fn sigkill_is_queued_however_it_is_set() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    // Blocked as far as the mask is concerned -- set_blocked drops it, so this
    // also checks that the two agree.
    {
        let mut guard = qu(&sh, &raw mut q).lock();
        guard.queue_mut().set_blocked(kernel_sigdisp::maskable(!0));
    }
    let info = info_for(9);
    assert!(qu(&sh, &raw mut q).send(9, info, false, Recipient::default(), || false).queued);
}

/// Linux's `sig_ignored()`: a traced task ignores nothing, because its tracer
/// is entitled to see every signal in a signal-delivery-stop. The `SIGCHLD` a
/// traced program gets from its own child was discarded here as ignored
/// before the tracer could see it.
#[test]
fn a_traced_task_keeps_a_signal_its_disposition_ignores() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    let sig = 17; // SIGCHLD, default action ignore, not blocked
    let info = info_for(sig);
    assert!(
        qu(&sh, &raw mut q).send(sig, info, true, Recipient { traced: true, ..Default::default() }, never).queued,
        "queued for the tracer to see"
    );
    assert_eq!(
        q.pending() & kernel_sigqueue::mask_of(sig),
        kernel_sigqueue::mask_of(sig)
    );
}

/// The terminal's background rule, which asks this before it stops a process.
///
/// It tested `sighand_try_self_signal` until 2026-09-30, which asked the same
/// question and queued the signal as well. That function had no caller left --
/// `crates/kernel/signaldeliver` asks this one -- so the rule is tested where
/// it is decided.
#[test]
fn a_self_signal_is_refused_when_blocked_or_ignored() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    let sig = 21; // SIGTTIN

    // Default action is stop, so with nothing set it goes.
    assert!(!qu(&sh, &raw mut q).is_ignored_or_blocked(sig));

    // Ignored: the process handles background terminal access itself.
    let ign = handler(kernel_sigdisp::SIG_IGN);
    assert_eq!(sh.get_set(sig, None, Some(&ign)), 0);
    assert!(qu(&sh, &raw mut q).is_ignored_or_blocked(sig));

    // Blocked, with the disposition put back.
    let dfl = Disposition::default();
    assert_eq!(sh.get_set(sig, None, Some(&dfl)), 0);
    {
        let mut guard = qu(&sh, &raw mut q).lock();
        guard.queue_mut()
            .set_blocked(kernel_sigdisp::maskable(kernel_sigqueue::mask_of(sig)));
    }
    assert!(qu(&sh, &raw mut q).is_ignored_or_blocked(sig));

}

/// A handler installed for it is still a reason to stop: it is not ignored and
/// not blocked, so the terminal access loses.
#[test]
fn a_self_signal_with_a_handler_still_goes() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    let sig = 22; // SIGTTOU
    let h = handler(0x400abc);
    assert_eq!(sh.get_set(sig, None, Some(&h)), 0);
    assert!(!qu(&sh, &raw mut q).is_ignored_or_blocked(sig));
}

/* `a_null_sighand_answers_no_rather_than_faulting` was here until 2026-09-30,
 * asking three entry points what they answered for a null table. They are
 * methods on a `Queue` now, which cannot be made from one --
 * `a_task_with_no_table_has_no_queue` is that test -- and each caller writes
 * what `None` means for it. */

/* `making_a_disposition_table_installs_the_wait_hook` moved to
 * `crates/kernel/taskview` on 2026-09-09 with its subject: the hook is
 * installed by `bind_current` there now, not by `sighand_new` here, because
 * that is the crate that can see both `crates/util/waitfor` and the current
 * task. */

/// Linux's `complete_signal`: a default-action signal that terminates without
/// a core and is not blocked ends the process at send time, and says so.
#[test]
fn a_fatal_signal_starts_the_exit_when_it_is_sent() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    let mut asked = 0;
    let a = qu(&sh, &raw mut q).send(15, info_for(15), true, Recipient::default(), || {
        asked += 1;
        true
    });
    assert!(a.queued && a.ends_group);
    assert_eq!(asked, 1);
    // Another started it first: queued, and not this sender's exit.
    let a = qu(&sh, &raw mut q).send(10, info_for(10), true, Recipient::default(), || false);
    assert!(a.queued && !a.ends_group);
}

#[test]
fn what_is_not_fatal_at_send_time() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    // A core-dumping signal is the delivering thread's.
    assert!(!qu(&sh, &raw mut q).send(3, info_for(3), true, Recipient::default(), never).ends_group);
    // Stops and ignores are not fatal.
    assert!(!qu(&sh, &raw mut q).send(20, info_for(20), true, Recipient::default(), never).ends_group);
    // A handler.
    assert_eq!(sh.get_set(12, None, Some(&handler(0x400abc))), 0);
    assert!(!qu(&sh, &raw mut q).send(12, info_for(12), true, Recipient::default(), never).ends_group);
    // A tracer, which sees it first; and a stop, which holds it.
    let traced = Recipient { traced: true, ..Default::default() };
    assert!(!qu(&sh, &raw mut q).send(14, info_for(14), true, traced, never).ends_group);
    let stopped = Recipient { stopped: true, ..Default::default() };
    assert!(!qu(&sh, &raw mut q).send(1, info_for(1), true, stopped, never).ends_group);
    // Blocked: it waits.
    {
        let mut guard = qu(&sh, &raw mut q).lock();
        guard.queue_mut().set_blocked(kernel_sigqueue::mask_of(2));
    }
    let a = qu(&sh, &raw mut q).send(2, info_for(2), true, Recipient::default(), never);
    assert!(a.queued && !a.ends_group);
}

#[test]
fn sigkill_ends_a_traced_or_stopped_process() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    let both = Recipient { traced: true, stopped: true, unkillable: false };
    assert!(qu(&sh, &raw mut q).send(9, info_for(9), false, both, || true).ends_group);
}

/// The chosen thread's mask decides, which is how init dies of a signal its
/// leader blocks (`sigfatal_probe`).
#[test]
fn the_chosen_threads_mask_decides() {
    let sh = SigHand::new();
    let mut chosen = Signals::default();
    let a = qu(&sh, &raw mut chosen).chosen(15, true, Recipient { unkillable: true, ..Default::default() }, || true);
    assert!(a.ends_group);
    {
        let mut guard = qu(&sh, &raw mut chosen).lock();
        guard.queue_mut().set_blocked(kernel_sigqueue::mask_of(15));
    }
    let a = qu(&sh, &raw mut chosen).chosen(15, true, Recipient::default(), never);
    assert!(!a.ends_group && !a.wake);
}

/// Linux's `sig_task_ignored` for `SIGNAL_UNKILLABLE`: what init has not
/// caught is discarded, `SIGKILL` included; what it blocks or handles is not.
#[test]
fn init_discards_what_it_has_not_caught() {
    let sh = SigHand::new();
    let mut q = Signals::default();
    let init = Recipient { unkillable: true, ..Default::default() };
    assert!(!qu(&sh, &raw mut q).send(15, info_for(15), true, init, never).queued);
    assert!(!qu(&sh, &raw mut q).send(9, info_for(9), false, init, never).queued);
    assert!(!qu(&sh, &raw mut q).send_shared(19, info_for(19), false, init));
    assert_eq!(sh.get_set(10, None, Some(&handler(0x400abc))), 0);
    assert!(qu(&sh, &raw mut q).send(10, info_for(10), true, init, never).queued);
    {
        let mut guard = qu(&sh, &raw mut q).lock();
        guard.queue_mut().set_blocked(kernel_sigqueue::mask_of(15));
    }
    assert!(qu(&sh, &raw mut q).send_shared(15, info_for(15), true, init));
}
