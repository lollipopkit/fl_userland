use super::*;

#[test]
fn the_ignore_set_is_exactly_four() {
    // Linux's SIG_KERNEL_IGNORE_MASK. SIGIO was a fifth here, so a process
    // with no handler for it survived a signal that should have killed it.
    let ignored: Vec<c_int> = (1..=MAX_SIG)
        .filter(|&s| default_action(s) == Default_::Ignore)
        .collect();
    assert_eq!(ignored, vec![SIGCHLD, SIGCONT, SIGURG, SIGWINCH]);
}

#[test]
fn the_stop_set_is_exactly_four() {
    let stopping: Vec<c_int> = (1..=MAX_SIG)
        .filter(|&s| default_action(s) == Default_::Stop)
        .collect();
    assert_eq!(stopping, vec![SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU]);
}

#[test]
fn the_core_set_is_exactly_ten_and_all_terminate() {
    // SIGQUIT SIGILL SIGTRAP SIGABRT SIGBUS SIGFPE SIGSEGV SIGXCPU SIGXFSZ
    // SIGSYS: Linux's SIG_KERNEL_COREDUMP_MASK on arm64, which has no SIGEMT.
    let core: Vec<c_int> = (1..=MAX_SIG).filter(|&s| dumps_core(s)).collect();
    assert_eq!(core, vec![3, 4, 5, 6, 7, 8, 11, 24, 25, 31]);
    assert!(core.iter().all(|&s| default_action(s) == Default_::Terminate));
}

#[test]
fn sigio_terminates() {
    assert_eq!(default_action(29), Default_::Terminate);
}

#[test]
fn every_other_signal_terminates() {
    for sig in 1..=MAX_SIG {
        if matches!(
            sig,
            SIGCHLD | SIGCONT | SIGURG | SIGWINCH | SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU
        ) {
            continue;
        }
        assert_eq!(default_action(sig), Default_::Terminate, "signal {sig}");
    }
}

#[test]
fn valid_covers_one_to_sixty_four() {
    assert!(!valid(0));
    assert!(valid(1));
    assert!(valid(64), "SIGRTMAX is a signal");
    assert!(!valid(65));
    assert!(!valid(-1), "a dword_t with the top bit set arrives as this");
    assert!(!valid(c_int::MIN));
}

#[test]
fn kill_and_stop_may_be_read_and_not_written() {
    for sig in [SIGKILL, SIGSTOP] {
        assert!(
            Table::may_change(sig, false),
            "signal {sig} may be asked about"
        );
        assert!(!Table::may_change(sig, true), "signal {sig} may not be set");
    }
    assert!(Table::may_change(10, true));
    assert!(
        !Table::may_change(0, false),
        "and 0 is not a signal either way"
    );
    assert!(!Table::may_change(65, false));
}

#[test]
fn the_unblockable_are_dropped_without_an_error() {
    let all = u64::MAX;
    let m = maskable(all);
    assert_eq!(m & (1 << (SIGKILL - 1)), 0);
    assert_eq!(m & (1 << (SIGSTOP - 1)), 0);
    assert_eq!(
        m | (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1)),
        all,
        "and nothing else is touched"
    );
}

#[test]
fn an_empty_table_is_all_default() {
    let t = Table::new();
    for sig in 1..=MAX_SIG {
        assert_eq!(t.handler(sig), SIG_DFL, "signal {sig}");
    }
    assert_eq!(t.get(0), None);
    assert_eq!(t.get(65), None);
    assert_eq!(t.handler(65), SIG_DFL, "and a bad number reads as default");
}

#[test]
fn what_is_set_is_what_is_read() {
    let mut t = Table::new();
    let d = Disposition {
        handler: 0x400000,
        flags: SA_ONSTACK,
        restorer: 0x500000,
        mask: 0xff,
    };
    assert!(t.set(10, d));
    assert_eq!(t.get(10), Some(d));
    assert_eq!(t.handler(10), 0x400000);
    assert!(!t.set(0, d));
    assert!(!t.set(65, d));
}

#[test]
fn the_action_for_a_signal_follows_its_disposition() {
    let mut t = Table::new();
    // Default: the table decides.
    assert_eq!(t.action(29), Action::Terminate, "SIGIO terminates");
    assert_eq!(t.action(SIGCHLD), Action::Ignore, "SIGCHLD is ignored");
    assert_eq!(t.action(SIGTSTP), Action::Stop, "SIGTSTP stops");
    // Ignored and handled.
    let ign = Disposition {
        handler: SIG_IGN,
        ..Disposition::default()
    };
    assert!(t.set(29, ign));
    assert_eq!(t.action(29), Action::Ignore);
    let h = Disposition {
        handler: 0x400000,
        ..Disposition::default()
    };
    assert!(t.set(29, h));
    assert_eq!(t.action(29), Action::Handler);
    // SIGKILL cannot be talked out of anything, even when the table says
    // otherwise. `set` *accepts* it -- the rule that refuses an install is
    // `may_change`, which the syscall applies and the table does not -- so
    // this is the second line of defence, and the one delivery relies on.
    assert!(t.set(SIGKILL, ign), "the table stores what it is told");
    assert_eq!(
        t.action(SIGKILL),
        Action::Terminate,
        "and delivery ignores it"
    );
    assert!(t.set(SIGSTOP, ign));
    assert_eq!(t.action(SIGSTOP), Action::Stop);
}

#[test]
fn exec_keeps_ignored_and_drops_handlers() {
    // A handler cannot survive: the code is gone. An ignored signal stays
    // ignored, which is how a shell hands SIGINT to a child it does not
    // want interrupted.
    let mut t = Table::new();
    t.set(
        2,
        Disposition {
            handler: 0x400000,
            flags: 7,
            restorer: 9,
            mask: 3,
        },
    );
    t.set(
        10,
        Disposition {
            handler: SIG_IGN,
            flags: 7,
            restorer: 9,
            mask: 3,
        },
    );
    t.on_exec();
    assert_eq!(t.handler(2), SIG_DFL, "the handler is gone");
    assert_eq!(t.handler(10), SIG_IGN, "and the ignore stays");
    let flags = t.get(10).unwrap().flags;
    assert_eq!(flags, 0, "with nothing else carried over");
}

#[test]
fn the_altstack_bounds_are_exclusive_below_and_inclusive_above() {
    // A stack grows down, so a freshly switched sp is one past the end.
    let mut s = AltStack::default();
    s.set(0x1000, 0x2000, 0, 0).unwrap();
    assert!(!s.contains(0x1000), "the base is not on it");
    assert!(s.contains(0x1001));
    assert!(s.contains(0x3000), "one past the end is");
    assert!(!s.contains(0x3001));
    assert!(!s.contains(0));
}

#[test]
fn nothing_is_on_a_stack_that_is_not_there() {
    let s = AltStack::default();
    assert!(!s.contains(0));
    assert!(!s.contains(0x1000));
    assert!(!s.should_switch(SA_ONSTACK, 0x1000));
}

#[test]
fn switching_needs_the_flag_and_needs_not_to_be_there_already() {
    // Switching whenever an alternate stack merely existed is a bug this
    // tree has had: JSC installs one for SIGSEGV and registers its other
    // handlers without SA_ONSTACK.
    let mut s = AltStack::default();
    s.set(0x1000, 0x2000, 0, 0).unwrap();
    assert!(
        s.should_switch(SA_ONSTACK, 0x90000),
        "asked for, and not on it"
    );
    assert!(!s.should_switch(0, 0x90000), "not asked for");
    assert!(!s.should_switch(SA_ONSTACK, 0x2000), "already on it");
}

#[test]
fn sigaltstack_reports_disabled_and_onstack() {
    let mut s = AltStack::default();
    assert_eq!(s.report(0x90000), (0, 0, SS_DISABLE));
    s.set(0x1000, 0x2000, 0, 0).unwrap();
    assert_eq!(s.report(0x90000), (0x1000, 0x2000, 0));
    assert_eq!(s.report(0x2000), (0x1000, 0x2000, SS_ONSTACK));
}

#[test]
fn a_stack_too_small_is_refused_and_changes_nothing() {
    let mut s = AltStack::default();
    s.set(0x1000, MINSIGSTKSZ, 0, 0).unwrap();
    assert_eq!(s.set(0x5000, MINSIGSTKSZ - 1, 0, 0), Err(-12));
    assert_eq!(
        s.bounds(),
        (0x1000, MINSIGSTKSZ),
        "the old one is still there"
    );
}

#[test]
fn disabling_ignores_the_size() {
    let mut s = AltStack::default();
    s.set(0x1000, MINSIGSTKSZ, 0, 0).unwrap();
    assert_eq!(s.set(0, 0, SS_DISABLE, 0x90000), Ok(()));
    assert_eq!(s.bounds(), (0, 0));
}

#[test]
fn it_cannot_be_changed_from_a_handler_running_on_it() {
    // The frame under the handler is on that stack.
    let mut s = AltStack::default();
    s.set(0x1000, 0x2000, 0, 0).unwrap();
    assert_eq!(s.set(0x9000, MINSIGSTKSZ, 0, 0x2000), Err(-1));
    assert_eq!(
        s.set(0, 0, SS_DISABLE, 0x2000),
        Err(-1),
        "not even to disable it"
    );
    assert_eq!(s.bounds(), (0x1000, 0x2000));
}

#[test]
fn a_new_thread_and_an_exec_both_start_with_none() {
    // Linux's copy_process resets it under CLONE_VM without CLONE_VFORK,
    // and flush_signal_handlers on exec. Two methods rather than one so
    // that a caller says which it means, but the same answer.
    let mut s = AltStack::default();
    s.set(0x1000, 0x2000, 0, 0).unwrap();
    s.on_new_thread();
    assert_eq!(s.bounds(), (0, 0));

    s.set(0x1000, 0x2000, 0, 0).unwrap();
    s.on_exec();
    assert_eq!(s.bounds(), (0, 0));
}

// `a_null_table_answers_rather_than_faulting` was here. It checked that the
// C ABI's entry points survived a null `struct sigdisp *`, which every one
// of them could be handed. There is no C ABI any more -- the callers hold a
// `&Table` that `crates/kernel/sighand` hands out from inside its lock --
// so a null table is not a value that can be constructed, which is a better
// answer than a test.
