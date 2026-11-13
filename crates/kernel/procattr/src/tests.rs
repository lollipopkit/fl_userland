//! Unit tests for process and thread attribute semantics.

use super::*;
use crate::thread::thread_name;

fn as_str(n: &[u8; 16]) -> String {
    let end = n.iter().position(|&b| b == 0).unwrap_or(n.len());
    String::from_utf8_lossy(&n[..end]).into_owned()
}

/// The ordinary case: the whole name and the pid, terminated.
#[test]
fn a_short_name_keeps_all_of_itself() {
    assert_eq!(as_str(&thread_name(b"sh", 12)), "sh-12");
    assert_eq!(as_str(&thread_name(b"", 1)), "-1");
    // Fifteen characters and a terminator is the whole budget.
    assert_eq!(as_str(&thread_name(b"abcdefghijkl", 12)).len(), 15);
}

/// The name is truncated to make room for the pid, not the other way
/// round: the pid is what tells two threads of one program apart, which is
/// the whole reason the suffix is there.
#[test]
fn the_pid_survives_a_long_name() {
    let n = thread_name(b"a-very-long-program-name", 4321);
    assert_eq!(as_str(&n), "a-very-lon-4321");
    assert!(as_str(&n).ends_with("-4321"));
    assert_eq!(as_str(&n).len(), 15);
}

/// A pid wide enough to fill the whole budget leaves nothing for the name,
/// and that is still the pid rather than a truncated one. The C computed
/// `sizeof(name) - 1 - pid_width` on a `size_t`, which for a wider pid
/// would have been about 2^64.
#[test]
fn a_very_wide_pid_takes_the_whole_name() {
    let n = thread_name(b"program", i32::MAX);
    assert_eq!(as_str(&n), "prog-2147483647");
    assert_eq!(as_str(&n).len(), 15);

    // And a negative one, which is wider still. A pid is never negative
    // here, but the arithmetic must not depend on that.
    let n = thread_name(b"program", i32::MIN);
    assert!(as_str(&n).starts_with('-') || as_str(&n).contains('-'));
    assert_eq!(as_str(&n).len(), 15);
}

/// The result is always NUL-terminated inside its sixteen bytes, which is
/// what `pthread_setname_np` requires.
#[test]
fn there_is_always_a_terminator() {
    for (comm, pid) in [
        (&b""[..], 0),
        (b"x", 1),
        (b"abcdefghijklmnopqrstuvwxyz", 999999),
        (b"abcdefghijklmno", i32::MAX),
    ] {
        let n = thread_name(comm, pid);
        assert!(n.contains(&0), "{:?} has no terminator", n);
        assert_eq!(n[15], 0);
    }
}

/// A `comm` that is already terminated stops there rather than carrying the
/// rest of the sixteen-byte field into the name.
#[test]
fn a_terminated_comm_stops_at_its_terminator() {
    let mut comm = [b'z'; 16];
    comm[2] = 0;
    assert_eq!(as_str(&thread_name(&comm, 7)), "zz-7");
}

/// The parent-death signal goes on a privileged exec and stays on an
/// ordinary one.
///
/// Otherwise an unprivileged process sets one, execs a setuid binary, and
/// the privileged program receives a signal it never asked for at a moment
/// the parent chooses by exiting.
#[test]
fn the_parent_death_signal_does_not_cross_a_privilege_boundary() {
    let mut t = ThreadAttr::default();
    t.set_pdeath_signal(9).unwrap();
    t.on_exec(false);
    assert_eq!(t.pdeath_signal(), 9, "an ordinary exec keeps it");
    t.on_exec(true);
    assert_eq!(t.pdeath_signal(), 0, "a privileged one does not");
}

/// `dumpable` comes back to `SUID_DUMP_USER` on an ordinary exec and to
/// `SUID_DUMP_DISABLE` on a privileged one.
///
/// A process that made itself dumpable and then exec'd a setuid binary
/// would otherwise stay readable by the less-privileged parent.
#[test]
fn dumpable_is_lowered_by_a_privileged_exec() {
    let p = ProcAttr::default();
    p.set_dumpable(0).unwrap();
    p.on_exec(false);
    assert_eq!(p.dumpable(), 1, "an ordinary exec restores it");
    p.set_dumpable(1).unwrap();
    p.on_exec(true);
    assert_eq!(p.dumpable(), 0, "a privileged one takes it away");
}

/// A credential change takes it away, and `PR_SET_DUMPABLE` gives it back.
#[test]
fn dumpable_is_lowered_by_an_identity_change() {
    let p = ProcAttr::default();
    p.on_identity_change();
    assert_eq!(p.dumpable(), suid_dumpable());
    p.set_dumpable(1).unwrap();
    assert_eq!(p.dumpable(), 1);
}

/// `no_new_privs` is a one-way latch: neither kind of exec clears it.
///
/// A process that set it must not be able to get out of it by exec'ing,
/// which is the whole point of the flag.
#[test]
fn no_new_privs_survives_every_exec() {
    for privileged in [false, true] {
        let mut t = ThreadAttr::default();
        t.set_no_new_privs(1, 0, 0, 0).unwrap();
        t.on_exec(privileged);
        assert!(t.no_new_privs(), "privileged={privileged}");
    }
}

/// The personality is left alone, including `ADDR_NO_RANDOMIZE`.
///
/// Linux clears four bits on a privileged exec because they weaken the
/// program that is about to gain privilege. This kernel has no
/// address-space randomisation and reports `ADDR_NO_RANDOMIZE` by default,
/// truthfully; clearing it would report that randomisation is on.
#[test]
fn the_personality_is_not_touched_by_an_exec() {
    let mut t = ThreadAttr::default();
    let before = t.personality();
    t.on_exec(true);
    assert_eq!(t.personality(), before);
}

// ------------------------------------------------------------ personality

#[test]
fn personality_query_does_not_change_anything() {
    let mut a = ThreadAttr::default();
    assert_eq!(a.set_personality(PERSONALITY_QUERY), Ok(ADDR_NO_RANDOMIZE));
    assert_eq!(a.personality(), ADDR_NO_RANDOMIZE);
}

#[test]
fn personality_answers_the_old_value_not_the_new_one() {
    // The defect this is about: returning the new value makes a
    // save-and-restore a no-op, because the caller saves what it just set.
    let mut a = ThreadAttr::default();
    let saved = a.set_personality(0).unwrap();
    assert_eq!(saved, ADDR_NO_RANDOMIZE);
    assert_eq!(a.personality(), 0);
    let back = a.set_personality(saved).unwrap();
    assert_eq!(back, 0);
    assert_eq!(a.personality(), ADDR_NO_RANDOMIZE);
}

#[test]
fn personality_accepts_values_nothing_implements() {
    let mut a = ThreadAttr::default();
    for p in [0u32, 0x0001, 0x0020_0000, 0x0040_0000, 0xffff_fffe, 0x0009] {
        assert_eq!(a.set_personality(p).map(|_| ()), Ok(()), "{p:#x}");
        assert_eq!(a.personality(), p, "{p:#x} was not stored whole");
    }
}

#[test]
fn personality_refuses_per_linux32_whatever_rides_along() {
    let mut a = ThreadAttr::default();
    for p in [PER_LINUX32, ADDR_NO_RANDOMIZE | PER_LINUX32, 0xffff_ff08] {
        assert_eq!(a.set_personality(p), Err(EINVAL), "{p:#x}");
        assert_eq!(a.personality(), ADDR_NO_RANDOMIZE, "a refusal changed it");
    }
}

#[test]
fn the_per_linux32_rule_is_about_the_whole_low_byte() {
    // 0x09 has bit 3 set and is not PER_LINUX32. A rule written as a mask
    // test rather than an equality would refuse it.
    let mut a = ThreadAttr::default();
    assert!(a.set_personality(0x0009).is_ok());
    assert_eq!(a.personality(), 0x0009);
}

// ------------------------------------------------------------------ comm

#[test]
fn comm_truncates_to_fifteen_characters_and_terminates() {
    let mut a = ThreadAttr::default();
    a.set_comm(b"0123456789abcdefghij\0");
    assert_eq!(&a.comm()[..15], b"0123456789abcde");
    assert_eq!(a.comm()[15], 0);
}

#[test]
fn comm_is_sixteen_bytes_with_the_tail_zeroed() {
    // PR_GET_NAME writes all sixteen, so what is past the terminator has to
    // be the kernel's zeroes rather than the last name that was set.
    let mut a = ThreadAttr::default();
    a.set_comm(b"0123456789abcdefghij\0");
    a.set_comm(b"short\0");
    assert_eq!(a.comm(), b"short\0\0\0\0\0\0\0\0\0\0\0");
}

#[test]
fn comm_of_a_fresh_thread_is_empty_and_terminated() {
    assert_eq!(ThreadAttr::default().comm(), &[0u8; COMM_LEN]);
}

#[test]
fn comm_with_no_terminator_in_the_input_still_terminates() {
    let mut a = ThreadAttr::default();
    a.set_comm(b"aaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(a.comm()[15], 0);
    assert_eq!(&a.comm()[..15], b"aaaaaaaaaaaaaaa");
}

#[test]
fn comm_stops_at_the_first_terminator() {
    let mut a = ThreadAttr::default();
    a.set_comm(b"ab\0cd\0");
    assert_eq!(a.comm(), b"ab\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
}

// -------------------------------------------------------------- pdeathsig

#[test]
fn pdeath_signal_range() {
    let mut a = ThreadAttr::default();
    // 0 disarms, and both sides of the bound are tested: MAX_SIG is inside
    // it, because the arrays are indexed by the number itself.
    for sig in [0u64, 1, 9, 64] {
        assert_eq!(a.set_pdeath_signal(sig), Ok(()), "{sig}");
        assert_eq!(a.pdeath_signal(), sig as i32);
    }
    for sig in [65u64, 1000, 0x1_0000_0009, u64::MAX] {
        assert_eq!(a.set_pdeath_signal(sig), Err(EINVAL), "{sig:#x}");
        assert_eq!(a.pdeath_signal(), 64, "a refusal changed it");
    }
}

#[test]
fn a_high_half_does_not_make_a_signal_number() {
    // The whole point of taking u64: `(int) 0x1_0000_0009` is 9, and 9 is a
    // signal. The value a guest passed is not.
    let mut a = ThreadAttr::default();
    assert_eq!(a.set_pdeath_signal(0x1_0000_0009), Err(EINVAL));
    assert_eq!(a.pdeath_signal(), 0);
}

// ----------------------------------------------------------- no_new_privs

#[test]
fn no_new_privs_is_one_way() {
    let mut a = ThreadAttr::default();
    assert!(!a.no_new_privs());
    assert_eq!(a.set_no_new_privs(1, 0, 0, 0), Ok(()));
    assert!(a.no_new_privs());
    // 0 is a refusal, not a clear.
    assert_eq!(a.set_no_new_privs(0, 0, 0, 0), Err(EINVAL));
    assert!(a.no_new_privs());
}

#[test]
fn no_new_privs_requires_its_other_arguments_to_be_zero() {
    let mut a = ThreadAttr::default();
    for (a2, a3, a4, a5) in [(1, 1, 0, 0), (1, 0, 1, 0), (1, 0, 0, 1), (2, 0, 0, 0)] {
        assert_eq!(
            a.set_no_new_privs(a2, a3, a4, a5),
            Err(EINVAL),
            "{a2} {a3} {a4} {a5}"
        );
        assert!(!a.no_new_privs(), "a refusal set it");
    }
    for (a2, a3, a4, a5) in [(1, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)] {
        assert_eq!(a.get_no_new_privs(a2, a3, a4, a5), Err(EINVAL));
    }
    assert_eq!(a.get_no_new_privs(0, 0, 0, 0), Ok(0));
}

// ------------------------------------------------------------ timer slack

#[test]
fn timer_slack_zero_means_the_default_the_fork_recorded() {
    let mut parent = ThreadAttr::default();
    assert_eq!(parent.timer_slack(), 50_000);
    parent.set_timer_slack(100_000);
    assert_eq!(parent.timer_slack(), 100_000);
    parent.set_timer_slack(0);
    assert_eq!(
        parent.timer_slack(),
        50_000,
        "a fresh process's default is 50 µs"
    );

    parent.set_timer_slack(7);
    let mut child = parent; // the struct copy a fork makes
    child.on_fork();
    child.set_timer_slack(u64::MAX);
    assert_eq!(child.timer_slack(), u64::MAX, "no value is refused");
    child.set_timer_slack(0);
    assert_eq!(
        child.timer_slack(),
        7,
        "the child's default is what the parent had at the fork"
    );
    parent.set_timer_slack(0);
    assert_eq!(
        parent.timer_slack(),
        50_000,
        "and the parent's is still its own"
    );
}

// ------------------------------------------------------------------- mce

#[test]
fn mce_kill_is_a_two_level_switch() {
    let mut a = ThreadAttr::default();
    assert_eq!(a.mce_kill_get(0, 0, 0, 0), Ok(2), "DEFAULT until set");
    assert_eq!(a.mce_kill(mce::KILL_SET, mce::KILL_EARLY, 0, 0), Ok(()));
    assert_eq!(a.mce_kill_get(0, 0, 0, 0), Ok(1));
    assert_eq!(a.mce_kill(mce::KILL_SET, mce::KILL_LATE, 0, 0), Ok(()));
    assert_eq!(a.mce_kill_get(0, 0, 0, 0), Ok(0));
    assert_eq!(a.mce_kill(mce::KILL_SET, mce::KILL_DEFAULT, 0, 0), Ok(()));
    assert_eq!(a.mce_kill_get(0, 0, 0, 0), Ok(2));
    assert_eq!(a.mce_kill(mce::KILL_SET, mce::KILL_EARLY, 0, 0), Ok(()));
    assert_eq!(a.mce_kill(mce::KILL_CLEAR, 0, 0, 0), Ok(()));
    assert_eq!(a.mce_kill_get(0, 0, 0, 0), Ok(2), "CLEAR is DEFAULT");
    // The refusals.
    assert_eq!(a.mce_kill(mce::KILL_CLEAR, 1, 0, 0), Err(EINVAL));
    assert_eq!(a.mce_kill(mce::KILL_SET, 3, 0, 0), Err(EINVAL));
    assert_eq!(a.mce_kill(2, 0, 0, 0), Err(EINVAL));
    assert_eq!(a.mce_kill(mce::KILL_SET, 0, 1, 0), Err(EINVAL));
    assert_eq!(a.mce_kill(mce::KILL_SET, 0, 0, 1), Err(EINVAL));
    assert_eq!(a.mce_kill_get(1, 0, 0, 0), Err(EINVAL));
}

// ------------------------------------------------------------ io flusher

#[test]
fn io_flusher_asks_for_the_capability_before_the_arguments() {
    let mut a = ThreadAttr::default();
    assert_eq!(
        a.set_io_flusher(7, 0, 0, 0, false),
        Err(EPERM),
        "EPERM before EINVAL"
    );
    assert_eq!(a.io_flusher(1, 0, 0, 0, false), Err(EPERM));
    assert_eq!(a.set_io_flusher(7, 0, 0, 0, true), Err(EINVAL));
    assert_eq!(a.set_io_flusher(1, 0, 1, 0, true), Err(EINVAL));
    assert_eq!(a.io_flusher(0, 0, 0, 0, true), Ok(0));
    assert_eq!(a.set_io_flusher(1, 0, 0, 0, true), Ok(()));
    assert_eq!(a.io_flusher(0, 0, 0, 0, true), Ok(1));
    assert_eq!(a.io_flusher(1, 0, 0, 0, true), Err(EINVAL));
    assert_eq!(a.set_io_flusher(0, 0, 0, 0, true), Ok(()));
    assert_eq!(a.io_flusher(0, 0, 0, 0, true), Ok(0));
}

// ------------------------------------------------------------ speculation

#[test]
fn speculation_control_answers_for_store_bypass_only() {
    let mut a = ThreadAttr::default();
    assert_eq!(
        a.spec_ctrl_get(spec::STORE_BYPASS, 0, 0, 0),
        Ok(spec::ENABLE as c_int)
    );
    assert_eq!(a.spec_ctrl_get(1, 0, 0, 0), Err(ENODEV), "indirect branch");
    assert_eq!(a.spec_ctrl_get(2, 0, 0, 0), Err(ENODEV), "l1d flush");
    assert_eq!(a.spec_ctrl_get(spec::STORE_BYPASS, 1, 0, 0), Err(EINVAL));
    assert_eq!(a.spec_ctrl_set(1, spec::ENABLE, 0, 0), Err(ENODEV));
    assert_eq!(
        a.spec_ctrl_set(spec::STORE_BYPASS, spec::ENABLE, 1, 0),
        Err(EINVAL)
    );
    assert_eq!(
        a.spec_ctrl_set(spec::STORE_BYPASS, 99, 0, 0),
        Err(ERANGE),
        "not EINVAL"
    );
    assert_eq!(a.spec_ctrl_set(spec::STORE_BYPASS, 0, 0, 0), Err(ERANGE));
}

/// What is asked for is kept for the rules about asking again, and none
/// of it is reported: the answer is "vulnerable" throughout.
#[test]
fn a_forced_disable_is_for_ever() {
    let mut a = ThreadAttr::default();
    let get = |a: &ThreadAttr| a.spec_ctrl_get(spec::STORE_BYPASS, 0, 0, 0).unwrap() as u64;
    a.spec_ctrl_set(spec::STORE_BYPASS, spec::DISABLE, 0, 0)
        .unwrap();
    assert_eq!(
        get(&a),
        spec::ENABLE,
        "a disable is not reported as a mitigation"
    );
    assert_eq!(a.ssb_for_test(), spec::SSB_DISABLE);
    a.spec_ctrl_set(spec::STORE_BYPASS, spec::ENABLE, 0, 0)
        .unwrap();
    assert_eq!(a.ssb_for_test(), 0, "a plain disable can be undone");
    a.spec_ctrl_set(spec::STORE_BYPASS, spec::DISABLE_NOEXEC, 0, 0)
        .unwrap();
    assert_eq!(a.ssb_for_test(), spec::SSB_DISABLE | spec::SSB_NOEXEC);
    a.on_exec(false);
    assert_eq!(a.ssb_for_test(), 0, "and until-exec means until exec");
    a.spec_ctrl_set(spec::STORE_BYPASS, spec::FORCE_DISABLE, 0, 0)
        .unwrap();
    assert_eq!(
        a.ssb_for_test(),
        spec::SSB_DISABLE | spec::SSB_FORCE_DISABLE
    );
    assert_eq!(get(&a), spec::ENABLE);
    assert_eq!(
        a.spec_ctrl_set(spec::STORE_BYPASS, spec::ENABLE, 0, 0),
        Err(EPERM)
    );
    assert_eq!(
        a.spec_ctrl_set(spec::STORE_BYPASS, spec::DISABLE_NOEXEC, 0, 0),
        Err(EPERM)
    );
    assert_eq!(
        a.spec_ctrl_set(spec::STORE_BYPASS, spec::DISABLE, 0, 0),
        Ok(()),
        "asking for less is fine"
    );
    a.on_exec(true);
    assert_eq!(
        a.ssb_for_test() & spec::SSB_FORCE_DISABLE,
        spec::SSB_FORCE_DISABLE,
        "an exec does not lift a forced disable"
    );
}

// ----------------------------------------------------- the stateless ones

#[test]
fn timing_has_one_value() {
    assert_eq!(set_timing(0), Ok(()));
    assert_eq!(set_timing(1), Err(EINVAL));
    assert_eq!(set_timing(u64::MAX), Err(EINVAL));
}

#[test]
fn tagged_addresses_are_disabled_the_way_the_sysctl_disables_them() {
    assert_eq!(tagged_addr_ctrl_get(0, 0, 0, 0), Ok(0));
    assert_eq!(tagged_addr_ctrl_get(1, 0, 0, 0), Err(EINVAL));
    assert_eq!(
        tagged_addr_ctrl_set(0, 0, 0, 0),
        Ok(()),
        "asking for off is fine"
    );
    assert_eq!(
        tagged_addr_ctrl_set(1, 0, 0, 0),
        Err(EINVAL),
        "asking for on is not"
    );
    assert_eq!(
        tagged_addr_ctrl_set(2, 0, 0, 0),
        Err(EINVAL),
        "an MTE bit, which a CPU without MTE refuses too"
    );
    assert_eq!(tagged_addr_ctrl_set(0, 1, 0, 0), Err(EINVAL));
}

#[test]
fn the_counter_is_readable_and_cannot_be_made_to_trap() {
    assert_eq!(set_tsc(1), Ok(()));
    assert_eq!(set_tsc(2), Err(EINVAL), "PR_TSC_SIGSEGV");
    assert_eq!(set_tsc(0), Err(EINVAL));
}

#[test]
fn set_mm_refuses_in_linuxs_order() {
    assert_eq!(
        set_mm(1, 0, 1, false),
        Err(EINVAL),
        "arg5 before the capability"
    );
    assert_eq!(
        set_mm(1, 1, 0, false),
        Err(EINVAL),
        "arg4 too, for an option that takes none"
    );
    assert_eq!(
        set_mm(12, 1, 0, false),
        Err(EPERM),
        "PR_SET_MM_AUXV takes arg4"
    );
    assert_eq!(set_mm(1, 0, 0, false), Err(EPERM));
    assert_eq!(set_mm(1, 0, 0, true), Err(EINVAL));
    assert_eq!(set_mm(99, 0, 0, true), Err(EINVAL));
}

// --------------------------------------------------------------- dumpable

#[test]
fn dumpable_refuses_suid_dump_root() {
    let a = ProcAttr::default();
    assert_eq!(a.dumpable(), 1);
    assert_eq!(a.set_dumpable(0), Ok(()));
    assert_eq!(a.dumpable(), 0);
    assert_eq!(a.set_dumpable(1), Ok(()));
    assert_eq!(a.dumpable(), 1);
    // 2 is SUID_DUMP_ROOT, which the kernel sets for itself.
    for v in [2u64, 3, 0x1_0000_0001, u64::MAX] {
        assert_eq!(a.set_dumpable(v), Err(EINVAL), "{v:#x}");
        assert_eq!(a.dumpable(), 1, "a refusal changed it");
    }
}

// -------------------------------------------------------- child_subreaper

#[test]
fn child_subreaper_is_the_truth_of_its_argument() {
    let a = ProcAttr::default();
    assert!(!a.child_subreaper());
    a.set_child_subreaper(7);
    assert!(a.child_subreaper(), "any non-zero sets it");
    a.set_child_subreaper(0);
    assert!(!a.child_subreaper());
    a.set_child_subreaper(u64::MAX);
    assert!(a.child_subreaper());
}

// ------------------------------------------------------------ inheritance

#[test]
fn a_child_inherits_by_being_copied() {
    // Which is how `struct task` makes one: the parent is assigned over the
    // child and then the fields that must not be shared are undone. These
    // are not among them -- fork inherits all of them on Linux.
    let mut parent = ThreadAttr::default();
    parent.set_comm(b"parent\0");
    parent.set_personality(0x1234_5600).unwrap();
    parent.set_pdeath_signal(9).unwrap();
    let child = parent;
    assert_eq!(child, parent);
    // And they are independent afterwards: this is plain data, not a
    // pointer to something shared.
    let mut child = child;
    child.set_comm(b"child\0");
    assert_eq!(&parent.comm()[..6], b"parent");
    assert_eq!(&child.comm()[..5], b"child");
}

// ------------------------------------------------------------- the sizes

// ----------------------------------------------------------------- ioprio

#[test]
fn a_fresh_task_has_no_io_priority() {
    assert_eq!(ThreadAttr::default().ioprio(), 0);
}

#[test]
fn ioprio_class_none_carries_no_level() {
    let mut a = ThreadAttr::default();
    for v in [1u32, 2, 7, 15, 8191] {
        assert_eq!(a.set_ioprio(v, false), Err(EINVAL), "{v}");
        assert_eq!(a.ioprio(), 0, "a refusal changed it");
    }
}

#[test]
fn the_level_is_three_bits_and_not_the_range_the_man_page_describes() {
    // 8 has a *level* of zero once the low three bits are taken, so
    // IOPRIO_CLASS_NONE accepts it -- while 7 and 15, which a `level > 7`
    // rule would let through and refuse respectively, go the other way.
    let mut a = ThreadAttr::default();
    assert_eq!(a.set_ioprio(8, false), Ok(()));
    assert_eq!(a.ioprio(), 8);
    assert_eq!(a.set_ioprio(7, false), Err(EINVAL));
    assert_eq!(a.set_ioprio(15, false), Err(EINVAL));
    assert_eq!(a.set_ioprio(16, false), Ok(()), "16 & 7 is 0");
}

#[test]
fn best_effort_and_idle_take_any_level() {
    let mut a = ThreadAttr::default();
    for class in [IOPRIO_CLASS_BE, IOPRIO_CLASS_IDLE] {
        for level in [0u32, 4, 7, 8, 8191] {
            let v = (class << IOPRIO_CLASS_SHIFT) | level;
            assert_eq!(a.set_ioprio(v, false), Ok(()), "{v:#x}");
            assert_eq!(a.ioprio(), v as i32, "{v:#x} was not stored whole");
        }
    }
}

#[test]
fn realtime_needs_privilege_and_an_unknown_class_is_refused() {
    let mut a = ThreadAttr::default();
    let rt = (IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT) | 4;
    assert_eq!(a.set_ioprio(rt, false), Err(EPERM));
    assert_eq!(a.ioprio(), 0);
    assert_eq!(a.set_ioprio(rt, true), Ok(()));
    assert_eq!(a.ioprio(), rt as i32);
    // Class 4..7. EINVAL whether or not the caller is privileged -- a
    // class that does not exist is not a permission question.
    for class in 4u32..=7 {
        let v = class << IOPRIO_CLASS_SHIFT;
        assert_eq!(a.set_ioprio(v, true), Err(EINVAL), "{class}");
        assert_eq!(a.set_ioprio(v, false), Err(EINVAL), "{class}");
    }
}

#[test]
fn a_priority_can_be_judged_without_a_task_to_put_it_on() {
    // Which is the whole reason this exists: Linux judges it before it
    // resolves `who`, so a bad priority at a dead pid is EINVAL and not
    // ESRCH.
    assert_eq!(
        ioprio_check((IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4, false),
        Ok(())
    );
    assert_eq!(ioprio_check(7, false), Err(EINVAL));
    assert_eq!(ioprio_check(6 << IOPRIO_CLASS_SHIFT, true), Err(EINVAL));
    assert_eq!(
        ioprio_check(IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT, false),
        Err(EPERM)
    );
    assert_eq!(
        ioprio_check(IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT, true),
        Ok(())
    );
}

#[test]
fn which_is_checked_before_anything_else() {
    assert!(ioprio_which_valid(1) && ioprio_which_valid(2) && ioprio_which_valid(3));
    for w in [i32::MIN, -1, 0, 4, 99, i32::MAX] {
        assert!(!ioprio_which_valid(w), "{w}");
    }
}

#[test]
fn the_group_fold_substitutes_a_default_for_a_task_with_none() {
    // Which is why ioprio_get answers 0 for one task that has never set one
    // and 0x4004 for the group it is in.
    let be4 = IOPRIO_BEST_DEFAULT;
    assert_eq!(ioprio_best(0, 0), be4);
    assert_eq!(ioprio_best(be4, 0), be4);
    // Lower is higher priority, so a real-time task wins over a default.
    let rt = ((IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT) | 4) as i32;
    assert_eq!(ioprio_best(rt, 0), rt);
    assert_eq!(ioprio_best(0, rt), rt);
    // And idle loses to it.
    let idle = (IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT) as i32;
    assert_eq!(ioprio_best(idle, be4), be4);
    // A class nothing defines is not better than the default either.
    let bogus = ((6u32 << IOPRIO_CLASS_SHIFT) | 1) as i32;
    assert_eq!(ioprio_best(bogus, be4), be4);
}

#[test]
fn the_sizes_the_c_declares_are_these() {
    // `struct task` embeds both by value. They were opaque byte arrays
    // in the C with a static_assert pinning each, because C had to
    // reserve space for a struct it could not see; it embeds these types
    // themselves since 2026-09-05, so what is left is a record of how
    // large they got.
    assert_eq!(std::mem::size_of::<ThreadAttr>(), 48);
    assert_eq!(std::mem::size_of::<ProcAttr>(), 8);
    // And the alignment, which is the half `struct groups` next door got
    // wrong: it is `[u32; 32] + u32` and wants four, the C declared it as
    // an array of `unsigned char` which wants one, and it landed aligned
    // only because every field above it happens to be four bytes wide.
    assert_eq!(std::mem::align_of::<ThreadAttr>(), 8);
    assert_eq!(std::mem::align_of::<ProcAttr>(), 4);
}

/* `a_null_attribute_is_refused_rather_than_dereferenced` was here. Its subject
 * was the null check in each of the sixteen raw-pointer entry points -- "every
 * C entry point takes a raw pointer, and returning EINVAL is cheaper than
 * trusting the caller" -- and there are no raw-pointer entry points left as of
 * 2026-09-16. A `&mut ThreadAttr` cannot be null, so the case it covered is not
 * reachable and not expressible; deleted rather than rewritten, because a test
 * that constructs what it is testing against is a test that agrees with
 * itself. */
