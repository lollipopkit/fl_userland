use super::*;

fn lim(cur: u64, max: u64) -> Rlimit {
    Rlimit { cur, max }
}

#[test]
fn every_resource_number_and_no_others() {
    for r in 0..NLIMITS {
        assert!(resource_valid(r), "{r}");
    }
    for r in [NLIMITS, NLIMITS + 1, 100, u32::MAX] {
        assert!(!resource_valid(r), "{r}");
    }
}

/// A soft limit above the hard one is EINVAL for root as well. This is the
/// case that had no check: it is not a permission question.
#[test]
fn a_soft_limit_above_the_hard_one_is_refused_even_for_root() {
    for sys_resource in [true, false] {
        assert_eq!(
            check_set(sys_resource, lim(10, 5), lim(0, INFINITY)),
            Err(EINVAL)
        );
    }
}

#[test]
fn raising_the_hard_limit_needs_privilege_and_lowering_never_does() {
    let old = lim(100, 100);
    assert_eq!(check_set(false, lim(100, 200), old), Err(EPERM));
    assert_eq!(check_set(true, lim(100, 200), old), Ok(()));
    // Lowering, and lowering to nothing, are both fine unprivileged.
    assert_eq!(check_set(false, lim(50, 50), old), Ok(()));
    assert_eq!(check_set(false, lim(0, 0), old), Ok(()));
    // Equal is not raising.
    assert_eq!(check_set(false, lim(100, 100), old), Ok(()));
}

/// A hard limit an unprivileged caller lowered cannot be raised again --
/// which is the entire purpose of a hard limit. Sweeping rather than
/// sampling: after any accepted unprivileged set, the new max is <= the old.
#[test]
fn an_unprivileged_hard_limit_only_ever_falls() {
    for old_max in [0u64, 1, 64, 1024, INFINITY] {
        for new_max in [0u64, 1, 64, 1024, INFINITY] {
            for new_cur in [0u64, 1, 64, 1024, INFINITY] {
                let r = check_set(false, lim(new_cur, new_max), lim(0, old_max));
                if r.is_ok() {
                    assert!(new_max <= old_max, "{new_max} > {old_max} was accepted");
                    assert!(new_cur <= new_max, "cur {new_cur} > max {new_max}");
                }
            }
        }
    }
}

/// INFINITY is a value like any other, and is the largest: an unprivileged
/// caller may not reach it from anything smaller, and may always leave it.
#[test]
fn infinity_is_the_top_of_the_order() {
    assert_eq!(
        check_set(false, lim(INFINITY, INFINITY), lim(0, 1024)),
        Err(EPERM)
    );
    assert_eq!(check_set(false, lim(1024, 1024), lim(0, INFINITY)), Ok(()));
    assert_eq!(
        check_set(false, lim(INFINITY, INFINITY), lim(0, INFINITY)),
        Ok(())
    );
    // cur = INFINITY with a finite max is still incoherent.
    assert_eq!(
        check_set(true, lim(INFINITY, 1024), lim(0, INFINITY)),
        Err(EINVAL)
    );
}

#[test]
fn nice_clamps_rather_than_refusing() {
    assert_eq!(clamp_nice(0), 0);
    assert_eq!(clamp_nice(-20), -20);
    assert_eq!(clamp_nice(19), 19);
    assert_eq!(clamp_nice(-1000), -20);
    assert_eq!(clamp_nice(1000), 19);
    assert_eq!(clamp_nice(i32::MIN), -20);
    assert_eq!(clamp_nice(i32::MAX), 19);
}

/// The encoding is what keeps a successful getpriority from looking like an
/// error: over the whole nice range the answer is 1..=40, never 0 and never
/// negative.
#[test]
fn getpriority_never_returns_something_that_looks_like_an_errno() {
    for nice in NICE_MIN..=NICE_MAX {
        let r = to_getpriority(nice);
        assert!((1..=40).contains(&r), "nice {nice} -> {r}");
    }
    assert_eq!(to_getpriority(0), 20);
    assert_eq!(to_getpriority(19), 1);
    assert_eq!(to_getpriority(-20), 40);
}

/// And it round-trips, so a program that reads, adjusts and writes back
/// lands where it meant to.
#[test]
fn the_encoding_round_trips() {
    for nice in NICE_MIN..=NICE_MAX {
        assert_eq!(20 - to_getpriority(nice), nice);
    }
}

#[test]
fn root_may_do_anything_to_anyone() {
    for prio in [-20, 0, 19] {
        assert_eq!(
            may_set_priority(true, 0, Some((1000, 1000)), prio, 0),
            Ok(())
        );
    }
}

#[test]
fn not_your_process_is_eperm_and_going_faster_is_eacces() {
    // Someone else's process: EPERM, whatever the nice value.
    assert_eq!(
        may_set_priority(false, 1000, Some((1001, 1001)), 19, 0),
        Err(EPERM)
    );
    assert_eq!(
        may_set_priority(false, 1000, Some((1001, 1001)), -5, 0),
        Err(EPERM)
    );
    // Your own, giving away priority: fine.
    assert_eq!(
        may_set_priority(false, 1000, Some((1000, 1000)), 10, 0),
        Ok(())
    );
    // Your own, taking priority back: EACCES, a different answer.
    assert_eq!(
        may_set_priority(false, 1000, Some((1000, 1000)), -1, 0),
        Err(EACCES)
    );
    assert_eq!(
        may_set_priority(false, 1000, Some((1000, 1000)), 5, 10),
        Err(EACCES)
    );
    // Matching either the real or the effective uid is enough.
    assert_eq!(
        may_set_priority(false, 1000, Some((1000, 0)), 10, 0),
        Ok(())
    );
    assert_eq!(
        may_set_priority(false, 1000, Some((0, 1000)), 10, 0),
        Ok(())
    );
}

/// Ownership is checked before the nice value, so "not your process" is not
/// reported as "not allowed to go faster" -- the two are distinguishable,
/// which is the reason Linux uses two errnos.
#[test]
fn ownership_is_reported_before_the_nice_value() {
    assert_eq!(
        may_set_priority(false, 1000, Some((1001, 1001)), -20, 19),
        Err(EPERM)
    );
}

/// Access does not imply the right to raise: an unprivileged caller that may
/// reach a process (`kernel_creds::Creds::may_prlimit`) still cannot lift a
/// hard limit.
#[test]
fn reaching_a_process_is_not_permission_to_raise_its_hard_limit() {
    assert_eq!(check_set(false, lim(0, 4096), lim(0, 1024)), Err(EPERM));
}

/// Nice is never *lowered* by an unprivileged caller, over the whole range.
/// A single-direction property, so a rule written backwards cannot pass.
#[test]
fn an_unprivileged_caller_never_lowers_a_nice_value() {
    for target_nice in NICE_MIN..=NICE_MAX {
        for prio in NICE_MIN..=NICE_MAX {
            let r = may_set_priority(false, 7, Some((7, 7)), prio, target_nice);
            if r.is_ok() {
                assert!(prio >= target_nice, "{prio} < {target_nice} was accepted");
            }
        }
    }
}

#[cfg(test)]
mod limits_tests {
    use super::*;

    #[test]
    fn every_resource_has_a_default() {
        // The property the memcpy-from-a-table version could not have: a
        // resource nobody named would have been {0, 0}, a hard limit of zero,
        // which refuses everything and looks deliberate.
        let l = Limits::defaults(32768);
        for r in 0..NLIMITS {
            let v = l.get(r).expect("resource {r} has no entry");
            assert!(
                v.cur <= v.max,
                "resource {r} has a soft limit above its hard one"
            );
        }
    }

    #[test]
    fn the_defaults_are_what_a_guest_expects() {
        let l = Limits::defaults(32768);
        assert_eq!(
            l.get(NPROC),
            Some(Rlimit {
                cur: 32768,
                max: 32768
            })
        );
        assert_eq!(
            l.get(NOFILE),
            Some(Rlimit {
                cur: 1024,
                max: 4096
            })
        );
        assert_eq!(
            l.get(CORE),
            Some(Rlimit {
                cur: 0,
                max: INFINITY
            }),
            "no core dumps, but nothing stopping a guest raising it"
        );
        assert_eq!(
            l.get(STACK),
            Some(Rlimit {
                cur: 128 * 1024 * 1024,
                max: INFINITY
            })
        );
        assert_eq!(
            l.get(CPU),
            Some(Rlimit {
                cur: INFINITY,
                max: INFINITY
            })
        );
        assert_eq!(
            l.get(NICE),
            Some(Rlimit { cur: 0, max: 0 }),
            "this kernel implements SCHED_OTHER only"
        );
    }

    #[test]
    fn a_resource_that_does_not_exist() {
        let l = Limits::defaults(32768);
        assert_eq!(l.get(NLIMITS), None);
        assert_eq!(l.get(u32::MAX), None);
        assert!(!l.set(NLIMITS, Rlimit { cur: 1, max: 1 }));
        assert!(!l.set(u32::MAX, Rlimit { cur: 1, max: 1 }));
    }

    #[test]
    fn what_is_set_is_what_is_read() {
        let l = Limits::defaults(32768);
        assert!(l.set(NOFILE, Rlimit { cur: 7, max: 9 }));
        assert_eq!(l.get(NOFILE), Some(Rlimit { cur: 7, max: 9 }));
        assert_eq!(
            l.get(NPROC),
            Some(Rlimit {
                cur: 32768,
                max: 32768
            }),
            "and nothing else moved"
        );
    }

    #[test]
    fn a_clone_is_a_copy() {
        let a = Limits::defaults(32768);
        a.set(NOFILE, Rlimit { cur: 7, max: 9 });
        let b = a.clone();
        a.set(NOFILE, Rlimit { cur: 1, max: 1 });
        assert_eq!(b.get(NOFILE), Some(Rlimit { cur: 7, max: 9 }));
    }

    /// What `the_pointer_api_round_trips` checked, without the pointer.
    ///
    /// It drove `Limits` through `rlimits_get`/`rlimits_set` until 2026-09-16 —
    /// an out parameter, an errno, and a null table. Two of its assertions went
    /// with those: "a refusal writes nothing" was about the out-parameter being
    /// left alone, which a `None` cannot fail to do, and "a null table answers"
    /// was about a pointer no caller could produce. The rest are about the
    /// table and are kept.
    #[test]
    fn a_resource_that_is_not_one_is_refused_and_a_copy_is_independent() {
        let limits = Limits::defaults(32768);
        assert_eq!(
            limits.get(NOFILE),
            Some(Rlimit {
                cur: 1024,
                max: 4096
            })
        );
        assert_eq!(limits.get(NLIMITS), None, "past the end is not a resource");
        assert!(limits.set(NOFILE, Rlimit { cur: 7, max: 9 }));
        assert!(!limits.set(NLIMITS, Rlimit { cur: 7, max: 9 }));

        let clone = limits.clone();
        assert_eq!(clone.get(NOFILE), Some(Rlimit { cur: 7, max: 9 }));
        clone.set(NOFILE, Rlimit { cur: 1, max: 1 });
        assert_eq!(
            limits.get(NOFILE),
            Some(Rlimit { cur: 7, max: 9 }),
            "a clone is independent"
        );
    }
}
