//! Unit tests for credential and identity transitions.

use super::*;
use crate::access::EACCES;
// --------------------------------------------------------------- the set

fn root() -> Creds {
    Creds::default()
}

/// Real, effective and saved all `id`, and unprivileged unless it is 0.
///
/// The gids go first. Privilege for *any* id change is the effective
/// **user** id, so dropping that one first makes the group change EPERM --
/// which is the rule working, and the order a real program uses for the
/// same reason.
fn as_user(id: u32) -> Creds {
    let mut c = Creds::default();
    c.setresgid(id, id, id).unwrap();
    c.setresuid(id, id, id).unwrap();
    c
}

// --------------------------------------------------------------- dumpable

/// `commit_creds`' test, case by case as a real kernel answered it
/// (`tests/guest/src/bin/dumpable_probe.rs`).
#[test]
fn an_identity_change_is_an_effective_or_fs_id_moving() {
    let changed = |f: fn(&mut Creds)| {
        let before = root();
        let mut after = before;
        f(&mut after);
        after.changes_identity(&before)
    };
    assert!(changed(|c| c.setuid(65534).unwrap()));
    assert!(changed(|c| c.setresuid(UNCHANGED, 65534, UNCHANGED).unwrap()));
    assert!(changed(|c| c.setresgid(UNCHANGED, 65534, UNCHANGED).unwrap()));
    assert!(changed(|c| { c.setfsuid(65534); }));
    assert!(changed(|c| { c.setfsgid(65534); }));
    assert!(!changed(|c| c.setuid(0).unwrap()), "no change");
    assert!(!changed(|c| c.setresuid(65534, UNCHANGED, UNCHANGED).unwrap()), "the real id");
    assert!(!changed(|c| c.setresuid(UNCHANGED, UNCHANGED, 65534).unwrap()), "the saved id");
    assert!(!changed(|c| c.groups_mut().set(&[1, 2]).unwrap()), "the groups");
}

#[test]
fn an_exec_keeps_dumpable_only_with_the_real_ids_and_a_readable_file() {
    assert!(root().exec_keeps_dumpable(0, 0, 0o100755));
    let mut c = root();
    c.setresuid(65534, 0, 0).unwrap();
    assert!(!c.exec_keeps_dumpable(0, 0, 0o100755), "euid is not the real uid");
    let mut c = root();
    c.setresgid(65534, 0, 0).unwrap();
    assert!(!c.exec_keeps_dumpable(0, 0, 0o100755), "egid is not the real gid");
    let c = as_user(65534);
    assert!(c.exec_keeps_dumpable(0, 0, 0o100755));
    assert!(!c.exec_keeps_dumpable(0, 0, 0o100711), "a file it cannot read");
}

// ------------------------------------------------------ who may signal whom

#[test]
fn a_user_may_signal_their_own_processes() {
    let a = as_user(1000);
    let b = as_user(1000);
    assert!(a.may_signal(&b));
}

#[test]
fn a_user_may_not_signal_another_users() {
    let a = as_user(1000);
    let b = as_user(1001);
    assert!(!a.may_signal(&b));
    assert!(!b.may_signal(&a));
}

#[test]
fn root_may_signal_anyone() {
    assert!(root().may_signal(&as_user(1000)));
}

#[test]
fn a_user_may_not_signal_root() {
    assert!(!as_user(1000).may_signal(&root()));
}

/// A setuid program's real id is still the user who started it, and that is
/// enough — which is what lets a shell kill a `sudo` it launched.
#[test]
fn the_senders_real_id_counts_as_well_as_the_effective_one() {
    // What execing a setuid-1001 binary as user 1000 leaves: the real id is
    // still who started it. Built from root because an unprivileged task
    // cannot assume an id it does not already hold -- which is the rule
    // working, not a limitation of the test.
    let mut sender = root();
    sender.setresuid(1000, 1001, 1000).unwrap();
    assert_eq!(sender.uid(), 1000);
    assert_eq!(sender.euid(), 1001);
    assert!(sender.may_signal(&as_user(1000)), "by the real id");
    assert!(
        sender.may_signal(&as_user(1001)),
        "and by the effective one"
    );
}

/// The *target's* effective id is deliberately not one of the four: a
/// process that has temporarily assumed another identity has not put itself
/// out of reach of the user it belongs to.
#[test]
fn the_targets_effective_id_is_not_what_is_checked() {
    let mut target = root();
    target.setresuid(1000, 1001, 1000).unwrap();
    assert_eq!(target.uid(), 1000, "real");
    assert_eq!(target.euid(), 1001, "effective");

    assert!(
        as_user(1000).may_signal(&target),
        "the user it belongs to still reaches it"
    );
    assert!(
        !as_user(1001).may_signal(&target),
        "and the identity it borrowed does not"
    );
}

/// The saved id is what a program that has dropped privilege to do some
/// work can still be reached by.
#[test]
fn the_targets_saved_id_counts() {
    // A program that has dropped privilege to do some work: 1001 real and
    // effective, 1000 kept in the saved slot to go back to.
    let mut target = root();
    target.setresuid(1001, 1001, 1000).unwrap();
    assert_eq!(target.suid(), 1000, "saved");
    assert!(as_user(1000).may_signal(&target));
}

/* `the_signal_permission_abi` was here until 2026-09-16. Its first two
 * assertions restated the test above it through the ABI wrapper; its other two
 * were about that wrapper answering `false` for a null pointer, and there is no
 * pointer left to be null -- `may_signal` takes a `&Creds`, and the one caller
 * passes `&raw const (*task).creds`, which is the address of a field. Deleted
 * rather than rewritten: the case is not reachable and not expressible. */

#[test]
fn the_fs_ids_follow_the_effective_ones_through_every_door() {
    // The whole reason this is an object. Each of these used to be a
    // separate assignment in C, and one of the three was nearly missed.
    let mut c = root();
    c.setuid(1000).unwrap();
    assert_eq!((c.euid(), c.fsuid()), (1000, 1000), "setuid");

    let mut c = root();
    c.setreuid(UNCHANGED, 1001).unwrap();
    assert_eq!((c.euid(), c.fsuid()), (1001, 1001), "setreuid");

    let mut c = root();
    c.setresuid(UNCHANGED, 1002, UNCHANGED).unwrap();
    assert_eq!((c.euid(), c.fsuid()), (1002, 1002), "setresuid");

    let mut c = root();
    c.setgid(1003).unwrap();
    assert_eq!((c.egid(), c.fsgid()), (1003, 1003), "setgid");

    let mut c = root();
    c.setregid(UNCHANGED, 1004).unwrap();
    assert_eq!((c.egid(), c.fsgid()), (1004, 1004), "setregid");

    let mut c = root();
    c.setresgid(UNCHANGED, 1005, UNCHANGED).unwrap();
    assert_eq!((c.egid(), c.fsgid()), (1005, 1005), "setresgid");

    // And the execve transition, which is the one that is easiest to
    // forget because it does not go through any of the setters.
    let file = crate::ExecFile { mode: 0o104755, uid: 0, gid: 0, caps: None, no_new_privs: false };
    let c = as_user(1000).exec(&file).unwrap().creds;
    assert_eq!(c.euid(), 0, "a set-uid execve raises the effective uid");
    assert_eq!(c.fsuid(), 0, "and the fs uid with it");
}

#[test]
fn a_refusal_moves_nothing_including_the_fs_ids() {
    let mut c = as_user(1000);
    c.setfsuid(1000);
    assert_eq!(c.setuid(0), Err(EPERM));
    assert_eq!((c.uid(), c.euid(), c.suid()), (1000, 1000, 1000));
    assert_eq!(
        c.fsuid(),
        1000,
        "a refused setuid did not move the fsuid either"
    );
}

#[test]
fn the_fs_ids_can_be_moved_on_their_own() {
    // Which is the point of having them: everything else stays put.
    let mut c = root();
    assert_eq!(c.setfsuid(1000), 0, "answers the previous value");
    assert_eq!(c.fsuid(), 1000);
    assert_eq!(c.euid(), 0, "the effective uid did not move");
    assert_eq!(c.uid(), 0, "nor the real one");
    // And the *next* credential change takes the fsuid back with it, which
    // is why a program that never calls setfsuid sees one id.
    c.setresuid(UNCHANGED, 7, UNCHANGED).unwrap();
    assert_eq!(c.fsuid(), 7);
}

#[test]
fn privilege_for_a_file_is_a_different_question_from_privilege() {
    use crate::caps::{CAP_DAC_OVERRIDE, CAP_SETUID};
    let mut c = root();
    assert!(c.capable(CAP_SETUID) && c.capable(CAP_DAC_OVERRIDE));
    c.setfsuid(1000);
    assert!(c.capable(CAP_SETUID), "the rest of the effective set stays");
    assert!(
        !c.capable(CAP_DAC_OVERRIDE),
        "but the filesystem capabilities are gone"
    );
    // And that is what the file checks use.
    assert_eq!(c.access(0, 0, 0o600, AC_R), Err(EACCES));
    assert_eq!(c.may_link(0, 0, 0o100644), Err(EPERM));
}

#[test]
fn the_id_change_rules_ask_setuid_and_setgid() {
    // CAP_SETGID is not in the filesystem set, so moving the fsuid must not
    // affect it.
    let mut c = root();
    c.setfsuid(1000);
    assert_eq!(c.setgid(42), Ok(()), "still allowed to change the gid");
    assert_eq!(c.egid(), 42);
}

#[test]
fn a_child_is_a_copy_and_is_independent() {
    let mut parent = Creds::default();
    parent.groups_mut().set(&[7, 8]).unwrap();
    parent.setfsuid(1000);
    let mut child = parent;
    assert_eq!(child, parent);
    child.setfsuid(2000);
    assert_eq!(child.fsuid(), 2000);
    assert_eq!(parent.fsuid(), 1000, "the parent is untouched");
    child.groups_mut().set(&[9]).unwrap();
    assert_eq!(
        parent.groups().as_slice(),
        &[7, 8],
        "the parent's list is its own"
    );
    assert_eq!(child.groups().as_slice(), &[9]);
}

#[test]
fn a_fresh_set_is_root_with_no_groups() {
    // `struct task` is zeroed when it is made, so a zeroed Creds has to be
    // the right starting point rather than merely look like one.
    let c = Creds::default();
    assert_eq!(
        (c.uid(), c.euid(), c.suid(), c.gid(), c.egid(), c.sgid()),
        (0, 0, 0, 0, 0, 0)
    );
    assert_eq!((c.fsuid(), c.fsgid()), (0, 0));
    assert_eq!(c.groups().as_slice(), &[] as &[u32]);
    assert_eq!(*c.caps(), crate::caps::Caps::ROOT, "a root login's sets");
    assert_eq!(c.securebits(), 0);
}

#[test]
fn the_access_override_is_not_subject_to_the_setfsuid_rule() {
    // It is a kernel-internal override, and treating it as a setfsuid would
    // make an unrelated change to that rule silently break access(2).
    let mut c = Creds::default();
    c.setresgid(2000, 2001, 2002).unwrap();
    c.setresuid(1000, 1001, 1002).unwrap();
    assert_eq!(
        (c.fsuid(), c.fsgid()),
        (1001, 2001),
        "they followed the effective ids"
    );
    let old = c.override_fsids_with_real();
    assert_eq!((c.fsuid(), c.fsgid()), (1000, 2000), "now the real ones");
    assert_eq!((c.uid(), c.euid()), (1000, 1001), "and nothing else moved");
    c.restore_fsids(old);
    assert_eq!((c.fsuid(), c.fsgid()), (1001, 2001));
}

/// `access_override_creds`: a real uid of 0 checks with the whole permitted
/// set, whatever the effective set held, and gives the effective one back.
#[test]
fn the_access_override_takes_the_real_uids_capabilities() {
    use crate::caps::{CAP_DAC_OVERRIDE, CAP_FULL};
    let mut c = root();
    c.capset(CAP_FULL & !(1 << CAP_DAC_OVERRIDE), CAP_FULL, 0).unwrap();
    let old = c.override_fsids_with_real();
    assert!(c.capable(CAP_DAC_OVERRIDE));
    c.restore_fsids(old);
    assert!(!c.capable(CAP_DAC_OVERRIDE));
    let mut user = root();
    user.setresuid(1000, 0, 0).unwrap();
    let old = user.override_fsids_with_real();
    assert_eq!(user.caps().effective, 0, "a real uid other than 0 checks with none");
    user.restore_fsids(old);
    assert_eq!(user.caps().effective, CAP_FULL);
}

/// The size and alignment `struct task` embeds this at.
///
/// It was pinned against a `static_assert` in `kernel/task.c` over an
/// `unsigned char _opaque[168]`, because C had to reserve space for a
/// struct it could not see. It embeds this type itself since 2026-09-05,
/// so nothing has to agree with the number any more -- what is left is a
/// record of how large this got, and a place for a comment when it moves.
#[test]
fn the_size_and_alignment_are_recorded() {
    // 172 bytes of ids, groups and securebits, then the five sets, aligned.
    assert_eq!(std::mem::size_of::<Creds>(), 216);
    assert_eq!(std::mem::align_of::<Creds>(), 8);
}

// ---------------------------------------------------- protected_hardlinks

const REG: u32 = 0o100000;
const DIR: u32 = 0o040000;

#[test]
fn the_owner_may_link_their_own_file_whatever_it_is() {
    // Including a set-uid one: they could have made it.
    for mode in [REG | 0o644, REG | 0o4755, REG, DIR | 0o755] {
        assert_eq!(
            may_link(false, 1000, 1000, &[], 1000, 1000, mode),
            Ok(()),
            "{mode:o}"
        );
    }
}

#[test]
fn privilege_allows_any_link() {
    assert_eq!(may_link(true, 1000, 1000, &[], 0, 0, REG | 0o4755), Ok(()));
}

#[test]
fn a_readable_and_writable_regular_file_may_be_linked() {
    // 0666: the caller is neither owner nor in the group, so "other" gives
    // read and write, which is what the rule asks for.
    assert_eq!(may_link(false, 1000, 1000, &[], 0, 0, REG | 0o666), Ok(()));
}

#[test]
fn one_you_cannot_write_may_not_be() {
    // The common case, and the one that matters: a world-readable file
    // belonging to someone else.
    assert_eq!(
        may_link(false, 1000, 1000, &[], 0, 0, REG | 0o644),
        Err(EPERM)
    );
    assert_eq!(may_link(false, 1000, 1000, &[], 0, 0, REG), Err(EPERM));
    // Writable but not readable is refused too -- the rule wants both.
    assert_eq!(
        may_link(false, 1000, 1000, &[], 0, 0, REG | 0o622),
        Err(EPERM)
    );
}

#[test]
fn a_set_uid_file_may_not_be_linked_even_when_writable() {
    // This is the one the whole rule exists for: pinning a set-uid binary
    // so it survives the owner deleting it.
    assert_eq!(
        may_link(false, 1000, 1000, &[], 0, 0, REG | 0o4666),
        Err(EPERM)
    );
}

#[test]
fn set_gid_is_about_the_pair_of_bits() {
    // S_ISGID without group-execute means mandatory locking, not
    // privilege, so it is not a reason to refuse.
    assert_eq!(may_link(false, 1000, 1000, &[], 0, 0, REG | 0o2666), Ok(()));
    // With it, it is.
    assert_eq!(
        may_link(false, 1000, 1000, &[], 0, 0, REG | 0o2676),
        Err(EPERM)
    );
}

#[test]
fn only_a_regular_file_may_be_linked_by_a_stranger() {
    // A device node or a fifo pinned by someone who does not own it is the
    // same hazard by a different route.
    for kind in [0o020000u32, 0o060000, 0o010000, 0o140000, DIR] {
        assert_eq!(
            may_link(false, 1000, 1000, &[], 0, 0, kind | 0o666),
            Err(EPERM),
            "{kind:o}"
        );
    }
}

#[test]
fn a_supplementary_group_can_carry_the_permission() {
    // The read/write test is the ordinary one, so the group list counts.
    assert_eq!(may_link(false, 1000, 7, &[42], 0, 42, REG | 0o660), Ok(()));
    assert_eq!(
        may_link(false, 1000, 7, &[], 0, 42, REG | 0o660),
        Err(EPERM)
    );
}

// -------------------------------------------------------------- fsuid

fn ids(real: u32, eff: u32, saved: u32) -> Ids {
    Ids { real, eff, saved }
}

#[test]
fn an_fsid_may_become_any_of_the_four() {
    let cur = ids(10, 20, 30);
    for want in [10u32, 20, 30, 40] {
        assert_eq!(set_fsid(false, cur, 40, want), want, "{want}");
    }
}

#[test]
fn anything_else_is_refused_silently() {
    // Not an error -- the value simply does not move, and the caller is
    // told the old one either way.
    let cur = ids(10, 20, 30);
    for want in [0u32, 1, 41, 999, u32::MAX] {
        assert_eq!(set_fsid(false, cur, 40, want), 40, "{want}");
    }
}

#[test]
fn unchanged_is_how_the_value_is_read() {
    // `setfsuid(-1)` is not a uid at all, and is rejected before the
    // permission check -- which is what makes it a read for *everyone*.
    let cur = ids(10, 20, 30);
    assert_eq!(set_fsid(false, cur, 40, UNCHANGED), 40);
    // Including a privileged caller. Checked separately because getting
    // the order wrong gives a privileged caller an fsuid of 0xffffffff,
    // and every later filesystem check is then made against an id nothing
    // owns. That is what the first version of this did.
    assert_eq!(set_fsid(true, cur, 40, UNCHANGED), 40);
    // And even when one of the ids nominally *is* that value, because the
    // rejection comes first.
    assert_eq!(set_fsid(false, ids(UNCHANGED, 20, 30), 40, UNCHANGED), 40);
}

#[test]
fn privilege_allows_any_id() {
    let cur = ids(10, 20, 30);
    for want in [0u32, 999, 4242] {
        assert_eq!(set_fsid(true, cur, 40, want), want, "{want}");
    }
}

#[test]
fn the_current_fsid_may_always_be_asked_for_again() {
    // Which is not implied by the other three: an fsid that came from
    // privilege is not any of uid, euid or suid afterwards, and setting it
    // to itself must still work.
    let cur = ids(10, 20, 30);
    assert_eq!(set_fsid(false, cur, 4242, 4242), 4242);
}

const ROOT: Ids = Ids {
    real: 0,
    eff: 0,
    saved: 0,
};

#[test]
fn setuid_from_root_sets_all_three() {
    assert_eq!(
        set_id(true, ROOT, 1000),
        Ok(Ids {
            real: 1000,
            eff: 1000,
            saved: 1000
        })
    );
}

#[test]
fn unprivileged_setuid_moves_only_the_effective_id() {
    let cur = Ids {
        real: 1000,
        eff: 0,
        saved: 0,
    };
    assert_eq!(
        set_id(false, cur, 1000),
        Ok(Ids {
            real: 1000,
            eff: 1000,
            saved: 0
        })
    );
    // ... and may not name an id it does not hold.
    assert_eq!(set_id(false, cur, 1234), Err(EPERM));
}

#[test]
fn setreuid_moves_the_saved_id_with_the_effective_one() {
    // The defect this crate was written for. euid becomes 1000, which is
    // not the previous real id, so the saved id must follow.
    assert_eq!(
        set_reid(true, ROOT, UNCHANGED, 1000),
        Ok(Ids {
            real: 0,
            eff: 1000,
            saved: 1000
        })
    );
    // And a full drop leaves nothing privileged to come back to.
    assert_eq!(
        set_reid(true, ROOT, 1000, 1000),
        Ok(Ids {
            real: 1000,
            eff: 1000,
            saved: 1000
        })
    );
}

#[test]
fn setreuid_leaves_the_saved_id_when_the_rule_does_not_apply() {
    // Effective set to the *previous real* id, real untouched: no move.
    let cur = Ids {
        real: 0,
        eff: 0,
        saved: 7,
    };
    assert_eq!(set_reid(true, cur, UNCHANGED, 0), Ok(cur));
    // Neither argument given: nothing happens at all.
    assert_eq!(set_reid(true, cur, UNCHANGED, UNCHANGED), Ok(cur));
}

#[test]
fn setresuid_never_moves_the_saved_id_on_its_own() {
    // The control that keeps the fix honest: setresuid names the saved id
    // explicitly, so UNCHANGED must leave it alone even when setreuid would
    // have moved it.
    assert_eq!(
        set_resid(true, ROOT, UNCHANGED, 1000, UNCHANGED),
        Ok(Ids {
            real: 0,
            eff: 1000,
            saved: 0
        })
    );
}

#[test]
fn setreuid_restricts_the_real_id_more_than_setresuid() {
    // Linux's __sys_setreuid allows the real id to become the current real
    // or effective id only. setresuid also allows the saved one. The C
    // forwarded one to the other, so this was permitted.
    let cur = Ids {
        real: 1000,
        eff: 1000,
        saved: 0,
    };
    assert_eq!(set_reid(false, cur, 0, UNCHANGED), Err(EPERM));
    assert!(set_resid(false, cur, 0, UNCHANGED, UNCHANGED).is_ok());
    // The effective id, by contrast, may become the saved one in both.
    assert!(set_reid(false, cur, UNCHANGED, 0).is_ok());
}

/// Whatever the rules are, they must never hand out an id the task did not
/// already hold — that is the one invariant a privilege check exists for.
#[test]
fn an_unprivileged_change_never_invents_an_id() {
    let ids = [0u32, 1, 1000];
    for &real in &ids {
        for &eff in &ids {
            for &saved in &ids {
                let cur = Ids { real, eff, saved };
                for &a in &[UNCHANGED, 0, 1, 1000, 4242] {
                    for &b in &[UNCHANGED, 0, 1, 1000, 4242] {
                        for &c in &[UNCHANGED, 0, 1, 1000, 4242] {
                            for got in [
                                set_id(false, cur, a),
                                set_reid(false, cur, a, b),
                                set_resid(false, cur, a, b, c),
                            ]
                            .into_iter()
                            .flatten()
                            {
                                for id in [got.real, got.eff, got.saved] {
                                    assert!(
                                        cur.holds(id),
                                        "{cur:?} + ({a},{b},{c}) produced {got:?}, \
                                         which holds {id} from nowhere"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// 4242 is in none of the starting triples above, so every call that names
/// it must be refused. Without this the sweep passes against an
/// implementation that refuses everything.
#[test]
fn the_sweep_has_something_to_refuse() {
    let cur = Ids {
        real: 1000,
        eff: 1000,
        saved: 1000,
    };
    assert_eq!(set_id(false, cur, 4242), Err(EPERM));
    assert_eq!(set_reid(false, cur, 4242, UNCHANGED), Err(EPERM));
    assert_eq!(
        set_resid(false, cur, UNCHANGED, UNCHANGED, 4242),
        Err(EPERM)
    );
    // And a privileged caller is refused nothing.
    assert!(set_id(true, cur, 4242).is_ok());
    assert!(set_reid(true, cur, 4242, 4242).is_ok());
}
