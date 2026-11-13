//! Job control: which session owns a terminal, which process group is in its
//! foreground, and the rules for changing either.
//!
//! Two integers and about a dozen rules. The integers were fields on
//! `struct tty` that eight places in `fs/tty.c` read and wrote directly, and
//! the rules were spread across those places as `if` chains. Every one of them
//! is ABI: what a `^C` reaches, whether a background read stops or fails, which
//! terminal a session leader ends up with. Four of them were wrong on
//! 2026-08-23:
//!
//! - `TIOCSPGRP` stored whatever number it was given. Negative, zero, and
//!   numbers naming no process group were all accepted, so a terminal could be
//!   pointed at nothing and never say so.
//! - A pty *master* could be claimed as a controlling terminal, which Linux
//!   refuses unconditionally. Every session leader with no console acquired one
//!   by calling `posix_openpt`.
//! - Hangup sent no signal at all.
//! - `TIOCSWINSZ` reached `pids_lock` with the terminal's lock held, the
//!   opposite of the order the rest of the kernel uses.
//!
//! The first two are decisions and live here. The other two are about locks and
//! signals; their callers remain responsible for lock ordering and delivery,
//! while the job-control decisions are typed and testable here.
//!
//! # What this owns and what it does not
//!
//! It owns `session` and `fg_group` for one terminal, and every transition
//! between them. It owns no locks: `ttys_lock` and the terminal's own lock are
//! belong to the surrounding terminal layer, and every entry point here runs
//! under them. It knows nothing about
//! processes — whether a process group exists, and what session it is in, are
//! facts only the caller can look up, so they arrive as arguments.
//!
//! Splitting it that way is what makes the *order* of the checks testable.
//! Linux's `tiocspgrp` rejects a negative number before it decides whether the
//! terminal is yours, so `dup3`-style "check the arguments first" is not a
//! detail here — a test asserting `ENOTTY` for a negative pgid on someone
//! else's terminal was wrong about Linux, and only the sweep caught it.

use std::ffi::c_int;

/// Guest errnos, from `crates/util/errno`. Negative, as every `sys_*` returns.
pub use guest_errno::c_int_::{EINVAL, EIO, ENOTTY, EPERM, ESRCH};

/// `O_NOCTTY_` from `kernel/fs.h`.
pub const O_NOCTTY: c_int = 1 << 8;

mod policy;
pub use policy::{Access, JobControl, Pid, Sig};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_terminal_belongs_to_nobody() {
        let j = JobControl::new();
        assert!(j.unowned());
        assert_eq!(j.session(), 0);
        assert_eq!(j.fg_group(), 0);
        assert_eq!(j.hangup_target(), None);
    }

    #[test]
    fn claiming_sets_both() {
        let mut j = JobControl::new();
        j.claim(7, 9);
        assert!(!j.unowned());
        assert_eq!(j.session(), 7);
        assert_eq!(j.fg_group(), 9);
        assert_eq!(j.hangup_target(), Some(7));
    }

    #[test]
    fn disowning_leaves_the_foreground_group() {
        // Deliberate, and what the C did: TIOCGPGRP keeps answering the same
        // number until someone claims the terminal again, because there is no
        // better answer for a terminal nobody owns.
        let mut j = JobControl::new();
        j.claim(7, 9);
        j.disown();
        assert!(j.unowned());
        assert_eq!(j.fg_group(), 9);
        assert_eq!(j.hangup_target(), None);
    }

    #[test]
    fn detaching_clears_both() {
        let mut j = JobControl::new();
        j.claim(7, 9);
        j.detach();
        assert!(j.unowned());
        assert_eq!(j.fg_group(), 0);
        assert_eq!(j.hangup_target(), None);
    }

    #[test]
    fn a_pty_master_is_never_claimed() {
        // Whatever the flags say. This is the one that let every session leader
        // with no console acquire a terminal by calling posix_openpt.
        assert!(!JobControl::open_claims(0, true));
        assert!(!JobControl::open_claims(O_NOCTTY, true));
        assert!(JobControl::open_claims(0, false));
        assert!(!JobControl::open_claims(O_NOCTTY, false));
    }

    #[test]
    fn other_open_flags_do_not_matter() {
        // O_NOCTTY is 1 << 8; the bits around it are other flags entirely and
        // were once tested with the wrong mask elsewhere in this tree.
        assert!(JobControl::open_claims(1 << 7, false));
        assert!(JobControl::open_claims(1 << 9, false));
        assert!(!JobControl::open_claims((1 << 7) | O_NOCTTY, false));
    }

    #[test]
    fn get_pgrp_needs_a_terminal_of_ours_with_a_group() {
        let mut j = JobControl::new();
        j.claim(7, 9);
        assert_eq!(j.get_pgrp(true), Ok(9));
        assert_eq!(j.get_pgrp(false), Err(ENOTTY));
        let mut empty = JobControl::new();
        empty.claim(7, 0);
        assert_eq!(empty.get_pgrp(true), Err(ENOTTY));
    }

    #[test]
    fn a_negative_group_is_refused_before_the_terminal_is_looked_at() {
        // The order is the ABI. A test asserting ENOTTY here was wrong about
        // Linux and the emulator agreed with it, which is why it took a real
        // kernel to settle.
        let mut j = JobControl::new();
        j.claim(7, 9);
        assert_eq!(j.set_pgrp_check(-1, false, 999), Err(EINVAL));
        assert_eq!(j.set_pgrp_check(i32::MIN, false, 999), Err(EINVAL));
        // And a well-formed number on someone else's terminal is ENOTTY.
        assert_eq!(j.set_pgrp_check(5, false, 7), Err(ENOTTY));
        assert_eq!(j.set_pgrp_check(5, true, 8), Err(ENOTTY));
        assert_eq!(j.set_pgrp_check(5, true, 7), Ok(()));
    }

    #[test]
    fn set_pgrp_wants_a_group_that_exists_in_our_session() {
        let mut j = JobControl::new();
        j.claim(7, 9);
        assert_eq!(j.set_pgrp(5, true, 7, None), Err(ESRCH));
        assert_eq!(j.fg_group(), 9, "a refusal changes nothing");
        assert_eq!(j.set_pgrp(5, true, 7, Some(8)), Err(EPERM));
        assert_eq!(j.fg_group(), 9, "a refusal changes nothing");
        assert_eq!(j.set_pgrp(5, true, 7, Some(7)), Ok(()));
        assert_eq!(j.fg_group(), 5);
    }

    #[test]
    fn zero_is_not_a_process_group() {
        // Not negative, so it passes the first check, and then there is no
        // group 0 to find. Linux answers ESRCH.
        let mut j = JobControl::new();
        j.claim(7, 9);
        assert_eq!(j.set_pgrp_check(0, true, 7), Ok(()));
        assert_eq!(j.set_pgrp(0, true, 7, None), Err(ESRCH));
    }

    #[test]
    fn set_ctty_when_it_is_already_ours() {
        let mut j = JobControl::new();
        j.claim(7, 9);
        assert_eq!(j.set_ctty(true, 7, true, false, false), Ok(None));
        // Not a session leader with that sid: the "already ours" shortcut does
        // not apply, and having a terminal already is EPERM.
        assert_eq!(j.set_ctty(false, 7, true, false, false), Err(EPERM));
    }

    #[test]
    fn set_ctty_on_a_free_terminal() {
        let j = JobControl::new();
        assert_eq!(j.set_ctty(true, 7, false, false, false), Ok(Some(false)));
    }

    #[test]
    fn set_ctty_stealing() {
        let mut j = JobControl::new();
        j.claim(7, 9);
        // Someone else's terminal, and we have none of our own.
        assert_eq!(j.set_ctty(true, 8, false, false, false), Err(EPERM));
        assert_eq!(
            j.set_ctty(true, 8, false, true, false),
            Err(EPERM),
            "force needs root"
        );
        assert_eq!(
            j.set_ctty(true, 8, false, false, true),
            Err(EPERM),
            "root needs force"
        );
        assert_eq!(j.set_ctty(true, 8, false, true, true), Ok(Some(true)));
    }

    #[test]
    fn the_foreground_group_may_do_as_it_likes() {
        let mut j = JobControl::new();
        j.claim(7, 9);
        assert_eq!(j.access(true, 9, Sig::Ttin, false, false), Access::Allow);
        assert_eq!(j.access(true, 9, Sig::Ttou, false, true), Access::Allow);
    }

    #[test]
    fn a_terminal_that_is_not_ours_is_free_to_use() {
        // Surprising, and what Linux does.
        let mut j = JobControl::new();
        j.claim(7, 9);
        assert_eq!(j.access(false, 4, Sig::Ttin, false, false), Access::Allow);
    }

    #[test]
    fn the_cheap_answer_agrees_with_the_full_one() {
        // The fast path may only ever *allow*. Everywhere it says "no lookup
        // needed", the full decision has to be Allow for both orphan answers --
        // otherwise skipping the lookup would change the result.
        for (session, fg) in [(0, 0), (7, 0), (7, 9)] {
            let mut j = JobControl::new();
            if session != 0 {
                j.claim(session, fg);
            }
            for is_current in [false, true] {
                for pgid in [0, 4, 9] {
                    if !j.access_needs_orphan(is_current, pgid) {
                        for sig in [Sig::Ttin, Sig::Ttou] {
                            for ignored in [false, true] {
                                assert_eq!(
                                    j.access(is_current, pgid, sig, ignored, false),
                                    Access::Allow
                                );
                                assert_eq!(
                                    j.access(is_current, pgid, sig, ignored, true),
                                    Access::Allow
                                );
                            }
                        }
                    } else {
                        // And where it says a lookup *is* needed, the answer
                        // really does depend on it -- otherwise the fast path
                        // is leaving work on the table.
                        // With the signal not ignored, the orphan answer is
                        // what decides -- which is exactly the lookup the
                        // fast path is deciding whether to pay for.
                        assert_ne!(
                            j.access(is_current, pgid, Sig::Ttin, false, false),
                            j.access(is_current, pgid, Sig::Ttin, false, true)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_background_group_stops_unless_it_is_orphaned() {
        let mut j = JobControl::new();
        j.claim(7, 9);
        assert_eq!(j.access(true, 4, Sig::Ttin, false, false), Access::Stop);
        // Nobody left who could send SIGCONT, so stopping would be a hang.
        assert_eq!(j.access(true, 4, Sig::Ttin, false, true), Access::Eio);
    }

    #[test]
    fn a_terminal_with_no_foreground_group_stops_nobody() {
        let mut j = JobControl::new();
        j.claim(7, 0);
        assert_eq!(j.access(true, 4, Sig::Ttin, false, false), Access::Allow);
    }

    #[test]
    fn ignoring_the_signal_is_decided_before_the_orphan_is() {
        // Linux's order, and not the order the checks read in. An orphaned
        // group that ignores SIGTTOU is *allowed*; asking about the orphan
        // first would answer EIO, which is what this kernel did.
        let mut j = JobControl::new();
        j.claim(7, 9);
        assert_eq!(j.access(true, 4, Sig::Ttou, true, true), Access::Allow);
        assert_eq!(j.access(true, 4, Sig::Ttou, true, false), Access::Allow);
        // A read cannot be allowed on the same grounds: there would be nothing
        // to return and the caller would spin.
        assert_eq!(j.access(true, 4, Sig::Ttin, true, true), Access::Eio);
        assert_eq!(j.access(true, 4, Sig::Ttin, true, false), Access::Eio);
        // And with the signal not ignored, the orphan answer decides again.
        assert_eq!(j.access(true, 4, Sig::Ttou, false, true), Access::Eio);
        assert_eq!(j.access(true, 4, Sig::Ttou, false, false), Access::Stop);
    }

    #[test]
    fn the_typed_api_round_trips() {
        let mut j = JobControl::new();
        assert!(j.unowned());
        j.claim(7, 9);
        assert_eq!(j.session(), 7);
        assert_eq!(j.fg_group(), 9);
        assert_eq!(j.hangup_target(), Some(7));

        assert_eq!(j.get_pgrp(true), Ok(9));
        assert_eq!(j.get_pgrp(false), Err(ENOTTY));

        assert_eq!(j.set_pgrp_check(-1, false, 0), Err(EINVAL));
        assert_eq!(j.set_pgrp(5, true, 7, None), Err(ESRCH));
        assert_eq!(j.set_pgrp(5, true, 7, Some(8)), Err(EPERM));
        assert_eq!(j.set_pgrp(5, true, 7, Some(7)), Ok(()));
        assert_eq!(j.fg_group(), 5);

        assert_eq!(j.access(true, 5, Sig::Ttin, false, false), Access::Allow);
        assert_eq!(j.access(true, 4, Sig::Ttin, false, false), Access::Stop);
        assert_eq!(j.access(true, 4, Sig::Ttin, false, true), Access::Eio);
        assert_eq!(j.access(true, 4, Sig::Ttin, true, false), Access::Eio);
        assert_eq!(j.access(true, 4, Sig::Ttou, true, true), Access::Allow);

        assert_eq!(j.set_ctty(true, 7, true, false, false), Ok(None));
        assert_eq!(j.set_ctty(true, 8, false, true, true), Ok(Some(true)));

        j.disown();
        assert_eq!(j.hangup_target(), None);
    }
}
