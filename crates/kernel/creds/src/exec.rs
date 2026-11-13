//! Credential transitions performed by `execve`.

use std::ffi::c_int;

use super::{Creds, EPERM, Ids};
use crate::caps::{FileCaps, secure};

const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_IXGRP: u32 = 0o0010;

// -------------------------------------------------------------------- exec

/// The user and group triples after an `execve`.
///
/// Linux does this in two steps and the second is **not** conditional on the
/// first. `bprm_fill_uid` moves the effective ids for a set-id file, and
/// `cap_bprm_creds_from_file` then ends every exec with
/// `new->suid = new->fsuid = new->euid; new->sgid = new->fsgid = new->egid;`.
///
/// Folding the two together, and folding them into the `if`, is what produced
/// all three of the defects in
/// `docs/changelog/2026-08-22-execve-put-the-old-identity-in-the-saved-id.md`:
/// the saved id took the *old* identity, `S_ISGID` was honoured without
/// `S_IXGRP`, and the saved ids did not follow on a plain exec.
pub(crate) fn after_exec(uid: Ids, gid: Ids, file_mode: u32, file_uid: u32, file_gid: u32) -> (Ids, Ids) {
    let mut uid = uid;
    let mut gid = gid;
    if file_mode & S_ISUID != 0 {
        uid.eff = file_uid;
    }
    // S_ISGID without S_IXGRP is the mandatory-locking marker, not a setgid
    // binary, and Linux does not change the effective group for it.
    if file_mode & (S_ISGID | S_IXGRP) == S_ISGID | S_IXGRP {
        gid.eff = file_gid;
    }
    // Unconditional: exec is a privilege boundary, so a saved id kept from
    // before it does not survive.
    uid.saved = uid.eff;
    gid.saved = gid.eff;
    (uid, gid)
}

/// The program an `execve` runs, as the credential rules see it: the ELF the
/// image is loaded from (for a `#!` script, its interpreter -- a set-id script
/// is not one), and its `security.capability`, decoded.
#[derive(Clone, Copy, Debug)]
pub struct ExecFile {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub caps: Option<FileCaps>,
    /// `no_new_privs` on the calling thread: neither the set-id bits nor the
    /// file's capabilities may add anything.
    pub no_new_privs: bool,
}

/// What the new image runs with.
#[derive(Clone, Copy, Debug)]
pub struct Exec {
    pub creds: Creds,
    /// `bprm->secureexec`, which is `AT_SECURE`, and what takes the
    /// parent-death signal away.
    pub secure: bool,
}

impl Creds {
    /// `bprm_fill_uid` and `cap_bprm_creds_from_file`. `EPERM` for a file
    /// whose effective bit is set and whose permitted set the bounding set
    /// does not cover: a program written to expect its capabilities is not
    /// started without them, measured.
    ///
    /// ```text
    /// pA' = file caps or set-id ? 0 : pA
    /// pP' = (fP & pB) | (fI & pI) | pA'      root: pB | pI
    /// pE' = fE ? pP' : pA'                    root (effective): pP'
    /// ```
    ///
    /// Not modelled: the downgrade for a traced process or one sharing its
    /// `fs_struct`, which needs a tracer that can attach, and `nosuid`
    /// mounts, which nothing here mounts.
    pub fn exec(&self, file: &ExecFile) -> Result<Exec, c_int> {
        let old = self;
        let mut new = *self;
        if !file.no_new_privs {
            (new.uid, new.gid) = after_exec(old.uid, old.gid, file.mode, file.uid, file.gid);
        }

        // `get_file_caps` starts from nothing: a plain exec keeps no
        // permitted capability the root rule or the ambient set does not give.
        let mut effective = false;
        new.caps.permitted = 0;
        if let Some(fc) = file.caps {
            effective = fc.effective;
            new.caps.permitted = (old.caps.bounding & fc.permitted) | (old.caps.inheritable & fc.inheritable);
            if effective && fc.permitted & !new.caps.permitted != 0 {
                return Err(EPERM);
            }
        }

        // `handle_privileged_root`. A set-uid-root file that also has file
        // capabilities, run by someone else, gets only the file's.
        if old.securebits & secure::mask(secure::NOROOT) == 0
            && !(file.caps.is_some() && new.uid.real != 0 && new.uid.eff == 0)
        {
            if new.uid.eff == 0 || new.uid.real == 0 {
                new.caps.permitted = old.caps.bounding | old.caps.inheritable;
            }
            if new.uid.eff == 0 {
                effective = true;
            }
        }

        // `in_group_p` of the old credentials: a set-gid program of a group
        // the caller is already in changes no identity.
        let id_changed = new.uid.eff != old.uid.eff || !old.in_group(new.gid.eff);
        let gained = new.caps.permitted & !old.caps.permitted != 0;
        if (id_changed || gained) && file.no_new_privs {
            new.uid.eff = new.uid.real;
            new.gid.eff = new.gid.real;
            new.caps.permitted &= old.caps.permitted;
        }
        new.uid.saved = new.uid.eff;
        new.fsuid = new.uid.eff;
        new.gid.saved = new.gid.eff;
        new.fsgid = new.gid.eff;

        if file.caps.is_some() || id_changed {
            new.caps.ambient = 0;
        }
        new.caps.permitted |= new.caps.ambient;
        new.caps.effective = if effective { new.caps.permitted } else { new.caps.ambient };
        new.securebits &= !secure::mask(secure::KEEP_CAPS);

        let secure = id_changed
            || new.uid.eff != old.uid.real
            || new.gid.eff != old.gid.real
            || (new.uid.real != 0 && (effective || new.caps.permitted & !new.caps.ambient != 0));
        Ok(Exec { creds: new, secure })
    }
}

#[cfg(test)]
mod exec_tests {
    use super::*;

    /// An unprivileged caller: real 1000 everywhere.
    const USER: Ids = Ids {
        real: 1000,
        eff: 1000,
        saved: 1000,
    };

    #[test]
    fn a_setuid_binary_moves_the_effective_and_saved_ids() {
        let (u, g) = after_exec(USER, USER, 0o4755, 0, 0);
        assert_eq!(
            u,
            Ids {
                real: 1000,
                eff: 0,
                saved: 0
            }
        );
        // The real id is untouched -- that is what lets the program know who
        // invoked it, and what setuid(getuid()) drops back to.
        assert_eq!(g, USER);
    }

    #[test]
    fn setgid_needs_the_group_execute_bit() {
        // With it: a real setgid binary.
        let (_, g) = after_exec(USER, USER, 0o2755, 0, 4242);
        assert_eq!(
            g,
            Ids {
                real: 1000,
                eff: 4242,
                saved: 4242
            }
        );
        // Without it: the mandatory-locking marker, and nothing moves.
        let (_, g) = after_exec(USER, USER, 0o2705, 0, 4242);
        assert_eq!(g, USER);
    }

    #[test]
    fn a_plain_exec_still_drops_a_saved_id() {
        // Effective already dropped, saved still privileged: exec is a
        // boundary, so the saved id follows the effective one down and the
        // privilege cannot be taken back afterwards.
        let before = Ids {
            real: 1000,
            eff: 1000,
            saved: 0,
        };
        let (u, _) = after_exec(before, USER, 0o0755, 0, 0);
        assert_eq!(
            u,
            Ids {
                real: 1000,
                eff: 1000,
                saved: 1000
            }
        );
    }

    #[test]
    fn the_saved_id_always_equals_the_effective_one_afterwards() {
        // The invariant, over every combination rather than the cases above.
        for mode in [0o0755u32, 0o4755, 0o2755, 0o2705, 0o6755, 0o0644] {
            for saved in [0u32, 7, 1000] {
                let start = Ids {
                    real: 1000,
                    eff: 1000,
                    saved,
                };
                let (u, g) = after_exec(start, start, mode, 0, 4242);
                assert_eq!(u.saved, u.eff, "mode {mode:o}, saved {saved}");
                assert_eq!(g.saved, g.eff, "mode {mode:o}, saved {saved}");
                // And the real ids never move.
                assert_eq!(u.real, 1000);
                assert_eq!(g.real, 1000);
            }
        }
    }
}

/// The exec rows of `caps_probe`, as the reference kernel answered them.
#[cfg(test)]
mod caps_exec_tests {
    use super::*;
    use crate::caps::{CAP_CHOWN, CAP_FULL, CAP_NET_BIND_SERVICE, CAP_NET_RAW};

    const X: u64 = 1 << CAP_NET_BIND_SERVICE;

    fn plain() -> ExecFile {
        ExecFile { mode: 0o100755, uid: 0, gid: 0, caps: None, no_new_privs: false }
    }

    fn fcap(effective: bool, permitted: u64, inheritable: u64) -> ExecFile {
        ExecFile { caps: Some(FileCaps { permitted, inheritable, effective }), ..plain() }
    }

    fn user() -> Creds {
        let mut c = Creds::default();
        c.setresuid(1000, 1000, 1000).unwrap();
        c
    }

    /// Kept permitted set, inheritable `i`, uid 1000.
    fn user_keeping(i: u64) -> Creds {
        let mut c = Creds::default();
        c.capset(CAP_FULL, CAP_FULL, i).unwrap();
        c.set_keepcaps(1).unwrap();
        c.setresuid(1000, 1000, 1000).unwrap();
        c
    }

    fn sets(e: &Exec) -> (u64, u64, u64, bool) {
        let c = e.creds.caps();
        (c.effective, c.permitted, c.ambient, e.secure)
    }

    #[test]
    fn root_gets_the_bounding_set_unless_noroot() {
        let root = Creds::default();
        assert_eq!(sets(&root.exec(&plain()).unwrap()), (CAP_FULL, CAP_FULL, 0, false));
        let mut bounded = root;
        bounded.cap_bset_drop(CAP_CHOWN as u64).unwrap();
        assert_eq!(bounded.exec(&plain()).unwrap().creds.caps().permitted, CAP_FULL & !1);
        let mut inherited = root;
        inherited.capset(CAP_FULL, CAP_FULL, 1).unwrap();
        inherited.cap_bset_drop(CAP_CHOWN as u64).unwrap();
        assert_eq!(inherited.exec(&plain()).unwrap().creds.caps().permitted, CAP_FULL, "pB | pI");
        let mut noroot = root;
        noroot.set_securebits(1).unwrap();
        assert_eq!(sets(&noroot.exec(&plain()).unwrap()), (0, 0, 0, false));
        assert_eq!(sets(&noroot.exec(&fcap(true, X, 0)).unwrap()), (X, X, 0, false));
        let mut keep = root;
        keep.set_keepcaps(1).unwrap();
        assert!(!keep.exec(&plain()).unwrap().creds.keepcaps(), "cleared by every exec");
    }

    #[test]
    fn a_real_or_effective_root_alone() {
        let mut real = Creds::default();
        real.setresuid(0, 1000, 0).unwrap();
        assert_eq!(sets(&real.exec(&plain()).unwrap()), (0, CAP_FULL, 0, true));
        let mut eff = Creds::default();
        eff.setresuid(1000, 0, 0).unwrap();
        assert_eq!(sets(&eff.exec(&plain()).unwrap()), (CAP_FULL, CAP_FULL, 0, true));
    }

    #[test]
    fn a_user_keeps_only_the_ambient_set() {
        assert_eq!(sets(&user().exec(&plain()).unwrap()), (0, 0, 0, false));
        assert_eq!(sets(&user_keeping(0).exec(&plain()).unwrap()), (0, 0, 0, false));
        let mut amb = user_keeping(X);
        amb.cap_ambient(2, CAP_NET_BIND_SERVICE as u64, 0, 0).unwrap();
        assert_eq!(sets(&amb.exec(&plain()).unwrap()), (X, X, X, false));
    }

    #[test]
    fn file_capabilities() {
        assert_eq!(sets(&user().exec(&fcap(true, X, 0)).unwrap()), (X, X, 0, true));
        assert_eq!(sets(&user().exec(&fcap(false, X, 0)).unwrap()), (0, X, 0, true));
        let raw = 1 << CAP_NET_RAW;
        assert_eq!(sets(&user_keeping(raw).exec(&fcap(false, 0, raw | 1)).unwrap()), (0, raw, 0, true));
        let mut amb = user_keeping(1);
        amb.cap_ambient(2, CAP_CHOWN as u64, 0, 0).unwrap();
        assert_eq!(sets(&amb.exec(&fcap(true, X, 0)).unwrap()), (X, X, 0, true), "ambient cleared");
        assert_eq!(sets(&amb.exec(&fcap(false, 0, 0)).unwrap()), (0, 0, 0, false));
        assert_eq!(sets(&Creds::default().exec(&fcap(false, X, 0)).unwrap()), (CAP_FULL, CAP_FULL, 0, false));
    }

    #[test]
    fn a_file_needing_more_than_the_bounding_set_does_not_start() {
        let mut c = Creds::default();
        c.cap_bset_drop(CAP_NET_BIND_SERVICE as u64).unwrap();
        c.setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(c.exec(&fcap(true, X, 0)).unwrap_err(), EPERM);
        assert_eq!(sets(&c.exec(&fcap(false, X, 0)).unwrap()), (0, 0, 0, false));
    }

    #[test]
    fn setuid_root() {
        let suid = ExecFile { mode: 0o104755, ..plain() };
        let e = user().exec(&suid).unwrap();
        assert_eq!((e.creds.euid(), e.creds.suid()), (0, 0));
        assert_eq!(sets(&e), (CAP_FULL, CAP_FULL, 0, true));
        let mut noroot = Creds::default();
        noroot.set_securebits(1).unwrap();
        noroot.setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(sets(&noroot.exec(&suid).unwrap()), (0, 0, 0, true));
        let mut amb = user_keeping(1);
        amb.cap_ambient(2, CAP_CHOWN as u64, 0, 0).unwrap();
        assert_eq!(sets(&amb.exec(&suid).unwrap()).2, 0, "a set-id exec clears ambient");
        let mixed = ExecFile { caps: Some(FileCaps { permitted: X, inheritable: 0, effective: true }), ..suid };
        assert_eq!(sets(&user().exec(&mixed).unwrap()), (X, X, 0, true), "file caps win");
    }

    #[test]
    fn no_new_privs_adds_nothing() {
        let suid = ExecFile { mode: 0o104755, no_new_privs: true, ..plain() };
        let e = user().exec(&suid).unwrap();
        assert_eq!((e.creds.euid(), e.secure), (1000, false));
        let f = ExecFile { no_new_privs: true, ..fcap(true, X, 0) };
        assert_eq!(sets(&user().exec(&f).unwrap()), (0, 0, 0, true));
    }

    #[test]
    fn a_setgid_program_of_a_group_already_held_changes_no_identity() {
        let sgid = ExecFile { mode: 0o102755, gid: 4242, ..plain() };
        let mut c = user_keeping(1);
        c.cap_ambient(2, CAP_CHOWN as u64, 0, 0).unwrap();
        assert_eq!(c.exec(&sgid).unwrap().creds.caps().ambient, 0);
        let mut member = Creds::default();
        member.capset(CAP_FULL, CAP_FULL, 1).unwrap();
        member.setgroups(&[4242]).unwrap();
        member.set_keepcaps(1).unwrap();
        member.setresuid(1000, 1000, 1000).unwrap();
        member.cap_ambient(2, CAP_CHOWN as u64, 0, 0).unwrap();
        let e = member.exec(&sgid).unwrap();
        assert_eq!((e.creds.egid(), e.creds.caps().ambient), (4242, 1));
    }
}
