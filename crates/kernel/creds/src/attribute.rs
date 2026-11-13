//! Permission rules for changing filesystem attributes.

use std::ffi::c_int;

use super::{AC_W, EPERM, access, in_group};
use crate::caps::{CAP_CHOWN, CAP_FOWNER};

#[cfg(test)]
use crate::access::EACCES;

// ------------------------------------------------------- attribute changes

/// Which attribute a request changes, carrying the new value where the rule
/// reads it: the owner and the group are judged by what they become, the mode
/// and the size only by who is asking.
///
/// Four `c_int`s and a `u32` beside them until 2026-09-29, matching the C's
/// `enum attr_type`, with a `_ => EPERM` for the numbers no caller could mean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Mode,
    Uid(u32),
    Gid(u32),
    Size,
}

const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_IXGRP: u32 = 0o0010;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

/// May this caller make this change to this node?
///
/// | change | permitted to |
/// | --- | --- |
/// | mode | the owner, or `CAP_FOWNER` |
/// | uid | `CAP_CHOWN`; the owner may name the owner it has, since programs re-chown to the same id to touch ctime |
/// | gid | the owner, to a group they belong to; `CAP_CHOWN`, to any |
/// | size | write permission, because a truncate is a write |
///
/// `chown_ok` asks for the owner on the no-op too: a stranger re-chowning a
/// file to its own owner is `EPERM`, which this allowed until 2026-11-13.
///
/// There was no check of any kind in the C. With set-id exec working that was a
/// local root: chown a shell to 0:0, chmod it setuid, run it.
#[allow(clippy::too_many_arguments)]
pub fn setattr(
    caps: u64,
    euid: u32,
    egid: u32,
    groups: &[u32],
    node_uid: u32,
    node_gid: u32,
    node_mode: u32,
    change: Change,
) -> Result<(), c_int> {
    let capable = |cap: u32| caps & (1 << cap) != 0;
    let owner = euid == node_uid;
    match change {
        Change::Mode if owner || capable(CAP_FOWNER) => Ok(()),
        Change::Uid(uid) if (owner && uid == node_uid) || capable(CAP_CHOWN) => Ok(()),
        Change::Gid(gid) if (owner && (gid == node_gid || in_group(egid, groups, gid))) || capable(CAP_CHOWN) => {
            Ok(())
        }
        Change::Size => access(caps, euid, egid, groups, node_uid, node_gid, node_mode, AC_W),
        Change::Mode | Change::Uid(_) | Change::Gid(_) => Err(EPERM),
    }
}

/// The mode a node must be reduced to after its ownership changes, or `None`
/// if nothing has to change.
///
/// Linux's `chown_common` asks for the set-id bits to be killed on any
/// non-directory, and `should_remove_suid` spells out the asymmetry:
///
/// > suid always must be killed. sgid without any exec bits is just a mandatory
/// > locking mark; leave it alone. If some exec bits are set, it's a real sgid,
/// > kill it.
///
/// The same `S_IXGRP` distinction the exec path needs, for the same reason: a
/// setgid bit without it is not a setgid binary.
pub fn mode_after_chown(mode: u32) -> Option<u32> {
    if mode & S_IFMT == S_IFDIR {
        return None;
    }
    let mut out = mode;
    out &= !S_ISUID;
    if mode & S_IXGRP != 0 {
        out &= !S_ISGID;
    }
    if out == mode { None } else { Some(out) }
}
/* `creds_mode_after_chown` was here: `mode_after_chown` with its `Option`
 * flattened onto `-1`, which both callers tested with `if reduced >= 0` and
 * then cast back. A sentinel for an answer the type already has. Removed
 * 2026-09-16. */

#[cfg(test)]
mod setattr_tests {
    use super::*;

    const OURS: (u32, u32) = (1000, 1000);

    const ALL: u64 = crate::caps::CAP_FULL;

    fn try_set(change: Change, node_uid: u32) -> Result<(), c_int> {
        setattr(0, OURS.0, OURS.1, &[], node_uid, 1000, 0o644, change)
    }

    #[test]
    fn chmod_needs_ownership() {
        assert!(try_set(Change::Mode, 1000).is_ok());
        assert_eq!(try_set(Change::Mode, 0), Err(EPERM));
    }

    #[test]
    fn chown_to_a_new_uid_needs_privilege() {
        // Not even on a file we own -- giving a file away is privileged.
        assert_eq!(try_set(Change::Uid(0), 1000), Err(EPERM));
        assert_eq!(try_set(Change::Uid(1000), 0), Err(EPERM));
        // A no-op is allowed to the owner: programs re-chown to the same id
        // to touch ctime. Not to anyone else (`chown_ok`).
        assert!(try_set(Change::Uid(1000), 1000).is_ok());
        assert_eq!(try_set(Change::Uid(0), 0), Err(EPERM));
        // CAP_CHOWN allows anything, and is the only capability asked.
        assert!(setattr(1 << CAP_CHOWN, 1000, 1000, &[], 0, 0, 0o644, Change::Uid(42)).is_ok());
        assert!(setattr(1 << CAP_CHOWN, 1000, 1000, &[], 0, 0, 0o644, Change::Gid(42)).is_ok());
        assert_eq!(setattr(ALL & !(1 << CAP_CHOWN), 1000, 1000, &[], 0, 0, 0o644, Change::Uid(42)), Err(EPERM));
        assert_eq!(setattr(ALL & !(1 << CAP_FOWNER), 1000, 1000, &[], 0, 0, 0o644, Change::Mode), Err(EPERM));
        assert!(setattr(1 << CAP_FOWNER, 1000, 1000, &[], 0, 0, 0o644, Change::Mode).is_ok());
    }

    #[test]
    fn chgrp_needs_ownership_and_membership() {
        let owned = |groups: &[u32], gid: u32| {
            setattr(0, 1000, 1000, groups, 1000, 1000, 0o644, Change::Gid(gid))
        };
        assert!(owned(&[4242], 4242).is_ok(), "a group we are in");
        assert_eq!(owned(&[7], 4242), Err(EPERM), "a group we are not in");
        assert!(owned(&[], 1000).is_ok(), "our own effective group");
        // Ownership is required as well as membership.
        assert_eq!(
            setattr(0, 1000, 1000, &[4242], 0, 1000, 0o644, Change::Gid(4242)),
            Err(EPERM)
        );
    }

    #[test]
    fn truncate_needs_write_permission() {
        let with_mode = |mode: u32, node_uid: u32| {
            setattr(0, 1000, 1000, &[], node_uid, 1000, mode, Change::Size)
        };
        assert!(with_mode(0o600, 1000).is_ok());
        assert_eq!(
            with_mode(0o400, 1000),
            Err(EACCES),
            "a read-only file is EACCES, not EPERM"
        );
        assert!(with_mode(0o666, 0).is_ok(), "not ours, but world-writable");
    }

    #[test]
    fn chown_kills_the_set_id_bits() {
        // suid always.
        assert_eq!(mode_after_chown(0o4755), Some(0o0755));
        // sgid only when a group-execute bit says it is a real setgid binary.
        assert_eq!(mode_after_chown(0o2755), Some(0o0755));
        // Without S_IXGRP it is the mandatory-locking marker, and stays.
        assert_eq!(mode_after_chown(0o2705), None);
        assert_eq!(mode_after_chown(0o6755), Some(0o0755));
        // Nothing to do for an ordinary mode, so the caller does no extra work.
        assert_eq!(mode_after_chown(0o0644), None);
        // Directories keep theirs: S_ISGID on a directory is inheritance, not
        // privilege, and killing it would change how files inside are created.
        assert_eq!(mode_after_chown(S_IFDIR | 0o2775), None);
    }
}
