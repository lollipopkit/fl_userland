//! Discretionary access and hard-link permission rules.

use std::ffi::c_int;

use super::EPERM;
use crate::caps::{CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH};

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_IXGRP: u32 = 0o0010;

/// `EACCES`, the guest's, from `crates/util/errno`.
pub(crate) use guest_errno::c_int_::EACCES;

/// The permission bits, in the order they sit in a mode.
pub const AC_R: u32 = 4;
pub const AC_W: u32 = 2;
pub const AC_X: u32 = 1;

/// Whether `gid` is one the caller belongs to, as its effective group or a
/// supplementary one.
pub(crate) fn in_group(egid: u32, groups: &[u32], gid: u32) -> bool {
    egid == gid || groups.contains(&gid)
}

/// Which triad of a mode applies to this caller.
///
/// Owner wins outright: a caller that owns the node is judged on the owner bits
/// alone, even where the group bits would allow more. That is Linux's rule and
/// it is deliberately not a fallback chain.
fn applicable_bits(euid: u32, egid: u32, groups: &[u32], uid: u32, gid: u32, mode: u32) -> u32 {
    if euid == uid {
        (mode >> 6) & 7
    } else if in_group(egid, groups, gid) {
        (mode >> 3) & 7
    } else {
        mode & 7
    }
}

/// May a caller with these ids and this effective set do `want` to a node
/// with these ids and mode? Linux's `generic_permission`.
///
/// `want` is a mask of `AC_R`/`AC_W`/`AC_X`. **Every** requested bit must be
/// granted. The C this replaces tested `!(mode & check)`, which is "none of
/// them", so a request for read and write together succeeded where only read
/// was granted -- and `open(O_RDWR)` is exactly that request.
///
/// The mode bits are asked first and the two capabilities only when they
/// refuse, which keeps the common case free of them:
///
/// ```c
/// if (S_ISDIR(inode->i_mode)) {
///         if (!(mask & MAY_WRITE))
///                 if (capable_wrt_inode_uidgid(..., CAP_DAC_READ_SEARCH))
///                         return 0;
///         if (capable_wrt_inode_uidgid(..., CAP_DAC_OVERRIDE))
///                 return 0;
///         return -EACCES;
/// }
/// if (mask == MAY_READ)
///         if (capable_wrt_inode_uidgid(..., CAP_DAC_READ_SEARCH))
///                 return 0;
/// if (!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO))
///         if (capable_wrt_inode_uidgid(..., CAP_DAC_OVERRIDE))
///                 return 0;
/// ```
///
/// So `CAP_DAC_OVERRIDE` grants execute only where somebody could execute
/// the file, and `CAP_DAC_READ_SEARCH` reads files and searches and lists
/// directories but writes nothing (`caps_probe`).
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn access(
    caps: u64,
    euid: u32,
    egid: u32,
    groups: &[u32],
    uid: u32,
    gid: u32,
    mode: u32,
    want: u32,
) -> Result<(), c_int> {
    let have = applicable_bits(euid, egid, groups, uid, gid, mode);
    if have & want == want {
        return Ok(());
    }
    let override_ = caps & (1 << CAP_DAC_OVERRIDE) != 0;
    let read_search = caps & (1 << CAP_DAC_READ_SEARCH) != 0;
    if mode & S_IFMT == S_IFDIR {
        if (want & AC_W == 0 && read_search) || override_ {
            return Ok(());
        }
        return Err(EACCES);
    }
    if want == AC_R && read_search {
        return Ok(());
    }
    if override_ && (want & AC_X == 0 || mode & 0o111 != 0) {
        return Ok(());
    }
    Err(EACCES)
}

#[cfg(test)]
mod privileged_exec_tests {
    use super::{AC_R, AC_W, AC_X, EACCES, access};
    use crate::caps::{CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FULL};

    const ALL: u64 = CAP_FULL;

    /// Each of the two capabilities alone, as `caps_probe` measured them.
    #[test]
    fn read_search_reads_and_searches_and_writes_nothing() {
        let rs = 1 << CAP_DAC_READ_SEARCH;
        let reg = 0o100_600;
        let dir = 0o040_700;
        assert_eq!(access(rs, 0, 0, &[], 1000, 1000, reg, AC_R), Ok(()));
        assert_eq!(access(rs, 0, 0, &[], 1000, 1000, reg, AC_W), Err(EACCES));
        assert_eq!(access(rs, 0, 0, &[], 1000, 1000, reg, AC_R | AC_W), Err(EACCES));
        assert_eq!(access(rs, 0, 0, &[], 1000, 1000, dir, AC_R | AC_X), Ok(()));
        assert_eq!(access(rs, 0, 0, &[], 1000, 1000, dir, AC_W | AC_X), Err(EACCES));
        let ov = 1 << CAP_DAC_OVERRIDE;
        assert_eq!(access(ov, 0, 0, &[], 1000, 1000, reg, AC_R | AC_W), Ok(()));
        assert_eq!(access(ov, 0, 0, &[], 1000, 1000, dir, AC_W | AC_X), Ok(()));
        assert_eq!(access(0, 0, 0, &[], 1000, 1000, reg, AC_R), Err(EACCES));
    }

    /// `CAP_DAC_OVERRIDE` grants read and write on anything and execute only
    /// where at least one execute bit is set. Root running a file nobody can
    /// execute is the one thing the capability does not cover, and it is what
    /// makes `command -v` answer honestly: a shell asks `access(X_OK)` before
    /// it reports a path.
    #[test]
    fn root_cannot_execute_a_file_with_no_execute_bit() {
        let reg = 0o100_000;
        assert_eq!(
            access(ALL, 0, 0, &[], 1000, 1000, reg | 0o666, AC_X),
            Err(EACCES)
        );
        assert_eq!(
            access(ALL, 0, 0, &[], 1000, 1000, reg | 0o666, AC_R),
            Ok(())
        );
        assert_eq!(
            access(ALL, 0, 0, &[], 1000, 1000, reg | 0o600, AC_R | AC_W),
            Ok(())
        );
        // One bit anywhere is enough, even somebody else's.
        assert_eq!(
            access(ALL, 0, 0, &[], 1000, 1000, reg | 0o001, AC_X),
            Ok(())
        );
        assert_eq!(
            access(ALL, 0, 0, &[], 1000, 1000, reg | 0o100, AC_X),
            Ok(())
        );
        // And read-and-execute together fails on the execute half.
        assert_eq!(
            access(ALL, 0, 0, &[], 1000, 1000, reg | 0o666, AC_R | AC_X),
            Err(EACCES)
        );
    }

    /// A directory is searchable for a privileged caller whatever its bits say.
    /// Without the exemption, `chmod 000 /somedir` would lock root out of it.
    #[test]
    fn a_directory_is_always_searchable_for_root() {
        let dir = 0o040_000;
        assert_eq!(access(ALL, 0, 0, &[], 1000, 1000, dir, AC_X), Ok(()));
        assert_eq!(
            access(ALL, 0, 0, &[], 1000, 1000, dir, AC_R | AC_X),
            Ok(())
        );
    }

    /// Nothing changes for an unprivileged caller.
    #[test]
    fn the_ordinary_rules_are_untouched() {
        let reg = 0o100_000;
        assert_eq!(
            access(0, 1000, 1000, &[], 1000, 1000, reg | 0o700, AC_X),
            Ok(())
        );
        assert_eq!(
            access(0, 1000, 1000, &[], 1000, 1000, reg | 0o600, AC_X),
            Err(EACCES)
        );
        assert_eq!(access(0, 1000, 1000, &[], 1000, 1000, reg, 0), Ok(()));
    }
}

/// `protected_hardlinks`: may this caller make a hard link to this file?
///
/// A hard link *pins* an inode: once made, the owner of the original cannot get
/// rid of it by unlinking their copy, and the permissions the link is checked
/// against are the inode's, which the linker may later be able to change. So
/// linking to something you cannot already read and write is a way to keep a
/// reference to a file you were never allowed to have — a set-uid binary, or a
/// file in a directory that is about to become unreadable.
///
/// Linux calls this `may_linkat`, gates it on `sysctl_protected_hardlinks`, and
/// has had it on by default since 3.6 — every distribution ships it enabled.
///
/// ```c
/// static bool safe_hardlink_source(struct inode *inode)
/// {
///     umode_t mode = inode->i_mode;
///     if (!S_ISREG(mode))                                 return false;
///     if (mode & S_ISUID)                                 return false;
///     if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) return false;
///     if (inode_permission(idmap, inode, MAY_READ | MAY_WRITE)) return false;
///     return true;
/// }
/// ```
///
/// and the answer is `safe_hardlink_source(inode) || inode_owner_or_capable()`,
/// else `EPERM`. Note the shape: **the owner may always link their own file**,
/// even a set-uid one, because they could have made it themselves.
///
/// `privileged` is `CAP_FOWNER`, which `inode_owner_or_capable` asks for and
/// which setting the fsuid away from root drops.
pub fn may_link(
    privileged: bool,
    fsuid: u32,
    fsgid: u32,
    groups: &[u32],
    node_uid: u32,
    node_gid: u32,
    node_mode: u32,
) -> Result<(), c_int> {
    if privileged || node_uid == fsuid {
        return Ok(());
    }
    if safe_hardlink_source(fsuid, fsgid, groups, node_uid, node_gid, node_mode) {
        return Ok(());
    }
    Err(EPERM)
}

/// The `safe_hardlink_source` half of [`may_link`], for a caller who is neither
/// the owner nor privileged.
fn safe_hardlink_source(
    fsuid: u32,
    fsgid: u32,
    groups: &[u32],
    node_uid: u32,
    node_gid: u32,
    node_mode: u32,
) -> bool {
    // Anything that is not a plain file: a device node, a fifo, a socket. None
    // of them should be pinned to the filesystem by someone who does not own
    // it, and a symlink is not linkable at all.
    if node_mode & S_IFMT != S_IFREG {
        return false;
    }
    // A set-uid file, or a set-gid one that is group-executable. The set-gid
    // bit on a file that is not executable means mandatory locking, not
    // privilege, which is why the test is on the pair.
    if node_mode & S_ISUID != 0 {
        return false;
    }
    if node_mode & (S_ISGID | S_IXGRP) == (S_ISGID | S_IXGRP) {
        return false;
    }
    // And it has to be something the caller could already have copied.
    access(
        0,
        fsuid,
        fsgid,
        groups,
        node_uid,
        node_gid,
        node_mode,
        AC_R | AC_W,
    )
    .is_ok()
}

/* `creds_in_group` was here: a `(*const u32, u32)` pair, a null-or-empty arm,
 * and a `bool` widened to `c_int`, over `in_group(egid, &[u32], gid)` two
 * functions up. **No caller anywhere in the tree** -- the attribute rules its
 * doc comment named reach `in_group` directly. Removed 2026-09-16 with the
 * rest of the adapter layer; `pub` is not a reachability signal, which is why
 * nothing reported it. */

#[cfg(test)]
mod access_tests {
    use super::*;

    const ALL: u64 = crate::caps::CAP_FULL;

    fn ok(mode: u32, want: u32) -> bool {
        // Caller owns the node, so the owner triad applies.
        access(0, 1000, 1000, &[], 1000, 1000, mode, want).is_ok()
    }

    #[test]
    fn every_requested_bit_must_be_granted() {
        // The defect: read-and-write on a read-only file.
        assert!(ok(0o400, AC_R));
        assert!(!ok(0o400, AC_W));
        assert!(!ok(0o400, AC_R | AC_W));
        assert!(ok(0o600, AC_R | AC_W));
        assert!(!ok(0o600, AC_R | AC_W | AC_X));
        assert!(ok(0o700, AC_R | AC_W | AC_X));
    }

    /// The property that catches it without restating the implementation:
    /// permission is monotone in what you ask for. If a larger request is
    /// granted, every subset of it must be too — and conversely a request that
    /// fails cannot be made to succeed by asking for *more*.
    ///
    /// `!(mode & check)` violates this directly: `W` on 0400 fails while
    /// `R|W` on 0400 succeeds.
    #[test]
    fn asking_for_more_never_succeeds_where_less_failed() {
        for mode in 0..0o1000u32 {
            for want in 0..8u32 {
                if !ok(mode, want) {
                    continue;
                }
                for smaller in 0..8u32 {
                    if smaller & want == smaller {
                        assert!(
                            ok(mode, smaller),
                            "mode {mode:o}: {want:03b} is allowed but its subset {smaller:03b} is not"
                        );
                    }
                }
            }
        }
    }

    /// And monotone in what is granted: adding a bit to the mode never takes
    /// permission away.
    #[test]
    fn granting_more_never_denies_more() {
        for mode in 0..0o1000u32 {
            for extra in 0..0o1000u32 {
                let richer = mode | extra;
                for want in 0..8u32 {
                    if ok(mode, want) {
                        assert!(
                            ok(richer, want),
                            "{mode:o} allows {want:03b}, {richer:o} does not"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_supplementary_group_counts() {
        // Mode 0040: readable only through the group, and the caller is not the
        // owner. Reachable only if supplementary groups are consulted.
        assert!(access(0, 1000, 1000, &[4242], 0, 4242, 0o040, AC_R).is_ok());
        // The control: with the group bits clear it is still refused, so the
        // group path is not a way in on its own.
        assert!(access(0, 1000, 1000, &[4242], 0, 4242, 0o400, AC_R).is_err());
        // And a group the caller is not in does not help.
        assert!(access(0, 1000, 1000, &[7], 0, 4242, 0o040, AC_R).is_err());
    }

    #[test]
    fn the_owner_triad_wins_even_when_it_grants_less() {
        // Owner has nothing, group has everything, and the caller is both. The
        // owner bits decide: a fallback chain would allow this.
        assert!(access(0, 1000, 1000, &[], 1000, 1000, 0o077, AC_R).is_err());
        // Not the owner, and the group grants it: allowed.
        assert!(access(0, 1000, 1000, &[], 42, 1000, 0o077, AC_R).is_ok());
    }

    #[test]
    fn root_and_empty_requests_pass() {
        // Read and write on anything, and execute where the mode has an
        // execute bit -- see `privileged_exec_tests` for the one case that is
        // not overridable. The type bits are part of the mode here, and a mode
        // of 0o000 is not a directory, so it does not get the search exemption.
        assert!(access(ALL, 1000, 1000, &[], 0, 0, 0o100_000, AC_R | AC_W).is_ok());
        assert!(access(ALL, 1000, 1000, &[], 0, 0, 0o100_111, AC_R | AC_W | AC_X).is_ok());
        // F_OK: asking for nothing is asking whether it exists, which the
        // caller has already established by getting a stat.
        assert!(access(0, 1000, 1000, &[], 0, 0, 0o000, 0).is_ok());
    }
}
