//! The rules the twelve extended-attribute syscalls apply before a filesystem
//! sees them.
//!
//! Every one of them is a **refusal**, and that is why they are here rather
//! than in each mount: a filesystem that implements the calls and none of the
//! rules passes every "does it work" test and silently accepts what Linux
//! refuses. The namespace is the whole access-control story for xattrs —
//! `security.capability` is a file capability and `user.*` is the only one an
//! unprivileged program may write — so a mount that lets any name through has
//! given the guest a way around it.
//!
//! # Where these came from
//!
//! Measured, not read: `tests/guest/src/bin/xattr_probe.rs` against an arm64
//! container. Four of them are things `xattr(7)` does not say and one of them
//! contradicts the obvious reading:
//!
//! - `XATTR_CREATE | XATTR_REPLACE` together is **`EEXIST`** when the name is
//!   set and **`ENODATA`** when it is not. Neither is `EINVAL`: the two flags
//!   are not checked against each other at all, `CREATE` is applied first and
//!   `REPLACE` second, and whichever fails first is the answer.
//! - An empty name is **`ERANGE`**, not `EINVAL` — the length is checked before
//!   the prefix, so `""` fails as "0 is not in 1..=255" rather than as "no
//!   namespace".
//! - `"user."` — a good prefix and an empty suffix — is **`EINVAL`**, where
//!   `"user"` is `EOPNOTSUPP`, because the second never matched a prefix.
//! - `system.*` is **`EOPNOTSUPP`**: the namespace exists but is for ACLs,
//!   which this kernel has none of.
//!
//! # What is not here
//!
//! Whether the *value* fits, which is the filesystem's answer and differs
//! between them — the container said `ENOSPC` for a 64 KiB value on overlayfs
//! and `E2BIG` for one byte more, so the `E2BIG` is the kernel's cap and the
//! `ENOSPC` is the disk's. Only the cap is here.

use std::ffi::c_int;

// Guest errnos, negative, as `crates/util/errno` spells them.
pub use guest_errno::c_int_::{E2BIG, EEXIST, EINVAL, ENODATA, EOPNOTSUPP, EPERM, ERANGE};

/// `XATTR_CREATE`: refuse if the name is already set.
pub const XATTR_CREATE: c_int = 1;
/// `XATTR_REPLACE`: refuse if it is not.
pub const XATTR_REPLACE: c_int = 2;

/// `XATTR_NAME_MAX`. Includes the namespace prefix.
pub const NAME_MAX: usize = 255;
/// `XATTR_SIZE_MAX`. A larger value is `E2BIG` before any filesystem is asked.
pub const SIZE_MAX: usize = 65536;
/// `XATTR_LIST_MAX`, for the buffer `listxattr` fills.
pub const LIST_MAX: usize = 65536;

/// Which namespace a name is in.
///
/// The prefixes are Linux's four. There is no "other": a name that matches none
/// of them has no rule that could apply to it, which is what `EOPNOTSUPP` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Namespace {
    /// `user.` — a regular file or a directory, and write permission on it.
    User,
    /// `trusted.` — `CAP_SYS_ADMIN`.
    Trusted,
    /// `security.` — likewise here. Linux lets an LSM decide; there is none.
    Security,
    /// `system.` — ACLs, which this kernel does not have.
    System,
}

const PREFIXES: &[(&[u8], Namespace)] = &[
    (b"user.", Namespace::User),
    (b"trusted.", Namespace::Trusted),
    (b"security.", Namespace::Security),
    (b"system.", Namespace::System),
];

/// The namespace of `name`, or the errno a caller gets for it.
///
/// The order of the three checks is observable and is the order below: length,
/// then prefix, then a non-empty suffix. See the module comment.
pub fn namespace(name: &[u8]) -> Result<Namespace, c_int> {
    if name.is_empty() || name.len() > NAME_MAX {
        return Err(ERANGE);
    }
    let Some((prefix, ns)) = PREFIXES.iter().find(|(p, _)| name.starts_with(p)) else {
        return Err(EOPNOTSUPP);
    };
    if name.len() == prefix.len() {
        return Err(EINVAL);
    }
    Ok(*ns)
}

/// What a file has to be for a `user.*` attribute to be allowed on it.
///
/// Only a regular file or a directory. On anything else the permission the
/// namespace grants — write access to the file — means nothing, so Linux
/// refuses rather than granting a channel with no owner. A symlink is included
/// in "anything else", which is why every `l*xattr` on one is `EPERM`.
pub(crate) fn user_namespace_allows(mode: u32) -> bool {
    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    matches!(mode & S_IFMT, S_IFREG | S_IFDIR)
}

/// `security.capability`, a file capability: written and removed with
/// `CAP_SETFCAP` alone, and a value whose header is not a v2 or v3 is
/// `EINVAL` before the capability is asked (`cap_convert_nscap`, measured).
pub const SECURITY_CAPABILITY: &[u8] = b"security.capability";

/// The two capabilities the namespaces ask.
#[derive(Clone, Copy, Debug, Default)]
pub struct Privilege {
    /// `CAP_SYS_ADMIN`: `trusted.*`, and `security.*` other than a file
    /// capability.
    pub sys_admin: bool,
    /// `CAP_SETFCAP`: `security.capability`.
    pub setfcap: bool,
}

/// Whether this name may be read or written at all, before the filesystem is
/// asked.
///
/// `mode` is the target's `st_mode`. `writing` separates `setxattr` and
/// `removexattr`, which need the permission, from `getxattr`, which does not
/// except for `trusted.*`: without `CAP_SYS_ADMIN` such an attribute is
/// invisible, and reading one answers `ENODATA` rather than `EPERM`
/// (`xattr_permission`).
///
/// A *set* of `security.capability` passes here: its value has to be read
/// and validated before the capability is asked, which is the caller's.
pub fn check(name: &[u8], mode: u32, privilege: Privilege, writing: bool) -> Result<Namespace, c_int> {
    let ns = namespace(name)?;
    match ns {
        // ACLs. The namespace is defined and this kernel implements nothing in
        // it, which is `EOPNOTSUPP` rather than `EPERM` -- the difference
        // between "not here" and "not for you".
        Namespace::System => Err(EOPNOTSUPP),
        Namespace::Trusted if !privilege.sys_admin => Err(if writing { EPERM } else { ENODATA }),
        Namespace::Security if writing && name == SECURITY_CAPABILITY => Ok(ns),
        Namespace::Security if writing && !privilege.sys_admin => Err(EPERM),
        Namespace::User if writing && !user_namespace_allows(mode) => Err(EPERM),
        _ => Ok(ns),
    }
}

/// The flags `setxattr` accepts. A bit outside them is `EINVAL`.
pub fn check_flags(flags: c_int) -> Result<(), c_int> {
    if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
        return Err(EINVAL);
    }
    Ok(())
}

/// What the two flags say about a name that is, or is not, already set.
///
/// **Not "the two together are invalid"**, which is the obvious reading and is
/// wrong: they are applied one after the other, so both set over an existing
/// name is `EEXIST` and both over a missing one is `ENODATA`.
pub fn check_exists(flags: c_int, exists: bool) -> Result<(), c_int> {
    if flags & XATTR_CREATE != 0 && exists {
        return Err(EEXIST);
    }
    if flags & XATTR_REPLACE != 0 && !exists {
        return Err(ENODATA);
    }
    Ok(())
}

/// Whether a value may be stored at all. The filesystem may still refuse a
/// smaller one for its own reasons.
pub fn check_value(len: usize) -> Result<(), c_int> {
    if len > SIZE_MAX {
        return Err(E2BIG);
    }
    Ok(())
}

/// How large a kernel buffer an *answer* of `size` bytes needs: the caller's
/// number, clamped to `cap`.
///
/// `getxattr` and `listxattr` take the buffer length from the guest and nothing
/// above bounds it — the caller passes a number, not a buffer, and a number can
/// be `u64::MAX`. Linux clamps it (`XATTR_SIZE_MAX`, `XATTR_LIST_MAX`) before
/// allocating and this does the same, for two reasons rather than one:
///
/// - **A clamp is what Linux answers.** An attribute cannot exceed the cap, so
///   a caller asking for more gets the same bytes it would get for exactly the
///   cap. Refusing a large `size` with an errno would be a divergence.
/// - **`vec![0u8; size]` aborts.** Rust's allocation failure is not a `NULL` to
///   test; it is `handle_alloc_error`, and this crate's kernel is a library in
///   somebody else's process. `getxattr(path, name, buf, 1 << 48)` took the
///   whole emulator down with `signal 6` until 2026-09-14, from an
///   unprivileged guest, in one syscall.
///
/// **A set is not clamped and must not be**: [`check_value`] has already
/// refused anything above the cap with `E2BIG`, and clamping there would store
/// a truncated value where Linux refuses the call.
pub fn buffer_len(size: u64, cap: usize) -> usize {
    size.min(cap as u64) as usize
}

/// Copy an answer into the caller's buffer, or report its length.
///
/// A `size` of 0 is a question about the length and writes nothing; a buffer
/// that is too small is `ERANGE` and **not a truncated answer**, which is the
/// difference between a caller that retries with a bigger buffer and one that
/// reads rubbish.
pub fn fit(answer: &[u8], size: usize) -> Result<usize, c_int> {
    if size == 0 {
        return Ok(answer.len());
    }
    if answer.len() > size {
        return Err(ERANGE);
    }
    Ok(answer.len())
}

/// The NUL-separated, NUL-terminated list `listxattr` produces.
///
/// Every name is followed by a NUL, including the last — so the length of a
/// one-name list is the name plus one, and an empty list is zero bytes rather
/// than one.
pub fn pack_list(names: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for n in names {
        out.extend_from_slice(n);
        out.push(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(all: bool) -> Privilege {
        Privilege { sys_admin: all, setfcap: all }
    }

    const REG: u32 = 0o100644;
    const DIR: u32 = 0o040755;
    const FIFO: u32 = 0o010644;
    const LNK: u32 = 0o120777;

    #[test]
    fn the_three_name_checks_are_in_the_order_a_caller_can_see() {
        // Every line is `xattr_probe`'s against a real arm64 kernel. The order
        // is what makes them different answers: length, prefix, suffix.
        assert_eq!(namespace(b""), Err(ERANGE), "empty is a length failure");
        assert_eq!(namespace(&[b'x'; 256]), Err(ERANGE));
        assert_eq!(namespace(b"nodots"), Err(EOPNOTSUPP));
        assert_eq!(namespace(b"bogus.a"), Err(EOPNOTSUPP));
        assert_eq!(namespace(b"userx.a"), Err(EOPNOTSUPP));
        assert_eq!(namespace(b"user"), Err(EOPNOTSUPP), "no dot, so no prefix");
        assert_eq!(namespace(b"user."), Err(EINVAL), "prefix, empty suffix");
        assert_eq!(namespace(b"."), Err(EOPNOTSUPP));
        assert_eq!(namespace(b"user.a"), Ok(Namespace::User));
        assert_eq!(namespace(b"trusted.a"), Ok(Namespace::Trusted));
        assert_eq!(namespace(b"security.a"), Ok(Namespace::Security));
        assert_eq!(namespace(b"system.a"), Ok(Namespace::System));
    }

    #[test]
    fn a_name_of_exactly_255_is_allowed_and_256_is_not() {
        let mut n = b"user.".to_vec();
        n.resize(255, b'n');
        assert_eq!(namespace(&n), Ok(Namespace::User));
        n.push(b'n');
        assert_eq!(namespace(&n), Err(ERANGE));
    }

    #[test]
    fn user_attributes_go_on_files_and_directories_only() {
        assert!(user_namespace_allows(REG));
        assert!(user_namespace_allows(DIR));
        assert!(!user_namespace_allows(FIFO));
        assert!(
            !user_namespace_allows(LNK),
            "which is why lsetxattr is EPERM"
        );
        assert_eq!(check(b"user.a", FIFO, p(false), true), Err(EPERM));
        assert_eq!(
            check(b"user.a", LNK, p(true), true),
            Err(EPERM),
            "even for root"
        );
        assert_eq!(check(b"user.a", DIR, p(false), true), Ok(Namespace::User));
    }

    #[test]
    fn reading_is_not_writing() {
        // A `trusted.*` attribute a caller without CAP_SYS_ADMIN may not write
        // is invisible rather than forbidden: ENODATA, which is what tells a
        // caller nothing is there rather than that something is being kept
        // from it -- whether or not root set one.
        assert_eq!(check(b"trusted.a", REG, p(false), true), Err(EPERM));
        assert_eq!(check(b"trusted.a", REG, p(false), false), Err(ENODATA));
        assert_eq!(check(b"trusted.a", REG, p(true), true), Ok(Namespace::Trusted));
        // security.* is CAP_SYS_ADMIN's to write, except the file capability,
        // which is CAP_SETFCAP's and judged after its value is read.
        assert_eq!(check(b"security.a", REG, p(false), true), Err(EPERM));
        assert_eq!(check(b"security.a", REG, p(false), false), Ok(Namespace::Security));
        assert_eq!(check(b"security.capability", REG, p(false), true), Ok(Namespace::Security));
        // And a `user.*` on a fifo is refused for a write and not for a read,
        // for the same reason: there is nothing there either way.
        assert_eq!(check(b"user.a", FIFO, p(false), false), Ok(Namespace::User));
    }

    #[test]
    fn system_is_not_here_rather_than_not_for_you() {
        // EOPNOTSUPP for everyone, privileged or not, reading or writing: the
        // namespace is ACLs and this kernel has none.
        for privileged in [false, true] {
            for writing in [false, true] {
                assert_eq!(
                    check(b"system.posix_acl_access", REG, p(privileged), writing),
                    Err(EOPNOTSUPP)
                );
            }
        }
    }

    #[test]
    fn the_two_flags_are_applied_in_turn_and_not_compared() {
        assert_eq!(check_flags(0), Ok(()));
        assert_eq!(check_flags(XATTR_CREATE), Ok(()));
        assert_eq!(
            check_flags(XATTR_CREATE | XATTR_REPLACE),
            Ok(()),
            "not EINVAL"
        );
        assert_eq!(check_flags(0x40), Err(EINVAL));

        assert_eq!(check_exists(0, true), Ok(()));
        assert_eq!(check_exists(0, false), Ok(()));
        assert_eq!(check_exists(XATTR_CREATE, true), Err(EEXIST));
        assert_eq!(check_exists(XATTR_CREATE, false), Ok(()));
        assert_eq!(check_exists(XATTR_REPLACE, true), Ok(()));
        assert_eq!(check_exists(XATTR_REPLACE, false), Err(ENODATA));
        // The pair the probe was extended for: CREATE first, then REPLACE.
        assert_eq!(
            check_exists(XATTR_CREATE | XATTR_REPLACE, true),
            Err(EEXIST)
        );
        assert_eq!(
            check_exists(XATTR_CREATE | XATTR_REPLACE, false),
            Err(ENODATA)
        );
    }

    #[test]
    fn a_size_of_zero_asks_the_length_and_a_short_buffer_is_range() {
        assert_eq!(fit(b"three", 0), Ok(5));
        assert_eq!(fit(b"three", 5), Ok(5));
        assert_eq!(fit(b"three", 6), Ok(5));
        assert_eq!(fit(b"three", 4), Err(ERANGE));
        assert_eq!(fit(b"", 0), Ok(0), "an empty value has a length too");
        assert_eq!(fit(b"", 1), Ok(0));
    }

    #[test]
    fn the_list_terminates_every_name_including_the_last() {
        assert_eq!(pack_list(&[]), b"");
        assert_eq!(pack_list(&[b"user.a".to_vec()]), b"user.a\0");
        assert_eq!(
            pack_list(&[b"user.a".to_vec(), b"user.b".to_vec()]),
            b"user.a\0user.b\0"
        );
        // Which is the length the probe measured: one name of six is seven.
        assert_eq!(pack_list(&[b"user.a".to_vec()]).len(), 7);
    }

    #[test]
    fn the_value_cap_is_the_kernels_and_64_kib_is_allowed() {
        assert_eq!(check_value(0), Ok(()));
        assert_eq!(check_value(SIZE_MAX), Ok(()));
        assert_eq!(check_value(SIZE_MAX + 1), Err(E2BIG));
    }

    #[test]
    fn an_answer_buffer_is_the_callers_size_until_the_cap() {
        assert_eq!(buffer_len(0, SIZE_MAX), 0, "0 asks the length");
        assert_eq!(buffer_len(64, SIZE_MAX), 64);
        assert_eq!(buffer_len(SIZE_MAX as u64, SIZE_MAX), SIZE_MAX);
        // The number a guest can pass, which is the whole point: not an
        // allocation, and not an error either.
        assert_eq!(buffer_len(1 << 48, SIZE_MAX), SIZE_MAX);
        assert_eq!(buffer_len(u64::MAX, SIZE_MAX), SIZE_MAX);
        assert_eq!(buffer_len(u64::MAX, LIST_MAX), LIST_MAX);
    }
}
