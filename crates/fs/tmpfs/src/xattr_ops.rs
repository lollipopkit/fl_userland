//! Extended attribute operations for the in-memory filesystem.


use crate::errno::{EBADF, EINVAL, Result};
use crate::ffi;
use crate::{CStr, Dirent, Timespec, fd_state, lock, lookup, mount_root};

// ============================================================
// fs_ops: extended attributes
// ============================================================

/// One operation on an inode's attribute map.
///
/// The namespace and flag rules are `crates/fs/xattrabi`'s and have already
/// been applied by the time this runs — what is left is the storage, and the
/// two rules that belong to it: `XATTR_CREATE`/`XATTR_REPLACE` need to know
/// whether the name is *there*, which only this layer can say, and a buffer
/// that is too small is `ERANGE` rather than a truncated answer.
///
/// Unlike `crates/fs/realfs` this has no host limit behind it, so Linux's
/// 255-byte name and 64 KiB value are the only caps — which is why
/// `fs_conformance` checks the long-name rule on this mount and not on the
/// other two.
pub(crate) fn xattr_op(dirent: &Dirent, call: ffi::XattrCall<'_>) -> Result<isize> {
    let mut body = lock(&dirent.inode.body);
    match call {
        ffi::XattrCall::Get { name, out } => {
            let found = body.xattrs.get(name.to_bytes()).ok_or(xattrabi::ENODATA)?;
            let n = xattrabi::fit(found, out.len())?;
            if !out.is_empty() {
                out[..n].copy_from_slice(found);
            }
            Ok(n as isize)
        }
        ffi::XattrCall::Set { name, value, flags } => {
            let name = name.to_bytes();
            xattrabi::check_exists(flags, body.xattrs.contains_key(name))?;
            body.xattrs.insert(name.to_vec(), value.to_vec());
            body.ctime = Timespec::now();
            Ok(0)
        }
        ffi::XattrCall::List { out } => {
            let names: Vec<Vec<u8>> = body.xattrs.keys().cloned().collect();
            let list = xattrabi::pack_list(&names);
            let n = xattrabi::fit(&list, out.len())?;
            if !out.is_empty() {
                out[..n].copy_from_slice(&list);
            }
            Ok(n as isize)
        }
        ffi::XattrCall::Remove { name } => {
            body.xattrs.remove(name.to_bytes()).ok_or(xattrabi::ENODATA)?;
            body.ctime = Timespec::now();
            Ok(0)
        }
    }
}

// `xattr_args` was here until 2026-09-15. Its whole job was to unpack the
// `XattrCall` struct's `*mut c_void` and `usize` into a `&mut [u8]` and a
// `&[u8]` **from the same pointer**, with a comment saying "only one is used
// per call" -- two live slices over one allocation kept apart by a convention.
// `XattrCall` is an enum with the buffer in each arm now, so there is nothing
// to unpack and the three `name.ok_or(EINVAL)?` above went with it: a `Get`
// has a name by construction.

pub(crate) fn tmpfs_xattr(mount: &ffi::mount,
    path: &CStr,
    call: ffi::XattrCall,
    _follow_links: bool,
) -> isize {
    // The path arrives already resolved, as it does for `tmpfs_utime`: tmpfs
    // holds no symlink this could follow a second time.
    let path = path.to_bytes();
    match mount_root(mount) {
        Some(root) => match lookup(root, path).and_then(|d| xattr_op(&d, call)) {
            Ok(n) => n,
            Err(e) => e as isize,
        },
        None => EINVAL as isize,
    }
}

pub(crate) fn tmpfs_fxattr(fd: &ffi::fd, call: ffi::XattrCall) -> isize {
    let Some(state) = fd_state(fd) else {
        return EBADF as isize;
    };
    match xattr_op(&state.dirent, call) {
        Ok(n) => n,
        Err(e) => e as isize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{Dirent, Inode};

    const S_IFREG: u32 = 0o100000;

    fn file() -> std::sync::Arc<Dirent> {
        Dirent::new_root(Inode::new(S_IFREG | 0o644, 0, 0, 0))
    }

    /// The four verbs, in one round trip.
    ///
    /// `op` was a `c_int` against four constants until 2026-09-11 and two
    /// filesystems matched it with a guard chain, so a verb that fell through
    /// reached the `_ => EINVAL` arm and looked like a caller's mistake. There
    /// is no such arm now — the enum is exhaustive — and this is what says the
    /// four still mean what they did.
    ///
    /// Each call was six arguments until 2026-09-15 — a verb, an
    /// `Option<&[u8]>` name, an output slice, a length *beside* it and an
    /// input slice — of which a `Remove` filled four with `None`, `&mut []`,
    /// `0` and `&[]`. The buffer belongs to the verb that uses it.
    #[test]
    fn the_four_verbs_each_reach_their_own_operation() {
        let d = file();
        let mut buf = [0u8; 64];

        // Set, then get it back.
        assert_eq!(
            xattr_op(
                &d,
                ffi::XattrCall::Set {
                    name: c"user.a",
                    value: b"one",
                    flags: 0
                }
            ),
            Ok(0)
        );
        assert_eq!(
            xattr_op(
                &d,
                ffi::XattrCall::Get {
                    name: c"user.a",
                    out: &mut buf
                }
            ),
            Ok(3)
        );
        assert_eq!(&buf[..3], b"one");

        // List names it; remove takes it away and a second remove is ENODATA.
        assert_eq!(xattr_op(&d, ffi::XattrCall::List { out: &mut buf }), Ok(7));
        assert_eq!(&buf[..7], b"user.a\0");
        assert_eq!(
            xattr_op(&d, ffi::XattrCall::Remove { name: c"user.a" }),
            Ok(0)
        );
        assert_eq!(
            xattr_op(&d, ffi::XattrCall::Remove { name: c"user.a" }),
            Err(xattrabi::ENODATA)
        );
    }

    /// **`flags` rides on the verb, and only one verb reads it.**
    ///
    /// It used to be a seventh parameter passed beside `op` on all four, which
    /// three of the four callers filled in with a literal zero. Folding it into
    /// [`ffi::XattrCall::Set`] is the change this test guards: if the fold
    /// dropped it — `check_exists(0, ..)` instead of the caller's word —
    /// `XATTR_CREATE` over a name that is already set would quietly succeed
    /// and overwrite, which is the one thing an exclusive create must not do.
    #[test]
    fn xattr_create_over_an_existing_name_is_still_eexist() {
        let d = file();
        let set = |flags| {
            xattr_op(
                &d,
                ffi::XattrCall::Set {
                    name: c"user.a",
                    value: b"one",
                    flags,
                },
            )
        };
        assert_eq!(set(xattrabi::XATTR_CREATE), Ok(0));
        assert_eq!(set(xattrabi::XATTR_CREATE), Err(xattrabi::EEXIST));
        // And `XATTR_REPLACE` is the mirror: it needs the name to be there.
        assert_eq!(set(xattrabi::XATTR_REPLACE), Ok(0));
        assert_eq!(
            xattr_op(&d, ffi::XattrCall::Remove { name: c"user.a" }),
            Ok(0)
        );
        assert_eq!(set(xattrabi::XATTR_REPLACE), Err(xattrabi::ENODATA));
    }
}
