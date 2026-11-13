//! The three permission questions a path operation asks about the *caller*.
//!
//! Every rule is `crates/kernel/creds`, which owns who may do what and knows
//! nothing about `current`. What is here is the one thing it cannot do for
//! itself: reach the calling task's credential set. That was three functions in
//! `kernel/fs.c` whose whole content was `&current->creds` followed by a call
//! into the crate — the accessor shape that made a field at a time cost more
//! than it saved. `crates/kernel/taskview` is what makes them expressible here.
//!
//! They keep their C symbol names, so the four call sites in three other crates
//! did not change: a Rust caller of an `extern "C"` function pays nothing for
//! the `extern`, and this file being Rust removes a boundary crossing rather
//! than adding one.
//!
//! # Its own crate, and not `crates/fs/generic`'s
//!
//! It was a module there until 2026-09-05. `crates/fs/path`'s walk asks
//! `access_check` for execute permission on every directory it enters, so
//! making that a Rust call put `fs-path` -> `fs-generic` in the graph while
//! `fs-generic` -> `fs-path` was already there for the walk itself: a cycle,
//! and a cycle because a permission rule is below both of them. It needs
//! nothing either one has -- a `struct statbuf`, the caller's credentials, and
//! `crates/kernel/creds`.
//!
//! # The fs ids, not the effective ones
//!
//! Every check below runs against `fsuid`/`fsgid`, and privilege comes from the
//! fsuid rather than from "is this root": setting the fsuid away from root drops
//! `CAP_DAC_OVERRIDE` and the rest of the filesystem capability set, so a root
//! process whose fsuid is someone else's cannot read that someone's private
//! file. Measured against a real kernel — `tests/guest/src/bin/fsuid_abi.rs`.

use std::ffi::c_int;

use kernel_creds::Creds;
use taskview::with_current_creds;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

/// The three checks below refuse when there is no task, which is what the
/// `kernel_creds` wrappers they used to call did with their null arm --
/// `EACCES` for access, `EPERM` for the other two. Saying it at each means
/// each caller states its own refusal rather than inheriting a default from a
/// wrapper three crates away.
///
/// The credentials come from `taskview::with_current_creds`, whose closure
/// bounds the borrow. This crate had its own `unsafe fn creds<'a>() ->
/// Option<&'a Creds>` until 2026-09-30, whose lifetime nothing bounded.
fn with_creds(no_task: c_int, f: impl FnOnce(&Creds) -> Result<(), c_int>) -> Result<(), c_int> {
    with_current_creds(f).unwrap_or(Err(no_task))
}

/// Discretionary access. 0, or `-EACCES`.
///
/// Two defects came out of the four lines this replaced in C. The requested bits
/// were tested with `!(mode & check)` — "none of them" — where POSIX requires
/// all, so `open(O_RDWR)` on a mode 0400 file returned a writable descriptor.
/// And only the effective gid was compared against the node's group, so a file
/// group-owned by one of the caller's supplementary groups was refused.
///
/// `Ok(())` to allow. A `&statbuf` and a `Result` since 2026-09-16: this took
/// a `*const ffi::statbuf` and answered `0`-or-a-negative-errno, and **every
/// caller already had a reference** — each one wrote `access_check(&st, …)`,
/// which the compiler coerced. So the null arm was unreachable, the `unsafe`
/// bought nothing, and each caller spelled the sentinel test out as
/// `if err < 0`.
pub fn access_check(stat: &ffi::statbuf, check: c_int) -> Result<(), c_int> {
    // EACCES: no task is no access.
    with_creds(-13, |c| c.access(stat.uid, stat.gid, stat.mode, check as u32))
}

/// `protected_hardlinks`.
///
/// A hard link pins an inode: once made, the owner of the original cannot get
/// rid of it by unlinking their copy, and the permissions it is checked against
/// are the inode's. So linking to something you cannot already read and write
/// keeps a reference to a file you were never allowed to have. Linux has had
/// this on by default since 3.6 and every distribution ships it enabled; there
/// was no check here at all.
///
/// As [`access_check`].
pub fn link_check(stat: &ffi::statbuf) -> Result<(), c_int> {
    with_creds(-1, |c| c.may_link(stat.uid, stat.gid, stat.mode)) // EPERM
}

/// The mode a write or a truncation by this caller leaves `stat` with, or
/// `None` if it keeps its set-id bits: `kernel_creds::mode_after_write`. A
/// thread with no task is the embedder, which holds every capability.
pub fn mode_after_write(stat: &ffi::statbuf) -> Option<u32> {
    with_current_creds(|c| c.mode_after_write(stat.gid, stat.mode)).flatten()
}

/// May this caller make this change to this node?
///
/// There was no check of any kind, which with set-id exec working was a local
/// root.
///
/// `attr_size` carries a value this does not look at: whether a file may be
/// truncated is a write permission on the file, which the caller has already
/// asked about, not a property of the length.
///
/// As [`access_check`], answering the change to make: a mode loses
/// `S_ISGID` when the caller is neither in the file's group nor holds
/// `CAP_FSETID`, which `setattr_prepare` does silently.
pub fn setattr_check(stat: &ffi::statbuf, attr: ffi::Attr) -> Result<ffi::Attr, c_int> {
    use kernel_creds::Change;
    let change = match attr {
        ffi::Attr::Uid(uid) => Change::Uid(uid),
        ffi::Attr::Gid(gid) => Change::Gid(gid),
        ffi::Attr::Mode(_) => Change::Mode,
        ffi::Attr::Size(_) => Change::Size,
    };
    // EPERM with no task.
    with_current_creds(|c| {
        c.setattr(stat.uid, stat.gid, stat.mode, change)?;
        Ok(match attr {
            ffi::Attr::Mode(m) => ffi::Attr::Mode(c.chmod_mode(stat.gid, m as u32) as ffi::mode_t_),
            other => other,
        })
    })
    .unwrap_or(Err(-1))
}
