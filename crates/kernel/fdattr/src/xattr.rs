//! The twelve extended-attribute syscalls.
//!
//! Four verbs — get, set, list, remove — crossed with three ways of naming the
//! target: a path that follows symlinks, a path that does not, and an open
//! descriptor. They landed on a single stub answering `ENOTSUP` until
//! 2026-09-07, which was a true statement about the general case ("this kernel
//! has no extended attributes") applied to a particular one where the host
//! does: Darwin has all four, and `crates/kernel/errno` has mapped Darwin's
//! `ENOATTR` onto Linux's `ENODATA` since before anything called it.
//!
//! # The rules are here and the storage is not
//!
//! `crates/fs/xattrabi` holds the namespace, the flag and the size rules, and
//! this module applies them before any mount is asked. That is the whole point
//! of the split: the namespace *is* the access control for xattrs —
//! `security.capability` is a file capability and `user.*` is the only one an
//! unprivileged program may write — so a filesystem that implements the calls
//! and none of the rules has given a guest a way around it, and would pass
//! every "does it work" test doing so.
//!
//! Two things this cannot decide and passes down: whether the name is already
//! set, which `XATTR_CREATE` and `XATTR_REPLACE` turn on, and whether the
//! caller's buffer is big enough. Both need the stored value.
//!
//! # The order the checks run in is observable
//!
//! Measured with `tests/guest/src/bin/xattr_probe.rs` against an arm64
//! container, because it settles four things `xattr(7)` does not say — see
//! `crates/fs/xattrabi`'s module comment for the list. What is checked before
//! the path is resolved is what Linux's `import_xattr_name` and
//! `setxattr_copy` check: the flags, the name's *length*, the value's size.
//! Its *namespace* is judged after, against the file -- a name with no prefix
//! on a missing file is ENOENT, measured by `fsat_probe`.
//!
//! # Sixteen, since Linux 6.13
//!
//! `setxattrat`, `getxattrat`, `listxattrat` and `removexattrat` are the path
//! form with a `*at` descriptor, an `AT_SYMLINK_NOFOLLOW`/`AT_EMPTY_PATH` flag
//! word and, for the two that carry a value, a `struct xattr_args` passed with
//! its size. They are the twelve's bodies -- Linux implements the old path
//! calls as the new ones with `AT_FDCWD` -- and an empty path under
//! `AT_EMPTY_PATH` is the descriptor form, `O_PATH` refused as there.

use guest_errno::Errno;

use crate::{Fd, ffi};
use std::ffi::c_int;
use strace::strace;
use usercopy::GuestMem;

/// `AT_FDCWD`, as `fs/fd.h` spells it. Named here rather than pulled through
/// bindgen because it is one number and this crate reads no other `AT_*`.
const AT_FDCWD: c_int = -100;
/// The `l*` calls' "do not follow", as the `*at` flag word spells it.
const NOFOLLOW: c_int = ffi::AT_SYMLINK_NOFOLLOW_ as c_int;

/// The four verbs. `crates/kernel/abi`'s enum, not a second copy of four
/// numbers: this file had `const XATTR_OP_GET: c_int = 0` and its three
/// neighbours, `constants.rs` had the same four as `u32`, and two filesystems
/// compared against the second set with a guard chain.
use ffi::{XattrCall, XattrOp};

/// A name from guest memory, as bytes without the terminator.
///
/// `XATTR_NAME_MAX + 1` is the whole buffer a name can need; a longer one is
/// `ERANGE` from [`xattrabi::namespace`] and never reaches a filesystem.
fn read_name(addr: u64) -> Result<Vec<u8>, Errno> {
    if addr == 0 {
        return Err(Errno::EFAULT);
    }
    // One past the longest legal name, so a name that fills the buffer is one
    // that was too long -- `read_string` answers the length up to the
    // terminator and reports the whole buffer when there is none.
    let mut buf = vec![0u8; xattrabi::NAME_MAX + 2];
    let n = GuestMem
        .read_string(addr, &mut buf)
        .map_err(Errno::from_negative_or_eio)?;
    buf.truncate(n);
    Ok(buf)
}

/// A guest path, the way every path syscall reads one.
pub(crate) fn read_path(addr: u64) -> Result<std::ffi::CString, Errno> {
    // `MAX_PATH` is 4096 in `kernel/fs.h`; a longer path is what
    // `path_normalize` refuses, so the buffer only has to be able to hold one.
    let mut buf = vec![0u8; 4096];
    let n = GuestMem
        .read_string(addr, &mut buf)
        .map_err(Errno::from_negative_or_eio)?;
    // `read_string` stops at the terminator, so there is no interior NUL.
    buf.truncate(n);
    std::ffi::CString::new(buf).map_err(|_| Errno::EINVAL)
}

/// The target's mode, for the `user.*` rule — which is about what kind of file
/// it is, so it has to be looked at before the namespace can be judged.
fn mode_of_path(at: c_int, path: &std::ffi::CStr, follow: bool) -> Result<u32, Errno> {
    let mut st = ffi::statbuf::default();
    let Some(base) = fs_fdobj::at_fd(at, path) else {
        return Err(Errno::EBADF);
    };
    crate::done(fs_generic::generic_statat(base.at(), path, &mut st, follow))?;
    Ok(st.mode)
}

fn mode_of_fd(fd: &Fd) -> Result<u32, Errno> {
    let st = fs_fdobj::fd_fstat(fd)
        .map_err(Errno::from_negative_or_eio)?;
    Ok(st.mode)
}

/// Everything the rules can decide without the stored value.
///
/// `writing` separates set and remove from get and list. A `name` of `None` is
/// a list, which has no name to judge — the namespace rules are per attribute
/// and a listing names none of them.
fn judge(name: Option<&[u8]>, mode: u32, op: XattrOp) -> Result<(), Errno> {
    use taskview::caps::{CAP_SETFCAP, CAP_SYS_ADMIN};
    let writing = matches!(op, XattrOp::Set { .. } | XattrOp::Remove);
    if let Some(name) = name {
        let privilege = xattrabi::Privilege {
            sys_admin: taskview::capable(CAP_SYS_ADMIN),
            setfcap: taskview::capable(CAP_SETFCAP),
        };
        xattrabi::check(name, mode, privilege, writing).map_err(Errno::from_negative_or_eio)?;
        // `cap_inode_removexattr`. A set is judged in `run`, once its value
        // has been read.
        if op == XattrOp::Remove && name == xattrabi::SECURITY_CAPABILITY && !privilege.setfcap {
            return Err(Errno::EPERM);
        }
    }
    Ok(())
}

/// What Linux refuses before it looks at the target: a set's flags, the
/// name's length -- `import_xattr_name` copies at most `XATTR_NAME_MAX + 1`
/// bytes and answers ERANGE for an empty or a full buffer -- and a set's
/// value size. The name is read here, so a NULL one is EFAULT in this order
/// too.
fn arguments(op: XattrOp, name_addr: u64, size: u64) -> Result<Option<Vec<u8>>, Errno> {
    xattrabi::check_flags(flags_of(op)).map_err(Errno::from_negative_or_eio)?;
    let name = if op == XattrOp::List {
        None
    } else {
        let name = read_name(name_addr)?;
        if name.is_empty() || name.len() > xattrabi::NAME_MAX {
            return Err(Errno::ERANGE);
        }
        Some(name)
    };
    if matches!(op, XattrOp::Set { .. }) {
        xattrabi::check_value(size as usize).map_err(Errno::from_negative_or_eio)?;
    }
    Ok(name)
}

/// The body of every path-named call: the six old ones, with `AT_FDCWD` and
/// a flag word of their own, and the four `*at` ones.
///
/// `path_addr` 0 is a path only under `AT_EMPTY_PATH`, which makes it the
/// empty one, as Linux's `getname_maybe_null` does; otherwise it is EFAULT
/// when it is read.
fn by_at(
    op: XattrOp,
    at: c_int,
    path_addr: u64,
    at_flags: c_int,
    name_addr: u64,
    value_addr: u64,
    size: u64,
) -> Result<i64, Errno> {
    if at_flags & !(ffi::AT_SYMLINK_NOFOLLOW_ | ffi::AT_EMPTY_PATH_) as c_int != 0 {
        return Err(Errno::EINVAL);
    }
    let follow = at_flags & ffi::AT_SYMLINK_NOFOLLOW_ as c_int == 0;
    let name = arguments(op, name_addr, size)?;
    let empty_allowed = at_flags & ffi::AT_EMPTY_PATH_ as c_int != 0;
    let path = if empty_allowed && path_addr == 0 {
        std::ffi::CString::default()
    } else {
        read_path(path_addr)?
    };
    // An empty path under `AT_EMPTY_PATH` with a descriptor is the descriptor
    // form, `O_PATH` refused as it is there. With `AT_FDCWD` it is the
    // working directory, by path.
    let path = if empty_allowed && path.is_empty() {
        if at >= 0 {
            return on_fd(op, Fd::get(at)?, name, value_addr, size);
        }
        std::ffi::CString::from(c".")
    } else {
        path
    };
    // The mode first, because the `user.*` rule is about what the target is --
    // and a path that is not there is `ENOENT` whatever the name was, which is
    // what the probe measured.
    let mode = mode_of_path(at, &path, follow)?;
    judge(name.as_deref(), mode, op)?;
    // After the judgement: a set above the cap is `E2BIG` rather than a
    // truncated value, which is what `buffer_len` leaving a set alone depends
    // on.
    let size = buffer_len(op, size);
    run(
        |call| {
            let Some(base) = fs_fdobj::at_fd(at, &path) else {
                return Err(Errno::EBADF);
            };
            Ok(fs_generic::generic_xattr(base.at(), &path, call, follow))
        },
        op,
        name.as_deref(),
        value_addr,
        size,
    )
}

/// The body of all four descriptor-named calls.
fn by_fd(op: XattrOp, num: c_int, name_addr: u64, value_addr: u64, size: u64) -> Result<i64, Errno> {
    // The descriptor before anything else, as Linux's `fsetxattr` looks it up
    // first.
    let fd = Fd::get(num)?;
    let name = arguments(op, name_addr, size)?;
    on_fd(op, fd, name, value_addr, size)
}

fn on_fd(op: XattrOp, fd: Fd, name: Option<Vec<u8>>, value_addr: u64, size: u64) -> Result<i64, Errno> {
    // A reference opens nothing to ask. EBADF, which is `fdget`'s answer for
    // an `O_PATH` descriptor; it was asked through here.
    if fd.is_path_only() {
        return Err(Errno::EBADF);
    }
    let mode = mode_of_fd(&fd)?;
    judge(name.as_deref(), mode, op)?;
    // As above: judged on the caller's number, run on the clamped one.
    let size = buffer_len(op, size);
    run(
        |call| Ok(fs_generic::generic_fxattr(&fd, call)),
        op,
        name.as_deref(),
        value_addr,
        size,
    )
}

/// The `XATTR_CREATE`/`XATTR_REPLACE` word a set carries. Zero for the other
/// three, which is what all six of their callers used to pass by hand.
fn flags_of(op: XattrOp) -> c_int {
    match op {
        XattrOp::Set { flags } => flags,
        _ => 0,
    }
}

/// The kernel buffer this call needs, from the `size` the guest passed.
///
/// **The guest's number is not a length until this has been applied.** A get
/// and a list are answered *into* a buffer this kernel allocates, and the
/// number naming it comes straight from a register — so it is
/// [`xattrabi::buffer_len`] that stands between `getxattr(.., 1 << 48)` and an
/// allocation the process aborts on. See that function for why a clamp is also
/// what Linux answers.
///
/// A set is the caller's number unchanged, because [`judge`] has already run
/// `check_value` over it and refused anything above the cap; a remove names no
/// buffer at all and its callers pass zero.
///
/// The result is used **twice** — the `Vec` here and `XattrCall.size` handed to
/// the filesystem — and the two have to be the same number: `call.value` is
/// documented to the mounts as `call.size` writable bytes, so a filesystem
/// given the unclamped size and the clamped buffer would write past it. That
/// is why this is one function called once per body rather than a `min` at each
/// use.
fn buffer_len(op: XattrOp, size: u64) -> usize {
    match op {
        XattrOp::Get => xattrabi::buffer_len(size, xattrabi::SIZE_MAX),
        XattrOp::List => xattrabi::buffer_len(size, xattrabi::LIST_MAX),
        XattrOp::Set { .. } | XattrOp::Remove => size as usize,
    }
}

/// Move the value across the guest boundary and call the filesystem.
///
/// A set copies **in** before the call and the other three copy **out** after
/// it, so the buffer here is the kernel's either way and no filesystem is given
/// a guest address. That is the rule `kernel/calls.h` states for every syscall
/// and it matters more than usual here: a filesystem writing a guest address
/// directly would be writing it without the page table's checks.
///
/// `size` is a length, not the guest's argument: [`buffer_len`] has been
/// applied. It is a `usize` for that reason — the `u64` this took until
/// 2026-09-14 is what a register holds, and taking one here is what let an
/// unclamped number reach the allocation below.
fn run(
    to_mount: impl FnOnce(XattrCall<'_>) -> Result<isize, Errno>,
    op: XattrOp,
    name: Option<&[u8]>,
    value_addr: u64,
    size: usize,
) -> Result<i64, Errno> {
    // The name as a `CStr`, which every verb but a list has by construction.
    let cname = name
        .map(|n| std::ffi::CString::new(n).map_err(|_| Errno::EINVAL))
        .transpose()?;

    let writes_in = matches!(op, XattrOp::Set { .. });
    let file_caps = name == Some(xattrabi::SECURITY_CAPABILITY);
    if file_caps && op == XattrOp::Get {
        return get_file_caps(to_mount, value_addr, size);
    }
    let mut buf = vec![0u8; size];
    if writes_in && size > 0 && GuestMem.read(value_addr, &mut buf) != 0 {
        return Err(Errno::EFAULT);
    }
    // `cap_convert_nscap`: the header before the capability, measured -- a
    // malformed value is EINVAL with or without CAP_SETFCAP. A v3 is stored
    // as written: in the one user namespace here its rootid needs no
    // translating. An empty value is not converted and so not judged at all,
    // measured: it is set without CAP_SETFCAP, and reads back as EINVAL.
    if writes_in && file_caps && size > 0 {
        if !kernel_creds::caps::xattr_caps_valid(&buf) {
            return Err(Errno::EINVAL);
        }
        if !taskview::capable(taskview::caps::CAP_SETFCAP) {
            return Err(Errno::EPERM);
        }
    }
    // Each arm carries the buffer the way it uses it: a set reads, the other
    // three write, and a remove has none. The `if size == 0 { null }` this
    // replaces is an empty slice, which is the same thing said by the type.
    let n = {
        // `unwrap_or` rather than `?`: the name is `None` only for a list,
        // which is the one arm that does not take one.
        let named = cname.as_deref().unwrap_or(c"");
        to_mount(match op {
            XattrOp::Get => XattrCall::Get {
                name: named,
                out: &mut buf,
            },
            XattrOp::Set { flags } => XattrCall::Set {
                name: named,
                value: &buf,
                flags,
            },
            XattrOp::List => XattrCall::List { out: &mut buf },
            XattrOp::Remove => XattrCall::Remove { name: named },
        })?
    };
    // `isize`: an xattr call answers a length, so `split` is what reads the
    // errno range out of it.
    let n = Errno::split(n as i64)?;
    // A `size` of 0 asked for the length and nothing was written, so there is
    // nothing to copy back -- and `value_addr` may legitimately be null.
    if !writes_in && size > 0 && n > 0 && GuestMem.write(value_addr, &buf[..n as usize]) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(n)
}

/// `getxattr("security.capability")`, which Linux answers through
/// `cap_inode_getsecurity` rather than as stored: a v3 whose rootid is 0 is
/// this namespace's own and reads back as the 20-byte v2, the size query
/// included (measured), and a value that is neither is `EINVAL`.
fn get_file_caps(
    to_mount: impl FnOnce(XattrCall<'_>) -> Result<isize, Errno>,
    value_addr: u64,
    size: usize,
) -> Result<i64, Errno> {
    let mut stored = [0u8; 64];
    let n = to_mount(XattrCall::Get { name: c"security.capability", out: &mut stored })?;
    let n = match Errno::split(n as i64) {
        Err(Errno::ERANGE) => return Err(Errno::EINVAL),
        other => other?,
    } as usize;
    let stored = &stored[..n];
    if !kernel_creds::caps::xattr_caps_valid(stored) {
        return Err(Errno::EINVAL);
    }
    let v2 = kernel_creds::caps::xattr_caps_for_reader(stored);
    let value = v2.as_ref().map_or(stored, |v| &v[..]);
    if size == 0 {
        return Ok(value.len() as i64);
    }
    if size < value.len() {
        return Err(Errno::ERANGE);
    }
    if GuestMem.write(value_addr, value) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(value.len() as i64)
}

// ---------------------------------------------------------------------------
// The twelve
// ---------------------------------------------------------------------------

pub fn sys_setxattr(path: u64, name: u64, value: u64, size: u64, flags: c_int) -> Result<i64, Errno> {
    strace!("setxattr({path:#x}, {name:#x}, {value:#x}, {size}, {flags})");
    by_at(XattrOp::Set { flags }, AT_FDCWD, path, 0, name, value, size)
}

pub fn sys_lsetxattr(path: u64, name: u64, value: u64, size: u64, flags: c_int) -> Result<i64, Errno> {
    strace!("lsetxattr({path:#x}, {name:#x}, {value:#x}, {size}, {flags})");
    by_at(XattrOp::Set { flags }, AT_FDCWD, path, NOFOLLOW, name, value, size)
}

pub fn sys_fsetxattr(num: c_int, name: u64, value: u64, size: u64, flags: c_int) -> Result<i64, Errno> {
    strace!("fsetxattr({num}, {name:#x}, {value:#x}, {size}, {flags})");
    by_fd(XattrOp::Set { flags }, num, name, value, size)
}

pub fn sys_getxattr(path: u64, name: u64, value: u64, size: u64) -> Result<i64, Errno> {
    strace!("getxattr({path:#x}, {name:#x}, {value:#x}, {size})");
    by_at(XattrOp::Get, AT_FDCWD, path, 0, name, value, size)
}

pub fn sys_lgetxattr(path: u64, name: u64, value: u64, size: u64) -> Result<i64, Errno> {
    strace!("lgetxattr({path:#x}, {name:#x}, {value:#x}, {size})");
    by_at(XattrOp::Get, AT_FDCWD, path, NOFOLLOW, name, value, size)
}

pub fn sys_fgetxattr(num: c_int, name: u64, value: u64, size: u64) -> Result<i64, Errno> {
    strace!("fgetxattr({num}, {name:#x}, {value:#x}, {size})");
    by_fd(XattrOp::Get, num, name, value, size)
}

pub fn sys_listxattr(path: u64, list: u64, size: u64) -> Result<i64, Errno> {
    strace!("listxattr({path:#x}, {list:#x}, {size})");
    by_at(XattrOp::List, AT_FDCWD, path, 0, 0, list, size)
}

pub fn sys_llistxattr(path: u64, list: u64, size: u64) -> Result<i64, Errno> {
    strace!("llistxattr({path:#x}, {list:#x}, {size})");
    by_at(XattrOp::List, AT_FDCWD, path, NOFOLLOW, 0, list, size)
}

pub fn sys_flistxattr(num: c_int, list: u64, size: u64) -> Result<i64, Errno> {
    strace!("flistxattr({num}, {list:#x}, {size})");
    by_fd(XattrOp::List, num, 0, list, size)
}

pub fn sys_removexattr(path: u64, name: u64) -> Result<i64, Errno> {
    strace!("removexattr({path:#x}, {name:#x})");
    by_at(XattrOp::Remove, AT_FDCWD, path, 0, name, 0, 0)
}

pub fn sys_lremovexattr(path: u64, name: u64) -> Result<i64, Errno> {
    strace!("lremovexattr({path:#x}, {name:#x})");
    by_at(XattrOp::Remove, AT_FDCWD, path, NOFOLLOW, name, 0, 0)
}

pub fn sys_fremovexattr(num: c_int, name: u64) -> Result<i64, Errno> {
    strace!("fremovexattr({num}, {name:#x})");
    by_fd(XattrOp::Remove, num, name, 0, 0)
}

// ---------------------------------------------------------------------------
// The four *at forms, Linux 6.13
// ---------------------------------------------------------------------------

/// `struct xattr_args`: `{ __aligned_u64 value; __u32 size; __u32 flags; }`.
const XATTR_ARGS_SIZE_VER0: usize = 16;

/// The value pointer, its size and the flags, from a struct passed with its
/// own size: `EINVAL` below the first published size, `E2BIG` above a page or
/// for a nonzero byte this kernel has no field for.
fn xattr_args(addr: u64, usize: u64) -> Result<(u64, u64, c_int), Errno> {
    if (usize as usize) < XATTR_ARGS_SIZE_VER0 {
        return Err(Errno::EINVAL);
    }
    if usize > ffi::PAGE_SIZE as u64 {
        return Err(Errno::E2BIG);
    }
    let mut raw = [0u8; XATTR_ARGS_SIZE_VER0];
    usercopy::read_extensible(&GuestMem, addr, usize as usize, &mut raw)?;
    let value = u64::from_le_bytes(raw[0..8].try_into().expect("eight bytes"));
    let size = u32::from_le_bytes(raw[8..12].try_into().expect("four bytes"));
    let flags = u32::from_le_bytes(raw[12..16].try_into().expect("four bytes"));
    Ok((value, u64::from(size), flags as c_int))
}

pub fn sys_setxattrat(
    at: c_int,
    path: u64,
    at_flags: c_int,
    name: u64,
    args: u64,
    usize: u64,
) -> Result<i64, Errno> {
    strace!("setxattrat({at}, {path:#x}, {at_flags:#x}, {name:#x}, {args:#x}, {usize})");
    let (value, size, flags) = xattr_args(args, usize)?;
    by_at(XattrOp::Set { flags }, at, path, at_flags, name, value, size)
}

pub fn sys_getxattrat(
    at: c_int,
    path: u64,
    at_flags: c_int,
    name: u64,
    args: u64,
    usize: u64,
) -> Result<i64, Errno> {
    strace!("getxattrat({at}, {path:#x}, {at_flags:#x}, {name:#x}, {args:#x}, {usize})");
    let (value, size, flags) = xattr_args(args, usize)?;
    // A get has no flags, and the field is reserved rather than ignored.
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    by_at(XattrOp::Get, at, path, at_flags, name, value, size)
}

pub fn sys_listxattrat(at: c_int, path: u64, at_flags: c_int, list: u64, size: u64) -> Result<i64, Errno> {
    strace!("listxattrat({at}, {path:#x}, {at_flags:#x}, {list:#x}, {size})");
    by_at(XattrOp::List, at, path, at_flags, 0, list, size)
}

pub fn sys_removexattrat(at: c_int, path: u64, at_flags: c_int, name: u64) -> Result<i64, Errno> {
    strace!("removexattrat({at}, {path:#x}, {at_flags:#x}, {name:#x})");
    by_at(XattrOp::Remove, at, path, at_flags, name, 0, 0)
}
