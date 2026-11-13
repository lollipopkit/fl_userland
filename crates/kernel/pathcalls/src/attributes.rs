//! Path based metadata mutation syscalls.

use super::*;

// ---------------------------------------------------------------------------
// Attributes, by path
// ---------------------------------------------------------------------------

/// Reads a path and its `*at` base, for the attribute calls.
fn path_and_at(at_f: c_int, path_addr: u64) -> Result<(Path, fs_fdobj::AtRef), Errno> {
    let path = Path::read(path_addr)?;
    let at = at_of(at_f, &path)?;
    Ok((path, at))
}

pub(crate) fn follows(flags: c_int) -> bool {
    flags & ffi::AT_SYMLINK_NOFOLLOW_ as c_int == 0
}

/// `fchmodat(2)`: three arguments, and always follows.
pub fn sys_fchmodat(at_f: c_int, path_addr: u64, mode: c_uint) -> Result<(), Errno> {
    sys_fchmodat2(at_f, path_addr, mode, 0)
}

/// `fchmodat2(2)`, Linux 6.6: `fchmodat` with the flags word POSIX always
/// specified and Linux never had, so libc can stop emulating
/// `AT_SYMLINK_NOFOLLOW` through `O_PATH` and `/proc/self/fd`.
///
/// What `AT_SYMLINK_NOFOLLOW` reaches is the one case the walk does not
/// follow, and a symlink's mode is refused by `generic_setattrat` with
/// EOPNOTSUPP. glibc's `fchmodat` falls back on ENOSYS from this number, which
/// is what it answered until 2026-11-11.
pub fn sys_fchmodat2(at_f: c_int, path_addr: u64, mode: c_uint, flags: c_uint) -> Result<(), Errno> {
    if flags & !(ffi::AT_SYMLINK_NOFOLLOW_ | ffi::AT_EMPTY_PATH_) != 0 {
        return Err(Errno::EINVAL);
    }
    let path = Path::read(path_addr)?;
    strace!("fchmodat2({at_f}, {:?}, {mode:#o}, {flags:#x})", path.as_str());
    let follow = flags & ffi::AT_SYMLINK_NOFOLLOW_ == 0;
    // Truncated to the guest's `mode_t`, as the union's 16-bit arm did; the
    // file-type bits are not the caller's to set and are dropped, as
    // `chmod_common`'s `S_IALLUGO` mask drops them.
    let a = ffi::Attr::Mode((mode & !0o170000) as ffi::mode_t_);
    if flags & ffi::AT_EMPTY_PATH_ != 0 && path.0[0] == 0 {
        return match Itself::of(at_f)? {
            Itself::Named(at) => done(fs_generic::generic_setattrat(at.at(), c".", a, follow)),
            Itself::Nameless(_) => fdattr::sys_fchmod(at_f, mode),
        };
    }
    let at = at_of(at_f, &path)?;
    done(fs_generic::generic_setattrat(at.at(), path.as_cstr(), a, follow))
}

pub fn sys_fchownat(
    at_f: c_int,
    path_addr: u64,
    owner: c_uint,
    group: c_uint,
    flags: c_int,
) -> Result<(), Errno> {
    let (path, at) = path_and_at(at_f, path_addr)?;
    strace!(
        "fchownat({at_f}, {:?}, {owner}, {group}, {flags})",
        path.as_str()
    );
    // The two flags this call takes. Anything else is EINVAL on Linux, and was
    // accepted here -- so a caller that passed the wrong constant was told its
    // request had been honoured.
    if flags & !(ffi::AT_SYMLINK_NOFOLLOW_ as c_int | ffi::AT_EMPTY_PATH_ as c_int) != 0 {
        return Err(Errno::EINVAL);
    }
    let follow = follows(flags);
    // `AT_EMPTY_PATH` with an empty path is the descriptor's own file. The
    // flag was *accepted* and not honoured, so the empty path went to the
    // resolver and came back ENOENT — a caller was told the file was not
    // there while holding it open. `fstatat` had the same gap and it is what
    // stopped systemd's postinst; see the comment in `crates/fs/statcalls`.
    //
    // **By path, and `AT_FDCWD` is the working directory.** This answered
    // EBADF for `AT_FDCWD`, on the reasoning that it is not a descriptor;
    // Linux resolves the empty name with `LOOKUP_EMPTY` and changes the
    // working directory's owner. Measured by `fsat_probe`.
    if flags & ffi::AT_EMPTY_PATH_ as c_int != 0 && path.0[0] == 0 {
        let at = match Itself::of(at_f)? {
            Itself::Named(at) => at,
            Itself::Nameless(_) => return fdattr::sys_fchown32(at_f, owner, group),
        };
        for a in [(owner != u32::MAX).then_some(ffi::Attr::Uid(owner)), (group != u32::MAX).then_some(ffi::Attr::Gid(group))]
            .into_iter()
            .flatten()
        {
            done(fs_generic::generic_setattrat(at.at(), c".", a, follow))?;
        }
        return Ok(());
    }
    // -1 means "leave this one", which is why the two are separate operations
    // rather than one: there is no attribute that sets both.
    if owner != u32::MAX {
        let a = ffi::Attr::Uid(owner);
        done(fs_generic::generic_setattrat(at.at(), path.as_cstr(), a, follow))?;
    }
    if group != u32::MAX {
        let a = ffi::Attr::Gid(group);
        done(fs_generic::generic_setattrat(at.at(), path.as_cstr(), a, follow))?;
    }
    Ok(())
}

pub fn sys_truncate64(path_addr: u64, size: i64) -> Result<(), Errno> {
    let path = Path::read(path_addr)?;
    strace!("truncate({:?}, {size})", path.as_str());
    let a = ffi::Attr::Size(size);
    done(fs_generic::generic_setattrat(ffi::At::Pwd, path.as_cstr(), a, true))
}
