//! Path based creation, lookup, and name mutation syscalls.

use super::*;

// ---------------------------------------------------------------------------
// Opening, and asking whether you could
// ---------------------------------------------------------------------------

pub fn sys_openat(
    at_f: c_int,
    path_addr: u64,
    flags: c_uint,
    mode: c_uint,
) -> Result<i64, Errno> {
    let path = Path::read(path_addr)?;
    strace!("openat({at_f}, {:?}, {flags:#x}, {mode:#o})", path.as_str());

    // An empty name is ENOENT before the descriptor is looked at -- Linux's
    // `getname` refuses it first, so `openat(999, "")` is ENOENT and was
    // EBADF here -- unless `O_EMPTYPATH` says it names the descriptor.
    if path.0[0] == 0 && flags & fs_generic::O_EMPTYPATH as c_uint == 0 {
        return Err(Errno::ENOENT);
    }
    // `O_TMPFILE` creates as `O_CREAT` does, and the umask applies to it --
    // as `openat2` already said, and this did not.
    let mode = if flags & ffi::O_CREAT_ != 0 || flags & ffi::O_TMPFILE_ == ffi::O_TMPFILE_ {
        apply_umask(mode)
    } else {
        mode
    };
    let at = at_of(at_f, &path)?;
    let fd = fs_generic::generic_openat(at.at(), path.as_cstr(), flags as c_int, mode as c_int)?;
    Errno::split(fs_fdobj::f_install(fd, flags as c_int) as i64)
}

/// The three bits `access(2)` may ask about; `F_OK` is none of them.
const AC_R: c_uint = 4;
const AC_W: c_uint = 2;
const AC_X: c_uint = 1;
const AT_EACCESS: c_uint = 0x200;

/// `faccessat(2)`, which takes **three** arguments where `faccessat2(2)` takes
/// four.
///
/// Syscall 48 pointed straight at [`sys_faccessat`] until 2026-09-03, and the
/// dispatcher hands every implementation six registers whatever the syscall's
/// arity is — so `flags` was whatever the guest had left in `x3`. A bit outside
/// `AT_EACCESS|AT_SYMLINK_NOFOLLOW` is `EINVAL`, so a plain `access()` could
/// fail for no reason a caller could see. A real kernel ignores the register.
pub fn sys_faccessat3(at_f: c_int, path_addr: u64, mode: c_uint) -> Result<(), Errno> {
    sys_faccessat(at_f, path_addr, mode, 0)
}

/// `faccessat(2)` is three arguments; `faccessat2(2)` is the same with a
/// fourth. The three-argument number pointed at the four-argument
/// implementation until 2026-09-03, so `flags` was whatever the guest happened
/// to leave in x3 -- and a bit outside `AT_EACCESS|AT_SYMLINK_NOFOLLOW` is
/// `EINVAL`, so `access()` could fail for no reason at all.
pub fn sys_faccessat(
    at_f: c_int,
    path_addr: u64,
    mode: c_uint,
    flags: c_uint,
) -> Result<(), Errno> {
    // Linux's order: the flags and the mode, then the path, then the
    // descriptor. `faccessat2` with a bad flag is EINVAL whatever the path.
    //
    // A mode bit outside R_OK|W_OK|X_OK is EINVAL. It used to be ignored, so a
    // caller asking about a permission this does not implement was told the
    // file had it.
    if mode & !(AC_R | AC_W | AC_X) != 0 {
        return Err(Errno::EINVAL);
    }
    // `AT_EMPTY_PATH` is `faccessat2`'s third flag. It was EINVAL here, so a
    // caller asking about a descriptor -- `access` on an `O_PATH` one is how
    // a sandbox asks without reopening -- was told its arguments were wrong.
    if flags & !(AT_EACCESS | ffi::AT_SYMLINK_NOFOLLOW_ | ffi::AT_EMPTY_PATH_) != 0 {
        return Err(Errno::EINVAL);
    }
    let path = Path::read(path_addr)?;
    strace!("faccessat({at_f}, {:?}, {mode:#x}, {flags})", path.as_str());
    let follow = flags & ffi::AT_SYMLINK_NOFOLLOW_ == 0;
    let empty = flags & ffi::AT_EMPTY_PATH_ != 0 && path.0[0] == 0;
    let target = if empty {
        Itself::of(at_f)?
    } else {
        Itself::Named(at_of(at_f, &path)?)
    };
    let check = || match &target {
        Itself::Named(at) if empty => fs_generic::generic_accessat(at.at(), c".", mode as c_int, follow),
        Itself::Named(at) => fs_generic::generic_accessat(at.at(), path.as_cstr(), mode as c_int, follow),
        Itself::Nameless(fd) => match fs_fdobj::fd_fstat(fd) {
            Ok(st) => fs_perm::access_check(&st, mode as c_int).err().unwrap_or(0),
            Err(e) => e,
        },
    };

    // AT_EACCESS asks for the ids a real access would use, which is the fs
    // pair -- so this needs no swap at all.
    if flags & AT_EACCESS != 0 {
        return done(check());
    }

    // access(2) without AT_EACCESS answers for the *real* ids, and that has to
    // hold for the whole path resolution -- the search permission on every
    // directory along the way, not only the final check. Threading a second
    // pair of ids through the walk would mean every mount's lookup carrying
    // them, so the ids are swapped for the duration instead. Linux did the same
    // with override_creds() until faccessat2 gave it a better way.
    //
    // The window is safe here for a reason worth stating, since it would not be
    // in a real kernel: `current` is this thread's own, so no other thread can
    // see the swap, and signals are delivered at syscall boundaries rather than
    // mid-call, so no handler can run inside it and observe a lowered euid.
    //
    // The **fs** ids, which is what the check reads. This swapped euid/egid
    // until setfsuid existed, and swapping those now would do nothing at all --
    // a silent way to lose the rule this whole comment is about.
    //
    // A returned pair, where this passed `&mut uid, &mut gid` to a wrapper
    // that wrote through them. The out-parameters were there because "a struct
    // small enough to come back in registers leaves its upper half in x0",
    // which is about a *syscall* return crossing the guest ABI and says
    // nothing about a Rust call; the method has always answered a `(u32, u32)`.
    //
    // **Two borrows, one per change, and neither across the walk.** This held
    // one `&mut Creds` from the swap to the restore, and the walk between them
    // reads these same ids through its own pointer -- `fs_generic`'s `fsuid()`
    // is `(*current_creds()).fsuid()` -- so a unique borrow was alive across
    // reads that did not come through it.
    //
    // And each **under `pids_lock`**, which is the field's lock: another
    // thread checking whether this process may be signalled or have its
    // limits read holds a `&Creds` of this task under that lock, and a shared
    // reference asserts that no byte of the struct changes while it lives --
    // the fs ids included, though that reader never looks at them. The
    // `set*id` calls have taken it since 2026-09-15; this swap did not.
    //
    // Each `&mut` lives for one method call with the field's lock held.
    let in_task = "a syscall runs in a task";
    let old = kernel_pids::PidsGuard::take()
        .override_current_creds(|c| c.override_fsids_with_real())
        .expect(in_task);
    let err = check();
    kernel_pids::PidsGuard::take().override_current_creds(|c| c.restore_fsids(old)).expect(in_task);
    done(err)
}

pub fn sys_readlinkat(
    at_f: c_int,
    path_addr: u64,
    buf_addr: u64,
    bufsize: c_uint,
) -> Result<i64, Errno> {
    // Linux declares bufsiz as `int` and answers EINVAL for anything that is
    // not positive -- which includes every size above INT_MAX, because the
    // guest's 32 bits are read as signed. `readlinkat(fd, path, buf,
    // 3000000000)` is therefore EINVAL there and was a 3 GB request here.
    //
    // That request used to be a stack array of exactly that size and took the
    // emulator down; then it was clamped to MAX_PATH and answered, on the
    // reasoning that Linux answers a large request with the length it has.
    // Linux does, up to INT_MAX. Above it there is no request, only a negative
    // number. Measured against a real kernel, not read off the man page.
    //
    // It is judged **before** the path is read, which is also Linux's order:
    // `readlinkat(fd, NULL, buf, 0)` is `EINVAL` there and was `EFAULT` here.
    if (bufsize as i32) <= 0 {
        return Err(Errno::EINVAL);
    }
    let path = Path::read(path_addr)?;
    strace!(
        "readlinkat({at_f}, {:?}, {buf_addr:#x}, {bufsize:#x})",
        path.as_str()
    );
    let at = at_of(at_f, &path)?;
    // A link's target is a path, so nothing longer than MAX_PATH can ever be
    // produced: asking for more is asking for room that cannot be filled.
    let room = (bufsize as usize).min(MAX_PATH);
    let mut buf = [0u8; MAX_PATH];
    let size = fs_generic::generic_readlinkat(at.at(), path.as_cstr(), &mut buf[..room]);
    // `isize`, not a `c_int` like the rest of the VFS: this one answers a
    // length. `split` reads the errno range and passes a length through.
    let size = Errno::split(size as i64)? as usize;
    strace!(" {:?}", String::from_utf8_lossy(&buf[..size]));
    if GuestMem.write(buf_addr, &buf[..size]) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(size as i64)
}

// ---------------------------------------------------------------------------
// Making and unmaking names
// ---------------------------------------------------------------------------

/// Two paths and their `*at` bases, which is what `link` and `rename` take.
fn two_paths(
    src_at_f: c_int,
    src_addr: u64,
    dst_at_f: c_int,
    dst_addr: u64,
) -> Result<(Path, fs_fdobj::AtRef, Path, fs_fdobj::AtRef), Errno> {
    let src = Path::read(src_addr)?;
    let dst = Path::read(dst_addr)?;
    let src_at = at_of(src_at_f, &src)?;
    let dst_at = at_of(dst_at_f, &dst)?;
    Ok((src, src_at, dst, dst_at))
}

pub fn sys_linkat(
    src_at_f: c_int,
    src_addr: u64,
    dst_at_f: c_int,
    dst_addr: u64,
    flags: c_int,
) -> Result<(), Errno> {
    // `linkat` takes five arguments and this took four until 2026-09-03, so
    // `AT_SYMLINK_FOLLOW` was dropped: a hard link to a symlink was always made
    // to the *link* where the caller had asked for the target. A flag outside
    // the two was accepted as well, so a wrong constant read as success.
    if flags & !(AT_SYMLINK_FOLLOW | ffi::AT_EMPTY_PATH_ as c_int) != 0 {
        return Err(Errno::EINVAL);
    }
    // `AT_EMPTY_PATH` names the *descriptor* rather than a path, and this
    // answers `ENOENT` for it — the resolver's answer for the empty path.
    //
    // **Deliberately, and it is the errno that matters.** Linking a
    // description means linking the inode it holds, which is not the same
    // thing as linking the path it was opened by: a rename in between would
    // give the caller a link to the wrong file, and answering "ok" for that is
    // worse than refusing. Every caller has the same fallback — systemd's
    // `link_fd` retries with `/proc/self/fd/<n>` as the source and
    // `AT_SYMLINK_FOLLOW` — and it triggers on exactly this errno, which is
    // why this is not `EPERM`. That fallback works here, because
    // `/proc/<pid>/fd/<n>` is a symlink to the path.
    //
    // What it is really for is naming an `O_TMPFILE` file, which has no path
    // to be wrong about, and that it does: Linux's `flink` rule since 6.10,
    // `CAP_DAC_READ_SEARCH` or the file's own opener -- here, its owner.
    if flags & ffi::AT_EMPTY_PATH_ as c_int != 0 {
        let src = Path::read(src_addr)?;
        if src.0[0] == 0 {
            let fd = fs_fdobj::f_get(src_at_f).ok_or(Errno::EBADF)?;
            if fd.unnamed.is_none() {
                return Err(Errno::ENOENT);
            }
            let owner = fs_fdobj::fd_fstat(&fd).map_or(u32::MAX, |st| st.uid);
            let may = taskview::with_current_creds(|c| c.capable(kernel_creds::caps::CAP_DAC_READ_SEARCH) || c.fsuid() == owner);
            if may != Some(true) {
                return Err(Errno::ENOENT);
            }
            let dst = Path::read(dst_addr)?;
            let dst_at = at_of(dst_at_f, &dst)?;
            return done(fs_generic::generic_link_unnamed(&fd, dst_at.at(), dst.as_cstr()));
        }
    }
    let (src, src_at, dst, dst_at) = two_paths(src_at_f, src_addr, dst_at_f, dst_addr)?;
    strace!(
        "linkat({src_at_f}, {:?}, {dst_at_f}, {:?}, {flags})",
        src.as_str(),
        dst.as_str()
    );
    let follow = flags & AT_SYMLINK_FOLLOW != 0;
    done(fs_generic::generic_linkat(src_at.at(), src.as_cstr(), dst_at.at(), dst.as_cstr(), follow))
}

/// `linkat`'s own flag: resolve a symlink source rather than linking it.
///
/// The opposite default from every other `*at` call, which is why it has its
/// own constant rather than reusing `AT_SYMLINK_NOFOLLOW`.
const AT_SYMLINK_FOLLOW: c_int = 0x400;

/// `unlinkat`'s only flag, from `fcntl.h`.
const AT_REMOVEDIR: c_int = 0x200;

pub fn sys_unlinkat(at_f: c_int, path_addr: u64, flags: c_int) -> Result<(), Errno> {
    let path = Path::read(path_addr)?;
    strace!("unlinkat({at_f}, {:?}, {flags})", path.as_str());
    // AT_REMOVEDIR is the only flag this call has, and Linux refuses the rest:
    //
    //     if ((flag & ~AT_REMOVEDIR) != 0)
    //             return -EINVAL;
    //
    // Nothing checked, so `unlinkat(fd, path, 0x1000)` -- a caller that meant
    // AT_REMOVEDIR and got the constant wrong, or one built against a newer
    // header -- **deleted the file** and reported success. Measured against a
    // real arm64 kernel, which leaves it alone and says EINVAL.
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Errno::EINVAL);
    }
    let at = at_of(at_f, &path)?;
    done(if flags & AT_REMOVEDIR != 0 {
        fs_generic::generic_rmdirat(at.at(), path.as_cstr())
    } else {
        fs_generic::generic_unlinkat(at.at(), path.as_cstr())
    })
}

pub fn sys_renameat2(
    src_at_f: c_int,
    src_addr: u64,
    dst_at_f: c_int,
    dst_addr: u64,
    flags: c_int,
) -> Result<(), Errno> {
    // do_renameat2's two rules, in its order. RENAME_NOREPLACE is the atomic
    // create-if-absent a lock file needs and RENAME_EXCHANGE the atomic swap a
    // config rewrite needs; every flag used to be EINVAL, so neither existed
    // and a caller that checked for that fell back to a racy sequence.
    let known = (ffi::RENAME_NOREPLACE_ | ffi::RENAME_EXCHANGE_ | ffi::RENAME_WHITEOUT_) as c_int;
    if flags & !known != 0 {
        return Err(Errno::EINVAL);
    }
    let exchange = flags & ffi::RENAME_EXCHANGE_ as c_int != 0;
    let no_replace_or_whiteout =
        flags & (ffi::RENAME_NOREPLACE_ | ffi::RENAME_WHITEOUT_) as c_int != 0;
    if no_replace_or_whiteout && exchange {
        return Err(Errno::EINVAL);
    }
    // RENAME_WHITEOUT leaves a whiteout inode behind and exists for overlayfs.
    // Nothing here is a union mount, and Linux answers EINVAL from a filesystem
    // that does not implement it.
    if flags & ffi::RENAME_WHITEOUT_ as c_int != 0 {
        return Err(Errno::EINVAL);
    }

    let (src, src_at, dst, dst_at) = two_paths(src_at_f, src_addr, dst_at_f, dst_addr)?;
    strace!(
        "renameat({src_at_f}, {:?}, {dst_at_f}, {:?})",
        src.as_str(),
        dst.as_str()
    );
    done(fs_generic::generic_renameat(
        src_at.at(),
        src.as_cstr(),
        dst_at.at(),
        dst.as_cstr(),
        flags as c_uint,
    ))
}

pub fn sys_renameat(
    src_at_f: c_int,
    src_addr: u64,
    dst_at_f: c_int,
    dst_addr: u64,
) -> Result<(), Errno> {
    sys_renameat2(src_at_f, src_addr, dst_at_f, dst_addr, 0)
}

pub fn sys_symlinkat(target_addr: u64, at_f: c_int, link_addr: u64) -> Result<(), Errno> {
    let target = Path::read(target_addr)?;
    let link = Path::read(link_addr)?;
    strace!(
        "symlinkat({:?}, {at_f}, {:?})",
        target.as_str(),
        link.as_str()
    );
    // An empty target is ENOENT, which is Linux's `if (!*oldname) return
    // -ENOENT;` in do_symlinkat. A symlink to "" resolves to nothing and can
    // never be followed, so creating one leaves a name that every open of it
    // answers ENOENT for -- the error belongs at the creation, where the caller
    // can still do something about it. Measured.
    if target.0[0] == 0 {
        return Err(Errno::ENOENT);
    }
    let at = at_of(at_f, &link)?;
    done(fs_generic::symlink_at(target.as_cstr(), at.at(), link.as_cstr()))
}

pub fn sys_mknodat(
    at_f: c_int,
    path_addr: u64,
    mode: c_uint,
    dev: c_uint,
) -> Result<(), Errno> {
    let path = Path::read(path_addr)?;
    strace!("mknodat({at_f}, {:?}, {mode:#x}, {dev:#x})", path.as_str());
    let mode = apply_umask(mode);
    let at = at_of(at_f, &path)?;
    done(fs_generic::mknod_at(at.at(), path.as_cstr(), mode as u16, dev))
}

pub fn sys_mkdirat(at_f: c_int, path_addr: u64, mode: c_uint) -> Result<(), Errno> {
    let path = Path::read(path_addr)?;
    strace!("mkdirat({at_f}, {:?}, {mode:#o})", path.as_str());
    let mode = apply_umask(mode);
    let at = at_of(at_f, &path)?;
    done(fs_generic::mkdir_at(at.at(), path.as_cstr(), mode as u16))
}
