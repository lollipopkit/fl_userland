//! Generic mutation, attribute, directory, and seek operations.

use super::*;

pub fn generic_renameat(
    src_at: ffi::At<'_>,
    src_name: &CStr,
    dst_at: ffi::At<'_>,
    dst_name: &CStr,
    flags: c_uint,
) -> c_int {
    // Rename removes the source from its parent directory and puts a name in
    // the destination's, so **both** parents need write permission -- the
    // destination either way, because replacing an existing name changes that
    // directory too.
    let mut src = match normalize(
        src_at,
        src_name,
        (ffi::N_SYMLINK_NOFOLLOW | ffi::N_PARENT_DIR_WRITE_DELETE) as c_int,
    ) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut dst = match normalize(
        dst_at,
        dst_name,
        (ffi::N_SYMLINK_NOFOLLOW | ffi::N_PARENT_DIR_WRITE) as c_int,
    ) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if fs_mounttable::contains_mount_point(src.as_cstr()) {
        return errno::EBUSY;
    }
    // A trailing slash on either name is a claim that it is a directory, and
    // the walk enforces that only where the name *exists* -- so a destination
    // that is not there yet arrives here having said "directory" and being
    // about to become whatever the source is. Linux's `do_renameat2`:
    //
    //     if (flags & RENAME_NOREPLACE) ...
    //     if (old_last.name[old_last.len] || new_last.name[new_last.len])
    //             if (!d_is_dir(old_dentry)) -> ENOTDIR
    //
    // `rename("file", "other/")` used to move the file to `other`.
    // Answered from the callers' strings, because a normalised path has had
    // the slash taken off it.
    let wrote_slash = |name: &CStr| name.to_bytes().last() == Some(&b'/');
    if wrote_slash(src_name) || wrote_slash(dst_name) {
        // The mount's own stat of the already-normalised source, the way
        // `sticky_check` asks: going back through `generic_statat` would
        // normalise a second time and it wants a directory descriptor this
        // does not have.
        let mut probe = PathBuf::new();
        if probe.set(src.bytes()).is_ok() {
            let mount = Mount::of(&mut probe);
            let answer = mount.stat(&probe);
            drop(mount);
            if let Ok(st) = answer
                && st.mode & S_IFMT != S_IFDIR
            {
                return errno::ENOTDIR;
            }
        }
    }
    let (src_full, dst_full) = (src.clone_buf(), dst.clone_buf());
    // Both ends: the source leaves its directory, and an existing destination is
    // removed from its own. sticky_check answers Ok for a destination that does
    // not exist yet, which is the common case.
    if let Err(e) = sticky_check(&src_full) {
        return e;
    }
    if let Err(e) = sticky_check(&dst_full) {
        return e;
    }

    let mount = Mount::of(&mut src);
    let dst_mount = Mount::of(&mut dst);
    if mount.as_ptr() != dst_mount.as_ptr() {
        return errno::EXDEV;
    }
    let err = mount
            .fs()
            .rename(
mount.get(), src.as_cstr(), dst.as_cstr(), flags);
    if err >= 0 {
        // One cookie for both halves, so a watcher can pair them.
        let cookie = inotify::next_cookie();
        notify(&src_full, inotify::IN_MOVED_FROM, cookie);
        notify(&dst_full, inotify::IN_MOVED_TO, cookie);
        notify(&src_full, inotify::IN_MOVE_SELF, 0);
        // An exchange moves *both* names, so vfs_rename calls fsnotify_move
        // twice, the second in the opposite direction and with its own cookie.
        // A watcher pairing by cookie sees two complete moves rather than one
        // move and two unpaired halves.
        if flags & ffi::RENAME_EXCHANGE_ != 0 {
            let back = inotify::next_cookie();
            notify(&dst_full, inotify::IN_MOVED_FROM, back);
            notify(&src_full, inotify::IN_MOVED_TO, back);
            notify(&dst_full, inotify::IN_MOVE_SELF, 0);
        }
    }
    err
}

pub fn symlink_at(
    target: &CStr,
    at: ffi::At<'_>,
    link_name: &CStr,
) -> c_int {
    let mut link = match normalize(
        at,
        link_name,
        (ffi::N_SYMLINK_NOFOLLOW | ffi::N_PARENT_DIR_WRITE_CREATE) as c_int,
    ) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let full = link.clone_buf();
    let mount = Mount::of(&mut link);
    // Stored verbatim rather than walked: it means whatever it means when
    // the guest follows it.
    let err = mount.fs().symlink(
mount.get(), target, link.as_cstr());
    if err >= 0 {
        notify(&full, inotify::IN_CREATE, 0);
    }
    err
}

/// `iul.h`'s `generic_symlinkat`, which is [`symlink_at`] with the base converted.
///
/// **The conversion belongs here and at the other two declarations in that
/// header, and nowhere else.** `iul.h` says
/// `#define AT_PWD (struct fd *) -2` and declares this parameter as
/// `struct fd *at`, so an [`ffi::At`] in *this* signature would be an ABI
/// break: the enum's niche is null, so an embedder's `-2` would read as a
/// descriptor at address -2. No gate would catch that —
/// `tools/extern-signatures.py` compares arity and deliberately not types.
///
/// # Safety
/// As [`generic_openat`], and `at` is `AT_PWD`, a live description or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn generic_symlinkat(
    target: *const c_char,
    at: *mut ffi::fd,
    link: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract.
    let Some(at) = (unsafe { ffi::At::from_raw(at) }) else {
        return errno::EBADF;
    };
    // SAFETY: the caller's contract, as declared in `iul.h`.
    let (target, link) = unsafe { (CStr::from_ptr(target), CStr::from_ptr(link)) };
    symlink_at(target, at, link)
}


pub fn mknod_at(
    at: ffi::At<'_>,
    name: &CStr,
    mode: u16,
    dev: u32,
) -> c_int {
    let m = mode as u32;
    if is(m, S_IFDIR) || is(m, S_IFLNK) {
        return errno::EINVAL;
    }
    // CAP_MKNOD, which is in the set setfsuid drops.
    if !capable(taskview::caps::CAP_MKNOD) && (is(m, S_IFBLK) || is(m, S_IFCHR)) {
        return errno::EPERM;
    }
    let mut path = match normalize(
        at,
        name,
        (ffi::N_SYMLINK_NOFOLLOW | ffi::N_PARENT_DIR_WRITE_CREATE) as c_int,
    ) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mount = Mount::of(&mut path);
    mount.fs().mknod(
mount.get(), path.as_cstr(), mode, dev)
}

/// `iul.h`'s `generic_mknodat`, which is [`mknod_at`] with the base converted.
///
/// **The conversion belongs here and at the other two declarations in that
/// header, and nowhere else.** `iul.h` says
/// `#define AT_PWD (struct fd *) -2` and declares this parameter as
/// `struct fd *at`, so an [`ffi::At`] in *this* signature would be an ABI
/// break: the enum's niche is null, so an embedder's `-2` would read as a
/// descriptor at address -2. No gate would catch that —
/// `tools/extern-signatures.py` compares arity and deliberately not types.
///
/// # Safety
/// As [`generic_openat`], and `at` is `AT_PWD`, a live description or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn generic_mknodat(
    at: *mut ffi::fd,
    path: *const c_char,
    mode: u16,
    dev: u32,
) -> c_int {
    // SAFETY: the caller's contract.
    let Some(at) = (unsafe { ffi::At::from_raw(at) }) else {
        return errno::EBADF;
    };
    // SAFETY: the caller's contract, as declared in `iul.h`.
    mknod_at(at, unsafe { CStr::from_ptr(path) }, mode, dev)
}


pub fn generic_setattrat(
    at: ffi::At<'_>,
    name: &CStr,
    attr: ffi::Attr,
    follow_links: bool,
) -> c_int {
    let mut path = match normalize(at, name, symlink_flag(follow_links)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mount = Mount::of(&mut path);
    let stat = match mount.stat(&path) {
        Ok(st) => st,
        Err(e) => return e,
    };
    // A symlink's mode is not changed, by anyone: Linux's `notify_change`
    // answers EOPNOTSUPP before it asks who the caller is, since 6.6. Only a
    // walk that did not follow reaches one -- `fchmodat2(AT_SYMLINK_NOFOLLOW)`
    // -- and realfs would otherwise `lchmod` the host's link.
    if matches!(attr, ffi::Attr::Mode(_)) && is(stat.mode & S_IFMT, S_IFLNK) {
        return guest_errno::c_int_::EOPNOTSUPP;
    }
    let attr = match fs_perm::setattr_check(&stat, attr) {
        Ok(attr) => attr,
        Err(e) => return e,
    };
    // `truncate(2)` of a running program is ETXTBSY: Linux's
    // `do_sys_truncate` takes write access on the inode after the permission
    // check and before the truncation, the same as an `open(O_WRONLY)` would.
    // There is no descriptor here to take it through, so the count is asked
    // by number and nothing is held -- a program that starts between the
    // question and the truncation is the race Linux's window has too.
    if matches!(attr, ffi::Attr::Size(_))
        && is(stat.mode & S_IFMT, S_IFREG)
        && fs_inode::inode_writers_of(mount.get(), stat.inode) < 0
    {
        return errno::ETXTBSY;
    }
    // A truncation to the size the file already has changes nothing, and that
    // includes the timestamps: `ext4_setattr` does its work under
    // `if (attr->ia_size != inode->i_size)`, so `truncate(f, its own size)`
    // leaves `mtime` alone. It moved both `mtime` and `ctime` here, because the
    // host's `truncate` was called regardless -- which makes a build system
    // rebuild for a file nobody changed. Measured by `filetime_probe`.
    //
    // The checks above still run: whether the caller may truncate at all, and
    // whether the file is being executed, are questions with the same answer
    // either way, and Linux asks them before it compares the sizes.
    if let ffi::Attr::Size(size) = attr
        && is(stat.mode & S_IFMT, S_IFREG)
        && u64::try_from(size) == Ok(stat.size)
    {
        return 0;
    }
    let err = mount.fs().setattr(
mount.get(), path.as_cstr(), attr);
    if err >= 0 && matches!(attr, ffi::Attr::Uid(_) | ffi::Attr::Gid(_)) {
        // A change of ownership takes the set-id bits with it, and the file's
        // capabilities (`ATTR_KILL_PRIV`, measured). Best effort: the
        // ownership change is done, and failing here would report the wrong
        // operation.
        if !is(stat.mode & S_IFMT, S_IFDIR) {
            let remove = ffi::XattrCall::Remove { name: c"security.capability" };
            mount.fs().xattr(mount.get(), path.as_cstr(), remove, follow_links);
        }
        if let Some(reduced) = kernel_creds::mode_after_chown(stat.mode) {
            // A mode, where it was written through the union's `size` arm --
            // right only because both start at offset 0 on a little-endian
            // machine. The mode bits fit: `mode_after_chown` only clears.
            let mode_attr = ffi::Attr::Mode(reduced as ffi::mode_t_);
            mount.fs().setattr(mount.get(), path.as_cstr(), mode_attr);
        }
    }
    err
}

pub(crate) fn symlink_flag(follow: bool) -> c_int {
    (if follow {
        ffi::N_SYMLINK_FOLLOW
    } else {
        ffi::N_SYMLINK_NOFOLLOW
    }) as c_int
}

pub fn generic_utime(
    at: ffi::At<'_>,
    name: &CStr,
    atime: ffi::timespec,
    mtime: ffi::timespec,
    follow_links: bool,
) -> c_int {
    let mut path = match normalize(at, name, symlink_flag(follow_links)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mount = Mount::of(&mut path);
    mount
            .fs()
            .utime(
mount.get(), path.as_cstr(), atime, mtime, follow_links)
}

pub fn generic_readlinkat(
    at: ffi::At<'_>,
    name: &CStr,
    buf: &mut [u8],
) -> isize {
    let mut path = match normalize(at, name, ffi::N_SYMLINK_NOFOLLOW as c_int) {
        Ok(p) => p,
        Err(e) => return e as isize,
    };
    let mount = Mount::of(&mut path);
    mount.fs().readlink(
mount.get(), path.as_cstr(), buf)
}

pub fn mkdir_at(
    at: ffi::At<'_>,
    name: &CStr,
    mode: u16,
) -> c_int {
    let mut path = match normalize(
        at,
        name,
        (ffi::N_SYMLINK_FOLLOW | ffi::N_PARENT_DIR_WRITE_CREATE) as c_int,
    ) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let full = path.clone_buf();
    let mount = Mount::of(&mut path);
    let err = mount.fs().mkdir(
mount.get(), path.as_cstr(), mode);
    if err >= 0 {
        notify(&full, inotify::IN_CREATE | inotify::IN_ISDIR, 0);
    }
    err
}

/// `iul.h`'s `generic_mkdirat`, which is [`mkdir_at`] with the base converted.
///
/// **The conversion belongs here and at the other two declarations in that
/// header, and nowhere else.** `iul.h` says
/// `#define AT_PWD (struct fd *) -2` and declares this parameter as
/// `struct fd *at`, so an [`ffi::At`] in *this* signature would be an ABI
/// break: the enum's niche is null, so an embedder's `-2` would read as a
/// descriptor at address -2. No gate would catch that —
/// `tools/extern-signatures.py` compares arity and deliberately not types.
///
/// # Safety
/// As [`generic_openat`], and `at` is `AT_PWD`, a live description or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn generic_mkdirat(
    at: *mut ffi::fd,
    path: *const c_char,
    mode: u16,
) -> c_int {
    // SAFETY: the caller's contract.
    let Some(at) = (unsafe { ffi::At::from_raw(at) }) else {
        return errno::EBADF;
    };
    // SAFETY: the caller's contract, as declared in `iul.h`.
    mkdir_at(at, unsafe { CStr::from_ptr(path) }, mode)
}


pub fn generic_rmdirat(at: ffi::At<'_>, name: &CStr) -> c_int {
    // Before the path is normalised, because normalising is what hides it:
    // `dir/.` becomes `dir`, and this removed `dir`. Measured -- a real arm64
    // kernel answers EINVAL for a last component of `.`, ENOTEMPTY for `..` and
    // EBUSY for the root, and Linux's do_rmdir checks the *parsed* last
    // component for exactly that reason.
    let last = path::rmdir_last_component_bytes(name.to_bytes());
    if last < 0 {
        return last;
    }
    let mut path = match normalize(
        at,
        name,
        (ffi::N_SYMLINK_FOLLOW | ffi::N_PARENT_DIR_WRITE_DELETE) as c_int,
    ) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if fs_mounttable::contains_mount_point(path.as_cstr()) {
        return errno::EBUSY;
    }
    let full = path.clone_buf();
    if let Err(e) = sticky_check(&full) {
        return e;
    }
    let mount = Mount::of(&mut path);
    let err = mount.fs().rmdir(
mount.get(), path.as_cstr());
    if err >= 0 {
        notify(&full, inotify::IN_DELETE | inotify::IN_ISDIR, 0);
        notify(&full, inotify::IN_DELETE_SELF, 0);
    }
    err
}

/// The file position arithmetic every mount that has a position shares.
///
/// The caller holds `fd`'s lock.
pub fn generic_seek(fd: &ffi::fd, off: i64, whence: c_int, size: usize) -> c_int {
    let current = fd.offset();
    let new = match whence as u32 {
        ffi::LSEEK_SET => {
            // The check the other two whences already made. Without it a
            // negative offset was stored, and because `offset` was unsigned it
            // became a very large one: lseek(fd, -4096, SEEK_SET) on tmpfs
            // *succeeded*, returned -4096, and left every later read and write
            // addressing 0xfffffffffffff000. Only offsets in [-4095, -1] looked
            // like failures, and only because libc reads that range as an errno.
            off
        }
        ffi::LSEEK_CUR => match current.checked_add(off) {
            Some(n) => n,
            None => return errno::EINVAL,
        },
        ffi::LSEEK_END => match (size as i64).checked_add(off) {
            Some(n) => n,
            None => return errno::EINVAL,
        },
        _ => return errno::EINVAL,
    };
    if new < 0 {
        return errno::EINVAL;
    }
    fd.set_offset(new);
    0
}
