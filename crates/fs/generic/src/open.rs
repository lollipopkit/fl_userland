//! Generic open policy and mount handoff for `open(2)` and `openat(2)`.

use super::*;
use guest_errno::Errno;

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

/// `open`, `openat` and everything they decide before and after the mount's own
/// `open`.
///
/// Safe since 2026-09-29: `at` is a borrow and `name` a `&CStr`, where they
/// were a raw pointer each and a sentence saying what they had to be.
pub fn generic_openat(
    at: ffi::At<'_>,
    name: &CStr,
    flags: c_int,
    mode: c_int,
) -> Result<fs_fdobj::Owned, Errno> {
    generic_openat2(at, name, flags, mode, OpenHow::default())
}

/// What `openat2` asks of an open beyond `openat`'s flags: the walk's
/// refusals, and the one flag that lives above the 32 bits `open(2)` can
/// express. The default is `openat`.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenHow {
    pub scope: path::Scope,
    /// `OPENAT2_REGULAR`: anything but a regular file is `EFTYPE`.
    pub regular_only: bool,
    /// `open_exec`: the file is opened to be run, so what the caller needs
    /// is execute permission and not read. `execve` of a `0711` file by
    /// someone other than its owner was `EACCES` here, where Linux runs it
    /// (and leaves it undumpable, which is the only thing unreadable means
    /// to an exec). Not reachable from the guest's flags.
    pub exec: bool,
}

/// `O_EMPTYPATH`: with an empty name, open what `at` is open on. Linux 7.x,
/// for `openat` and `openat2` both -- it is bit 26 of the 32 `open(2)` has.
pub const O_EMPTYPATH: c_int = 1 << 26;

/// What an `O_PATH` open keeps: Linux's `O_PATH_FLAGS`.
pub const O_PATH_FLAGS: c_int =
    (ffi::O_DIRECTORY_ | ffi::O_NOFOLLOW_ | ffi::O_PATH_ | ffi::O_CLOEXEC_) as c_int | O_EMPTYPATH;

/// `generic_openat`, with `openat2`'s additions.
pub fn generic_openat2(
    at: ffi::At<'_>,
    name: &CStr,
    flags: c_int,
    mode: c_int,
    how: OpenHow,
) -> Result<fs_fdobj::Owned, Errno> {
    open_inner(at, name, flags, mode, how, false)
}

/// `own_link` is `O_EMPTYPATH`'s reopen: the name is the descriptor's own
/// path and its last component is the file itself, so the mount must not
/// follow it -- a descriptor onto a symlink reopens the link, which is ELOOP
/// unless `O_PATH` -- and must not record an `O_NOFOLLOW` nobody asked for.
fn open_inner(
    at: ffi::At<'_>,
    name: &CStr,
    mut flags: c_int,
    mode: c_int,
    how: OpenHow,
    own_link: bool,
) -> Result<fs_fdobj::Owned, Errno> {
    // `O_PATH` beats everything else: Linux's `build_open_how` masks the
    // flags down to the four that mean something for a reference before
    // anything looks at them. This kept `O_CREAT`, so `openat(dir, "new",
    // O_PATH|O_CREAT)` made a file where Linux answers ENOENT. `openat2`
    // refuses the extra bits instead, before it gets here.
    if flags & ffi::O_PATH_ as c_int != 0 {
        flags &= O_PATH_FLAGS;
    }
    if flags & ffi::O_RDWR_ as c_int != 0 && flags & ffi::O_WRONLY_ as c_int != 0 {
        return Err(Errno::EINVAL);
    }
    // `O_DIRECTORY|O_CREAT` asks for a directory and for a regular file at
    // once. Linux refuses it in `build_open_flags` since 6.4, for `openat` as
    // well as `openat2`: before that the combination made a regular file and
    // then answered ENOTDIR about it. It answered ENOTDIR here, which is the
    // old kernel's errno for a request the new one never starts. Measured by
    // `openat2_probe`. `O_TMPFILE` contains `O_DIRECTORY`, so it is refused
    // with `O_CREAT` too, as there.
    let dir_and_create = (ffi::O_DIRECTORY_ | ffi::O_CREAT_) as c_int;
    if flags & dir_and_create == dir_and_create {
        return Err(Errno::EINVAL);
    }
    // `O_EMPTYPATH` and an empty name: the file `at` is open on, opened
    // again with this call's flags. By *path*, the way this kernel follows
    // `/proc/self/fd/<n>` for a file with a name -- "." against the
    // descriptor, which the walk answers with the descriptor's own path and
    // does not follow -- and by `reopen` for one with none.
    if name.is_empty() && flags & O_EMPTYPATH != 0 {
        if let ffi::At::Fd(fd) = at {
            let mut buf = [0u8; MAX_PATH + 1];
            let err = crate::generic_getpath(fd, &mut buf);
            if err < 0 {
                return Err(Errno::from_negative_or_eio(err));
            }
            if buf[0] != b'/' {
                return reopen(fd, flags);
            }
        }
        return open_inner(at, c".", flags, mode, how, true);
    }

    // O_NOFOLLOW has to be honoured here rather than by handing the flag to the
    // host open(): the walk resolves the final component itself, so by the time
    // the mount's open runs the symlink is already gone. Leaving it unresolved
    // makes the S_ISLNK check below return ELOOP, as Linux does.
    //
    // `last_existed` is whether O_CREAT is about to make this. The walk already
    // looks -- that is how it decides whether the parent-directory write check
    // applies to a create -- so this reuses its answer instead of asking again.
    let walk_flags = (if flags & ffi::O_NOFOLLOW_ as c_int != 0 {
        ffi::N_SYMLINK_NOFOLLOW
    } else {
        ffi::N_SYMLINK_FOLLOW
    }) as c_int
        | if flags & ffi::O_CREAT_ as c_int != 0 {
            ffi::N_PARENT_DIR_WRITE_CREATE as c_int
        } else {
            0
        };
    let resolved = crate::normalize::resolve_scoped(at, name.to_bytes(), walk_flags, how.scope)
        .map_err(Errno::from_negative_or_eio)?;
    if let Some(file) = &resolved.magic {
        return reopen(file, flags);
    }
    let mut path = PathBuf::new();
    path.set(&resolved.path).map_err(Errno::from_negative_or_eio)?;

    // Two things need this. The IN_CREATE below reports a creation rather than
    // merely an open, and the access check further down is *skipped* for a file
    // this call has just made: Linux's do_last goes to finish_open_created and
    // never calls may_open for one. Without that,
    // `open("new", O_CREAT|O_RDWR, 0400)` answered EACCES *and left the file
    // behind* -- an error and a file, where Linux hands back a writable
    // descriptor.
    let creating = flags & ffi::O_CREAT_ as c_int != 0 && resolved.last_existed == Some(false);

    // A create through a trailing slash. The walk refuses one whose last
    // component *exists* and is not a directory; this is the other half, where
    // nothing is there and the caller has asked for a regular file at a name it
    // spelled as a directory. Linux's `do_last`:
    //
    //     if (nd->last.name[nd->last.len])   /* the byte after the name */
    //             return -EISDIR;
    //
    // `open("new/", O_CREAT)` used to make a regular file called `new`.
    // Answered from the *caller's* string, because the normalised path has had
    // the slash taken off it and this is the only thing that still knows.
    if creating && name.to_bytes().last() == Some(&b'/') {
        return Err(Errno::EISDIR);
    }

    // `OPENAT2_REGULAR`, asked of what is there before the mount opens it, so
    // that a FIFO is refused rather than waited on and a device's driver
    // never hears of it. A symlink left by `O_NOFOLLOW` goes on to be ELOOP
    // below, which is Linux's order: the walk refuses it before `do_open`
    // looks at the type. Measured: a directory and `/dev/null` are `EFTYPE`.
    if how.regular_only && !creating {
        let mut probe = path.clone_buf();
        let mount = Mount::of(&mut probe);
        if let Ok(st) = mount.stat(&probe)
            && !is(st.mode, S_IFREG)
            && !is(st.mode, S_IFLNK)
        {
            return Err(Errno::EFTYPE);
        }
    }

    // O_TMPFILE, which this kernel does not implement.
    //
    // Its encoding is O_DIRECTORY plus a bit, so an implementation that does not
    // know it opens the *directory* -- which is what happened, and a caller that
    // asked for an unnamed temporary file got a descriptor onto the directory it
    // named. Linux's rules are checked first so the answers are the ones a
    // caller distinguishes: an access mode that is not write or read-write is
    // EINVAL, and a filesystem that cannot make one is EOPNOTSUPP -- which is
    // what sends a caller to mkstemp.
    if flags & ffi::O_TMPFILE_ as c_int == ffi::O_TMPFILE_ as c_int {
        if flags & (ffi::O_WRONLY_ | ffi::O_RDWR_) as c_int == 0 {
            return Err(Errno::EINVAL);
        }
        return Err(Errno::EOPNOTSUPP);
    }

    // O_PATH asks for a *reference* to the object and not for access to it. So
    // there is no permission to check, nothing is opened behind a device node,
    // and the access mode is ignored -- an O_PATH descriptor for a directory is
    // the usual way to hold one open as a `*at` base.
    //
    // The flag was defined and never looked at, so `open(x, O_PATH)` behaved
    // like an ordinary open: it answered EACCES for a file the caller could not
    // read, where Linux hands back a descriptor that simply cannot be read
    // through. That is the wrong way round for a caller that only wants to name
    // the file -- systemd, container runtimes and Go's `os.Root` all do.
    // The access mode and everything else went at the top of this function.
    let path_only = flags & ffi::O_PATH_ as c_int != 0;

    let full = path.clone_buf();
    let mount = Mount::of(&mut path);
    // O_TRUNC is done *after* every check below has passed, as Linux's
    // handle_truncate is, and so is kept from the mount's open: a truncation
    // the mount performed first was not undone by a refusal, and an
    // `open(O_WRONLY|O_TRUNC)` of a running program emptied the program and
    // then answered ETXTBSY.
    let truncating = flags & ffi::O_TRUNC_ as c_int != 0 && !path_only;
    // The mount's failure is its reference's to release, which `?` does by
    // dropping `mount` here; on the success path it is handed to the fd below.
    let nofollow = if own_link { ffi::O_NOFOLLOW_ as c_int } else { 0 };
    let fd = mount.fs().open(
        mount.get(),
        path.as_cstr(),
        (flags | nofollow) & !(ffi::O_TRUNC_ as c_int),
        mode,
    )?;
    // Unpublished until every refusal below has been asked, so a refusal drops
    // it -- the host descriptor with it -- and nothing outside this function
    // ever saw it. It was published first and filled in through `unsafe {
    // (*fd).x }` until 2026-10-01, and before 2026-09-29 closed by a
    // `fail(fd, e)` closure called from nine places.
    let mut fd = fs_fdobj::NewFd::from(fd);
    if creating {
        notify(&full, inotify::IN_CREATE, 0);
    }
    // Remembered so close can report IN_CLOSE_WRITE, and so a write can report
    // IN_MODIFY without asking the filesystem for the path again.
    if flags & (ffi::O_WRONLY_ | ffi::O_RDWR_) as c_int != 0 {
        fd.inotify_path = Some(full.as_cstr().to_owned());
        if flags & ffi::O_TRUNC_ as c_int != 0 {
            notify(&full, inotify::IN_MODIFY, 0);
        }
    }

    // The mount's reference moves to the descriptor, which releases it on
    // close -- and before the inode, because a filesystem's `fstat` reads the
    // descriptor's mount.
    fd.set_mount(mount.into_ref());
    let mut stat = ffi::statbuf::default();
    let err = fs_inode::generic_attach_inode(&mut fd, &mut stat);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    let ty = stat.mode & S_IFMT;
    fd.type_ = ty as u16;
    // What the description reports from now on: not the flags as asked, which
    // is what F_GETFL used to answer -- O_CREAT and all, and never
    // O_LARGEFILE. The rule is `crates/fs/fdobj`'s.
    //
    // O_NOCTTY is put back until the driver has seen it. Linux clears the four
    // consumed flags in `do_dentry_open` *after* `f_op->open`, and the tty
    // driver's open is what reads O_NOCTTY to decide whether this opener
    // claims the terminal -- so clearing it here made every
    // `open("/dev/ptmx", O_NOCTTY)` by a session leader claim one, and the
    // leader then took `SIGHUP` when the terminal went away. It is taken off
    // again below, after `dev_open`.
    fd.set_flags(fs_fdobj::status::at_open(flags as u32) | (flags as u32 & ffi::O_NOCTTY_));
    fd.created = creating;

    // Not for a file this call created. Linux does not permission-check one it
    // has just made -- you named the mode, you get the descriptor -- and
    // checking it means `open(path, O_CREAT|O_WRONLY, 0400)` fails after the
    // file is already there.
    if !creating && !path_only {
        const AC_R: c_int = 4;
        const AC_W: c_int = 2;
        const AC_X: c_int = 1;
        let accmode = if how.exec {
            AC_X
        } else if flags & ffi::O_RDWR_ as c_int != 0 {
            AC_R | AC_W
        } else if flags & ffi::O_WRONLY_ as c_int != 0 {
            AC_W
        } else {
            AC_R
        };
        if let Err(e) = path::access(full.as_cstr().to_bytes(), &stat, accmode) {
            return Err(Errno::from_negative_or_eio(e));
        }
    }

    if is(ty, S_IFLNK) && !path_only {
        // The walk should have resolved symlinks; if it did not, answer rather
        // than crash.
        //
        // `O_PATH|O_NOFOLLOW` is the one case where a symlink here is what the
        // caller asked for: it names the link itself, which is how Go's
        // `os.Root` and every container runtime walk a tree without following
        // a link out of it. This used to be `ELOOP` for that too, on the
        // grounds that the mount's open would have to open a symlink and
        // realfs had no portable way to ask a host for one -- Darwin has
        // `O_SYMLINK`, which is what `crates/fs/realfs` uses now. See
        // `tests/guest/src/bin/o_path.rs`.
        return Err(Errno::from_negative_or_eio(errno::ELOOP));
    }
    // The type refusals, **before** a device's open rather than after it, as
    // Linux's are: `O_DIRECTORY` is the path walk's question and `EISDIR` and
    // `ENXIO` are `may_open`'s, so a device opened with `O_DIRECTORY` is
    // refused without its driver hearing of it. They followed `dev_open` until
    // 2026-10-01, which ran a terminal's open -- and its controlling-tty claim
    // -- for a descriptor about to be refused.
    if is(ty, S_IFSOCK) && !path_only {
        return Err(Errno::from_negative_or_eio(errno::ENXIO));
    }
    // `O_CREAT` of a name that is a directory is EISDIR whatever the access
    // mode, as Linux's `do_open` answers before `may_open`; a read-only one
    // opened the directory here.
    let wants_file = (ffi::O_RDWR_ | ffi::O_WRONLY_ | ffi::O_CREAT_) as c_int;
    if is(ty, S_IFDIR) && flags & wants_file != 0 && !path_only {
        return Err(Errno::from_negative_or_eio(errno::EISDIR));
    }
    if !is(ty, S_IFDIR) && flags & ffi::O_DIRECTORY_ as c_int != 0 {
        return Err(Errno::from_negative_or_eio(errno::ENOTDIR));
    }

    // A write-capable open of a file some process is *running* is ETXTBSY:
    // Linux's `get_write_access` on the inode's `i_writecount`, which an exec
    // holds negative. Last of the refusals, as it is in Linux's `do_open`,
    // where `may_open`'s permission check comes first. Not for O_PATH, which
    // opens nothing, and only for a regular file, which is the only kind an
    // exec can hold -- so it cannot meet the device branch below. The
    // descriptor remembers that it took one so that close gives it back.
    let writing = flags & (ffi::O_WRONLY_ | ffi::O_RDWR_) as c_int != 0 && !path_only;
    if writing && is(ty, S_IFREG) {
        let err = fd.inode().map_or(0, fs_inode::inode_get_write_access);
        if err < 0 {
            return Err(Errno::from_negative_or_eio(err));
        }
        fd.holds_write_access = true;
    }

    if (is(ty, S_IFBLK) || is(ty, S_IFCHR)) && !path_only {
        const DEV_BLOCK: c_int = 0;
        const DEV_CHAR: c_int = 1;
        let kind = if is(ty, S_IFBLK) { DEV_BLOCK } else { DEV_CHAR };
        // The owner's decoders, `crates/fs/devices`'. A guest `dev_t_` is 32
        // bits and `statbuf.rdev` is a `qword_t`; neither decoder reads a bit
        // above 31, so the narrowing loses nothing either of them looks at.
        let rdev = stat.rdev as u32;
        // Before publishing: the driver writes `ops` and its state through
        // `&mut`, and takes no reference to the description -- a terminal
        // keeps the watcher list, not the descriptor.
        let err = fs_devices::open_device(
            fs_devices::dev_major(rdev) as c_int,
            fs_devices::dev_minor(rdev) as c_int,
            kind,
            &mut fd,
        );
        if err < 0 {
            return Err(Errno::from_negative_or_eio(err));
        }
    }
    // The driver has had its look; see the note where the flags are stored.
    fd.set_flags(fd.flags() & !ffi::O_NOCTTY_);
    // Published here, after every refusal; from now on a failure closes
    // through `fd_finalize`, which gives back the write access above.
    let fd = fd.into_owned();

    // And only now the truncation the caller asked for, through the same
    // attribute an `ftruncate` sets. Linux ignores O_TRUNC on anything but a
    // regular file, and on a read-only open.
    if truncating && writing && is(ty, S_IFREG) {
        let size = ffi::Attr::Size(0);
        let err = match fd.mount().and_then(|m| m.fs) {
            Some(fs) => match super::killpriv::remove_privs(&fd) {
                0 => fs.fsetattr(&fd, size),
                e => e,
            },
            None => errno::EPERM,
        };
        if err < 0 {
            return Err(Errno::from_negative_or_eio(err));
        }
    }
    Ok(fd)
}

/// # Safety
///
/// As [`generic_openat`].
/// The C entry point, which `iul.h` declares and an embedder may call.
///
/// **One of the three places the `ERR_PTR` encoding is left**, the others
/// being `realfs_open` and `crates/fs/ttydev`'s `pty_open_fake`: `iul.h` says
/// `struct fd *generic_open(...)` and an embedder reads the answer with
/// `IS_ERR`. Everything above it answers a `Result` since 2026-09-14.
///
/// It said *two* until 2026-09-16, and so did `realfs_open`'s. The third wrote
/// the encoding out by hand as `e as isize as *mut ffi::tty` rather than
/// calling [`ffi::err_ptr`], so a grep for the helper found the two that
/// agreed with each other. `tools/err-ptr.py` is what counts them now.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn generic_open(
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> *mut ffi::fd {
    // SAFETY: the caller's contract, as declared in `iul.h`.
    match generic_openat(ffi::At::Pwd, unsafe { CStr::from_ptr(path) }, flags, mode) {
        Ok(fd) => fd.into_raw(),
        Err(e) => ffi::err_ptr(e.as_c_int()),
    }
}

/// Opening a link onto an open file with no name -- `/proc/<pid>/fd/<n>` on a
/// pipe, which is `/dev/stdin` -- opens that file again, as Linux's
/// `proc_fd_link` does: a new description, with the access this call asks
/// for. A pipe can be; a socket or an anonymous inode is ENXIO, the driver's
/// default. Checked against the file's own mode, as any open is.
fn reopen(file: &ffi::fd, flags: c_int) -> Result<fs_fdobj::Owned, Errno> {
    if flags & ffi::O_DIRECTORY_ as c_int != 0 {
        return Err(Errno::ENOTDIR);
    }
    let st = fs_fdobj::fd_fstat(file).map_err(Errno::from_negative_or_eio)?;
    let accmode = match flags as u32 & ffi::O_ACCMODE_ {
        a if a == ffi::O_WRONLY_ => 2,
        a if a == ffi::O_RDWR_ => 6,
        _ => 4,
    };
    fs_perm::access_check(&st, accmode).map_err(Errno::from_negative_or_eio)?;
    let ops = file.ops.ok_or(Errno::ENXIO)?;
    let new = ops.reopen(file, flags).map_err(Errno::from_negative_or_eio)?;
    new.set_flags(fs_fdobj::status::at_open(flags as u32));
    Ok(new)
}
