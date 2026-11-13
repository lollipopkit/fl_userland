//! Timestamp update syscalls for paths.

use super::*;

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

// Linux's sentinels for "now" and "leave this one alone". They are not the
// host's -- Darwin spells UTIME_NOW as -1 and UTIME_OMIT as -2 -- and nothing
// translated them: the guest's timespec went to the host's utimensat verbatim,
// so a UTIME_OMIT that should have preserved a timestamp instead asked for
// 1073741822 nanoseconds. Only tmpfs got this right, because it interprets the
// values itself; every other mount was wrong, and so would every new one be.
// Resolving them here means a filesystem only ever sees a real time.
const UTIME_NOW: i64 = 0x3fff_ffff;
const UTIME_OMIT: i64 = 0x3fff_fffe;

fn utime_nsec_ok(nsec: i64) -> bool {
    nsec == UTIME_NOW || nsec == UTIME_OMIT || (0..1_000_000_000).contains(&nsec)
}

/// The host's `struct timespec`, as bindgen generated it.
///
/// The same layout as `libc::timespec`; it is a separate type because each
/// crate's bindings are its own, and `generic_utime` takes this one.
type HostTimespec = ffi::timespec;

fn now() -> HostTimespec {
    let (sec, nsec) = util_timeabi::host_clock(libc::CLOCK_REALTIME).unwrap_or((0, 0));
    timespec(sec, nsec)
}

fn timespec(sec: i64, nsec: i64) -> HostTimespec {
    HostTimespec {
        tv_sec: sec as _,
        tv_nsec: nsec as _,
    }
}

/// The path for a `utimensat`, which may be absent.
///
/// `"."` rather than uninitialised: `futimens(fd, times)` reaches here as
/// `utimensat(fd, NULL, times, 0)`, and `at_fd` reads the first byte to decide
/// whether the path is absolute — so with nothing written into the buffer it
/// read whatever was on the stack, and a leading `/` there made it resolve
/// against the working directory instead of the descriptor. The timestamp went
/// to the current directory rather than to the file, and which of the two
/// happened depended on the stack.
///
/// An empty one under `AT_EMPTY_PATH` is the same `"."`: the descriptor's own
/// file, by path, which is how Linux's `LOOKUP_EMPTY` reaches an `O_PATH`
/// descriptor that `futimens` cannot.
fn utime_path(path_addr: u64, flags: c_int) -> Result<Path, Errno> {
    let dot = || {
        let mut buf = [0u8; MAX_PATH];
        buf[0] = b'.';
        Path(buf)
    };
    if path_addr == 0 {
        return Ok(dot());
    }
    let path = Path::read(path_addr)?;
    if flags & ffi::AT_EMPTY_PATH_ as c_int != 0 && path.0[0] == 0 {
        return Ok(dot());
    }
    Ok(path)
}

fn utime_common(
    at_f: c_int,
    path_addr: u64,
    atime: HostTimespec,
    mtime: HostTimespec,
    flags: c_int,
) -> Result<(), Errno> {
    let path = utime_path(path_addr, flags)?;
    strace!(
        "utimensat({at_f}, {:?}, {{{}, {}}}, {{{}, {}}}, {flags})",
        path.as_str(),
        atime.tv_sec,
        atime.tv_nsec,
        mtime.tv_sec,
        mtime.tv_nsec
    );
    let at = at_of(at_f, &path)?;
    done(fs_generic::generic_utime(at.at(), path.as_cstr(), atime, mtime, follows(flags)))
}

/// `utimensat(fd, NULL, ...)` on a descriptor whose filesystem answers it
/// itself -- see `FsOps::futime`. `None` to go the path way, which is every
/// other case and which then answers `EBADF` for a bad descriptor as before.
fn by_descriptor(
    at_f: c_int,
    path_addr: u64,
    atime: Option<HostTimespec>,
    mtime: Option<HostTimespec>,
    touch: bool,
) -> Option<Result<(), Errno>> {
    if path_addr != 0 {
        return None;
    }
    let fd = fs_fdobj::f_get(at_f)?;
    let fs = fd.mount()?.fs?;
    fs.futime(&fd, atime, mtime, touch).map(done)
}

/// Who may set a file's times: `setattr_prepare` and `notify_change`. An
/// explicit time needs the owner or `CAP_FOWNER` (`EPERM`); "now" -- no times,
/// or both `UTIME_NOW` -- lets a caller who may write the file too (`EACCES`). Nothing asked until 2026-11-13: any process could set any
/// file's times (`caps_probe`).
fn may_set_times(at_f: c_int, path_addr: u64, flags: c_int, touch: bool) -> Result<(), Errno> {
    let st = if path_addr == 0 {
        let fd = fs_fdobj::f_get(at_f).ok_or(Errno::EBADF)?;
        fs_fdobj::fd_fstat(&fd).map_err(Errno::from_negative_or_eio)?
    } else {
        let path = utime_path(path_addr, flags)?;
        let at = at_of(at_f, &path)?;
        let mut st = ffi::statbuf::default();
        done(fs_generic::generic_statat(at.at(), path.as_cstr(), &mut st, follows(flags)))?;
        st
    };
    taskview::with_current_creds(|c| c.may_set_times(st.uid, st.gid, st.mode, touch))
        .unwrap_or(Err(guest_errno::c_int_::EPERM))
        .map_err(Errno::from_negative_or_eio)
}

pub fn sys_utimensat(
    at_f: c_int,
    path_addr: u64,
    times_addr: u64,
    flags: c_uint,
) -> Result<(), Errno> {
    let flags = flags as c_int;
    // `AT_SYMLINK_NOFOLLOW` and `AT_EMPTY_PATH`. Linux's `do_utimes_path`
    // begins
    //
    //     if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
    //             return -EINVAL;
    //
    // and this accepted anything until 2026-09, so a caller asking for
    // something this kernel does not do was told it had been done. It then
    // refused `AT_EMPTY_PATH` on the reading that Linux does not take it here;
    // Linux has since 5.8, and `fsat_probe` measured `utimensat(fd, "", t,
    // AT_EMPTY_PATH)` answering 0 on a 7.2 kernel and EINVAL here.
    if flags & !((ffi::AT_SYMLINK_NOFOLLOW_ | ffi::AT_EMPTY_PATH_) as c_int) != 0 {
        return Err(Errno::EINVAL);
    }
    // An empty path naming a file with no name has only its descriptor to go
    // by, which is `futimens`'s route.
    let path_addr = if flags & ffi::AT_EMPTY_PATH_ as c_int != 0
        && path_addr != 0
        && Path::read(path_addr)?.0[0] == 0
        && matches!(Itself::of(at_f)?, Itself::Nameless(_))
    {
        0
    } else {
        path_addr
    };
    if times_addr == 0 {
        may_set_times(at_f, path_addr, flags, true)?;
        let n = now();
        if let Some(done) = by_descriptor(at_f, path_addr, Some(n), Some(n), true) {
            return done;
        }
        return utime_common(at_f, path_addr, n, n, flags);
    }

    let mut b = [0u8; 32];
    if GuestMem.read(times_addr, &mut b) != 0 {
        return Err(Errno::EFAULT);
    }
    let at_i64 = |o: usize| i64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let (a_sec, a_nsec, m_sec, m_nsec) = (at_i64(0), at_i64(8), at_i64(16), at_i64(24));

    // A nanosecond field outside 0..999999999 that is not a sentinel is EINVAL.
    // It used to be passed down to be interpreted as a time.
    if !utime_nsec_ok(a_nsec) || !utime_nsec_ok(m_nsec) {
        return Err(Errno::EINVAL);
    }
    // Both omitted: nothing to do, and Linux still checks nothing.
    if a_nsec == UTIME_OMIT && m_nsec == UTIME_OMIT {
        return Ok(());
    }
    // Both `UTIME_NOW` is `times == NULL` to `vfs_utimes`; anything else, an
    // `UTIME_OMIT` included, is an explicit update (`ATTR_TIMES_SET`).
    // Measured: `{NOW, OMIT}` on another user's writable file is `EPERM`.
    may_set_times(at_f, path_addr, flags, a_nsec == UTIME_NOW && m_nsec == UTIME_NOW)?;

    let n = now();
    let mut atime = if a_nsec == UTIME_NOW {
        n
    } else {
        timespec(a_sec, a_nsec)
    };
    let mut mtime = if m_nsec == UTIME_NOW {
        n
    } else {
        timespec(m_sec, m_nsec)
    };

    if let Some(done) = by_descriptor(
        at_f,
        path_addr,
        (a_nsec != UTIME_OMIT).then_some(atime),
        (m_nsec != UTIME_OMIT).then_some(mtime),
        a_nsec == UTIME_NOW && m_nsec == UTIME_NOW,
    ) {
        return done;
    }

    // UTIME_OMIT means keep what is there, and a filesystem operation that sets
    // both is the only one there is -- so read the current value and write it
    // back. Not atomic against another setter, which Linux's is; nothing here
    // can express "change one" without a second VFS operation, and preserving
    // the timestamp beats corrupting it.
    if a_nsec == UTIME_OMIT || m_nsec == UTIME_OMIT {
        let path = utime_path(path_addr, flags)?;
        let at = at_of(at_f, &path)?;
        let mut st = ffi::statbuf::default();
        done(fs_generic::generic_statat(at.at(), path.as_cstr(), &mut st, follows(flags)))?;
        if a_nsec == UTIME_OMIT {
            atime = timespec(st.atime, st.atime_nsec as i64);
        }
        if m_nsec == UTIME_OMIT {
            mtime = timespec(st.mtime, st.mtime_nsec as i64);
        }
    }
    utime_common(at_f, path_addr, atime, mtime, flags)
}

/* `sys_utimes` and `sys_utime` were here, and **no syscall table reached
 * either**: aarch64 has `utimensat` and nothing else, and both were i386
 * numbers left behind by the x86 removal. `kernel/calls.h` declared them, which
 * is what kept `tools/dead-exports.py` from saying so -- a prototype in a
 * *header* is an interface, deliberately, because an embedder compiles against
 * that file.
 *
 * They were found by `tools/deadline-overflow.py`, which reported `sys_utimes`
 * multiplying a guest `tv_usec` by 1000 with nothing bounding it. That is the
 * shape that aborts the emulator elsewhere; here it was unreachable, and the
 * answer to unreachable code is not to fix its arithmetic. `sys_epoll_create0`,
 * `sys_select` and `sys_poll` went for the same reason.
 *
 * `sys_utimensat` is the reachable one and validates: a nanosecond field outside
 * `0..999999999` that is not `UTIME_NOW` or `UTIME_OMIT` is `EINVAL`, and it
 * needs no conversion at all because a `timespec` is already nanoseconds. */
