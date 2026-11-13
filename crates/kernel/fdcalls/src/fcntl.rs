//! `fcntl(2)` command policy and descriptor lock operations.

use super::*;

// ---------------------------------------------------------------------------
// fcntl
// ---------------------------------------------------------------------------

pub(super) const F_DUPFD: c_uint = 0;
pub(super) const F_GETFD: c_uint = 1;
pub(super) const F_SETFD: c_uint = 2;
pub(super) const F_GETFL: c_uint = 3;
pub(super) const F_SETFL: c_uint = 4;

pub(super) const F_GETLK: c_uint = 5;
pub(super) const F_SETLK: c_uint = 6;
pub(super) const F_SETLKW: c_uint = 7;
/// The 32-bit ABI's names for the three above, accepted as aliases.
///
/// On a 32-bit ABI there are two of each — `F_GETLK` with a 32-bit `off_t` and
/// `F_GETLK64` with a 64-bit one — and `fs/fd.c` carried both, the first
/// reading an i386 `struct flock` and the second an i386 `struct flock64`.
/// aarch64 has neither: `off_t` is 64 bits, so musl sends 5, 6 and 7 with the
/// layout `struct flock_` describes and 12, 13 and 14 never arrive. They are
/// kept as aliases rather than deleted, because a 64-bit libc that does define
/// them defines them to mean exactly this.
pub(super) const F_GETLK64: c_uint = 12;
pub(super) const F_SETLK64: c_uint = 13;
pub(super) const F_SETLKW64: c_uint = 14;

/// Linux's `f_owner`: who is told when this description becomes ready, and with
/// which signal. `F_GETOWN` answers a **negative** number for a process group,
/// which is why the arm below cannot report an errno as well -- an errno and a
/// result are not separable there, so an unknown command is `EINVAL` and this
/// one is not.
///
/// Recorded and reported; the signal is not raised. `fs/fd.h` says at length
/// why, and what would have to change for it to be.
pub(super) const F_GETOWN: c_uint = 9;
pub(super) const F_SETOWN: c_uint = 8;
pub(super) const F_GETSIG: c_uint = 11;
pub(super) const F_SETSIG: c_uint = 10;
pub(super) const F_SETOWN_EX: c_uint = 15;
pub(super) const F_GETOWN_EX: c_uint = 16;

/// The largest signal number `F_SETSIG` takes, which is `kernel/signal.h`'s
/// `MAX_SIG`. Zero means the default, which is `SIGIO`.
pub(super) const MAX_SIG: i32 = 64;

/// `struct f_owner_ex`'s `type`: a thread, a process, a process group.
pub(super) const F_OWNER_TID: i32 = 0;
pub(super) const F_OWNER_PID: i32 = 1;
pub(super) const F_OWNER_PGRP: i32 = 2;

/// Open file description locks. Same records, same conflict rules; the owner is
/// the description rather than the descriptor table, so two opens of one file
/// contend where two threads of one process do not. SQLite asks for these by
/// preference on Linux, and they were `EINVAL`.
pub(super) const F_OFD_GETLK: c_uint = 36;
pub(super) const F_OFD_SETLK: c_uint = 37;
pub(super) const F_OFD_SETLKW: c_uint = 38;

/// Leases. None is ever granted here -- see the arm -- so what these answer is
/// what a file open elsewhere answers.
pub(super) const F_SETLEASE: c_uint = 1024;
pub(super) const F_GETLEASE: c_uint = 1025;
/// Whether two descriptors name one open file description (6.10), and whether
/// this description's open created the file (6.12). Both were `EINVAL`, which
/// is what a kernel too old to have them answers, and a program that probes
/// for them read this kernel as one.
pub(super) const F_DUPFD_QUERY: c_uint = 1027;
pub(super) const F_CREATED_QUERY: c_uint = 1028;
pub(super) const F_DUPFD_CLOEXEC: c_uint = 1030;
/// Pipe-only, and answered by `crates/fs/pipe`. They were `EINVAL`, because a
/// host pipe has no equivalent fcntl on macOS at all.
pub(super) const F_SETPIPE_SZ: c_uint = 1031;
pub(super) const F_GETPIPE_SZ: c_uint = 1032;
/// memfd-only, and answered by `crates/kernel/memfdcalls`.
pub(super) const F_ADD_SEALS: c_uint = 1033;
pub(super) const F_GET_SEALS: c_uint = 1034;
/// The write-life hint on the inode, `RWH_WRITE_LIFE_*`. Stored and read back
/// and nothing else, which is what a filesystem without stream separation does
/// with it on Linux too.
pub(super) const F_GET_RW_HINT: c_uint = 1035;
pub(super) const F_SET_RW_HINT: c_uint = 1036;

/// `struct flock`'s three lock types, which `F_SETLEASE` reuses as lease types.
pub(super) const F_RDLCK: u64 = 0;
pub(super) const F_WRLCK: u64 = 1;
pub(super) const F_UNLCK: u64 = 2;

/// The largest `RWH_WRITE_LIFE_*` value: `NOT_SET`, `NONE`, `SHORT`, `MEDIUM`,
/// `LONG`, `EXTREME` are 0 to 5, and Linux's `rw_hint_valid` is that list.
pub(super) fn rw_hint_valid(hint: u64) -> bool {
    hint <= 5
}

/// Linux's `check_fcntl_cmd`: the five commands an `O_PATH` descriptor answers.
/// Every other one is `EBADF` on it -- it names a file without being able to
/// read or write it, and `F_SETFL(O_NONBLOCK)` on one used to succeed and
/// record a flag on a description nothing could ever block on.
pub(super) fn allowed_on_path_only(cmd: c_uint) -> bool {
    matches!(cmd, F_DUPFD | F_DUPFD_CLOEXEC | F_GETFD | F_SETFD | F_GETFL)
}

/// `F_DUPFD`'s minimum as `f_dupfd` receives it: `unsigned int`, so the upper
/// half of a 64-bit argument is dropped before the limit is compared.
/// `F_DUPFD(1 << 40)` is therefore `F_DUPFD(0)` on Linux, and was `EINVAL` here.
pub(super) fn dupfd_minimum(arg: u64) -> u64 {
    arg as u32 as u64
}

/// Whether `F_DUPFD`'s minimum descriptor number is one a caller may ask for.
///
/// Linux's `f_dupfd` begins
///
/// ```c
/// if (from >= rlimit(RLIMIT_NOFILE))
///         return -EINVAL;
/// ```
///
/// and `from` is *unsigned*, so -1 is a very large number rather than a small
/// one. Nothing checked here, so the value went to the installer, which
/// answered `EBADF` for -1 and `EMFILE` for a merely huge one. Both are
/// `EINVAL` on a real kernel, and the difference matters: `EMFILE` says "close
/// something and retry", which a caller that passed a nonsense minimum will do
/// for ever.
pub(super) fn dupfd_start_ok(arg: u64, limit: u64) -> bool {
    arg < limit
}

pub fn sys_fcntl(f: c_int, cmd: c_uint, arg: u64) -> Ret {
    let handle = fs_fdobj::f_get(f).ok_or(Errno::EBADF)?;
    let fd = &*handle;
    if fd.is_path_only() && !allowed_on_path_only(cmd) {
        strace!("fcntl({f}, {cmd}) on an O_PATH descriptor");
        return Err(Errno::EBADF);
    }
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let from = dupfd_minimum(arg);
            if !dupfd_start_ok(from, nofile_limit()) {
                return Err(Errno::EINVAL);
            }
            let cloexec = cmd == F_DUPFD_CLOEXEC;
            strace!(
                "fcntl({f}, {}, {from})",
                if cloexec {
                    "F_DUPFD_CLOEXEC"
                } else {
                    "F_DUPFD"
                }
            );
            // See sys_dup.
            let fd = handle.retain();
            // `f_install_start` reaches `fdtable_expand`, which reallocates the
            // table's arrays; `f_install` holds the table lock across it and
            // these two did not.
            Errno::split(fs_fdobj::f_install_start(fd, from as c_int, cloexec) as i64)
        }
        F_DUPFD_QUERY => {
            strace!("fcntl({f}, F_DUPFD_QUERY, {arg})");
            let Some(other) = fs_fdobj::f_get(arg as c_int) else {
                return Err(Errno::EBADF);
            };
            let other = &*other;
            Ok(i64::from(std::ptr::eq(fd, other)))
        }
        F_CREATED_QUERY => {
            strace!("fcntl({f}, F_CREATED_QUERY)");
            Ok(i64::from(fd.created))
        }

        F_GETFD => {
            strace!("fcntl({f}, F_GETFD)");
            // 0 for a number another thread closed since `f_get`, as the table
            // answered before.
            with_table(|table| Ok(i64::from(table.cloexec(f).unwrap_or(false))))
        }
        F_SETFD => {
            strace!("fcntl({f}, F_SETFD, {arg:#x})");
            with_table(|table| Errno::split(table.set_cloexec(f, arg & 1 != 0) as i64))
        }

        F_GETPIPE_SZ => {
            strace!("fcntl({f}, F_GETPIPE_SZ)");
            Errno::split(pipecalls::pipe_fcntl_get_size(fd) as i64)
        }
        F_SETPIPE_SZ => {
            strace!("fcntl({f}, F_SETPIPE_SZ, {arg})");
            // 32 bits, as pipe_set_size receives it; the privilege is
            // CAP_SYS_RESOURCE.
            Errno::split(
                pipecalls::pipe_fcntl_set_size(fd, arg as u32, taskview::capable(taskview::caps::CAP_SYS_RESOURCE)) as i64,
            )
        }

        F_GETFL => {
            strace!("fcntl({f}, F_GETFL)");
            Ok(fd.flags() as i64)
        }
        F_SETFL => {
            strace!("fcntl({f}, F_SETFL, {arg:#x})");
            // The one rule the description cannot check for itself: turning
            // O_NOATIME *on* takes the file's owner or CAP_FOWNER, because it
            // hides the reader's traces from the owner. setfl():
            //
            //     if ((arg & O_NOATIME) && !(filp->f_flags & O_NOATIME))
            //             if (!inode_owner_or_capable(idmap, inode))
            //                     return -EPERM;
            let wanted = arg as u32;
            let now = fd.flags();
            if wanted & ffi::O_NOATIME_ != 0 && now & ffi::O_NOATIME_ == 0 && !owner_or_capable(fd)
            {
                return Err(Errno::EPERM);
            }
            Errno::split(fs_fdobj::fd_setflags(fd, wanted as c_int) as i64)
        }

        F_GETLK | F_GETLK64 => {
            strace!("fcntl({f}, F_GETLK, {arg:#x})");
            let Some(mut flock) = read_flock(arg) else {
                return Err(Errno::EFAULT);
            };
            let err = fs_locks::fcntl_getlk(fd, &mut flock);
            // Written back only on success: a failed query has nothing to say
            // about the lock, and overwriting the caller's struct would answer
            // a question it did not get an answer to.
            if err >= 0 && !write_flock(arg, &flock) {
                return Err(Errno::EFAULT);
            }
            Errno::split(err as i64)
        }

        F_SETLK | F_SETLKW | F_SETLK64 | F_SETLKW64 => {
            let waiting = cmd == F_SETLKW || cmd == F_SETLKW64;
            strace!(
                "fcntl({f}, F_SETLK{}, {arg:#x})",
                if waiting { "W" } else { "" }
            );
            let Some(mut flock) = read_flock(arg) else {
                return Err(Errno::EFAULT);
            };
            // Each arm asks whether *its own* command was the waiting one. The
            // two used to be crossed -- one tested F_SETLKW64 and the other
            // F_SETLKW -- so neither could ever be true and F_SETLKW never
            // blocked on either path.
            Errno::split(fs_locks::fcntl_setlk(fd, &mut flock, waiting) as i64)
        }

        F_OFD_GETLK => {
            strace!("fcntl({f}, F_OFD_GETLK, {arg:#x})");
            let Some(mut flock) = read_flock(arg) else {
                return Err(Errno::EFAULT);
            };
            let err = fs_locks::fcntl_getlk_owned(fd, &mut flock, true);
            if err >= 0 && !write_flock(arg, &flock) {
                return Err(Errno::EFAULT);
            }
            Errno::split(err as i64)
        }

        F_OFD_SETLK | F_OFD_SETLKW => {
            let waiting = cmd == F_OFD_SETLKW;
            strace!(
                "fcntl({f}, F_OFD_SETLK{}, {arg:#x})",
                if waiting { "W" } else { "" }
            );
            let Some(mut flock) = read_flock(arg) else {
                return Err(Errno::EFAULT);
            };
            Errno::split(
                fs_locks::fcntl_setlk_owned(fd, &mut flock, waiting, true) as i64,
            )
        }

        // The seals of a memfd, `crates/kernel/memfdcalls`. Both answer EINVAL
        // for a descriptor that is not one, which is Linux's answer for a file
        // that has no seals.
        F_ADD_SEALS => {
            strace!("fcntl({f}, F_ADD_SEALS, {arg:#x})");
            // `.cast()`: every crate has its own bindgen rendering of
            // `struct fd`, so the same C type is two Rust types. The cast is
            // what a header declaring the function used to hide -- and the
            // pin in `crates/fs/adhoc` is what says the two renderings agree.
            memfdcalls::memfd_add_seals(fd, arg as c_uint).map(|()| 0)
        }
        F_GET_SEALS => {
            strace!("fcntl({f}, F_GET_SEALS)");
            memfdcalls::memfd_get_seals(fd).map(i64::from)
        }

        F_GET_RW_HINT => {
            strace!("fcntl({f}, F_GET_RW_HINT, {arg:#x})");
            let hint = u64::from(fd.inode().map_or(0, fs_inode::write_hint));
            if GuestMem.write(arg, &hint.to_le_bytes()) != 0 {
                return Err(Errno::EFAULT);
            }
            Ok(0)
        }
        F_SET_RW_HINT => {
            strace!("fcntl({f}, F_SET_RW_HINT, {arg:#x})");
            let mut raw = [0u8; 8];
            if GuestMem.read(arg, &mut raw) != 0 {
                return Err(Errno::EFAULT);
            }
            let hint = u64::from_le_bytes(raw);
            if !rw_hint_valid(hint) {
                return Err(Errno::EINVAL);
            }
            // A descriptor with no inode -- a pipe, a socket -- has nowhere to
            // keep it; the value is validated and not stored, and a get answers
            // NOT_SET. Linux keeps one on the pipefs inode; nothing reads it.
            if let Some(inode) = fd.inode() {
                fs_inode::set_write_hint(inode, hint as u8);
            }
            Ok(0)
        }

        // Leases. This kernel grants none: a lease is a promise to be told,
        // and given 45 seconds to finish, before another process opens the file
        // -- and with no way to hold that other open() while the holder is
        // told, a lease granted would be a lie. What is answered is what
        // Linux answers for a file somebody else has open: EAGAIN, from
        // check_conflicting_open. F_UNLCK with no lease held is EAGAIN there
        // as well, from generic_delete_lease. Measured by fcntl_probe. Both
        // were EINVAL, which a program reads as "no leases on this kernel"
        // and which is a different, wrong, answer -- EINVAL is for a lease
        // *type* that does not exist and a file that is not regular.
        F_GETLEASE => {
            strace!("fcntl({f}, F_GETLEASE)");
            Ok(F_UNLCK as i64)
        }
        F_SETLEASE => {
            strace!("fcntl({f}, F_SETLEASE, {arg})");
            // The file's kind first, whatever is asked: F_UNLCK on a pipe is
            // EINVAL and not EAGAIN. Measured.
            if fd.type_ as u32 != libc::S_IFREG as u32 {
                return Err(Errno::EINVAL);
            }
            match arg {
                F_UNLCK => Err(Errno::EAGAIN),
                F_RDLCK | F_WRLCK => {
                    // A lease is the owner's or CAP_LEASE's to ask for.
                    if !owner_or_capable(fd) {
                        return Err(Errno::EACCES);
                    }
                    Err(Errno::EAGAIN)
                }
                _ => Err(Errno::EINVAL),
            }
        }

        // The owner. Recorded and reported; see the field in `fs/fd.h` for why
        // that is better than the refusal it replaced, and what raising the
        // signal would take.
        F_GETOWN => {
            strace!("fcntl({f}, F_GETOWN)");
            // `Ok` of a negative number, and not an errno. This is the arm the
            // old shape could not express: a process group is reported as a
            // negative pid, so -13 here means the group 13 and not EACCES.
            Ok(fd.owner_pid() as i64)
        }
        F_SETOWN => {
            strace!("fcntl({f}, F_SETOWN, {arg})");
            // Truncated to 32 bits as Linux's `f_setown` takes an `int`, and
            // sign-extended back: a negative owner is a process group.
            fd.set_owner_pid(arg as i32);
            Ok(0)
        }
        F_GETSIG => {
            strace!("fcntl({f}, F_GETSIG)");
            Ok(fd.owner_sig() as i64)
        }
        F_SETSIG => {
            strace!("fcntl({f}, F_SETSIG, {arg})");
            // Zero means the default, which is SIGIO. Linux's `do_fcntl`
            // refuses anything that is not a valid signal number.
            let sig = arg as i32;
            if !(0..=MAX_SIG).contains(&sig) {
                return Err(Errno::EINVAL);
            }
            fd.set_owner_sig(sig);
            Ok(0)
        }
        F_GETOWN_EX => {
            strace!("fcntl({f}, F_GETOWN_EX, {arg:#x})");
            let owner = fd.owner_pid();
            // Linux never answers F_OWNER_TID here unless F_SETOWN_EX asked
            // for one, and this kernel does not record which was asked -- so
            // a group is negative and everything else is a process, which is
            // what `f_getown_ex` reports for an owner set by plain F_SETOWN.
            let (ty, pid) = if owner < 0 {
                (F_OWNER_PGRP, -owner)
            } else {
                (F_OWNER_PID, owner)
            };
            let mut buf = [0u8; 8];
            buf[..4].copy_from_slice(&ty.to_ne_bytes());
            buf[4..].copy_from_slice(&pid.to_ne_bytes());
            if GuestMem::current().write(arg, &buf) != 0 {
                return Err(Errno::EFAULT);
            }
            Ok(0)
        }
        F_SETOWN_EX => {
            strace!("fcntl({f}, F_SETOWN_EX, {arg:#x})");
            let mut buf = [0u8; 8];
            if GuestMem::current().read(arg, &mut buf) != 0 {
                return Err(Errno::EFAULT);
            }
            let ty = i32::from_ne_bytes(buf[..4].try_into().unwrap());
            let pid = i32::from_ne_bytes(buf[4..].try_into().unwrap());
            match ty {
                F_OWNER_TID | F_OWNER_PID => fd.set_owner_pid(pid),
                F_OWNER_PGRP => fd.set_owner_pid(-pid),
                _ => return Err(Errno::EINVAL),
            }
            Ok(0)
        }

        _ => {
            // Still EINVAL, which is what Linux answers for a command it does
            // not know -- and unlike the socket option table, a caller here
            // cannot be given anything better: F_GETOWN legitimately returns
            // negative values, so an errno and a result are not separable.
            //
            // Unimplemented and refused: F_NOTIFY, which asks for a signal
            // when a *directory* changes. Answering it without delivering
            // would make a program that asked wait for ever, and unlike the
            // owner commands above nothing refuses to start without it --
            // every user of dnotify has an inotify path, which this kernel
            // has.
            strace!("fcntl({f}, {cmd}) unimplemented");
            Err(Errno::EINVAL)
        }
    }
}

/// Whether the caller owns the file behind `fd` or is privileged for a
/// filesystem decision -- `inode_owner_or_capable`, which is `CAP_FOWNER`, one
/// of the capabilities setting the fsuid away from root drops.
pub(super) fn owner_or_capable(fd: &ffi::fd) -> bool {
    if taskview::capable(taskview::caps::CAP_FOWNER) {
        return true;
    }
    match stat_of(fd) {
        Some(st) => taskview::with_current_creds(|c| c.owner_or_capable(st.uid)).unwrap_or(false),
        None => false,
    }
}

/// The file's attributes: the mount's `fstat`, or the descriptor's own for one
/// that has no mount -- a pipe, a socket.
pub(super) fn stat_of(fd: &ffi::fd) -> Option<ffi::statbuf> {
    let Some(mount) = fd.mount() else {
        return Some(fd.stat);
    };
    // This is one of the two callers the trait's own doc named as wanting
    // an `Option<statbuf>` back, and now it is one line.
    mount.fs.and_then(|fs| fs.fstat(fd))?.ok()
}

/// The guest's `struct flock` at `addr`. `flock_` is `Plain`: its padding is
/// spelled out as `_pad0` and `_pad1`, and `plain!` asserts there is no other.
pub(super) fn read_flock(addr: u64) -> Option<ffi::flock_> {
    GuestMem.read_value(addr).ok()
}

/// The reverse. See [`read_flock`].
pub(super) fn write_flock(addr: u64, flock: &ffi::flock_) -> bool {
    GuestMem.write_value(addr, flock) == 0
}
