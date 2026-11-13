//! Asking what a file is: `stat64`, `lstat64`, `fstat64`, `fstatat64` and
//! `statx`.
//!
//! Five syscalls over one question and two answers. The old answer is
//! `struct stat_arm64`, 128 bytes with two explicit padding fields, and the new
//! one is `statx`'s 256 — whose layout and mask protocol are `crates/fs/statx`,
//! because that is where a bit can be tied to the line that writes its field.
//!
//! What is here is the argument handling, and it is the same three steps every
//! time: read the path, work out what a relative one is relative to, and hand
//! both to `generic_statat`. `fstat64` is the one that skips the path, and
//! `statx` is the one that can go either way — `AT_EMPTY_PATH` with an empty
//! path means "the descriptor", which is how a caller stats something it has
//! open without naming it.
//!
//! # `struct newstat64` went rather than moved
//!
//! `fs/stat.c` also had `stat_convert_newstat64`, filling a 96-byte i386
//! layout. **Nothing called it** — it was left behind when the x86 backend was
//! removed, along with `struct newstat64` in `fs/stat.h`. Both are gone.


use std::ffi::{CStr, CString, c_int, c_uint};

use fs_devices::{dev_major, dev_minor};
use statx::{FileInfo, Timestamp};
use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/// `AT_FDCWD`, as the guest spells it.
const AT_FDCWD: c_int = -100;
/// `AT_SYMLINK_NOFOLLOW`.
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
/// `AT_EMPTY_PATH`: an empty path names the descriptor itself.
const AT_EMPTY_PATH: c_int = 0x1000;
/// `AT_NO_AUTOMOUNT`: accepted and ignored, as it is on a kernel with no
/// automounter — which is every kernel this one could be.
const AT_NO_AUTOMOUNT: c_int = 0x800;

// ---------------------------------------------------------------------------
// The old answer
// ---------------------------------------------------------------------------

/// `struct statbuf` as the guest's 128-byte `struct stat`.
///
/// Generated on both sides, so this is field names rather than offsets — which
/// is the point: the C wrote twenty assignments including two paddings, and a
/// field written into the wrong one of two adjacent 64-bit slots is a size a
/// program reads as a timestamp.
fn to_guest_stat(st: &ffi::statbuf) -> ffi::stat_arm64 {
    ffi::stat_arm64 {
        dev: st.dev,
        ino: st.inode,
        mode: st.mode,
        nlink: st.nlink,
        uid: st.uid,
        gid: st.gid,
        rdev: st.rdev,
        size: st.size as _,
        blksize: st.blksize as _,
        blocks: st.blocks as _,
        atime_: st.atime as _,
        atime_nsec: st.atime_nsec as _,
        mtime_: st.mtime as _,
        mtime_nsec: st.mtime_nsec as _,
        ctime_: st.ctime as _,
        ctime_nsec: st.ctime_nsec as _,
        ..Default::default()
    }
}

fn put_stat(addr: u64, st: &ffi::statbuf) -> Result<(), Errno> {
    if GuestMem::current().write_value(addr, &to_guest_stat(st)) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// The guest path at `addr`, at most `MAX_PATH` bytes, which is what the C's
/// stack array was. A `CString`, where it was a `Vec<c_char>` handed on as a
/// pointer: `read_string` stops at the terminator, so there is no interior NUL
/// to refuse.
fn read_path(addr: u64) -> Result<CString, Errno> {
    let mut buf = vec![0u8; ffi::MAX_PATH as usize];
    let n = GuestMem::current()
        .read_string(addr, &mut buf)
        .map_err(Errno::from_negative_or_eio)?;
    buf.truncate(n);
    CString::new(buf).map_err(|_| Errno::EINVAL)
}

fn as_str(path: &CStr) -> String {
    path.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// The four that answer a struct stat
// ---------------------------------------------------------------------------

fn stat_path(at_f: c_int, path_addr: u64, statbuf_addr: u64, follow: bool) -> Result<(), Errno> {
    let path = read_path(path_addr)?;
    strace!(
        "stat(at={at_f}, path={:?}, statbuf={statbuf_addr:#x}, follow_links={follow})",
        as_str(&path)
    );
    let Some(at) = fs_fdobj::at_fd(at_f, &path) else {
        return Err(Errno::EBADF);
    };
    let mut st = ffi::statbuf::default();
    let err = fs_generic::generic_statat(at.at(), &path, &mut st, follow);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    put_stat(statbuf_addr, &st)
}

pub fn sys_fstatat64(
    at: c_int,
    path_addr: u64,
    statbuf_addr: u64,
    flags: c_uint,
) -> Result<(), Errno> {
    let flags = flags as c_int;
    // Linux's `vfs_fstatat` refuses anything else outright. This accepted
    // whatever it was given and looked at one bit.
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    // `AT_EMPTY_PATH` with an empty path is "stat what this descriptor is
    // open on", and it is how **`chase()` in systemd** asks about every
    // component it has walked to: open `O_PATH|O_NOFOLLOW`, then
    // `fstatat(fd, "", AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)`.
    //
    // It was not implemented, so the empty path went to the resolver and came
    // back `ENOENT` — and `systemd-machine-id-setup` reported
    // "Cannot open '/etc/machine-id' in neither writable nor read-only mode:
    // No such file or directory" about a file that was there and that every
    // `open` in the trace had just succeeded on. That failed the `systemd`
    // package's postinst, which failed `apt install` for everything that
    // pulls it in.
    //
    // `sys_statx` had it. The comment there said `statx` was "the only way
    // systemd asks", which is what a second implementation of one rule turns
    // into.
    if flags & AT_EMPTY_PATH != 0 {
        // A NULL path is the empty one under `AT_EMPTY_PATH`, since Linux
        // 6.11: `vfs_empty_path` reads no byte for it. It was EFAULT here.
        let mut first = [0u8; 1];
        if path_addr != 0 && GuestMem::current().read(path_addr, &mut first) != 0 {
            return Err(Errno::EFAULT);
        }
        if first[0] == 0 {
            strace!("stat(at={at}, AT_EMPTY_PATH, statbuf={statbuf_addr:#x})");
            // An empty path names *what the dirfd names*, which for `AT_FDCWD`
            // is the working directory — Linux resolves it with `LOOKUP_EMPTY`
            // rather than treating -100 as a descriptor, and `atcall_probe`
            // measured it: `fstatat(AT_FDCWD, "", AT_EMPTY_PATH)` is 0 there
            // and was `EBADF` here.
            if at == AT_FDCWD {
                let mut st = ffi::statbuf::default();
                let err = fs_generic::generic_statat(ffi::At::Pwd, c".", &mut st, true);
                if err < 0 {
                    return Err(Errno::from_negative_or_eio(err));
                }
                return put_stat(statbuf_addr, &st);
            }
            let Some(fd) = fs_fdobj::f_get(at) else {
                return Err(Errno::EBADF);
            };
            return put_stat(statbuf_addr, &fstat_of(&fd)?);
        }
    }
    stat_path(
        at,
        path_addr,
        statbuf_addr,
        flags & AT_SYMLINK_NOFOLLOW == 0,
    )
}

pub fn sys_fstat64(fd_no: c_int, statbuf_addr: u64) -> Result<(), Errno> {
    strace!("fstat64({fd_no}, {statbuf_addr:#x})");
    let Some(fd) = fs_fdobj::f_get(fd_no) else {
        return Err(Errno::EBADF);
    };
    put_stat(statbuf_addr, &fstat_of(&fd)?)
}

/// The mount's `fstat`, which every mount has.
///
/// The mount id and device are stamped by `fd_fstat`, as `generic_statat`
/// stamps them for a path: a filesystem does not know which mount it is. This
/// is the path `statx(fd, "", AT_EMPTY_PATH)` takes, which is the only way
/// systemd asks.
///
/// Safe since 2026-10-01: it was an `unsafe fn` with no contract that read
/// `fd.mount` raw and dereferenced it without a null test.
fn fstat_of(fd: &ffi::fd) -> Result<ffi::statbuf, Errno> {
    fs_fdobj::fd_fstat(fd).map_err(Errno::from_negative_or_eio)
}

// ---------------------------------------------------------------------------
// statx
// ---------------------------------------------------------------------------

pub fn sys_statx(
    at_f: c_int,
    path_addr: u64,
    flags: c_int,
    mask: c_uint,
    statx_addr: u64,
) -> Result<(), Errno> {
    // NULL is the empty path under `AT_EMPTY_PATH`, as for `fstatat` above.
    let path = if path_addr == 0 && flags & AT_EMPTY_PATH != 0 {
        CString::default()
    } else {
        read_path(path_addr)?
    };
    strace!(
        "statx(at={at_f}, path={:?}, flags={flags}, mask={mask}, statx={statx_addr:#x})",
        as_str(&path)
    );
    let Some(at) = fs_fdobj::at_fd(at_f, &path) else {
        return Err(Errno::EBADF);
    };

    // Checked before anything is looked up, as Linux does: a caller probing for
    // a field or a sync mode this kernel does not implement has to be told so,
    // and nothing here checked either.
    statx::validate(flags, mask)?;

    let (st, mount_root) = if flags & AT_EMPTY_PATH != 0 && path.is_empty() {
        // **An empty path names what the dirfd names**, and for `AT_FDCWD`
        // that is the working directory rather than a descriptor --
        // `LOOKUP_EMPTY` in Linux, and exactly what `sys_fstatat` above spells
        // out and measured against a real kernel.
        //
        // This passed `at` straight to `fstat_of`, which reads `fd->mount`.
        // For `AT_FDCWD` that `at` was `AT_PWD`, the sentinel
        // `(struct fd *) -2`, so `statx(AT_FDCWD, "", AT_EMPTY_PATH)` read a
        // field off address -2 and took the **host** down with SIGSEGV --
        // three lines from any guest program. The sentinel is a variant of
        // `ffi::At` now, so there is nothing here to dereference by mistake.
        match at {
            fs_fdobj::AtRef::Fd(fd) => {
                let st = fstat_of(&fd)?;
                (st, fs_generic::generic_fd_is_mount_root(&fd, &st))
            }
            fs_fdobj::AtRef::Pwd => fs_generic::generic_statat_root(at.at(), c".", true)
                .map_err(Errno::from_negative_or_eio)?,
        }
    } else {
        fs_generic::generic_statat_root(at.at(), &path, flags & AT_SYMLINK_NOFOLLOW == 0)
            .map_err(Errno::from_negative_or_eio)?
    };

    let mut out = [0u8; statx::STATX_BYTES];
    statx::encode(&mut out, &FileInfo { mount_root, ..info_of(&st) }, mask);
    if GuestMem::current().write(statx_addr, &out) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// A `struct statbuf` as what `statx` reports.
///
/// `btime` stays `None`: no mount here reports a creation time, and the
/// difference between not knowing and answering the epoch is exactly what that
/// `Option` is for.
///
/// `mnt_id` is the mount's, which the VFS fills in -- 0 means "no mount", which
/// is a descriptor with none rather than a mount whose id is zero, since ids
/// start at 1. systemd asks for it to decide whether two directories are on the
/// same mount; with it unreported it fell back to `name_to_handle_at`, which is
/// a stub here, and gave up -- `systemd-sysusers` then could not find a
/// configuration file that was there.
fn info_of(st: &ffi::statbuf) -> FileInfo {
    FileInfo {
        blksize: st.blksize,
        nlink: st.nlink,
        uid: st.uid,
        gid: st.gid,
        mode: st.mode as u16,
        ino: st.inode,
        size: st.size,
        blocks: st.blocks,
        atime: Timestamp {
            sec: st.atime,
            nsec: st.atime_nsec,
        },
        mtime: Timestamp {
            sec: st.mtime,
            nsec: st.mtime_nsec,
        },
        ctime: Timestamp {
            sec: st.ctime,
            nsec: st.ctime_nsec,
        },
        // `has_btime` rather than a zero check: the epoch is a legal creation
        // time, and telling "we do not know" from "1970" is what `stx_mask`
        // exists for.
        // `has_btime` rather than a zero check: the epoch is a legal creation
        // time, and telling "we do not know" from "1970" is what `stx_mask`
        // exists for.
        btime: (st.has_btime != 0).then_some(Timestamp {
            sec: st.btime,
            nsec: st.btime_nsec,
        }),
        // `crates/fs/devices`' decoders, not a second copy. A guest `dev_t_`
        // is 32 bits and these fields are `qword_t`; neither decoder reads a
        // bit above 31.
        rdev_major: dev_major(st.rdev as u32),
        rdev_minor: dev_minor(st.rdev as u32),
        dev_major: dev_major(st.dev as u32),
        dev_minor: dev_minor(st.dev as u32),
        mnt_id: (st.mount_id != 0).then_some(u64::from(st.mount_id)),
        mnt_id_unique: (st.mount_id != 0).then(|| ffi::unique_mount_id(st.mount_id)),
        mount_root: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ffi::statbuf {
        ffi::statbuf {
            dev: 0x0000_0501, // major 5, minor 1
            inode: 42,
            mode: 0o100644,
            nlink: 3,
            uid: 1000,
            gid: 1001,
            rdev: 0x0000_0102, // major 1, minor 2
            size: 123456,
            blksize: 4096,
            blocks: 241,
            atime: 111,
            atime_nsec: 1,
            mtime: 222,
            mtime_nsec: 2,
            ctime: 333,
            ctime_nsec: 3,
            ..Default::default()
        }
    }

    /// 128 bytes, and every value in the slot the guest reads it from. The C
    /// wrote twenty assignments including two paddings; what makes this
    /// checkable is that both structs are generated.
    #[test]
    fn the_old_answer_is_128_bytes_with_every_field_in_place() {
        assert_eq!(std::mem::size_of::<ffi::stat_arm64>(), 128);
        let out = to_guest_stat(&sample());
        assert_eq!(out.dev, 0x0000_0501);
        assert_eq!(out.ino, 42);
        assert_eq!(out.mode, 0o100644);
        assert_eq!(out.nlink, 3);
        assert_eq!((out.uid, out.gid), (1000, 1001));
        assert_eq!(out.rdev, 0x0000_0102);
        assert_eq!(out.size, 123456);
        assert_eq!(out.blksize, 4096);
        assert_eq!(out.blocks, 241);
        assert_eq!((out.atime_, out.atime_nsec), (111, 1));
        assert_eq!((out.mtime_, out.mtime_nsec), (222, 2));
        assert_eq!((out.ctime_, out.ctime_nsec), (333, 3));
    }

    /// The padding is zero. It is two fields the guest does not read, and
    /// leaving the caller's stack in them is a disclosure of whatever was
    /// there.
    #[test]
    fn the_padding_is_cleared() {
        let out = to_guest_stat(&sample());
        assert_eq!(out.__pad1, 0);
        assert_eq!(out.__pad2, 0);
        assert_eq!(out.__unused4, 0);
        assert_eq!(out.__unused5, 0);
    }

    /// A device number is split the guest's way, which is not the host's:
    /// `mmmMMMmm` in hex. Getting it wrong opens the wrong device node.
    #[test]
    fn the_device_split_is_the_guests() {
        let info = info_of(&sample());
        assert_eq!((info.dev_major, info.dev_minor), (5, 1));
        assert_eq!((info.rdev_major, info.rdev_minor), (1, 2));
    }

    /// What is not known stays unknown. `statx`'s mask is the promise that a
    /// field was filled, and answering the epoch for a creation time nothing
    /// records is a lie a caller cannot detect.
    #[test]
    fn a_creation_time_nobody_has_is_not_reported() {
        let info = info_of(&sample());
        assert!(info.btime.is_none());
        assert!(info.mnt_id.is_none(), "zero is no mount, not mount zero");
        let on_a_mount = ffi::statbuf {
            mount_id: 7,
            ..sample()
        };
        assert_eq!(info_of(&on_a_mount).mnt_id, Some(7));
    }
}
