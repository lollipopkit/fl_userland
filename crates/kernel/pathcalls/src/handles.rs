//! `name_to_handle_at(2)` and `open_by_handle_at(2)`.
//!
//! # No filesystem here exports, so a handle identifies and nothing decodes
//!
//! A decodable handle is a filesystem's promise that it can find an inode
//! again from a few bytes, after a rename and across a reboot -- Linux's
//! `export_operations`, which NFS serving needs. None of the mounts here can
//! keep it: realfs would need the host's inode-to-path lookup, which a sandboxed
//! iOS process does not have, and tmpfs and procfs never had one on Linux
//! either. So every mount is what Linux calls a filesystem with no export
//! operations, and answers as one:
//!
//! - `name_to_handle_at` without `AT_HANDLE_FID` is EOPNOTSUPP -- the answer
//!   systemd and `findmnt` fall back from;
//! - with `AT_HANDLE_FID`, which asks for a handle only to *compare* (fanotify,
//!   systemd's "same inode?" test), it is Linux's generic one:
//!   `FILEID_INO64_GEN`, the inode number and a generation of 0;
//! - `open_by_handle_at` judges its arguments and the caller as Linux does and
//!   then answers ESTALE, which is what a handle no filesystem can decode is.
//!
//! Measured with `tests/guest/src/bin/fsat_probe.rs` against procfs on a 7.2
//! kernel, which has no export operations either.

use super::*;

/// The largest `handle_bytes` either call accepts.
const MAX_HANDLE_SZ: u32 = 128;
/// `struct file_handle`'s fixed part: `u32 handle_bytes; i32 handle_type;`.
const HEADER: usize = 8;
use ffi::FILEID_INO64_GEN;
const FID_BYTES: u32 = 12;
/// What a handle that did not fit reports as its type.
const FILEID_INVALID: i32 = 0xff;
/// The two handle-type bits `open_by_handle_at` lets a caller set.
const FILEID_VALID_USER_FLAGS: i32 = 0x3_0000;

const AT_HANDLE_MNT_ID_UNIQUE: c_int = 0x001;
const AT_HANDLE_CONNECTABLE: c_int = 0x002;
const AT_HANDLE_FID: c_int = 0x200;
const AT_SYMLINK_FOLLOW: c_int = 0x400;

pub fn sys_name_to_handle_at(
    at_f: c_int,
    path_addr: u64,
    handle_addr: u64,
    mnt_id_addr: u64,
    flags: c_int,
) -> Result<(), Errno> {
    strace!("name_to_handle_at({at_f}, {path_addr:#x}, {handle_addr:#x}, {mnt_id_addr:#x}, {flags:#x})");
    let known = AT_SYMLINK_FOLLOW
        | ffi::AT_EMPTY_PATH_ as c_int
        | AT_HANDLE_FID
        | AT_HANDLE_MNT_ID_UNIQUE
        | AT_HANDLE_CONNECTABLE;
    if flags & !known != 0 {
        return Err(Errno::EINVAL);
    }
    // A connectable handle is one to decode with its path, which a FID is
    // not for and an empty path cannot give.
    if flags & AT_HANDLE_CONNECTABLE != 0 && flags & (AT_HANDLE_FID | ffi::AT_EMPTY_PATH_ as c_int) != 0 {
        return Err(Errno::EINVAL);
    }

    // The lookup, by the rules of every `*at` call: `AT_SYMLINK_FOLLOW` here
    // because a handle names the link unless told otherwise.
    let path = Path::read(path_addr)?;
    let follow = flags & AT_SYMLINK_FOLLOW != 0;
    let st = if flags & ffi::AT_EMPTY_PATH_ as c_int != 0 && path.0[0] == 0 {
        match Itself::of(at_f)? {
            Itself::Named(at) => stat_at(at.at(), c".", follow)?,
            Itself::Nameless(fd) => fs_fdobj::fd_fstat(&fd).map_err(Errno::from_negative_or_eio)?,
        }
    } else {
        let at = at_of(at_f, &path)?;
        stat_at(at.at(), path.as_cstr(), follow)?
    };

    // Only an identifying handle can be made; see the module comment.
    if flags & AT_HANDLE_FID == 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let mut asked = [0u8; 4];
    if GuestMem.read(handle_addr, &mut asked) != 0 {
        return Err(Errno::EFAULT);
    }
    let asked = u32::from_le_bytes(asked);
    if asked > MAX_HANDLE_SZ {
        return Err(Errno::EINVAL);
    }
    // Rounded down to whole words, as Linux counts them.
    let fits = asked / 4 * 4 >= FID_BYTES;
    let mut out = Vec::with_capacity(HEADER + FID_BYTES as usize);
    out.extend_from_slice(&FID_BYTES.to_le_bytes());
    out.extend_from_slice(&(if fits { FILEID_INO64_GEN } else { FILEID_INVALID }).to_le_bytes());
    if fits {
        out.extend_from_slice(&ffi::fid_ino64_gen(st.inode));
    }

    // The mount id first and the handle after, as Linux writes them.
    let written = if flags & AT_HANDLE_MNT_ID_UNIQUE != 0 {
        GuestMem.write_u64(mnt_id_addr, ffi::unique_mount_id(st.mount_id))
    } else {
        GuestMem.write(mnt_id_addr, &(st.mount_id as i32).to_le_bytes())
    };
    if written != 0 || GuestMem.write(handle_addr, &out) != 0 {
        return Err(Errno::EFAULT);
    }
    if fits { Ok(()) } else { Err(Errno::EOVERFLOW) }
}

fn stat_at(at: ffi::At<'_>, path: &std::ffi::CStr, follow: bool) -> Result<ffi::statbuf, Errno> {
    let mut st = ffi::statbuf::default();
    done(fs_generic::generic_statat(at, path, &mut st, follow))?;
    Ok(st)
}

pub fn sys_open_by_handle_at(mount_fd: c_int, handle_addr: u64, flags: c_int) -> Result<i64, Errno> {
    strace!("open_by_handle_at({mount_fd}, {handle_addr:#x}, {flags:#x})");
    // The anchor, then who may ask, then the handle -- Linux's order. A
    // handle bypasses every directory permission on the way to the file,
    // which is why it is `CAP_DAC_READ_SEARCH`'s.
    if mount_fd != ffi::AT_FDCWD_ {
        fs_fdobj::f_get(mount_fd).ok_or(Errno::EBADF)?;
    }
    if !taskview::capable(taskview::caps::CAP_DAC_READ_SEARCH) {
        return Err(Errno::EPERM);
    }
    let mut header = [0u8; HEADER];
    if GuestMem.read(handle_addr, &mut header) != 0 {
        return Err(Errno::EFAULT);
    }
    let bytes = u32::from_le_bytes(header[0..4].try_into().expect("four bytes"));
    let kind = i32::from_le_bytes(header[4..8].try_into().expect("four bytes"));
    if bytes == 0 || bytes > MAX_HANDLE_SZ {
        return Err(Errno::EINVAL);
    }
    if kind < 0 || kind & !0xffff & !FILEID_VALID_USER_FLAGS != 0 {
        return Err(Errno::EINVAL);
    }
    let mut body = vec![0u8; bytes as usize];
    if GuestMem.read(handle_addr + HEADER as u64, &mut body) != 0 {
        return Err(Errno::EFAULT);
    }
    // Nothing here can find an inode from a handle.
    Err(Errno::ESTALE)
}
