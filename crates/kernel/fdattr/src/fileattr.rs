//! `file_getattr(2)` and `file_setattr(2)`, Linux 6.17: `FS_IOC_FSGETXATTR`
//! and `FS_IOC_FSSETXATTR` by path, with a `struct file_attr` passed with its
//! size.
//!
//! # Every mount here answers EOPNOTSUPP
//!
//! The attributes are inode flags -- immutable, append-only, no-dump, project
//! ids -- and **no filesystem in this tree stores any**: realfs and fakefs
//! would have to map them onto the host's `chflags` and enforce them on every
//! write, tmpfs would have to keep and enforce them itself. Linux answers
//! EOPNOTSUPP for a filesystem with no `fileattr_get` (procfs, a pipe), and
//! that is the answer here, after the arguments and the path have been judged
//! exactly as Linux judges them -- measured by `fsat_probe` against a 7.2
//! kernel, where procfs answers the same. A caller that wanted the flags
//! learns they are not there; one that would set them is refused rather than
//! told an immutable file was made.

use super::*;

use std::ffi::{CStr, CString};

use crate::xattr::read_path;

use usercopy::GuestMem;

/// `FILE_ATTR_SIZE_VER0`: `{ u64 fa_xflags; u32 fa_extsize; u32 fa_nextents;
/// u32 fa_projid; u32 fa_cowextsize; }`.
const FILE_ATTR_SIZE_VER0: usize = 24;

/// The `fa_xflags` bits a set may carry. Measured bit by bit on 7.2: bits 0,
/// 1, 3 to 19 and 31 (`FS_XFLAG_HASATTR`) reach the filesystem; bit 2 and
/// everything else is `EINVAL` before the path is looked at.
const FS_XFLAGS_MASK: u64 = 0x800f_fffb;

/// Linux's order for both: the flag word, the size, then the path.
fn sizes(usize: u64, at_flags: c_int) -> Result<(), Errno> {
    if at_flags & !(ffi::AT_SYMLINK_NOFOLLOW_ | ffi::AT_EMPTY_PATH_) as c_int != 0 {
        return Err(Errno::EINVAL);
    }
    if usize > ffi::PAGE_SIZE as u64 {
        return Err(Errno::E2BIG);
    }
    if (usize as usize) < FILE_ATTR_SIZE_VER0 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Find what the call names, and say what its filesystem can do with it.
///
/// An empty or NULL path under `AT_EMPTY_PATH` is the descriptor's file --
/// `O_PATH` refused, as `fdget` refuses it -- or, for `AT_FDCWD`, the working
/// directory. Otherwise the path is resolved and has to exist.
fn target(at: c_int, path_addr: u64, at_flags: c_int) -> Result<(), Errno> {
    let empty_allowed = at_flags & ffi::AT_EMPTY_PATH_ as c_int != 0;
    let path = if empty_allowed && path_addr == 0 {
        CString::default()
    } else {
        read_path(path_addr)?
    };
    if empty_allowed && path.is_empty() && at >= 0 {
        let fd = Fd::get(at)?;
        if fd.is_path_only() {
            return Err(Errno::EBADF);
        }
        return Err(Errno::EOPNOTSUPP);
    }
    let path: &CStr = if path.is_empty() && empty_allowed { c"." } else { &path };
    let base = fs_fdobj::at_fd(at, path).ok_or(Errno::EBADF)?;
    let follow = at_flags & ffi::AT_SYMLINK_NOFOLLOW_ as c_int == 0;
    let mut st = ffi::statbuf::default();
    done(fs_generic::generic_statat(base.at(), path, &mut st, follow))?;
    // The file is there; no mount here keeps inode flags. See the module
    // comment.
    Err(Errno::EOPNOTSUPP)
}

pub fn sys_file_getattr(at: c_int, path: u64, attr: u64, usize: u64, at_flags: c_int) -> Result<(), Errno> {
    strace!("file_getattr({at}, {path:#x}, {attr:#x}, {usize}, {at_flags:#x})");
    sizes(usize, at_flags)?;
    target(at, path, at_flags)
}

pub fn sys_file_setattr(at: c_int, path: u64, attr: u64, usize: u64, at_flags: c_int) -> Result<(), Errno> {
    strace!("file_setattr({at}, {path:#x}, {attr:#x}, {usize}, {at_flags:#x})");
    sizes(usize, at_flags)?;
    // The struct is read and judged before the path: a bad buffer is EFAULT
    // and an undefined flag EINVAL whatever the file.
    let mut raw = [0u8; FILE_ATTR_SIZE_VER0];
    usercopy::read_extensible(&GuestMem, attr, usize as usize, &mut raw)?;
    let xflags = u64::from_le_bytes(raw[0..8].try_into().expect("eight bytes"));
    if xflags & !FS_XFLAGS_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    target(at, path, at_flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_word_is_judged_before_the_size() {
        assert_eq!(sizes(4097, 0x200), Err(Errno::EINVAL));
        assert_eq!(sizes(4097, 0), Err(Errno::E2BIG));
        assert_eq!(sizes(23, 0), Err(Errno::EINVAL));
        assert_eq!(sizes(24, ffi::AT_EMPTY_PATH_ as c_int), Ok(()));
        assert_eq!(sizes(4096, ffi::AT_SYMLINK_NOFOLLOW_ as c_int), Ok(()));
    }

    #[test]
    fn the_xflag_mask_is_the_measured_one() {
        for bit in (0..=1).chain(3..=19).chain([31]) {
            assert_ne!(FS_XFLAGS_MASK & (1 << bit), 0, "bit {bit}");
        }
        for bit in [2, 20, 30, 32, 63] {
            assert_eq!(FS_XFLAGS_MASK & (1 << bit), 0, "bit {bit}");
        }
    }
}
