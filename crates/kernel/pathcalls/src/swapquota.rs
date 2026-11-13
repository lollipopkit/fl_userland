//! `swapon`, `swapoff`, `quotactl` and `quotactl_fd`, answered as a Linux
//! kernel answers them when there is no swap area, no block device backs a
//! mount, and no filesystem has quota support -- which is this kernel's
//! situation, not a pretence of it.
//!
//! Each is the real call's checks in the real call's order, up to the point
//! where Linux would look for a swap header, a superblock on a block device or
//! a filesystem's quota operations; every answer past that point is fixed:
//!
//! - `swapon` resolves the file as its `O_RDWR` open would and then finds no
//!   swap signature and no filesystem that can host a swap file: `EINVAL`. Linux answers the same
//!   for a file whose filesystem cannot map its blocks.
//! - `swapoff` resolves the file the same way and then finds it is not an active swap area:
//!   `EINVAL`, as on any Linux machine for a file that is not one.
//! - `quotactl` resolves `special` as a block device: `ENOTBLK` for anything
//!   else, `ENODEV` for a block device nothing is mounted from. `Q_SYNC` with
//!   no device syncs every filesystem with quota on, which is none: 0.
//! - `quotactl_fd` reaches the filesystem's quota operations and there are
//!   none: `ENOSYS`, which is what Linux's `do_quotactl` answers for a
//!   filesystem without `s_qcop` (tmpfs without `quota`, overlayfs, procfs).
//!
//! Measured by `rarecalls_probe` on a 7.2 arm64 kernel, as root in a
//! privileged container. Two rules are not modelled: `quotactl` on a `nodev`
//! mount is `EACCES` before the type check, and a writing `quotactl_fd`
//! command on a read-only mount is `EROFS` before `ENOSYS`; this kernel does
//! not enforce either mount flag anywhere else.

use super::*;

/// `SWAP_FLAG_PRIO_MASK | SWAP_FLAG_PREFER | SWAP_FLAG_DISCARD |
/// SWAP_FLAG_DISCARD_ONCE | SWAP_FLAG_DISCARD_PAGES`.
const SWAP_FLAGS_VALID: c_uint = 0x7ffff;

/// The errors `swapon` and `swapoff` get from `file_open_name(O_RDWR)`, read
/// off the file rather than by opening it: `ENOENT`, `ENOTDIR` and `ELOOP` from
/// the walk, `EISDIR` for a directory, `ENXIO` for a socket.
///
/// A stat and not an open, for two reasons. Realfs opens the host file, so
/// `O_RDWR` on a mode 0400 file was the host's `EACCES` where root's
/// `CAP_DAC_OVERRIDE` opens it on Linux (`rarecalls_probe`); and an open has
/// effects -- a terminal opened without `O_NOCTTY` becomes the caller's -- that
/// an answer which is `EINVAL` either way must not have. `ETXTBSY` for a file
/// being executed is the one open error this does not reproduce.
fn swap_target(path_addr: u64) -> Result<(), Errno> {
    let path = Path::read(path_addr)?;
    strace!(" {:?}", path.as_str());
    if path.0[0] == 0 {
        return Err(Errno::ENOENT);
    }
    let mut st = ffi::statbuf::default();
    done(fs_generic::generic_statat(ffi::At::Pwd, path.as_cstr(), &mut st, true))?;
    match st.mode & ffi::S_IFMT {
        ffi::S_IFDIR => Err(Errno::EISDIR),
        ffi::S_IFSOCK => Err(Errno::ENXIO),
        _ => Ok(()),
    }
}

pub fn sys_swapon(path_addr: u64, flags: c_uint) -> Result<(), Errno> {
    strace!("swapon({path_addr:#x}, {flags:#x})");
    if flags & !SWAP_FLAGS_VALID != 0 {
        return Err(Errno::EINVAL);
    }
    if !taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    swap_target(path_addr)?;
    Err(Errno::EINVAL)
}

pub fn sys_swapoff(path_addr: u64) -> Result<(), Errno> {
    strace!("swapoff({path_addr:#x})");
    if !taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    swap_target(path_addr)?;
    Err(Errno::EINVAL)
}

/// `MAXQUOTAS`: user, group and project.
const MAXQUOTAS: c_uint = 3;
const Q_SYNC: c_uint = 0x800001;

/// The quota type in the low byte, or `EINVAL` for one Linux does not have.
fn quota_type(cmd: c_uint) -> Result<(), Errno> {
    if cmd & 0xff >= MAXQUOTAS { Err(Errno::EINVAL) } else { Ok(()) }
}

pub fn sys_quotactl(cmd: c_uint, special_addr: u64, id: c_uint, addr: u64) -> Result<(), Errno> {
    strace!("quotactl({cmd:#x}, {special_addr:#x}, {id}, {addr:#x})");
    quota_type(cmd)?;
    if special_addr == 0 {
        return if cmd >> 8 == Q_SYNC { Ok(()) } else { Err(Errno::ENODEV) };
    }
    // `lookup_bdev`: the name, followed, and then whether it is a block
    // device at all.
    let path = Path::read(special_addr)?;
    strace!(" {:?}", path.as_str());
    if path.0[0] == 0 {
        return Err(Errno::ENOENT);
    }
    let mut st = ffi::statbuf::default();
    done(fs_generic::generic_statat(ffi::At::Pwd, path.as_cstr(), &mut st, true))?;
    if st.mode & ffi::S_IFMT != ffi::S_IFBLK {
        return Err(Errno::ENOTBLK);
    }
    Err(Errno::ENODEV)
}

/// `fd_raw`: an `O_PATH` descriptor names a mount as well as any other, so it
/// is accepted, as Linux accepts it.
pub fn sys_quotactl_fd(fd: c_int, cmd: c_uint, id: c_uint, addr: u64) -> Result<(), Errno> {
    strace!("quotactl_fd({fd}, {cmd:#x}, {id}, {addr:#x})");
    fs_fdobj::f_get(fd).ok_or(Errno::EBADF)?;
    quota_type(cmd)?;
    Err(Errno::ENOSYS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The five flags `swapon` knows end at bit 18, and the probe's
    /// `0x100000` is the first refused.
    #[test]
    fn swap_flags_are_linuxs() {
        let (prio_mask, prefer, discard, once, pages) = (0x7fff, 0x8000, 0x10000, 0x20000, 0x40000);
        assert_eq!(SWAP_FLAGS_VALID, prio_mask | prefer | discard | once | pages);
        assert_ne!(0x100000 & !SWAP_FLAGS_VALID, 0);
    }

    #[test]
    fn the_quota_type_is_the_low_byte() {
        let qcmd = |c: c_uint, t: c_uint| (c << 8) | t;
        assert!(quota_type(qcmd(Q_SYNC, 0)).is_ok());
        assert!(quota_type(qcmd(Q_SYNC, 2)).is_ok());
        assert_eq!(quota_type(qcmd(Q_SYNC, 3)), Err(Errno::EINVAL));
        assert_eq!(quota_type(0xff), Err(Errno::EINVAL));
    }
}
