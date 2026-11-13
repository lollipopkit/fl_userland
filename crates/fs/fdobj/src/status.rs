/// The status flags of a description -- Linux's `f_flags` -- and the two rules
/// over them: what an `open` leaves in them, and what `F_SETFL` may change.
///
/// Both are pure, and both used to be wrong in the same way: the flags were
/// stored as the caller passed them, so `F_GETFL` reported `O_CREAT` and never
/// `O_LARGEFILE`, and `F_SETFL` kept two bits and dropped the rest of what Linux
/// keeps. `fcntl_probe` is the measurement.
use crate::ffi;

use guest_errno::c_int_::EINVAL;

/// The bits `F_SETFL` changes: Linux's `SETFL_MASK`. `O_NDELAY` is
/// `O_NONBLOCK` on aarch64. `O_ASYNC` is not in it, because Linux keeps that
/// one through the `fasync` path and only on a file that has one.
pub const SETFL_MASK: u32 = ffi::O_APPEND_ | ffi::O_NONBLOCK_ | ffi::O_DIRECT_ | ffi::O_NOATIME_;

/// The four an open consumes, from `do_dentry_open`:
///
/// ```c
/// f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
/// ```
///
/// plus `O_CLOEXEC`, which `build_open_flags` strips first because it is a
/// descriptor flag and not a description one.
const CONSUMED: u32 =
    ffi::O_CREAT_ | ffi::O_EXCL_ | ffi::O_NOCTTY_ | ffi::O_TRUNC_ | ffi::O_CLOEXEC_;

/// What an `open(flags)` leaves in `f_flags`.
///
/// Every 64-bit open carries `O_LARGEFILE`, because `force_o_largefile()`
/// is true for a 64-bit task and `openat` ORs it in before anything else
/// looks at the flags. `O_PATH` beats everything: the only other bits such
/// a description keeps are `O_DIRECTORY` and `O_NOFOLLOW`, and it does not
/// get `O_LARGEFILE` because `build_open_how` masks it off again.
pub fn at_open(flags: u32) -> u32 {
    if flags & ffi::O_PATH_ != 0 {
        return flags & (ffi::O_PATH_ | ffi::O_DIRECTORY_ | ffi::O_NOFOLLOW_);
    }
    (flags | ffi::O_LARGEFILE_) & !CONSUMED
}

/// The kinds of description `F_SETFL` tells apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Regular,
    Fifo,
    Socket,
    Other,
}

impl Kind {
    /// From the `S_IFMT` part of a mode. The host's and Linux's `S_IF*`
    /// values are the same numbers.
    pub fn of_mode(mode: u32) -> Kind {
        match mode & libc::S_IFMT as u32 {
            m if m == libc::S_IFREG as u32 => Kind::Regular,
            m if m == libc::S_IFIFO as u32 => Kind::Fifo,
            m if m == libc::S_IFSOCK as u32 => Kind::Socket,
            _ => Kind::Other,
        }
    }
}

/// `F_SETFL(wanted)` on a description of `kind` whose flags are `current`:
/// the flags it will have, or the errno.
///
/// Two rules from `setfl()`, and the shape of a third:
///
/// - `O_DIRECT` may be turned on only where direct I/O exists -- a regular
///   file, whose filesystem here is the host's, and a pipe, where it is
///   packet mode. Anywhere else it is `EINVAL`.
/// - `O_ASYNC` is kept on a description that can raise `SIGIO` -- a socket
///   or a pipe -- and silently dropped on one that cannot, which is what a
///   regular file on Linux does with it: `ext4` has no `fasync`.
/// - `O_NOATIME` needs the file's owner or `CAP_FOWNER`; that check needs
///   the inode and is the caller's, in `crates/kernel/fdcalls`.
///
/// Everything outside `SETFL_MASK` and `O_ASYNC` is ignored: the access mode
/// cannot change after the fact, and neither can `O_SYNC`.
pub fn setfl(kind: Kind, current: u32, wanted: u32) -> Result<u32, i32> {
    if wanted & ffi::O_DIRECT_ != 0
        && current & ffi::O_DIRECT_ == 0
        && !matches!(kind, Kind::Regular | Kind::Fifo)
    {
        return Err(EINVAL);
    }
    let mut new = (current & !(SETFL_MASK | ffi::O_ASYNC_)) | (wanted & SETFL_MASK);
    if matches!(kind, Kind::Socket | Kind::Fifo) {
        new |= wanted & ffi::O_ASYNC_;
    }
    Ok(new)
}
