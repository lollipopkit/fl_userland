//! Descriptor advice syscalls: validate the hint and descriptor shape.

use std::ffi::{c_int, c_uint};

use strace::strace;

use guest_errno::Errno;

use crate::{Fd, S_IFBLK, S_IFIFO, S_IFMT, S_IFREG, ffi};

// The six advice values Linux knows. The numbering after RANDOM is
// architecture-dependent; aarch64 uses the generic one, where NOREUSE is 5.
const POSIX_FADV_MAX: c_uint = 5;

/// `posix_fadvise64` (223).
///
/// The hints are advisory and this does no caching of its own, so acting on
/// them is a no-op — but *accepting* them is not. An advice value Linux does
/// not know is `EINVAL` from `generic_fadvise`, and a FIFO is `ESPIPE`; this
/// answered success for both, so a caller probing which hints it may use was
/// told all of them and a caller checking its own argument handling found
/// nothing wrong with a number that means nothing.
pub fn sys_fadvise64(num: c_int, offset: u64, len: u64, advice: c_uint) -> Result<(), Errno> {
    strace!("fadvise64({num}, {offset}, {len}, {advice})");
    if advice > POSIX_FADV_MAX {
        return Err(Errno::EINVAL);
    }
    // Both arguments are `loff_t`, and a negative one is EINVAL. A negative
    // offset was accepted through Linux 7.0 and is refused on 7.2.9, measured
    // by `tests/guest/src/bin/atcall_probe.rs` -- which also says a length of
    // LLONG_MAX and a sum that overflows are both accepted. Zero means "to the
    // end of the file".
    if (len as i64) < 0 || (offset as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    let fd = Fd::get(num)?;
    if fd.kind() & S_IFMT == S_IFIFO {
        return Err(Errno::ESPIPE);
    }
    Ok(())
}

/// `readahead` (213).
///
/// Advisory too, and it was a stub — so glibc's `readahead()` answered `ENOSYS`
/// where Linux answers 0, and a caller that checks the return (as a copy loop
/// priming its source does) treated a working file as a broken one.
///
/// Doing the work is not required and not possible on every mount; what is
/// required is Linux's argument handling. `ksys_readahead` refuses a descriptor
/// that is not open for reading with `EBADF`, and one that is not a regular file
/// or a block device with `EINVAL`, before it does anything at all.
///
/// `count` is a `size_t` on Linux, so 64 bits here: `tools/syscall-abi.py`
/// caught this as a `dword_t`, which would have dropped the top half of a guest
/// argument the first time anything asked to prime more than four gigabytes.
pub fn sys_readahead(num: c_int, offset: i64, count: u64) -> Result<(), Errno> {
    strace!("readahead({num}, {offset}, {count})");
    let fd = Fd::get(num)?;
    if fd.flags() & ffi::O_ACCMODE_ == ffi::O_WRONLY_ {
        return Err(Errno::EBADF);
    }
    let ty = fd.kind() & S_IFMT;
    if ty != S_IFREG && ty != S_IFBLK {
        return Err(Errno::EINVAL);
    }
    Ok(())
}
