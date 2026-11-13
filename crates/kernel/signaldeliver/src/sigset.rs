//! Guest signal set validation and decoding.

use std::ffi::c_int;

use super::{EFAULT, EINVAL};

/// Linux is exact about this one:
///
/// ```c
/// if (sigsetsize != sizeof(sigset_t))
///     return -EINVAL;
/// ```
///
/// This accepted anything that was a multiple of 8 and at least 8, so a guest
/// passing 16, 24 or 128 was told its mask had been set when the kernel had
/// only ever looked at the first eight bytes. Every libc passes 8.
/// **One copy.** `crates/kernel/signalcalls` had a second function of this
/// name, with this doc comment, until 2026-09-15 — same rule, same quoted
/// snippet, same record of the same fixed bug, answering `bool` where this
/// answered `c_int`. They agreed; nothing compared them. The split was by
/// syscall group rather than by meaning: `ppoll`, `pselect6` and
/// `epoll_pwait` reached this one through [`user_get_sigset`], and
/// `rt_sigprocmask`, `rt_sigsuspend` and `rt_sigaction` reached the other.
/// `signalcalls` depends on this crate, so the rule lives here.
pub fn sigset_size_valid(size: u64) -> bool {
    size == 8
}

/// Read a guest signal set into `out`.
pub fn user_get_sigset(addr: u64, size: u64, out: &mut u64) -> c_int {
    if !sigset_size_valid(size) {
        return EINVAL;
    }
    let mut word = [0u8; 8];
    if usercopy::GuestMem.read(addr, &mut word) != 0 {
        return EFAULT;
    }
    *out = u64::from_le_bytes(word);
    0
}
