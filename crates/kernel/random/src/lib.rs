//! `getrandom(2)`, and the host randomness behind it.
//!
//! Two rules and a loop. The rules are where the defects were, and both are
//! about a guest asking for something and being told the wrong thing:
//!
//! - **A flag outside the known set has to be refused.** `GRND_RANDOM` once
//!   selected a different pool and no longer does, and `GRND_INSECURE` asks for
//!   bytes before the pool is seeded; neither changes what a correct answer
//!   looks like here, where the host supplies the randomness and is always
//!   ready. But an *unknown* flag is a guest asking for something this does not
//!   do, and answering success tells it that it got it.
//! - **A large request is a short read, not an error.** Linux answers at most
//!   32 MB and reports the count, and every libc loops on that. This answered
//!   `EIO` past one megabyte, so a program asking for two megabytes of
//!   randomness in one call simply failed.
//!
//! The loop is a fixed 64 KB buffer rather than an allocation the size of the
//! request: the length is the guest's to choose and has no business becoming an
//! allocation here.
//!
//! # A partial answer is an answer
//!
//! Once any bytes have reached the guest, the call returns how many rather than
//! an error — the caller has been given randomness and must not be told it has
//! not. Only a failure on the *first* chunk is `EIO` or `EFAULT`.


use std::ffi::c_int;

use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

/// Ask for bytes now rather than waiting for the pool to be seeded.
pub const GRND_NONBLOCK: u32 = 0x0001;
/// Once selected a different pool; no longer does.
pub const GRND_RANDOM: u32 = 0x0002;
/// Take whatever the pool has, seeded or not.
pub const GRND_INSECURE: u32 = 0x0004;
/// The three Linux defines.
pub const GRND_KNOWN: u32 = GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE;

/// What one call may deliver, as Linux's `getrandom` does.
pub const GETRANDOM_MAX: u32 = 32 * 1024 * 1024;

/// Filled and copied out a piece at a time.
const CHUNK: usize = 64 * 1024;

/// Fill `buf` with host randomness.
///
/// Apple's `arc4random_buf` is the system CSPRNG and cannot fail, which is what
/// `CCRandomGenerateBytes` was reached for before — one fewer library, and the
/// same source of bytes. So there is no error to answer: it answered a C-style
/// 0 that every caller tested until 2026-10-17, and `crates/fs/proc`'s boot id
/// called `arc4random_buf` itself.
pub fn fill(buf: &mut [u8]) {
    // SAFETY: `buf` is `buf.len()` writable bytes.
    unsafe { libc::arc4random_buf(buf.as_mut_ptr().cast(), buf.len()) };
}

/// What `len` a request of this size actually delivers.
///
/// Clamped rather than refused. The caller asks again for the rest, which is
/// what every libc does with Linux's answer.
pub fn deliverable(len: u32) -> u32 {
    len.min(GETRANDOM_MAX)
}

/// Are these flags ones Linux accepts?
///
/// Two rules, and the second is not "are these bits defined": `GRND_INSECURE`
/// asks for whatever the pool has and `GRND_RANDOM` asks for the pool that
/// blocks, so **together they are `EINVAL`** — Linux's `random.c` refuses that
/// pair before anything else. Asked of a real arm64 kernel, `0x6` and `0x7` are
/// `EINVAL` and the other six combinations succeed.
///
/// Neither flag changes what a correct answer looks like here, where the host
/// supplies the randomness and is always ready. What a caller can see is which
/// requests are refused, and a request for two contradictory things is one of
/// them.
pub fn flags_valid(flags: u32) -> bool {
    if flags & !GRND_KNOWN != 0 {
        return false;
    }
    flags & (GRND_INSECURE | GRND_RANDOM) != (GRND_INSECURE | GRND_RANDOM)
}

pub fn sys_getrandom(buf_addr: u64, len: u32, flags: u32) -> Result<c_int, Errno> {
    strace!("getrandom({buf_addr:#x}, {len}, {flags:#x})");
    if !flags_valid(flags) {
        return Err(Errno::EINVAL);
    }
    let len = deliverable(len) as usize;
    if len == 0 {
        return Ok(0);
    }

    let mut chunk = [0u8; CHUNK];
    let mem = GuestMem::current();
    let mut done = 0usize;
    while done < len {
        let n = (len - done).min(CHUNK);
        let piece = &mut chunk[..n];
        fill(piece);
        if mem.write(buf_addr + done as u64, piece) != 0 {
            return partial(done, Errno::EFAULT);
        }
        done += n;
    }
    Ok(done as c_int)
}

/// What to answer once `done` bytes are already in the caller's buffer: the
/// count, because those bytes are there and a short read is a valid answer --
/// and the errno only when nothing has been delivered at all.
fn partial(done: usize, e: Errno) -> Result<c_int, Errno> {
    if done > 0 { Ok(done as c_int) } else { Err(e) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three Linux defines, and nothing else. An unknown flag is a guest
    /// asking for behaviour this does not have.
    ///
    /// Every one of the nine cases is what an arm64 kernel answered, not what
    /// the man page says: `getrandom(2)` describes the three flags and is
    /// silent about the pair that cannot be asked for together.
    #[test]
    fn only_the_combinations_linux_accepts() {
        for f in [0, 1, 2, 4, 3, 5] {
            assert!(flags_valid(f), "{f:#x}");
        }
        // GRND_INSECURE with GRND_RANDOM: "give me whatever there is" and "give
        // me the pool that blocks" at once.
        for f in [6, 7] {
            assert!(!flags_valid(f), "{f:#x}");
        }
        for f in [8, 16, 0x8000_0000, !0] {
            assert!(!flags_valid(f), "{f:#x}");
        }
    }

    /// A large request is a short read. It used to be `EIO` past one megabyte,
    /// so a program asking for two megabytes in one call simply failed.
    #[test]
    fn a_large_request_is_clamped_rather_than_refused() {
        assert_eq!(deliverable(0), 0);
        assert_eq!(deliverable(64), 64);
        assert_eq!(deliverable(2 * 1024 * 1024), 2 * 1024 * 1024);
        assert_eq!(deliverable(GETRANDOM_MAX), GETRANDOM_MAX);
        assert_eq!(deliverable(GETRANDOM_MAX + 1), GETRANDOM_MAX);
        assert_eq!(deliverable(u32::MAX), GETRANDOM_MAX);
    }

    /// The bytes are actually random, which nothing else here checks: every
    /// rule above is about lengths and flags and would pass against a fill that
    /// wrote zeroes.
    #[test]
    fn the_bytes_are_not_all_the_same() {
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        fill(&mut a);
        fill(&mut b);
        assert_ne!(a, b, "two fills gave the same 256 bytes");
        assert!(a.iter().any(|&x| x != a[0]), "one repeated byte");
    }
}
