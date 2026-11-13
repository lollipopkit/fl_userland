//! The one syscall that reads the kernel log.
//!
//! `syslog(2)` is eleven commands over one ring buffer, and what a caller can
//! observe about most of them is **their argument handling**: five of the eleven
//! do nothing at all here — this kernel has no console log level and no
//! open/close state — so all that is left of them is which arguments they
//! accept. Answering success for a value Linux refuses tells a program probing
//! its own arguments that nothing is wrong with a number that means nothing,
//! which is the same shape as `fadvise64` in `crates/kernel/fdattr`.
//!
//! Three rules were missing, and one of them lost the answer entirely:
//!
//! - **`SYSLOG_ACTION_READ_CLEAR` returned 0.** It read into the caller's buffer
//!   and then fell through to the clear arm, whose `return 0` it inherited — so
//!   `dmesg -c` was told nothing had been read while the log was consumed
//!   underneath it. Linux returns the byte count.
//! - **`SYSLOG_ACTION_CONSOLE_LEVEL` accepted any level.** Linux takes 1 to 8
//!   and answers `EINVAL` otherwise. Nothing here has a console level, so the
//!   number is discarded either way; what differs is that a caller asking for
//!   level 99 used to be told it got it.
//! - **A null destination was not refused.** Linux answers `EINVAL` for a read
//!   command with a null buffer, before it looks at the address at all. Here it
//!   reached the copy, which answered `EFAULT` when the log had bytes and 0 when
//!   it did not — so the same call had two different wrong answers depending on
//!   how much the emulator had printed.
//!
//! # This log's own arrangement, which is not Linux's
//!
//! Linux keeps a per-reader sequence number; this keeps one consuming cursor.
//! `READ` takes from the front and consumes, `READ_ALL` peeks the tail, and
//! `CLEAR` moves the boundary that bounds the tail rather than draining the
//! ring. That is deliberate — the ring is also where the emulator's own
//! diagnostics go, and a guest clearing the log should not delete them from
//! under `-Dlog=verbose`. It is written down here because the numbers
//! `SIZE_UNREAD` reports follow from it.
//!
//! # Locking
//!
//! The ring and the clear boundary are one `Mutex` in `crates/util/logline`'s
//! `klog` since 2026-09-29, when the ring moved there from this crate; the C
//! had a `log_lock` covering both plus the host-side output. `kernel/log.c` still
//! holds that lock across a line — it is what stops two threads interleaving
//! `fprintf`s — and calls in for the append, so the order is `log_lock` then
//! this one and `sys_syslog` takes only this one. `tools/lock-order.py` reads
//! only C and cannot see that, which is why it is here.

use guest_errno::Errno;
use logline::klog;
use strace::strace;
use usercopy::GuestMem;

// ---- the commands ------------------------------------------------------

/// What a guest may ask of the log. The numbers are Linux's and are ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// 0 and 1. No open/close state here, so both succeed and do nothing.
    Close,
    Open,
    /// 2: take from the front, consuming.
    Read,
    /// 3: the last `len` bytes, left in place.
    ReadAll,
    /// 4: [`Action::ReadAll`], and then [`Action::Clear`].
    ReadClear,
    /// 5.
    Clear,
    /// 6, 7 and 8. No console log level here.
    ConsoleOff,
    ConsoleOn,
    ConsoleLevel,
    /// 9 and 10.
    SizeUnread,
    SizeBuffer,
}

impl Action {
    pub fn from_number(n: i32) -> Option<Action> {
        Some(match n {
            0 => Action::Close,
            1 => Action::Open,
            2 => Action::Read,
            3 => Action::ReadAll,
            4 => Action::ReadClear,
            5 => Action::Clear,
            6 => Action::ConsoleOff,
            7 => Action::ConsoleOn,
            8 => Action::ConsoleLevel,
            9 => Action::SizeUnread,
            10 => Action::SizeBuffer,
            _ => return None,
        })
    }

    /// Whether this command copies into the caller's buffer, which is what
    /// decides whether `buf` and `len` are looked at at all.
    pub fn copies_out(self) -> bool {
        matches!(self, Action::Read | Action::ReadAll | Action::ReadClear)
    }
}

/// What Linux checks before running the command, given the arguments as they
/// arrived.
///
/// `buf` is the guest address and is compared against zero rather than
/// dereferenced: Linux's check is `if (!buf || len < 0) return -EINVAL`, which
/// happens before any access check, so a null buffer is `EINVAL` and an
/// unmapped one is `EFAULT`.
pub(crate) fn check_args(action: Action, buf: u64, len: i32) -> Result<(), Errno> {
    if action.copies_out() && (buf == 0 || len < 0) {
        return Err(Errno::EINVAL);
    }
    // The level is carried in `len`, and 1 to 8 is the whole range. Nothing
    // here stores it; refusing the ones Linux refuses is the only part of this
    // command a caller can see.
    if action == Action::ConsoleLevel && !(1..=8).contains(&len) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

// ---- the syscall -------------------------------------------------------

fn read_out(
    mem: &GuestMem,
    buf_addr: u64,
    len: i32,
    tail: bool,
    peek: bool,
    clear: bool,
) -> Result<i32, Errno> {
    let out = klog::take(len, tail, peek, clear);
    if out.is_empty() {
        return Ok(0);
    }
    if mem.write(buf_addr, &out) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(out.len() as i32)
}

fn do_syslog(mem: &GuestMem, action: Action, buf_addr: u64, len: i32) -> Result<i32, Errno> {
    match action {
        Action::Read => read_out(mem, buf_addr, len, false, false, false),
        Action::ReadAll => read_out(mem, buf_addr, len, true, true, false),
        // The count is the answer. Falling through to the clear arm's
        // `return 0` is what made `dmesg -c` print nothing.
        Action::ReadClear => read_out(mem, buf_addr, len, true, true, true),
        Action::Clear => {
            klog::clear();
            Ok(0)
        }
        Action::SizeUnread => Ok(klog::len() as i32),
        Action::SizeBuffer => Ok(klog::capacity() as i32),
        Action::Close
        | Action::Open
        | Action::ConsoleOff
        | Action::ConsoleOn
        | Action::ConsoleLevel => Ok(0),
    }
}

pub fn sys_syslog(type_: i32, buf_addr: u64, len: i32) -> Result<i32, Errno> {
    strace!("syslog({type_}, {buf_addr:#x}, {len})");
    let Some(action) = Action::from_number(type_) else {
        return Err(Errno::EINVAL);
    };
    // `check_syslog_permissions`, before the arguments: every action is
    // CAP_SYSLOG's under `dmesg_restrict`, which the reference kernel sets and
    // this one has no switch for.
    // Measured: CAP_SYS_ADMIN alone is refused.
    if !taskview::capable(taskview::caps::CAP_SYSLOG) {
        return Err(Errno::EPERM);
    }
    check_args(action, buf_addr, len)?;
    do_syslog(&GuestMem::current(), action, buf_addr, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_eleven_commands_and_nothing_else() {
        for n in 0..=10 {
            assert!(Action::from_number(n).is_some(), "command {n}");
        }
        for n in [-1, 11, 12, 99, i32::MIN, i32::MAX] {
            assert!(Action::from_number(n).is_none(), "command {n}");
        }
    }

    /// A null destination is refused before the address is looked at.
    ///
    /// It used to reach the copy, where the answer depended on how much the
    /// emulator had printed: `EFAULT` once there was something to copy, and 0
    /// while the log was empty.
    #[test]
    fn a_read_with_no_buffer_is_einval() {
        for a in [Action::Read, Action::ReadAll, Action::ReadClear] {
            assert_eq!(check_args(a, 0, 64), Err(Errno::EINVAL), "{a:?}");
            assert_eq!(check_args(a, 0x1000, 64), Ok(()), "{a:?}");
        }
        // The commands that copy nothing do not look at either argument.
        for a in [Action::Clear, Action::SizeUnread, Action::SizeBuffer] {
            assert_eq!(check_args(a, 0, -1), Ok(()), "{a:?}");
        }
    }

    #[test]
    fn a_negative_length_is_einval_for_the_reads_only() {
        assert_eq!(check_args(Action::Read, 0x1000, -1), Err(Errno::EINVAL));
        assert_eq!(check_args(Action::SizeUnread, 0x1000, -1), Ok(()));
    }

    /// The console level is 1 to 8. Nothing here stores it, so this rule is the
    /// entire observable content of the command.
    #[test]
    fn the_console_level_has_a_range() {
        for len in 1..=8 {
            assert_eq!(check_args(Action::ConsoleLevel, 0, len), Ok(()), "{len}");
        }
        for len in [i32::MIN, -1, 0, 9, 99] {
            assert_eq!(
                check_args(Action::ConsoleLevel, 0, len),
                Err(Errno::EINVAL),
                "{len}"
            );
        }
        // ...and it is this command alone: the neighbouring no-ops take any
        // length, which is what made the missing check easy to write.
        assert_eq!(check_args(Action::ConsoleOn, 0, 99), Ok(()));
        assert_eq!(check_args(Action::ConsoleOff, 0, 99), Ok(()));
    }
}
