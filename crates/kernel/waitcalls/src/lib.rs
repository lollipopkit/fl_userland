//! Reaping a child: `waitid`, `wait4` and `waitpid`.
//!
//! The wait *loop* stays in `kernel/exit.c` — it holds `pids_lock` across a
//! condition wait on the group's `child_exit`, walks the child list, and reaps,
//! which is the task lifecycle rather than an ABI. What is here is everything
//! on either side of it: which `idtype` a pid argument means, the status
//! decoding, and the guest copies.
//!
//! # The status word has two shapes
//!
//! `do_wait` hands back the raw `wait(2)` encoding, which is what `wait4`
//! wants. `waitid` wants the *decoded* value in `si_status` and a `si_code`
//! saying which kind of event it was, so [`decode_status`] is the one place
//! that translates — and it is a pure function over one 32-bit word, which is
//! why it can be tested without a child at all.


use std::ffi::{c_int, c_uint};

use strace::strace;
use usercopy::GuestMem;

mod wait;
use wait::do_wait;

use guest_errno::Errno;

// `idtype` values, from the guest's `wait.h`.
const P_ALL: c_int = 0;
const P_PID: c_int = 1;
const P_PGID: c_int = 2;
const P_PIDFD: c_int = 3;

// `options`.
const WNOHANG: c_int = 1;
const WEXITED: c_int = 4;
const WNOWAIT: c_int = 0x0100_0000;

/// The siginfo layout and the status decode, which are
/// `crates/kernel/sigqueue`'s: it owns [`kernel_sigqueue::SigInfo`], and
/// `crates/kernel/exitcalls` needs the decode too and reached it through the C
/// ABI to avoid a cycle. Moved 2026-09-09, and the `keep-c-abi` marker with it.
pub use kernel_sigqueue::childinfo::{SIGINFO_SIZE, decode_status, offset};
use kernel_sigqueue::childinfo::{get_i32, set_i32};

pub fn sys_waitid(
    idtype: c_int,
    id: c_int,
    info_addr: u64,
    options: c_int,
) -> Result<(), Errno> {
    strace!("waitid({idtype}, {id}, {info_addr:#x}, {options:#x})");
    let mut info = kernel_sigqueue::SigInfo::default();
    let res = waitid_wait(idtype, id, &mut info, options);
    // Linux writes the siginfo **whatever the answer was**, and the write
    // happens before the answer is returned: `SYSCALL_DEFINE5(waitid)` takes
    // the error from `kernel_waitid`, then fills the buffer with zeros and only
    // then returns it. So a `waitid` with no children and an unwritable `infop`
    // is `EFAULT` and not `ECHILD` -- which is what this used to answer,
    // because it returned the error without touching the buffer. Found by
    // tests/guest/src/bin/wait_probe.rs against a real kernel.
    //
    // The zeros matter on their own: `si_pid == 0` is how a caller tells "no
    // child was ready" from "a child was reaped" after `WNOHANG`, and the same
    // is true of a caller that reuses one `siginfo_t` across a failed wait and
    // a successful one.
    if info_addr != 0 && GuestMem.write(info_addr, kernel_sigqueue::as_bytes(&info)) != 0 {
        return Err(Errno::EFAULT);
    }
    res
}

/// The wait itself, filling `info` for a child it found and leaving it zeroed
/// for one it did not. Answers 0 or a negative errno.
fn waitid_wait(
    idtype: c_int,
    id: c_int,
    info: &mut kernel_sigqueue::SigInfo,
    options: c_int,
) -> Result<(), Errno> {
    // Here rather than in the wait loop, which `wait4` also uses -- and that
    // one hands P_ALL the id -1 it was given.
    //
    // **P_ALL does not look at the id at all**, which is what Linux's
    // `kernel_waitid` does: its `case P_ALL:` sets the type and breaks without
    // touching `upid`. This answered EINVAL for `waitid(P_ALL, 12345, ...)`
    // until 2026-09-09, and a regression test asserted that -- written from the
    // implementation rather than from a kernel.
    if idtype == P_PID && id <= 0 {
        return Err(Errno::EINVAL);
    }
    // A `PIDFD_NONBLOCK` pidfd makes the wait a `WNOHANG` one, and finding
    // nothing then is `EAGAIN` unless the caller asked for `WNOHANG` itself --
    // Linux's `kernel_waitid`. It was ignored, so the wait blocked.
    let mut nonblock = false;
    let (idtype, id) = if idtype == P_PIDFD {
        // Resolved before pids_lock is taken, which is the whole reason it
        // happens here and not inside the loop.
        let (pid, nb) = pidfdcalls::pidfd_resolve(id)?;
        nonblock = nb;
        (P_PID, pid)
    } else {
        (idtype, id)
    };
    let asked_nohang = options & WNOHANG != 0;
    let options = if nonblock { options | WNOHANG } else { options };

    let res = do_wait(idtype, id, kernel_sigqueue::as_bytes_mut(info), None, options);
    if res < 0 {
        // Whatever the loop wrote before failing is not an answer.
        kernel_sigqueue::as_bytes_mut(info).fill(0);
        return Err(Errno::from_negative_or_eio(res));
    }
    // WNOHANG with nothing to report: the buffer stays zeroed.
    if res == 0 && get_i32(kernel_sigqueue::as_bytes(info), offset::CHILD_PID) == 0 {
        if nonblock && !asked_nohang {
            return Err(Errno::EAGAIN);
        }
        return Ok(());
    }
    kernel_sigqueue::childinfo::decode_in_place(info);
    Ok(())
}

/// `struct rusage_` is 144 bytes; only the two timevals are filled.
const RUSAGE_SIZE: usize = 144;

pub fn sys_wait4(
    id: c_int,
    status_addr: u64,
    options: c_uint,
    rusage_addr: u64,
) -> Result<c_int, Errno> {
    strace!("wait4({id}, {status_addr:#x}, {options:#x}, {rusage_addr:#x})");
    let options = options as c_int;
    if options & WNOWAIT != 0 {
        return Err(Errno::EINVAL);
    }

    // What a `wait4` pid means, which is not what a `waitid` idtype means: a
    // positive one is a pid, -1 is any child, 0 is this process's group, and
    // anything else negative is the group whose id it names.
    let (idtype, id) = if id > 0 {
        (P_PID, id)
    } else if id == -1 {
        (P_ALL, id)
    } else if id == 0 {
        // No lock: `do_wait` takes `pids_lock` a few frames later and it is
        // not reentrant. `pgid` is atomic for exactly this read.
        (P_PGID, taskview::current_pgid())
    } else {
        (P_PGID, -id)
    };

    let mut info = kernel_sigqueue::SigInfo::default();
    let mut rusage = [0u8; RUSAGE_SIZE];
    let res = do_wait(
        idtype,
        id,
        kernel_sigqueue::as_bytes_mut(&mut info),
        Some(&mut rusage),
        options | WEXITED,
    );
    let info_bytes = kernel_sigqueue::as_bytes(&info);
    let child_pid = get_i32(info_bytes, offset::CHILD_PID);
    // 0 with no child is `WNOHANG` finding nothing, which is an answer and not
    // an error -- so the two cases the old shape folded into one `return res`
    // are two arms now.
    if res < 0 {
        return Err(Errno::from_negative_or_eio(res));
    }
    if res == 0 && child_pid == 0 {
        return Ok(0);
    }
    if status_addr != 0
        && GuestMem.write(
            status_addr,
            &info_bytes[offset::CHILD_STATUS..offset::CHILD_STATUS + 4],
        ) != 0
    {
        return Err(Errno::EFAULT);
    }
    if rusage_addr != 0 && GuestMem.write(rusage_addr, &rusage) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(child_pid)
}

/// `WNOHANG`, exported so the meaning is in one place.
pub const WNOHANG_: c_int = WNOHANG;

#[cfg(test)]
mod tests {
    /// `si_code` for a SIGCHLD, and the two signal numbers the decode names.
    ///
    /// Here rather than at the top of the file since 2026-09-09: the decode
    /// itself is `crates/kernel/sigqueue`'s, so these are the *test's* copy of
    /// what it is supposed to answer, which is what an assertion should be
    /// written from.
    const CLD_EXITED: c_int = 1;
    const CLD_KILLED: c_int = 2;
    const CLD_DUMPED: c_int = 3;
    const CLD_TRAPPED: c_int = 4;
    const CLD_STOPPED: c_int = 5;
    const CLD_CONTINUED: c_int = 6;
    const SIGCHLD: c_int = 17;
    const SIGCONT: c_int = 18;

    use super::*;

    /// The six encodings, which is the whole of what this function is.
    ///
    /// Testable without a child because the input is one 32-bit word: reaching
    /// it through `sys_waitid` would mean a real process for each case, and two
    /// of them cannot be produced at all.
    #[test]
    fn every_status_encoding_decodes_to_its_own_code() {
        // exit(3): status << 8, low byte zero.
        assert_eq!(decode_status(3 << 8, 0), (CLD_EXITED, 3));
        // exit(0) is not "no event": a zero word is still a normal exit.
        assert_eq!(decode_status(0, 0), (CLD_EXITED, 0));
        // Killed by SIGKILL: the signal in the low seven bits.
        assert_eq!(decode_status(9, 0), (CLD_KILLED, 9));
        // With the core-dump bit, which nothing sets today.
        assert_eq!(decode_status(9 | 0x80, 0), (CLD_DUMPED, 9));
        // A group stop: sig << 8 | 0x7f.
        assert_eq!(decode_status((19 << 8) | 0x7f, 0), (CLD_STOPPED, 19));
        // A ptrace stop packs identically, so the caller's code decides.
        assert_eq!(
            decode_status((5 << 8) | 0x7f, CLD_TRAPPED),
            (CLD_TRAPPED, 5)
        );
        // Continued.
        assert_eq!(decode_status(0xffff, 0), (CLD_CONTINUED, SIGCONT));
    }

    /// A stop and a signal death are told apart by the *low byte*, and 0x7f is
    /// not a signal number a process can be killed by — which is what makes the
    /// encoding unambiguous and worth asserting.
    #[test]
    fn a_stop_is_not_mistaken_for_a_death() {
        let (code, _) = decode_status((19 << 8) | 0x7f, 0);
        assert_eq!(code, CLD_STOPPED);
        // One bit different in the low byte and it is a death instead.
        let (code, status) = decode_status((19 << 8) | 0x7e, 0);
        assert_eq!((code, status), (CLD_KILLED, 0x7e));

        // And a high byte on a signal death does not make it an exit: only the
        // low seven bits being zero does. `tests/unit/waitid_test.c` was the
        // only thing asking this until 2026-09-08, and it is the ordering the
        // decode has to get right rather than the arithmetic -- `0xffff` also
        // satisfies "low byte is 0x7f", and a signal death satisfies neither of
        // the two cases before it.
        assert_eq!(decode_status((3 << 8) | 9, 0), (CLD_KILLED, 9));
        // `0x7f` is not a signal number, so a stop is not read as a death by
        // signal 127.
        assert_eq!(decode_status((19 << 8) | 0x7f, 0).0, CLD_STOPPED);
        assert_eq!(decode_status(0xffff, 0).0, CLD_CONTINUED);
    }

    /// The offsets, tied to the one thing `kernel/signal.h` states outright.
    ///
    /// The header says `utime` and `stime` are at 32 and 40 -- it says so
    /// because they were once at 28 and 32 and a guest reading `si_utime` got
    /// `si_stime`. Everything before them follows: `status` is four bytes
    /// ending where `utime`'s 8-alignment begins, `uid` is four before that,
    /// `pid` four before that, and the union therefore starts at 16 rather than
    /// at the 12 three leading ints would suggest.
    #[test]
    fn the_child_offsets_agree_with_the_header() {
        assert_eq!(offset::CHILD_UTIME, 32, "kernel/signal.h states this");
        assert_eq!(offset::CHILD_STIME, 40, "and this");
        // utime is 8-aligned, so status has to end at or before 32 and cannot
        // start earlier than 32 - 8 without leaving a hole the union has no
        // member for.
        assert_eq!(offset::CHILD_STATUS + 4, 28);
        const { assert!(offset::CHILD_UTIME - (offset::CHILD_STATUS + 4) < 8) };
        assert_eq!(offset::CHILD_UID + 4, offset::CHILD_STATUS);
        assert_eq!(offset::CHILD_PID + 4, offset::CHILD_UID);
        // And the union starts after the three leading ints, padded up.
        assert_eq!(offset::CHILD_PID, 16);
        const { assert!(offset::CHILD_PID > offset::CODE + 4, "after si_code") };
        assert_eq!(offset::CHILD_PID % 8, 0, "8-aligned, as its members are");
    }

    /// The in-place form writes all three fields, which is what the C caller
    /// and `sys_waitid` both rely on.
    #[test]
    fn the_c_form_writes_sig_code_and_status() {
        // A `SigInfo`, not a `[u8; 128]`: the C prototype says
        // `struct siginfo_ *` and that has alignment 8, so a byte array is a
        // misaligned pointer. It was one until 2026-09-05, when the Rust
        // signature stopped saying `*mut u8` and started saying what the
        // header says -- and `-Zmiri`-style alignment checking caught it at
        // once. `tests/unit/waitid_test.c`, which was this test in C until
        // 2026-09-08, never had the problem: it declares a `struct siginfo_`.
        let decode = |raw: i32, code: i32| {
            let mut info = kernel_sigqueue::SigInfo::default();
            {
                let buf = kernel_sigqueue::as_bytes_mut(&mut info);
                set_i32(buf, offset::CHILD_STATUS, raw);
                set_i32(buf, offset::CODE, code);
            }
            kernel_sigqueue::childinfo::decode_in_place(&mut info);
            let buf = kernel_sigqueue::as_bytes(&info);
            (
                get_i32(buf, offset::SIG),
                get_i32(buf, offset::CODE),
                get_i32(buf, offset::CHILD_STATUS),
            )
        };
        assert_eq!(decode(7 << 8, 0), (SIGCHLD, CLD_EXITED, 7));

        // **Every** decode reports SIGCHLD, whatever the event was: `waitid`
        // fills a siginfo for the signal the parent would have received.
        assert_eq!(decode(9, 0), (SIGCHLD, CLD_KILLED, 9));
        assert_eq!(decode((19 << 8) | 0x7f, 0), (SIGCHLD, CLD_STOPPED, 19));

        // A ptrace stop and a group stop pack into the same word. `do_wait` is
        // the only place that knows which it read, so it marks the ptrace one
        // and the decode has to leave that mark alone -- Linux reports
        // CLD_TRAPPED there. Driving a real tracee is out of reach here; what
        // the decode is responsible for is not overwriting it.
        assert_eq!(
            decode((5 << 8) | 0x7f, CLD_TRAPPED),
            (SIGCHLD, CLD_TRAPPED, 5)
        );
    }
}
