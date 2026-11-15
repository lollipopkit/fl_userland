//! `prctl` and `reboot`.
//!
//! What each `prctl` option *means* is `crates/kernel/procattr` for the
//! per-thread ones and `crates/kernel/mmapcalls`'s `mmflags` for the two that
//! belong to the address space: which values are accepted, what the boundary
//! is, and which of `prctl`'s other arguments Linux requires to be zero. What
//! is here is the syscall's own business — which argument is a guest address,
//! which capability an option asks for, and taking the lock.
//!
//! # Every unknown option is `EINVAL`
//!
//! Which is what Linux says for an option it does not know, so a program can
//! tell "not implemented" from "implemented and refused". Forty-two options
//! are answered; only the first two of them used to exist, and until 2026-09-04
//! it was twelve — `prctl_probe` found the other thirty being refused where
//! Linux answers, and the answer for each is either the rule Linux applies or
//! a refusal this kernel can stand behind. Four are the second kind, and each
//! says why at its rule: tagged addresses, seccomp, `PR_SET_MM` and a counter
//! that traps.
//!
//! # The arguments are `unsigned long` and stay that way
//!
//! Two of these narrowed one to `int` before bounding it, so
//! `prctl(PR_SET_PDEATHSIG, 0x1_0000_0009)` was `SIGKILL` and
//! `prctl(PR_SET_DUMPABLE, 0x1_0000_0001)` was `SUID_DUMP_USER`. They are passed
//! on whole; `tools/syscall-abi.py`'s second rule exists because of them.
//!
//! # And the return is a `long`
//!
//! `PR_GET_TIMERSLACK` answers the `unsigned long` a program set, so the
//! syscall is in `returns_64bit` and a slack of 2^40 comes back whole.


use std::ffi::c_int;

use kernel_pids::PidsGuard;
use kernel_procattr as procattr;
use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

mod keys;
mod landlock;
mod seccomp;
pub use keys::{sys_add_key, sys_keyctl, sys_request_key};
pub use landlock::{sys_landlock_add_rule, sys_landlock_create_ruleset, sys_landlock_restrict_self};
pub use seccomp::sys_seccomp;

/// The options this answers. Everything else is `EINVAL`.
mod option {
    pub const SET_PDEATHSIG: u32 = 1;
    pub const GET_PDEATHSIG: u32 = 2;
    pub const GET_DUMPABLE: u32 = 3;
    pub const SET_DUMPABLE: u32 = 4;
    pub const GET_KEEPCAPS: u32 = 7;
    pub const SET_KEEPCAPS: u32 = 8;
    pub const GET_TIMING: u32 = 13;
    pub const SET_TIMING: u32 = 14;
    pub const SET_NAME: u32 = 15;
    pub const GET_NAME: u32 = 16;
    pub const GET_SECCOMP: u32 = 21;
    pub const SET_SECCOMP: u32 = 22;
    pub const CAPBSET_READ: u32 = 23;
    pub const CAPBSET_DROP: u32 = 24;
    pub const GET_TSC: u32 = 25;
    pub const SET_TSC: u32 = 26;
    pub const GET_SECUREBITS: u32 = 27;
    pub const SET_SECUREBITS: u32 = 28;
    pub const SET_TIMERSLACK: u32 = 29;
    pub const GET_TIMERSLACK: u32 = 30;
    pub const TASK_PERF_EVENTS_DISABLE: u32 = 31;
    pub const TASK_PERF_EVENTS_ENABLE: u32 = 32;
    pub const MCE_KILL: u32 = 33;
    pub const MCE_KILL_GET: u32 = 34;
    pub const SET_MM: u32 = 35;
    pub const SET_CHILD_SUBREAPER: u32 = 36;
    pub const GET_CHILD_SUBREAPER: u32 = 37;
    pub const SET_NO_NEW_PRIVS: u32 = 38;
    pub const GET_NO_NEW_PRIVS: u32 = 39;
    pub const GET_TID_ADDRESS: u32 = 40;
    pub const SET_THP_DISABLE: u32 = 41;
    pub const GET_THP_DISABLE: u32 = 42;
    pub const CAP_AMBIENT: u32 = 47;
    pub const GET_SPECULATION_CTRL: u32 = 52;
    pub const SET_SPECULATION_CTRL: u32 = 53;
    pub const SET_TAGGED_ADDR_CTRL: u32 = 55;
    pub const GET_TAGGED_ADDR_CTRL: u32 = 56;
    pub const SET_IO_FLUSHER: u32 = 57;
    pub const GET_IO_FLUSHER: u32 = 58;
    pub const SET_MDWE: u32 = 65;
    pub const GET_MDWE: u32 = 66;
    pub const FUTEX_HASH: u32 = 78;
    /// `'AUXV'`.
    pub const GET_AUXV: u32 = 0x4155_5856;

    /// Every one, for the test that says no two share a number.
    #[cfg(test)]
    pub const ALL: [u32; 43] = [
        SET_PDEATHSIG,
        GET_PDEATHSIG,
        GET_DUMPABLE,
        SET_DUMPABLE,
        GET_KEEPCAPS,
        SET_KEEPCAPS,
        GET_TIMING,
        SET_TIMING,
        SET_NAME,
        GET_NAME,
        GET_SECCOMP,
        SET_SECCOMP,
        CAPBSET_READ,
        CAPBSET_DROP,
        GET_TSC,
        SET_TSC,
        GET_SECUREBITS,
        SET_SECUREBITS,
        SET_TIMERSLACK,
        GET_TIMERSLACK,
        TASK_PERF_EVENTS_DISABLE,
        TASK_PERF_EVENTS_ENABLE,
        MCE_KILL,
        MCE_KILL_GET,
        SET_MM,
        SET_CHILD_SUBREAPER,
        GET_CHILD_SUBREAPER,
        SET_NO_NEW_PRIVS,
        GET_NO_NEW_PRIVS,
        GET_TID_ADDRESS,
        SET_THP_DISABLE,
        GET_THP_DISABLE,
        CAP_AMBIENT,
        GET_SPECULATION_CTRL,
        SET_SPECULATION_CTRL,
        SET_TAGGED_ADDR_CTRL,
        GET_TAGGED_ADDR_CTRL,
        SET_IO_FLUSHER,
        GET_IO_FLUSHER,
        SET_MDWE,
        GET_MDWE,
        FUTEX_HASH,
        GET_AUXV,
    ];
}

/// `TASK_COMM_LEN`. Sixteen bytes including the terminator.
const COMM_LEN: usize = 16;

/// How many bytes `PR_GET_AUXV` says the vector is, whatever was asked for:
/// Linux's `sizeof(mm->saved_auxv)`, which is `AT_VECTOR_SIZE` words and a
/// constant of the kernel version — 54 on the 7.0 arm64 kernel this was
/// measured against. The vector `execve` wrote here is shorter and the rest is
/// zero, which is also what Linux's is.
const SAVED_AUXV_BYTES: usize = 54 * 8;

/// The calling thread's attributes, borrowed for `f` under their lock.
/// `EINVAL` on a thread with none.
fn thread<R>(f: impl FnOnce(&mut procattr::ThreadAttr) -> R) -> Result<R, Errno> {
    taskview::with_current_attr(f).ok_or(Errno::EINVAL)
}

/// A rule run against those attributes, whose own answer is a `Result`.
///
/// Two errors in one call -- this file's "the thread has no attributes" and the
/// rule's own refusal -- and both are an errno, at different widths. Fifteen
/// call sites wrote `thread(...).and_then(|r| r)` to flatten them and could not
/// have without `crates/kernel/procattr` saying errno in a `c_int`. Here is
/// where the two meet, once.
fn thread_rule<R>(
    f: impl FnOnce(&mut procattr::ThreadAttr) -> Result<R, c_int>,
) -> Result<R, Errno> {
    thread(f)?.map_err(Errno::from_negative_or_eio)
}

/// The calling process's attributes, as [`thread`].
fn process<R>(f: impl FnOnce(&procattr::ProcAttr) -> R) -> Result<R, Errno> {
    let _pids = PidsGuard::take();
    taskview::with_current_group(|g| f(&g.attr)).ok_or(Errno::EINVAL)
}

/// As [`thread_rule`], for the process's attributes.
fn process_rule<R>(f: impl FnOnce(&procattr::ProcAttr) -> Result<R, c_int>) -> Result<R, Errno> {
    process(f)?.map_err(Errno::from_negative_or_eio)
}

/// A rule over the calling task's credentials, committed under `pids_lock`
/// as every credential change is (`crates/kernel/idcalls`' `with_creds_locked`):
/// the bounding set, the ambient set and the securebits are Linux's `cred`.
fn creds_rule<R>(f: impl FnOnce(&mut kernel_creds::Creds) -> Result<R, c_int>) -> Result<R, Errno> {
    PidsGuard::take()
        .commit_current_creds(f)
        .ok_or(Errno::EINVAL)?
        .map_err(Errno::from_negative_or_eio)
}

/// A question about them, read on the task's own thread.
fn creds<R>(f: impl FnOnce(&kernel_creds::Creds) -> R) -> Result<R, Errno> {
    taskview::with_current_creds(f).ok_or(Errno::EINVAL)
}

/// A rule whose answer is only whether it was allowed.
fn done(r: Result<(), c_int>) -> Result<i64, Errno> {
    r.map(|()| 0).map_err(Errno::from_negative_or_eio)
}

/// A rule that answers a number.
fn answer(r: Result<c_int, Errno>) -> Result<i64, Errno> {
    r.map(i64::from)
}

/// A `crates/kernel/procattr` rule that answers a number and reports its own
/// refusal as a `c_int`. [`done`]'s shape, for the getters.
fn done_value(r: Result<c_int, c_int>) -> Result<i64, Errno> {
    match r {
        Ok(v) => Ok(v.into()),
        Err(e) => Err(Errno::from_negative_or_eio(e)),
    }
}

/// An answer delivered through `arg2`: the `put_user` half of a getter.
fn put(mem: &GuestMem, addr: u64, bytes: &[u8]) -> Result<i64, Errno> {
    if mem.write(addr, bytes) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(0)
}

/// `PR_GET_AUXV`: the auxiliary vector `execve` left, zero-padded to the
/// size Linux keeps it at, of which the caller gets as much as it asked for.
/// The return is that size, so a caller learns how much to ask for.
///
/// The bytes are read back out of the guest's own stack, where `execve` put
/// them. A process that has unmapped that page gets zeroes for it, which is
/// what a vector with nothing in it looks like.
fn get_auxv(mem: &GuestMem, addr: u64, len: u64, a4: u64, a5: u64) -> Result<i64, Errno> {
    if a4 | a5 != 0 {
        return Err(Errno::EINVAL);
    }
    let mut saved = [0u8; SAVED_AUXV_BYTES];
    // Read under the read lock `execve` writes it under, and released before
    // the guest read below takes it again.
    let auxv = pagetable::memlock::ReadGuard::current().map(|held| pagetable::memlock::Held::image(&held).auxv);
    if let Some((start, end)) = auxv {
        let n = usize::try_from(end.saturating_sub(start))
            .unwrap_or(0)
            .min(SAVED_AUXV_BYTES);
        if n > 0 && mem.read(start, &mut saved[..n]) != 0 {
            saved = [0; SAVED_AUXV_BYTES];
        }
    }
    let size = usize::try_from(len)
        .unwrap_or(usize::MAX)
        .min(SAVED_AUXV_BYTES);
    if size > 0 && mem.write(addr, &saved[..size]) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(SAVED_AUXV_BYTES as i64)
}

/// Answers a `long`: `PR_GET_TIMERSLACK` returns an unsigned long, so 167 is in
/// `syscalltable::returns_64bit`.
///
pub fn sys_prctl(option: u32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64, Errno> {
    let mem = GuestMem::current();
    // `PR_SET_MM` and the IO flusher pair ask CAP_SYS_RESOURCE; the
    // capability options ask the credentials themselves.
    let sys_resource = taskview::capable(taskview::caps::CAP_SYS_RESOURCE);
    match option {
        option::SET_NAME => {
            // Linux truncates rather than refusing: `prctl(PR_SET_NAME)` calls
            // `strncpy_from_user(comm, arg2, TASK_COMM_LEN - 1)` over a buffer
            // whose last byte it has already zeroed, and that returns the count
            // rather than an error when the name is longer. So fifteen
            // characters and success.
            //
            // `read_string` reports ENAMETOOLONG for a string with no
            // terminator in the space given, which is what every other caller
            // wants and what this one must not pass on. What it read is still
            // there, and `set_comm` does the truncation.
            let mut name = [0u8; COMM_LEN];
            match mem.read_string(arg2, &mut name) {
                Ok(_) => {}
                Err(-36) => {} // ENAMETOOLONG
                Err(e) => return Err(Errno::from_negative_or_eio(e)),
            }
            strace!(
                "prctl(PR_SET_NAME, {:?})",
                String::from_utf8_lossy(&name[..name.iter().position(|&b| b == 0).unwrap_or(15)])
            );
            thread(|a| a.set_comm(&name))?;
            Ok(0)
        }

        option::GET_NAME => {
            // Sixteen bytes, always -- Linux's is `copy_to_user(arg2, comm,
            // sizeof(comm))`, not strlen + 1. A caller with a 16-byte buffer is
            // entitled to have all of it written, so what follows the
            // terminator is the kernel's zeroes rather than its own stack.
            let name = thread(|a| *a.comm())?;
            strace!(
                "prctl(PR_GET_NAME) -> {:?}",
                String::from_utf8_lossy(&name[..name.iter().position(|&b| b == 0).unwrap_or(15)])
            );
            put(&mem, arg2, &name)
        }

        option::SET_PDEATHSIG => {
            strace!("prctl(PR_SET_PDEATHSIG, {arg2})");
            thread_rule(|a| a.set_pdeath_signal(arg2)).map(|()| 0)
        }
        option::GET_PDEATHSIG => put(&mem, arg2, &thread(|a| a.pdeath_signal())?.to_ne_bytes()),

        option::SET_DUMPABLE => process_rule(|p| p.set_dumpable(arg2)).map(|()| 0),
        option::GET_DUMPABLE => answer(process(|p| p.dumpable())),

        // `keepcaps` is a securebit on the credentials: what a uid change
        // away from 0 keeps the permitted set by.
        option::SET_KEEPCAPS => creds_rule(|c| c.set_keepcaps(arg2)).map(|()| 0),
        option::GET_KEEPCAPS => answer(creds(|c| c.keepcaps() as c_int)),

        option::SET_CHILD_SUBREAPER => process(|p| p.set_child_subreaper(arg2)).map(|()| 0),
        option::GET_CHILD_SUBREAPER => put(
            &mem,
            arg2,
            &process(|p| p.child_subreaper() as i32)?.to_ne_bytes(),
        ),

        option::SET_NO_NEW_PRIVS => {
            thread_rule(|a| a.set_no_new_privs(arg2, arg3, arg4, arg5)).map(|()| 0)
        }
        option::GET_NO_NEW_PRIVS => {
            answer(thread_rule(|a| a.get_no_new_privs(arg2, arg3, arg4, arg5)))
        }

        option::GET_TIMING => Ok(procattr::TIMING_STATISTICAL as i64),
        option::SET_TIMING => done(procattr::set_timing(arg2)),

        // seccomp's older spelling. This answered as a kernel without
        // CONFIG_SECCOMP until 2026-11-11 -- except that such a kernel says
        // EINVAL to PR_GET_SECCOMP too, and this said 0. See
        // crates/kernel/seccomp.
        option::GET_SECCOMP => seccomp::prctl_get(),
        option::SET_SECCOMP => seccomp::prctl_set(arg2, arg3),

        option::CAPBSET_READ => {
            creds(|c| c.cap_bset_has(arg2))?.map(i64::from).map_err(Errno::from_negative_or_eio)
        }
        option::CAPBSET_DROP => creds_rule(|c| c.cap_bset_drop(arg2)).map(|()| 0),

        option::GET_TSC => put(&mem, arg2, &(procattr::TSC_ENABLE as u32).to_ne_bytes()),
        option::SET_TSC => done(procattr::set_tsc(arg2)),

        option::GET_SECUREBITS => answer(creds(|c| c.securebits() as c_int)),
        option::SET_SECUREBITS => creds_rule(|c| c.set_securebits(arg2)).map(|()| 0),

        option::SET_TIMERSLACK => thread(|a| a.set_timer_slack(arg2)).map(|()| 0),
        option::GET_TIMERSLACK => thread(|a| a.timer_slack()).map(|ns| ns as i64),

        // There are no perf events to disable, and Linux's answer with none
        // open is 0 too.
        option::TASK_PERF_EVENTS_DISABLE | option::TASK_PERF_EVENTS_ENABLE => Ok(0),

        option::MCE_KILL => thread_rule(|a| a.mce_kill(arg2, arg3, arg4, arg5)).map(|()| 0),
        option::MCE_KILL_GET => answer(thread_rule(|a| a.mce_kill_get(arg2, arg3, arg4, arg5))),

        option::SET_MM => done(procattr::set_mm(arg2, arg4, arg5, sys_resource)),

        option::GET_TID_ADDRESS => put(&mem, arg2, &taskview::current_clear_tid().to_ne_bytes()),

        option::SET_THP_DISABLE => {
            Errno::split(mmapcalls::prctl::thp_disable_set(arg2, arg3, arg4, arg5) as i64)
        }
        option::GET_THP_DISABLE => {
            Errno::split(mmapcalls::prctl::thp_disable_get(arg2, arg3, arg4, arg5) as i64)
        }

        option::CAP_AMBIENT => creds_rule(|c| c.cap_ambient(arg2, arg3, arg4, arg5)).map(i64::from),

        option::GET_SPECULATION_CTRL => {
            answer(thread_rule(|a| a.spec_ctrl_get(arg2, arg3, arg4, arg5)))
        }
        option::SET_SPECULATION_CTRL => {
            thread_rule(|a| a.spec_ctrl_set(arg2, arg3, arg4, arg5)).map(|()| 0)
        }

        option::SET_TAGGED_ADDR_CTRL => {
            done(procattr::tagged_addr_ctrl_set(arg2, arg3, arg4, arg5))
        }
        option::GET_TAGGED_ADDR_CTRL => {
            done_value(procattr::tagged_addr_ctrl_get(arg2, arg3, arg4, arg5))
        }

        option::SET_IO_FLUSHER => {
            thread_rule(|a| a.set_io_flusher(arg2, arg3, arg4, arg5, sys_resource)).map(|()| 0)
        }
        option::GET_IO_FLUSHER => {
            answer(thread_rule(|a| a.io_flusher(arg2, arg3, arg4, arg5, sys_resource)))
        }

        option::SET_MDWE => Errno::split(mmapcalls::prctl::mdwe_set(arg2, arg3, arg4, arg5) as i64),
        option::GET_MDWE => Errno::split(mmapcalls::prctl::mdwe_get(arg2, arg3, arg4, arg5) as i64),

        option::GET_AUXV => get_auxv(&mem, arg2, arg3, arg4, arg5),

        option::FUTEX_HASH => futexcalls::hash::prctl_futex_hash(arg2, arg3, arg4, arg5),

        _ => {
            strace!("prctl({option:#x})");
            Err(Errno::EINVAL)
        }
    }
}

// `sys_arch_prctl` was here and went with the rest of the x86 backend:
// `arch_prctl` is an x86-64 syscall, aarch64 has no number for it, and this one
// was dispatched from nowhere.

/// The magic numbers `reboot(2)` demands. They exist so that a wild call cannot
/// reach it by accident, and refusing the wrong ones is the whole of what this
/// syscall does here.
mod reboot {
    pub const MAGIC1: i32 = 0xfee1dead_u32 as i32;
    pub const MAGIC2: i32 = 672274793;
    pub const MAGIC2A: i32 = 85072278;
    pub const MAGIC2B: i32 = 369367448;
    pub const MAGIC2C: i32 = 537993216;

    /// Ctrl-Alt-Delete on and off, which are the two commands that do not
    /// restart anything.
    pub const CMD_CAD_OFF: i32 = 0;
    pub const CMD_CAD_ON: i32 = 0x89abcdef_u32 as i32;
}

pub fn sys_reboot(magic: i32, magic2: i32, cmd: i32) -> Result<(), Errno> {
    strace!("reboot({magic:#x}, {magic2}, {cmd})");
    if !taskview::capable(taskview::caps::CAP_SYS_BOOT) {
        return Err(Errno::EPERM);
    }
    if magic != reboot::MAGIC1
        || !matches!(
            magic2,
            reboot::MAGIC2 | reboot::MAGIC2A | reboot::MAGIC2B | reboot::MAGIC2C
        )
    {
        return Err(Errno::EINVAL);
    }
    match cmd {
        reboot::CMD_CAD_ON | reboot::CMD_CAD_OFF => Ok(()),
        // Everything else would end the emulator, which is the embedder's
        // decision and not a guest's.
        _ => Err(Errno::EPERM),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The magic numbers, which are the whole of `reboot`'s argument handling.
    /// `MAGIC1` is `0xfee1dead` and does not fit an `i32` — writing it as one
    /// without the cast is a compile error in Rust and a silent sign change in
    /// C, which is why the C had `(int) REBOOT_MAGIC1` at the comparison.
    #[test]
    fn the_reboot_magics_are_the_numbers_linux_wants() {
        assert_eq!(reboot::MAGIC1 as u32, 0xfee1dead);
        assert_eq!(reboot::MAGIC2, 672274793); // 0x28121969, Torvalds' birthday
        assert_eq!(reboot::MAGIC2A, 85072278); // 0x05121996
        assert_eq!(reboot::MAGIC2B, 369367448); // 0x16041998
        assert_eq!(reboot::MAGIC2C, 537993216); // 0x20112000
        assert_eq!(reboot::CMD_CAD_ON as u32, 0x89abcdef);
        assert_eq!(reboot::CMD_CAD_OFF, 0);
    }

    /// Forty-three options and no two the same number. A duplicate would make
    /// one of them unreachable, which is the kind of thing a `switch` hides.
    #[test]
    fn the_options_are_distinct() {
        let mut sorted = option::ALL.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            option::ALL.len(),
            "two options share a number"
        );
        assert_eq!(option::ALL.len(), 43);
    }

    /// `TASK_COMM_LEN`. The name is truncated to fifteen characters and a
    /// terminator, and `PR_GET_NAME` writes all sixteen bytes whatever the
    /// length.
    #[test]
    fn the_comm_length_is_sixteen() {
        assert_eq!(COMM_LEN, 16);
    }

    /// `PR_GET_AUXV` reports the size Linux keeps the vector at, which is
    /// the 7.0 arm64 kernel's 54 words.
    #[test]
    fn the_saved_auxv_is_fifty_four_words() {
        assert_eq!(SAVED_AUXV_BYTES, 432);
    }
}
