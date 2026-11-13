//! The process and thread attributes a guest sets and reads back: `prctl`'s
//! table and `personality`.
//!
//! Few of these attributes *do* anything in this emulator. There is no core
//! dump for `dumpable` to suppress and no address randomisation for
//! `ADDR_NO_RANDOMIZE` to disable; `no_new_privs` is read by `execve`. What they do is get remembered
//! and reported. `dumpable` is the exception: `crates/fs/proc` reads it to
//! decide who owns `/proc/<pid>` and who may look at another process's
//! descriptors.
//!
//! That is exactly why they belong here rather than as fields somewhere with an
//! `if` beside each one. An attribute whose only job is to answer honestly has
//! nothing but its rule, and the rule is where every defect was:
//!
//! - `personality` refused every value except `ADDR_NO_RANDOMIZE`, where Linux
//!   refuses only one, and returned the *new* value where Linux returns the
//!   old — so the save-and-restore a caller does around a child could not
//!   restore anything.
//! - `dumpable` accepted `SUID_DUMP_ROOT`, which a process may not set.
//! - `keepcaps` accepted any value and stored none, and `PR_GET_KEEPCAPS` did
//!   not exist, so a program could set it and never read it back. It is a
//!   securebit on the credentials now, with the capability sets
//!   (`crates/kernel/creds`).
//! - `no_new_privs` ignored `arg3`..`arg5`, which Linux requires to be zero.
//! - `pdeath_signal` and `dumpable` narrowed their argument to `int` before
//!   bounding it, so `0x1_0000_0009` was `SIGKILL` and `0x1_0000_0001` was
//!   `SUID_DUMP_USER`. `prctl`'s arguments are `unsigned long`.
//! - `personality` and `no_new_privs` were stored per *thread group*, and Linux
//!   keeps both on `task_struct` — one thread's `setarch` reached its siblings.
//!
//! Every rule below was checked against a real arm64 kernel through
//! `tests/guest/src/bin/prctl_abi.rs` and `personality_abi.rs`, run under
//! `differential.sh`. Two of them are not in the man pages at all.
//!
//! # What is not here
//!
//! Guest memory. `prctl`'s arguments are sometimes addresses, and which ones
//! is a property of the syscall rather than of the attribute — so reading a
//! name in and writing one out stays with the caller, the way `crates/fs/dirent`
//! owns the `getdents64` record and `fs/dir.c` keeps the loop that writes it.
//!
//! # Where the state lives
//!
//! [`ThreadAttr`] is embedded in `struct task` and [`ProcAttr`] in
//! `struct tgroup`, both as opaque byte arrays whose size is asserted from
//! here. That split is Linux's: `personality`, `pdeath_signal`, `no_new_privs`
//! and `comm` are per thread; `dumpable` (which Linux keeps in
//! `mm->flags`) and `child_subreaper` are per process.
//!
//! Neither has a zeroed default, so neither can rely on the struct being
//! zeroed the way `crates/kernel/creds`' `Groups` does — [`ThreadAttr::init`]
//! and [`ProcAttr::init`] exist and the C calls them. A child inherits both by
//! the struct assignment that makes it, which is what Linux does.

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

mod flags;
use flags::mce;
pub use flags::{SCHED_BATCH, SCHED_IDLE, SCHED_OTHER, sched_policy_supported, spec};
mod ioprio;
#[path = "thread.rs"]
mod thread;
// Exported under their own names since 2026-09-16. They were reachable only
// through `procattr_ioprio_which_valid` and friends -- a `pub fn` per `fn`,
// adding a prefix and, for `ioprio_check`, flattening a `Result` into an errno
// the caller unflattened again.
pub use ioprio::{
    IOPRIO_BEST_DEFAULT, IOPRIO_CLASS_SHIFT, ioprio_best, ioprio_check, ioprio_which_valid,
};
use ioprio::{
    IOPRIO_CLASS_BE, IOPRIO_CLASS_IDLE, IOPRIO_CLASS_MASK, IOPRIO_CLASS_NONE, IOPRIO_CLASS_RT,
    IOPRIO_LEVEL_MASK, IOPRIO_NONE,
};
pub use thread::ThreadAttr;

use guest_errno::c_int_::{EINVAL, EPERM};

/// Linux's `TASK_COMM_LEN`: fifteen visible characters and a terminator.
pub const COMM_LEN: usize = 16;

/// `MAX_SIG` in `kernel/signal.h`. Linux's `valid_signal` is `sig <= _NSIG`,
/// so this number is *inside* the range even though no signal 64 is delivered.
const MAX_SIG: u64 = 64;

/// `PER_MASK` from `include/uapi/linux/personality.h`: the low byte of a
/// personality is its "type", and the bits above it are flags.
const PER_MASK: u32 = 0x00ff;
const PER_LINUX32: u32 = 0x0008;
/// `personality(0xffffffff)` asks rather than sets.
const PERSONALITY_QUERY: u32 = 0xffff_ffff;
/// What a fresh process starts with. Linux would say `PER_LINUX` (0); this
/// says `ADDR_NO_RANDOMIZE` because it is true — there is no randomisation
/// here, and a program that checks before re-executing itself under `setarch`
/// should be able to skip that.
pub const ADDR_NO_RANDOMIZE: u32 = 0x0004_0000;

// ------------------------------------------------------------- thread state

/// `PR_SET_TIMERSLACK(0)` means "the default", and the default of a fresh
/// process is Linux's `default_timer_slack_ns`.
const DEFAULT_TIMER_SLACK_NS: u64 = 50_000;

use guest_errno::c_int_::{ENODEV, ERANGE};

// -------------------------------------------------- the options with no state
//
// Each is a rule and nothing else: what a process is told is fixed, and only
// the argument handling can be got wrong. They are here rather than in the
// syscall so that each has a test beside its reason.

/// `PR_GET_TIMING` answers `PR_TIMING_STATISTICAL`, the only timing there is,
/// and `PR_SET_TIMING` accepts only that.
pub const TIMING_STATISTICAL: c_int = 0;

pub fn set_timing(arg2: u64) -> Result<(), c_int> {
    if arg2 != TIMING_STATISTICAL as u64 {
        return Err(EINVAL);
    }
    Ok(())
}

/// `PR_GET_TAGGED_ADDR_CTRL`. This kernel behaves as one whose
/// `abi.tagged_addr_disabled` sysctl is set. The instructions ignore an
/// address's top byte, as the CPU does (since 2026-10-18; `tests/guest`
/// bad_pc_addr), but the *syscall* side of the tagged-address ABI is not
/// here: usercopy refuses an address above the 48-bit space, so a tagged
/// pointer passed to a syscall is `EFAULT`, which is what an untagged-ABI
/// process gets on Linux too. Telling a program tagging is on would promise the
/// syscalls accept them. Linux's `set_tagged_addr_ctrl` answers `EINVAL` to an
/// enable request under that sysctl and 0 to a query, which is the state a
/// portable program already handles.
pub fn tagged_addr_ctrl_get(a2: u64, a3: u64, a4: u64, a5: u64) -> Result<c_int, c_int> {
    if a2 | a3 | a4 | a5 != 0 {
        return Err(EINVAL);
    }
    Ok(0)
}

/// `PR_TAGGED_ADDR_ENABLE`, the one bit of the control an arm64 without MTE
/// has.
const TAGGED_ADDR_ENABLE: u64 = 1;

pub fn tagged_addr_ctrl_set(arg: u64, a3: u64, a4: u64, a5: u64) -> Result<(), c_int> {
    if a3 | a4 | a5 != 0 {
        return Err(EINVAL);
    }
    if arg & !TAGGED_ADDR_ENABLE != 0 || arg & TAGGED_ADDR_ENABLE != 0 {
        return Err(EINVAL);
    }
    Ok(())
}

/// `PR_GET_TSC` answers `PR_TSC_ENABLE`: the counter is readable. arm64 gained
/// the control in 7.0, and `PR_TSC_SIGSEGV` — make every `cntvct_el0` read
/// trap — is refused here rather than claimed, because honouring it would put
/// a test on the counter-read gadget every `clock_gettime` goes through.
pub const TSC_ENABLE: c_int = 1;

pub fn set_tsc(arg2: u64) -> Result<(), c_int> {
    if arg2 != TSC_ENABLE as u64 {
        return Err(EINVAL);
    }
    Ok(())
}

/// `PR_SET_MM`. Nothing here is settable, so what is kept is the *order* of
/// the refusals, which is what a caller sees: the argument shape first
/// (`arg5`, and `arg4` for any option but the three that take one), then
/// `CAP_SYS_RESOURCE`, then `EINVAL` for the option itself.
pub fn set_mm(opt: u64, a4: u64, a5: u64, capable: bool) -> Result<(), c_int> {
    const AUXV: u64 = 12;
    const MAP: u64 = 14;
    const MAP_SIZE: u64 = 15;
    if a5 != 0 || (a4 != 0 && !matches!(opt, AUXV | MAP | MAP_SIZE)) {
        return Err(EINVAL);
    }
    if !capable {
        return Err(EPERM);
    }
    Err(EINVAL)
}

// ------------------------------------------------------------ process state

/// `fs.suid_dumpable`: what a credential change or a set-id exec leaves
/// `dumpable` at. 0 (`SUID_DUMP_DISABLE`) is Linux's default, 1 leaves such a
/// process dumpable, and 2 (`SUID_DUMP_ROOT`) leaves it at 2, which keeps it
/// from everyone but root as 0 does and which `PR_GET_DUMPABLE` reports as is.
/// `/proc/sys/fs/suid_dumpable` reads and writes it.
static SUID_DUMPABLE: AtomicI32 = AtomicI32::new(0);

/// The current value of [`SUID_DUMPABLE`].
pub fn suid_dumpable() -> c_int {
    SUID_DUMPABLE.load(Ordering::Relaxed)
}

/// Write [`SUID_DUMPABLE`]: 0, 1 or 2, `EINVAL` for anything else.
pub fn set_suid_dumpable(value: i64) -> Result<(), c_int> {
    let value = c_int::try_from(value).ok().filter(|v| (0..=2).contains(v)).ok_or(EINVAL)?;
    SUID_DUMPABLE.store(value, Ordering::Relaxed);
    Ok(())
}

/// The attributes Linux keeps per process — `child_subreaper` on
/// `signal_struct`, and `dumpable` in `mm->flags`, which amounts to the same
/// thing here because every thread of a group shares an `mm`.
///
/// **Atomic since 2026-09-30**, though every access holds `pids_lock`: the
/// struct is a field of `struct tgroup`, and the group's `sid()` and `pgid()`
/// are read without that lock through a shared reference to the whole group.
/// A plain field another thread writes under a lock makes that reference
/// unsound whatever the lock says, and these were two of the last three.
#[derive(Debug)]
#[repr(C)]
pub struct ProcAttr {
    dumpable: AtomicI32,
    child_subreaper: AtomicBool,
}

impl Default for ProcAttr {
    fn default() -> Self {
        // SUID_DUMP_USER. Linux's default for a process that has not done a
        // privileged execve, and this emulator has no other kind.
        ProcAttr {
            dumpable: AtomicI32::new(1),
            child_subreaper: AtomicBool::new(false),
        }
    }
}

impl Clone for ProcAttr {
    fn clone(&self) -> Self {
        ProcAttr {
            dumpable: AtomicI32::new(self.dumpable()),
            child_subreaper: AtomicBool::new(self.child_subreaper()),
        }
    }
}

impl ProcAttr {
    pub fn dumpable(&self) -> c_int {
        self.dumpable.load(Ordering::Relaxed)
    }

    /// What an `execve` leaves behind, of the one attribute a *process* has:
    /// `begin_new_exec`'s "figure out dumpability".
    ///
    /// `SUID_DUMP_USER` on an ordinary exec and [`suid_dumpable`] when
    /// `undumpable` — the caller's `kernel_creds::Creds::exec_keeps_dumpable`
    /// said no. A process that made itself dumpable and then exec'd a setuid
    /// binary would otherwise stay readable by the less-privileged parent.
    /// Linux sets this *before* the new credentials are committed, and that
    /// commit may lower it again ([`ProcAttr::on_identity_change`]): measured,
    /// `setfsuid(65534); execve()` as root leaves 0. See
    /// `ThreadAttr::on_exec` for the rest and for what is deliberately not done.
    pub fn on_exec(&self, undumpable: bool) {
        self.dumpable.store(if undumpable { suid_dumpable() } else { 1 }, Ordering::Relaxed);
    }

    /// `commit_creds`' half: a credential change that moved an effective or
    /// fs id (`kernel_creds::Creds::changes_identity`) leaves the process
    /// [`suid_dumpable`], so a process that was root a moment ago cannot be
    /// read by the user it has just become, nor one that has just become root
    /// by the user it was. `PR_SET_DUMPABLE` can give it back.
    pub fn on_identity_change(&self) {
        self.dumpable.store(suid_dumpable(), Ordering::Relaxed);
    }

    /// `PR_SET_DUMPABLE`. `SUID_DUMP_DISABLE` and `SUID_DUMP_USER` only:
    /// `SUID_DUMP_ROOT` is a value the kernel sets for itself after a
    /// privileged execve and is not one a process may ask for. Linux compares
    /// against the two constants and this accepted anything from 0 to 2.
    pub fn set_dumpable(&self, value: u64) -> Result<(), c_int> {
        if value > 1 {
            return Err(EINVAL);
        }
        self.dumpable.store(value as c_int, Ordering::Relaxed);
        Ok(())
    }

    pub fn child_subreaper(&self) -> bool {
        self.child_subreaper.load(Ordering::Relaxed)
    }

    /// `PR_SET_CHILD_SUBREAPER`. Linux stores `!!arg2`, so any non-zero sets
    /// it and it always reads back as exactly 1. No value is refused.
    pub fn set_child_subreaper(&self, value: u64) {
        self.child_subreaper.store(value != 0, Ordering::Relaxed);
    }
}

// ------------------------------------------------------- reaching the state
//
// There was a "C binding" here until 2026-09-16: sixteen `unsafe fn` taking a
// `*mut ThreadAttr` or a `*const ProcAttr`, null-checking it, and calling the
// method of the same name. Two hundred and seventy lines that translated a
// safe Rust API into a C one for a C that no longer exists.
//
// What each wrapper added, and why none of it was worth keeping:
//
// | | |
// | --- | --- |
// | a null check answering `EINVAL` | a `&ThreadAttr` cannot be null, and no caller could produce one — every one passes `&raw mut (*task).attr`, the address of a field |
// | `Result<_, c_int>` flattened to an errno `int` | the callers unflattened it again |
// | `bool` as `c_int` | `child_subreaper` reads as a `bool` at its one call site now |
// | `&[u8; 16]` as `*const c_char` | four crates rebuilt the same `from_raw_parts`/find-the-NUL/`from_utf8_lossy` out of it; [`ThreadAttr::name`] is that, once |
// | `[u8; 16]` written through an out pointer | its one caller wanted the array |
//
// The `unsafe` did not disappear, it moved to where it belongs: a call site
// that has a `*mut task` forms one reference to one field, and says under what
// lock. That is one obligation per call rather than one per crate, and it is
// the obligation that was always there.

#[cfg(test)]
mod tests;
