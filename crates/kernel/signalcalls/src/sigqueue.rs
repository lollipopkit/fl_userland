//! Queued signal info syscall helpers.

use super::*;

// ---------------------------------------------------------------------------
// sigqueue
// ---------------------------------------------------------------------------

/// The bytes Linux reads from a caller's `siginfo_t`: `sizeof(kernel_siginfo)`,
/// not `sizeof(siginfo_t)`. The rest is padding the kernel neither reads nor
/// trusts, and reading all 128 would make an `EFAULT` of a caller who allocated
/// only the part that means anything.
const SIGINFO_KERNEL_SIZE: usize = 48;

/// `SI_TKILL`, from `kernel/signal.h`.
const SI_TKILL: i32 = -6;

/// `sigqueue(3)` and `pthread_sigqueue(3)`: a signal with a `siginfo` the
/// *caller* supplies, which is how a value is attached to it.
///
/// Both slots were `syscall_stub`, and glibc's `sigqueue` has no fallback — so
/// a program that used one got `ENOSYS`, and the neighbouring slot pointed at
/// `sys_rt_sigreturn`, which restored a CPU state from a frame that was not
/// there.
/// The caller's `siginfo` as bytes.
///
/// No alignment of its own since 2026-09-30, because nothing reads a struct
/// through its address any more: `do_kill` gets `SigInfo::from_le_bytes`,
/// field by field. Until then it was handed on as a `*const SigInfo` and was
/// `#[repr(align(8))]` for that reason -- a plain `[u8; 128]` read through that
/// cast aborted a debug build with "misaligned pointer dereference: address
/// must be a multiple of 0x8 but is 0x16da393ec", from one `sigqueue`, in the
/// middle of `signal_probe`, and a release build read through the misaligned
/// pointer instead.
///
/// The bytes stay bytes until then because that is what the guest sent:
/// `si_code` is read out of them and the signal number written back in before
/// anything interprets the whole.
struct RawSigInfo([u8; 128]);

fn do_sigqueueinfo(
    tgid: c_int,
    pid: c_int,
    sig: c_uint,
    mut raw: RawSigInfo,
    thread_directed: bool,
) -> Result<(), Errno> {
    let info = &mut raw.0;
    if sig > MAX_SIG {
        return Err(Errno::EINVAL);
    }
    // `si_code` is the fourth word of the guest's siginfo: signo, errno, code.
    let code = i32::from_le_bytes(info[8..12].try_into().unwrap());
    // Not even root may claim a signal came from the kernel, or wear the source
    // information kill() and tgkill() attach. Linux allows either only when the
    // target is the caller's own thread -- so a process cannot forge an SI_USER
    // or an SI_KERNEL signal at anything else.
    if (code >= 0 || code == SI_TKILL) && taskview::current_pid() != pid {
        return Err(Errno::EPERM);
    }
    // The signal number the caller asked for wins over whatever is in the
    // struct.
    info[..4].copy_from_slice(&(sig as i32).to_le_bytes());
    // POSIX.1b says nothing about process groups, and neither does Linux here:
    // the id names one task, so kill()'s negative and zero forms are simply not
    // found rather than reaching a whole group.
    if pid <= 0 {
        return Err(Errno::ESRCH);
    }
    do_kill(
        pid,
        sig,
        if thread_directed { tgid } else { 0 },
        thread_directed,
        Some(SigInfo::from_le_bytes(info)),
    )
}

/// The caller's `siginfo`: 128 bytes, of which the first 48 are read, so the
/// rest stays zero rather than being whatever the caller's buffer held past the
/// part it allocated.
///
/// It is read **before** either call looks at its ids. Linux copies in the
/// syscall wrapper and validates in the function below it — so
/// `rt_tgsigqueueinfo(0, 0, 0, NULL)` is `EFAULT` and not `EINVAL`, which is the
/// opposite of what a comment here used to assert.
fn read_siginfo(info_addr: u64) -> Result<RawSigInfo, Errno> {
    let mut info = RawSigInfo([0u8; 128]);
    if GuestMem.read(info_addr, &mut info.0[..SIGINFO_KERNEL_SIZE]) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(info)
}

/// `pidfd_send_signal(..., PIDFD_SIGNAL_PROCESS_GROUP)` with a caller's
/// `siginfo`: every process in group `pgid` gets it.
///
/// The si_code rule is `do_sigqueueinfo`'s, with the target never being the
/// caller's own thread -- Linux's `pidfd_send_signal` refuses a non-negative
/// code (or `SI_TKILL`) for any scope wider than a thread group.
/// The same without a siginfo: `kill(-pgid, sig)`, except that `pgid` is
/// always a process group -- `kill(-1)` is every process, and a group whose
/// id is 1 must not become that.
pub fn kill_pgrp(pgid: c_int, sig: c_uint) -> Result<(), Errno> {
    if sig > MAX_SIG {
        return Err(Errno::EINVAL);
    }
    let guard = kernel_pids::PidsGuard::take();
    super::kill::kill_group(&guard, pgid, sig, None)
}

pub fn pgrp_sigqueueinfo(pgid: c_int, sig: c_uint, info_addr: u64) -> Result<(), Errno> {
    let mut raw = read_siginfo(info_addr)?;
    if sig > MAX_SIG {
        return Err(Errno::EINVAL);
    }
    let code = i32::from_le_bytes(raw.0[8..12].try_into().unwrap());
    if code >= 0 || code == SI_TKILL {
        return Err(Errno::EPERM);
    }
    raw.0[..4].copy_from_slice(&(sig as i32).to_le_bytes());
    let guard = kernel_pids::PidsGuard::take();
    super::kill::kill_group(&guard, pgid, sig, Some(SigInfo::from_le_bytes(&raw.0)))
}

pub fn sys_rt_sigqueueinfo(tgid: c_int, sig: c_uint, info_addr: u64) -> Result<(), Errno> {
    strace!("rt_sigqueueinfo({tgid}, {sig}, {info_addr:#x})");
    let info = read_siginfo(info_addr)?;
    do_sigqueueinfo(tgid, tgid, sig, info, false)
}

pub fn sys_rt_tgsigqueueinfo(
    tgid: c_int,
    tid: c_int,
    sig: c_uint,
    info_addr: u64,
) -> Result<(), Errno> {
    strace!("rt_tgsigqueueinfo({tgid}, {tid}, {sig}, {info_addr:#x})");
    let info = read_siginfo(info_addr)?;
    // An id of zero is not "this group" here, it is a mistake.
    if tgid <= 0 || tid <= 0 {
        return Err(Errno::EINVAL);
    }
    do_sigqueueinfo(tgid, tid, sig, info, true)
}
