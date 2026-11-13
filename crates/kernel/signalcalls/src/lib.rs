//! The signal syscalls that need neither the CPU nor the pid registry.
//!
//! Seven of `kernel/signal.c`'s fourteen `sys_*`: `rt_sigaction`,
//! `rt_sigprocmask`, `rt_sigpending`, `sigaltstack`, `pause`, `rt_sigsuspend`
//! and `rt_sigtimedwait`. What they have in common is that none of them touches
//! `struct cpu_state` beyond `sp` or needs to find another process — so they
//! are the part of the family that can move while `current` is still a C
//! `__thread` variable.
//!
//! The last three **wait**, on sighand's own lock, which is why they could not
//! be one-question entry points on `SigHand` and had to wait for the guard to
//! be reachable from Rust. `SigHandGuard::wait` releases the lock while parked,
//! so the queue is re-read on every pass — a wakeup is not an answer.
//!
//! Each takes the state it needs as arguments rather than reaching for
//! `current`, so the C side is a four-line wrapper that will disappear rather
//! than an accessor that will have to be unpicked. The state itself is already
//! owned here: [`kernel_sighand::SigHand`] and [`kernel_sigqueue::Signals`].
//!
//! ## The wire format is the reason this is worth moving
//!
//! `struct sigaction` as the guest passes it is not the struct this kernel uses
//! internally, and `kernel/signal.c` had two definitions and a set of
//! `static_assert`s keeping them apart:
//!
//! ```c
//! struct sigaction_arm64_kernel {
//!     uint64_t handler;
//!     uint64_t flags;      // 4 bytes in the internal one
//!     uint64_t restorer;
//!     uint64_t mask[1];
//! };
//! ```
//!
//! Every ABI defect this tree has had was an offset — `struct cmsghdr_` was
//! i386's, the signal frame was i386's, `siginfo_`'s union ended at 48. A
//! layout belongs somewhere the offsets are the code rather than a comment on
//! it, which is what [`SigActionAbi`] is.

use std::ffi::{c_int, c_uint};
use std::time::{Duration, Instant};

use kernel_sigdisp::Disposition;
use kernel_sighand::{Queue, SigHand, Woke};
use kernel_sigqueue::SigInfo;
use strace::strace;
use util_timeabi as timeabi;

mod abi;
pub use abi::{SigActionAbi, StackTAbi, read_sigset, sigset_size_valid, write_sigset};

pub use usercopy::GuestMem;
#[path = "kill.rs"]
mod kill;
mod waits;
pub use waits::{pause, rt_sigsuspend, rt_sigtimedwait};
mod sigqueue;
pub(crate) use kill::{Errno, MAX_SIG, do_kill, done};
pub use kill::{sys_kill, sys_restart_syscall, sys_tgkill, sys_tkill};
pub use sigqueue::{kill_pgrp, pgrp_sigqueueinfo, sys_rt_sigqueueinfo, sys_rt_tgsigqueueinfo};

#[cfg(test)]
mod tests;

/// Guest errnos, negated as everywhere else in the tree.
use guest_errno::c_int_::{EAGAIN, EFAULT, EINTR, EINVAL};

/// `how` for `rt_sigprocmask`.
const SIG_BLOCK: c_uint = 0;
const SIG_UNBLOCK: c_uint = 1;
const SIG_SETMASK: c_uint = 2;

// ---------------------------------------------------------------------------
// The syscalls
// ---------------------------------------------------------------------------

/// `rt_sigaction(2)`.
///
/// The read of the old disposition and the write of the new one happen under
/// **one** acquisition, which is `SigHand::get_set`. Two would let another
/// thread install something between them, and the value reported as "what it
/// was" would be something that never was.
pub fn rt_sigaction<M: usercopy::GuestIo>(
    sh: &SigHand,
    mem: &M,
    signum: u32,
    action_addr: u64,
    oldaction_addr: u64,
    sigset_size: u64,
) -> c_int {
    if !sigset_size_valid(sigset_size) {
        return EINVAL;
    }

    // `signum` is unsigned all the way down. It arrives from the guest as a
    // 32-bit word, and taking it as an `int` made 0x80000000 a large negative
    // number that compared *below* a `sig > MAX_SIG` bound and indexed the
    // table backwards; `rt_sigaction(0x80000000, ...)` crashed the emulator.
    let sig = signum as c_int;

    let new = if action_addr != 0 {
        match SigActionAbi::read(mem, action_addr, sigset_size) {
            Ok(d) => Some(d),
            Err(e) => return e,
        }
    } else {
        None
    };

    let mut old = Disposition::default();
    let want_old = oldaction_addr != 0;
    let err = sh.get_set(sig, want_old.then_some(&mut old), new.as_ref());
    if err != 0 {
        return err;
    }

    if want_old && let Err(e) = SigActionAbi::write(mem, oldaction_addr, sigset_size, &old) {
        return e;
    }
    0
}

/// `rt_sigprocmask(2)`.
///
/// `oldset` is reported **before** the change, and the `how` is validated
/// before anything is written, so a bad `how` leaves the mask alone.
pub fn rt_sigprocmask<M: usercopy::GuestIo>(
    queue: Queue<'_>,
    mem: &M,
    how: u32,
    set_addr: u64,
    oldset_addr: u64,
    size: u64,
) -> c_int {
    if !sigset_size_valid(size) {
        return EINVAL;
    }

    // The copy comes before the `how` is looked at, which is the order Linux
    // has and is observable: `rt_sigprocmask(99, <unmapped>, ...)` answers
    // EFAULT, not EINVAL.
    //
    // ```c
    // if (nset) {
    //         if (copy_from_user(&new_set, nset, sizeof(sigset_t)))
    //                 return -EFAULT;
    //         ...
    //         error = sigprocmask(how, &new_set, NULL);
    // ```
    let set = if set_addr != 0 {
        match read_sigset(mem, set_addr, size) {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    } else {
        None
    };

    if set.is_some() && !matches!(how, SIG_BLOCK | SIG_UNBLOCK | SIG_SETMASK) {
        return EINVAL;
    }

    // One acquisition covers the report and the change together, so a caller
    // that passes both pointers is told exactly what it replaced. The C took
    // the lock only for the change and read `blocked` for the report outside
    // it, which is a window another thread's sigprocmask fits through.
    let mut guard = queue.lock();
    let queue = guard.queue_mut();
    let previous = queue.blocked();
    if let Some(set) = set {
        let wanted = match how {
            SIG_BLOCK => previous | set,
            SIG_UNBLOCK => previous & !set,
            _ => set,
        };
        queue.set_blocked(kernel_sigdisp::maskable(wanted));
    }
    drop(guard);

    if oldset_addr != 0
        && let Err(e) = write_sigset(mem, oldset_addr, size, previous)
    {
        return e;
    }
    0
}

/// `rt_sigpending(2)`: what has arrived and is blocked.
///
/// The standard says the answer is the *blocked* pending signals. An unblocked
/// one is not pending, it is about to run.
///
/// **Its size rule is not its neighbours'.** Linux spells this one
///
/// ```c
/// if (sigsetsize > sizeof(*uset))
///         return -EINVAL;
/// ```
///
/// where `rt_sigprocmask` and `rt_sigsuspend` spell it `!=`. So a smaller size
/// is accepted here and copies that many bytes — a prefix of the mask — and
/// `rt_sigpending(NULL, 0)` is 0, writing nothing. That is not a symmetry
/// anybody would guess, and it was measured rather than read: this refused every
/// size but 8, which is right for the other two.
pub fn rt_sigpending<M: usercopy::GuestIo>(
    queue: Queue<'_>,
    mem: &M,
    set_addr: u64,
    size: u64,
) -> c_int {
    if size > 8 {
        return EINVAL;
    }
    // The thread's own and its process's: `sigpending(2)` is the union.
    let pending = queue.sigpending();
    // A zero-length copy touches nothing, so the address is never looked at —
    // `copy_to_user(NULL, x, 0)` succeeds on Linux and this has to as well.
    if size == 0 {
        return 0;
    }
    let bytes = pending.to_le_bytes();
    mem.write(set_addr, &bytes[..size as usize])
}

/// `sigaltstack(2)`.
///
/// `sp` is the guest's stack pointer, which decides both answers: whether the
/// thread is *running on* the alternate stack, which is `SS_ONSTACK` in the
/// report and `EPERM` for a change.
///
/// `q` is the calling thread's, because the stack is: it was the table's until
/// 2026-09-04, one per process, and every Go thread's `sigaltstack` overwrote
/// the one before it.
pub fn sigaltstack<M: usercopy::GuestIo>(
    queue: Queue<'_>,
    mem: &M,
    sp: u64,
    ss_addr: u64,
    old_ss_addr: u64,
) -> c_int {
    // The old one is reported first and from the same acquisition as the
    // change, so a caller that saves and restores gets what it replaced.
    let mut guard = queue.lock();

    if old_ss_addr != 0 {
        let (stack, size, flags) = guard.queue().altstack().report(sp);
        // The flags word writes the four padding bytes above `ss_flags` as
        // zero, which the C's struct write also did.
        for (off, word) in [
            (StackTAbi::SP, stack),
            (StackTAbi::FLAGS, flags as u64),
            (StackTAbi::SIZE, size),
        ] {
            if mem.write_u64(old_ss_addr + off, word) != 0 {
                return EFAULT;
            }
        }
    }

    if ss_addr == 0 {
        return 0;
    }

    let stack = match mem.read_u64(ss_addr + StackTAbi::SP) {
        Ok(v) => v,
        Err(_) => return EFAULT,
    };
    // The low half of the word: `ss_flags` is four bytes and the guest is
    // little-endian, so the padding above it is discarded rather than read as
    // part of the value.
    let flags = match mem.read_u64(ss_addr + StackTAbi::FLAGS) {
        Ok(v) => v as u32,
        Err(_) => return EFAULT,
    };
    let size = match mem.read_u64(ss_addr + StackTAbi::SIZE) {
        Ok(v) => v,
        Err(_) => return EFAULT,
    };

    match guard.queue_mut()
        .altstack_mut()
        .set(stack, size, flags, sp)
    {
        Ok(()) => 0,
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// The syscall entry points
// ---------------------------------------------------------------------------
//
// These six were `crates/kernel/signaldeliver`'s until 2026-09-09, and each was
// a `strace!` and a delegation to the function immediately below it here. That
// is what made the two crates mutually dependent: delivery called six of this
// crate's entry points, this crate called delivery's `signal_kill_task_for_rs`,
// and the cycle cargo refuses was settled with a hand-written `extern "C"`
// declaration whose `*mut task` was one of the last four to cross a C ABI
// boundary.
//
// The direction is not arbitrary. Choosing *which* tasks to signal is a
// syscall's question and is this crate's; *how* to deliver one is below it. So
// the entry points belong here, and delivery keeps no reason to know that
// syscalls exist -- the edge is gone rather than reversed.
//
// What they needed from delivery was `sig_state`, a two-field read of the
// calling task. That is `crates/kernel/taskview::current_sighand` and
// `current_sigqueue`, which is what its accessors are for.

/// Called on a guest thread, from the syscall table.
pub fn sys_rt_sigaction(
    signum: u32,
    action_addr: u64,
    oldaction_addr: u64,
    sigset_size: u64,
) -> Result<(), Errno> {
    strace!("rt_sigaction({signum}, {action_addr:#x}, {oldaction_addr:#x}, {sigset_size})");
    let answer = taskview::with_current_sighand(|sh| {
        let err = rt_sigaction(sh, &GuestMem::current(), signum, action_addr, oldaction_addr, sigset_size);
        let now_ignored = err == 0 && action_addr != 0 && sh.action(signum as c_int) == kernel_sigdisp::Action::Ignore;
        (err, now_ignored)
    });
    let (err, now_ignored) = answer.ok_or(Errno::EINVAL)?;
    if now_ignored {
        discard_pending(signum as c_int);
    }
    done(err)
}

/// POSIX's "setting a signal action to `SIG_IGN` for a signal that is pending
/// shall cause the pending signal to be discarded, whether or not it is
/// blocked" -- and a default that ignores, such as `SIGCHLD`'s, likewise:
/// Linux's `do_sigaction` empties it out of the process's shared set and every
/// thread's own. Nothing did, so a blocked `SIGUSR1` sent before `SIG_IGN`
/// was still there to `sigwait` for after it (`sigshared_probe`).
///
/// Under `pids_lock`, for the thread list, and each queue under sighand's lock
/// below it, which is the order everywhere.
fn discard_pending(sig: c_int) {
    let bit = kernel_sigqueue::mask_of(sig);
    let pids = kernel_pids::PidsGuard::take();
    let Some(group) = pids.me().and_then(|me| me.group()) else {
        return;
    };
    let mut shared_done = false;
    for thread in group.threads() {
        let Some(queue) = thread.signal_queue() else {
            continue;
        };
        let mut guard = queue.lock();
        let (own, shared) = guard.both_mut();
        own.retain(|info| kernel_sigqueue::mask_of(info.sig) != bit);
        if !shared_done {
            shared.retain(|info| kernel_sigqueue::mask_of(info.sig) != bit);
            shared_done = true;
        }
    }
}

/// Run `f` with the calling thread's signal state, or `EINVAL` for a thread
/// with none.
///
/// The one place the five entry points below reach it. Each wrote the same
/// `unsafe` pair -- `current_sighand().as_ref()` and
/// `current_sigqueue().as_mut()` -- and the second was a `&mut Signals` that
/// lived across a wait while other threads wrote the queue; see
/// `kernel_sighand::QueueGuard`. It is `taskview::with_current_queue` now,
/// which states the pairing once for every crate that needs it.
fn on_queue<T>(f: impl FnOnce(Queue<'_>) -> T) -> Result<T, Errno> {
    taskview::with_current_queue(f).ok_or(Errno::EINVAL)
}

pub fn sys_rt_sigprocmask(
    how: u32,
    set_addr: u64,
    oldset_addr: u64,
    size: u64,
) -> Result<(), Errno> {
    strace!(
        "rt_sigprocmask({}, {set_addr:#x}, {oldset_addr:#x}, {size})",
        match how {
            0 => "SIG_BLOCK",
            1 => "SIG_UNBLOCK",
            2 => "SIG_SETMASK",
            _ => "??",
        }
    );
    done(on_queue(|queue| rt_sigprocmask(queue, &GuestMem::current(), how, set_addr, oldset_addr, size))?)
}

pub fn sys_rt_sigpending(set_addr: u64, size: u64) -> Result<(), Errno> {
    strace!("rt_sigpending({set_addr:#x}, {size})");
    done(on_queue(|queue| rt_sigpending(queue, &GuestMem::current(), set_addr, size))?)
}

pub fn sys_sigaltstack(ss_addr: u64, old_ss_addr: u64) -> Result<(), Errno> {
    strace!("sigaltstack({ss_addr:#x}, {old_ss_addr:#x})");
    let task = taskview::current();
    if task.is_null() {
        return Err(Errno::EINVAL);
    }
    // `sp` decides both answers: whether the thread is running *on* the
    // alternate stack, which is SS_ONSTACK in the report and EPERM for a
    // change. The stack is the queue's -- this thread's -- and not the table's.
    // SAFETY: this thread's own task; `cpu` is written by this thread only.
    let sp = unsafe { (*(*task).cpu.get()).sp };
    done(on_queue(|queue| sigaltstack(queue, &GuestMem::current(), sp, ss_addr, old_ss_addr))?)
}

pub fn sys_rt_sigsuspend(mask_addr: u64, size: u64) -> Result<(), Errno> {
    strace!("sigsuspend({mask_addr:#x}, {size}) = ...");
    done(on_queue(|queue| rt_sigsuspend(queue, &GuestMem::current(), mask_addr, size))?)
}

pub fn sys_rt_sigtimedwait(
    set_addr: u64,
    info_addr: u64,
    timeout_addr: u64,
    set_size: u64,
) -> Result<i64, Errno> {
    strace!("sigtimedwait({set_addr:#x}, {info_addr:#x}, {timeout_addr:#x}, {set_size}) = ...");
    // Negative means "no timeout", which is what a null `timeout_addr` is. The
    // guest's timespec is read and judged here rather than in the crate: this
    // is the only argument of the four that is a *struct*, and the rule is the
    // same one pselect and timerfd apply.
    //
    // A negative second, a negative nanosecond, or a nanosecond field of a
    // whole second or more is EINVAL. Unchecked, they went into the wait
    // arithmetic and came back EAGAIN after actually waiting, so a caller that
    // passed a bad timeout was told its signal had not arrived.
    let mut timeout_ns: i64 = -1;
    if timeout_addr != 0 {
        let mut raw = [0u8; 16];
        if usercopy::GuestMem.read(timeout_addr, &mut raw) != 0 {
            return Err(Errno::EFAULT);
        }
        let sec = i64::from_le_bytes(raw[..8].try_into().unwrap());
        let nsec = i64::from_le_bytes(raw[8..].try_into().unwrap());
        if !timeabi::timespec_valid(sec, nsec) {
            return Err(Errno::EINVAL);
        }
        // Saturating, in crates/util/timeabi. `timespec_valid` puts no upper
        // bound on `tv_sec` -- Linux saturates -- so `LLONG_MAX` is a request a
        // real kernel accepts, and this multiply overflowed: a panic inside an
        // `extern "C"` function, which cannot unwind, so **one
        // `rt_sigtimedwait` from any guest aborted the emulator**.
        timeout_ns = timeabi::timespec_to_nsec(sec, nsec);
    }
    let timeout = (timeout_ns >= 0).then(|| Duration::from_nanos(timeout_ns as u64));
    // The **signal number** on success, which is what this one syscall in the
    // family answers, so `split` rather than `done`.
    let answer = on_queue(|queue| rt_sigtimedwait(queue, &GuestMem::current(), set_addr, info_addr, timeout, set_size))?;
    Errno::split(answer as i64)
}
