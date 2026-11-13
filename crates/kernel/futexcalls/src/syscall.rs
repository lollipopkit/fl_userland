//! `futex(2)`'s dispatch: what each operation number means and how its
//! timeout is read.

use super::*;

/// Which clock an operation's timeout is measured against, and whether it is
/// absolute. `None` for an operation that takes no timeout, whose fourth
/// argument is `val2` instead -- Linux's `futex_cmd_has_timeout`.
///
/// `FUTEX_WAIT` is relative; `FUTEX_LOCK_PI` is absolute and **always**
/// `CLOCK_REALTIME`, which is its historical ABI and why `FUTEX_LOCK_PI2`
/// exists; the rest are absolute on `CLOCK_MONOTONIC` unless
/// `FUTEX_CLOCK_REALTIME` is set.
fn timeout_kind(cmd: u32, realtime: bool) -> Option<(bool, libc::clockid_t)> {
    let clock = if realtime { libc::CLOCK_REALTIME } else { libc::CLOCK_MONOTONIC };
    match cmd {
        cmd::WAIT => Some((false, libc::CLOCK_MONOTONIC)),
        cmd::LOCK_PI => Some((true, libc::CLOCK_REALTIME)),
        cmd::WAIT_BITSET | cmd::LOCK_PI2 | cmd::WAIT_REQUEUE_PI => Some((true, clock)),
        _ => None,
    }
}

pub fn sys_futex(
    uaddr: u64,
    op: u32,
    val: u32,
    timeout_or_val2: u64,
    uaddr2: u64,
    val3: u32,
) -> Result<i64, Errno> {
    let cmd = op & FUTEX_CMD_MASK;
    // Read from the *unmasked* word, as the clock flag is: FUTEX_CMD_MASK
    // strips both. A futex without it is keyed on the page rather than on the
    // address space, which is what makes one on a MAP_SHARED page one futex
    // across two processes -- see crates/kernel/futex.
    let private = op & FUTEX_PRIVATE_FLAG != 0;
    let realtime = op & FUTEX_CLOCK_REALTIME != 0;
    let w = Word { addr: uaddr, private };
    let w2 = Word { addr: uaddr2, private };

    // Linux's order, which `futex2_probe` measured: the timeout is read and
    // validated in `sys_futex` itself, then `do_futex` refuses the clock flag
    // and an unknown operation with `ENOSYS`, and only then does the operation
    // look at the address. An unknown operation on an unaligned address is
    // `ENOSYS` there, and a bad timeout pointer with one is `EFAULT`; both were
    // `EINVAL` here until 2026-11-11, when alignment was checked first.
    let deadline = match timeout_kind(cmd, realtime) {
        Some((absolute, clock)) if timeout_or_val2 != 0 => {
            let t = deadline::read(timeout_or_val2)?;
            if absolute { deadline::absolute(t, clock) } else { deadline::relative(t) }
        }
        _ => None,
    };

    // `FUTEX_CLOCK_REALTIME` says which clock an *absolute* deadline is
    // measured against, so it means nothing on an operation that has no
    // deadline -- and Linux answers `ENOSYS` rather than ignoring it, which is
    // how a caller finds out that the kernel is not doing what it asked.
    // `FUTEX_LOCK_PI` is `ENOSYS` with it too: its clock is fixed.
    if realtime && !matches!(cmd, cmd::WAIT_BITSET | cmd::WAIT_REQUEUE_PI | cmd::LOCK_PI2) {
        return Err(Errno::ENOSYS);
    }
    if !(cmd::WAIT..=cmd::LOCK_PI2).contains(&cmd) || cmd == 2 {
        // **ENOSYS**, which is what a real kernel answers for an operation
        // it does not have -- `FUTEX_FD` (2) was withdrawn in 2.6.26 and is
        // `ENOSYS` there, and so is any number past the last allocated one.
        //
        // This was `EINVAL` until 2026-09-03, on the reasoning that "most
        // userspace libraries fall back to FUTEX_WAKE/WAIT on EINVAL, where
        // ENOSYS reads as 'kernel too old' and makes them abort". That was
        // never measured against a library and it is the wrong way round:
        // `EINVAL` says the caller's *arguments* are wrong. `futex_probe` is
        // what says so: a real kernel answers `ENOSYS` for operation 14 and
        // for 99, and this answered `EINVAL` for both.
        futex_report_unsupported(op, cmd, uaddr, val, uaddr2, val3);
        return Err(Errno::ENOSYS);
    }

    // A futex word is a naturally aligned `u32`, and an address that is not is
    // `EINVAL` on every operation. Nothing checked it: `FUTEX_WAIT` on an
    // unaligned address **waited**, and `FUTEX_WAKE` on one answered 0, so a
    // guest that got its arithmetic wrong by a byte was told its two threads
    // were talking to each other while each was reading a different word.
    if !uaddr.is_multiple_of(4) {
        return Err(Errno::EINVAL);
    }
    let val2 = timeout_or_val2 as u32;

    // The operations below answer "how many, or an errno" in one i64.
    // `crates/kernel/futex` is the table they go through and that is its
    // convention; this is the one place it is read.
    Errno::split(match cmd {
        cmd::WAIT => {
            strace!("futex(FUTEX_WAIT, {uaddr:#x}, {val})");
            // FUTEX_WAIT is FUTEX_WAIT_BITSET with every bit set.
            let r = futex_wait(w, val, BITSET_MATCH_ANY, deadline);
            if r == Errno::EINTR.as_i64()
                && let Some(deadline) = deadline
            {
                leave_wait_block(w, val, deadline);
            }
            r
        }
        cmd::WAIT_BITSET => {
            // The mask is honoured. It used to be dropped, so a
            // FUTEX_WAKE_BITSET naming a disjoint set woke this thread anyway
            // -- the spurious wakeup the bitset exists to prevent, and glibc
            // uses it to keep a pthread_cond_broadcast from waking the signal
            // path's waiters. An empty mask is EINVAL; the queue answers it.
            strace!("futex(FUTEX_WAIT_BITSET, {uaddr:#x}, {val}, mask={val3:#x})");
            futex_wait(w, val, val3, deadline)
        }
        cmd::WAKE => {
            strace!("futex(FUTEX_WAKE, {uaddr:#x}, {val})");
            counted(kernel_futex::wake(&CurrentSpace::new(), w, wake_count(val as i32), BITSET_MATCH_ANY))
        }
        cmd::WAKE_BITSET => {
            strace!("futex(FUTEX_WAKE_BITSET, {uaddr:#x}, {val}, mask={val3:#x})");
            counted(kernel_futex::wake(&CurrentSpace::new(), w, wake_count(val as i32), val3))
        }
        cmd::REQUEUE => {
            strace!("futex(FUTEX_REQUEUE, {uaddr:#x}, {val}, {uaddr2:#x})");
            cmp_requeue(w, val, val2, w2, None)
        }
        cmd::CMP_REQUEUE => {
            strace!("futex(FUTEX_CMP_REQUEUE, {uaddr:#x}, {val}, {uaddr2:#x}, expected={val3})");
            cmp_requeue(w, val, val2, w2, Some(val3))
        }
        cmd::WAKE_OP => {
            strace!("futex(FUTEX_WAKE_OP, {uaddr:#x}, {val}, {uaddr2:#x}, {val3:#x})");
            wake_op(w, wake_count(val as i32), w2, wake_count(val2 as i32), val3)
        }
        cmd::LOCK_PI | cmd::LOCK_PI2 | cmd::TRYLOCK_PI => {
            strace!("futex(FUTEX_LOCK_PI*, {uaddr:#x}) cmd={cmd}");
            let try_only = cmd == cmd::TRYLOCK_PI;
            taskview::set_blocking(!try_only);
            let r = kernel_futex::lock_pi(&CurrentSpace::new(), w, current_tid(), &pi_owner_alive, deadline, try_only);
            taskview::set_blocking(false);
            r as i64
        }
        cmd::UNLOCK_PI => {
            strace!("futex(FUTEX_UNLOCK_PI, {uaddr:#x})");
            kernel_futex::unlock_pi(&CurrentSpace::new(), w, current_tid()) as i64
        }
        cmd::WAIT_REQUEUE_PI => {
            strace!("futex(FUTEX_WAIT_REQUEUE_PI, {uaddr:#x}, {val}, {uaddr2:#x})");
            if !uaddr2.is_multiple_of(4) || uaddr == uaddr2 {
                return Err(Errno::EINVAL);
            }
            taskview::set_blocking(true);
            let r = kernel_futex::wait_requeue_pi(
                &CurrentSpace::new(),
                w,
                val,
                w2,
                current_tid(),
                &pi_owner_alive,
                deadline,
            );
            taskview::set_blocking(false);
            r as i64
        }
        cmd::CMP_REQUEUE_PI => {
            strace!("futex(FUTEX_CMP_REQUEUE_PI, {uaddr:#x}, {val}, {uaddr2:#x}, expected={val3})");
            // Linux's order: the signed counts, then exactly one to wake --
            // the one the mutex is taken for -- then the two words being the
            // same. Measured by `futex2_probe`.
            if !rules::requeue_counts_ok(val, val2) || val != 1 {
                return Err(Errno::EINVAL);
            }
            if !uaddr2.is_multiple_of(4) || uaddr == uaddr2 {
                return Err(Errno::EINVAL);
            }
            counted(kernel_futex::cmp_requeue_pi(&CurrentSpace::new(), w, w2, val2, val3, &pi_owner_alive))
        }
        // Every other number was refused above.
        _ => ENOSYS,
    })
}

/// A `FUTEX_WAIT` with a relative timeout that a signal interrupted leaves the
/// deadline it became, for `restart_syscall` to wait out: Linux's
/// `futex_wait_restart`. A `FUTEX_WAIT_BITSET` deadline is absolute already
/// and restarts from the top (`kernel_syscallrestart::classify`).
fn leave_wait_block(w: Word, val: u32, deadline: std::time::Instant) {
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    let at = util_timeabi::monotonic_ns().saturating_add(left.as_nanos() as u64);
    let block = kernel_syscallrestart::Block {
        run: restart_wait,
        data: [w.addr, w.private as u64, val as u64, at],
    };
    taskview::with_current_restart(|r| r.set_block(block));
}

/// `restart_syscall` for an interrupted timed `FUTEX_WAIT`: the same wait, to
/// the same instant, which re-reads the word first as any wait does.
fn restart_wait(data: &[u64; 4]) -> i64 {
    let w = Word { addr: data[0], private: data[1] != 0 };
    let val = data[2] as u32;
    let left = std::time::Duration::from_nanos(data[3].saturating_sub(util_timeabi::monotonic_ns()));
    let deadline = std::time::Instant::now() + left;
    let r = futex_wait(w, val, BITSET_MATCH_ANY, Some(deadline));
    if r == Errno::EINTR.as_i64() {
        leave_wait_block(w, val, deadline);
    }
    r
}
