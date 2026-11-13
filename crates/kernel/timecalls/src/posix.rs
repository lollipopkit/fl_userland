//! POSIX timer syscalls and guest sigevent handling.

use std::ffi::{c_int, c_uint};

use kernel_pids::TaskRef;
use kernel_posixtimers::Notify;
use strace::strace;
use usercopy::GuestMem;
use util_timeabi as timeabi;
use util_timer::{Spec, Timespec};

use crate::ffi;

use super::timers::{leader_ref, with_posix_timers, thread_ref};
use super::wire::{read_pair, write_pair};
use guest_errno::Errno;

use super::host_clock_id;

// ---------------------------------------------------------------------------
// POSIX timers
// ---------------------------------------------------------------------------

// How a POSIX timer says it wants to be told. SIGEV_THREAD is libc's, and
// reaches the kernel only from a libc that passes it through.
const SIGEV_SIGNAL: c_int = 0;
const SIGEV_NONE: c_int = 1;
const SIGEV_THREAD: c_int = 2;
const SIGEV_THREAD_ID: c_int = 4;
/// `SIGALRM`, the default a NULL sigevent means.
const SIGALRM: c_int = 14;
/// `timer_settime`'s only flag.
const TIMER_ABSTIME: c_int = 1;

/// The guest's `struct sigevent`: a `sigval` at 0, the signal at 8, the method
/// at 12, and for `SIGEV_THREAD_ID` a tid at 16. 64 bytes; the rest is padding
/// for fields libc fills in and never passes.
struct Sigevent {
    value: u64,
    signo: c_int,
    method: c_int,
    tid: c_int,
}

fn read_sigevent(addr: u64) -> Result<Sigevent, Errno> {
    if addr == 0 {
        // A NULL sigevent is SIGEV_SIGNAL delivering SIGALRM to the process,
        // which is POSIX's default and Linux's. musl's timer_create passes NULL
        // for the common `timer_create(clock, NULL, &id)` form -- coreutils
        // `timeout` among them -- and reading through it was EFAULT, so every
        // such call failed spuriously.
        return Ok(Sigevent {
            value: 0,
            signo: SIGALRM,
            method: SIGEV_SIGNAL,
            tid: 0,
        });
    }
    let mut b = [0u8; 20];
    if GuestMem.read(addr, &mut b) != 0 {
        return Err(Errno::EFAULT);
    }
    let i32_at = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    Ok(Sigevent {
        value: u64::from_le_bytes(b[..8].try_into().unwrap()),
        signo: i32_at(8),
        method: i32_at(12),
        tid: i32_at(16),
    })
}

pub fn sys_timer_create(
    clock: c_uint,
    sigevent_addr: u64,
    timer_addr: u64,
) -> Result<(), Errno> {
    strace!("timer_create({clock}, {sigevent_addr:#x}, {timer_addr:#x})");
    // Linux's order, measured by `clock2_probe`: the sigevent is copied first
    // (`EFAULT`), then the clock (`EINVAL` for none, `EOPNOTSUPP` for one
    // that cannot arm a timer -- the raw and coarse clocks, which were
    // accepted here until 2026-11-11), then the sigevent's rules, and only
    // then the clock's own: the alarm clocks' capability.
    let sigev = read_sigevent(sigevent_addr)?;
    let Some(ops) = timeabi::ops(clock) else {
        return Err(Errno::EINVAL);
    };
    if !ops.timer {
        return Err(Errno::EOPNOTSUPP);
    }
    // `SIGEV_THREAD` reaches the kernel too, from a libc that does not
    // implement it in userspace, and Linux treats it as `SIGEV_SIGNAL`.
    if !matches!(sigev.method, SIGEV_SIGNAL | SIGEV_NONE | SIGEV_THREAD | SIGEV_THREAD_ID) {
        return Err(Errno::EINVAL);
    }
    // The signal, for the methods that send one. `good_sigevent` checks it at
    // creation, not at expiry, which is the difference a caller can act on: a
    // timer created with a signal that does not exist would otherwise arm,
    // count down and deliver nothing. **Signal 0 is refused**: this accepted
    // it, under a comment saying it meant "no signal" as `kill(pid, 0)` does,
    // and 7.2 answers `EINVAL` (`clock2_probe`).
    if sigev.method != SIGEV_NONE && !(1..=ffi::MAX_SIG as c_int).contains(&sigev.signo) {
        return Err(Errno::EINVAL);
    }

    // Which thread hears about it, as a reference rather than a number, so a
    // thread that exits and whose number goes to another task is not
    // signalled through that task. The process is addressed through its group
    // leader: this used to store 0, and the callback looks the pid up, so every
    // SIGEV_SIGNAL timer -- the default -- was created, armed, counted down,
    // and delivered nothing.
    let target = match sigev.method {
        SIGEV_THREAD_ID => thread_ref(sigev.tid).ok_or(Errno::EINVAL)?,
        SIGEV_SIGNAL | SIGEV_THREAD => leader_ref().ok_or(Errno::EINVAL)?,
        _ => TaskRef::default(),
    };
    if ops.alarm {
        return Err(Errno::EPERM);
    }
    let h = match timeabi::clock_of(clock) {
        timeabi::Clock::Host(h) => h,
        // A CPU-time timer would need a running total of the task's CPU time
        // to hang a deadline on, and there is none: it is sampled from the
        // host on demand, which is why ITIMER_VIRTUAL and ITIMER_PROF are
        // refused as well (`crates/kernel/timecalls/src/timers.rs`). The clock
        // is checked first, so a pid that is not one is still `EINVAL`.
        timeabi::Clock::Cpu { pid, per_thread, which } => {
            super::cpu_clock(pid, per_thread, which)?;
            return Err(Errno::EOPNOTSUPP);
        }
        timeabi::Clock::Invalid => return Err(Errno::EINVAL),
    };

    let notify: Option<Notify> = match sigev.method {
        SIGEV_NONE => None,
        SIGEV_THREAD_ID => Some(super::timers::notify_thread),
        _ => Some(super::timers::notify_process),
    };
    with_posix_timers(|timers| {
        let id = timers.create(
            host_clock_id(h) as c_int,
            notify,
            sigev.signo,
            sigev.value,
            target,
        );
        if id < 0 {
            return Err(Errno::from_negative_or_eio(id));
        }
        if GuestMem.write(timer_addr, &id.to_le_bytes()) != 0 {
            timers.delete(id);
            return Err(Errno::EFAULT);
        }
        Ok(())
    })?
}

pub fn sys_timer_settime(
    timer_id: c_uint,
    flags: c_int,
    new_value_addr: u64,
    old_value_addr: u64,
) -> Result<(), Errno> {
    strace!("timer_settime({timer_id}, {flags}, {new_value_addr:#x}, {old_value_addr:#x})");
    // A null new value is `EINVAL` rather than `EFAULT` -- Linux tests the
    // pointer against NULL before it copies, so "you gave me no new setting" and
    // "the setting you gave me is unreadable" are different answers. This
    // answered `EFAULT` for both. `setitimer` is the opposite: a null new value
    // there means disarm, and is 0.
    if new_value_addr == 0 {
        return Err(Errno::EINVAL);
    }
    let [int_sec, int_nsec, val_sec, val_nsec] = read_pair(new_value_addr)?;
    // Both halves, and the interval even when the value is zero. A POSIX timer
    // with an unchecked interval re-arms itself at whatever the nonsense works
    // out to, for the life of the process.
    if !timeabi::itimerspec_valid(val_sec, val_nsec, int_sec, int_nsec) {
        return Err(Errno::EINVAL);
    }

    // The bound is the table's. Every one of the four entry points here used to
    // carry its own, and two of them were wrong.
    let spec = Spec {
        value: Timespec {
            sec: val_sec,
            nsec: val_nsec,
        },
        interval: Timespec {
            sec: int_sec,
            nsec: int_nsec,
        },
    };
    let mut old = Spec::default();
    let err = with_posix_timers(|timers| {
        timers.set(timer_id as c_int, flags & TIMER_ABSTIME != 0, spec, &mut old)
    })?;
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    if old_value_addr != 0 {
        let out = [
            old.interval.sec,
            old.interval.nsec,
            old.value.sec,
            old.value.nsec,
        ];
        write_pair(old_value_addr, out)?;
    }
    Ok(())
}

pub fn sys_timer_gettime(timer_id: c_uint, curr_value_addr: u64) -> Result<(), Errno> {
    strace!("timer_gettime({timer_id}, {curr_value_addr:#x})");
    let mut spec = Spec::default();
    let err = with_posix_timers(|timers| timers.get(timer_id as c_int, &mut spec))?;
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    let out = [
        spec.interval.sec,
        spec.interval.nsec,
        spec.value.sec,
        spec.value.nsec,
    ];
    write_pair(curr_value_addr, out)
}

pub fn sys_timer_getoverrun(timer_id: c_uint) -> Result<i64, Errno> {
    strace!("timer_getoverrun({timer_id})");
    Errno::split(with_posix_timers(|timers| timers.overrun(timer_id as c_int))? as i64)
}

pub fn sys_timer_delete(timer_id: c_uint) -> Result<(), Errno> {
    strace!("timer_delete({timer_id})");
    Errno::split(with_posix_timers(|timers| timers.delete(timer_id as c_int))? as i64).map(|_| ())
}
