//! What a process may consume, and who may change it.
//!
//! `getrlimit`, `setrlimit` and `prlimit` from `kernel/resource.c`. Every rule
//! they apply — which of the sixteen resources exist and whether a change is
//! allowed — are `crates/kernel/rlimit`'s, and who may ask about another
//! process is `kernel_creds::Creds::may_prlimit`; what is here is the lookup
//! and the guest copies.
//!
//! # Why `prlimit` is the interesting one
//!
//! It names *another* process, so it has to find a task and then touch it, and
//! a task found through the registry can exit and be freed the moment
//! `pids_lock` is dropped. [`PidsGuard`] is what makes holding it across both
//! the only shape a Rust caller can write; the C spelled it as a `lock` and an
//! `unlock` at each of seven exits.
//!
//! Guest memory is touched **outside** that lock, at both ends: a copy can
//! fault, which reaches the memory subsystem, and `pids_lock` is not a lock to
//! be holding when that happens.

use std::ffi::{c_int, c_uint};

use kernel_pids::PidsGuard;
use kernel_rlimit as rlimit;
use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/// `pub` because `crates/kernel/syscalltable` names the two entry points in
/// it directly. They were reached by symbol until 2026-09-08, which needs no
/// dependency edge and so no visibility either.
pub mod ioprio;

mod rlimit_ops;
mod sched;
pub use rlimit_ops::{rlimit, sys_getrlimit64, sys_prlimit64, sys_setrlimit64};
pub use sched::{
    sys_getcpu, sys_getpriority, sys_sched_get_priority_max, sys_sched_get_priority_min,
    sys_sched_getaffinity, sys_sched_getattr, sys_sched_getparam, sys_sched_getscheduler,
    sys_sched_rr_get_interval, sys_sched_setaffinity, sys_sched_setattr, sys_sched_setparam,
    sys_sched_setscheduler, sys_setpriority,
};

// ---------------------------------------------------------------------------
// Affinity, priority and the scheduling policy
// ---------------------------------------------------------------------------

use kernel_schedabi as schedabi;

/// What the calling thread group's exited threads and reaped children
/// consumed, as a `struct rusage_`'s first four fields.
///
/// Two functions in `kernel/task.c` until 2026-09-03, both of which read
/// `current`, walked to `group->times` and asked `crates/kernel/grouprusage`.
/// The walk is `crates/kernel/taskview`'s and the accumulator was already this
/// crate's neighbour, so what is left is the conversion.
///
/// Zero for a thread with no task or no group, which is what the C would have
/// dereferenced.
fn group_rusage(children: bool) -> hostrusage::Rusage {
    let Some((own, kids)) = taskview::with_current_group_times(|t| t.both()) else {
        return hostrusage::Rusage::default();
    };
    times_rusage(if children { kids } else { own })
}

/// A group's accumulated times as a `Rusage`.
fn times_rusage(t: grouprusage::Times) -> hostrusage::Rusage {
    let mut out = hostrusage::Rusage::default();
    let (u, s) = (t.utime(), t.stime());
    out.utime = hostrusage::Timeval {
        sec: u.sec,
        usec: u.usec,
    };
    out.stime = hostrusage::Timeval {
        sec: s.sec,
        usec: s.usec,
    };
    out
}

// ---------------------------------------------------------------------------
// How many processors there are
// ---------------------------------------------------------------------------

/// The mask is kept in a word, so a host with more than 64 reports 64 — a
/// smaller answer than the truth rather than a wrong one, and nothing here
/// schedules by it anyway.
const CPU_MASK_BITS: u32 = 64;

/// How many processors a thread may be told it can run on.
///
/// `IUL_FAKE_NCPU` overrides it, which is how a guest can be shown a different
/// machine without one being found.
pub fn sched_online_cpus() -> c_uint {
    // `IUL_FAKE_NCPU`, or 0. A C accessor in `util/ish_env.c` until
    // 2026-09-04, written because this crate had no view of the struct.
    let fake = util_iulenv::env().fake_ncpu;
    let cpus = if fake > 0 {
        fake as i64
    } else {
        // `std`'s answer is `sysconf(_SC_NPROCESSORS_ONLN)` on Apple targets,
        // which is what this was.
        std::thread::available_parallelism().map_or(1, |n| n.get() as i64)
    };
    online_from(cpus)
}

/// The rule, without the host call: at least one, at most [`CPU_MASK_BITS`].
fn online_from(reported: i64) -> c_uint {
    reported.clamp(1, CPU_MASK_BITS as i64) as c_uint
}

/// Every processor, which is what a thread starts out allowed.
pub fn sched_all_cpus_mask() -> u64 {
    mask_for(sched_online_cpus())
}

/// `1 << cpus` minus one, and all ones at 64 — where the shift would be
/// undefined.
fn mask_for(cpus: c_uint) -> u64 {
    if cpus >= 64 {
        u64::MAX
    } else {
        (1u64 << cpus) - 1
    }
}

// ---------------------------------------------------------------------------
// getrusage
// ---------------------------------------------------------------------------

const RUSAGE_SELF: c_int = 0;
const RUSAGE_CHILDREN: c_int = -1;
const RUSAGE_THREAD: c_int = 1;

/// What a process, a thread or a set of reaped children consumed.
///
/// `RUSAGE_SELF` is the whole **thread group**. It reported the calling thread
/// only, so a process that had joined a worker was told it had used the main
/// thread's time and nothing else — which is the difference between a
/// single-threaded program and every other one.
///
pub fn sys_getrusage(who: c_int, rusage_addr: u64) -> Result<(), Errno> {
    strace!("getrusage({who}, {rusage_addr:#x})");
    let rusage = match who {
        // The whole thread group.
        RUSAGE_SELF => rusage_get_process(),
        RUSAGE_THREAD => hostrusage::thread_rusage(),
        RUSAGE_CHILDREN => group_rusage(true),
        _ => return Err(Errno::EINVAL),
    };
    if GuestMem::current().write_value(rusage_addr, &rusage) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// This thread group's consumed CPU time: every live thread's, and what its
/// exited threads left in the group's total.
///
/// **Every** live thread since 2026-11-11. It was this thread and the exited
/// ones, so a process whose main thread waited while a worker ran was told it
/// had used nothing: `getrusage(RUSAGE_SELF)` under-reported, and a relative
/// `clock_nanosleep` on `CLOCK_PROCESS_CPUTIME_ID` -- which waits for the
/// process clock to advance -- waited for ever. `adjtime_abi`'s CPU-clock
/// sleep is the test.
pub fn rusage_get_process() -> hostrusage::Rusage {
    task_cpu(0, false).unwrap_or_else(hostrusage::thread_rusage)
}

/// What a task has consumed, for the CPU-time clocks: one thread when
/// `per_thread`, else a whole thread group. `pid` 0 is the caller.
///
/// `None` where Linux's `pid_for_clock` finds no task: a pid nobody has, a
/// thread outside the caller's group (a thread clock is the caller's group's
/// business only), or a process clock named by a pid that is not a group
/// leader.
///
/// Under `pids_lock`, which is what makes a group's sum consistent: a thread
/// leaves the list and adds its time to the group's total in one hold of it
/// (`crates/kernel/exitcalls`' `do_exit`), so no thread is counted twice or
/// not at all. It is also what keeps each listed thread's pthread alive while
/// it is asked -- see `hostrusage::pthread_rusage`.
pub fn task_cpu(pid: c_int, per_thread: bool) -> Option<hostrusage::Rusage> {
    let pids = PidsGuard::take();
    let me = pids.me()?;
    let target = if pid == 0 { me } else { pids.find(pid)? };
    if per_thread {
        if target.group()?.id() != me.group()?.id() {
            return None;
        }
        if target.pid() == me.pid() {
            return Some(hostrusage::thread_rusage());
        }
        return Some(thread_cpu(target));
    }
    // `pid` 0 is the caller's group from any of its threads; a pid is a
    // process only if it is a group's leader.
    if pid != 0 && !target.is_leader() {
        return None;
    }
    let group = target.group()?;
    let mut ru = times_rusage(group.times().own());
    for t in group.threads() {
        add(&mut ru, &thread_cpu(t));
    }
    Some(ru)
}

/// One thread's time, asked of its host thread.
///
/// Nothing for one created and not yet started, and nothing for one that is
/// exiting or a zombie: its time is already in the group's total (it was
/// added in the same hold of `pids_lock` that marked it exiting), and its
/// pthread may be gone -- a zombie leader's has returned.
fn thread_cpu(t: kernel_pids::Task<'_>) -> hostrusage::Rusage {
    if t.is_exiting() || t.is_zombie() {
        return hostrusage::Rusage::default();
    }
    match t.task().thread.get() {
        // SAFETY: lent under `pids_lock` and not exiting, so its pthread is
        // still running it -- see `pthread_rusage`.
        Some(thread) => unsafe { hostrusage::pthread_rusage(thread) },
        None => hostrusage::Rusage::default(),
    }
}

/// Add `src`'s two times into `dst`.
///
/// Each is normalised on the way in — `crates/kernel/grouprusage` holds a total
/// rather than a pair and so has nothing to carry — so this carries once and
/// that is enough. The C carried once over two possibly-denormalised inputs,
/// which left a denormalised `src` denormalising `dst`.
///
/// There was a `#[no_mangle] rusage_add` wrapper over this until 2026-09-08.
/// Its only caller was `tests/unit/rusage_test.c`; the test is above and the
/// export went with it, which `tools/dead-exports.py` is what said so.
fn add(dst: &mut hostrusage::Rusage, src: &hostrusage::Rusage) {
    for (d, s) in [
        (&mut dst.utime as *mut _, &src.utime),
        (&mut dst.stime as *mut _, &src.stime),
    ] {
        let d: &mut hostrusage::Timeval = unsafe { &mut *d };
        let total = (d.sec + s.sec) * 1_000_000 + d.usec + s.usec;
        d.sec = total / 1_000_000;
        d.usec = total % 1_000_000;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// At least one processor and at most 64, whatever the host says. The cap
    /// is the mask's width: a bit per processor in one word, so 65 would drop
    /// one silently.
    #[test]
    fn the_processor_count_is_clamped_to_the_masks_width() {
        assert_eq!(online_from(0), 1, "a host that reports none");
        assert_eq!(online_from(-1), 1, "a sysconf that failed");
        assert_eq!(online_from(1), 1);
        assert_eq!(online_from(8), 8);
        assert_eq!(online_from(64), 64);
        assert_eq!(online_from(128), 64, "smaller than the truth, not wrong");
        assert_eq!(online_from(i64::MAX), 64);
    }

    /// And the mask that goes with it. 64 is all ones rather than `1 << 64`,
    /// which is undefined.
    #[test]
    fn the_mask_has_one_bit_per_processor() {
        assert_eq!(mask_for(1), 0b1);
        assert_eq!(mask_for(4), 0b1111);
        assert_eq!(mask_for(63), (1u64 << 63) - 1);
        assert_eq!(mask_for(64), u64::MAX);
        assert_eq!(mask_for(65), u64::MAX);
        assert_eq!(mask_for(0), 0);
    }

    /// The carry, which is what the C got wrong: it added both halves and
    /// carried **once**, so a denormalised input denormalised the total. Each
    /// value is turned into one number here, so there is nothing to carry
    /// twice.
    ///
    /// The sweep at the end was `tests/unit/rusage_test.c`'s until 2026-09-08:
    /// the two cases above are the ones that were wrong, and the sweep is what
    /// says the property holds for values nobody picked.
    #[test]
    fn adding_two_times_normalises_the_result() {
        let mut a = hostrusage::Rusage {
            utime: hostrusage::Timeval {
                sec: 1,
                usec: 900_000,
            },
            ..Default::default()
        };
        let b = hostrusage::Rusage {
            utime: hostrusage::Timeval {
                sec: 2,
                usec: 900_000,
            },
            ..Default::default()
        };
        add(&mut a, &b);
        assert_eq!(a.utime.sec, 4);
        assert_eq!(a.utime.usec, 800_000);

        // A denormalised input -- more than a second of microseconds -- comes
        // out normalised rather than carrying into the caller's next sum.
        let mut c = hostrusage::Rusage {
            stime: hostrusage::Timeval {
                sec: 0,
                usec: 5_500_000,
            },
            ..Default::default()
        };
        let d = hostrusage::Rusage {
            stime: hostrusage::Timeval {
                sec: 0,
                usec: 600_000,
            },
            ..Default::default()
        };
        add(&mut c, &d);
        assert_eq!(c.stime.sec, 6);
        assert_eq!(c.stime.usec, 100_000);

        // Whatever goes in, what comes out is normalised and worth the same.
        let mut usec = 0i64;
        while usec < 5_000_000 {
            let mut x = hostrusage::Rusage::default();
            let y = hostrusage::Rusage {
                utime: hostrusage::Timeval { sec: 0, usec },
                ..Default::default()
            };
            add(&mut x, &y);
            assert!(
                (0..1_000_000).contains(&x.utime.usec),
                "{usec} -> {:?}",
                x.utime
            );
            assert_eq!(x.utime.sec * 1_000_000 + x.utime.usec, usec);
            usec += 333_331;
        }
    }

    /// The three `who` values, and that nothing else is one.
    #[test]
    fn getrusage_knows_three_subjects() {
        assert_eq!((RUSAGE_SELF, RUSAGE_CHILDREN, RUSAGE_THREAD), (0, -1, 1));
        for who in [2, -2, 100, i32::MIN, i32::MAX] {
            assert!(
                !matches!(who, RUSAGE_SELF | RUSAGE_CHILDREN | RUSAGE_THREAD),
                "{who}"
            );
        }
    }
}
