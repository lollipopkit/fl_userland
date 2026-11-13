//! `prctl(PR_FUTEX_HASH)`: the size of a process's private futex hash.
//!
//! Linux 6.17 gave each process its own futex hash table, sized on the first
//! `clone(CLONE_THREAD | CLONE_VM)` and resizable with this `prctl`. This
//! kernel has one queue for every futex (see `crates/kernel/futex`) and nothing
//! to resize, so what is kept is the **answer**: what a program set and what
//! Linux would report. That is all the interface lets a program observe -- the
//! number of buckets changes how long a wake takes, never what it does.
//!
//! The rules, each a line of `tests/guest/src/bin/futex2_probe.rs` on a real
//! kernel:
//!
//! - `GET_SLOTS` is 0 until the address space's first thread, and then the
//!   default, `roundup_pow_of_two(4 * min(threads, cpus))` clamped to at least
//!   16 -- recomputed on each new thread, never shrinking, and never once a
//!   size was set;
//! - `SET_SLOTS n` takes 0 or a power of two of at least 2, read as an
//!   `unsigned int`; 0 moves the process to the global hash, after which every
//!   `SET_SLOTS` is `EBUSY` and `GET_SLOTS` is 0;
//! - a flags word (`arg4`) that is not 0 is `EINVAL`, and `arg5` is ignored;
//! - a size whose table Linux cannot allocate is `ENOMEM`. 2^20 slots succeed
//!   there and 2^31 do not; the line between is the machine's memory, so this
//!   draws it at 2^24 (a gibibyte of 64-byte buckets) and says so.
//!
//! The state is `mm.futex_hash`, so a fork child and an `execve` start from 0,
//! which is what Linux's fresh `mm` does.

use std::sync::atomic::{AtomicU32, Ordering};

use guest_errno::Errno;
use strace::strace;

const SET_SLOTS: u64 = 1;
const GET_SLOTS: u64 = 2;

/// The state word: a tag in the top two bits, a slot count below.
const TAG_SHIFT: u32 = 30;
const SLOTS_MASK: u32 = (1 << TAG_SHIFT) - 1;
/// No private hash yet: the space has never had a second thread.
const NONE: u32 = 0;
/// The size Linux picks, which grows with the thread count.
const DEFAULT: u32 = 1 << TAG_SHIFT;
/// A size the program set.
const CUSTOM: u32 = 2 << TAG_SHIFT;
/// `SET_SLOTS 0`: the global hash, for good.
const GLOBAL: u32 = 3 << TAG_SHIFT;

/// Above this, `ENOMEM`; see the module comment.
const MAX_SLOTS: u32 = 1 << 24;

fn slots_of(state: u32) -> u32 {
    match state & !SLOTS_MASK {
        DEFAULT | CUSTOM => state & SLOTS_MASK,
        _ => 0,
    }
}

/// The default for a space with `threads` threads already, on `cpus`.
fn default_slots(threads: u32, cpus: u32) -> u32 {
    let n = (4 * threads.min(cpus).max(1)).next_power_of_two();
    // Linux clamps to its global hash's size too, `roundup_pow_of_two(256 *
    // cpus)`, which is always at least 4 * cpus and so never binds here.
    n.max(16)
}

/// A thread is being added to a space that already has `threads`: Linux's
/// `futex_hash_allocate_default`. `crates/kernel/forkcalls` calls this for
/// every `CLONE_THREAD`.
pub fn thread_created(state: &AtomicU32, threads: u32) {
    let want = DEFAULT | default_slots(threads, rescalls::sched_online_cpus());
    let _ = state.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| match cur & !SLOTS_MASK {
        NONE => Some(want),
        DEFAULT if slots_of(cur) < slots_of(want) => Some(want),
        _ => None,
    });
}

/// What `SET_SLOTS` does to `state`: the new word, or the errno.
fn set(cur: u32, slots: u32, flags: u64) -> Result<u32, Errno> {
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    if cur & !SLOTS_MASK == GLOBAL {
        return Err(Errno::EBUSY);
    }
    match slots {
        0 => Ok(GLOBAL),
        1 => Err(Errno::EINVAL),
        n if !n.is_power_of_two() => Err(Errno::EINVAL),
        n if n > MAX_SLOTS => Err(Errno::ENOMEM),
        n => Ok(CUSTOM | n),
    }
}

/// `prctl(PR_FUTEX_HASH, op, arg3, arg4, arg5)`.
pub fn prctl_futex_hash(op: u64, arg3: u64, arg4: u64, _arg5: u64) -> Result<i64, Errno> {
    strace!("prctl(PR_FUTEX_HASH, {op}, {arg3}, {arg4})");
    taskview::with_current_mm(|mm| {
        let state = &mm.futex_hash;
        match op {
            GET_SLOTS => Ok(slots_of(state.load(Ordering::Relaxed)) as i64),
            SET_SLOTS => {
                // An `unsigned int`: 2^40 is 0, which is the global hash.
                let slots = arg3 as u32;
                let mut cur = state.load(Ordering::Relaxed);
                loop {
                    let new = set(cur, slots, arg4)?;
                    match state.compare_exchange(cur, new, Ordering::Relaxed, Ordering::Relaxed) {
                        Ok(_) => return Ok(0),
                        Err(now) => cur = now,
                    }
                }
            }
            _ => Err(Errno::EINVAL),
        }
    })
    .unwrap_or(Err(Errno::EINVAL))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_four_per_thread_and_at_least_sixteen() {
        assert_eq!(default_slots(1, 8), 16);
        assert_eq!(default_slots(4, 8), 16);
        assert_eq!(default_slots(5, 8), 32);
        assert_eq!(default_slots(100, 8), 32, "bounded by the cpus");
        assert_eq!(default_slots(100, 64), 256);
    }

    #[test]
    fn a_new_thread_sets_the_default_and_never_shrinks_or_overrides() {
        let s = AtomicU32::new(NONE);
        s.store(DEFAULT | 64, Ordering::Relaxed);
        thread_created(&s, 1);
        assert_eq!(slots_of(s.load(Ordering::Relaxed)), 64, "never shrinks");
        s.store(CUSTOM | 2, Ordering::Relaxed);
        thread_created(&s, 1);
        assert_eq!(s.load(Ordering::Relaxed), CUSTOM | 2, "a set size stays");
        s.store(GLOBAL, Ordering::Relaxed);
        thread_created(&s, 1);
        assert_eq!(s.load(Ordering::Relaxed), GLOBAL);
        s.store(NONE, Ordering::Relaxed);
        thread_created(&s, 1);
        assert_eq!(slots_of(s.load(Ordering::Relaxed)), 16);
    }

    #[test]
    fn set_follows_the_kernel() {
        assert_eq!(set(NONE, 16, 0), Ok(CUSTOM | 16));
        assert_eq!(set(NONE, 2, 0), Ok(CUSTOM | 2));
        assert_eq!(set(NONE, 1, 0), Err(Errno::EINVAL));
        assert_eq!(set(NONE, 3, 0), Err(Errno::EINVAL));
        assert_eq!(set(NONE, 6, 0), Err(Errno::EINVAL));
        assert_eq!(set(NONE, u32::MAX, 0), Err(Errno::EINVAL));
        assert_eq!(set(NONE, 1 << 20, 0), Ok(CUSTOM | 1 << 20));
        assert_eq!(set(NONE, 1 << 31, 0), Err(Errno::ENOMEM));
        assert_eq!(set(NONE, 16, 1), Err(Errno::EINVAL));
        assert_eq!(set(DEFAULT | 16, 0, 0), Ok(GLOBAL));
        assert_eq!(set(GLOBAL, 16, 0), Err(Errno::EBUSY));
        assert_eq!(set(GLOBAL, 0, 0), Err(Errno::EBUSY));
        assert_eq!(slots_of(GLOBAL), 0);
        assert_eq!(slots_of(NONE), 0);
    }
}
