//! The per-thread-group resource-limit state.
//!
//! This is a leaf because `struct tgroup` owns the state by value. The policy
//! and syscall-facing operations remain in `kernel-rlimit`; keeping the state
//! here avoids making the shared task types depend on their consumer.

use std::sync::atomic::{AtomicU64, Ordering};

/// A guest `struct rlimit`: two 64-bit values, soft then hard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Rlimit {
    pub cur: u64,
    pub max: u64,
}

const _: () = assert!(core::mem::size_of::<Rlimit>() == 16);

/// `RLIMIT_NLIMITS` — the number of resource slots.
pub const NLIMITS: u32 = 16;

/// `RLIM_INFINITY`: all ones, at whatever width.
pub const INFINITY: u64 = u64::MAX;

/// The sixteen resources, by number.
pub const STACK: u32 = 3;
pub const CORE: u32 = 4;
pub const NPROC: u32 = 6;
pub const NOFILE: u32 = 7;
pub const MEMLOCK: u32 = 8;
pub const SIGPENDING: u32 = 11;
pub const MSGQUEUE: u32 = 12;
pub const NICE: u32 = 13;
pub const RTPRIO: u32 = 14;

/// One slot, as two words a reader on another thread may load while a writer
/// stores.
#[derive(Debug, Default)]
struct Slot {
    cur: AtomicU64,
    max: AtomicU64,
}

/// One thread group's resource limits.
///
/// **Atomic since 2026-09-30.** It was a plain `[Rlimit; 16]` that
/// `setrlimit` and `prlimit` wrote through `&mut (*group).limits` holding
/// `pids_lock`, while every other thread of the group read its own soft
/// limits through `kernel_rlimit::current_soft` holding nothing -- the
/// descriptor limit on every open among them. That is a data race, and the
/// `&mut` asserted that no other thread was reading at all. The comments
/// beside both said the group's "limits lock" was held; the group has had no
/// lock since 2026-08-31.
///
/// Writers still hold `pids_lock` -- that is what makes a reader under the same
/// lock see a `cur` and `max` that belong together. A lock-free reader reads
/// one word, and the soft limit is the only one any of them asks for.
#[derive(Debug)]
pub struct Limits {
    table: [Slot; NLIMITS as usize],
}

impl Clone for Limits {
    /// A snapshot, for a new group copying its parent's.
    fn clone(&self) -> Self {
        let limits = Limits {
            table: Default::default(),
        };
        for resource in 0..NLIMITS {
            limits.set(resource, self.get(resource).expect("in range"));
        }
        limits
    }
}

impl Limits {
    /// The limits of a newly created group.
    pub fn defaults(max_pid: u64) -> Self {
        let inf = Rlimit {
            cur: INFINITY,
            max: INFINITY,
        };
        let mut table = [inf; NLIMITS as usize];
        table[STACK as usize] = Rlimit {
            cur: 128 * 1024 * 1024,
            max: INFINITY,
        };
        table[CORE as usize] = Rlimit {
            cur: 0,
            max: INFINITY,
        };
        table[NPROC as usize] = Rlimit {
            cur: max_pid,
            max: max_pid,
        };
        table[NOFILE as usize] = Rlimit {
            cur: 1024,
            max: 4096,
        };
        table[MEMLOCK as usize] = Rlimit {
            cur: 64 * 1024,
            max: 64 * 1024,
        };
        table[SIGPENDING as usize] = Rlimit {
            cur: 1024,
            max: 1024,
        };
        table[MSGQUEUE as usize] = Rlimit {
            cur: 819200,
            max: 819200,
        };
        table[NICE as usize] = Rlimit { cur: 0, max: 0 };
        table[RTPRIO as usize] = Rlimit { cur: 0, max: 0 };
        Self {
            table: table.map(|r| Slot {
                cur: AtomicU64::new(r.cur),
                max: AtomicU64::new(r.max),
            }),
        }
    }

    /// Read one resource slot.
    pub fn get(&self, resource: u32) -> Option<Rlimit> {
        let slot = self.table.get(resource as usize)?;
        Some(Rlimit {
            cur: slot.cur.load(Ordering::Relaxed),
            max: slot.max.load(Ordering::Relaxed),
        })
    }

    /// The soft limit alone, which is what a lock-free reader asks.
    pub fn soft(&self, resource: u32) -> Option<u64> {
        Some(self.table.get(resource as usize)?.cur.load(Ordering::Relaxed))
    }

    /// Replace one resource slot. The caller holds `pids_lock`, which is what
    /// serialises writers; see the type's comment.
    pub fn set(&self, resource: u32, value: Rlimit) -> bool {
        let Some(slot) = self.table.get(resource as usize) else {
            return false;
        };
        slot.cur.store(value.cur, Ordering::Relaxed);
        slot.max.store(value.max, Ordering::Relaxed);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_populate_every_resource_slot() {
        let limits = Limits::defaults(32768);
        for resource in 0..NLIMITS {
            assert!(
                limits.get(resource).is_some(),
                "missing resource {resource}"
            );
        }
        assert_eq!(
            limits.get(NPROC),
            Some(Rlimit {
                cur: 32768,
                max: 32768
            })
        );
        assert_eq!(
            limits.get(NOFILE),
            Some(Rlimit {
                cur: 1024,
                max: 4096
            })
        );
    }

    #[test]
    fn copied_limits_are_independent_values() {
        let original = Limits::defaults(32768);
        original.set(NOFILE, Rlimit { cur: 7, max: 9 });
        let copy = original.clone();
        original.set(NOFILE, Rlimit { cur: 1, max: 1 });
        assert_eq!(copy.get(NOFILE), Some(Rlimit { cur: 7, max: 9 }));
    }

    /// A writer on one thread and a lock-free reader on another, which is the
    /// arrangement a group has: `prlimit` from elsewhere, `current_soft` on the
    /// group's own threads. It needed a `&mut` to write until 2026-09-30, so
    /// this could not be written; the reader sees each value whole.
    #[test]
    fn a_reader_on_another_thread_sees_whole_values() {
        let limits = std::sync::Arc::new(Limits::defaults(32768));
        let writer = {
            let limits = limits.clone();
            std::thread::spawn(move || {
                for n in 0..10_000u64 {
                    let v = if n % 2 == 0 { 7 } else { u64::MAX - 7 };
                    limits.set(NOFILE, Rlimit { cur: v, max: v });
                }
            })
        };
        for _ in 0..10_000 {
            let cur = limits.soft(NOFILE).unwrap();
            assert!([1024, 7, u64::MAX - 7].contains(&cur), "torn: {cur:#x}");
        }
        writer.join().unwrap();
    }
}