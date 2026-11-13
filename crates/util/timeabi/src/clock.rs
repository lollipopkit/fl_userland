//! Guest clock identifiers and host clock mapping.
//!
//! Two questions about a clock id, and Linux answers them in two places: what
//! a clock *reads* (its `k_clock`'s `clock_get_timespec`), and which of the
//! other clock syscalls it has at all (which members of the `k_clock` are
//! present). [`clock_of`] is the first and [`ops`] the second. They are kept
//! apart because the errno for a missing member is not the errno for a
//! missing clock: `clock_nanosleep(CLOCK_MONOTONIC_RAW)` is `EOPNOTSUPP`, and
//! `clock_nanosleep(99)` is `EINVAL`. Every row of [`ops`] was measured
//! against 7.2 by `tests/guest/src/bin/clock2_probe.rs` on 2026-11-11.

// --------------------------------------------------------------- the clocks

/// The guest's clock ids, from `kernel/time.h`.
pub const REALTIME: u32 = 0;
pub const MONOTONIC: u32 = 1;
pub const PROCESS_CPUTIME_ID: u32 = 2;
pub const THREAD_CPUTIME_ID: u32 = 3;
pub const MONOTONIC_RAW: u32 = 4;
pub const REALTIME_COARSE: u32 = 5;
pub const MONOTONIC_COARSE: u32 = 6;
pub const BOOTTIME: u32 = 7;
pub const REALTIME_ALARM: u32 = 8;
pub const BOOTTIME_ALARM: u32 = 9;
pub const TAI: u32 = 11;

/// The low three bits of a negative clock id that make it a dynamic POSIX
/// clock (`CLOCKFD`): `(~fd << 3) | 3`, a `/dev/ptp*` descriptor.
const CLOCKFD: i32 = 3;
/// The per-thread bit of an encoded CPU clock.
const CPUCLOCK_PERTHREAD: i32 = 4;

/// Which host clock a guest clock id is answered from, if any.
///
/// The pairing is not one to one and does not need to be: `CLOCK_MONOTONIC_RAW`
/// is monotonic without NTP slew and `CLOCK_BOOTTIME` counts suspended time,
/// neither of which this emulator can offer over a host that does not — and
/// answering with plain monotonic is closer than refusing.
///
/// `CLOCK_TAI` is the realtime clock plus the TAI offset, and the offset
/// `adjtimex` reports here is 0, which is also what a Linux machine reports
/// until something sets it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HostClock {
    Realtime,
    Monotonic,
}

/// What a CPU-time clock counts: `CPUCLOCK_PROF`, `CPUCLOCK_VIRT` and
/// `CPUCLOCK_SCHED`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CpuWhich {
    /// User and system time.
    Prof,
    /// User time only.
    Virt,
    /// Scheduled time, which is user plus system here: there is no separate
    /// runqueue accounting to report.
    Sched,
}

/// What a clock id names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Clock {
    /// A host clock.
    Host(HostClock),
    /// A task's consumed CPU time, answered from its own accounting and with
    /// no host clock behind it. `pid` 0 is the caller: that is what
    /// `CLOCK_PROCESS_CPUTIME_ID` and `CLOCK_THREAD_CPUTIME_ID` are, and an
    /// encoded `(~pid << 3) | which` id names another task or, with 0, the
    /// caller again.
    Cpu { pid: i32, per_thread: bool, which: CpuWhich },
    /// Not a clock that can be read: an unallocated id, a disabled
    /// auxiliary clock, a dynamic clock (there are no `/dev/ptp*` devices),
    /// or an encoded CPU clock whose kind is not one of the three.
    Invalid,
}

pub fn clock_of(id: u32) -> Clock {
    match id {
        REALTIME | REALTIME_COARSE | REALTIME_ALARM | TAI => Clock::Host(HostClock::Realtime),
        MONOTONIC | MONOTONIC_RAW | MONOTONIC_COARSE | BOOTTIME | BOOTTIME_ALARM => {
            Clock::Host(HostClock::Monotonic)
        }
        PROCESS_CPUTIME_ID => Clock::Cpu { pid: 0, per_thread: false, which: CpuWhich::Sched },
        THREAD_CPUTIME_ID => Clock::Cpu { pid: 0, per_thread: true, which: CpuWhich::Sched },
        _ => {
            let id = id as i32;
            if id >= 0 || id & 7 == CLOCKFD {
                return Clock::Invalid;
            }
            let which = match id & 3 {
                0 => CpuWhich::Prof,
                1 => CpuWhich::Virt,
                2 => CpuWhich::Sched,
                _ => return Clock::Invalid,
            };
            Clock::Cpu { pid: !(id >> 3), per_thread: id & CPUCLOCK_PERTHREAD != 0, which }
        }
    }
}

/// Which of the other clock syscalls a clock has: the members of its
/// `k_clock` beyond reading. `None` is no `k_clock` at all, which every one
/// of those syscalls answers `EINVAL`; a `false` here is `EOPNOTSUPP` for
/// `clock_nanosleep`, `timer_create` and `clock_adjtime`, and `EINVAL` for
/// `clock_settime`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Ops {
    /// `clock_settime`. Never granted here; this says whether the answer is
    /// the permission (`EPERM`) or the clock (`EINVAL`).
    pub set: bool,
    /// `clock_adjtime`.
    pub adjust: bool,
    /// `clock_nanosleep`.
    pub sleep: bool,
    /// `timer_create`.
    pub timer: bool,
    /// Sleeping and timers want `CAP_WAKE_ALARM`.
    pub alarm: bool,
}

pub fn ops(id: u32) -> Option<Ops> {
    let none = Ops::default();
    let waits = Ops { sleep: true, timer: true, ..none };
    Some(match id {
        REALTIME => Ops { set: true, adjust: true, ..waits },
        MONOTONIC | BOOTTIME | TAI | PROCESS_CPUTIME_ID => waits,
        THREAD_CPUTIME_ID => Ops { timer: true, ..none },
        MONOTONIC_RAW | REALTIME_COARSE | MONOTONIC_COARSE => none,
        REALTIME_ALARM | BOOTTIME_ALARM => Ops { alarm: true, ..waits },
        _ if (id as i32) >= 0 => return None,
        // A dynamic clock has a setter and an adjuster and nothing to sleep
        // on; the descriptor lookup that follows is what fails here.
        _ if (id as i32) & 7 == CLOCKFD => Ops { set: true, adjust: true, ..none },
        // `clock_posix_cpu`: settable in name (the answer is `EPERM`), and no
        // adjuster.
        _ => Ops { set: true, ..waits },
    })
}

/// Whether `id` is a dynamic POSIX clock, `(~fd << 3) | 3`.
pub fn is_dynamic(id: u32) -> bool {
    (id as i32) < 0 && (id as i32) & 7 == CLOCKFD
}
