//! Stateless process attribute flags and scheduling policy rules.

use std::os::raw::c_int;

// ------------------------------------------------------- the small flags

/// `PR_MCE_KILL`'s two flags, `PF_MCE_PROCESS` and `PF_MCE_EARLY`.
pub(crate) mod mce {
    pub const PROCESS: u8 = 1;
    pub const EARLY: u8 = 2;

    pub const KILL_CLEAR: u64 = 0;
    pub const KILL_SET: u64 = 1;
    pub const KILL_LATE: u64 = 0;
    pub const KILL_EARLY: u64 = 1;
    pub const KILL_DEFAULT: u64 = 2;
}

/// `PR_SPEC_*`: what a task has asked about speculative store bypass.
pub mod spec {
    pub const STORE_BYPASS: u64 = 0;

    pub const PRCTL: u64 = 1 << 0;
    pub const ENABLE: u64 = 1 << 1;
    pub const DISABLE: u64 = 1 << 2;
    pub const FORCE_DISABLE: u64 = 1 << 3;
    pub const DISABLE_NOEXEC: u64 = 1 << 4;

    /// The per-task bits, `TIF_SSBD` and its two qualifiers.
    pub(crate) const SSB_DISABLE: u8 = 1;
    pub(crate) const SSB_FORCE_DISABLE: u8 = 2;
    pub(crate) const SSB_NOEXEC: u8 = 4;
}

/// The three non-realtime scheduling policies, which are the three this kernel
/// accepts. `sched(7)`'s numbers.
pub const SCHED_OTHER: u8 = 0;
pub const SCHED_BATCH: u8 = 3;
pub const SCHED_IDLE: u8 = 5;

/// Whether `sched_setscheduler` may be given this policy.
///
/// The realtime ones are refused rather than remembered: see
/// [`ThreadAttr::sched_policy`] for why the two groups are not treated alike.
pub fn sched_policy_supported(policy: c_int) -> bool {
    matches!(policy, 0 | 3 | 5)
}
