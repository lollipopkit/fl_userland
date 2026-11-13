//! Linux I/O priority validation and aggregation rules.

use std::os::raw::c_int;

use crate::ThreadAttr;

// ------------------------------------------------------------------ ioprio
//
// Nothing here schedules I/O. What is worth having is the shape of the answers,
// and every number below was measured against a real arm64 kernel rather than
// read from the man page — which describes a `data` field of 0..7 and is
// describing a kernel from before the field was split.
//
// On 6.x the low **three** bits are the level and bits 3..12 are a "hint":
//
//     #define IOPRIO_LEVEL_NR_BITS 3
//     #define IOPRIO_PRIO_LEVEL(ioprio) ((ioprio) & IOPRIO_LEVEL_MASK)
//
// so `IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 8)` has a level of *zero* and is
// accepted, while 7 and 15 are refused. Writing the obvious `level > 7` gets
// that backwards in both directions.

/// Where the class sits in an ioprio value.
pub const IOPRIO_CLASS_SHIFT: u32 = 13;
pub(crate) const IOPRIO_CLASS_MASK: u32 = 0x07;
/// Three bits, not thirteen. See above.
pub(crate) const IOPRIO_LEVEL_MASK: u32 = 0x07;

pub(crate) const IOPRIO_CLASS_NONE: u32 = 0;
pub(crate) const IOPRIO_CLASS_RT: u32 = 1;
pub(crate) const IOPRIO_CLASS_BE: u32 = 2;
pub(crate) const IOPRIO_CLASS_IDLE: u32 = 3;

/// A task that has never asked for one. `IOPRIO_CLASS_NONE` at level 0, which
/// is what `ioprio_get(IOPRIO_WHO_PROCESS)` answers for a fresh process.
pub(crate) const IOPRIO_NONE: u16 = 0;

/// What `ioprio_best` substitutes for a value that names no class: best-effort
/// at the middle level. `ioprio_get` for a *group* or a *user* answers this for
/// a set of tasks that have all left theirs alone, where the same question
/// about one task answers 0.
pub const IOPRIO_BEST_DEFAULT: i32 = ((IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4) as i32;

/// `IOPRIO_WHO_PROCESS`, `_PGRP`, `_USER`. Anything else is `EINVAL`, and that
/// is checked before the target is looked up.
pub fn ioprio_which_valid(which: i32) -> bool {
    (1..=3).contains(&which)
}

/// Whether a priority may be set at all, without a task to set it on.
///
/// Linux calls `ioprio_check_cap` at the very top of `ioprio_set`, **before**
/// it looks at `which` or resolves `who`. So a malformed priority aimed at a
/// pid that does not exist is `EINVAL` and not `ESRCH`, and a caller probing
/// for real-time support learns the answer without needing a live target.
pub fn ioprio_check(value: u32, privileged: bool) -> Result<(), c_int> {
    ThreadAttr::default()
        .set_ioprio(value, privileged)
        .map(|_| ())
}

/// Fold two priorities the way `ioprio_get` does over a group or a user: a
/// value that names no class counts as [`IOPRIO_BEST_DEFAULT`], and the lower
/// number wins because a lower class number is a higher priority.
pub fn ioprio_best(a: i32, b: i32) -> i32 {
    fn valid(p: i32) -> i32 {
        let class = ((p as u32) >> IOPRIO_CLASS_SHIFT) & IOPRIO_CLASS_MASK;
        if class == IOPRIO_CLASS_NONE || class > IOPRIO_CLASS_IDLE {
            IOPRIO_BEST_DEFAULT
        } else {
            p
        }
    }
    valid(a).min(valid(b))
}
