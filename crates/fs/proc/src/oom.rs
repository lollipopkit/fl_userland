//! `/proc/<pid>/oom_score_adj` and the legacy `oom_adj`.
//!
//! Nothing here kills a process for memory: the host does that, and is not
//! told. The value is kept because a daemon that sets its own and reads it
//! back -- PostgreSQL's postmaster, Chromium, systemd -- failed the open while
//! the file was missing (until 2026-10-18). The rules are Linux's
//! `__set_oom_adj`, measured by `tests/guest` procfs_probe.

use std::ffi::c_int;

use guest_errno::c_int_::{EACCES, EINVAL, ESRCH};

use crate::ffi;
use crate::pidsnap::Found;

const MAX: i32 = 1000;
const MIN: i32 = -1000;
/// `OOM_DISABLE`, the legacy file's minimum, which means [`MIN`].
const LEGACY_MIN: i32 = -17;
/// `OOM_ADJUST_MAX`, which means [`MAX`].
const LEGACY_MAX: i32 = 15;

/// A written number: surrounding whitespace allowed, as Linux strips it.
fn parse(bytes: &[u8]) -> Result<i32, c_int> {
    std::str::from_utf8(bytes).ok().and_then(|s| s.trim().parse().ok()).ok_or(EINVAL)
}

/// What the legacy file shows for `adj`.
fn to_legacy(adj: i32) -> i32 {
    if adj == MAX { LEGACY_MAX } else { adj * -LEGACY_MIN / MAX }
}

/// What a legacy write of `v` sets.
fn from_legacy(v: i32) -> Result<i32, c_int> {
    match v {
        LEGACY_MAX => Ok(MAX),
        LEGACY_MIN..LEGACY_MAX => Ok(v * MAX / -LEGACY_MIN),
        _ => Err(EINVAL),
    }
}

/// Whether `new` may be set over `cur`, and the floor afterwards.
///
/// Without `CAP_SYS_RESOURCE` the legacy file may not lower the value at all,
/// and `oom_score_adj` may not take it below the floor -- which is where the
/// last privileged writer of `oom_score_adj` left it, 0 to begin with.
fn decide(new: i32, legacy: bool, cur: i32, min: i32, privileged: bool) -> Result<i32, c_int> {
    let floor = if legacy { cur } else { min };
    if new < floor && !privileged {
        return Err(EACCES);
    }
    Ok(if !legacy && privileged { new } else { min })
}

fn show(entry: &mut ffi::proc_entry, data: &mut ffi::proc_data, legacy: bool) -> c_int {
    let Some(found) = Found::get(entry) else {
        return ESRCH;
    };
    let adj = found.group().oom_score_adj();
    let shown = if legacy { to_legacy(adj) } else { adj };
    data.append(format!("{shown}\n").as_bytes());
    0
}

fn update(entry: &mut ffi::proc_entry, data: &mut ffi::proc_data, legacy: bool) -> c_int {
    let new = match parse(data.as_slice()).and_then(|v| {
        if legacy {
            from_legacy(v)
        } else if (MIN..=MAX).contains(&v) {
            Ok(v)
        } else {
            Err(EINVAL)
        }
    }) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let privileged = taskview::capable(taskview::caps::CAP_SYS_RESOURCE);
    let Some(found) = Found::get(entry) else {
        return ESRCH;
    };
    let group = found.group();
    match decide(new, legacy, group.oom_score_adj(), group.oom_score_adj_min(), privileged) {
        Ok(min) => {
            group.set_oom_score_adj(new, min);
            0
        }
        Err(e) => e,
    }
}

pub(crate) fn adj_show(entry: &mut ffi::proc_entry, data: &mut ffi::proc_data) -> c_int {
    show(entry, data, false)
}

pub(crate) fn adj_update(entry: &mut ffi::proc_entry, data: &mut ffi::proc_data) -> c_int {
    update(entry, data, false)
}

pub(crate) fn legacy_show(entry: &mut ffi::proc_entry, data: &mut ffi::proc_data) -> c_int {
    show(entry, data, true)
}

pub(crate) fn legacy_update(entry: &mut ffi::proc_entry, data: &mut ffi::proc_data) -> c_int {
    update(entry, data, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_with_whitespace_parses_and_anything_else_is_einval() {
        assert_eq!(parse(b" 42\n"), Ok(42));
        assert_eq!(parse(b"-5"), Ok(-5));
        assert_eq!(parse(b"abc"), Err(EINVAL));
        assert_eq!(parse(b""), Err(EINVAL));
    }

    #[test]
    fn the_legacy_scale_is_seventeenths_with_15_meaning_the_maximum() {
        assert_eq!(to_legacy(500), 8);
        assert_eq!(to_legacy(MAX), 15);
        assert_eq!(to_legacy(MIN), -17);
        assert_eq!(from_legacy(15), Ok(MAX));
        assert_eq!(from_legacy(-17), Ok(MIN));
        assert_eq!(from_legacy(16), Err(EINVAL));
        assert_eq!(from_legacy(-18), Err(EINVAL));
    }

    #[test]
    fn lowering_needs_privilege_below_the_floor_or_at_all_through_the_legacy_file() {
        // Measured: from 1000, `oom_score_adj` = 300 is allowed unprivileged
        // (the floor is 0), and `oom_adj` = 0 is EACCES.
        assert_eq!(decide(300, false, 1000, 0, false), Ok(0));
        assert_eq!(decide(-1, false, 1000, 0, false), Err(EACCES));
        assert_eq!(decide(0, true, 1000, 0, false), Err(EACCES));
        // Privileged: allowed, and `oom_score_adj` moves the floor with it.
        assert_eq!(decide(-500, false, 0, 0, true), Ok(-500));
        assert_eq!(decide(-1000, true, 0, 0, true), Ok(0));
    }
}
