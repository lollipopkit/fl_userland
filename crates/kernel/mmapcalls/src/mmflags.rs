//! Linux's `mm->flags`, the part of it a guest sets: whether transparent huge
//! pages are wanted, and whether the address space refuses to gain executable
//! memory — `PR_SET_THP_DISABLE` and `PR_SET_MDWE`.
//!
//! Both are per address space rather than per thread, which is why they are
//! this crate's and not `crates/kernel/procattr`'s: every thread of a process
//! shares them, and a fork copies them. What each rule below is is
//! `kernel/sys.c`'s, with its argument checks in the order Linux applies them.
//!
//! # MDWE is enforced, not remembered
//!
//! `PR_SET_MDWE(PR_MDWE_REFUSE_EXEC_GAIN)` is a promise to the process that it
//! will never again hold memory that is both writable and executable, and that
//! memory which was not executable will not become so. A kernel that stored the
//! bit and honoured none of it would be telling a hardened program it was
//! protected. So `mmap` and `mprotect` ask [`deny_write_exec`] — Linux's
//! `map_deny_write_exec` — and answer `EACCES` where it says so. The setting is
//! one-way: it can be asked for again with the same bits, and asked for
//! differently it is `EPERM`.
//!
//! # THP disable is remembered
//!
//! There are no huge pages here to disable. What a program reads back is what
//! it set, with the 6.x extension that `PR_THP_DISABLE_EXCEPT_ADVISED` may ride
//! along on a disable and on nothing else.
//!
//! # What a new address space inherits
//!
//! Linux's `mmf_init_flags`: everything here, unless `PR_MDWE_NO_INHERIT` was
//! asked for, in which case both MDWE bits are dropped. It applies to a fork's
//! copy **and** to the space an `execve` builds, because both go through
//! `mm_init` — so MDWE survives an exec unless the process said not to.

use std::ffi::c_int;

use crate::{P_EXEC, P_WRITE};

/// `MMF_DISABLE_THP_COMPLETELY`.
pub const DISABLE_THP: u32 = 1 << 0;
/// `MMF_DISABLE_THP_EXCEPT_ADVISED`.
pub const DISABLE_THP_EXCEPT_ADVISED: u32 = 1 << 1;
/// `MMF_HAS_MDWE`.
pub const HAS_MDWE: u32 = 1 << 2;
/// `MMF_HAS_MDWE_NO_INHERIT`.
pub const HAS_MDWE_NO_INHERIT: u32 = 1 << 3;

/// `PR_THP_DISABLE_EXCEPT_ADVISED`, which is `arg3` of `PR_SET_THP_DISABLE`
/// and a bit of what `PR_GET_THP_DISABLE` answers.
const PR_THP_DISABLE_EXCEPT_ADVISED: u64 = 1 << 1;
/// `PR_MDWE_REFUSE_EXEC_GAIN` and `PR_MDWE_NO_INHERIT`, the two bits
/// `PR_SET_MDWE` takes.
const PR_MDWE_REFUSE_EXEC_GAIN: u64 = 1 << 0;
const PR_MDWE_NO_INHERIT: u64 = 1 << 1;

use guest_errno::c_int_::{EINVAL, EPERM};

/// What a new address space takes from the one it is made from.
pub fn inherit(flags: u32) -> u32 {
    if flags & HAS_MDWE_NO_INHERIT != 0 {
        flags & !(HAS_MDWE | HAS_MDWE_NO_INHERIT)
    } else {
        flags
    }
}

/// `PR_GET_THP_DISABLE`: 0, 1, or `1 | PR_THP_DISABLE_EXCEPT_ADVISED`. Every
/// argument must be zero.
pub(crate) fn thp_get(flags: u32, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<c_int, c_int> {
    if a2 | a3 | a4 | a5 != 0 {
        return Err(EINVAL);
    }
    Ok(if flags & DISABLE_THP != 0 {
        1
    } else if flags & DISABLE_THP_EXCEPT_ADVISED != 0 {
        1 | PR_THP_DISABLE_EXCEPT_ADVISED as c_int
    } else {
        0
    })
}

/// `PR_SET_THP_DISABLE(disable, flags)`: the new `mm->flags`. A flag is only
/// allowed when disabling, and the only flag is `EXCEPT_ADVISED`.
pub(crate) fn thp_set(
    flags: u32,
    disable: u64,
    arg_flags: u64,
    a4: u64,
    a5: u64,
) -> Result<u32, c_int> {
    if a4 | a5 != 0 {
        return Err(EINVAL);
    }
    if (disable == 0 && arg_flags != 0) || arg_flags & !PR_THP_DISABLE_EXCEPT_ADVISED != 0 {
        return Err(EINVAL);
    }
    let cleared = flags & !(DISABLE_THP | DISABLE_THP_EXCEPT_ADVISED);
    Ok(if disable == 0 {
        cleared
    } else if arg_flags & PR_THP_DISABLE_EXCEPT_ADVISED != 0 {
        cleared | DISABLE_THP_EXCEPT_ADVISED
    } else {
        cleared | DISABLE_THP
    })
}

/// The `PR_MDWE_*` bits the flags amount to: what `PR_GET_MDWE` answers and
/// what `PR_SET_MDWE` compares a second request against.
fn mdwe_bits(flags: u32) -> u64 {
    let mut bits = 0;
    if flags & HAS_MDWE != 0 {
        bits |= PR_MDWE_REFUSE_EXEC_GAIN;
    }
    if flags & HAS_MDWE_NO_INHERIT != 0 {
        bits |= PR_MDWE_NO_INHERIT;
    }
    bits
}

/// `PR_GET_MDWE`. Every argument must be zero.
pub fn mdwe_get(flags: u32, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<c_int, c_int> {
    if a2 | a3 | a4 | a5 != 0 {
        return Err(EINVAL);
    }
    Ok(mdwe_bits(flags) as c_int)
}

/// `PR_SET_MDWE(bits)`: the new `mm->flags`. The bits are the two above and
/// `NO_INHERIT` needs `REFUSE_EXEC_GAIN` beside it; once set, a request for
/// anything but the same bits is `EPERM`, because the flags cannot be unset.
pub fn mdwe_set(flags: u32, bits: u64, a3: u64, a4: u64, a5: u64) -> Result<u32, c_int> {
    if a3 | a4 | a5 != 0 {
        return Err(EINVAL);
    }
    if bits & !(PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT) != 0 {
        return Err(EINVAL);
    }
    if bits & PR_MDWE_NO_INHERIT != 0 && bits & PR_MDWE_REFUSE_EXEC_GAIN == 0 {
        return Err(EINVAL);
    }
    let current = mdwe_bits(flags);
    if current != 0 && current != bits {
        return Err(EPERM);
    }
    let mut flags = flags;
    if bits & PR_MDWE_NO_INHERIT != 0 {
        flags |= HAS_MDWE_NO_INHERIT;
    }
    if bits & PR_MDWE_REFUSE_EXEC_GAIN != 0 {
        flags |= HAS_MDWE;
    }
    Ok(flags)
}

/// Linux's `map_deny_write_exec`: under MDWE, refuse a mapping that would be
/// writable and executable at once, and refuse making executable a mapping
/// that was not. `old` is the page's flags as they are — for a fresh `mmap`
/// the same as `new` — and both are `P_*` bits.
pub(crate) fn deny_write_exec(flags: u32, old: u32, new: u32) -> bool {
    if flags & HAS_MDWE == 0 {
        return false;
    }
    if new & P_EXEC as u32 == 0 {
        return false;
    }
    if new & P_WRITE as u32 != 0 {
        return true;
    }
    old & P_EXEC as u32 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: u32 = 1;
    const W: u32 = 2;
    const X: u32 = 4;

    #[test]
    fn the_page_bits_are_what_the_rules_assume() {
        assert_eq!(P_WRITE as u32, W);
        assert_eq!(P_EXEC as u32, X);
    }

    #[test]
    fn nothing_is_denied_without_mdwe() {
        assert!(!deny_write_exec(0, R | W | X, R | W | X));
        assert!(!deny_write_exec(DISABLE_THP, R, R | X));
    }

    #[test]
    fn mdwe_denies_write_plus_exec_and_gaining_exec() {
        let f = HAS_MDWE;
        assert!(
            deny_write_exec(f, R | W | X, R | W | X),
            "a fresh W+X mapping"
        );
        assert!(
            deny_write_exec(f, R | W, R | W | X),
            "mprotect adding exec to writable"
        );
        assert!(
            deny_write_exec(f, R, R | X),
            "mprotect adding exec to read-only"
        );
        assert!(
            !deny_write_exec(f, R | X, R | X),
            "a fresh R+X mapping is fine"
        );
        assert!(!deny_write_exec(f, R | X, R), "dropping exec is fine");
        assert!(
            !deny_write_exec(f, R | X, R | W),
            "so is making it writable, having dropped exec"
        );
        assert!(
            !deny_write_exec(f, R | W, R | W),
            "and a writable mapping staying writable"
        );
        assert!(
            !deny_write_exec(f, 0, R | W),
            "or a PROT_NONE page becoming writable"
        );
    }

    #[test]
    fn mdwe_set_is_one_way() {
        let f = mdwe_set(0, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0).unwrap();
        assert_eq!(f, HAS_MDWE);
        assert_eq!(mdwe_get(f, 0, 0, 0, 0), Ok(1));
        assert_eq!(
            mdwe_set(f, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0),
            Ok(f),
            "the same again is fine"
        );
        assert_eq!(mdwe_set(f, 0, 0, 0, 0), Err(EPERM), "cannot be cleared");
        assert_eq!(
            mdwe_set(f, PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT, 0, 0, 0),
            Err(EPERM),
            "nor changed"
        );
        // Asking for nothing on an unset space is fine and sets nothing.
        assert_eq!(mdwe_set(0, 0, 0, 0, 0), Ok(0));
    }

    #[test]
    fn mdwe_set_argument_rules() {
        assert_eq!(
            mdwe_set(0, 4, 0, 0, 0),
            Err(EINVAL),
            "a bit that is not one of the two"
        );
        assert_eq!(mdwe_set(0, 0xffff, 0, 0, 0), Err(EINVAL));
        assert_eq!(
            mdwe_set(0, PR_MDWE_NO_INHERIT, 0, 0, 0),
            Err(EINVAL),
            "NO_INHERIT alone"
        );
        assert_eq!(mdwe_set(0, 1, 1, 0, 0), Err(EINVAL));
        assert_eq!(mdwe_set(0, 1, 0, 0, 1), Err(EINVAL));
        assert_eq!(mdwe_get(0, 1, 0, 0, 0), Err(EINVAL));
        let both = mdwe_set(0, PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT, 0, 0, 0).unwrap();
        assert_eq!(mdwe_get(both, 0, 0, 0, 0), Ok(3));
    }

    #[test]
    fn no_inherit_drops_both_mdwe_bits_and_nothing_else() {
        let both = HAS_MDWE | HAS_MDWE_NO_INHERIT | DISABLE_THP;
        assert_eq!(inherit(both), DISABLE_THP);
        assert_eq!(
            inherit(HAS_MDWE | DISABLE_THP),
            HAS_MDWE | DISABLE_THP,
            "without NO_INHERIT it is kept"
        );
        assert_eq!(inherit(0), 0);
    }

    #[test]
    fn thp_disable_reads_back_what_was_set() {
        assert_eq!(thp_get(0, 0, 0, 0, 0), Ok(0));
        let f = thp_set(0, 1, 0, 0, 0).unwrap();
        assert_eq!(thp_get(f, 0, 0, 0, 0), Ok(1));
        let f = thp_set(f, 1, PR_THP_DISABLE_EXCEPT_ADVISED, 0, 0).unwrap();
        assert_eq!(thp_get(f, 0, 0, 0, 0), Ok(3));
        assert_eq!(
            f & DISABLE_THP,
            0,
            "EXCEPT_ADVISED replaces a complete disable"
        );
        let f = thp_set(f, 0, 0, 0, 0).unwrap();
        assert_eq!(thp_get(f, 0, 0, 0, 0), Ok(0));
        // Any non-zero disables, as Linux's `bool` parameter does.
        assert_eq!(thp_get(thp_set(0, 7, 0, 0, 0).unwrap(), 0, 0, 0, 0), Ok(1));
    }

    #[test]
    fn thp_disable_argument_rules() {
        assert_eq!(
            thp_set(0, 0, PR_THP_DISABLE_EXCEPT_ADVISED, 0, 0),
            Err(EINVAL),
            "a flag while enabling"
        );
        assert_eq!(
            thp_set(0, 1, 1, 0, 0),
            Err(EINVAL),
            "a flag that is not EXCEPT_ADVISED"
        );
        assert_eq!(thp_set(0, 1, 0, 1, 0), Err(EINVAL));
        assert_eq!(thp_set(0, 1, 0, 0, 1), Err(EINVAL));
        assert_eq!(thp_get(0, 0, 0, 0, 1), Err(EINVAL));
        // The flag bits are kept apart from MDWE's.
        let f = thp_set(HAS_MDWE, 1, 0, 0, 0).unwrap();
        assert_eq!(f, HAS_MDWE | DISABLE_THP);
        assert_eq!(thp_set(f, 0, 0, 0, 0), Ok(HAS_MDWE));
    }
}
