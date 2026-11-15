//! `pkey_alloc(2)`, `pkey_free(2)`, and `pkey_mprotect(2)`.

use std::cell::Cell;
use std::ffi::c_int;
use std::sync::atomic::Ordering;

use guest_errno::Errno;
use strace::strace;

const MAX_PKEYS: u32 = 16;
const PKEY_DISABLE_ACCESS: u32 = 0x1;
const PKEY_DISABLE_WRITE: u32 = 0x2;
const PKEY_RIGHTS_MASK: u32 = PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE;
const DEFAULT_PKEY_MASK: u16 = 1; // bit 0 reserved for default pkey 0

thread_local! {
    static TEST_PKEY_MASK: Cell<u16> = const { Cell::new(DEFAULT_PKEY_MASK) };
}

fn load_mask() -> u16 {
    taskview::with_current_mm(|mm| mm.pkey_alloc_mask.load(Ordering::Acquire) | DEFAULT_PKEY_MASK)
        .unwrap_or_else(|| TEST_PKEY_MASK.with(|m| m.get() | DEFAULT_PKEY_MASK))
}

fn update_mask<R>(mut f: impl FnMut(u16) -> Result<(u16, R), Errno>) -> Result<R, Errno> {
    if let Some(res) = taskview::with_current_mm(|mm| {
        let mut cur = mm.pkey_alloc_mask.load(Ordering::Acquire);
        loop {
            let (next, out) = f(cur | DEFAULT_PKEY_MASK)?;
            match mm.pkey_alloc_mask.compare_exchange_weak(
                cur,
                next | DEFAULT_PKEY_MASK,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(out),
                Err(observed) => cur = observed,
            }
        }
    }) {
        return res;
    }

    TEST_PKEY_MASK.with(|cell| {
        let cur = cell.get() | DEFAULT_PKEY_MASK;
        let (next, out) = f(cur)?;
        cell.set(next | DEFAULT_PKEY_MASK);
        Ok(out)
    })
}

pub fn sys_pkey_alloc(flags: u32, access_rights: u32) -> Result<i64, Errno> {
    strace!("pkey_alloc({flags:#x}, {access_rights:#x})");
    if flags != 0 || (access_rights & !PKEY_RIGHTS_MASK) != 0 {
        return Err(Errno::EINVAL);
    }
    update_mask(|bits| {
        for key in 1..MAX_PKEYS {
            let mask = 1u16 << key;
            if (bits & mask) == 0 {
                return Ok((bits | mask, i64::from(key)));
            }
        }
        Err(Errno::ENOSPC)
    })
}

pub fn sys_pkey_free(pkey: c_int) -> Result<(), Errno> {
    strace!("pkey_free({pkey})");
    if pkey <= 0 || pkey >= MAX_PKEYS as c_int {
        return Err(Errno::EINVAL);
    }
    let mask = 1u16 << (pkey as u32);
    update_mask(|bits| {
        if (bits & mask) == 0 {
            return Err(Errno::EINVAL);
        }
        Ok((bits & !mask, ()))
    })
}

pub fn sys_pkey_mprotect(addr: u64, len: u64, prot: c_int, pkey: c_int) -> Result<(), Errno> {
    strace!("pkey_mprotect({addr:#x}, {len:#x}, {prot:#x}, {pkey})");
    if pkey < -1 || pkey >= MAX_PKEYS as c_int {
        return Err(Errno::EINVAL);
    }
    if pkey > 0 {
        let mask = 1u16 << (pkey as u32);
        let bits = load_mask();
        if (bits & mask) == 0 {
            return Err(Errno::EINVAL);
        }
    }
    crate::sys_mprotect(addr, len, prot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkey_alloc_and_free_tracks_15_keys() {
        TEST_PKEY_MASK.with(|m| m.set(DEFAULT_PKEY_MASK));
        let mut allocated = Vec::new();
        for _ in 1..MAX_PKEYS {
            allocated.push(sys_pkey_alloc(0, PKEY_DISABLE_WRITE).unwrap() as c_int);
        }
        assert_eq!(sys_pkey_alloc(0, 0), Err(Errno::ENOSPC));
        for k in allocated {
            assert_eq!(sys_pkey_free(k), Ok(()));
            assert_eq!(sys_pkey_free(k), Err(Errno::EINVAL));
        }
    }

    #[test]
    fn pkey_bounds_and_default_key_checks() {
        TEST_PKEY_MASK.with(|m| m.set(DEFAULT_PKEY_MASK));
        assert_eq!(sys_pkey_free(0), Err(Errno::EINVAL));
        assert_eq!(sys_pkey_free(-1), Err(Errno::EINVAL));
        assert_eq!(sys_pkey_free(MAX_PKEYS as c_int), Err(Errno::EINVAL));
        assert_eq!(sys_pkey_mprotect(0, 0, 0, -2), Err(Errno::EINVAL));
        assert_eq!(sys_pkey_mprotect(0, 0, 0, MAX_PKEYS as c_int), Err(Errno::EINVAL));
        assert_eq!(sys_pkey_mprotect(0, 0, 0, 1), Err(Errno::EINVAL));
    }
}
