//! Robust-list walking and owner-death handling.

use alloc::vec::Vec;

use crate::{
    FUTEX_OWNER_DIED, FUTEX_TID_MASK, FUTEX_WAITERS, GuestMem, HEAD_FUTEX_OFFSET, HEAD_LIST,
    HEAD_LIST_OP_PENDING, ROBUST_LIST_LIMIT,
};

/// Read an entry pointer, and its flag bit apart.
///
/// The low bit marks a priority-inheritance futex. It is not part of the
/// address and following it unmasked reads one byte past every entry.
fn fetch_entry(mem: &mut dyn GuestMem, at: u64) -> Option<(u64, bool)> {
    let raw = mem.read_u64(at)?;
    Some((raw & !1u64, raw & 1 != 0))
}

/// Mark one futex as having lost its owner.
///
/// Returns the address if a waiter has to be woken. Does nothing at all when
/// the futex is owned by somebody else — a thread disowns what it held, and
/// the list is only a hint about which those were.
///
/// **A compare-and-swap, retried**, as Linux's `handle_futex_death` does. It was
/// a read and then a write until 2026-11-11, and a waiter that set
/// `FUTEX_WAITERS` in between and parked had the bit overwritten: the walk then
/// woke nobody, and the waiter slept for ever behind a dead owner.
///
/// `pending` is the `list_op_pending` entry, which gets one rule more (Linux
/// ca16d5bee598): a word of 0 there means the dying thread was woken to take
/// the lock and died before it could, so the next waiter is woken in its
/// place. A PI futex is never woken from here; `crates/kernel/futex` hands it
/// on when the owner's exit is reported.
fn handle_death(mem: &mut dyn GuestMem, futex_addr: u64, tid: u32, pi: bool, pending: bool) -> Option<u64> {
    let mut uval = mem.read_u32(futex_addr)?;
    loop {
        if pending && !pi && uval == 0 {
            return Some(futex_addr);
        }
        if uval & FUTEX_TID_MASK != tid & FUTEX_TID_MASK {
            return None;
        }
        // Keep the waiters bit, drop the owner, set died. The owner's tid is
        // gone on purpose: there is no owner any more, and a caller that reads
        // one would go looking for a thread that has exited.
        let mval = (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
        match mem.cmpxchg_u32(futex_addr, uval, mval)? {
            Ok(()) => break,
            Err(now) => uval = now,
        }
    }
    (!pi && uval & FUTEX_WAITERS != 0).then_some(futex_addr)
}

/// Walk a dying thread's robust list, disowning what it held.
///
/// Returns the futex addresses that have a waiter to wake. The caller does the
/// waking, because that is kernel state this crate does not have.
///
/// This is `exit_robust_list` in `kernel/futex/core.c`, including the two
/// things that are easy to leave out: the `list_op_pending` entry is skipped
/// during the walk and handled *after* it — it is the mutex libc was in the
/// middle of taking, and it is on the list and about to be on it at the same
/// time — and the walk stops at [`ROBUST_LIST_LIMIT`].
pub fn exit_robust_list(mem: &mut dyn GuestMem, head_addr: u64, tid: u32) -> Vec<u64> {
    let mut wake = Vec::new();
    if head_addr == 0 {
        return wake;
    }

    let Some((mut entry, mut pi)) = fetch_entry(mem, head_addr + HEAD_LIST) else {
        return wake;
    };
    // Signed, and 64-bit. glibc's is negative.
    let Some(futex_offset) = mem.read_u64(head_addr + HEAD_FUTEX_OFFSET) else {
        return wake;
    };
    let futex_offset = futex_offset as i64;
    let Some((pending, pending_pi)) = fetch_entry(mem, head_addr + HEAD_LIST_OP_PENDING) else {
        return wake;
    };

    let mut limit = ROBUST_LIST_LIMIT;
    while entry != head_addr {
        // Read the next pointer *before* touching this entry: the futex write
        // below is visible to other threads, and one of them may free the node.
        let next = fetch_entry(mem, entry);
        if entry != pending
            && let Some(addr) = futex_of(entry, futex_offset)
            && let Some(w) = handle_death(mem, addr, tid, pi, false)
        {
            wake.push(w);
        }
        let Some((next, next_pi)) = next else { break };
        (entry, pi) = (next, next_pi);
        limit -= 1;
        if limit == 0 {
            // A cycle, or a list longer than any real program has. Linux stops
            // here too; the alternative is an exit that never finishes.
            break;
        }
    }

    if pending != 0
        && let Some(addr) = futex_of(pending, futex_offset)
        && let Some(w) = handle_death(mem, addr, tid, pending_pi, true)
    {
        wake.push(w);
    }
    wake
}

/// `entry + futex_offset`, refusing to wrap.
///
/// The offset is signed and guest-supplied, so both directions have to be
/// checked: an offset of -2^63 on a low entry, or a huge positive one, would
/// otherwise wrap around to an address that is mapped.
fn futex_of(entry: u64, futex_offset: i64) -> Option<u64> {
    entry.checked_add_signed(futex_offset)
}
