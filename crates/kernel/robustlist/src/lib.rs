//! The robust futex list: what a dying thread owes the mutexes it held.
//!
//! A thread registers a **robust list head** with `set_robust_list`, and libc
//! links every robust mutex it takes onto it. When the thread dies without
//! unlocking — killed, faulted, or out through the raw `exit` syscall — the
//! kernel walks that list and, for each futex the thread owned, sets
//! `FUTEX_OWNER_DIED` and wakes a waiter. The next `lock` then reports
//! `EOWNERDEAD` instead of blocking on an owner that no longer exists.
//!
//! Nothing else can do it: libc's own unwinding runs on the orderly path, which
//! is the path where nothing went wrong. Storing the head and never walking it
//! is therefore a **hang**, not a wrong answer, and that is what this kernel
//! did — `sys_set_robust_list` wrote `current->robust_list` and no exit path
//! ever read it.
//!
//! # Why this is a crate
//!
//! The list lives in **guest memory and the guest wrote it**. Every pointer in
//! it is untrusted, and three things follow that the C would have had to get
//! right by hand:
//!
//! - a `next` that points back at an earlier entry is a **cycle**, and the walk
//!   has to stop. Linux bounds it at 2048 entries and so does this;
//! - the low bit of every entry pointer is a flag, not part of the address,
//!   and must be stripped before the pointer is followed;
//! - `futex_offset` is a **signed** 64-bit quantity. glibc's is negative — the
//!   futex sits *before* the list node — so reading it unsigned puts the futex
//!   address astronomically far away. `struct robust_list_head_` in
//!   `kernel/futex.c` declared it `dword_t`: unsigned, and half the width.
//!
//! Guest memory is reached through [`GuestMem`], which the C implements with
//! `user_get`/`user_put` and the tests implement with a `BTreeMap`. That is
//! what makes a cycle something you can write a test for.

#![no_std]

extern crate alloc;

/// `struct robust_list_head` is three 8-byte fields on any 64-bit Linux.
pub const HEAD_BYTES: usize = 24;
const HEAD_LIST: u64 = 0;
const HEAD_FUTEX_OFFSET: u64 = 8;
const HEAD_LIST_OP_PENDING: u64 = 16;

/// The owner's thread id lives in the low 30 bits of a futex word.
pub const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
/// Someone is waiting on this futex.
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
/// The owner died holding it.
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;

/// Linux's `ROBUST_LIST_LIMIT`. The list is guest-written, so this is the only
/// thing standing between a cycle and a kernel that never returns from exit.
pub const ROBUST_LIST_LIMIT: usize = 2048;

/// Guest memory, as much of it as this needs.
///
/// Every method returns `None`/`false` for an address the guest cannot reach.
/// A dying thread's list may point anywhere; a failed read ends the walk
/// rather than failing the exit, which is what Linux does.
pub trait GuestMem {
    fn read_u64(&mut self, addr: u64) -> Option<u64>;
    fn read_u32(&mut self, addr: u64) -> Option<u32>;
    /// Compare-and-swap: `None` when unmapped for writing, `Some(Err(actual))`
    /// when the word was not `old`.
    fn cmpxchg_u32(&mut self, addr: u64, old: u32, new: u32) -> Option<Result<(), u32>>;
}

#[path = "walk.rs"]
mod walk;
pub use walk::exit_robust_list;

// The C ABI that was here until 2026-09-09: a `#[repr(C)]` `Ops` of four
// `Option<unsafe extern "C" fn>`, a `CMem` adapter implementing [`GuestMem`]
// over it, and a `robustlist_exit` entry point taking `*const Ops`.
//
// **Nothing called any of it.** `crates/kernel/futexcalls` implements
// [`GuestMem`] directly, which is what the trait is for, and the adapter was
// left behind when `kernel/futex.c` went. `tools/dead-exports.py` did not
// report it because it was not `#[no_mangle]` -- it was `pub`, in a crate
// something depends on, which is enough to keep a thing alive without keeping
// it reachable.

/// `sizeof(struct robust_list_head)`, which `set_robust_list` requires exactly
/// and `get_robust_list` reports.
pub fn robustlist_head_size() -> usize {
    HEAD_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    /// Guest memory as a map, so a test can build a list the guest could have
    /// written — including ones no correct libc would.
    #[derive(Default)]
    struct Mem {
        words: BTreeMap<u64, u64>,
        halves: BTreeMap<u64, u32>,
        writes: usize,
    }

    impl Mem {
        fn u64(&mut self, addr: u64, v: u64) -> &mut Self {
            self.words.insert(addr, v);
            self
        }
        fn u32(&mut self, addr: u64, v: u32) -> &mut Self {
            self.halves.insert(addr, v);
            self
        }
    }

    impl GuestMem for Mem {
        fn read_u64(&mut self, addr: u64) -> Option<u64> {
            self.words.get(&addr).copied()
        }
        fn read_u32(&mut self, addr: u64) -> Option<u32> {
            self.halves.get(&addr).copied()
        }
        fn cmpxchg_u32(&mut self, addr: u64, old: u32, new: u32) -> Option<Result<(), u32>> {
            let cur = *self.halves.get(&addr)?;
            if cur != old {
                return Some(Err(cur));
            }
            self.writes += 1;
            self.halves.insert(addr, new);
            Some(Ok(()))
        }
    }

    const HEAD: u64 = 0x1000;
    const TID: u32 = 42;

    /// A head whose list is empty and whose pending is null.
    fn empty() -> Mem {
        let mut m = Mem::default();
        m.u64(HEAD + HEAD_LIST, HEAD)
            .u64(HEAD + HEAD_FUTEX_OFFSET, 8)
            .u64(HEAD + HEAD_LIST_OP_PENDING, 0);
        m
    }

    #[test]
    fn the_head_is_three_words() {
        assert_eq!(
            HEAD_BYTES, 24,
            "robust_list_head is 24 bytes on any 64-bit Linux"
        );
        assert_eq!(HEAD_FUTEX_OFFSET, 8);
        assert_eq!(HEAD_LIST_OP_PENDING, 16);
    }

    #[test]
    fn an_empty_list_does_nothing() {
        let mut m = empty();
        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty());
        assert_eq!(m.writes, 0);
    }

    #[test]
    fn a_null_head_does_nothing() {
        let mut m = empty();
        assert!(exit_robust_list(&mut m, 0, TID).is_empty());
    }

    /// One entry, owned by the dying thread, with nobody waiting.
    #[test]
    fn a_held_futex_is_disowned() {
        let entry = 0x2000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST, entry)
            .u64(entry, HEAD)
            .u32(entry + 8, TID);

        let wake = exit_robust_list(&mut m, HEAD, TID);
        assert!(wake.is_empty(), "nobody was waiting, so nobody is woken");
        assert_eq!(m.halves[&(entry + 8)], FUTEX_OWNER_DIED);
    }

    /// With a waiter, the bit is kept and the address comes back to be woken.
    /// Losing the waiters bit would leave the next unlock thinking it has no
    /// one to wake.
    #[test]
    fn a_waiter_is_kept_and_reported() {
        let entry = 0x2000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST, entry)
            .u64(entry, HEAD)
            .u32(entry + 8, TID | FUTEX_WAITERS);

        let wake = exit_robust_list(&mut m, HEAD, TID);
        assert_eq!(wake, alloc::vec![entry + 8]);
        assert_eq!(m.halves[&(entry + 8)], FUTEX_WAITERS | FUTEX_OWNER_DIED);
    }

    /// A futex the thread did not own is left alone. The list says what it
    /// *took*, and it may have released one since.
    #[test]
    fn a_futex_owned_by_somebody_else_is_untouched() {
        let entry = 0x2000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST, entry)
            .u64(entry, HEAD)
            .u32(entry + 8, 99);

        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty());
        assert_eq!(
            m.halves[&(entry + 8)],
            99,
            "somebody else's futex was rewritten"
        );
        assert_eq!(m.writes, 0);
    }

    /// glibc's `futex_offset` is negative: the futex sits *before* the list
    /// node. Read unsigned — which `struct robust_list_head_` in the C did,
    /// and at half the width — the address lands 4 GB away.
    #[test]
    fn a_negative_futex_offset_points_backwards() {
        let entry = 0x2000;
        let mut m = empty();
        m.u64(HEAD + HEAD_FUTEX_OFFSET, (-16i64) as u64)
            .u64(HEAD + HEAD_LIST, entry)
            .u64(entry, HEAD)
            .u32(entry - 16, TID);

        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty());
        assert_eq!(m.halves[&(entry - 16)], FUTEX_OWNER_DIED);
    }

    /// Several entries, all disowned.
    #[test]
    fn every_entry_on_the_list_is_visited() {
        let mut m = empty();
        let entries = [0x2000u64, 0x3000, 0x4000];
        m.u64(HEAD + HEAD_LIST, entries[0]);
        for (i, e) in entries.iter().enumerate() {
            let next = entries.get(i + 1).copied().unwrap_or(HEAD);
            m.u64(*e, next).u32(*e + 8, TID);
        }
        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty());
        for e in entries {
            assert_eq!(m.halves[&(e + 8)], FUTEX_OWNER_DIED, "entry {e:#x}");
        }
    }

    /// The low bit of an entry pointer is a flag. Following it unmasked reads
    /// one byte into every node.
    #[test]
    fn the_flag_bit_is_stripped_from_a_pointer() {
        let entry = 0x2000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST, entry | 1)
            .u64(entry, HEAD)
            .u32(entry + 8, TID);
        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty());
        assert_eq!(m.halves[&(entry + 8)], FUTEX_OWNER_DIED);
    }

    /// The entry libc was in the middle of taking is skipped during the walk
    /// and handled once at the end -- it can be on the list and about to be on
    /// it at the same time, and disowning it twice would clear the waiters bit
    /// the second time round.
    #[test]
    fn the_pending_entry_is_handled_once() {
        let entry = 0x2000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST, entry)
            .u64(HEAD + HEAD_LIST_OP_PENDING, entry)
            .u64(entry, HEAD)
            .u32(entry + 8, TID | FUTEX_WAITERS);

        let wake = exit_robust_list(&mut m, HEAD, TID);
        assert_eq!(wake.len(), 1, "the pending entry was disowned twice");
        assert_eq!(m.writes, 1);
        assert_eq!(m.halves[&(entry + 8)], FUTEX_WAITERS | FUTEX_OWNER_DIED);
    }

    /// A waiter that sets `FUTEX_WAITERS` between the walk's read and its
    /// write must not lose the bit: the swap fails, the walk reads again, and
    /// the address comes back to be woken.
    #[test]
    fn a_waiter_arriving_mid_walk_keeps_its_bit() {
        struct Racing(Mem, bool);
        impl GuestMem for Racing {
            fn read_u64(&mut self, a: u64) -> Option<u64> {
                self.0.read_u64(a)
            }
            fn read_u32(&mut self, a: u64) -> Option<u32> {
                self.0.read_u32(a)
            }
            fn cmpxchg_u32(&mut self, a: u64, old: u32, new: u32) -> Option<Result<(), u32>> {
                if !self.1 {
                    // The other thread's cmpxchg lands first.
                    self.1 = true;
                    let cur = self.0.halves[&a];
                    self.0.halves.insert(a, cur | FUTEX_WAITERS);
                }
                self.0.cmpxchg_u32(a, old, new)
            }
        }
        let entry = 0x2000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST, entry).u64(entry, HEAD).u32(entry + 8, TID);
        let mut r = Racing(m, false);
        let wake = exit_robust_list(&mut r, HEAD, TID);
        assert_eq!(wake, alloc::vec![entry + 8], "the waiter that arrived is woken");
        assert_eq!(r.0.halves[&(entry + 8)], FUTEX_WAITERS | FUTEX_OWNER_DIED);
    }

    /// A pending entry whose word is 0: the dying thread had been woken to
    /// take it and died first, so the next waiter is woken in its place. Not
    /// for a PI futex, and not for an entry on the list.
    #[test]
    fn a_pending_free_futex_wakes_the_next_waiter() {
        let pending = 0x5000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST_OP_PENDING, pending).u32(pending + 8, 0);
        assert_eq!(exit_robust_list(&mut m, HEAD, TID), alloc::vec![pending + 8]);
        assert_eq!(m.writes, 0, "and nothing is written");

        let mut m = empty();
        m.u64(HEAD + HEAD_LIST_OP_PENDING, pending | 1).u32(pending + 8, 0);
        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty(), "not for PI");

        let entry = 0x2000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST, entry).u64(entry, HEAD).u32(entry + 8, 0);
        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty(), "not for a listed entry");
    }

    /// A PI futex is disowned but never woken from the walk.
    #[test]
    fn a_pi_futex_is_disowned_and_not_woken() {
        let entry = 0x2000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST, entry | 1).u64(entry, HEAD).u32(entry + 8, TID | FUTEX_WAITERS);
        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty());
        assert_eq!(m.halves[&(entry + 8)], FUTEX_WAITERS | FUTEX_OWNER_DIED);
    }

    /// A pending entry that is *not* on the list is still handled.
    #[test]
    fn a_pending_entry_off_the_list_is_still_handled() {
        let pending = 0x5000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST_OP_PENDING, pending)
            .u32(pending + 8, TID);
        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty());
        assert_eq!(m.halves[&(pending + 8)], FUTEX_OWNER_DIED);
    }

    /// The guest wrote this list. A cycle must not be an exit that never
    /// finishes.
    #[test]
    fn a_cycle_terminates() {
        let a = 0x2000;
        let b = 0x3000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST, a)
            .u64(a, b)
            .u64(b, a)
            .u32(a + 8, TID)
            .u32(b + 8, TID);

        let wake = exit_robust_list(&mut m, HEAD, TID);
        assert!(wake.is_empty());
        assert!(
            m.writes <= ROBUST_LIST_LIMIT,
            "walked past the limit: {}",
            m.writes
        );
        assert!(m.writes >= 2, "it should still have disowned what it saw");
    }

    /// A self-pointing entry is the shortest cycle there is.
    #[test]
    fn a_self_pointing_entry_terminates() {
        let a = 0x2000;
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST, a).u64(a, a).u32(a + 8, TID);
        exit_robust_list(&mut m, HEAD, TID);
        assert!(m.writes <= ROBUST_LIST_LIMIT);
    }

    /// An unreadable address ends the walk instead of the process.
    #[test]
    fn an_unreadable_entry_ends_the_walk() {
        let mut m = empty();
        m.u64(HEAD + HEAD_LIST, 0xdead_0000);
        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty());

        // And an unreadable head is not a crash either.
        let mut bare = Mem::default();
        assert!(exit_robust_list(&mut bare, HEAD, TID).is_empty());
    }

    /// An offset that would wrap the address space is refused rather than
    /// aliasing onto something mapped.
    #[test]
    fn an_offset_that_wraps_is_refused() {
        let entry = 0x2000;
        let mut m = empty();
        m.u64(HEAD + HEAD_FUTEX_OFFSET, i64::MIN as u64)
            .u64(HEAD + HEAD_LIST, entry)
            .u64(entry, HEAD);
        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty());
        assert_eq!(m.writes, 0);

        let mut m = empty();
        m.u64(HEAD + HEAD_FUTEX_OFFSET, i64::MAX as u64)
            .u64(HEAD + HEAD_LIST, u64::MAX - 8)
            .u64(u64::MAX - 8, HEAD);
        assert!(exit_robust_list(&mut m, HEAD, TID).is_empty());
        assert_eq!(m.writes, 0);
    }
}
