//! Descriptor-table allocation, sharing, copying, and teardown.
//!
//! **The share count is `Arc`'s** since 2026-09-12. It was
//! `shares: AtomicUsize` with `fdtable_retain` doing a `fetch_add(Relaxed)`,
//! `fdtable_release` a `fetch_sub(Release)` plus an `Acquire` fence, and a
//! hand-written teardown behind the `!= 1`. That is `Arc<Table>`'s
//! implementation, line for line, and object model step 9.2 is stopping this
//! crate from keeping a second copy of it.
//!
//! The holder set did not change: every `fdtable_retain` became an
//! `Arc::clone`, so `strong_count()` counts what `shares` counted — the tasks
//! sharing the table after a `CLONE_FILES`, plus whatever `crates/fs/proc` has
//! taken for the length of one directory read.
//!
//! # The task's field
//!
//! `struct task`'s `files` is a `taskview::ArcSlot<fdtable>`: an atomic pointer
//! owning one count. It is not an `Option<Arc<Table>>` for the reason it
//! became an atomic on 2026-09-12: `f_get` reads it on **every descriptor
//! syscall**, on the task's own thread, holding no lock, while the group-exit
//! valve moves it out from another. An `Option<Arc<Table>>` written under
//! `pids_lock` would put a plain load back on the descriptor path -- see
//! `docs/changelog/2026-09-12-three-fields-the-valve-said-pids_lock-excluded.md`.
//!
//! `into_raw`, `from_raw`, `clone_raw` and `retain_raw` were here until
//! 2026-10-16, the erasure that field needed at every site that moved a
//! count; the slot does it once. [`is_shared`] is what is left, for
//! `close_range(CLOSE_RANGE_UNSHARE)`.
//!
//! Everything else in this crate **borrows**: a `*const Table` read inside one
//! call, with no count operation anywhere near it.

use super::*;
use std::mem::ManuallyDrop;
use std::sync::Arc;

/// Borrow the `Arc` a raw pointer names, without touching the count.
///
/// `ManuallyDrop` rather than `Arc::from_raw` alone: the caller does not own
/// the reference this reconstructs, so letting it drop would release somebody
/// else's.
///
/// # Safety
/// `table` is non-null, came from `Arc::into_raw`, and something the caller
/// holds keeps it alive for the whole borrow.
unsafe fn borrow<D: Descriptor>(table: *const Table<D>) -> ManuallyDrop<Arc<Table<D>>> {
    ManuallyDrop::new(unsafe { Arc::from_raw(table) })
}

impl<D: Descriptor> Table<D> {
    /// A table with `size` empty slots.
    ///
    /// `None` when the entry vector cannot be allocated, which is a `fork`
    /// answering `_ENOMEM` rather than the emulator dying. The `Arc` itself is
    /// `Arc::new` and therefore aborts on failure — 40 bytes, the same trade
    /// `crates/kernel/pagetable`'s `Data`, `crates/fs/inode` and
    /// `crates/fs/mount` make for their own small fixed allocations. The
    /// unbounded half is the vector, which is the half that keeps its
    /// `try_reserve`.
    pub fn new(size: c_int, ops: Ops<D>) -> Option<Arc<Table<D>>> {
        let mut entries = Vec::new();
        let size = size.max(0) as usize;
        entries.try_reserve(size).ok()?;
        // `resize_with`: an `Entry` owns a reference and so is not `Copy`.
        entries.resize_with(size, Entry::default);
        LIVE.fetch_add(1, Ordering::Relaxed);
        Some(Arc::new(Table {
            state: Mutex::new(State { entries }),
            ops,
        }))
    }

    /// Copy the numbering and CLOEXEC state, retaining one reference per slot.
    ///
    /// A second **table**, not a second share: this is `fork` without
    /// `CLONE_FILES`, and the two are independent from here on. The reference
    /// per occupied slot is taken under this table's mutex, so a slot cannot be
    /// removed between being read and being counted.
    pub fn copy(&self) -> Option<Arc<Table<D>>> {
        let entries = {
            let state = lock(self);
            let mut copied = Vec::new();
            copied.try_reserve(state.entries.len()).ok()?;
            // `clone` per entry rather than `extend_from_slice` and a retain
            // loop: an `Entry` is not `Copy` any more, and cloning one **is**
            // the retain. That is the whole of what the `retain` callback did.
            copied.extend(state.entries.iter().map(|e| Entry {
                fd: e.fd.clone(),
                cloexec: e.cloexec,
            }));
            copied
        };
        let Some(result) = Table::new(0, self.ops) else {
            // The references above have no table to live in. Give them back
            // with `remove_locks` off: no slot of the new table ever existed,
            // so no record lock is owned by it.
            release_entries(self, entries, false);
            return None;
        };
        lock(&result).entries = entries;
        Some(result)
    }
}

/// Is anything other than the calling task holding this table?
///
/// `close_range(CLOSE_RANGE_UNSHARE)` is the one caller, and it splits the
/// table when the answer is yes.
///
/// # Safety
/// `table` is null or live, and the caller holds whatever stops it being
/// released across this call -- nothing at all for the calling task's own.
pub unsafe fn is_shared<D: Descriptor>(table: *const Table<D>) -> bool {
    if table.is_null() {
        return false;
    }
    // SAFETY: the caller's contract.
    let held = unsafe { borrow(table) };
    Arc::strong_count(&held) > 1
}
