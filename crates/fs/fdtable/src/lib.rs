//! Rust-owned descriptor table: lifetime, synchronization, numbering and
//! close-on-exec state.
//!
//! A table entry owns one C `struct fd *` reference. Rust never dereferences
//! that pointer. The callback table is the complete cross-language ownership
//! contract: `retain` is an atomic reference increment; `release` performs the
//! C descriptor's last-reference teardown when appropriate.
//!
//! # Lock and callback rule
//!
//! The table mutex protects only entries and sharing metadata. `retain` may run
//! under it because it is atomic and invokes no callbacks. `release` and record
//! lock cleanup must run after the mutex is dropped: a final descriptor release
//! enters poll cleanup, `fd_ops::close`, filesystem close, inotify, inode and
//! mount teardown. None of those may be called under this Rust mutex.
//!
//! # Where the last share goes, and what is held while it does
//!
//! [`Drop for Table`](Table#impl-Drop-for-Table) is the whole teardown. It runs
//! at four places, none of which holds a lock of this crate's:
//!
//! | the last share is dropped | thread | holding |
//! | --- | --- | --- |
//! | `do_exit`'s `release_guest_memory` | the task's own | nothing — the `swap` that took it out gave `pids_lock` back first |
//! | `run_tlb_cleanup` | a dying thread's `pthread_exit` handler | nothing |
//! | `close_range(CLOSE_RANGE_UNSHARE)` | the task's own | nothing |
//! | `crates/kernel/boot`'s `Partial::drop`, `crates/kernel/forkcalls`' `Given::undo` | the creating thread | nothing; a half-built task unwinding |
//!
//! `crates/fs/proc` takes a share under `pids_lock` and gives it back after,
//! and its drop can be the last only if the owning task exited in between.
//! That table is empty of *its* descriptors by then — `do_exit` released them
//! — so the destructor below has nothing to call.
//!
//! The rule this records, which `tools/lock-order.py --calls` cannot see
//! because a destructor is one level below any call it follows: **the entry
//! release callbacks reach a whole descriptor teardown**, and no caller may
//! hold a lock that teardown takes.

use std::ffi::c_int;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use guest_errno::c_int_::{EBADF, EINVAL, EMFILE, ENOMEM};

/// What the table does to a descriptor it takes or drops.
///
/// Plain Rust `fn` pointers, and not `#[repr(C)]`: `crates/fs/fdobj` fills the
/// one table that exists and nothing else can. It was
/// `Option<unsafe extern "C" fn>` with a second rendering of the same three
/// fields in `taskview::ffi::fdtable_ops`, which `crates/kernel/boot` `.cast()`
/// between — checking nothing.
///
/// # Why this vtable survives 9.2, and what replaces it in 9.7
///
/// `docs/object-model-arc.md` asks for the choice to be made here rather than
/// later, because a table still holding a vtable after `struct fd` becomes an
/// `Arc` is a second rendering of the descriptor's lifetime. The two shapes it
/// offers are `Table<D>`, generic in the descriptor handle, and moving the
/// handle type down so this crate can name it. **It is `Table<D>`, and the
/// reason is a cycle rather than a preference:**
///
/// `crates/kernel/abi` does `pub use fdtable::Table as fdtable`, because
/// `struct task`'s `files` field has to name a type and the foundation is where
/// that name lives. So `kernel-abi` depends on this crate, and this crate can
/// never name `iul_abi::fd` — which is what 9.7's recommended shape,
/// `Arc<iul_abi::fd>` behind a finalize hook, makes the entry type. A generic
/// parameter is the only one of the two that leaves that edge pointing the way
/// it already points: `kernel-abi` writes
/// `pub type fdtable = fdtable::Table<Arc<fd>>;` and this crate names no
/// descriptor at all — not even `fs_fd::Payload`, so the `fs-fd` dependency
/// goes with the vtable.
///
/// Monomorphised, so the product's call is direct and costs nothing, which is
/// the argument `<M: GuestIo>` is already the precedent for in this tree. What
/// the trait needs is what these three fields are: `Clone` for the copy a
/// `fork` makes, `Drop` for the release, and one method for the record-lock
/// removal — which is *not* part of a descriptor's lifetime and is the one
/// thing here that will not fall out of `Arc`.
///
/// Done on 2026-10-17, as the first step of moving descriptors to `Arc`: the
/// entry type is [`Descriptor`], which `kernel-abi`'s `FdOwned` -- an
/// `Arc<fd>` -- implements.
// `fs-fd::Payload` is the shared opaque descriptor type. The concrete `fd`
// layout remains private to `fs-fdobj`, so this dependency stays acyclic while
// callbacks retain a typed boundary.
///
/// **One field, since 2026-09-12.** `retain` and `release` were the other two,
/// and they were here because an entry was a `usize` that this crate could not
/// release by itself — the `Handle` behind a descriptor is reached through
/// `struct fd`'s `owner`, whose layout is `crates/fs/fdobj`'s. An entry holds
/// an [`D`] now, which *is* the handle, so the table releases what
/// it holds and the two callbacks have nothing left to do. Object model step
/// 9.7.
///
/// `remove_locks` is not a lifetime operation and stays: a POSIX record lock is
/// owned by the **process**, so the identity it is held by is this table, and
/// only the layer above knows what to do about it.
pub struct Ops<D: Descriptor> {
    /// A safe `fn` over the entry's handle and the table since 2026-10-01; it
    /// took the payload and the table as raw pointers, and both call sites
    /// held a reference to each.
    pub remove_locks: Option<fn(fd: &D, owner: &Table<D>)>,
}

// By hand: a derive would ask `D` to be `Copy`, and a descriptor reference is
// not -- copying it would be a retain nobody counted.
impl<D: Descriptor> Clone for Ops<D> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<D: Descriptor> Copy for Ops<D> {}

/// What a table holds per occupied slot: one counted reference to a
/// descriptor. `Clone` is the retain a `fork`'s copy takes, `Drop` the release
/// of a slot nobody closes, and [`Descriptor::close`] the release `close(2)`
/// reports on.
///
/// **Generic since 2026-10-17**, which is the `Table<D>` shape the comment on
/// [`Ops`] chose: this crate names no descriptor, so `kernel-abi` -- which
/// depends on it -- can name the table over its own.
pub trait Descriptor: Clone {
    /// Give the reference back, answering the driver's close error when it was
    /// the last one and 0 otherwise.
    fn close(self) -> c_int;
}


/// One descriptor number's slot.
///
/// **Not `Copy`, and that is the change.** It was `{ fd: usize, cloexec: bool }`
/// with zero for an empty slot, and every release was somebody else's callback;
/// it owns its reference now, so `None` is the empty slot and dropping the
/// vector releases what is in it. The `Copy` had to go with it, which is the
/// same trap `pt_entry` hit in step 9.1: `entries.resize(n, Entry::default())`
/// becomes `resize_with`.
struct Entry<D> {
    fd: Option<D>,
    cloexec: bool,
}

impl<D> Default for Entry<D> {
    fn default() -> Self {
        Entry { fd: None, cloexec: false }
    }
}

struct State<D> {
    entries: Vec<Entry<D>>,
}

/// How many tables are alive.
///
/// **This is the only thing in the tree that can see a leaked table**, and a
/// leak is the failure mode of the step this counter was added for: a share
/// count one too high keeps the table and every descriptor in it for ever, and
/// every assertion in the guest suite still passes. Nothing else counts them —
/// `/proc/iul/objects` counts tasks and cleanup structs, `fd_limit` measures
/// descriptor *numbers* in one table rather than tables, and the host's own
/// resident size moves by a few hundred bytes, which is inside the noise of
/// anything that could measure it.
///
/// `Relaxed`: it is a diagnostic, and a reader that wants it to mean anything
/// has to be the only thread making tables. `crates/fs/fdtable/tests/` is that
/// reader, in a binary of its own for the reason
/// `crates/kernel/eventfd/tests/live_count.rs` gives about its own counter.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// See [`LIVE`].
pub fn table_live_count() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// A process's open file descriptors: the numbering, the CLOEXEC bits and one
/// owned reference per occupied slot.
///
/// **Held as `Arc<Table>`**, and the strong count is what `shares: AtomicUsize`
/// counted by hand until 2026-09-12 — the tasks sharing it after a
/// `CLONE_FILES`, plus whatever `crates/fs/proc` has taken for the length of
/// one directory read. The holder set is exactly the old one, which is why
/// `is_shared` still answers what `close_range(CLOSE_RANGE_UNSHARE)` expects:
/// every `fdtable_retain` became an `Arc::clone` and no new holder arrived.
///
/// It is `Send` and `Sync` without an `unsafe impl`, unlike
/// `crates/kernel/pagetable`'s `Data`, and for a reason worth keeping: every
/// field is one the compiler can decide. Entries are `usize`, not `*mut fd`,
/// and `Ops` is plain `fn` pointers — so the descriptor addresses this holds
/// are opaque words and the question "is a `struct fd` safe to touch from
/// another thread" is not asked here. See the `Ops` comment for why that is
/// also the shape step 9.7 has to keep.
pub struct Table<D: Descriptor> {
    state: Mutex<State<D>>,
    ops: Ops<D>,
}

impl<D: Descriptor> Drop for Table<D> {
    /// The last share has gone: every entry the table still holds is released.
    ///
    /// **No lock is taken here, and that is the improvement over the explicit
    /// teardown this replaces.** That one took the table mutex to `mem::take`
    /// the entry vector out and then dropped it before running a single
    /// callback, because a final descriptor release enters poll cleanup, the
    /// driver's `close`, inotify and mount teardown — none of which may run
    /// under this crate's mutex. `Drop` has `&mut self`, so [`Mutex::get_mut`]
    /// answers without locking at all and the rule is enforced by the signature
    /// rather than by the order of two statements.
    ///
    /// `&mut self` is also what says no other thread is inside the mutex: an
    /// exclusive reference to the table cannot exist while one is.
    ///
    /// See the module comment for which lock each caller holds when its share
    /// is the last one.
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::Relaxed);
        let ops = self.ops;
        let entries = std::mem::take(
            &mut self
                .state
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entries,
        );
        for entry in entries {
            // Each entry releases what it holds when it goes; what is left here
            // is the record locks, which are not a lifetime operation.
            if let (Some(fd), Some(remove)) = (&entry.fd, ops.remove_locks) {
                remove(fd, self);
            }
        }
    }
}

fn lock<D: Descriptor>(table: &Table<D>) -> MutexGuard<'_, State<D>> {
    table
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn expand<D>(entries: &mut Vec<Entry<D>>, fd: c_int, limit: usize) -> c_int {
    if fd < 0 {
        return EBADF;
    }
    let want = fd as usize + 1;
    if want > limit {
        return EMFILE;
    }
    if want <= entries.len() {
        return 0;
    }
    if entries.try_reserve(want - entries.len()).is_err() {
        return ENOMEM;
    }
    // `resize_with`, because an `Entry` owns a reference and so is not `Copy`.
    entries.resize_with(want, Entry::default);
    0
}

/// Gives an entry's reference back, answering the finalizer's errno.
///
/// The record locks first and the reference after, which is the order
/// `sys_close` needs: a lock is owned by the table and has to go while the
/// description is still there to unlock.
fn release_entry<D: Descriptor>(table: &Table<D>, entry: Entry<D>, remove_locks: bool) -> c_int {
    let Some(fd) = entry.fd else {
        return EBADF;
    };
    if remove_locks && let Some(remove) = table.ops.remove_locks {
        remove(&fd, table);
    }
    fd.close()
}

fn release_entries<D: Descriptor>(table: &Table<D>, entries: Vec<Entry<D>>, remove_locks: bool) {
    for entry in entries {
        release_entry(table, entry, remove_locks);
    }
}

fn find_free<D>(entries: &mut Vec<Entry<D>>, start: c_int, limit: usize) -> c_int {
    if start < 0 {
        return EBADF;
    }
    let from = start as usize;
    if let Some((index, _)) = entries
        .iter()
        .enumerate()
        .skip(from)
        .find(|(_, entry)| entry.fd.is_none())
    {
        return index as c_int;
    }
    let next = entries.len().max(from);
    if next >= limit {
        return EMFILE;
    }
    let error = expand(entries, next as c_int, limit);
    if error < 0 { error } else { next as c_int }
}

mod lifecycle;
pub use lifecycle::is_shared;

/// The operations, on a borrowed table.
///
/// **Methods on `&Table` since 2026-09-30.** Each was an `unsafe fn` taking a
/// `*const Table` or `*mut Table`, testing it for null and dereferencing it --
/// and `crates/fs/proc`, which holds an `Arc<Table>`, turned it back into a
/// pointer with `Arc::as_ptr` to call them. `&self` is the liveness the
/// `# Safety` sections asked for; the null a caller could pass is an
/// `Option<&Table>` on its side, which is where a task on its way out has one.
impl<D: Descriptor> Table<D> {
    /// Lookup and retain atomically with respect to slot removal. The returned
    /// fd owns one reference which the caller must release.
    pub fn lookup_retain(&self, fd: c_int) -> Option<D> {
        if fd < 0 {
            return None;
        }
        let state = lock(self);
        // The clone **is** the retain, and it happens under the table's mutex --
        // which is what makes the lookup and the reference one transaction, and
        // what the `retain` callback used to be for.
        state.entries.get(fd as usize)?.fd.clone()
    }

    /// Install an owned reference at the lowest free number.
    ///
    /// **`Err` gives the reference back**, which is what "on failure the caller
    /// still owns `fd`" used to say in prose. The caller relies on it:
    /// `f_install` closes the descriptor itself when the table refuses, so a
    /// version that consumed it either way would be a double release on every
    /// `EMFILE`.
    pub fn install_lowest(
        &self,
        fd: D,
        start: c_int,
        cloexec: bool,
        limit: usize,
    ) -> Result<c_int, (c_int, D)> {
        let mut state = lock(self);
        let number = find_free(&mut state.entries, start, limit);
        if number < 0 {
            return Err((number, fd));
        }
        state.entries[number as usize] = Entry { fd: Some(fd), cloexec };
        Ok(number)
    }

    /// Install at a fixed number, answering the displaced reference.
    ///
    /// The table operation is atomic and the **release is the caller's**, after
    /// this returns: a final release reaches the driver's `close`, which must
    /// not run under the table's mutex. That rule used to be a sentence; it is
    /// the signature now, because what comes back is a handle the caller has to
    /// drop somewhere.
    pub fn replace(
        &self,
        source: D,
        target: c_int,
        cloexec: bool,
        limit: usize,
    ) -> Result<Option<D>, (c_int, D)> {
        let mut state = lock(self);
        let error = expand(&mut state.entries, target, limit);
        if error < 0 {
            return Err((error, source));
        }
        let displaced = std::mem::replace(
            &mut state.entries[target as usize],
            Entry { fd: Some(source), cloexec },
        );
        Ok(displaced.fd)
    }

    /// Replace a contiguous range atomically, answering every displaced
    /// reference.
    ///
    /// **`Err` gives the reference back**, as [`Table::install_lowest`] and
    /// [`Table::replace`] do. The three used to disagree about that -- two of
    /// them consumed it either way and one did not -- which is how the same
    /// double release was written twice in one afternoon. The rule is one
    /// sentence now and it is in three signatures: **the table takes the
    /// reference only on success**.
    ///
    /// **The C entry point is `crates/fs/fdobj`'s**, not this function.
    /// `iul.h` declares `fdtable_replace_range` and
    /// `tests/integration/sbm_api_test.c` calls it -- it is how an embedder
    /// points the guest's stdio at a pty -- so the signature is a contract and
    /// takes a `void *`. A payload address cannot be turned back into a
    /// [`D`]: the control block is reached through `struct fd`'s
    /// `owner`, whose layout this crate deliberately does not know. So the shim
    /// lives where the layout does and this is the operation.
    pub fn replace_range(
        &self,
        source: D,
        first: c_int,
        count: usize,
        cloexec: bool,
        limit: usize,
        out_displaced: &mut Vec<Option<D>>,
    ) -> Result<(), (c_int, D)> {
        if first < 0 || count == 0 {
            return Err((EBADF, source));
        }
        let Some(last) = (first as usize).checked_add(count - 1) else {
            return Err((EMFILE, source));
        };
        let Ok(last) = c_int::try_from(last) else {
            return Err((EMFILE, source));
        };
        let mut state = lock(self);
        let error = expand(&mut state.entries, last, limit);
        if error < 0 {
            return Err((error, source));
        }
        if out_displaced.try_reserve(count).is_err() {
            return Err((ENOMEM, source));
        }
        for offset in 0..count {
            // One reference per slot. The clone **is** the retain the `Ops`
            // table used to carry: the old shape called `retain` `count - 1`
            // times and then stored the caller's own into every slot, which is
            // the same arithmetic written so that nobody can get the `- 1`
            // wrong.
            let displaced = std::mem::replace(
                &mut state.entries[first as usize + offset],
                Entry { fd: Some(source.clone()), cloexec },
            );
            out_displaced.push(displaced.fd);
        }
        // The reference the caller handed over. Every slot took a clone, so the
        // table holds `count` and this is the `+ 1` that must not stay.
        drop(source);
        Ok(())
    }

    /// Remove one slot and answer the reference it held.
    ///
    /// Nothing is released here: the caller decides where, which matters
    /// because a final release reaches the driver's `close` and must not run
    /// under the table's mutex. That used to be "no release callback runs
    /// here" in prose.
    pub fn take(&self, fd: c_int) -> Option<D> {
        if fd < 0 {
            return None;
        }
        lock(self)
            .entries
            .get_mut(fd as usize)
            .and_then(|entry| std::mem::take(entry).fd)
    }

    /// How many slots the table has, occupied or not: `/proc/<pid>/status`'s
    /// `FDSize`.
    pub fn size(&self) -> usize {
        lock(self).entries.len()
    }

    /// `FD_CLOEXEC` of an open descriptor; `None` when `fd` is not open.
    pub fn cloexec(&self, fd: c_int) -> Option<bool> {
        let index = usize::try_from(fd).ok()?;
        lock(self)
            .entries
            .get(index)
            .filter(|entry| entry.fd.is_some())
            .map(|entry| entry.cloexec)
    }

    /// Set `FD_CLOEXEC`. `EBADF` when `fd` is not open.
    pub fn set_cloexec(&self, fd: c_int, value: bool) -> c_int {
        let Ok(index) = usize::try_from(fd) else {
            return EBADF;
        };
        let mut state = lock(self);
        match state.entries.get_mut(index) {
            Some(entry) if entry.fd.is_some() => {
                entry.cloexec = value;
                0
            }
            _ => EBADF,
        }
    }

    /// The open descriptor numbers, ascending. No references are taken.
    ///
    /// `Err` when the vector cannot be allocated, which a `/proc` read answers
    /// with `ENOMEM`. It was a C-shaped pair of calls -- one with a null buffer
    /// for the count, one to fill it -- and both callers looped because the
    /// count could change between the two; one call under the lock cannot.
    pub fn numbers(&self) -> Result<Vec<c_int>, std::collections::TryReserveError> {
        let state = lock(self);
        let mut out = Vec::new();
        out.try_reserve(state.entries.iter().filter(|entry| entry.fd.is_some()).count())?;
        out.extend(
            state
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.fd.is_some())
                .map(|(slot, _)| slot as c_int),
        );
        Ok(out)
    }

    /// Drain CLOEXEC slots. Entries are removed atomically, then released after
    /// the mutex is dropped.
    pub fn exec_close(&self) {
        let doomed = {
            let mut state = lock(self);
            let mut doomed = Vec::new();
            let count = state
                .entries
                .iter()
                .filter(|entry| entry.fd.is_some() && entry.cloexec)
                .count();
            if doomed.try_reserve(count).is_err() {
                // Fall back to one-at-a-time detach; no allocation may turn exec
                // CLOEXEC cleanup into a silent skip.
                drop(state);
                loop {
                    let entry = {
                        let mut state = lock(self);
                        let Some(index) = state
                            .entries
                            .iter()
                            .position(|entry| entry.fd.is_some() && entry.cloexec)
                        else {
                            break;
                        };
                        std::mem::take(&mut state.entries[index])
                    };
                    release_entry(self, entry, true);
                }
                return;
            }
            for entry in &mut state.entries {
                if entry.fd.is_some() && entry.cloexec {
                    doomed.push(std::mem::take(entry));
                }
            }
            doomed
        };
        release_entries(self, doomed, true);
    }

    /// Apply `close_range`. 0, or `EINVAL` for a backwards range.
    pub fn close_range(&self, first: u32, last: u32, cloexec: bool) -> c_int {
        if first > last {
            return EINVAL;
        }
        if cloexec {
            let mut state = lock(self);
            if state.entries.is_empty() || first as usize >= state.entries.len() {
                return 0;
            }
            let end = (last as usize).min(state.entries.len() - 1);
            for entry in &mut state.entries[first as usize..=end] {
                if entry.fd.is_some() {
                    entry.cloexec = true;
                }
            }
            return 0;
        }
        let mut cursor = first as usize;
        loop {
            let (entry, next) = {
                let mut state = lock(self);
                if state.entries.is_empty() || cursor >= state.entries.len() {
                    break;
                }
                let end = (last as usize).min(state.entries.len() - 1);
                if cursor > end {
                    break;
                }
                let Some(index) = (cursor..=end).find(|&index| state.entries[index].fd.is_some()) else {
                    break;
                };
                (std::mem::take(&mut state.entries[index]), index + 1)
            };
            release_entry(self, entry, true);
            // Finalization runs without the table mutex and may let another
            // thread reuse the number just detached. Linux continues after that
            // number; starting again at `first` would close the newly published
            // entry too.
            cursor = next;
        }
        0
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
