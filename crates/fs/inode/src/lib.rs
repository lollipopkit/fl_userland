//! One `inode_data` per `(mount, inode number)`, for as long as anything holds
//! it.
//!
//! Every filesystem's inodes go through this one table. What hangs off an entry
//! is the file locks — POSIX record locks and BSD `flock` alike, because both
//! are properties of the *inode* and not of the filesystem holding it — and the
//! socket id an `AF_UNIX` bind stamps on the node it made.
//!
//! # A `HashMap`, where the C had a 1024-bucket intrusive hash
//!
//! Keyed on the pair, which is what the C compared after finding the bucket. The
//! bucket index was `ino % 1024` and the list was walked comparing both fields,
//! so this is the same lookup with the collision handling written by somebody
//! else. `inode_data.chain`, the bucket link, was still a field until
//! 2026-09-12 and nothing had read it since.
//!
//! # `Arc<Inode>`, and a `Weak` in the table
//!
//! Object model step 9.3, 2026-09-12. `inode_data.refcount` was a `u32`
//! maintained by hand under the inode's own `lock_t`: `inode_release`
//! decremented it, and the release that reached zero unlinked the table entry
//! under `inodes_lock` and then tore the object down outside both locks. The
//! strong count is an [`Arc`]'s now and the teardown is [`release`].
//!
//! **`Weak::upgrade` under `inodes_lock` is the interning idiom**, and it is
//! what removes the window the old shape existed to close. A lookup that finds
//! an entry whose strong count has already reached zero gets `None` — the
//! object is on its way out and cannot be resurrected — and makes a fresh one,
//! which is the answer the hand-rolled version could only approximate by doing
//! the unlink and the decrement under one lock.
//!
//! That leaves one obligation the `Arc` does not discharge, and it is the
//! classic interning bug: a dying inode's `Drop` must not unlink an entry a
//! *newer* inode has already put in its place. [`release`] removes the key
//! only when the `Weak` still stored under it points at this allocation.
//!
//! ## The `Arc` is the reference everywhere
//!
//! `struct fd`'s `inode` field is an `Option<Arc<inode_data>>`, and
//! `crates/fs/sock` holds a [`Ref`]. Until 2026-10-01 the `Arc` was of a
//! newtype only this crate could name, so every holder outside it had a
//! `*mut inode_data` from `Arc::into_raw` and gave it back through an
//! `unsafe` `inode_release`; `inode_data`'s own `Drop` reaches [`release`]
//! through a hook now, which is what let the newtype go.
//!
//! It also settles the `pthread_exit` question. `crates/kernel/exitcalls`'
//! `do_exit` ends in `pthread_exit`, which on Darwin abandons the Rust frames
//! below it without unwinding, so **nothing owning may be alive on the stack
//! at that call** — and an `Arc` in a syscall body's local is exactly that
//! shape. No syscall body holds one: the four sites that reach `do_exit*` or
//! `pthread_exit` from inside a syscall (`crates/kernel/pollcalls`' `poll` and
//! `select` watchdogs, `crates/kernel/offloadexec`'s `exit_with`, and
//! `crates/kernel/syscalldispatch`'s bail for a destroyed task) hold a raw
//! `*mut ffi::inode_data` at most, which owns nothing and leaks nothing.
//!
//! ## Where the last reference goes, and what is held when it does
//!
//! A `Drop` makes the release implicit, which is the point and is also what
//! makes this question harder to answer by reading than `inode_release(inode)`
//! on a line by itself was. `tools/lock-order.py --calls` cannot see a
//! destructor — it is one level below any call it follows — so this table is
//! the record:
//!
//! | site | thread | locks held at the drop | can it be the last? |
//! | --- | --- | --- | --- |
//! | `fs_fdobj::fd_finalize` | whoever closed the last descriptor | none — `crates/fs/fdtable` takes its entry vector out with `mem::take` before releasing anything, and `crates/kernel/pagetable`'s `pt_unmap_always` reaches it under `mem->lock` | **yes**, and usually |
//! | `crates/fs/sock`'s `sock_close` and `drop_names` | the closing thread | none | **yes**, for a bound `AF_UNIX` name nothing else has open |
//! | [`unix_socket_id`]'s [`Ref`], once the caller drops it | the binding thread | none — the inode's own lock is released two lines above | yes, when the node was made for this lookup |
//! | [`inode_writers_of`] | any | none — **the upgraded reference is dropped after `with` returns**, deliberately, because the holder can release between the upgrade and the read | yes, and see below |
//!
//! **[`release`] takes `inodes_lock`**, which is why the fourth row is
//! written the way it is: dropping that reference inside the `with` closure
//! would be `inodes_lock` taken twice on one thread, and `std::sync::Mutex` is
//! not reentrant. That is the one deadlock this conversion could introduce and
//! the only place it could.
//!
//! It then takes **no other lock**. The filesystem's `inode_orphaned` does
//! database work, so it runs after the table's lock is dropped — holding a global lock across a call
//! into an arbitrary mount is how lock-order inversions get made.
//!
//! That last sentence is about the *teardown* path, and it is worth being
//! exact, because two functions here do the opposite **on purpose** and a
//! reader who takes it as a crate-wide rule will read them as mistakes:
//! [`generic_attach_inode`] calls the mount's `fstat` under `inodes_lock`
//! because the stat and the lookup have to be one operation, and
//! [`inode_check_orphaned`] calls `inode_orphaned` under it. So the order
//! `inodes_lock → a mount's own lock` exists and is taken deliberately, which
//! is exactly why the teardown must not add `a mount's own lock →
//! inodes_lock` — and it is the reason the destructor's unlink is a short
//! critical section with everything else after it.
//!
//! `tools/lock-order.py` sees none of this: `inodes_lock` is a Rust `Mutex`
//! rather than a `lock_t`, and the teardown is inside a `Drop`.
//!
//! # Two things the C leaked
//!
//! `inode_release` freed the inode and never touched the lock set hanging off
//! it, and never destroyed the condition variable it had initialised. Both
//! live in `inode_data.state` now and go when it drops; `GuestLock`'s
//! destroy is where pthread answers `EBUSY` for a waiter still parked on
//! memory about to be freed — which is why it is a destroy and not a skip.
//!
//! A thread parked on that condition is a thread inside a blocking `fcntl`
//! lock request, and it reached that wait through a descriptor whose reference
//! it still holds — so there can be no waiter when the last reference goes,
//! and the destroy traps if that is ever untrue rather than freeing the memory
//! out from under one.

/* `#![allow(clippy::missing_safety_doc)]` was here until 2026-09-15. Measured
 * rather than read, per `docs/changelog/2026-09-12-two-clippy-suppressions-that-covered-nothing.md`:
 * delete it, `touch` the file so clippy recompiles, and count the lint's spans.
 * It is zero -- every `unsafe fn` this crate exports has a `# Safety` section,
 * and the ones that lost theirs this commit lost the `unsafe` with it. A
 * blanket allow over an empty set reads as "this crate has undocumented
 * contracts", which is the opposite of what is true here. */

use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

mod errno {
    pub use guest_errno::c_int_::ENOMEM;
}

/// `(mount, inode number)`: two filesystems can have the same inode number.
///
/// The mount half was a `usize` — its address cast to an integer, which is
/// what the C compared — until 2026-09-15. It is [`ffi::MountId`] now, so the
/// two halves of the key cannot be swapped or compared against each other, and
/// the cast that made one is in the type rather than at each of the six call
/// sites. Nothing here ever reads the mount back out; see `MountId` for why
/// that is what makes constructing one safe.
type Key = (ffi::MountId, u64);

/// An owned reference to an interned inode. **Dropping it is the release.**
///
/// `Arc<inode_data>` since 2026-10-01. It was `Arc<Inode>`, a newtype this
/// crate owned so that it could `impl Drop`, erased to a `*mut inode_data`
/// with `into_raw` for `struct fd` and given back with an `unsafe`
/// `inode_release`. `inode_data`'s own `Drop` calls [`release`] through a
/// hook now, so the field is an `Option<Arc>` and the erasure is gone.
pub type Ref = Arc<ffi::inode_data>;

/// Every live inode, weakly.
///
/// A `Weak` and not an `Arc`: the table interns, it does not own. An entry
/// whose strong count has reached zero is one whose [`release`] is running or
/// about to, and `Weak::upgrade` answering `None` is exactly the question a
/// lookup needs to ask.
struct Table(HashMap<Key, Weak<ffi::inode_data>>);

static TABLE: Mutex<Option<Table>> = Mutex::new(None);

fn with<T>(f: impl FnOnce(&mut Table) -> T) -> T {
    let mut guard = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(|| Table(HashMap::new())))
}

fn key(mount: &ffi::mount, ino: u64) -> Key {
    (mount.id(), ino)
}

/// How many inodes are held right now, for `/proc/iul/objects`.
///
/// An inode is created on the first reference and freed on the last, so a
/// process that opens and closes the same files returns this to where it
/// started. A number that only grows is a reference nobody released — and this
/// table is reached from every filesystem, so that would be a leak the size of
/// the workload.
///
/// **A counter and not `TABLE.len()`**, which is what it was until the `Weak`
/// arrived on 2026-09-12: an entry stays in the map from the moment its strong
/// count reaches zero until [`release`] takes `inodes_lock` and unlinks it,
/// so `len()` would report a dead inode as live and a leak as normal. This is
/// also **the only thing in the tree that can see a leaked inode** — a strong
/// count one too high keeps the object, its lock set and a mount reference for
/// ever, and every assertion in the guest suite still passes. See
/// `crates/fs/inode/tests/live_count.rs`.
///
/// `Relaxed`: it is a diagnostic, and a reader that wants it to mean anything
/// has to be the only thread opening files.
///
/// Not `#[unsafe(no_mangle)]` since 2026-09-06. No C source calls it, no
/// `ffi::` reaches it, and no header the embedder example compiles against
/// declares it -- so the export was a second interface with nobody on the
/// other side, and an optimisation barrier: LTO must emit an externally
/// visible function as written and cannot specialise the call.
pub fn inode_live_count() -> u64 {
    LIVE.load(Ordering::Relaxed) as u64
}

/// See [`inode_live_count`].
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// Make an entry, with one reference taken.
///
/// The mount is retained here and released in [`release`].
///
/// Infallible, where the version before the `Arc` answered a null pointer that
/// three callers tested: `Arc::new` cannot fail — Rust aborts on allocation
/// failure — and neither could `Box::new` before it, so the tests were dead.
fn make(mount: &ffi::mount, ino: u64) -> Ref {
    // The first inode is the earliest moment the hook can have anything to
    // do; see `inode_data`'s `Drop`.
    ffi::set_inode_release_hook(release);
    // Handed to the field, and given back by [`release`]'s `from_raw`.
    // SAFETY: `retain` wants a pointer and only touches `refcount`, which is
    // an `AtomicU32`; the reference is what says it is live.
    let mount = unsafe { fs_mounttable::MountRef::retain(mount.as_ptr()) }.into_raw();
    let inode = Arc::new(ffi::inode_data::new(ino as _, mount));
    LIVE.fetch_add(1, Ordering::Relaxed);
    inode
}

/// The last reference has gone: `inode_data`'s `Drop`, through the hook
/// [`make`] installs. See the module comment for which lock is held at each
/// site that can drop one.
fn release(me: &mut ffi::inode_data) {
    // The entry, **only if it is still ours**. A lookup whose `Weak::upgrade`
    // failed while this was on its way out has already put a fresh inode under
    // the same key, and removing that one is the interning bug `Arc` does not
    // prevent: the next lookup would build a third object for a file two
    // descriptors already share. The mount as an identity, which is all a key
    // is. `make` retained one, so the null arm is an `inode_data` that never
    // went through `make` -- a test's -- and there is nothing to undo.
    let Some(id) = ffi::MountId::from_ptr(me.mount) else {
        return;
    };
    let k = (id, me.number);
    let address: *const ffi::inode_data = me;
    with(|t| {
        if t.0.get(&k).is_some_and(|w| std::ptr::eq(w.as_ptr(), address)) {
            t.0.remove(&k);
        }
    });
    LIVE.fetch_sub(1, Ordering::Relaxed);

    // Outside the table's lock: the filesystem's `inode_orphaned` does
    // database work, and holding a global lock across a call into an
    // arbitrary mount is how lock-order inversions get made. The file locks,
    // the condition variable and the mutex go with `state` after this returns
    // -- the C leaked the first two.
    //
    // SAFETY: `make` stored a `MountRef::into_raw` here, and this is the one
    // place it is taken back.
    let mount = unsafe { fs_mounttable::MountRef::from_raw(me.mount) };
    if let Some(fs) = mount.fs {
        fs.inode_orphaned(&mount, me.number);
    }
}

/// The returned `Arc` must not be dropped while the caller still holds the
/// table's lock — see the module comment's fourth drop-site row. That is a
/// **deadlock** and not undefined behaviour, so it is stated here rather than
/// in a `# Safety` section: `std::sync::Mutex` is not reentrant and
/// [`release`] takes `inodes_lock`.
fn get_locked(t: &mut Table, mount: &ffi::mount, ino: u64) -> Ref {
    let k = key(mount, ino);
    // The interning idiom: a failed upgrade means this entry's inode has
    // already reached zero strong references, so it cannot be revived and a
    // fresh one takes its place. The old shape did the decrement and the unlink
    // under one lock to close the same window; this closes it in the type.
    if let Some(found) = t.0.get(&k).and_then(Weak::upgrade) {
        return found;
    }
    let inode = make(mount, ino);
    t.0.insert(k, Arc::downgrade(&inode));
    inode
}

// ------------------------------------------------------------ the writer count
//
// Linux's `i_writecount`, and the reason a running program cannot be written
// to and a file being written cannot be run -- `ETXTBSY` in both directions.
// Positive is how many descriptors hold the file open for writing; negative
// is how many running programs hold it. A transition that would cross zero
// the wrong way is refused. Each is one compare-and-swap, because an `open`
// and an `execve` of the same file on two threads share no lock, and Linux's
// are `atomic_inc_unless_negative` and `atomic_dec_unless_positive` for the
// same reason.

use guest_errno::c_int_::ETXTBSY;

/// A descriptor is being opened for writing: `0`, or `ETXTBSY` if a program
/// holds the file.
///
/// The four take `&inode_data` since 2026-10-01; they were `unsafe fn`s over a
/// nullable pointer, and every caller had a description holding the inode.
pub fn inode_get_write_access(inode: &ffi::inode_data) -> c_int {
    match inode.writers.fetch_update(Ordering::AcqRel, Ordering::Acquire, |w| {
        (w >= 0).then_some(w + 1)
    }) {
        Ok(_) => 0,
        Err(_) => ETXTBSY,
    }
}

/// The descriptor that took one, by [`inode_get_write_access`], is closing.
pub fn inode_put_write_access(inode: &ffi::inode_data) {
    inode.writers.fetch_sub(1, Ordering::AcqRel);
}

/// A program is about to run from this file: `0`, or `ETXTBSY` if a
/// descriptor holds it open for writing.
///
pub fn inode_deny_write_access(inode: &ffi::inode_data) -> c_int {
    match inode.writers.fetch_update(Ordering::AcqRel, Ordering::Acquire, |w| {
        (w <= 0).then_some(w - 1)
    }) {
        Ok(_) => 0,
        Err(_) => ETXTBSY,
    }
}

/// The program's descriptor, which [`inode_deny_write_access`] succeeded
/// for, is closing.
pub fn inode_allow_write_access(inode: &ffi::inode_data) {
    inode.writers.fetch_add(1, Ordering::AcqRel);
}

/// `F_GET_RW_HINT`: the write-life hint stored on this inode, 0 when none has
/// been set.
pub fn write_hint(inode: &ffi::inode_data) -> u8 {
    inode.write_hint.load(Ordering::Relaxed)
}

/// `F_SET_RW_HINT`, validated by the caller. Per inode rather than per
/// description, which is what makes a set through one descriptor visible
/// through another of the same file, as on Linux.
pub fn set_write_hint(inode: &ffi::inode_data, value: u8) {
    inode.write_hint.store(value, Ordering::Relaxed);
}

/// The count for `(mount, ino)`, or 0 when no descriptor holds the file at
/// all: a lookup that creates nothing, for a path operation with no
/// descriptor of its own. `truncate(2)` asks it, because Linux's
/// `do_sys_truncate` takes write access on the way and answers `ETXTBSY` for
/// a running program.
///
pub fn inode_writers_of(mount: &ffi::mount, ino: u64) -> c_int {
    // **The upgraded reference leaves the closure before it is dropped**, and
    // that is the one thing this conversion could deadlock on: the holder can
    // release between the upgrade and the read, which makes this the last
    // reference, and [`release`] takes `inodes_lock` — which `with` is
    // still holding inside the closure, and a `std::sync::Mutex` is not
    // reentrant.
    let found = with(|t| t.0.get(&key(mount, ino)).and_then(Weak::upgrade));
    match found {
        Some(inode) => inode.writers.load(Ordering::Acquire),
        None => 0,
    }
}

/// Nothing holds this inode any more, so the filesystem may drop whatever it
/// keeps for it. Called after an unlink, where the last reference may or may not
/// have gone.
///
/// The null check on the operation matters: only fakefs implements
/// `inode_orphaned`, so any other mount reaching this would call through a null
/// pointer. Not reachable today — both callers are in fakefs — and one line away
/// from being so.
pub fn inode_check_orphaned(mount: &ffi::mount, ino: u64) {
    with(|t| {
        // `strong_count` and not `contains_key`, and not `upgrade` either: an
        // entry stays in the map until [`release`] unlinks it, so a
        // present-but-dead one would read as held; and upgrading would make
        // this closure a place the last reference could be dropped, under the
        // lock that `Drop` takes. An inode on its way out counts as held,
        // because its own `Drop` calls `inode_orphaned` a few lines later.
        if t.0.get(&key(mount, ino)).is_some_and(|w| w.strong_count() != 0) {
            return;
        }
        if let Some(fs) = mount.fs {
            fs.inode_orphaned(&*mount, ino as _);
        }
    });
}

/// The socket id an inode carries, assigned on first use.
///
/// The reference comes back with it, and **the caller's `drop` is "release it
/// here"**. A `bind` keeps it, so the node stays alive while there is a
/// listener; a lookup drops it.
///
/// It was `(mount, ino, id_out: *mut u32, keep: *mut *mut inode_data) -> c_int`
/// until 2026-09-14: two out-parameters, a null `keep` meaning "release it
/// yourself", and a return code that was always 0.
///
/// The id is read **under the inode's lock**. The version this replaces
/// assigned it inside the lock and read it outside, so two threads binding the
/// same path could see different ids for one inode: the second one's read raced
/// the first one's assignment. Nothing observed it — the window is two
/// instructions — but the whole point of the id is that one inode has one.
///
/// The `# Safety` section here read "`mount` is live; `id_out` is writable;
/// `keep` is null or writable" until 2026-09-15, and by then two of its three
/// clauses named parameters this function no longer has — the id and the
/// reference are the return value. The third is what `&mount` says.
pub fn unix_socket_id(mount: &ffi::mount, ino: u64) -> (u32, Ref) {
    let held = with(|t| get_locked(t, mount, ino));
    let id = {
        let mut state = held.state.lock();
        if state.socket_id == 0 {
            state.socket_id = unixname::unixname_next_id();
        }
        state.socket_id
    };
    (id, held)
}

/// The inode side of an open: `fstat` the descriptor and attach the entry for
/// what it reports, **under one hold of the table's lock**.
///
/// The two have to be one operation. Between an `fstat` that reports an inode
/// number and the lookup for it, an `unlink` on another thread can take the last
/// reference and free the entry, and the open would then make a second one for a
/// node the filesystem has already dropped.
///
/// Fills `stat` as a side effect, because the caller needs the mode and the
/// device number and asking twice would be a second trip into the mount.
///
/// Safe since 2026-10-01: it took the description as a raw pointer, and its
/// one caller builds it unpublished and holds it by `&mut`.
///
/// The mount is the description's own: its `fstat` reads it.
pub fn generic_attach_inode(fd: &mut ffi::fd, stat: &mut ffi::statbuf) -> c_int {
    let Some(mount) = fd.mount() else {
        return errno::ENOMEM;
    };
    let found = with(|t| {
        // Three states, three arms. `None` -- the filesystem does not answer
        // `fstat` -- is `ENOMEM` here, which is this caller's own reading and
        // is why the trait keeps the case distinct from a failure.
        let filled = match mount.fs.and_then(|fs| fs.fstat(fd)) {
            None => return Err(errno::ENOMEM),
            Some(Err(e)) => return Err(e),
            Some(Ok(filled)) => filled,
        };
        *stat = filled;
        Ok(get_locked(t, mount, stat.inode))
    });
    // Stored after the table's lock is released: the assignment drops whatever
    // the field held, and a drop is [`release`], which takes that lock.
    match found {
        Ok(inode) => {
            fd.inode = Some(inode);
            0
        }
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two filesystems can have the same inode number, which is why the key is
    /// the pair. The C found the bucket by `ino % 1024` and then compared both
    /// fields; this is the same lookup.
    #[test]
    fn the_key_is_the_mount_and_the_number() {
        // Two identities, and no mounts. `ffi::MountId::from_ptr` is safe
        // because a `MountId` is never dereferenced, which is what lets this
        // test say what it is about — the pair — rather than build two
        // filesystems to say it.
        let a = ffi::MountId::from_ptr(0x1000 as *mut ffi::mount).unwrap();
        let b = ffi::MountId::from_ptr(0x2000 as *mut ffi::mount).unwrap();
        assert_ne!((a, 5), (b, 5));
        assert_ne!((a, 5), (a, 6));
        assert_eq!((a, 5), (a, 5));
        assert_eq!(ffi::MountId::from_ptr(std::ptr::null_mut()), None);
    }

    /// Making an inode installs the release hook, and nothing else can catch
    /// it if it stops: without it every inode would leak its table entry, its
    /// mount reference and the filesystem's `inode_orphaned`, and every answer
    /// would still be right.
    #[test]
    fn making_an_inode_installs_its_release() {
        let owned = Box::<ffi::mount>::default();
        drop(make(&owned, 0xfeed_0001));
        assert!(ffi::inode_release_hook_installed());
    }

    /// A dying inode must not unlink the entry that replaced it.
    ///
    /// This is the interning bug `Arc` does **not** prevent, and the only
    /// thing [`release`]'s pointer comparison is for. It arises when a
    /// lookup's `Weak::upgrade` answers `None` — the entry's inode has reached
    /// zero strong references but its `Drop` has not yet taken `inodes_lock` —
    /// so the lookup puts a fresh inode under the same key and the dying one
    /// arrives at the table afterwards.
    ///
    /// Getting there by racing needs two threads and would be a test that
    /// passes most of the time, which this tree counts as a test that passes
    /// against nothing. The *state* the race produces is one line, so this
    /// builds it directly: an entry replaced while the first inode is still
    /// alive, which is the same table the loser of the race would arrive at.
    ///
    /// What it costs to be wrong: the entry is gone while a live inode exists
    /// for that file, so the next `open` builds a third object — two
    /// `struct fd`s pointing at two `inode_data`s for one node, which is two
    /// disjoint sets of file locks and two `writers` counts on one file.
    /// Remove the `ours` test in [`release`] and the first assertion below
    /// fails.
    #[test]
    fn a_dying_inode_does_not_unlink_the_entry_that_replaced_it() {
        // Zeroed, which is `fs: None` -- so the teardown skips
        // `inode_orphaned` and this needs no filesystem. The mount's own
        // refcount is what `MountRef` moves, and it balances here.
        let owned = Box::<ffi::mount>::default();
        let mount: &ffi::mount = &owned;
        let ino = 0xfeed_1234;
        let k = key(mount, ino);

        let first = with(|t| get_locked(t, mount, ino));
        let second = make(mount, ino);
        with(|t| t.0.insert(k, Arc::downgrade(&second)));

        drop(first);
        assert!(
            with(|t| t.0.contains_key(&k)),
            "the dying inode unlinked an entry a newer one owns"
        );
        // And it is still the replacement under that key, not something the
        // removal-and-reinsert could have left. The upgraded reference is
        // dropped *after* `with` returns, which is the module comment's rule.
        let under_key = with(|t| t.0.get(&k).and_then(Weak::upgrade));
        assert!(under_key.is_some_and(|f| Arc::ptr_eq(&f, &second)));

        drop(second);
        assert!(
            !with(|t| t.0.contains_key(&k)),
            "the owner of the entry left it behind"
        );
        drop(owned);
    }
}
