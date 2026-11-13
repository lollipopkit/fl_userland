//! File locking, for every filesystem at once.
//!
//! Locks belong to the inode, not to the filesystem holding it, which is why
//! this is one crate and not a `flock` entry in each `fs_ops`. The C treated
//! the two kinds of lock differently for no reason that survives inspection:
//! POSIX record locks were implemented here, generically, on `inode_data`,
//! while `flock(2)` was dispatched through `fs_ops` — so it worked only on the
//! mounts backed by a host file and answered `EBADF` everywhere else.
//!
//! realfs and fakefs still take `flock` themselves, and should: their files
//! are host files, possibly shared with a host process, and the host's lock is
//! then the one that matters. Everything else lands here.
//!
//! ## What holds what
//!
//! The set of locks hangs off `inode_data.locks` and is only ever touched
//! under `inode_data.lock`. A request that cannot be granted waits on
//! `inode_data.lock_released` through the kernel's `wait_for`, which is the
//! only interruptible wait there is — it records the sleeping task's condition
//! and lock so that delivering a signal can wake it. A Rust `Condvar` would
//! not be interruptible, and a guest blocked on a lock would then ignore
//! Ctrl-C for ever.

use std::os::raw::c_int;

mod bsd;
mod posix;

mod fcntl;
pub(crate) use fcntl::inode_of;

mod flock;
pub use fcntl::*;
pub use flock::*;

#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    clippy::all
)]
/// Public since 2026-09-06 so that `crates/kernel/fdcalls` can import
/// `flock_` from here instead of generating a second one. The two met over a C
/// ABI call that reinterpreted and checked nothing; rustc says they are
/// different types the moment the call is Rust. Not in
/// `crates/kernel/taskview` because only two crates want it and the shared set
/// costs every consumer a rebuild when its defining header changes.
// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

// Guest errnos, negated as everywhere else in the tree.
use guest_errno::c_int_::{EAGAIN, EBADF, EDEADLK, EINTR, EINVAL, EOVERFLOW};
use util_guestlock::{GuestGuard, Woke};

/// Deadlock detection for blocking requests: Linux's `posix_locks_deadlock`.
///
/// A request that would wait for a lock whose owner is itself waiting --
/// directly or through others -- for a lock the requester holds can never be
/// granted, and Linux refuses it with `EDEADLK` instead of parking it for
/// ever. The table is process-wide and keyed by owner, because a cycle can run
/// through two files: A holds file 1 and waits for file 2, B holds file 2 and
/// waits for file 1. Open-file-description locks are exempt, as they are on
/// Linux, whose comment says why: their owner is a description, which can be
/// shared by processes that are not waiting on each other at all.
///
/// Until 2026-09-04 nothing here detected anything: `lock_probe` closed a
/// cycle between a parent and its child, and the request that closed it waited
/// until an alarm interrupted it.
/// Who a lock belongs to.
///
/// **Two kinds of address, and there were two `Owner` aliases.** A POSIX
/// record lock belongs to the descriptor *table*, so threads sharing one do
/// not lock each other out and a forked child does; a BSD `flock` and an
/// open-file-description lock (`F_OFD_SETLK`) belong to the *description*
/// instead.
///
/// Until 2026-09-16 that was `posix::Owner = usize` — documented as "an owner
/// is a `struct fdtable *`", which is true of one of the two things it carried
/// — and `bsd::Owner = usize` beside it. Two aliases of one underlying type in
/// one crate, for three meanings, so `bsd.release(posix_owner)` type-checked
/// as readily as the right call and `crates/fs/locks/src/flock.rs` passed
/// `fd as usize` to both.
///
/// No defect followed: a `struct fd` and a `struct fdtable` are different
/// allocations, so the kinds could never compare equal by accident. What it
/// cost is that the types said one thing and carried two.
///
/// **Compared, never dereferenced** — which is why the address inside is a
/// plain `usize` and why the pure-logic tests in [`posix`] and [`bsd`] can name
/// owners as `1` and `2`. That is the same trade `crates/kernel/epoll`'s
/// `SetId` and `FileId` make, and it is stated where they are defined too.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Owner {
    /// A `struct fdtable *`: every descriptor in one table shares this owner.
    Table(usize),
    /// A `struct fd *`: one open file description, shared by `dup` and `fork`
    /// and released when the description goes.
    Description(usize),
}

impl Owner {
    /// The description this descriptor is, as an owner — what a BSD lock and
    /// an `F_OFD_*` record lock both use.
    fn of_description(fd: &ffi::fd) -> Owner {
        Owner::Description(std::ptr::from_ref(fd) as usize)
    }
}

mod deadlock {
    use crate::Owner;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, MutexGuard};

    /// How far a chain is followed. Linux's `MAX_DEADLK_ITERATIONS`: a chain
    /// longer than this is not called a deadlock, and the request waits.
    const MAX_DEPTH: usize = 10;

    /// Who is waiting on whom, by owner. Linux's `blocked_hash`.
    ///
    /// Keyed on [`Owner`] rather than on a `usize`, which is what it was: this
    /// is the same owner the records carry, and two spellings of one concept
    /// is what let that alias claim to be a `struct fdtable *` while carrying
    /// a `struct fd *` half the time.
    static WAITS: Mutex<BTreeMap<Owner, Owner>> = Mutex::new(BTreeMap::new());

    fn table() -> MutexGuard<'static, BTreeMap<Owner, Owner>> {
        WAITS.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `requester` waiting on `blocker` would close a cycle: `blocker`
    /// is waiting, directly or through up to [`MAX_DEPTH`] others, on a lock
    /// `requester` holds.
    pub fn closes_cycle(blocker: Owner, requester: Owner) -> bool {
        walk(&table(), blocker, requester)
    }

    fn walk(waits: &BTreeMap<Owner, Owner>, blocker: Owner, requester: Owner) -> bool {
        let mut at = blocker;
        for _ in 0..=MAX_DEPTH {
            if at == requester {
                return true;
            }
            match waits.get(&at) {
                Some(next) => at = *next,
                None => return false,
            }
        }
        false
    }

    /// An owner parked on another's lock, for as long as this exists.
    pub struct Waiting(Owner);

    impl Waiting {
        pub fn new(owner: Owner, blocker: Owner) -> Waiting {
            table().insert(owner, blocker);
            Waiting(owner)
        }
    }

    impl Drop for Waiting {
        fn drop(&mut self) {
            table().remove(&self.0);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Owners by number, as this module's tests have always named them:
        /// the graph compares them and never reads through one, which is the
        /// same reason [`Owner`]'s address is a plain `usize`.
        fn o(n: usize) -> Owner {
            Owner::Table(n)
        }

        #[test]
        fn a_direct_cycle_is_refused_and_an_open_chain_is_not() {
            let mut waits = BTreeMap::new();
            // B is waiting on A. A asking to wait on B closes the cycle.
            waits.insert(o(2), o(1));
            assert!(walk(&waits, o(2), o(1)));
            // A third party asking to wait on B is a chain, not a cycle.
            assert!(!walk(&waits, o(2), o(3)));
            // And nobody waiting on the blocker at all.
            assert!(!walk(&BTreeMap::new(), o(2), o(1)));
        }

        #[test]
        fn a_cycle_through_others_is_found() {
            let mut waits = BTreeMap::new();
            waits.insert(o(3), o(2)); // C waits on B
            waits.insert(o(2), o(1)); // B waits on A
            assert!(
                walk(&waits, o(3), o(1)),
                "A waiting on C closes A -> C -> B -> A"
            );
            assert!(!walk(&waits, o(3), o(9)));
        }

        #[test]
        fn a_chain_longer_than_linux_follows_is_not_called_a_deadlock() {
            let mut waits = BTreeMap::new();
            for i in 2..=(MAX_DEPTH + 3) {
                waits.insert(o(i), o(i - 1));
            }
            // The cycle would close at 1, which is MAX_DEPTH + 2 hops away.
            assert!(!walk(&waits, o(MAX_DEPTH + 3), o(1)));
            // A cycle within the bound is found.
            assert!(walk(&waits, o(MAX_DEPTH + 1), o(1)));
        }

        #[test]
        fn a_wait_is_recorded_only_while_it_lasts() {
            let owner = o(0xdead_0001);
            let blocker = o(0xdead_0002);
            {
                let _w = Waiting::new(owner, blocker);
                assert!(closes_cycle(owner, blocker));
            }
            assert!(!closes_cycle(owner, blocker));
        }

        /// **A table owner and a description owner are not the same owner**,
        /// even at one address. They cannot collide in the product -- a
        /// `struct fd` and a `struct fdtable` are different allocations -- so
        /// this is about the type rather than about a defect: before
        /// 2026-09-16 both were a bare `usize` and this assertion could not be
        /// written at all.
        #[test]
        fn the_two_kinds_of_owner_are_distinct() {
            let mut waits = BTreeMap::new();
            // Description 1 is waiting on description 2.
            waits.insert(Owner::Description(1), Owner::Description(2));
            assert!(walk(&waits, Owner::Description(1), Owner::Description(2)));

            // **Table 1 is a different owner**, so it is waiting on nothing
            // and this chain does not reach description 2.
            //
            // The mixed pair is what isolates the kind, and the first version
            // of this test did not have it: asking `walk(Table(1), Table(2))`
            // answers false whether or not the lookup distinguishes them, so
            // it passed with an `Ord` that ignored the variant. A check that
            // accepts either answer is not a check.
            assert!(
                !walk(&waits, Owner::Table(1), Owner::Description(2)),
                "a table owner is not the description owner at the same address"
            );
        }
    }
}

/// Both kinds of lock on one inode.
///
/// One allocation per inode that has ever been locked, made on demand and
/// freed when the inode goes away — or as soon as the last lock on it is
/// dropped; see [`InodeGuard`].
#[derive(Default)]
struct Locks {
    posix: posix::Set,
    bsd: bsd::Set,
}

impl Locks {
    fn is_empty(&self) -> bool {
        self.posix.is_empty() && self.bsd.is_empty()
    }
}

/// Tell `crates/fs/fdobj` what to do about a lock when a descriptor dies.
///
/// `flock_release` and `file_lock_remove_owned_by` were `extern "C"`
/// declarations under a `keep-c-abi` marker until 2026-09-09. The marker's
/// reason was right and has not changed — a file lock is owned by a descriptor,
/// so this crate depends on `fdobj` and a call the other way is a cycle. What
/// changed is that the edge no longer needs a symbol. `fs/inode`'s
/// `file_locks_destroy` was a third hook until 2026-10-01; the set is dropped
/// with the inode now.
///
/// Idempotent: after the first, each `OnceLock::set` is an acquire load that
/// fails.
fn install_hooks() {
    fs_fdobj::set_fd_locks_hook(&Hooks);
}

/// The descriptor half, as one object because the two always arrive together.
struct Hooks;

// Both methods are the free functions below.
impl fs_fdobj::FdLocks for Hooks {
    fn flock_release(&self, fd: &ffi::fd) {
        flock_release(fd);
    }
    fn remove_owned_by(&self, fd: &ffi::fd, owner: *mut ffi::fdtable) {
        file_lock_remove_owned_by(fd, owner);
    }
    fn held_by(&self, fd: &ffi::fd, table: *const ffi::fdtable) -> Vec<fs_fdobj::HeldLock> {
        held_by(fd, table)
    }
}

// ---------------------------------------------------------------------------
// The inode's lock and condition
// ---------------------------------------------------------------------------

/// Holds `inode_data.state` for as long as it exists, and drops the lock set
/// on the way out if nothing is left in it -- so a program locking and
/// unlocking in a loop does not leave a growing pile of empty sets behind it.
///
/// It held a raw `*mut inode_data` and took the embedded `lock_t` by hand
/// until 2026-10-01, and the set was a `*mut c_void` boxed and unboxed in four
/// `unsafe fn`s; the `GuestLock` owns the set now.
struct InodeGuard<'a>(GuestGuard<'a, ffi::InodeState>);

impl<'a> InodeGuard<'a> {
    fn new(inode: &'a ffi::inode_data) -> InodeGuard<'a> {
        InodeGuard(inode.state.lock())
    }

    /// The lock set, made if this inode has none yet.
    fn locks(&mut self) -> &mut Locks {
        self.0
            .locks
            .get_or_insert_with(|| {
                // The first lock set in the process, so the earliest moment
                // either hook can have anything to do: before this, every
                // inode's set is `None` and a closing descriptor releases
                // nothing. Installing here rather than at boot is the rule
                // CLAUDE.md states, and the condition it asks for holds
                // exactly.
                install_hooks();
                Box::<Locks>::default()
            })
            .downcast_mut()
            .expect("crates/fs/locks is the only writer of inode_data.state.locks")
    }

    /// Whether this inode has a lock set at all. A close asks before taking
    /// anything further.
    fn has_locks(&self) -> bool {
        self.0.locks.is_some()
    }

    /// Wake everything waiting for a lock on this inode to be released.
    fn notify(&self) {
        self.0.owner().notify(ffi::INODE_LOCK_RELEASED);
    }

    /// Release the inode lock, wait for someone to drop a lock, and take it
    /// again. `EINTR` if a signal arrived instead.
    fn wait(&mut self) -> Result<(), c_int> {
        match self.0.wait(ffi::INODE_LOCK_RELEASED, None) {
            Woke::Interrupted => Err(EINTR),
            Woke::Notified | Woke::TimedOut => Ok(()),
        }
    }
}

impl Drop for InodeGuard<'_> {
    fn drop(&mut self) {
        let empty = self
            .0
            .locks
            .as_deref()
            .and_then(|l| l.downcast_ref::<Locks>())
            .is_some_and(Locks::is_empty);
        if empty {
            self.0.locks = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly one of the three operations, with `LOCK_NB` optional.
    ///
    /// The C tested each bit separately, so `LOCK_SH|LOCK_EX` asked the host for
    /// both; and `sys_flock` used to look the descriptor up before applying any
    /// of this, so `flock(-1, 0)` answered `EBADF` — naming the argument that
    /// was fine.
    #[test]
    fn an_operation_is_one_of_three() {
        let sh = ffi::LOCK_SH_ as c_int;
        let ex = ffi::LOCK_EX_ as c_int;
        let un = ffi::LOCK_UN_ as c_int;
        let nb = ffi::LOCK_NB_ as c_int;

        assert_eq!(decode_flock(sh), Ok((Flock::Shared, true)));
        assert_eq!(decode_flock(ex), Ok((Flock::Exclusive, true)));
        assert_eq!(decode_flock(un), Ok((Flock::Unlock, true)));
        assert_eq!(decode_flock(ex | nb), Ok((Flock::Exclusive, false)));

        assert_eq!(decode_flock(0), Err(EINVAL), "no operation at all");
        assert_eq!(decode_flock(sh | ex), Err(EINVAL), "two at once");
        assert_eq!(
            decode_flock(nb),
            Err(EINVAL),
            "a modifier and nothing to modify"
        );
        assert_eq!(decode_flock(0x40), Err(EINVAL), "a bit that means nothing");
    }

    /// Making the first lock set installs the hook, and nothing else can
    /// catch it if it stops: with no hook a closing descriptor releases
    /// nothing, and with it a descriptor that holds no lock does nothing
    /// either. A missing install shows only in a running guest, as a record
    /// lock outliving the process that took it.
    ///
    /// Through [`InodeGuard::locks`] since 2026-10-01, which is the call site
    /// under test: an `inode_data` can be built without a filesystem now.
    #[test]
    fn the_first_lock_set_installs_what_frees_it() {
        let inode = ffi::inode_data::new(1, std::ptr::null_mut());
        InodeGuard::new(&inode).locks();
        assert!(fs_fdobj::fd_locks_hook_installed());
    }

    /// What `/proc/<pid>/fdinfo` lists for a description: its own BSD and
    /// OFD locks, and a POSIX lock only through the description it was taken
    /// on and for the table that owns it. Linux's `__show_fd_locks` filters on
    /// both, measured by `fdinfo_probe`: a second description of the same file
    /// and a forked child sharing the first list none.
    #[test]
    fn a_description_lists_the_locks_it_holds_and_no_others() {
        use fs_fdobj::{HeldLock, LockClass};
        let mut a = ffi::fd::default();
        let mut b = ffi::fd::default();
        let inode = std::sync::Arc::new(ffi::inode_data::new(1, std::ptr::null_mut()));
        a.inode = Some(inode.clone());
        b.inode = Some(inode.clone());
        let (table, other) = (0x1000usize, 0x2000usize);
        let record = |fd: &ffi::fd, owner, kind, start, end| posix::Record {
            start,
            end,
            kind,
            owner,
            pid: 7,
            file: std::ptr::from_ref(fd) as usize,
        };
        {
            let mut guard = InodeGuard::new(&inode);
            let locks = guard.locks();
            let w = record(&a, Owner::Table(table), posix::Kind::Write, 0, 49);
            assert_eq!(locks.posix.apply(&w, Some(posix::Kind::Write)), posix::Applied::Granted { released: false });
            let r = record(&b, Owner::Description(std::ptr::from_ref(&b) as usize), posix::Kind::Read, 100, 109);
            assert_eq!(locks.posix.apply(&r, Some(posix::Kind::Read)), posix::Applied::Granted { released: false });
            locks.bsd.acquire(Owner::of_description(&b), bsd::Mode::Shared, 7);
        }
        let posix = HeldLock { class: LockClass::Posix, write: true, pid: 7, start: 0, end: Some(49) };
        assert_eq!(held_by(&a, table as *const _), [posix]);
        assert_eq!(held_by(&a, other as *const _), [], "another table owns none of them");
        assert_eq!(
            held_by(&b, table as *const _),
            [
                HeldLock { class: LockClass::Flock, write: false, pid: 7, start: 0, end: None },
                HeldLock { class: LockClass::Ofd, write: false, pid: 7, start: 100, end: Some(109) },
            ],
            "the flock first, then the record locks; a's POSIX lock is not b's"
        );
    }

    /// The set goes as soon as it is empty, and stays while it holds a lock.
    #[test]
    fn an_empty_lock_set_is_dropped_with_the_guard() {
        let inode = ffi::inode_data::new(1, std::ptr::null_mut());
        InodeGuard::new(&inode).locks();
        assert!(inode.state.lock().locks.is_none(), "an empty set outlived its guard");

        let owner = Owner::Description(1);
        InodeGuard::new(&inode).locks().bsd.acquire(owner, bsd::Mode::Shared, 0);
        assert!(inode.state.lock().locks.is_some(), "a held lock was dropped");

        assert!(InodeGuard::new(&inode).locks().bsd.release(owner));
        assert!(inode.state.lock().locks.is_none());
    }
}
