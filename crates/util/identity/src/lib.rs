//! [`Identity`]: an address used as a key, and never as an access.
//!
//! # The shape it replaces
//!
//! Three tables in this tree keyed something on "which object is this" and
//! spelled it `usize`:
//!
//! | | |
//! | --- | --- |
//! | `crates/fs/inode` | `type Key = (usize, u64)` — a mount's address beside an inode number, both integers, in one tuple |
//! | `crates/kernel/pids` | `type Handle = usize`, for a thread group's process-group and session indexes |
//! | `crates/kernel/pids` | `Vec<usize>` from pid to task, with **`0` for an empty slot** |
//!
//! Each carried the same sentence, written out once per function — five copies
//! in `crates/kernel/pids` alone:
//!
//! > The handle is an identity key only; this function never dereferences it.
//!
//! That is a property of the *value*, so it belongs on the type. And an
//! integer that is really a pointer is a conversion nothing checks in either
//! direction: `remove(group as usize)` accepts a pid, an index, or a
//! `*mut task` just as readily as the `*mut tgroup` it wants.
//!
//! # Constructing one is safe, and that is the design
//!
//! [`crate::FdId`] is the same idea for descriptors and is *not* this type: it
//! has a `with` that borrows the description, so making one is safe and using
//! one carries the contract.
//!
//! `Identity` has no accessor and no way back to the object, because no holder
//! wants one — a key is compared and hashed and nothing else. With nothing to
//! dereference, [`Identity::from_ptr`] needs no `unsafe` either: an identity
//! built from a dangling pointer is a value that will never match a live
//! object, which is the correct answer rather than undefined behaviour.
//!
//! Two things follow, and both are load-bearing:
//!
//! - **A test can key a table on `0x1000` and `0x2000`** without inventing two
//!   mounts or two thread groups, and say what it is about — the pair, or the
//!   index — rather than building the world to say it.
//! - **This type may not grow an accessor later.** The moment one exists,
//!   every `from_ptr` above becomes a place that has to prove its pointer is
//!   live, and none of them can.

use std::marker::PhantomData;
use std::ptr::NonNull;

/// Which `T`, as a value that can be compared and hashed but not read.
///
/// See the module comment. `Identity<task>` and `Identity<tgroup>` are
/// different types, which is the half a `usize` could not express.
#[repr(transparent)]
pub struct Identity<T>(NonNull<T>, PhantomData<fn() -> T>);

// SAFETY: an address, not an access. The pointer is never dereferenced —
// there is no method that could — so this is a `usize` that remembers what it
// points at, and a `usize` is `Send`. `PhantomData<fn() -> T>` rather than
// `PhantomData<T>` so that `T`'s own auto traits do not enter into it: what
// travels is the number.
unsafe impl<T> Send for Identity<T> {}
// SAFETY: as `Send`. There is no interior mutability, because there is no
// access at all.
unsafe impl<T> Sync for Identity<T> {}

impl<T> Identity<T> {
    /// The identity of something you have a reference to.
    pub fn of(t: &T) -> Identity<T> {
        Identity(NonNull::from(t), PhantomData)
    }

    /// The identity of whatever a raw pointer names, or `None` for a null one.
    ///
    /// Safe, and the module comment says why. The callers are the places that
    /// still hold the object as a raw field — `crates/fs/inode`'s
    /// `fs_inode`'s release reads `inode_data.mount` — and tests.
    /// `const`, so that a table's test can name three distinct groups as
    /// constants the way it did when they were `0x1000`, `0x2000` and
    /// `0x3000`. A `map` with a closure is not const, hence the `match`.
    pub const fn from_ptr(p: *mut T) -> Option<Identity<T>> {
        match NonNull::new(p) {
            Some(p) => Some(Identity(p, PhantomData)),
            None => None,
        }
    }

    /// The address back, for a callee that has not been converted yet.
    ///
    /// **Not an accessor**: it hands back the number this was made from and
    /// promises nothing about what is there. `crates/kernel/pids` answers one
    /// of these where its C-era signature returned a `*mut tgroup`, and every
    /// caller of that immediately passes it to something that does know the
    /// object is live — because it is holding the lock that keeps it so.
    pub fn as_ptr(self) -> *mut T {
        self.0.as_ptr()
    }
}

// Derived by hand rather than with `#[derive]`: the derives would add a `T:
// Trait` bound, and `mount`, `task` and `tgroup` implement none of these.
impl<T> Clone for Identity<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Identity<T> {}
impl<T> PartialEq for Identity<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<T> Eq for Identity<T> {}
impl<T> std::hash::Hash for Identity<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl<T> std::fmt::Debug for Identity<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({:p})", self.0.as_ptr())
    }
}

impl<T> From<&T> for Identity<T> {
    fn from(t: &T) -> Identity<T> {
        Identity::of(t)
    }
}

/// A task named **across time**: a pid, and the generation the number was
/// handed out with.
///
/// A pid alone does not name a task for later. Numbers wrap at `MAX_PID` and
/// are reused, so anything that stores one to act on afterwards -- a POSIX
/// timer addressing a thread, a pidfd -- would act on whoever holds the number
/// next. Linux has the same problem and answers it with a refcounted `struct
/// pid` that outlives the task; this is the same answer without the object.
/// The pid table counts how many times each slot has been filled, a reference
/// carries the count it was taken at, and `kernel_pids`' `Table::by_ref`
/// answers null once the number has been filled again.
///
/// Made only through `kernel_pids::PidsGuard::refer`, from a task that is there
/// now; resolved only through `PidsGuard::task_by_ref`, under the same lock.
///
/// **Here and not in `crates/kernel/pids`** since 2026-09-29, for the reason
/// [`Identity`] is: it is two integers, and holding one was the only thing
/// `crates/kernel/posixtimers` needed the pid table for -- an edge that put
/// `kernel-taskview` in that crate's closure and kept `struct tgroup`'s
/// `posix_timers` field an opaque placeholder with a cast at every reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct TaskRef {
    pub pid: std::ffi::c_int,
    pub generation: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pointee that does not exist, which is the point: these tests keyed on
    /// `crate::mount` while this type lived in `crates/kernel/abi`, and neither
    /// of them ever had a mount. An uninhabited marker says so.
    enum Thing {}

    /// Two identities of the same kind compare by address, and a null makes
    /// none. This is the whole contract, and it is checkable without a single
    /// live object — which is the property the type exists for.
    #[test]
    fn an_identity_is_its_address() {
        let a = Identity::<Thing>::from_ptr(0x1000 as *mut _).unwrap();
        let b = Identity::<Thing>::from_ptr(0x2000 as *mut _).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, Identity::from_ptr(0x1000 as *mut _).unwrap());
        assert_eq!(Identity::<Thing>::from_ptr(std::ptr::null_mut()), None);
        assert_eq!(a.as_ptr(), 0x1000 as *mut _);
    }

    /// `Option<Identity<T>>` is the same size as the pointer, which is what
    /// lets `crates/kernel/pids` store `Option<TaskId>` per pid where it
    /// stored a `usize` with `0` meaning empty, and `crates/kernel/ctty` store
    /// `Option<TtyId>` where it stored a `usize` with the same sentinel. If
    /// this ever stops holding, those tables grow and the sentinel was cheaper.
    #[test]
    fn the_empty_slot_is_free() {
        assert_eq!(
            std::mem::size_of::<Option<Identity<Thing>>>(),
            std::mem::size_of::<*mut Thing>()
        );
    }
}
