//! Guest inode state layout shared by filesystem and descriptor crates.
//!
//! Two fields went on 2026-09-12, with object model step 9.3:
//!
//! * `refcount` was the hand-rolled strong count. It is an `Arc<Inode>`'s now
//!   — `crates/fs/inode` owns the allocation and the destructor — so a field
//!   here would be a second count nothing keeps in step with the first.
//! * `chain` was the C's intrusive hash bucket, from the 1024-bucket table
//!   `fs/inode.c` walked. `crates/fs/inode` has been a `HashMap` keyed on
//!   `(mount, ino)` since it was written, and nothing has read either half of
//!   this `list` since; it was 16 bytes per inode that only the offset
//!   assertion below mentioned. Same shape as `pt_entry.blocks`, which step
//!   9.1 found dead for the same reason — a collection replaced an intrusive
//!   list and the field stayed.
//!
//! **Every field is either written once at construction or is reached
//! through interior mutability** -- atomics, or [`inode_data::state`] -- so a
//! `&inode_data` is an ordinary shared borrow. Until 2026-10-01 `locks` and
//! `socket_id` were plain fields written through a raw pointer under an
//! embedded `lock_t`, and `crates/fs/inode` wrapped the whole struct in an
//! `UnsafeCell` so that `&` was not a lie; the lock owns what it guards now.
//!
//! Not `#[repr(C)]`: no header, assembly or embedder names this layout.

use crate::ino_t;
use std::any::Any;
use util_guestlock::GuestLock;

/// What [`inode_data::state`] guards.
#[derive(Default)]
pub struct InodeState {
    /// The `AF_UNIX` socket id a `bind` stamped on this node, 0 until one
    /// does. Read under the lock too -- the version before 2026-09-06
    /// assigned it inside the lock and read it outside, so two threads binding
    /// one path could see different ids.
    pub socket_id: u32,
    /// `crates/fs/locks`' set of POSIX record locks and BSD `flock`s, if any
    /// were ever taken. `dyn Any` because that crate sits above this one;
    /// dropping the inode drops it, where the C leaked it and a hook freed it
    /// until 2026-10-01.
    pub locks: Option<Box<dyn Any + Send>>,
}

/// The condition [`inode_data::state`] carries: a file lock was released.
pub const INODE_LOCK_RELEASED: u32 = 0;


pub struct inode_data {
    pub number: ino_t,
    /// The filesystem instance this inode belongs to. The superblock and not
    /// a mount: every copy of a mount in another mount namespace shares it,
    /// so an inode is one object whichever namespace opened it, and holding
    /// it keeps no namespace's copy of the mount busy -- an `umount` of an
    /// idle copy succeeds while another namespace has the file open, as on
    /// Linux. `None` only for a test's inode, which never reached the table.
    pub sb: Option<std::sync::Arc<crate::Superblock>>,
    /// How many descriptors hold this inode open for writing, or -1 while it
    /// is being executed. **Atomic** because an open and an exec race on it
    /// with no lock in common; `crates/fs/inode` owns the four transitions.
    ///
    /// An `AtomicI32` and not an `i32`: `fs/inode.h` said `atomic_int`, which
    /// bindgen renders as a plain `c_int` -- so `+= 1` on it compiled, which is
    /// what `tools/atomic-fields.py` exists to catch. That gate read the header
    /// until 2026-09-08 and the header is gone; the type is the check now.
    pub writers: std::sync::atomic::AtomicI32,
    /// `F_SET_RW_HINT`'s value. An `AtomicU8` since 2026-09-29: it was a
    /// `u8` that `crates/fs/inode` reached through `AtomicU8::from_ptr`, the
    /// one field here whose atomicity was a promise its only accessor kept.
    pub write_hint: std::sync::atomic::AtomicU8,
    /// Linux's `S_NOSEC`: bit 0 says a write has nothing to remove -- no
    /// set-id bit, no `security.capability` -- so it skips the `fstat` and the
    /// xattr call. The rest is a generation, bumped by every change that could
    /// add one, so a check that raced such a change cannot set the bit from
    /// what it read before. `crates/fs/inode` owns the transitions.
    pub nosec: std::sync::atomic::AtomicU32,
    /// A `GuestLock` and not a `std::sync::Mutex`: a blocking `fcntl` or
    /// `flock` waits on [`INODE_LOCK_RELEASED`] through `wait_for`, the only
    /// wait a signal can interrupt.
    pub state: GuestLock<InodeState>,
}

// No `unsafe impl Send`/`Sync`: since `mount` -- a raw pointer -- became `sb`,
// an `Arc`, every field is `Send + Sync` on its own, and an inode is shared
// across threads (two threads opening one file get one object) on the
// compiler's word rather than a comment's.
const _: fn() = || {
    fn shared<T: Send + Sync>() {}
    shared::<inode_data>();
};

/// What the last reference to an inode does on its way out: unlink it from
/// `crates/fs/inode`'s table and tell the filesystem. A hook
/// because both of those crates sit above this one; installed by
/// `crates/fs/inode` when it makes its first inode, so an `inode_data` that
/// never reached the table -- a test's -- drops with nothing to undo.
static RELEASE: std::sync::OnceLock<fn(&mut inode_data)> = std::sync::OnceLock::new();

/// Install it. See [`RELEASE`]. Idempotent.
pub fn set_inode_release_hook(f: fn(&mut inode_data)) {
    let _ = RELEASE.set(f);
}

/// Whether it has been installed, for `crates/fs/inode`'s test.
pub fn inode_release_hook_installed() -> bool {
    RELEASE.get().is_some()
}

impl Drop for inode_data {
    fn drop(&mut self) {
        if let Some(release) = RELEASE.get() {
            release(self);
        }
    }
}

impl inode_data {
    pub fn new(number: ino_t, sb: Option<std::sync::Arc<crate::Superblock>>) -> inode_data {
        inode_data {
            number,
            sb,
            writers: Default::default(),
            write_hint: Default::default(),
            nosec: Default::default(),
            state: GuestLock::new(InodeState::default(), 1),
        }
    }
}
