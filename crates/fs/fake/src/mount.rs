//! Fakefs mount lifecycle and mount information callbacks.

use std::collections::HashSet;
use std::ffi::{CStr, c_int};
use std::os::fd::BorrowedFd;

use crate::{EINVAL, ENAMETOOLONG, PATH_MAX, ffi};

// ------------------------------------------------------- mount and umount

/// **Every** mounted fakefs, for the bind-mount API to reach.
///
/// It was a C global with a lock of its own. The lock guarded *this pointer
/// alone* — the bind-mount table has its own inside `crates/fs/bindmount`, and
/// holding this one across a call into it is not needed, because a lookup
/// either sees a registration or does not and never sees one half-written.
///
/// A `Mutex<usize>` holding a `*mut mount` with `0` for "none" until
/// 2026-09-16 — a pointer stored as an integer, with a sentinel, in a global.
/// `MountId` is `Identity<mount>`, which `crates/kernel/abi` already answers
/// from `mount.id()`, and it is `Copy + Eq + Hash`, so the set costs the same
/// per entry as the slot did.
///
/// # It was one slot, and there is never one fakefs
///
/// `fakefs_rs_mount` wrote the slot **unconditionally**, so the last fakefs
/// mounted was the only one anything could find. That is not an edge case:
/// `crates/tools/iul`'s `mount_shm` mounts a fakefs at `/dev/shm` on every
/// boot and `-r` mounts another at `/dev`, so a CLI run has two or three and
/// the root's was never the one in the slot.
///
/// Two things were wrong because of it, and one of them had already been found
/// from the other end. `fakefs_rs_mount_db` is what
/// `crates/kernel/offloadexec` asks "is *my root* a fakefs, and which
/// database" — it compares the slot against the mount it was handed, so with
/// `/dev/shm` in the slot it answered null for the root and native runs
/// registered nothing. And `fakefs_bind_mount` took its root descriptor and
/// its database from the slot, so an embedder's bind mount put its mount-point
/// symlink in `/dev/shm`'s `data/` directory and its `meta.db` row in
/// `/dev/shm`'s database.
///
/// `crates/fs/fake/tests/mount_registry.rs` is the reproducer, and it mounts
/// exactly what a boot does. `tests/bind_mounts.rs` mounts **one** fakefs,
/// which is why it never saw this.
static FAKEFS_MOUNTS: std::sync::Mutex<Option<HashSet<ffi::MountId>>> =
    std::sync::Mutex::new(None);

fn registry() -> std::sync::MutexGuard<'static, Option<HashSet<ffi::MountId>>> {
    FAKEFS_MOUNTS.lock().expect("not poisoned")
}

/// A fakefs mount, held: the mount cannot be unmounted while this exists, so
/// its root descriptor and its database cannot be closed either.
///
/// **That is the second thing the out-parameters cost.**
/// `fakefs_rs_mount_info` wrote a `root_fd` and a `*mut Db` into the caller's
/// stack under the registry lock and released it, and its own doc comment
/// argued that this was the safe shape:
///
/// > **Not a pointer to the mount.** A caller given one would dereference it
/// > after the lock was released, and an unmount in that gap leaves a dangling
/// > read.
///
/// The database **is** a pointer, and `fakefs_rs_umount` calls
/// `fakedb_close`, which is a `Box::from_raw` and a drop. Every caller used it
/// after blocking work — a `realpath`, a registration, a `symlinkat` — so the
/// gap the comment names was exactly where it always was, moved one field
/// over. A [`MountRef`](fs_mounttable::MountRef) is what closes it: the mount
/// carries the busy count `fs_mounttable::mounts_take_point` refuses a `umount` against.
pub struct FakefsMount(fs_mounttable::MountRef);

impl FakefsMount {
    /// The fakefs that owns `guest`, if a fakefs owns it at all.
    ///
    /// **The mount table is asked which mount owns the path**, rather than a
    /// second registry being asked which mount is "the" fakefs. The table is
    /// the registry; the set above only answers "is this one of mine", which
    /// is a question about a mount the caller already has.
    ///
    /// `guest` is a normalised absolute guest path; one that is not finds the
    /// wrong mount, which is a wrong answer and not memory unsafety, so this
    /// stopped being `unsafe` when the lookup took a `&CStr`.
    pub fn owning(guest: &CStr) -> Option<FakefsMount> {
        // Retains under the table's own lock and releases it before
        // returning, so nothing below is holding two locks.
        let mount = fs_mounttable::mount_find(guest);
        let is_fakefs = registry().as_ref().is_some_and(|s| s.contains(&mount.id()));
        is_fakefs.then(|| FakefsMount(mount))
    }

    /// The mount's `data/` directory, borrowed for as long as this is held.
    pub fn root(&self) -> BorrowedFd<'_> {
        // SAFETY: the reference held keeps the mount live, and the borrow
        // cannot outlive `self`.
        let mount = unsafe { &*self.0.as_ptr() };
        mount.root().expect("a mounted fakefs has a root directory")
    }

    /// Its `meta.db`, borrowed likewise.
    ///
    /// `None` for a mount whose database failed to open, which `fakefs_rs_mount`
    /// refuses — so in practice this is always `Some` and the `Option` is what
    /// the null check at each call site used to be.
    pub fn db(&self) -> Option<&fakedb::Db> {
        // SAFETY: as `root`: the reference held keeps the mount live.
        unsafe { &*self.0.as_ptr() }.state().fakefs()
    }
}

/// Whether any fakefs is mounted at all.
///
/// The cheap gate `fakefs_bind_mount` asks before it has a normalised path to
/// ask [`FakefsMount::owning`] with. It was `fakefs_rs_mount_info` called with
/// three null out-parameters, which is an existence check spelled as a write
/// of nothing.
pub fn any_fakefs_mounted() -> bool {
    registry().as_ref().is_some_and(|s| !s.is_empty())
}

/// The database of `mount`, if that mount is a fakefs.
///
/// Answered against a mount the caller already holds, which is the question
/// [`FakefsMount::owning`] answers from a path. `crates/kernel/offloadexec`
/// asks it about the calling task's root, because files a native run created
/// belong in the *root's* `meta.db` -- and until 2026-09-16 the registry was
/// one slot, so with `/dev/shm`'s fakefs in it this answered `None` for the
/// root and nothing was registered at all.
///
/// A `*mut Db` with null for "not a fakefs" until the same day. The null was
/// the `None`, and its one caller wrapped it back into an `Option` by hand.
pub fn fakefs_rs_mount_db(mount: &ffi::mount) -> Option<&fakedb::Db> {
    if !registry()
        .as_ref()
        .is_some_and(|s| s.contains(&mount.id()))
    {
        return None;
    }
    mount.state().fakefs()
}

/// # Safety
///
/// `mount` is live and its `source` is NUL-terminated.
pub fn fakefs_rs_mount(mount: &mut ffi::mount) -> c_int {
    // `mount->source` names the fakefs `data/` directory; the database sits
    // beside it. The length is checked rather than assumed: mount_root gets
    // the source from realpath, which the host bounds by its own PATH_MAX, so
    // it fits with nothing to spare -- and do_mount can be reached with a
    // source that came from somewhere else.
    let source = mount.source.to_bytes();
    // "meta.db" is longer than "data", so the join is the longer of the two.
    if source.len() + b"meta.db\0".len() > PATH_MAX {
        return ENAMETOOLONG;
    }
    // A source with no separator at all is not one of ours, and neither is one
    // whose last component is not `data`: the database is found by that name's
    // parent, so a source named anything else would open some other
    // directory's meta.db. Refused rather than asserted -- this was a
    // `debug_assert_eq!`, which in an `extern "C"` function is an abort of the
    // whole emulator, and it fired for a `data` that was a symlink because
    // `mount_root` had resolved the link away. See `resolved_source` in
    // crates/kernel/boot.
    let Some(slash) = source.iter().rposition(|b| *b == b'/') else {
        return EINVAL;
    };
    if &source[slash + 1..] != b"data" {
        return EINVAL;
    }
    let mut db_path = source[..=slash].to_vec();
    db_path.extend_from_slice(b"meta.db\0");

    // Before the database, so that a rebuild can use root_fd.
    let err = realfs::realfs_mount(mount);
    if err < 0 {
        return err;
    }

    // `db_path` was built above with its own NUL; `from_bytes_with_nul` is
    // what checks that rather than a comment saying so.
    let Ok(db_path_c) = CStr::from_bytes_with_nul(&db_path) else {
        return EINVAL;
    };
    let Some(root) = mount.root() else {
        return EINVAL;
    };
    // The root directory needs nothing done on failure: it is the mount's,
    // and `do_mount` drops the mount -- and so closes it -- when this fails.
    // It was closed by hand here until 2026-09-29, the one path of the
    // three that did.
    let db = match fakedb::db::open(db_path_c, root) {
        Ok(db) => db,
        Err(e) => return e,
    };
    crate::unnamed::clear_unnamed(root, &db);
    // The mount owns it from here; every other use of the database in this
    // tree is a borrow. It was parked as a raw pointer in a union until
    // 2026-09-29 and reconstituted by `fakefs_rs_umount`.
    mount.sb_mut().state = ffi::mount_state::Fakefs(db);

    registry().get_or_insert_with(HashSet::new).insert(mount.id());
    // The table's own lock is inside it.
    bindmount::bindmount_clear();
    0
}

/// The last copy of a fakefs mount has gone: `ffi::Superblock`'s drop.
pub fn fakefs_rs_umount(sb: &mut ffi::Superblock) {
    // The bind-mount state goes before the mount does. The superblock is
    // freed straight after this returns, and nothing here used to clear the
    // global or deactivate the table -- so a later fakefs_bind_unmount called
    // unlinkat through a dangling pointer, and translation kept handing out
    // routes to a closed root.
    {
        let mut set = registry();
        if set.as_mut().is_some_and(|s| s.remove(&sb.id())) {
            // The table's own lock is inside it.
            //
            // Every bind mount goes, not only this mount's: the table is one
            // and its entries are guest paths, so there is nothing in it that
            // names which fakefs a route was registered against. Unmounting
            // any fakefs therefore clears them all, which is what it did when
            // there was one slot and is now visibly more than is needed --
            // stated rather than fixed, because narrowing it means keeping the
            // mount beside each route and that is a change to `fs/bindmount`.
            bindmount::bindmount_clear();
        }
    }
    // The database closes here, after the bind-mount state above rather than
    // whenever the mount itself is freed.
    sb.state = ffi::mount_state::None;
}

/// An inode with no path left; the database may drop its row.
pub fn fakefs_rs_inode_orphaned(sb: &ffi::Superblock, inode: u64) {
    if let Some(db) = sb.state.fakefs() {
        db.inode_orphaned(inode);
    }
}
