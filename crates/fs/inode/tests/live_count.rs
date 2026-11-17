//! The inode count, in a test binary of its own.
//!
//! **A leak is this work's failure mode and nothing else in the tree sees
//! one.** A strong count one too high keeps an `inode_data`, its lock set and
//! a superblock reference for ever, and every assertion in `cargo test`,
//! `guest_tests.sh` and `tools/checks.sh` still passes — the object is
//! unreachable and nothing looks for it. `fs_inode::inode_live_count` is what
//! sees it, and this is its only reader outside `/proc/iul/objects`.
//!
//! A binary of its own because `LIVE` is process-wide and cargo runs a crate's
//! unit tests in parallel threads of one process, so an assertion about its
//! absolute value is only true when nothing else is opening files.
//! `crates/kernel/eventfd/tests/live_count.rs` is the older precedent and
//! `crates/kernel/pagetable/tests/live_mappings.rs` the one from object model
//! step 9.1 — whose three `#[test]`s each read a `before` another had already
//! moved, which is why this is **one**.
//!
//! `unix_socket_id` is the entry point rather than `inode_get`, which is
//! `pub(crate)`: it is the one public function that takes a reference and
//! hands it back, and the socket id it assigns doubles as a way to tell two
//! inodes for one key apart — a fresh object's `socket_id` is 0, so it is
//! given a new one.
//!
//! It answers a [`fs_inode::Ref`], an `Arc`, whose `Drop` is the release.

use fs_inode::{Ref, ffi, inode_live_count, unix_socket_id};
use std::sync::Arc;

/// A mount with no filesystem: `fs: None`, so a released inode skips
/// `inode_orphaned` and this test needs no `fs_ops` table. Its superblock's
/// count is what an inode moves, and it is checked at the end — a leaked
/// inode leaks a superblock reference with it, which is the second half of
/// the failure this file exists for.
///
/// Owned by the test as a `Box` and lent out, where it was `Box::into_raw` and
/// a matching `from_raw` until 2026-09-15: `unix_socket_id` takes a `&mount`
/// now, so the lifetime is the compiler's and the leak this file is about
/// cannot be joined by a second one in the harness.
fn mount() -> Box<ffi::mount> {
    Box::<ffi::mount>::default()
}

fn open(m: &ffi::mount, ino: u64) -> (Ref, u32) {
    let (id, held) = unix_socket_id(m, ino);
    (held, id)
}

#[test]
fn an_inode_lives_from_the_first_reference_to_the_last() {
    let owned = mount();
    let m = &*owned;
    assert_eq!(inode_live_count(), 0, "something is already live");

    // One holder.
    let (a1, id1) = open(m, 7);
    assert_eq!(inode_live_count(), 1);

    // **Two holders of one inode.** Two `open`s of one file share an
    // `inode_data` -- that is the whole reason the table interns -- so this is
    // one object with two references, not two objects. Both the address and
    // the socket id say so: a second object would have had `socket_id == 0`
    // and been given a new one.
    let (a2, id2) = open(m, 7);
    assert!(Arc::ptr_eq(&a2, &a1), "two lookups of one file built two inodes");
    assert_eq!(id2, id1, "the second lookup did not find the first's id");
    assert_eq!(inode_live_count(), 1, "a shared inode was counted twice");

    // A different file is a different object.
    let (b, _) = open(m, 8);
    assert!(!Arc::ptr_eq(&b, &a1));
    assert_eq!(inode_live_count(), 2);

    // Releasing one of two references frees nothing. This is the assertion a
    // count that is one too *low* fails, which is the other way to get this
    // wrong and is a use-after-free rather than a leak.
    drop(a2);
    assert_eq!(inode_live_count(), 2);

    // The last reference is what frees it.
    drop(a1);
    assert_eq!(inode_live_count(), 1, "the last release freed nothing");
    drop(b);
    assert_eq!(inode_live_count(), 0, "an inode outlived its last reference");

    // **And the dead entry is not revived.** The table holds a `Weak`, so a
    // lookup after the last release must find an entry it cannot upgrade -- or
    // no entry at all, which is what the release leaves -- and build a fresh
    // object. A fresh one has `socket_id == 0` and is given a new id; the same
    // id back would mean the old allocation was handed out again.
    let (again, id3) = open(m, 7);
    assert_eq!(inode_live_count(), 1);
    assert_ne!(id3, id1, "a released inode was handed back to a new lookup");
    drop(again);
    assert_eq!(inode_live_count(), 0);

    // Every inode took a reference to the superblock and every one gave it
    // back: the mount's own is the only one left. (A reference to the mount
    // until 2026-11-17, when inodes moved to the superblock every copy of the
    // mount shares.)
    assert_eq!(std::sync::Arc::strong_count(&m.sb), 1, "a freed inode leaked its superblock reference");
    assert_eq!(m.refcount.load(std::sync::atomic::Ordering::Relaxed), 0, "an inode holds the mount busy");
    drop(owned);
}
