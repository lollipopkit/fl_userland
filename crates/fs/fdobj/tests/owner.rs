//! A description's lifetime, as its handle's callers see it.
//!
//! `tests/unit/fdowner_test.c` until 2026-09-08. The count is an `Arc` since
//! 2026-10-17, which needs no test of its own; what needs a real descriptor is
//! that publishing, the handle's operations and `fd_close` are wired to it.
//!
//! An **integration** test, and the reason has outlived the thing that caused
//! it. It had to link `fs-locks` and `fs-poll` — the other side of this crate's
//! `keep-c-abi` edge, since a poll set holds descriptors and a file lock is
//! owned by one — because three `extern "C"` declarations here were resolved by
//! the linker. In `cargo test --lib` that meant `fs_fdobj` compiled twice, once
//! with `cfg(test)` and once as their dependency, and every `#[no_mangle]` in
//! it became a duplicate symbol `ld` picks between.
//!
//! Those calls are a hook and a direct `fs-pollset` call as of 2026-09-09, so
//! the two dev-dependencies are gone and nothing here needs a symbol resolved.
//! It stays a `tests/` binary: `CLAUDE.md`'s rule is that a test needing the
//! product is an integration test, and this one creates a real descriptor.

use taskview::ffi;

// ------------------------------------------------------- the owner handle
//
// What needs a real descriptor: that publishing, the handle and `fd_close`
// move the count the way their names say.

use std::sync::atomic::{AtomicUsize, Ordering};

static CLOSE_CALLS: AtomicUsize = AtomicUsize::new(0);

/// `CLOSE_CALLS` is one counter and cargo runs a crate's tests as
/// **threads**, so the two tests that reset and read it have to take turns.
/// Without this they pass alone and fail in a workspace run, which is the
/// shape a single re-run makes look like a flake.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// A driver that counts its closes and does nothing else.
struct TestOps;

impl ffi::FdOps for TestOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::NONE
    }
    fn close(&self, _fd: &mut ffi::fd) -> std::ffi::c_int {
        CLOSE_CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }
}

static TEST_OPS: TestOps = TestOps;

/// The description is the same across aliases and survives until the last
/// release, which is what a reverse edge holding a bare pointer relies on.
/// It compared `owner`, the count's control block, until 2026-10-17; the count
/// is the `Arc` around the description now, so the identity is its address.
#[test]
fn identity_is_stable_while_strong_references_exist() {
    let _serial = serial();
    CLOSE_CALLS.store(0, Ordering::SeqCst);
    let fd = fs_fdobj::NewFd::new(Some(&TEST_OPS)).into_owned();
    let id = fd.as_ptr();

    let alias = fd.clone();
    assert_eq!(alias.as_ptr(), id);
    assert_eq!(fd.close(), 0);
    assert_eq!(alias.as_ptr(), id, "still the same description");
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 0, "one reference left");

    assert_eq!(alias.close(), 0);
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1);
}

/* `try_retain_answers_a_live_descriptor` and `null_descriptor_has_no_owner`
 * were here until 2026-10-01, with the two functions they tested:
 * `fd_try_retain` and `fd_owner_of`, which nothing else called. The refusal
 * after final release is `crates/fs/fd`'s `fd_owner_try_retain`, tested
 * there against a blocked finalizer. */

// ------------------------------------------------------------ Owned
//
// Object model step 9.7: each of `Owned`'s operations moves the count the way
// its name says.

/// Every path through [`fs_fdobj::Owned`] balances, and the driver's `close`
/// runs exactly once.
///
/// **One `#[test]`, and the `serial()` guard**, because `CLOSE_CALLS` is one
/// counter and cargo runs a crate's tests as threads — the trap
/// `crates/kernel/pagetable/tests/live_mappings.rs` fell into one level down,
/// where three `#[test]`s in one integration binary each read a baseline
/// another had already moved.
#[test]
fn every_path_through_an_owned_handle_balances() {
    use fs_fdobj::Owned;

    let _serial = serial();
    CLOSE_CALLS.store(0, Ordering::SeqCst);

    // 1. A scope. `publish` answers with one reference taken, so adopting it
    //    is `from_raw` and not `retain` -- the distinction this type exists to
    //    make, and the one a bare `fd_retain`/`fd_close` pair cannot.
    {
        let fd = fs_fdobj::NewFd::new(Some(&TEST_OPS)).publish();
        assert!(!fd.is_null());
        let held = unsafe { Owned::from_raw(fd) };
        assert_eq!(held.as_ptr(), fd);
        assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 0, "still held");
    }
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1, "the scope closed it");

    // 2. `clone` is the retain, and only the last one finalizes.
    CLOSE_CALLS.store(0, Ordering::SeqCst);
    let a = fs_fdobj::NewFd::new(Some(&TEST_OPS)).into_owned();
    let b = a.clone();
    assert_eq!(b.as_ptr(), a.as_ptr(), "a clone names the same description");
    drop(a);
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 0, "one reference left");
    drop(b);
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1);

    // 3. `close` answers the driver's errno where `drop` discards it. That is
    //    the whole reason the two are different operations: `sys_close` returns
    //    this number to the guest.
    CLOSE_CALLS.store(0, Ordering::SeqCst);
    assert_eq!(fs_fdobj::NewFd::new(Some(&TEST_OPS)).into_owned().close(), 0);
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1);

    // 4. Through a `#[repr(C)]` field: `into_raw` must hand the reference on
    //    rather than drop it, and `from_raw` must take it back rather than add
    //    one. This is `struct fd`'s own `mount` shape one type along, and the
    //    case `crates/kernel/memfdcalls` got wrong for `MountRef`.
    CLOSE_CALLS.store(0, Ordering::SeqCst);
    let fd = fs_fdobj::NewFd::new(Some(&TEST_OPS)).publish();
    let stored = unsafe { Owned::from_raw(fd) }.into_raw();
    assert_eq!(stored, fd);
    assert_eq!(
        CLOSE_CALLS.load(Ordering::SeqCst),
        0,
        "into_raw hands the reference on, it does not drop it"
    );
    drop(unsafe { Owned::from_raw(stored) });
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1, "and from_raw's drop is the release");

    // 5. `retain` is the +1, where `from_raw` is not. Getting these two the
    //    same way round is the one mistake the type cannot catch for you.
    CLOSE_CALLS.store(0, Ordering::SeqCst);
    let fd = fs_fdobj::NewFd::new(Some(&TEST_OPS)).publish();
    let first = unsafe { Owned::from_raw(fd) };
    let second = unsafe { Owned::retain(fd) };
    drop(first);
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 0, "retain took one");
    drop(second);
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 1);
}

/// A description dropped before it was published gives back the mount
/// reference it took, runs no `close`, and was never counted as live.
#[test]
fn an_unpublished_description_gives_its_mount_back() {
    struct NoFs;
    impl ffi::FsOps for NoFs {
        fn name(&self) -> Option<&'static std::ffi::CStr> {
            None
        }
        fn magic(&self) -> u32 {
            0
        }
    }
    static NO_FS: NoFs = NoFs;
    let _g = serial();
    let mount = fs_mounttable::DetachedMount::leak(&NO_FS, 0);
    let held = |m: &fs_mounttable::DetachedMount| m.retain().refcount.load(Ordering::SeqCst) - 1;
    CLOSE_CALLS.store(0, Ordering::SeqCst);
    let live = fs_fdobj::fd_live_count();
    {
        let mut fd = fs_fdobj::NewFd::new(Some(&TEST_OPS));
        fd.set_mount(mount.retain());
        assert_eq!(held(&mount), 1);
    }
    assert_eq!(held(&mount), 0, "the unpublished description kept its mount");
    assert_eq!(CLOSE_CALLS.load(Ordering::SeqCst), 0, "nothing was opened, so nothing closes");
    assert_eq!(fs_fdobj::fd_live_count(), live);
}

// ------------------------------------------- what the count owes its callers
//
// Written on 2026-10-17, before the count moves from `crates/fs/fd`'s handle to
// an `Arc`, so that the move has something to answer to. None of them reads the
// representation -- no `owner` field, no handle -- only what a caller sees.

static ERR_CLOSES: AtomicUsize = AtomicUsize::new(0);

/// A driver whose close fails, so that which `close` reports it is visible.
struct FailingOps;

impl ffi::FdOps for FailingOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::NONE
    }
    fn close(&self, _fd: &mut ffi::fd) -> std::ffi::c_int {
        ERR_CLOSES.fetch_add(1, Ordering::SeqCst);
        guest_errno::c_int_::EIO
    }
}

static FAILING_OPS: FailingOps = FailingOps;

/// Only the close that gives back the last reference answers the driver's
/// error, which is what `sys_close` hands the guest; the others answer 0.
/// And the driver closes once.
#[test]
fn the_last_close_answers_the_drivers_error() {
    let _serial = serial();
    ERR_CLOSES.store(0, Ordering::SeqCst);
    let fd = fs_fdobj::NewFd::new(Some(&FAILING_OPS)).into_owned();
    let alias = fd.clone();
    assert_eq!(fd.close(), 0, "not the last reference");
    assert_eq!(ERR_CLOSES.load(Ordering::SeqCst), 0);
    assert_eq!(alias.close(), guest_errno::c_int_::EIO, "the last one");
    assert_eq!(ERR_CLOSES.load(Ordering::SeqCst), 1);
}

/// Many threads giving back the last references at once: the driver closes
/// exactly once, and exactly one of them is told its error.
#[test]
fn concurrent_last_closes_finalize_once() {
    let _serial = serial();
    ERR_CLOSES.store(0, Ordering::SeqCst);
    for _ in 0..200 {
        let fd = fs_fdobj::NewFd::new(Some(&FAILING_OPS)).into_owned();
        // This thread's reference goes before any closer starts. Dropped
        // while they ran, it was sometimes the last one -- the description
        // then finished in `drop`, which answers no one, and all eight were
        // told 0: 67 of 200 runs under load.
        let mine: Vec<_> = (0..8).map(|_| fd.clone()).collect();
        drop(fd);
        let start = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = mine
            .into_iter()
            .map(|mine| {
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    mine.close()
                })
            })
            .collect();
        let answers: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(
            answers.iter().filter(|&&e| e == guest_errno::c_int_::EIO).count(),
            1,
            "one closer is told: {answers:?}"
        );
    }
    assert_eq!(ERR_CLOSES.load(Ordering::SeqCst), 200, "one driver close each");
}

/// Publishing does not move a description. `crates/kernel/pidfdcalls`
/// registers a `NewFd`'s address before it is published, and every registry
/// keyed on a description's address assumes the same.
#[test]
fn publishing_does_not_move_a_description() {
    let _serial = serial();
    let new = fs_fdobj::NewFd::new(Some(&TEST_OPS));
    let before: *const ffi::fd = &*new;
    let fd = new.into_owned();
    assert_eq!(fd.as_ptr().cast_const(), before);
}
