//! The rules, against real descriptor handles.
//!
//! Each handle is a real `struct fd` -- carrying its tag in `offset`, the one
//! field nothing here reads otherwise -- with a finalizer that records the tag. So "the child holds its own
//! reference" is asserted as what it means: the descriptor is not finalized
//! when the parent lets go, and is when the child does.
//!
//! Until 2026-09-29 these substituted `fd_retain` and `fd_close` with counting
//! doubles over fake pointers, which checked the calls `Held` made rather than
//! the lifetime of anything.

use super::*;
use std::ffi::c_int;

/// The tags finalized so far. The tests share it, so they run one at a time.
static FINALIZED: Mutex<Vec<usize>> = Mutex::new(Vec::new());
static SERIAL: Mutex<()> = Mutex::new(());

/// Tolerates poison: a failing assertion elsewhere must not turn every later
/// finalizer into a panic, which a finalizer may not do.
fn finalized_so_far() -> std::sync::MutexGuard<'static, Vec<usize>> {
    FINALIZED.lock().unwrap_or_else(|p| p.into_inner())
}

fn finalize(fd: &mut iul_abi::fd) -> c_int {
    finalized_so_far().push(fd.offset.load(std::sync::atomic::Ordering::Relaxed) as usize);
    0
}

fn reset() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    finalized_so_far().clear();
    g
}

/// A descriptor handle tagged `n`, with its one reference.
fn fd(n: usize) -> Owned {
    let mut fd = iul_abi::fd::default();
    fd.offset.store(n as i64, std::sync::atomic::Ordering::Relaxed);
    fd.finalizer = Some(finalize);
    Owned::new(Arc::new(fd))
}

fn tag(fd: &Owned) -> usize {
    fd.offset.load(std::sync::atomic::Ordering::Relaxed) as usize
}

fn finalized(n: usize) -> bool {
    finalized_so_far().contains(&n)
}

#[test]
fn a_copy_takes_a_reference_to_each_descriptor() {
    let _g = reset();
    let fs = FsInfo::default();
    fs.chdir(fd(1));
    fs.chroot(fd(2));

    let child = fs.duplicate();
    drop(fs);
    assert!(
        !finalized(1) && !finalized(2),
        "the child holds its own reference to each"
    );
    drop(child);
    assert!(finalized(1) && finalized(2), "and gives both back");
}

/// The umask is copied, not shared: a child's umask(2) must not move its
/// parent's.
#[test]
fn a_copy_carries_the_umask_and_then_diverges() {
    let _g = reset();
    let parent = FsInfo::default();
    parent.set_umask(0o027);

    let child = parent.duplicate();
    assert_eq!(child.umask(), 0o027);

    child.set_umask(0o022);
    assert_eq!(parent.umask(), 0o027, "the parent is unchanged");
}

#[test]
fn replacing_the_working_directory_releases_the_old_one_exactly_once() {
    let _g = reset();
    let fs = FsInfo::default();
    fs.chdir(fd(1));
    fs.chdir(fd(2));
    let so_far = finalized_so_far().clone();
    assert_eq!(so_far, vec![1], "the first is released, once");
    drop(fs);
    let so_far = finalized_so_far().clone();
    assert_eq!(so_far, vec![1, 2]);
}

/// The reader interface hands out a *reference*, not a pointer.
///
/// This is the whole reason the type exists: `chdir` and `chroot` close the
/// descriptor they replace, and a thread created with CLONE_FS shares this
/// object, so a reader holding a bare pointer across the replacement is reading
/// freed memory.
#[test]
fn a_reader_holds_a_reference_across_a_concurrent_replacement() {
    let _g = reset();
    let fs = FsInfo::default();
    fs.chdir(fd(1));

    let (pwd, _root) = fs.pwd_and_root();
    let pwd = pwd.expect("a working directory");
    assert_eq!(tag(&pwd), 1);

    // Another thread chdirs. Without the reader's reference this would be the
    // last one.
    fs.chdir(fd(2));
    assert!(!finalized(1), "still alive, because the reader holds one");

    drop(pwd);
    assert!(finalized(1));
}

/// Both come from one hold, so a caller cannot see a pwd from before a chroot
/// and a root from after it.
#[test]
fn the_pair_is_read_together() {
    let _g = reset();
    let fs = FsInfo::default();
    fs.chdir(fd(1));
    fs.chroot(fd(2));
    let (pwd, root) = fs.pwd_and_root();
    assert_eq!((pwd.as_ref().map(tag), root.as_ref().map(tag)), (Some(1), Some(2)));
    assert_eq!(fs.pwd().as_ref().map(tag), Some(1));
    assert_eq!(fs.root().as_ref().map(tag), Some(2));
}

/// A task with neither has none of either, and a copy of it is still empty.
#[test]
fn an_empty_context_hands_out_nothing() {
    let _g = reset();
    let fs = FsInfo::default();
    let (pwd, root) = fs.pwd_and_root();
    assert!(pwd.is_none() && root.is_none());
    let child = fs.duplicate();
    assert!(child.pwd().is_none() && child.root().is_none());
    assert!(finalized_so_far().is_empty());
}

#[test]
fn the_umask_keeps_only_the_permission_bits() {
    let _g = reset();
    let fs = FsInfo::default();
    // umask(2) takes an int and Linux keeps the low nine bits.
    assert_eq!(fs.set_umask(0o7777), 0);
    assert_eq!(fs.umask(), 0o777);
    assert_eq!(fs.apply_umask(0o666), 0);
}
