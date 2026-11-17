//! Where a task resolves a path from: its working directory, its root, and its
//! umask.
//!
//! Three fields with two rules between them, from `kernel/fs_info.c` and the
//! chdir/chroot/umask calls in `kernel/fs.c`.
//!
//! **A thread created with `CLONE_FS` — every pthread — shares one of these.**
//! So `chdir` on one thread replaces the descriptor another thread is about to
//! resolve against, and the replacement *closes* the old one. Both rules follow
//! from that:
//!
//! 1. A reader takes a **reference**, not a pointer. Reading the pointer under
//!    the lock and using it afterwards is a use-after-free, and `fs/path.c`
//!    carries the changelog entry for the time it was.
//! 2. The pair is read **under one hold**. `path_normalize` wants the working
//!    directory and the root together; two acquisitions would give it a `pwd`
//!    from before a `chroot` and a root from after.
//!
//! Both are in the interface here rather than in each caller: there is no
//! function that hands out a bare pointer, so 1 cannot be got wrong, and
//! [`FsInfo::pwd_and_root`] is the only way to get both, so neither can 2.
//!
//! # What the C had
//!
//! `fs_info_copy` — `fork` without `CLONE_FS` — read `pwd` and `root`
//! **without the lock** and retained them afterwards, which is exactly the
//! use-after-free rule 1 exists for, on the one path that was never fixed. It
//! also dereferenced its allocation before checking it, so an `fs_info_new`
//! that returned NULL crashed rather than making `fork` answer `ENOMEM` — the
//! caller has the check and never got to run it.

use std::ffi::{c_uint, c_void};
use std::sync::{Arc, Mutex};

use iul_abi::FdOwned as Owned;

/// A descriptor this owns a reference to, or none: `kernel-abi`'s typed
/// handle since 2026-10-17. It was `fs_fd::Owned`, the untyped one, because
/// the typed one lived in the descriptor layer this crate may not depend on;
/// every caller converted between the two.
///
/// **It was a second implementation of that handle until 2026-09-29** --
/// `Held`, with `adopt`, `share`, `lend` and `release` against a `Drop` -- and
/// its tests ran against a *third*: `fd_retain` and `fd_close` substituted by a
/// `cfg`, counting against fake pointers `1`, `2`, `3`. So what the tests
/// checked was that `Held` called its doubles in the right order, never that a
/// reference held here keeps a descriptor alive. They make real handles now.
/// The handle was in `fs-fd`, below this crate, until 2026-10-17; it is
/// `kernel-abi`'s now, which this crate already depends on.
type Held = Option<Owned>;

#[derive(Default)]
struct Inner {
    umask: u32,
    pwd: Held,
    root: Held,
}

/// One task's path context. Shared by every thread of a `CLONE_FS` group.
#[derive(Default)]
pub struct FsInfo {
    inner: Mutex<Inner>,
}

impl FsInfo {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A copy for a `fork` that did not ask to share. Taken under one hold, so
    /// the child cannot get a `pwd` from before a concurrent `chroot` and a
    /// root from after it.
    pub fn duplicate(&self) -> FsInfo {
        let g = self.lock();
        FsInfo {
            inner: Mutex::new(Inner {
                umask: g.umask,
                pwd: g.pwd.clone(),
                root: g.root.clone(),
            }),
        }
    }

    /// Both, each a reference of the caller's own, under one hold of the lock.
    ///
    /// Either may be `None`: a task has no root until something chroots, and
    /// none of either until `become_first_process` has run.
    pub fn pwd_and_root(&self) -> (Option<Owned>, Option<Owned>) {
        let g = self.lock();
        (g.pwd.clone(), g.root.clone())
    }

    /// The working directory, a reference of the caller's own.
    pub fn pwd(&self) -> Option<Owned> {
        self.lock().pwd.clone()
    }

    /// The root. `None` for a task at the machine's own.
    pub fn root(&self) -> Option<Owned> {
        self.lock().root.clone()
    }

    /// Replaces the working directory with `fd`.
    pub fn chdir(&self, fd: Owned) {
        let old = self.lock().pwd.replace(fd);
        // Dropped outside the lock: closing a descriptor runs its filesystem's
        // own release, and holding this across a call into an arbitrary mount
        // is how lock-order inversions get made.
        drop(old);
    }

    /// Replaces the root with `fd`.
    pub fn chroot(&self, fd: Owned) {
        let old = self.lock().root.replace(fd);
        drop(old);
    }

    /// No root of its own: the machine's.
    pub fn reset_root(&self) {
        let old = self.lock().root.take();
        drop(old);
    }

    /// The current mask.
    pub fn umask(&self) -> c_uint {
        self.lock().umask
    }

    /// Sets it and answers the old one, which is what `umask(2)` returns.
    pub fn set_umask(&self, mask: c_uint) -> c_uint {
        std::mem::replace(&mut self.lock().umask, mask & 0o777)
    }

    /// `mode` without the masked bits, for a create about to use it.
    pub fn apply_umask(&self, mode: c_uint) -> c_uint {
        mode & !self.lock().umask
    }
}

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------
//
// A task holds its context in a `taskview::ArcSlot`, so a fresh one is an
// `Arc` and sharing one -- `fork` with `CLONE_FS` -- is a clone of it. The
// handle functions that were here until 2026-10-16 -- `fs_info_retain` and
// `fs_info_release` around `Arc::from_raw`, and `fs_info_new` and
// `fs_info_copy` answering `Arc::into_raw` -- were the slot's job done at
// every call site.

/// A fresh context: no working directory, no root, umask 0.
pub fn fs_info_new() -> Arc<FsInfo> {
    Arc::new(FsInfo::default())
}

// ---------------------------------------------------------------------------
// The two descriptors
// ---------------------------------------------------------------------------

/// Replaces the working directory. **Consumes** the caller's reference to `fd`.
///
/// The embedder's entry point, declared in `iul.h`; Rust calls
/// [`FsInfo::chdir`].
///
/// # Safety
///
/// `h` is a live context -- `current_fs()`'s answer, which the calling task
/// holds a count on -- and `fd` is a live `struct fd` carrying a reference the
/// caller is giving up.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fs_chdir(h: *mut c_void, fd: *mut c_void) {
    let fd = unsafe { Owned::from_raw(fd.cast()) };
    unsafe { &*h.cast::<FsInfo>() }.chdir(fd);
}

/// Replaces the root. **Consumes** the caller's reference to `fd`.
///
/// The embedder's entry point, like [`fs_chdir`]: ServerBox points each
/// session at one profile's subtree this way, and did it by writing
/// `current->fs->root` until `struct fs_info` became Rust's.
///
/// # Safety
///
/// As [`fs_chdir`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fs_chroot(h: *mut c_void, fd: *mut c_void) {
    let fd = unsafe { Owned::from_raw(fd.cast()) };
    unsafe { &*h.cast::<FsInfo>() }.chroot(fd);
}

/// A machine-absolute path -- what `generic_getpath` answers -- as the task
/// rooted at `root` names it: the working directory for `getcwd`, and the
/// links `/proc/<pid>/{cwd,root,exe,fd/*,map_files/*}` for a reader that is
/// chrooted.
///
/// `generic_getpath` answers in the *machine's* terms, and a task rooted at a
/// subtree would otherwise be told its working directory is a path it cannot
/// name — `/jail` for what is its own `/`. That is what Linux does for a
/// chrooted process.
///
/// Two things this must not do. `generic_getpath` answers `"/"` for a task
/// rooted at the machine's own — it repairs an empty result to that — so
/// stripping unconditionally would take the leading slash off every path a
/// normal task reports and turn `/tmp` into `tmp`. And the prefix has to end on
/// a component boundary, or a cwd of `/jail-old` under a root of `/jail` would
/// be reported as `-old`.
///
/// A cwd outside the root is left as it is: it cannot be spelled from inside,
/// but a machine-absolute path is at least true, and there is no reachable way
/// to produce one — `fs_chdir` only stores what this task resolved.
pub fn relative_to_root(pwd: &[u8], root: &[u8]) -> Vec<u8> {
    if root.len() > 1 && pwd.starts_with(root) && matches!(pwd.get(root.len()), None | Some(b'/')) {
        let rest = &pwd[root.len()..];
        return if rest.is_empty() {
            b"/".to_vec()
        } else {
            rest.to_vec()
        };
    }
    pwd.to_vec()
}

// ---------------------------------------------------------------------------
// umask
// ---------------------------------------------------------------------------

// `fs_umask`, `fs_umask_set` and `fs_apply_umask` were here until 2026-09-30,
// each an `unsafe fn` over the raw handle -- the last with a `*mut c_uint` for
// a value it could have answered. They are `FsInfo::umask`, `set_umask` and
// `apply_umask`.

#[cfg(test)]
mod tests;
