//! Guest-to-host path resolution for native offload.

use super::*;

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Ask something about the calling task's **root** mount.
///
/// The reference is held for the call and no pointer escapes: a `chroot` on
/// another thread of this `CLONE_FS` group closes the descriptor it replaces.
fn with_root_mount<T>(f: impl FnOnce(&ffi::mount) -> Option<T>) -> Option<T> {
    let root = taskview::with_current_fs(|fs| fs.root()).flatten()?;
    f(root.mount()?)
}

/// The root mount's source directory, for realfs and fakefs alike.
///
/// **The root's**, which is the whole point. This used to prefer whatever
/// `fakefs_rs_mount_info` reported, and that answers about *the* fakefs rather
/// than this task's root — so under the CLI's `-r`, which mounts a temporary
/// fakefs on `/dev` so the guest has device nodes, every offloaded program was
/// pointed at that `/dev` directory. It went unnoticed because the redirect
/// dylib was never built, so `FAKEFS_ROOT` was never injected and nothing read
/// the answer.
///
/// The source string outlives the descriptor — a mount is not unmounted while
/// a task is rooted at it — so the reference is only needed long enough to
/// read through it.
pub(super) fn root_source() -> Option<PathBuf> {
    with_root_mount(|mount| {
        let src = &mount.source;
        (!src.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(src.to_bytes())))
    })
}

/// Run `f` with the calling task's root fakefs database, if its root is one.
///
/// Same question as [`root_source`] and the same reason: files a native run
/// created belong in the *root's* `meta.db`, and registering them in `/dev`'s
/// puts them where nothing will ever look.
///
/// **The database is borrowed for the call and no pointer escapes.** This was
/// `root_fakefs_db() -> Option<*mut Db>` until 2026-09-16, and the pointer
/// outlived [`with_root_mount`]'s reference by the whole of
/// `register_new_files` -- a `read_dir` per directory the command named, plus
/// a `stat` and a transaction per file. A `umount` of the root in that window
/// reaches `fakedb_close`, which is a `Box::from_raw` and a drop. Answering
/// through a closure is what ties the borrow to the reference that keeps it
/// alive; `fs_fake::fakefs_rs_mount_db` answers an `Option<&Db>` now, so there
/// is no pointer here to let escape.
pub(super) fn with_root_fakefs<T>(f: impl FnOnce(&fakedb::Db) -> T) -> Option<T> {
    with_root_mount(|mount| {
        // The borrow is `with_root_mount`'s reference to the root, which
        // keeps the mount and its database for the whole of this closure.
        let db = fs_fake::fakefs_rs_mount_db(mount)?;
        Some(f(db))
    })
}

/// Where a guest absolute path is on the host.
///
/// Bind mounts win; otherwise the root's source directory plus the path. See
/// the module comment on why this is a `PathBuf`.
pub(super) fn host_path_for_guest(guest: &[u8]) -> Option<PathBuf> {
    if guest.first() == Some(&b'/')
        && let Some(host) = CString::new(guest)
            .ok()
            .and_then(|c| fs_fake::fakefs_bind_mount_translate_path(&c))
    {
        return Some(PathBuf::from(OsStr::from_bytes(host.as_bytes())));
    }
    let root = root_source()?;
    let rel = guest.strip_prefix(b"/").unwrap_or(guest);
    Some(root.join(OsStr::from_bytes(rel)))
}

/// The calling task's working directory, as the guest sees it.
///
/// A *reference*, not a pointer: a `chdir` on another thread of this
/// `CLONE_FS` group closes the descriptor it replaces, and the `getpath` below
/// dispatches into the mount.
pub(super) fn guest_cwd() -> Option<Vec<u8>> {
    let pwd = taskview::with_current_fs(|fs| fs.pwd()).flatten()?;
    // `MAX_PATH + 1`: an answer is the path *and* its terminator, and this was
    // a byte short of what eight implementations of `getpath` were written
    // against. The slice's length is what decides now.
    let mut buf = vec![0u8; ffi::MAX_PATH as usize + 1];
    // A filesystem with no `getpath` reaches the trait's default, which is
    // `_EPERM` -- negative, which is all this asks.
    //
    let err = match pwd.mount().and_then(|m| m.fs) {
        Some(fs) => fs.getpath(&pwd, &mut buf),
        None => -1,
    };
    if err < 0 {
        return None;
    }
    buf.truncate(ffi::path_bytes(&buf).len());
    Some(buf)
}

/// The host directory a native program should start in.
///
/// An empty guest cwd — or `/`, which is the same thing once the leading slash
/// is stripped — falls back to the root's source directly: bind-mount
/// translation is only meaningful for a subpath of a mounted prefix.
pub(super) fn host_cwd() -> Option<PathBuf> {
    let cwd = guest_cwd()?;
    if cwd.is_empty() || cwd == b"/" {
        return root_source();
    }
    host_path_for_guest(&cwd)
}
