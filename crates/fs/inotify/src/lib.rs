//! inotify: the watch registry and the event queue.
//!
//! `kernel/inotify.c` used to accept a watch, validate it carefully, and then
//! never report anything — the comment said so outright: "Watches are accepted
//! and validated, but nothing generates events, so a read has nothing to
//! return and never will." A watcher was told it had succeeded and then waited
//! for ever. Every file watcher works this way: `entr`, `cargo-watch`,
//! webpack, an editor's index.
//!
//! What lives here is the part that is a data structure and a wire format: who
//! is watching what, which events they asked for, and the byte layout a read
//! returns. What stays in C is where the events come from — the VFS operations
//! that create, delete, rename and modify things.
//!
//! The record, as an aarch64 guest reads it:
//!
//! ```text
//! offset  0   wd      i32
//!         4   mask    u32
//!         8   cookie  u32
//!        12   len     u32   (the name field's length, padding included)
//!        16   name    NUL-terminated, then padded to a multiple of 16
//! ```
//!
//! `len` counts the padding, unlike `getdents64`'s `d_reclen` which counts the
//! whole record. Getting that backwards would put every event after the first
//! at the wrong offset, which is the class of bug `fs/dirent-rs` and
//! `fs/cmsg-rs` were both written to make impossible.

use std::sync::OnceLock;

mod model;

pub use model::*;

// The C ABI this crate used to carry is gone. Every function in it existed so
// that `kernel/inotify.c` could reach an instance through an opaque pointer,
// and there is no `kernel/inotify.c`: `crates/kernel/inotifycalls` owns the
// registry and calls the methods above as Rust. Six exports went with it —
// `tools/dead-exports.py` is what named them.

// ---------------------------------------------------------------------------
// The hook the filesystem calls
// ---------------------------------------------------------------------------

/// What a filesystem event is handed to.
///
/// `path` is a normalized guest path, `mask` one event, and `cookie` pairs the
/// two halves of a rename.
pub type NotifyFn = fn(path: &[u8], mask: u32, cookie: u32);

/// Installed once by `crates/kernel/inotifycalls`, which owns the instances.
static HOOK: OnceLock<NotifyFn> = OnceLock::new();

/// Install the dispatcher. The first call wins; later ones are ignored, which
/// makes this safe to call from every `inotify_init1`.
pub fn set_notify_hook(f: NotifyFn) {
    let _ = HOOK.set(f);
}

/// Hand one event to whatever is watching.
///
/// # Why the indirection
///
/// The descriptor layer and the VFS produce these events and the *syscalls*
/// consume them, so the direct call went downward-to-upward:
/// `crates/fs/fdobj` depended on `crates/kernel/inotifycalls`, which depends
/// on `crates/fs/poll`, which reaches `fs/fdobj` again — a cycle cargo
/// refuses, and it is a cycle because the dependency was pointing the wrong
/// way. The event model is a leaf crate, so the hook lives here and the layer
/// that owns the instances installs it.
///
/// Nothing is installed until the first `inotify_init1`, and nothing can be
/// watching before then, so an event before that is dropped rather than
/// queued.
/// The cookie for the next rename.
///
/// Linux uses one cookie per rename so a watcher can match `IN_MOVED_FROM` with
/// `IN_MOVED_TO`; any value will do as long as it does not repeat while both
/// halves are still queued.
///
/// Here rather than in `crates/kernel/inotifycalls` for the reason
/// [`notify_path`] gives: the VFS is what renames, and reaching up to the
/// syscall crate for a counter is the edge that made `fs-generic` ->
/// `kernel-inotifycalls` -> `kernel-pathcalls` -> `kernel-fdattr` ->
/// `fs-generic` a cycle.
pub fn next_cookie() -> u32 {
    static COOKIE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    COOKIE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub fn notify_path(path: &[u8], mask: u32, cookie: u32) {
    if let Some(f) = HOOK.get() {
        f(path, mask, cookie);
    }
}
