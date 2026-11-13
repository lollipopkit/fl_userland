//! Filesystem notification hook and watch dispatch.

use std::sync::atomic::Ordering;

use crate::{ANYONE_WATCHING, wake, with_registry};

/// Whether anything is watching. The VFS asks before building a path.
pub(crate) fn inotify_watching() -> bool {
    ANYONE_WATCHING.load(Ordering::Relaxed)
}

// `inotify_notify_path` was here until 2026-09-30: a `pub unsafe fn` taking a
// C string, re-exported from the crate root, with no caller anywhere -- the VFS
// reaches `notify` through `crates/fs/inotify`'s hook. `pub` is what kept
// `dead_code` from saying so; the missing `# Safety` section is what did.

/// The dispatcher `crates/fs/inotify`'s hook points at.
///
/// The descriptor layer and the VFS raise these events and this layer consumes
/// them, so the call comes back up through the hook rather than down through a
/// dependency; see `inotify::notify_path`.
pub(super) fn notify(path: &[u8], mask: u32, cookie: u32) {
    if !inotify_watching() {
        return;
    }
    let Some(slash) = path.iter().rposition(|&b| b == b'/') else {
        // Not a normalized path; nothing can be watching it by this name.
        return;
    };
    // The root itself is "/" and not the empty string.
    let dir = &path[..slash.max(1)];
    let name = &path[slash + 1..];

    // Every instance that actually changed, collected while the registry is
    // stable and woken after the lock is released.
    let ready = with_registry(|entries| {
        entries
            .iter_mut()
            .filter_map(|e| {
                // Upgraded under the lock: a description whose last reference
                // has gone is closing and has no reader to wake.
                (e.instance.notify(dir, name, mask, cookie) != 0)
                    .then(|| fs_fdobj::Owned::upgrade(&e.fd))
                    .flatten()
            })
            .collect::<Vec<_>>()
    });
    for fd in &ready {
        wake(fd);
    }
    // Outside the lock: one of these can be the last reference, and its close
    // takes the lock to deregister.
    drop(ready);
}

/// Pairs the two halves of a rename.
///
/// Linux uses one cookie per rename so a watcher can match `IN_MOVED_FROM` with
/// `IN_MOVED_TO`; any value will do as long as it does not repeat while both
/// halves are still queued.
#[cfg(test)]
pub(crate) fn inotify_next_cookie() -> u32 {
    inotify::next_cookie()
}
