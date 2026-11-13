//! Bind mount registration, replacement, and restoration.

use std::ffi::{CStr, c_char, c_int};

use crate::{
    EINVAL, ENAMETOOLONG, ENOENT, FakefsMount, PATH_MAX, any_fakefs_mounted,
    fakefs_paths_changed_pub, ffi, fix_path, host_lstat,
};

// ---------------------------------------------------- bind mounts

use guest_errno::c_int_::ENODEV;

/// Serialises whole registrations against whole unmounts.
///
/// The bind-mount table's own lock cannot do it: the symlink and `meta.db`
/// work has to happen **outside** any lock a reader takes, and in that gap
/// `bind_unmount` removed a registration, another registration installed its
/// route, and then the first call's restore put the old tree back over the new
/// mount.
///
/// No reader takes this, so it cannot deadlock against the database lock.
static BIND_CHANGE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The metadata moves with the tree it describes.
///
/// Stashing the files and not their `meta.db` rows meant the rows were deleted
/// as the bind's own on the way out, and the restored tree came back with no
/// modes, types or inode numbers of its own. A rename moves a whole subtree by
/// prefix, which is exactly the shape of this.
fn meta_stash(db: &fakedb::Db, path: &[u8]) {
    let Some(saved) = stash_name(path) else {
        return;
    };
    let mut tx = db.write();
    if tx.path_inode(&saved) != 0 {
        // A stash is already there, from the registration this one replaces.
        // It describes the tree the guest had before any bind, which is what
        // the eventual restore has to put back -- so the rows being displaced
        // now are the outgoing bind's, and they go rather than overwrite it.
        // Deleting the stash first meant a replaced mount restored the *old
        // target's* metadata onto the original tree.
        tx.delete_tree(path);
    } else {
        tx.rename(path, &saved);
    }
    tx.commit();
}

fn meta_restore(db: &fakedb::Db, path: &[u8]) {
    let Some(saved) = stash_name(path) else {
        return;
    };
    let mut tx = db.write();
    tx.delete_tree(path); // the bind's own rows
    tx.rename(&saved, path);
    tx.commit();
}

fn stash_name(path: &[u8]) -> Option<Vec<u8>> {
    let p = std::str::from_utf8(path).ok()?;
    let name = bindstash::saved_name(p);
    if name.is_empty() {
        None
    } else {
        Some(name.into_bytes())
    }
}

/// # Safety
///
/// Both paths are NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fakefs_bind_mount(
    linux_path: *const c_char,
    host_path: *const c_char,
    read_only: bool,
) -> c_int {
    // Grafting a host directory in changes what guest paths resolve to, so the
    // same cached paths are stale.
    fakefs_paths_changed_pub();

    // SAFETY: the caller's contract.
    let (guest_c, host_c) = unsafe { (CStr::from_ptr(linux_path), CStr::from_ptr(host_path)) };
    let (Ok(guest), Ok(host_in)) = (guest_c.to_str(), host_c.to_str()) else {
        return EINVAL;
    };
    if !any_fakefs_mounted() {
        return ENODEV;
    }
    // The table is compared against normalized, absolute guest paths, so a
    // relative one registered a route nothing could ever match -- the mount
    // appeared to succeed and then did nothing.
    if !guest.starts_with('/') {
        return EINVAL;
    }
    // Normalized here as well as inside the table, because the paths this side
    // derives -- the symlink's and the meta.db rows' -- have to be the ones the
    // lookups compare against: a route registered as "/mnt/./sub" was matched
    // against "/mnt/sub" and never found.
    let Some(guest) = bindpath::normalize(guest, ffi::MAX_PATH as usize) else {
        return ENAMETOOLONG;
    };
    let Ok(guest_cs) = std::ffi::CString::new(guest.as_str()) else {
        return EINVAL;
    };

    let _change = BIND_CHANGE.lock().expect("not poisoned");

    // **The fakefs that owns this guest path**, held for the rest of the call.
    // Not "the fakefs": there are two or three on any boot and the registry
    // used to report whichever mounted last, so the symlink and the meta.db
    // row below went to `/dev/shm`. See `FakefsMount` and
    // `tests/mount_registry.rs`.
    //
    // `ENODEV` also covers a guest path owned by a mount that is not a fakefs
    // -- a tmpfs, say -- which used to be accepted and then written into
    // whichever fakefs was in the slot.
    let Some(fakefs) = FakefsMount::owning(&guest_cs) else {
        return ENODEV;
    };

    // The host side must exist and be a directory or a regular file.
    let Some(st) = host_lstat(host_c.to_bytes(), true) else {
        return ENOENT;
    };
    let fmt = st.st_mode as u32 & libc::S_IFMT as u32;
    let is_file = fmt == libc::S_IFREG as u32;
    if fmt != libc::S_IFDIR as u32 && !is_file {
        return ENOENT;
    }

    // Symlinks resolved so that the host path matches what F_GETPATH returns:
    // ~/Library/GroupContainersAlias/... is ~/Library/Group Containers/...
    let host = match std::fs::canonicalize(host_in) {
        Ok(real) => real.to_string_lossy().into_owned(),
        Err(_) => host_in.to_string(),
    };

    // The mount point's own mode, which the read-only flag decides.
    let top_mode = if is_file {
        libc::S_IFREG as u32 | if read_only { 0o444 } else { 0o644 }
    } else {
        libc::S_IFDIR as u32 | if read_only { 0o555 } else { 0o755 }
    };

    // One operation: it replaces whatever was registered at this guest path
    // and reports whether the host path changed, which is what decides the
    // symlink and meta.db work below. Asking and then registering would be
    // two, with a gap another registration could land in.
    //
    // The registration is not held across that work: it blocks, and stat
    // translates a path while holding a read transaction -- so taking the
    // database lock under the table's would invert the order the two are
    // acquired in and deadlock.
    let Ok(host_cs) = std::ffi::CString::new(host.as_str()) else {
        return EINVAL;
    };
    let registered = bindmount::bindmount_register(&guest_cs, &host_cs, read_only);
    if registered < 0 {
        return registered;
    }
    let host_changed = registered != 0;

    // A guest path is bounded by MAX_PATH (4096) and a *host* one by PATH_MAX,
    // which is 1024 here. This used to format across that boundary and
    // truncate, so a mount at a guest path longer than 1023 characters put its
    // symlink somewhere else entirely -- and the lookups, which keep the whole
    // path, still routed to the mount. Refused, with room for the stash suffix.
    let link = fix_path(&guest_cs).to_string_lossy().into_owned();
    if link.len() + bindstash::SAVED_SUFFIX.len() + 1 > PATH_MAX {
        bindmount::bindmount_unregister(&guest_cs);
        return ENAMETOOLONG;
    }

    let root = fakefs.root();
    if host_changed {
        let done =
            bindstash::stash(root, &link).and_then(|()| bindstash::symlink(root, &link, &host));
        if let Err(e) = done {
            bindmount::bindmount_unregister(&guest_cs);
            bindstash::restore(root, &link);
            return e;
        }
    }

    // The mount point exists in meta.db with the mode the read-only flag calls
    // for, and any rows describing the tree that used to be there are dropped.
    // Those rows outlived both the unmount and a change of host path, so a stat
    // of a path under the new target answered with the old one's type and
    // inode.
    if let Some(db) = fakefs.db() {
        if host_changed {
            meta_stash(db, guest.as_bytes());
        }
        let mut tx = db.write();
        let ino = tx.path_inode(guest.as_bytes());
        if ino == 0 {
            tx.path_create(
                guest.as_bytes(),
                &fakedb::IulStat {
                    mode: top_mode,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                },
            );
        } else if let Some(mut prev) = tx.inode_stat(ino) {
            prev.mode = top_mode;
            tx.inode_write_stat(ino, &prev);
        }
        tx.commit();
    }
    0
}

/// # Safety
///
/// `linux_path` is NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fakefs_bind_unmount(linux_path: *const c_char) -> c_int {
    // SAFETY: the caller's contract -- `iul.h` declares this and a C embedder
    // passes a `const char *`, so the conversion is here rather than in the
    // signature.
    let guest_c = unsafe { CStr::from_ptr(linux_path) };
    let Ok(guest) = guest_c.to_str() else {
        return EINVAL;
    };
    let Some(guest) = bindpath::normalize(guest, ffi::MAX_PATH as usize) else {
        return ENAMETOOLONG;
    };

    let Ok(guest_cs) = std::ffi::CString::new(guest.as_str()) else {
        return EINVAL;
    };

    let _change = BIND_CHANGE.lock().expect("not poisoned");
    // The same fakefs the registration went to, found the same way -- the one
    // that owns this guest path, not whichever mounted last.
    let Some(fakefs) = FakefsMount::owning(&guest_cs) else {
        return ENODEV;
    };
    // SAFETY: `guest_cs` is NUL-terminated.
    if !bindmount::bindmount_unregister(&guest_cs) {
        return ENOENT;
    }

    // The symlink goes and whatever the mount point held before it comes back,
    // which the registration moved aside rather than deleting.
    let link = fix_path(&guest_cs).to_string_lossy().into_owned();
    bindstash::restore(fakefs.root(), &link);
    // And its metadata: the bind's own rows go, the stashed tree's come back.
    // Leaving the bind's meant a later mount at the same guest path reused its
    // inode numbers, types and permissions for different files.
    if let Some(db) = fakefs.db() {
        meta_restore(db, guest.as_bytes());
    }
    0
}
