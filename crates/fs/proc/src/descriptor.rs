//! Procfs descriptor ownership and mount-relative path lookup.

use super::*;
use std::sync::Mutex;

/// Everything a procfs descriptor holds, behind `fd->fs_data`.
///
/// # Why the mutable half is behind a lock
///
/// **A descriptor is shared and the read path holds no lock.** `sys_read`
/// takes `fd->lock` for the positional calls only — see
/// `crates/kernel/rwcalls`' `FdGuard` — and procfs answers `read: false`, so a
/// plain `read()` falls through the capability fallback into `FdOps::pread`
/// with nothing held. Two threads on one descriptor therefore arrive here at
/// once, by `dup` or by `CLONE_FILES`, which every pthread is.
///
/// This used to be three plain fields and `state(fd)` used to answer
/// `&mut ProcFd`, so those two threads held two live `&mut` to one object and
/// both ran `refresh`, which clears a `Vec` and refills it. It panicked with
/// `range end index 2166 out of range for slice of length 1083` — twice the
/// length, one buffer — inside a syscall shim, which aborts.
/// `tests/guest/src/bin/proc_read_race.rs` is that, and
/// `crates/fs/tmpfs`'s `FdState` is the sibling that had it right, with
/// `dir_pos: Mutex<DirPos>`.
///
/// Linux's equivalent is `seq_file->lock`, which is a mutex per *open file*
/// for exactly this reason.
pub(crate) struct ProcFd {
    /// The path this was opened at, within the mount.
    ///
    /// The C rebuilt this by walking `meta->parent`, a field it had written
    /// into the shared table on the way down. Remembering it costs a string
    /// per descriptor and takes the tables out of the picture.
    ///
    /// **Outside the lock**: written by `proc_open` before the descriptor is
    /// reachable and read-only afterwards.
    pub(crate) path: Vec<u8>,
    /// What a read, a write, a seek or a readdir touches.
    pub(crate) open: Mutex<Open>,
}

/// The half of a procfs descriptor that operations mutate.
pub(crate) struct Open {
    /// Handed to the table's callbacks, which read `meta`, `pid`, `fd` and
    /// `name` — and, for the `/proc/iul/defaults` directories, write
    /// `child_names`.
    pub(crate) entry: ffi::proc_entry,
    /// The generated contents, cleared and refilled by [`crate::refresh`].
    pub(crate) data: ffi::proc_data,
}

impl Open {
    pub(crate) fn meta(&self) -> Option<&'static ffi::proc_dir_entry> {
        self.entry.meta
    }

    pub(crate) fn mode(&mut self) -> u32 {
        entry::proc_entry_mode(&mut self.entry) as u32
    }
}

/// This filesystem's state on one of its descriptors.
///
/// `None` for a descriptor procfs did not open -- `fs_data` is empty or holds
/// another type then, and the driver this is reached through is procfs's, so
/// in practice there is no such caller. [`ProcFd`] is written by `proc_open`
/// and dropped with the description.
///
/// A `# Safety` section said "`fd` must be a live descriptor this filesystem
/// opened" until 2026-09-16, on a **safe** function -- a promise the signature
/// does not ask the caller for, and the borrow already carries the liveness
/// half of it.
pub(crate) fn state(fd: &ffi::fd) -> Option<&ProcFd> {
    fd.fs_data::<ProcFd>()
}

/// The mutable half, locked.
///
/// **Not reentrant**, as `std::sync::Mutex` is not: no operation below takes
/// this twice, and the table callbacks it is held across read task, mount and
/// address-space state rather than reaching back into a procfs descriptor.
pub(crate) fn open_of(state: &ProcFd) -> std::sync::MutexGuard<'_, Open> {
    state.open.lock().unwrap_or_else(|p| p.into_inner())
}

// ============================================================
// Lookup
// ============================================================

/// Resolve a mount-relative path to an entry, and to the path itself.
///
/// The path is returned alongside because the caller keeps it: it is what
/// `getpath` reports, and rebuilding it from the tables is what forced the C
/// to write `parent` into them.
pub(crate) fn lookup(path: &[u8]) -> Result<(ffi::proc_entry, Vec<u8>), c_int> {
    // Every `return` below used to be preceded by `cleanup(&mut entry)`, and
    // the assignment in the middle by another. The entry owns its strings, so
    // the early returns drop it and `entry = child` drops what it replaces.
    let mut entry = ffi::proc_entry {
        meta: Some(&root::proc_root.0),
        ..Default::default()
    };
    let mut resolved: Vec<u8> = Vec::new();

    for component in components(path) {
        if component.len() > MAX_NAME {
            return Err(ENAMETOOLONG);
        }
        let mode = entry::proc_entry_mode(&mut entry) as u32;
        if mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        guarded(&entry)?;

        match find_child(&mut entry, component) {
            Some(child) => {
                entry = child;
                resolved.push(b'/');
                resolved.extend_from_slice(component);
            }
            None => return Err(ENOENT),
        }
    }
    Ok((entry, resolved))
}

/// A directory's own rule for who may look inside it; see `proc_dir_entry::guard`.
pub(crate) fn guarded(entry: &ffi::proc_entry) -> Result<(), c_int> {
    match entry.meta.and_then(|m| m.guard).map_or(0, |guard| guard(entry)) {
        0 => Ok(()),
        e => Err(e),
    }
}

/// Scan a directory entry's children for `name`.
pub(crate) fn find_child(dir: &mut ffi::proc_entry, name: &[u8]) -> Option<ffi::proc_entry> {
    let mut index: c_ulong = 0;
    loop {
        let Some(mut next) = entry::proc_dir_read(dir, &mut index) else {
            // What a listing does not show can still be named: a thread's
            // `/proc/<tid>`, as on Linux.
            return root::lookup_hidden_pid(dir, name);
        };

        let mut buf = [0u8; MAX_NAME + 1];
        // The truncation is against this slice's length now, so the comment
        // that used to say "at most MAX_NAME bytes plus a terminator" -- true
        // of four of the five implementations -- has nothing left to assert.
        entry::proc_entry_getname(&mut next, &mut buf);
        let got = ffi::path_bytes(&buf);
        if got == name {
            return Some(next);
        }
        // `next` is dropped here, which is what `cleanup(&mut next)` was.
    }
}

/// Split a mount-relative path into components, skipping `.` and empty ones.
pub(crate) fn components(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.split(|&b| b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
}
