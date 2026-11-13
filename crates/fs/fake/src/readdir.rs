//! Directory iteration and per-descriptor path caching.

use std::ffi::c_int;

use ffi::FdOps as _;

use crate::{
    EIO, ensure_inode, fakefs_path_generation_get, ffi, is_under_bind_mount,
    fd_db, translate,
};

// ------------------------------------------------------------ readdir

/// The `meta.db` key of an open directory, cached on the descriptor.
///
/// The key, not the guest path: they differ for the root, which `meta.db`
/// stores as the **empty blob**. `realfs_getpath` answers with the guest path,
/// which for the root *is* `/`, and appending an entry name to that gives
/// `//name` — no key in `paths`, so every entry of the root missed and was
/// skipped. `ls /` on a fakefs listed nothing at all, not even `.`.
///
/// The C comment here said the tests did not catch it, because
/// `fs_conformance` is handed a scratch *subdirectory* and never reads the
/// root of the mount it is testing. That was true when the defect was found
/// and is not now: `readdir-root` was added with the fix and reads `/`
/// directly. Backed out, it reports `the root has a '.' entry: [".."]` and
/// four more.
///
/// It is cached because `readdir` needs it per entry and resolving it is an
/// `F_GETPATH`, a bind-mount table lookup and an allocation for a string that
/// is the same every time. Walking `/usr` in the integration rootfs went from
/// 11 ms to 3 ms with it cached.
///
/// A rename can move the directory while a descriptor is open on it. Renames
/// and bind-mount changes bump a generation, and a cache from an older one is
/// thrown away — renames are rare and entries are many, so the check costs an
/// atomic load per entry and the resolve costs nothing in the common case.
struct DirCache(std::sync::Mutex<Cached>);

struct Cached {
    generation: u64,
    path: [u8; ffi::MAX_PATH as usize + 1],
}

/// The directory's `meta.db` key, from the cache or freshly resolved.
///
/// The cache is made on the first listing rather than at open, by the
/// description's `fs_data_or_init` -- two threads reaching it together both
/// get the one that won, which is what the compare-exchange and its
/// loser-frees-its-own-box did by hand until 2026-09-29. As a plain
/// test-and-store before that it leaked four kilobytes every time two threads
/// reached it together; `crates/fs/realfs`'s `open_stream` had the same shape
/// one layer down and leaked a host descriptor.
///
/// The contents are behind a `Mutex`, where the `&mut` to them relied on the
/// caller holding `fd->lock` -- `sys_getdents64` does, so the lock is
/// uncontended, and this no longer needs anyone to.
fn dir_path(fd: &ffi::fd, out: &mut [u8]) -> c_int {
    let generation = fakefs_path_generation_get();
    let Some(cache) = fd.fs_data_or_init(|| {
        DirCache(std::sync::Mutex::new(Cached {
            // No generation is `u64::MAX`, so the first call resolves.
            generation: u64::MAX,
            path: [0; ffi::MAX_PATH as usize + 1],
        }))
    }) else {
        return EIO;
    };
    let mut c = cache.0.lock().unwrap_or_else(|e| e.into_inner());
    if c.generation == generation {
        return ffi::fill_path(out, ffi::path_bytes(&c.path));
    }
    // A fakefs description holds a reference on its mount, which is what
    // `realfs_getpath` reads the source from.
    let err = realfs::realfs_getpath(fd, out);
    if err < 0 {
        return err;
    }
    // The root is the empty blob. See the type's comment.
    if ffi::path_bytes(out) == b"/" {
        out[0] = 0;
    }
    let len = ffi::path_bytes(out).len();
    c.generation = generation;
    ffi::fill_path(&mut c.path, &out[..len])
}

/// `dirent_type_from_mode`: what `getdents64` reports as `d_type`.
fn dirent_type(mode: u32) -> u8 {
    match mode & libc::S_IFMT as u32 {
        m if m == libc::S_IFIFO as u32 => 1,   // DT_FIFO
        m if m == libc::S_IFCHR as u32 => 2,   // DT_CHR
        m if m == libc::S_IFDIR as u32 => 4,   // DT_DIR
        m if m == libc::S_IFBLK as u32 => 6,   // DT_BLK
        m if m == libc::S_IFREG as u32 => 8,   // DT_REG
        m if m == libc::S_IFLNK as u32 => 10,  // DT_LNK
        m if m == libc::S_IFSOCK as u32 => 12, // DT_SOCK
        _ => 0,                                // DT_UNKNOWN
    }
}

/// `fd` is a fakefs description: [`fd_db`] panics on anything else.
///
/// Safe since 2026-10-01; its contract named an `entry` parameter it no longer
/// has, and the one dereference left was of `fd.mount`, which `fd.mount()`
/// lends.
pub fn fakefs_rs_readdir(fd: &ffi::fd) -> Result<Option<ffi::dir_entry>, c_int> {
    // The directory's path buffer, once per call rather than once per entry
    // skipped: it is `MAX_PATH` bytes, and zeroing it per name was a memset a
    // directory of hook-routed or undescribed entries paid for each.
    let mut buf = vec![0u8; ffi::MAX_PATH as usize + 1];
    loop {
        // SAFETY: the caller's contract, forwarded to the host's readdir.
        //
        // `res <= 0` covered both "end of directory" and "it failed" until
        // 2026-09-16, which is what a `?` and a `let else` say now.
        let Some(mut entry) = realfs::REALFS_FDOPS.readdir(fd)? else {
            return Ok(None);
        };
        let entry = &mut entry;

        // The directory's own path, cached per descriptor by `dir_path`.
        buf.resize(ffi::MAX_PATH as usize + 1, 0);
        if dir_path(fd, &mut buf) < 0 {
            return Err(EIO);
        }
        let dir_len = ffi::path_bytes(&buf).len();
        buf.truncate(dir_len);

        let name = entry.name().to_vec();
        let entry_path = if name == b".." {
            // The parent, which for the root is the root.
            match buf.iter().rposition(|b| *b == b'/') {
                Some(i) if !buf.is_empty() => buf[..i].to_vec(),
                _ => buf.clone(),
            }
        } else if name == b"." {
            buf.clone()
        } else {
            // Bounded. A name that cannot be expressed as a path under this
            // directory is a name no caller could open anyway, so it is
            // skipped -- the old comment here read "god I don't know what to
            // do if this would overflow".
            if dir_len + 1 + name.len() > ffi::MAX_PATH as usize {
                continue;
            }
            let mut p = buf.clone();
            p.push(b'/');
            p.extend_from_slice(&name);
            p
        };

        let Ok(entry_c) = std::ffi::CString::new(entry_path.clone()) else {
            continue;
        };
        // A hook-routed entry is not in meta.db by design. The inode realfs
        // gave came straight from the host directory, so it is stable for the
        // duration of this open descriptor.
        if matches!(translate(&entry_c), Some((_, true))) {
            return Ok(Some(*entry));
        }

        // path_stat rather than a bare inode lookup: it is the same one query
        // and it also carries the mode, which is what getdents64 reports as
        // d_type. Without it every entry went out as DT_UNKNOWN and the guest
        // had to stat each one -- and a stat of a fakefs path is this same
        // query again, plus the path resolution to reach it.
        let db = fd_db(fd);
        let looked = db.lookup_path(&entry_path);
        match &looked {
            Some((iul, ino)) => {
                entry.inode = *ino;
                entry.type_ = dirent_type(iul.mode);
            }
            None => {
                entry.inode = 0;
                entry.type_ = 0;
            }
        }
        if entry.inode == 0 {
            let ino = match fd.mount() {
                Some(mount) if is_under_bind_mount(&entry_c) => ensure_inode(mount, &entry_c),
                _ => 0,
            };
            if ino == 0 {
                continue; // nothing describes it; skip rather than crash
            }
            entry.inode = ino;
        }
        return Ok(Some(*entry));
    }
}
