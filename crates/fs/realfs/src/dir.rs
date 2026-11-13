//! Reading a directory.
//!
//! A guest directory descriptor lists through a host directory stream opened
//! on a dup of the descriptor, kept in `fd.dir`. The dup is what the stream
//! closes; `real_fd` stays available for `fstat`, `getpath` and the rest,
//! which is why the two are not the same descriptor.

use std::os::fd::AsRawFd;
use std::os::raw::{c_int, c_ulong};

use crate::errno::{self, ck};
use crate::ffi;

/// The descriptor's stream, made on first use.
///
/// Two threads can reach this together, and the install is `OnceLock::set`:
/// the loser's stream is dropped, which closes it and the dup inside it. As a
/// plain test-and-store this leaked a `DIR *` -- and the host descriptor
/// inside it -- every time: 1990 collisions in 2000 rounds, measured on
/// 2026-09-14, and under a 256-descriptor limit, which is the order of what an
/// app gets, four hundred rounds left the emulator unable to list anything at
/// all.
///
/// `sys_getdents64` holds `fd->lock` across the whole listing, so today the
/// losing branch cannot be reached. The lock is there for a different
/// property -- the `telldir`/`readdir`/`seekdir` sequence is one operation --
/// and it is the *caller's*, so a future caller can forget it. See
/// `crates/fs/dircalls` for the other half.
fn stream(fd: &ffi::fd) -> Option<&ffi::HostDir> {
    if let Some(dir) = fd.dir.get() {
        return Some(dir);
    }
    let dup = rustix::io::dup(fd.host()?).ok()?;
    let _ = fd.dir.set(Box::new(ffi::HostDir::open(dup).ok()?));
    fd.dir.get().map(|d| &**d)
}

pub(crate) fn realfs_readdir(fd: &ffi::fd) -> Result<Option<ffi::dir_entry>, c_int> {
    let dir = stream(fd).ok_or(errno::EIO)?;
    loop {
        let next = dir.read(|e| {
            let mut entry = ffi::dir_entry::default();
            // Darwin filenames can be up to 255 UTF-16 units, which in UTF-8
            // may be more than Linux's NAME_MAX of 255 bytes. There is nowhere
            // to put one -- dir_entry's name field is NAME_MAX + 1 -- and the
            // guest is better off walking past it than being handed a
            // truncated name that resolves to nothing. `set_name` answers
            // false for exactly that, so the two conditions are one.
            if e.name.len() > ffi::NAME_MAX as usize || !entry.set_name(e.name) {
                return None;
            }
            entry.inode = e.ino;
            // The host's d_type is the same DT_* numbering Linux uses, so it
            // passes through. Darwin reports DT_UNKNOWN for some filesystems,
            // which is the value the guest should see in that case anyway.
            entry.type_ = e.kind;
            Some(entry)
        });
        match next {
            Ok(None) => return Ok(None),
            Ok(Some(Some(entry))) => return Ok(Some(entry)),
            Ok(Some(None)) => continue,
            Err(e) => return Err(errno::io_err(e)),
        }
    }
}

pub(crate) fn realfs_telldir(fd: &ffi::fd) -> c_ulong {
    stream(fd).map_or(0, |dir| dir.tell() as c_ulong)
}

pub(crate) fn realfs_seekdir(fd: &ffi::fd, ptr: c_ulong) {
    if let Some(dir) = stream(fd) {
        dir.seek(ptr as i64);
    }
}


/// # Safety
/// Called by the VFS with a live descriptor.
pub unsafe fn realfs_lseek(fd: &ffi::fd, offset: i64, whence: c_int) -> i64 {
    unsafe {
        // A directory that has been read from is positioned by seekdir, whose
        // cookies are the only thing telldir's results mean anything to -- so
        // every whence has to be answered in those terms, not in the host
        // descriptor's bytes.
        //
        // `SEEK_CUR` used to fall through to the host, which for a directory
        // opened with `opendir` answers a byte offset into the host's own
        // buffer: `lseek(dirfd, 0, SEEK_CUR)` gave a number that `SEEK_SET`
        // could not seek back to, so the `telldir`/`seekdir` pair a caller
        // builds out of the two syscalls did not round-trip. `dir_probe`
        // measured it.
        //
        // A negative `SEEK_SET` used to be passed to `seekdir` and *returned*,
        // and -1 as an offset is EPERM to a caller. Linux answers EINVAL.
        if fd.dir.get().is_some() {
            match whence as u32 {
                ffi::LSEEK_SET => {
                    if offset < 0 {
                        return errno::EINVAL as i64;
                    }
                    realfs_seekdir(fd, offset as c_ulong);
                    return offset;
                }
                ffi::LSEEK_CUR => {
                    let here = realfs_telldir(fd) as i64;
                    let Some(new) = here.checked_add(offset) else {
                        return errno::EINVAL as i64;
                    };
                    if new < 0 {
                        return errno::EINVAL as i64;
                    }
                    if offset != 0 {
                        realfs_seekdir(fd, new as c_ulong);
                    }
                    return new;
                }
                // SEEK_END and the two data/hole whences are the host's, which
                // for a directory answers what the host filesystem thinks. A
                // caller that seeks a directory to its end is not asking a
                // question with a portable answer.
                _ => {}
            }
        }
        // The guest's numbering, not the host's. `SEEK_DATA` and `SEEK_HOLE`
        // are **swapped** between Linux and Darwin -- 3 and 4 against 4 and 3
        // -- so passing the guest's number through would answer the opposite
        // question, reporting a hole where the data is. Nothing about the
        // types would object; the values are both small integers.
        let host = match whence as u32 {
            ffi::LSEEK_SET => libc::SEEK_SET,
            ffi::LSEEK_CUR => libc::SEEK_CUR,
            ffi::LSEEK_END => libc::SEEK_END,
            // `libc`'s, which are Darwin's on every Apple target. They were two
            // constants written out under `cfg(target_os = "macos")`, with the
            // Linux numbers for "not macOS" -- which is iOS, so on the product
            // the two were swapped again.
            ffi::LSEEK_DATA => libc::SEEK_DATA,
            ffi::LSEEK_HOLE => libc::SEEK_HOLE,
            _ => return errno::EINVAL as i64,
        };
        // `libc`'s rather than `rustix::fs::seek`: `SeekFrom` takes the offset
        // unsigned for three of the five, and what the host answers for a
        // negative one is part of what `seek_probe` records.
        let Some(real) = fd.host() else {
            return errno::EBADF as i64;
        };
        match ck(libc::lseek(real.as_raw_fd(), offset, host)) {
            Ok(pos) => pos,
            Err(e) => e as i64,
        }
    }
}
