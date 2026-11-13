//! File-operation callbacks for memfd descriptors.

use std::ffi::c_int;
use std::sync::atomic::Ordering;

use taskview::ffi;

use super::rules::{chmod_refused, mapping_counts, mmap_refused, truncate_refused, write_refused};
use guest_errno::c_int_::{EIO, ENOENT, EPERM};
use guest_errno::{Errno, isize_};

use super::{seal, size_of, state};

/// `fstat`: the host file's, with the owner this memfd records.
pub(super) fn memfd_fstat(fd: &ffi::fd) -> Result<ffi::statbuf, c_int> {
    let mut out = realfs::realfs_fstat(fd)?;
    if let Some(m) = state(fd) {
        out.uid = m.uid.load(Ordering::Relaxed);
        out.gid = m.gid.load(Ordering::Relaxed);
    }
    Ok(out)
}

pub(super) fn mode_of(fd: &ffi::fd) -> Result<u32, Errno> {
    Ok((super::host_stat(fd)?.st_mode & 0o7777) as u32)
}

pub(super) fn memfd_write(fd: &ffi::fd, buf: &[u8]) -> isize {
    let len = buf.len();
    if let Some(m) = state(fd) {
        let seals = m.seals.load(Ordering::Acquire);
        if seals & (seal::WRITE | seal::FUTURE_WRITE | seal::GROW) != 0 {
            // The position a plain write lands at: the descriptor's, or the
            // end under O_APPEND.
            let (pos, size) = match (position_of(fd), size_of(fd)) {
                (Ok(p), Ok(s)) => (p, s),
                _ => return isize_::EIO,
            };
            let pos = if fd.flags() & ffi::O_APPEND_ != 0 {
                size
            } else {
                pos
            };
            if write_refused(seals, pos, len, size) {
                return isize_::EPERM;
            }
        }
    }
    realfs::realfs_write_bytes(fd, buf)
}

pub(super) fn memfd_pwrite(fd: &ffi::fd, buf: &[u8], off: i64) -> isize {
    let len = buf.len();
    if let Some(m) = state(fd) {
        let seals = m.seals.load(Ordering::Acquire);
        if seals & (seal::WRITE | seal::FUTURE_WRITE | seal::GROW) != 0 {
            let Ok(size) = size_of(fd) else {
                return isize_::EIO;
            };
            if write_refused(seals, off, len, size) {
                return isize_::EPERM;
            }
        }
    }
    realfs::realfs_pwrite(fd, buf, off)
}

fn position_of(fd: &ffi::fd) -> Result<i64, Errno> {
    let host = fd.host().ok_or(Errno::EIO)?;
    let pos = rustix::fs::seek(host, rustix::fs::SeekFrom::Current(0)).map_err(|_| Errno::EIO)?;
    Ok(pos as i64)
}

pub(super) unsafe fn memfd_mmap(fd: &ffi::fd,
    mem: *mut ffi::mem,
    start: ffi::page_t,
    pages: ffi::pages_t,
    offset: i64,
    prot: c_int,
    flags: c_int,
) -> c_int {
    let Some(m) = state(fd) else {
        return unsafe { realfs::map::realfs_mmap(fd, mem, start, pages, offset, prot, flags) };
    };
    let shared = flags as u32 & ffi::MMAP_SHARED != 0;
    let writable = prot as u32 & ffi::P_WRITE != 0;
    let seals = m.seals.load(Ordering::Acquire);
    if mmap_refused(seals, shared, writable) {
        return EPERM;
    }
    let err = unsafe { realfs::map::realfs_mmap(fd, mem, start, pages, offset, prot, flags) };
    if err >= 0 && mapping_counts(seals, shared) {
        m.shared_maps.fetch_add(1, Ordering::AcqRel);
    }
    err
}

pub(super) fn memfd_fsetattr(fd: &ffi::fd, attr: ffi::Attr) -> c_int {
    let Some(m) = state(fd) else {
        return realfs::realfs_fsetattr(fd, attr);
    };
    let seals = m.seals.load(Ordering::Acquire);
    match attr {
        ffi::Attr::Size(size) => {
            let Ok(now) = size_of(fd) else {
                return EIO;
            };
            if truncate_refused(seals, size, now) {
                return EPERM;
            }
        }
        ffi::Attr::Mode(mode) => {
            let Ok(old) = mode_of(fd) else {
                return EIO;
            };
            if chmod_refused(seals, old, u32::from(mode)) {
                return EPERM;
            }
        }
        // The owner is this crate's, not the host file's.
        ffi::Attr::Uid(uid) => {
            m.uid.store(uid, Ordering::Relaxed);
            return 0;
        }
        ffi::Attr::Gid(gid) => {
            m.gid.store(gid, Ordering::Relaxed);
            return 0;
        }
    }
    realfs::realfs_fsetattr(fd, attr)
}

pub(super) fn memfd_close(fd: &mut ffi::fd) -> c_int {
    // The `Memfd` goes with the description.
    realfs::realfs_close(fd)
}

/// `/memfd:<name> (deleted)`, which is what Linux's `/proc/<pid>/fd` says, or
/// the kernel file's own name in its place.
pub(super) fn memfd_getpath(fd: &ffi::fd, buf: &mut [u8]) -> c_int {
    let Some(m) = state(fd) else {
        return ENOENT;
    };
    let mut path = Vec::with_capacity(m.path.len() + 10);
    path.extend_from_slice(&m.path);
    path.extend_from_slice(b" (deleted)");
    ffi::fill_path(buf, &path)
}
