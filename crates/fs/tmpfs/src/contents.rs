//! A regular file's bytes, and where they move when the file is mapped.
//!
//! A file is a `Vec<u8>` in this process until something `mmap`s it. Mapping
//! needs host pages that every guest process -- all threads of this one host
//! process -- reaches as one set, that a `read` and a `write` on the file see,
//! and that a truncation cuts off: a host file mapped shared, which is what a
//! memfd already is (`crates/kernel/memfdcalls`). So the first `mmap` copies
//! the bytes into an unlinked host file, and the file stays there: from then
//! on a read is a `pread` and a write a `pwrite`, which a mapping of the same
//! host file sees at once. A file nothing maps pays nothing for this but the
//! one branch on which of the two it is.
//!
//! It never moves back. A mapping can outlive every descriptor of the file and
//! comes back through no call this filesystem sees, so there is no point at
//! which the host file is known to be unneeded short of the inode going.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use crate::errno::{EINVAL, ENOMEM, Result};
use crate::tree::{Body, Inode, account_bytes};

/// Where a regular file's bytes are. Also a symlink's target, which is
/// always [`Contents::Mem`].
#[derive(Debug, PartialEq, Eq)]
pub enum Contents {
    /// In this process.
    Mem(Vec<u8>),
    /// In the inode's host file, which is this many bytes long.
    Host(u64),
}

impl Default for Contents {
    fn default() -> Self {
        Contents::Mem(Vec::new())
    }
}

impl From<Vec<u8>> for Contents {
    fn from(bytes: Vec<u8>) -> Self {
        Contents::Mem(bytes)
    }
}

impl Contents {
    pub fn len(&self) -> u64 {
        match self {
            Contents::Mem(bytes) => bytes.len() as u64,
            Contents::Host(len) => *len,
        }
    }

    /// The bytes, while they are in this process.
    pub fn in_memory(&self) -> Option<&[u8]> {
        match self {
            Contents::Mem(bytes) => Some(bytes),
            Contents::Host(_) => None,
        }
    }
}

/// A host error as the guest's errno. A host file in the temp directory fails
/// for want of space or of memory, which are `ENOSPC` and `ENOMEM` from a
/// tmpfs on Linux too.
fn host_errno(e: rustix::io::Errno) -> i32 {
    if e == rustix::io::Errno::NOSPC { guest_errno::c_int_::ENOSPC } else { ENOMEM }
}

impl Inode {
    /// The host file mapping this inode shows, made on the first call.
    pub(crate) fn host_file(&self) -> Result<BorrowedFd<'_>> {
        let mut body = self.lock();
        if let Some(host) = self.host.get() {
            return Ok(host.as_fd());
        }
        let host: OwnedFd = realfs::unlinked_host_file(0o600).map_err(|_| ENOMEM)?;
        let len = match &body.data {
            Contents::Mem(bytes) => {
                pwrite_all(host.as_fd(), bytes, 0)?;
                bytes.len() as u64
            }
            Contents::Host(_) => unreachable!("contents are in a host file only once there is one"),
        };
        // Set once, here, under the body lock, which every write of the
        // contents holds too: nothing can land in the `Vec` after the copy.
        let host = self.host.get_or_init(|| host);
        body.data = Contents::Host(len);
        Ok(host.as_fd())
    }

    /// The host file, if the contents have moved there. Lock-free: set once.
    pub(crate) fn host(&self) -> Option<BorrowedFd<'_>> {
        self.host.get().map(AsFd::as_fd)
    }

    /// Up to `buf.len()` bytes from `at`, short at the end of the file.
    pub(crate) fn read_at(&self, body: &Body, at: u64, buf: &mut [u8]) -> Result<usize> {
        let n = buf.len().min(body.data.len().saturating_sub(at) as usize);
        if n == 0 {
            return Ok(0);
        }
        match &body.data {
            Contents::Mem(bytes) => {
                let at = at as usize;
                buf[..n].copy_from_slice(&bytes[at..at + n]);
                Ok(n)
            }
            Contents::Host(_) => {
                let host = self.host().expect("a host length has a host file");
                let mut done = 0;
                while done < n {
                    match rustix::io::pread(host, &mut buf[done..n], at + done as u64) {
                        Ok(0) => break,
                        Ok(k) => done += k,
                        Err(rustix::io::Errno::INTR) => {}
                        Err(e) => return Err(host_errno(e)),
                    }
                }
                Ok(done)
            }
        }
    }

    /// Write all of `buf` at `at`, zero-filling a gap past the end.
    pub(crate) fn write_at(&self, body: &mut Body, at: usize, buf: &[u8]) -> Result<()> {
        let end = at.checked_add(buf.len()).ok_or(EINVAL)?;
        // A write of nothing past the end does not move it.
        if buf.is_empty() {
            return Ok(());
        }
        match &mut body.data {
            Contents::Mem(bytes) => {
                if end > bytes.len() {
                    // try_reserve so a huge offset fails the write instead of
                    // aborting the process.
                    bytes.try_reserve(end - bytes.len()).map_err(|_| ENOMEM)?;
                    account_bytes(bytes.len(), end);
                    bytes.resize(end, 0);
                }
                // The range was ensured to exist above; both sides are
                // slices, so the copy is the one that cannot disagree about
                // its length.
                bytes[at..end].copy_from_slice(buf);
            }
            Contents::Host(len) => {
                let host = self.host.get().expect("a host length has a host file");
                pwrite_all(host.as_fd(), buf, at as u64)?;
                if end as u64 > *len {
                    account_bytes(*len as usize, end);
                    *len = end as u64;
                }
            }
        }
        Ok(())
    }

    /// `truncate(2)`: growing zero-fills, shrinking discards. A host file's
    /// shrink reaches its mappings through realfs's `host_ftruncate`, which
    /// raises `SIGBUS` for the pages it cut off.
    pub(crate) fn set_size(&self, body: &mut Body, size: u64) -> Result<()> {
        match &mut body.data {
            Contents::Mem(bytes) => {
                let size = usize::try_from(size).map_err(|_| EINVAL)?;
                if size > bytes.len() {
                    bytes.try_reserve(size - bytes.len()).map_err(|_| ENOMEM)?;
                }
                account_bytes(bytes.len(), size);
                bytes.resize(size, 0);
            }
            Contents::Host(len) => {
                let host = self.host.get().expect("a host length has a host file");
                realfs::host_ftruncate(host.as_fd(), size)?;
                account_bytes(*len as usize, size as usize);
                *len = size;
            }
        }
        Ok(())
    }
}

fn pwrite_all(host: BorrowedFd<'_>, mut buf: &[u8], mut at: u64) -> Result<()> {
    while !buf.is_empty() {
        match rustix::io::pwrite(host, buf, at) {
            Ok(n) => {
                buf = &buf[n..];
                at += n as u64;
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(host_errno(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::S_IFREG;
    use std::os::fd::AsRawFd;

    fn file(bytes: &[u8]) -> std::sync::Arc<Inode> {
        let inode = Inode::new(S_IFREG | 0o644, 0, 0, 0);
        inode.lock().data = bytes.to_vec().into();
        inode
    }

    fn read_all(inode: &Inode) -> Vec<u8> {
        let body = inode.lock();
        let mut buf = vec![0; body.size() as usize + 8];
        let n = inode.read_at(&body, 0, &mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    #[test]
    fn mapping_moves_the_bytes_to_a_host_file_once() {
        let inode = file(b"hello");
        let first = inode.host_file().unwrap().as_raw_fd();
        assert_eq!(inode.lock().data, Contents::Host(5));
        assert_eq!(inode.host_file().unwrap().as_raw_fd(), first);
        assert_eq!(read_all(&inode), b"hello");
    }

    #[test]
    fn a_moved_file_reads_writes_and_truncates_through_the_host_file() {
        let inode = file(b"hello");
        let host = inode.host_file().unwrap();
        let mut body = inode.lock();
        inode.write_at(&mut body, 7, b"!").unwrap();
        assert_eq!(body.size(), 8);
        drop(body);
        assert_eq!(read_all(&inode), b"hello\0\0!");
        assert_eq!(rustix::fs::fstat(host).unwrap().st_size, 8);
        let mut body = inode.lock();
        inode.set_size(&mut body, 2).unwrap();
        drop(body);
        assert_eq!(read_all(&inode), b"he");
        assert_eq!(rustix::fs::fstat(host).unwrap().st_size, 2);
    }

    #[test]
    fn writing_nothing_past_the_end_does_not_move_it() {
        for map in [false, true] {
            let inode = file(b"ab");
            if map {
                inode.host_file().unwrap();
            }
            let mut body = inode.lock();
            inode.write_at(&mut body, 100, b"").unwrap();
            assert_eq!(body.size(), 2, "mapped: {map}");
        }
    }

}
