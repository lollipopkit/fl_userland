//! A host directory stream: an owned `DIR *`.
//!
//! realfs lists a directory through the host's `readdir`, and a guest
//! positions the listing with `telldir`/`seekdir` cookies -- so the stream is
//! state that lives as long as the guest's description. It was an
//! `AtomicPtr<DIR>` on `struct fd` until 2026-09-29, closed by hand in
//! `realfs_close`, with every `readdir`, `telldir` and `seekdir` an `unsafe`
//! call on the raw pointer. This type is the one place that holds it.
//!
//! **Why not `rustix::fs::Dir`.** It has no `telldir`, so the cookie a guest's
//! `lseek(SEEK_CUR)` answers with cannot be read from it; and after one
//! failed `readdir` it reports end-of-directory for ever, where this kernel
//! reports the error each time and lets the guest decide.
//!
//! **The lock.** `readdir` on one `DIR` is not safe from two threads, and a
//! `telldir`/`readdir`/`seekdir` sequence is one operation to a caller.
//! `sys_getdents64` holds the description's lock across a whole listing, which
//! covers the second; the `Mutex` here makes the first a property of the type
//! rather than of its callers.

use std::io;
use std::os::fd::{IntoRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::{Mutex, MutexGuard};

pub struct HostDir(Mutex<NonNull<libc::DIR>>);

// SAFETY: a `DIR` is not tied to the thread that opened it, and every use of
// the pointer is under the mutex.
unsafe impl Send for HostDir {}
// SAFETY: as above -- `&HostDir` reaches the pointer only through the mutex.
unsafe impl Sync for HostDir {}

/// One entry, borrowed from the stream until the next read.
pub struct Entry<'a> {
    pub ino: u64,
    /// The host's `DT_*`, which is Linux's numbering.
    pub kind: u8,
    pub name: &'a [u8],
}

impl HostDir {
    /// A stream over `fd`, which it takes over and closes with the stream.
    /// On failure `fd` is dropped, and so closed: `fdopendir` takes a
    /// descriptor over only when it succeeds.
    pub fn open(fd: OwnedFd) -> io::Result<Self> {
        use std::os::fd::AsRawFd;
        // SAFETY: `fd` is open.
        let dir = unsafe { libc::fdopendir(fd.as_raw_fd()) };
        let dir = NonNull::new(dir).ok_or_else(io::Error::last_os_error)?;
        let _owned_by_the_stream = fd.into_raw_fd();
        Ok(Self(Mutex::new(dir)))
    }

    fn lock(&self) -> MutexGuard<'_, NonNull<libc::DIR>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The next entry, handed to `f`; `Ok(None)` at the end.
    ///
    /// `readdir` reports both "end" and "error" as null and tells them apart
    /// by `errno`, which it does not otherwise set -- so `errno` is cleared
    /// first. The entry is only valid until the next call on the stream,
    /// which the lock held across `f` is what guarantees.
    pub fn read<R>(&self, f: impl FnOnce(Entry<'_>) -> R) -> io::Result<Option<R>> {
        let dir = self.lock();
        clear_errno();
        // SAFETY: the stream is open and the lock makes this the only call.
        let dirent = unsafe { libc::readdir(dir.as_ptr()) };
        if dirent.is_null() {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(0) | None => Ok(None),
                _ => Err(err),
            };
        }
        // SAFETY: `readdir` answered a valid entry, which stays valid until
        // the next call on this stream -- after `f` returns and the lock goes.
        let d = unsafe { &*dirent };
        let name = unsafe { std::ffi::CStr::from_ptr(d.d_name.as_ptr()) }.to_bytes();
        Ok(Some(f(Entry { ino: d.d_ino, kind: d.d_type, name })))
    }

    /// `telldir`: a cookie that only [`HostDir::seek`] means anything to.
    pub fn tell(&self) -> i64 {
        let dir = self.lock();
        // SAFETY: the stream is open, under the lock.
        unsafe { libc::telldir(dir.as_ptr()) }
    }

    /// `seekdir` to a cookie from [`HostDir::tell`].
    pub fn seek(&self, cookie: i64) {
        let dir = self.lock();
        // SAFETY: the stream is open, under the lock. A cookie that did not
        // come from `telldir` is the host's to interpret; it is not memory.
        unsafe { libc::seekdir(dir.as_ptr(), cookie as libc::c_long) };
    }
}

impl Drop for HostDir {
    fn drop(&mut self) {
        let dir = *self.0.get_mut().unwrap_or_else(|p| p.into_inner());
        // SAFETY: the stream is open and this is its only owner. `closedir`
        // closes the descriptor `open` was given as well.
        unsafe { libc::closedir(dir.as_ptr()) };
    }
}

fn clear_errno() {
    // SAFETY: `__error` answers this thread's errno slot.
    unsafe { *libc::__error() = 0 };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn dir_with(names: &[&str]) -> (std::path::PathBuf, HostDir) {
        let root = std::env::temp_dir().join(format!(
            "hostdir-{}-{}",
            std::process::id(),
            names.join("-")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        for n in names {
            fs::write(root.join(n), b"").unwrap();
        }
        let fd: OwnedFd = fs::File::open(&root).unwrap().into();
        (root.clone(), HostDir::open(fd).unwrap())
    }

    fn names(dir: &HostDir) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(n) = dir.read(|e| e.name.to_vec()).unwrap() {
            out.push(n);
        }
        out.sort();
        out
    }

    #[test]
    fn lists_every_entry_and_then_ends() {
        let (root, dir) = dir_with(&["a", "b"]);
        assert_eq!(names(&dir), [&b"."[..], b"..", b"a", b"b"]);
        assert!(dir.read(|_| ()).unwrap().is_none(), "end stays the end");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_cookie_seeks_back_to_where_it_was_taken() {
        let (root, dir) = dir_with(&["x", "y", "z"]);
        dir.read(|_| ()).unwrap();
        let here = dir.tell();
        let next = dir.read(|e| e.name.to_vec()).unwrap();
        dir.seek(here);
        assert_eq!(dir.read(|e| e.name.to_vec()).unwrap(), next);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_file_is_not_a_directory_and_its_descriptor_is_not_leaked() {
        let path = std::env::temp_dir().join(format!("hostdir-file-{}", std::process::id()));
        fs::write(&path, b"").unwrap();
        let fd: OwnedFd = fs::File::open(&path).unwrap().into();
        let err = HostDir::open(fd).err().expect("a file is not a directory");
        assert_eq!(err.raw_os_error(), Some(libc::ENOTDIR));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn dropping_it_closes_the_descriptor() {
        let (root, dir) = dir_with(&["q"]);
        let raw = {
            let d = dir.lock();
            // SAFETY: the stream is open.
            unsafe { libc::dirfd(d.as_ptr()) }
        };
        let ino = |fd| {
            let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: `st` is written on success and read only then.
            (unsafe { libc::fstat(fd, st.as_mut_ptr()) } == 0)
                .then(|| unsafe { st.assume_init() }.st_ino)
        };
        let ours = ino(raw).expect("open while the stream is");
        drop(dir);
        // Another test in this binary may have been handed the same number
        // since, so the question is whether it still names *this* directory.
        assert_ne!(ino(raw), Some(ours), "the stream's descriptor outlived it");
        fs::remove_dir_all(root).unwrap();
    }
}
