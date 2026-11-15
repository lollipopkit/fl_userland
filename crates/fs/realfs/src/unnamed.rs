//! `O_TMPFILE` on a host directory: an unnamed regular file, and `linkat`
//! naming it.
//!
//! The file is made under a name nobody can guess and unlinked at once, so it
//! is truly anonymous on the host: it is in no listing, and a crash leaves
//! nothing behind. Darwin has no `flink` -- a descriptor cannot be given a
//! name -- so naming one is a copy: `fclonefileat` (APFS, copy-on-write, so
//! no data moves), or a plain copy where that is refused, opened again with
//! the description's flags and position and `dup2`'d onto the host
//! descriptor the guest's description holds. Every later read and write
//! through that description reaches the named file.
//!
//! What is lost, said plainly: the copy is a new host inode, so a shared
//! mapping made before the `linkat` stays on the unnamed one. fakefs, which
//! every guest root is, keeps the file under a hidden name instead and links
//! it, which is exact (`crates/fs/fake`'s `unnamed`).

use std::ffi::{CStr, CString, c_int};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{REALFS_FDOPS, at_path, ffi, flags, root};
use guest_errno::Errno;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn rx_err(e: rustix::io::Errno) -> c_int {
    kernel_errno::raised(e.raw_os_error())
}

/// `FsOps::tmpfile` for realfs.
pub fn realfs_tmpfile(mount: &ffi::mount, dir: &CStr, flags: c_int, mode: c_int) -> Result<Box<ffi::fd>, Errno> {
    let root = root(mount).map_err(Errno::from_negative_or_eio)?;
    let host_flags = flags::to_host(flags as u32) | libc::O_CREAT | libc::O_EXCL;
    let base = at_path(dir).to_bytes().to_vec();
    for _ in 0..16 {
        let mut name = base.clone();
        name.extend_from_slice(
            format!("/.iul-tmpfile-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)).as_bytes(),
        );
        let Ok(name) = CString::new(name) else {
            return Err(Errno::EINVAL);
        };
        let opened = rustix::fs::openat(
            root,
            name.as_c_str(),
            rustix::fs::OFlags::from_bits_retain(host_flags as _),
            rustix::fs::Mode::from_raw_mode(mode as libc::mode_t),
        );
        match opened {
            Err(rustix::io::Errno::EXIST) => continue,
            Err(e) => return Err(Errno::from_negative_or_eio(rx_err(e))),
            Ok(host) => {
                crate::meta::stamp_new_fd(host.as_fd());
                // A write-only description cannot be read to be copied when
                // it is named, and once the name is gone nothing can open
                // the file again: a reader is taken now.
                let source = (flags as u32 & ffi::O_ACCMODE_ == ffi::O_WRONLY_)
                    .then(|| rustix::fs::openat(root, name.as_c_str(), rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty()).ok())
                    .flatten();
                let _ = rustix::fs::unlinkat(root, name.as_c_str(), rustix::fs::AtFlags::empty());
                let mut fd = Box::new(ffi::fd::default());
                fd.ops = Some(&REALFS_FDOPS);
                fd.real_fd = Some(host);
                fd.unnamed = Some(Box::new(ffi::Unnamed { source, ..Default::default() }));
                return Ok(fd);
            }
        }
    }
    Err(Errno::EEXIST)
}

/// `FsOps::link_unnamed` for realfs: see the module comment.
pub fn realfs_link_unnamed(fd: &ffi::fd, mount: &ffi::mount, dst: &CStr) -> c_int {
    let (Ok(root), Some(host)) = (root(mount), fd.host()) else {
        return guest_errno::c_int_::EBADF;
    };
    let dst = at_path(dst);
    let st = match rustix::fs::fstat(host) {
        Ok(st) => st,
        Err(e) => return rx_err(e),
    };
    // Named once already: the name is a path, and this is a link.
    if st.st_nlink > 0 {
        return match rustix::fs::getpath(host) {
            Ok(path) => match rustix::fs::linkat(rustix::fs::CWD, path.as_c_str(), root, dst, rustix::fs::AtFlags::empty()) {
                Ok(()) => 0,
                Err(e) => rx_err(e),
            },
            Err(e) => rx_err(e),
        };
    }
    let reader = fd.unnamed.as_ref().and_then(|u| u.source.as_ref()).map_or(host, |s| s.as_fd());
    if let Err(e) = clone_or_copy(reader, root, dst, st.st_mode as libc::mode_t & 0o7777) {
        return e;
    }
    // Reopened as the description is -- its access mode and status flags --
    // at its position, then put where the description's host descriptor is.
    let status = match rustix::fs::fcntl_getfl(host) {
        Ok(f) => f.bits() as c_int,
        Err(e) => return rx_err(e),
    };
    let reopen = status & (libc::O_ACCMODE | libc::O_APPEND | libc::O_NONBLOCK);
    let named = match rustix::fs::openat(root, dst, rustix::fs::OFlags::from_bits_retain(reopen as _), rustix::fs::Mode::empty()) {
        Ok(f) => f,
        Err(e) => return rx_err(e),
    };
    let at = rustix::fs::seek(host, rustix::fs::SeekFrom::Current(0)).unwrap_or(0);
    let _ = rustix::fs::seek(&named, rustix::fs::SeekFrom::Start(at));
    // SAFETY: both descriptors are open; `dup2` replaces what the
    // description's number refers to in one step, and `named` is closed by
    // its drop.
    if unsafe { libc::dup2(named.as_raw_fd(), host.as_raw_fd()) } < 0 {
        return kernel_errno::errno_map();
    }
    0
}

/// `dst` as a copy of the file `src` is open on: a clone where the volume
/// can, the bytes otherwise.
fn clone_or_copy(src: std::os::fd::BorrowedFd<'_>, root: std::os::fd::BorrowedFd<'_>, dst: &CStr, mode: libc::mode_t) -> Result<(), c_int> {
    // SAFETY: valid descriptors and a NUL-terminated name.
    if unsafe { libc::fclonefileat(src.as_raw_fd(), root.as_raw_fd(), dst.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if e != libc::ENOTSUP && e != libc::EXDEV {
        return Err(kernel_errno::raised(e));
    }
    let out = rustix::fs::openat(
        root,
        dst,
        rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL | rustix::fs::OFlags::WRONLY,
        rustix::fs::Mode::from_raw_mode(mode),
    )
    .map_err(rx_err)?;
    let mut buf = vec![0u8; 1 << 16];
    let mut off = 0u64;
    loop {
        let n = rustix::io::pread(src, &mut buf, off).map_err(rx_err)?;
        if n == 0 {
            return Ok(());
        }
        let mut done = 0;
        while done < n {
            done += rustix::io::pwrite(out.as_fd(), &buf[done..n], off + done as u64).map_err(rx_err)?;
        }
        off += n as u64;
    }
}
