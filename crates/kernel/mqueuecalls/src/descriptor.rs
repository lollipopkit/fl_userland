//! The descriptor `mq_open` hands out, and the filesystem it lives on.
//!
//! What a guest can do with one besides the `mq_*` calls, every answer
//! measured by `mqueue_probe`:
//!
//! - `read`/`pread` give the status line, at the descriptor's position:
//!   Linux formats it and serves it with `simple_read_from_buffer`, so a
//!   second `read` is 0 and an `lseek` back starts it again. `EBADF` without
//!   read access, which access mode 3 does not have.
//! - `write` has no method: `EINVAL` when open for writing, `EBADF` when not.
//! - `lseek` is `default_llseek` against the inode's size, which is
//!   `FILENT_SIZE` until a `ftruncate` changes it -- and nothing else reads
//!   it, so a truncated queue reads its status line as before.
//! - `poll` is readable with a message queued and writable with room, for
//!   every access mode alike.
//! - `fsync` is `EINVAL`, `mmap` `ENODEV`, `FIONREAD` the size less the
//!   position (negative after a truncate, as on Linux).

use std::ffi::{CStr, c_int};
use std::sync::{Arc, LazyLock};

use guest_errno::c_int_::{EACCES, EBADF, EINVAL, ENXIO, EPERM};
use kernel_mqueue::abi;

use crate::{Mq, O_ACCMODE, O_RDWR, O_WRONLY, S_IFREG, deliver, ffi, may, wanted};

/// A description's driver state: the queue it is open on.
pub(crate) struct Desc {
    pub(crate) mq: Arc<Mq>,
}

fn state(fd: &ffi::fd) -> Option<&Desc> {
    fd.driver_state::<Desc>()
}

/// A description open on `mq` with `flags`, not yet installed.
pub(crate) fn describe(mq: Arc<Mq>, flags: u32) -> fs_fdobj::Owned {
    let mut fd = fs_fdobj::NewFd::new(Some(&MQUEUE_FDOPS));
    fd.set_mount(MQUEUE_MOUNT.retain());
    let inode = mq.queue.lock().inode;
    fd.type_ = S_IFREG as _;
    fd.stat.inode = inode.ino;
    fd.stat.mode = inode.mode;
    fd.stat.uid = inode.uid;
    fd.stat.gid = inode.gid;
    fd.set_flags(flags);
    mq.queue.watch(&fd.poll_watchers);
    fd.set_driver_state(Box::new(Desc { mq }));
    fd.into_owned()
}

// ------------------------------------------------------------ the driver

struct MqueueOps;

static MQUEUE_FDOPS: MqueueOps = MqueueOps;

impl ffi::FdOps for MqueueOps {
    /// A positional read and a position: `read(2)` goes through `pread` at
    /// the descriptor's offset and advances it.
    fn caps(&self) -> ffi::Caps {
        ffi::Caps { read_at: true, seek: true, ..ffi::Caps::NONE }
    }

    fn pread(&self, fd: &ffi::fd, buf: &mut [u8], off: i64) -> isize {
        let Some(d) = state(fd) else {
            return EBADF as isize;
        };
        if !crate::readable(fd) {
            return EBADF as isize;
        }
        if off < 0 {
            return EINVAL as isize;
        }
        let line = {
            let s = d.mq.queue.lock();
            abi::status_line(s.msgs.bytes(), s.notify_fields())
        };
        let line = line.as_bytes();
        let from = (off as u64).min(line.len() as u64) as usize;
        let n = buf.len().min(line.len() - from);
        buf[..n].copy_from_slice(&line[from..from + n]);
        n as isize
    }

    /// `default_llseek`: `SEEK_END`, `SEEK_DATA` and `SEEK_HOLE` against the
    /// inode's size, nothing past a negative.
    fn lseek(&self, fd: &ffi::fd, off: i64, whence: c_int) -> i64 {
        let Some(d) = state(fd) else {
            return EBADF as i64;
        };
        let size = d.mq.queue.lock().inode.size;
        let to = match whence as u32 {
            ffi::LSEEK_SET => Some(off),
            ffi::LSEEK_CUR => fd.offset().checked_add(off),
            ffi::LSEEK_END => size.checked_add(off),
            ffi::LSEEK_DATA if off >= size => return ENXIO as i64,
            ffi::LSEEK_DATA => Some(off),
            ffi::LSEEK_HOLE if off >= size => return ENXIO as i64,
            ffi::LSEEK_HOLE => Some(size),
            _ => return EINVAL as i64,
        };
        match to {
            Some(to) if to >= 0 => {
                fd.set_offset(to);
                to
            }
            _ => EINVAL as i64,
        }
    }

    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(state(fd).map_or(0, |d| d.mq.queue.poll() as c_int))
    }

    /// A regular file that `epoll` can wait on.
    fn regular_file_polls(&self) -> bool {
        true
    }

    fn ioctl_size(&self, cmd: c_int) -> isize {
        if cmd as u32 == ffi::FIONREAD_ { 4 } else { -1 }
    }

    /// `FIONREAD` on a regular file: `i_size - f_pos`, as an `int`.
    fn ioctl(&self, fd: &ffi::fd, _cmd: c_int, arg: ffi::IoctlArg<'_>) -> c_int {
        let (Some(d), ffi::IoctlArg::Buf(out)) = (state(fd), arg) else {
            return EINVAL;
        };
        let left = d.mq.queue.lock().inode.size.wrapping_sub(fd.offset()) as i32;
        out.copy_from_slice(&left.to_le_bytes());
        0
    }

    /// No `fsync` method: `EINVAL`.
    fn fsync(&self, _fd: &ffi::fd) -> c_int {
        EINVAL
    }

    /// `mqueue_flush_file`: the caller's registration goes with any close of
    /// any of its descriptors of this queue.
    fn flush(&self, fd: &ffi::fd) {
        if let Some(d) = state(fd)
            && let Some(removed) = d.mq.queue.unregister(taskview::current_tgid(), None)
        {
            deliver::deliver(removed);
        }
    }

    fn close(&self, fd: &mut ffi::fd) -> c_int {
        drop(fd.take_driver_state::<Desc>());
        0
    }

    /// `open("/proc/<pid>/fd/<n>")`: Linux follows the link to the queue and
    /// opens it again, checking the mode as `mq_open` would.
    fn reopen(&self, fd: &ffi::fd, flags: c_int) -> Result<ffi::FdOwned, c_int> {
        let d = state(fd).ok_or(EBADF)?;
        let want = wanted(flags as u32).ok_or(EINVAL)?;
        let inode = d.mq.queue.lock().inode;
        may(&inode, want).map_err(|e| e.as_c_int())?;
        Ok(describe(Arc::clone(&d.mq), fs_fdobj::status::at_open(flags as u32)))
    }
}

// -------------------------------------------------------- the filesystem

/// The queues' filesystem: the inode attributes and the name.
struct MqueueFs;

static MQUEUE_FS: MqueueFs = MqueueFs;

/// Leaked for the life of the process, as `crates/fs/adhoc`'s three are.
static MQUEUE_MOUNT: LazyLock<fs_mounttable::DetachedMount> =
    LazyLock::new(|| fs_mounttable::DetachedMount::leak(&MQUEUE_FS, fs_mounttable::next_mount_id()));

impl ffi::FsOps for MqueueFs {
    /// None: not mountable, and not in `/proc/filesystems`. See the crate
    /// comment.
    fn name(&self) -> Option<&'static CStr> {
        None
    }

    fn magic(&self) -> u32 {
        abi::MQUEUE_MAGIC
    }

    fn fstat(&self, fd: &ffi::fd) -> Option<Result<ffi::statbuf, c_int>> {
        let d = state(fd)?;
        let i = d.mq.queue.lock().inode;
        Some(Ok(ffi::statbuf {
            inode: i.ino,
            mode: i.mode,
            nlink: u32::from(i.linked),
            uid: i.uid,
            gid: i.gid,
            size: i.size as u64,
            blksize: 4096,
            atime: i.atime.0,
            atime_nsec: i.atime.1 as u32,
            mtime: i.mtime.0,
            mtime_nsec: i.mtime.1 as u32,
            ctime: i.ctime.0,
            ctime_nsec: i.ctime.1 as u32,
            ..ffi::statbuf::default()
        }))
    }

    /// `fchmod`, `fchown` and `ftruncate`, on the queue rather than on the
    /// description: the permission check before this is `crates/kernel/fdattr`'s.
    fn fsetattr(&self, fd: &ffi::fd, attr: ffi::Attr) -> c_int {
        let Some(d) = state(fd) else {
            return EBADF;
        };
        let (sec, nsec) = crate::now();
        let mut s = d.mq.queue.lock();
        match attr {
            ffi::Attr::Mode(mode) => s.inode.mode = S_IFREG | (u32::from(mode) & 0o7777),
            ffi::Attr::Uid(uid) => s.inode.uid = uid,
            ffi::Attr::Gid(gid) => s.inode.gid = gid,
            // `do_sys_ftruncate` wants the description open for writing, and
            // answers `EINVAL` rather than `EBADF` without it.
            ffi::Attr::Size(size) => {
                if size < 0 || !matches!(fd.flags() & O_ACCMODE, O_WRONLY | O_RDWR) {
                    return EINVAL;
                }
                s.inode.size = size;
                s.inode.mtime = (sec, nsec);
            }
        }
        s.inode.ctime = (sec, nsec);
        0
    }

    /// `futimens`, on the queue. The descriptor's path is `/<name>`, which the
    /// walk would find on the root filesystem, so this must not go that way.
    ///
    /// Linux's rule: the owner or `CAP_FOWNER` sets any time; anyone else may
    /// only touch both to now, and only with write permission (`EACCES`
    /// without it, `EPERM` for an explicit time).
    fn futime(
        &self,
        fd: &ffi::fd,
        atime: Option<ffi::timespec>,
        mtime: Option<ffi::timespec>,
        touch: bool,
    ) -> Option<c_int> {
        let d = state(fd)?;
        let mut s = d.mq.queue.lock();
        let i = s.inode;
        let (owner, may_write) = taskview::with_current_creds(|c| {
            (c.owner_or_capable(i.uid), c.access(i.uid, i.gid, i.mode, 2).is_ok())
        })
        .unwrap_or((false, false));
        if !owner && !touch {
            return Some(EPERM);
        }
        if !owner && !may_write {
            return Some(EACCES);
        }
        if let Some(t) = atime {
            s.inode.atime = (t.tv_sec, t.tv_nsec);
        }
        if let Some(t) = mtime {
            s.inode.mtime = (t.tv_sec, t.tv_nsec);
        }
        s.inode.ctime = crate::now();
        Some(0)
    }

    /// `/<name>`, and ` (deleted)` after it once the name is gone, as
    /// `d_path` writes it.
    fn getpath(&self, fd: &ffi::fd, buf: &mut [u8]) -> c_int {
        let Some(d) = state(fd) else {
            return EBADF;
        };
        let linked = d.mq.queue.lock().inode.linked;
        let mut path = Vec::with_capacity(d.mq.name.len() + 11);
        path.push(b'/');
        path.extend_from_slice(&d.mq.name);
        if !linked {
            path.extend_from_slice(b" (deleted)");
        }
        ffi::fill_path(buf, &path)
    }
}
