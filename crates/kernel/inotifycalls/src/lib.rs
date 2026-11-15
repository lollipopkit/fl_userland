//! The four inotify syscalls, the descriptor they hand out, and the registry a
//! filesystem mutation reaches every watcher through.
//!
//! The watch table, the event queue and the record format have been
//! `crates/fs/inotify` since 2026-08-22; `kernel/inotify.c` was the syscall
//! surface around them plus the set of live instances. Both are here now, and
//! the set is a `Vec` rather than an intrusive list threaded through
//! `struct fd` — the `inotify` arm of that union is gone with it.
//!
//! # One lock over the registry and every instance in it
//!
//! `Instance` is not internally synchronised, on purpose: the C held one
//! `inotify_lock` over the list *and* over each instance's queue, and the
//! reason is the notify path. A mutation walks every instance and pushes to
//! each, so a per-instance lock would be taken and dropped once per watcher
//! with nothing gained — the walk needs the list stable anyway.
//!
//! It is the innermost lock here and takes nothing while held. Two things
//! depend on that:
//!
//! - **The wakeup happens outside it.** `poll_wakeup` enters the member's
//!   reverse-edge list and an owner epoll's core, and epoll's readiness
//!   callback asks this same lock. Waking inside it is a real ABBA cycle, and
//!   was one.
//! - **The blocking read hands over.** `fd->lock` is taken *before* the
//!   registry lock is released and held until `wait_for` parks, so a notifier
//!   cannot slip between the empty read and the wait: to signal it must first
//!   take the registry lock, which is free by then, and then `fd->lock`, which
//!   is not until the wait has begun. The C had these the other way round for
//!   a while, and a guest that read an inotify descriptor while anything
//!   generated events deadlocked.


use std::ffi::{CStr, c_int, c_uint};
use std::sync::{Mutex, Weak};
use std::sync::atomic::{AtomicBool, Ordering};

use strace::strace;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

mod fanotify;
mod notify;
pub use fanotify::{sys_fanotify_init, sys_fanotify_mark};
#[cfg(test)]
pub(crate) use notify::inotify_next_cookie;

use guest_errno::Errno;

const POLL_READ: c_int = fs_poll::bits::READ as c_int;

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// One live inotify descriptor: the descriptor it is reached by, and what it
/// is watching.
struct Entry {
    /// Which descriptor this is, and the way `notify` reaches it to wake it.
    ///
    /// Weak since 2026-10-17. It was an `ffi::FdId` that `notify` borrowed
    /// back into the description after releasing this registry's lock, while
    /// a close on another thread could free it -- the race
    /// `crates/kernel/signalfdcalls` reproduced with the same shape.
    fd: Weak<ffi::fd>,
    instance: inotify::Instance,
}

impl Entry {
    fn names(&self, fd: &ffi::fd) -> bool {
        std::ptr::eq(self.fd.as_ptr(), fd)
    }
}

static REGISTRY: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

/// Whether anything is watching at all.
///
/// Read without the lock on the hot path: a filesystem mutation should cost
/// nothing measurable when nobody is watching, which is the usual case, and a
/// mutation racing the very first `inotify_add_watch` is a mutation the watcher
/// had not asked about yet.
///
/// Left true once anything has ever watched. Clearing it would mean deciding
/// that no instance holds a watch, which is a walk, and the flag only exists to
/// keep the cost off the mutation path in the case where nothing ever watched.
static ANYONE_WATCHING: AtomicBool = AtomicBool::new(false);

fn with_registry<T>(f: impl FnOnce(&mut Vec<Entry>) -> T) -> T {
    let mut guard = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

// ---------------------------------------------------------------------------
// The descriptor
// ---------------------------------------------------------------------------

/// An inotify descriptor's `fd_ops`: a read, a poll and a close.
///
/// Never writable, and that is deliberate rather than an omission: an inotify
/// descriptor cannot be written to, and a descriptor with no poll of its own
/// defaults to reporting itself writable, which makes a poll loop spin.
struct InotifyOps;

static INOTIFY_FDOPS: InotifyOps = InotifyOps;

fn inotify_fdops() -> Option<&'static dyn ffi::FdOps> {
    Some(&INOTIFY_FDOPS)
}

impl ffi::FdOps for InotifyOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::READ_ONLY_STREAM
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        inotify_read(fd, buf)
    }
    /// Answered rather than left to the default, and the comment above says
    /// why: no opinion means "ready in both directions", which would report an
    /// inotify descriptor writable and spin a poll loop.
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(inotify_poll(fd))
    }
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        inotify_close(fd)
    }
    /// `inotify_fdinfo`, one line per watch, newest first: the watch, the
    /// inode it was placed on and its device as the kernel holds it, the
    /// mask, and the identifying handle `name_to_handle_at(AT_HANDLE_FID)`
    /// gives for that inode.
    fn show_fdinfo(&self, fd: &ffi::fd, out: &mut String) {
        let listing = with_registry(|entries| {
            entries.iter().find(|e| e.names(fd)).map(|e| e.instance.listing())
        });
        for w in listing.unwrap_or_default() {
            let fid = ffi::fid_ino64_gen(w.inode.ino);
            let handle: String = fid.iter().map(|b| format!("{b:02x}")).collect();
            out.push_str(&format!(
                "inotify wd:{:x} ino:{:x} sdev:{:x} mask:{:x} ignored_mask:0 fhandle-bytes:{:x} fhandle-type:{:x} f_handle:{handle}\n",
                w.wd,
                w.inode.ino,
                ffi::kernel_dev(w.inode.dev),
                w.mask,
                fid.len(),
                ffi::FILEID_INO64_GEN,
            ));
        }
    }
}

fn is_inotify(fd: &ffi::fd) -> bool {
    fd.ops.is_some_and(|ops| ops.as_any().is::<InotifyOps>())
}

fn inotify_read(fd: &ffi::fd, buf: &mut [u8]) -> isize {
    loop {
        let taken = with_registry(|entries| {
            let entry = entries.iter_mut().find(|e| e.names(fd))?;
            Some(entry.instance.read_into(buf.len()))
        });
        match taken {
            // The descriptor is not in the registry: it is closing.
            None => return guest_errno::isize_::EBADF,
            // Too small for the record at the head, which Linux answers rather
            // than 0 -- 0 from a read means end of file and an inotify
            // descriptor never ends.
            Some(Err(err)) => return err as isize,
            Some(Ok(bytes)) if !bytes.is_empty() => {
                // `read_into` was told this buffer's length and answers no more
                // than that, which is what the slice makes checkable.
                buf[..bytes.len()].copy_from_slice(&bytes);
                return bytes.len() as isize;
            }
            Some(Ok(_)) => {}
        }

        // Empty. A read with nothing to report waits, unless it was asked not
        // to -- which is what it always used to do, because nothing ever put
        // anything in the queue.
        if fd.flags() & ffi::O_NONBLOCK_ != 0 {
            return guest_errno::isize_::EAGAIN;
        }
        // The handover: fd->lock is taken while the registry lock is still
        // held, so a notifier cannot signal between the empty read above and
        // the wait below. See this module's comment.
        let err = {
            let guard = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
            if !guard.iter().any(|e| e.names(fd)) {
                return guest_errno::isize_::EBADF;
            }
            let held = fs_fdobj::FdGuard::new(fd);
            drop(guard);
            held.wait()
        };
        if err < 0 {
            return err as isize;
        }
    }
}

fn inotify_poll(fd: &ffi::fd) -> c_int {
    let ready = with_registry(|entries| {
        entries
            .iter()
            .find(|e| e.names(fd))
            .is_some_and(|e| e.instance.has_events())
    });
    if ready { POLL_READ } else { 0 }
}

fn inotify_close(fd: &mut ffi::fd) -> c_int {
    with_registry(|entries| entries.retain(|e| !e.names(fd)));
    0
}

// ---------------------------------------------------------------------------
// The syscalls
// ---------------------------------------------------------------------------

/// The two flags `inotify_init1` takes, which are the open flags of the same
/// name rather than numbers of their own.
fn init_flags_ok(flags: c_int) -> bool {
    let allowed = (ffi::O_CLOEXEC_ | ffi::O_NONBLOCK_) as c_int;
    flags & !allowed == 0
}

pub fn sys_inotify_init1(flags: c_int) -> Result<i64, Errno> {
    strace!("inotify_init1({flags:#x})");
    if !init_flags_ok(flags) {
        return Err(Errno::EINVAL);
    }

    // The hook the descriptor layer and the VFS raise events through. Set on
    // every init and taken the first time: nothing can be watching before the
    // first instance exists, so there is no event to miss.
    inotify::set_notify_hook(notify::notify);

    // No brackets: Linux's `inotify_init1` names its inode "inotify" where
    // every other kind is "[name]", and `/proc/<pid>/fd` shows the difference.
    let fd = fs_adhoc::adhoc_anon(inotify_fdops(), Some(c"inotify"));
    // `O_RDONLY`, where every other anonymous kind is `O_RDWR`: Linux's
    // `inotify_init1` asks `anon_inode_getfd` for `O_RDONLY | flags`, so
    // `F_GETFL` answers 0 and a `write` is `EBADF` (`fdinfo_probe`).
    fd.set_flags(fd.flags() & !ffi::O_ACCMODE_);
    let fd = fd.into_owned();
    let registered = with_registry(|entries| {
        if entries.try_reserve(1).is_err() {
            return false;
        }
        entries.push(Entry {
            fd: fd.downgrade(),
            instance: inotify::Instance::new(),
        });
        true
    });
    if !registered {
        return Err(Errno::ENOMEM);
    }
    Errno::split(fs_fdobj::f_install(fd, flags) as i64)
}

pub fn sys_inotify_add_watch(
    inotify_f: c_int,
    path_addr: u64,
    mask: c_uint,
) -> Result<i64, Errno> {
    // Mask, then descriptor, then path -- Linux's order, measured rather than
    // read: `inotify_add_watch(-1, "/tmp", 0)` is `EINVAL` there and was
    // `EBADF` here, and `(-1, NULL, IN_ATTRIB)` is `EBADF` there and was
    // `EFAULT` here. A caller probing which of its arguments a kernel objects
    // to was told about the wrong one either way.
    if let Err(e) = inotify::check_mask(mask) {
        return Err(Errno::from_negative_or_eio(e));
    }
    let Some(fd) = fs_fdobj::f_get(inotify_f) else {
        return Err(Errno::EBADF);
    };
    let fd = &*fd;
    if !is_inotify(fd) {
        return Err(Errno::EINVAL);
    }

    let mut path_raw = [0u8; ffi::MAX_PATH as usize];
    let err = mmapcalls::usermem::read_current_string(path_addr, &mut path_raw);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    // Terminated: a success from `read_current_string` is a string that ended
    // inside the buffer.
    let name = CStr::from_bytes_until_nul(&path_raw).map_err(|_| Errno::ENAMETOOLONG)?;
    strace!("inotify_add_watch({inotify_f}, {path_addr:#x}, {mask:#x})");

    // The path has to be there. This used to answer with a watch descriptor
    // whatever it was given -- a missing path, an unreadable pointer, an empty
    // mask -- so a watcher setting up on a directory that did not exist was
    // told it had succeeded.
    let follow = mask & inotify::IN_DONT_FOLLOW == 0;
    let mut stat = ffi::statbuf::default();
    let err = fs_generic::generic_statat(ffi::At::Pwd, name, &mut stat, follow);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    if mask & inotify::IN_ONLYDIR != 0 && stat.mode & ffi::S_IFMT != ffi::S_IFDIR {
        return Err(Errno::ENOTDIR);
    }

    // Watches are keyed on the normalized path, because that is what a
    // filesystem mutation reports and the two have to be the same string.
    let follow_flag = if follow {
        ffi::N_SYMLINK_FOLLOW
    } else {
        ffi::N_SYMLINK_NOFOLLOW
    };
    let resolved = fs_generic::normalize::resolve(ffi::At::Pwd, name.to_bytes(), follow_flag as c_int)
        .map_err(Errno::from_negative_or_eio)?;
    let path = resolved.path.as_slice();

    with_registry(|entries| {
        let Some(entry) = entries.iter_mut().find(|e| e.names(fd)) else {
            return Err(Errno::EBADF);
        };
        let inode = inotify::Inode { ino: stat.inode, dev: stat.dev };
        let wd = entry.instance.add_watch(path, mask, inode);
        if wd >= 0 {
            ANYONE_WATCHING.store(true, Ordering::Relaxed);
        }
        Errno::split(wd as i64)
    })
}

pub fn sys_inotify_rm_watch(inotify_f: c_int, wd: c_int) -> Result<(), Errno> {
    strace!("inotify_rm_watch({inotify_f}, {wd})");
    let Some(fd) = fs_fdobj::f_get(inotify_f) else {
        return Err(Errno::EBADF);
    };
    let fd = &*fd;
    if !is_inotify(fd) {
        return Err(Errno::EINVAL);
    }
    let removed = with_registry(
        |entries| match entries.iter_mut().find(|e| e.names(fd)) {
            Some(entry) => Errno::split(entry.instance.rm_watch(wd) as i64),
            None => Err(Errno::EBADF),
        },
    );
    // Outside the registry lock: removing a watch queues an IN_IGNORED, which
    // is something to wake a reader for, and the wakeup must not happen under
    // it. See this module's comment.
    if removed.is_ok() {
        wake(fd);
    }
    removed?;
    Ok(())
}

/// Tells a reader and every poller that this descriptor has something.
fn wake(fd: &ffi::fd) {
    fs_fdobj::FdGuard::new(fd).notify();
    fs_poll::poll_wakeup(fd, POLL_READ);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The split `notify` does, which is the whole of its
    /// argument handling and the part that has to agree with what a watch was
    /// keyed on.
    fn split(path: &[u8]) -> Option<(&[u8], &[u8])> {
        let slash = path.iter().rposition(|&b| b == b'/')?;
        Some((&path[..slash.max(1)], &path[slash + 1..]))
    }

    #[test]
    fn a_path_splits_into_the_directory_watched_and_the_name_reported() {
        assert_eq!(split(b"/a/b/c"), Some((&b"/a/b"[..], &b"c"[..])));
        // A file in the root: the directory is "/" and not "", because that is
        // the string a watch on the root is keyed by.
        assert_eq!(split(b"/c"), Some((&b"/"[..], &b"c"[..])));
        // The root itself has no name half.
        assert_eq!(split(b"/"), Some((&b"/"[..], &b""[..])));
        // Not a normalized path: nothing can be watching it by this name.
        assert_eq!(split(b"relative"), None);
        assert_eq!(split(b""), None);
    }

    /// A cookie is never zero and never repeats twice in a row, which is all a
    /// watcher needs to pair the halves of one rename.
    #[test]
    fn a_rename_cookie_moves_every_time() {
        let a = inotify_next_cookie();
        let b = inotify_next_cookie();
        assert_ne!(a, b);
    }

    /// `inotify_init1` takes exactly two flags.
    ///
    /// The syscall itself cannot be reached from a standalone binary — it
    /// installs a descriptor, which is `struct fd` and therefore C — so what is
    /// tested here is the rule, and `tests/guest/src/bin/inotify_args.rs` is
    /// what tests the call.
    #[test]
    fn only_cloexec_and_nonblock_are_accepted() {
        assert!(init_flags_ok(0));
        assert!(init_flags_ok(ffi::O_CLOEXEC_ as c_int));
        assert!(init_flags_ok(ffi::O_NONBLOCK_ as c_int));
        assert!(init_flags_ok((ffi::O_CLOEXEC_ | ffi::O_NONBLOCK_) as c_int));
        assert!(!init_flags_ok(1 << 30));
        assert!(!init_flags_ok(ffi::O_CLOEXEC_ as c_int | 1 << 30));
        // O_CLOEXEC and O_NONBLOCK are not the same bit, which is the part a
        // hand-written pair of constants would get wrong.
        assert_ne!(ffi::O_CLOEXEC_, ffi::O_NONBLOCK_);
    }
}
