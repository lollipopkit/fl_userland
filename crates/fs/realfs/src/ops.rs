//! Host-backed directory, attribute, descriptor, and mount operations.

use super::*;
use crate::errno::{rx, status};
use rustix::fs::{self, AtFlags, Gid, Mode, OFlags, Timespec, Timestamps, Uid};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;

/// A guest mode's permission bits as the host's `mode_t`, which is 16 bits
/// on Darwin; the type bits never reach here.
fn mode_of(perms: u32) -> Mode {
    Mode::from_raw_mode(perms as libc::mode_t)
}

// ---------------------------------------------------------------------------
// Directory entries
// ---------------------------------------------------------------------------

pub fn realfs_link(mount: &ffi::mount,
    src: &CStr,
    dst: &CStr,
) -> c_int {
    status((|| {
        let root = root(mount)?;
        rx(fs::linkat(root, at_path(src), root, at_path(dst), AtFlags::empty()))
    })())
}

pub fn realfs_unlink(mount: &ffi::mount, path: &CStr) -> c_int {
    let root = match root(mount) {
        Ok(root) => root,
        Err(e) => return e,
    };
    {
        if let Err(e) = rx(fs::unlinkat(root, at_path(path), AtFlags::empty())) {
            // Linux answers EISDIR for unlink of a directory; Darwin answers
            // EPERM, and passing the host's errno through handed the guest the
            // wrong one. Checked only on the failure path, so the usual case
            // costs nothing, and only to relabel an error that already
            // happened — the race against something replacing the path in
            // between can at worst pick the other plausible errno for a call
            // that failed either way.
            if e == errno::EPERM && is_dir(root, path) {
                return errno::EISDIR;
            }
            return e;
        }
        record(path, ffi::FAKEFS_CHANGE_OP_UNLINK);
        0
    }
}

fn is_dir(root: BorrowedFd<'_>, path: &CStr) -> bool {
    fs::statat(root, at_path(path), AtFlags::SYMLINK_NOFOLLOW)
        .is_ok_and(|st| fs::FileType::from_raw_mode(st.st_mode) == fs::FileType::Directory)
}

pub fn realfs_rmdir(mount: &ffi::mount, path: &CStr) -> c_int {
    status((|| {
        rx(fs::unlinkat(root(mount)?, at_path(path), AtFlags::REMOVEDIR))?;
        record(path, ffi::FAKEFS_CHANGE_OP_UNLINK);
        Ok(())
    })())
}

/// The guest's `RENAME_*` (`kernel/fs.h`) as `rustix`'s, which are Darwin's.
///
/// The two spell the same names with **different numbers**, which is the trap:
/// Linux's `RENAME_EXCHANGE` is 2 and Darwin's `RENAME_SWAP` is 2, so an
/// exchange happens to survive being passed through unchanged — but Linux's
/// `RENAME_NOREPLACE` is 1 and Darwin's `RENAME_EXCL` is 4, and 1 on Darwin is
/// `RENAME_SECLUDE`, which is a different operation entirely. Passing the
/// guest's mask straight to `renameatx_np` would have turned a lock file's
/// create-if-absent into a secluded rename.
///
/// `None` for a flag this cannot honour, which the caller answers `EINVAL` —
/// what Linux does for a filesystem that does not implement one.
///
/// `rustix::fs::RenameFlags` names Linux's meanings and holds Darwin's
/// numbers -- `NOREPLACE` is `RENAME_EXCL`, `EXCHANGE` is `RENAME_SWAP` -- so
/// since 2026-09-29 the trap is closed by a type as well as by this table.
///
/// Public because `crates/fs/fake` needs it too: a rename whose paths go
/// straight to the host through a bind mount does not come through
/// [`realfs_rename`], and the C it replaced had `0x4 /* RENAME_EXCL */` written
/// out with a comment saying this was the one place the translation lives. Two
/// copies of a table whose two halves use the same names for different numbers
/// is how the trap above gets sprung twice.
pub fn rename_flags(flags: u32) -> Option<fs::RenameFlags> {
    const GUEST_NOREPLACE: u32 = 1 << 0;
    const GUEST_EXCHANGE: u32 = 1 << 1;

    let mut out = fs::RenameFlags::empty();
    let mut rest = flags;
    if rest & GUEST_NOREPLACE != 0 {
        out |= fs::RenameFlags::NOREPLACE;
        rest &= !GUEST_NOREPLACE;
    }
    if rest & GUEST_EXCHANGE != 0 {
        out |= fs::RenameFlags::EXCHANGE;
        rest &= !GUEST_EXCHANGE;
    }
    (rest == 0).then_some(out)
}

pub fn realfs_rename(mount: &ffi::mount,
    src: &CStr,
    dst: &CStr,
    flags: u32,
) -> c_int {
    status((|| {
        let root = root(mount)?;
        let host_flags = rename_flags(flags).ok_or(errno::EINVAL)?;
        rx(if host_flags.is_empty() {
            fs::renameat(root, at_path(src), root, at_path(dst))
        } else {
            fs::renameat_with(root, at_path(src), root, at_path(dst), host_flags)
        })?;
        // The source is gone and the destination appeared; the consumer
        // filters the paths it does not care about.
        record(src, ffi::FAKEFS_CHANGE_OP_UNLINK);
        record(dst, ffi::FAKEFS_CHANGE_OP_RENAME);
        Ok(())
    })())
}

pub fn realfs_symlink(mount: &ffi::mount,
    target: &CStr,
    link: &CStr,
) -> c_int {
    // The target is stored verbatim, not resolved, so it is not a path to
    // fix up: it means whatever it means when the guest follows it.
    status(root(mount).and_then(|root| rx(fs::symlinkat(target, root, at_path(link)))))
}

pub fn realfs_mknod(mount: &ffi::mount,
    path: &CStr,
    mode: u16,
    _dev: ffi::dev_t_,
) -> c_int {
    let root = match root(mount) {
        Ok(root) => root,
        Err(e) => return e,
    };
    let perms = u32::from(mode) & !(libc::S_IFMT as u32);
    {
        match u32::from(mode) & libc::S_IFMT as u32 {
            // The descriptor is closed as it drops. `close` can report an
            // error, and that one is not worth one: the file exists.
            x if x == libc::S_IFREG as u32 => status(
                rx(fs::openat(
                    root,
                    at_path(path),
                    OFlags::CREATE | OFlags::EXCL | OFlags::RDONLY,
                    mode_of(perms),
                ))
                .map(drop),
            ),
            x if x == libc::S_IFIFO as u32 => {
                // `mkfifoat`, which Darwin has. This used to change the
                // process's working directory and change it back, under a
                // global lock, on the stated grounds that there is no
                // `mkfifoat` -- and the working directory is process-wide, so
                // a guest calling `mkfifo(3)` moved it for every thread for
                // the duration and serialised every other caller behind the
                // lock that made that safe.
                //
                // `crates/tools/fakefsify` had the same comment and the same
                // call, and there it was a bug rather than a cost: it did the
                // chdir *without* a lock, so two concurrent imports created
                // each other's FIFOs.
                status(make_fifo(root, at_path(path), perms as libc::mode_t, mkfifoat()))
            }
            x if x == libc::S_IFSOCK as u32 => make_socket_node(mount, path, perms),
            // A host directory cannot hold a device node — making one needs
            // root on a Mac and is impossible on iOS.
            _ => errno::EPERM,
        }
    }
}

/// Darwin's `mkfifoat`, if this system has one.
type MkfifoAt = unsafe extern "C" fn(c_int, *const c_char, libc::mode_t) -> c_int;

/// Looked up rather than linked, because it is **newer than the deployment
/// target**: `sys/stat.h` says `ios(16.0)` and `IPHONEOS_DEPLOYMENT_TARGET` is
/// 13.0, and a strong reference to a symbol libSystem does not have is a
/// launch failure -- dyld refuses the whole app on iOS 13 to 15, before a line
/// of it runs. `libc::mkfifoat` was that reference from 2026-08-29 to
/// 2026-09-29. `rustix` leaves the function out on Apple targets for this
/// reason, and looks `renameatx_np` up the same way.
fn mkfifoat() -> Option<MkfifoAt> {
    static FOUND: std::sync::OnceLock<Option<MkfifoAt>> = std::sync::OnceLock::new();
    *FOUND.get_or_init(|| {
        // SAFETY: a lookup by name in the images already loaded.
        let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"mkfifoat".as_ptr()) };
        // SAFETY: the symbol is libSystem's `mkfifoat`, whose signature is
        // the one `MkfifoAt` spells, from the SDK's `sys/stat.h`.
        (!sym.is_null()).then(|| unsafe { std::mem::transmute::<*mut c_void, MkfifoAt>(sym) })
    })
}

/// Make a FIFO at `rel`, relative to `root`.
///
/// With `mkfifoat` when there is one. Without it the directory is changed
/// under [`util_fchdir::Chdir`]'s lock and `mkfifo` is given the relative path,
/// which is what this did before 2026-08-29 -- it moves the working directory
/// of the whole process for the duration, which is why it is only the
/// fallback.
fn make_fifo(root: BorrowedFd<'_>, rel: &CStr, mode: libc::mode_t, at: Option<MkfifoAt>) -> Result<()> {
    match at {
        // SAFETY: `root` is open and `rel` is NUL-terminated.
        Some(at) => ck(unsafe { at(root.as_raw_fd(), rel.as_ptr(), mode) }).map(drop),
        None => {
            let _at = util_fchdir::Chdir::to(root).map_err(errno::io_err)?;
            // SAFETY: `rel` is NUL-terminated.
            ck(unsafe { libc::mkfifo(rel.as_ptr(), mode) }).map(drop)
        }
    }
}

/// Create a real socket node on the host.
///
/// `bind(2)` is the only way an unprivileged process can make one: `mknod`
/// with `S_IFSOCK` needs root, which is why this used to answer EPERM and
/// `bind` on an AF_UNIX socket did not work at all on a passthrough mount.
/// Binding a throwaway socket to the path leaves the node behind when it is
/// closed, which is exactly what an ordinary unix socket server relies on when
/// it unlinks a stale socket at startup.
///
/// The node is only ever a marker. The socket the guest actually talks over is
/// bound to a short path of the emulator's own choosing — see
/// `sock_tmp_prefix` in `fs/sock.c` — because `sun_path` holds 104 bytes and a
/// guest path under a rootfs will not always fit. This one has to fit,
/// though, which is what the `util_fchdir::Chdir` is for: it makes the path relative
/// to the mount root instead of absolute against the host.
///
/// # Safety
/// `mount` must be live and `path` a valid NUL-terminated string.
/// Distinguishes the short names [`make_socket_node`] binds at before renaming.
/// Per process, and the pid is in the name too, so two guests sharing a mount
/// cannot collide either.
static NEXT_SOCK_NODE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn make_socket_node(mount: &ffi::mount, path: &CStr, perms: u32) -> c_int {

    /// Darwin's `sun_path`: `sockaddr_un` is a length byte, a family byte and
    /// this.
    const SUN_PATH_LEN: usize = 104;
    const _: () = assert!(size_of::<libc::sockaddr_un>() == 2 + SUN_PATH_LEN);

    let relative = at_path(path).to_bytes();

    // **Darwin's `sun_path` is 104 bytes and Linux's is 108.** A socket
    // inode can only be made by *binding* one — there is no `mknod` for
    // `S_IFSOCK` without root — so a guest name of 104 bytes or more did
    // not fit the host's address and answered `ENAMETOOLONG` for something
    // a real kernel binds. Measured by `tests/guest/src/bin/sock_probe.rs`,
    // which binds a full 108-byte `sun_path`.
    //
    // The way round it is that only the *creation* needs a short name:
    // bind at one in the mount root, then `rename` it into place. `rename`
    // has no such limit, the two are on the same filesystem by
    // construction, and the guest sees an `S_IFSOCK` inode at the name it
    // asked for either way — what a peer actually connects through is the
    // host socket in `/tmp`, not this node. See `crates/fs/sock`.
    //
    // Only for the names that do not fit: the common path is the direct
    // bind it always was, so nothing that works today grows a rename.
    let via_rename = relative.len() >= SUN_PATH_LEN;
    let short_name;
    let bind_at: &[u8] = if via_rename {
        short_name = format!(
            ".iul-mksock.{}.{:x}",
            std::process::id(),
            NEXT_SOCK_NODE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        short_name.as_bytes()
    } else {
        relative
    };
    if bind_at.len() >= SUN_PATH_LEN {
        return errno::ENAMETOOLONG;
    }

    // Relative to the mount root, which is what the change of directory is
    // for. `std`'s bind also listens, which leaves the node exactly as a bare
    // `bind` would; the socket itself is closed when it drops, at the end of
    // this statement, and the node stays.
    let bound = {
        let root = match root(mount) {
            Ok(root) => root,
            Err(e) => return e,
        };
        let _at = match util_fchdir::Chdir::to(root) {
            Ok(at) => at,
            Err(e) => return errno::io_err(e),
        };
        std::os::unix::net::UnixListener::bind(std::ffi::OsStr::from_bytes(bind_at))
    };
    if let Err(e) = errno::io(bound) {
        return e;
    }

    let root = match root(mount) {
        Ok(root) => root,
        Err(e) => return e,
    };
    if via_rename {
        let from = std::ffi::OsStr::from_bytes(bind_at);
        if let Err(e) = rx(fs::renameat(root, from, root, at_path(path))) {
            // The node exists under the short name and nothing will ever look
            // for it, so it has to go: leaving it turns a failed `bind` into
            // a file in the guest's tree.
            let _ = fs::unlinkat(root, from, AtFlags::empty());
            return e;
        }
    }

    // bind applies the umask; the guest asked for a particular mode and has
    // already had its own umask taken off by the caller.
    status(rx(fs::chmodat(root, at_path(path), mode_of(perms), AtFlags::empty())))
}

pub fn realfs_mkdir(mount: &ffi::mount,
    path: &CStr,
    mode: u16,
) -> c_int {
    status(root(mount).and_then(|root| rx(fs::mkdirat(root, at_path(path), mode_of(mode.into())))))
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

/// An unlinked host file in the host's temp directory, as `crates/tools/iul`
/// reads it: `mkstemp`, `unlink`, then `mode`. What backs a memfd, and a
/// tmpfs file once something maps it -- a file with no name anywhere that
/// goes with its last descriptor, and that the host can map shared.
pub fn unlinked_host_file(mode: u32) -> std::io::Result<std::os::fd::OwnedFd> {
    let dir = match std::env::var_os("TMPDIR") {
        Some(t) if !t.is_empty() => std::path::PathBuf::from(t),
        _ => std::path::PathBuf::from("/tmp"),
    };
    let mut template = dir.join("iul-memfd-XXXXXX").into_os_string().into_encoded_bytes();
    template.push(0);
    // SAFETY: a writable NUL-terminated template ending in six X's.
    let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast::<c_char>()) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `mkstemp` just opened it, and nothing else has the number.
    let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    if let Ok(path) = CStr::from_bytes_with_nul(&template) {
        let _ = fs::unlink(path);
    }
    let _ = fs::fchmod(&fd, Mode::from_raw_mode(mode as libc::mode_t));
    Ok(fd)
}

/// `ftruncate` of a host file, which tells the file's mappings when it made
/// the file shorter: a page now past the end raises `SIGBUS` on its next
/// touch (`pagetable::file_shrunk`). A guest errno on failure.
pub fn host_ftruncate(host: BorrowedFd<'_>, size: u64) -> Result<()> {
    let before = fs::fstat(host).ok();
    rx(fs::ftruncate(host, size))?;
    if let Some(st) = before
        && size < st.st_size as u64
    {
        pagetable::file_shrunk(st.st_dev as u64, st.st_ino, size);
    }
    Ok(())
}

/// [`host_ftruncate`] by host path, for a file that cannot be opened to be
/// truncated: a FIFO opened for writing waits for a reader.
pub fn host_truncate_path(path: &CStr, size: i64) -> c_int {
    let before = fs::stat(path).ok();
    // SAFETY: `path` is NUL-terminated.
    if unsafe { libc::truncate(path.as_ptr(), size) } < 0 {
        return kernel_errno::errno_map();
    }
    if let Some(st) = before
        && size < st.st_size
    {
        pagetable::file_shrunk(st.st_dev as u64, st.st_ino, size as u64);
    }
    0
}

pub(crate) fn realfs_truncate(mount: &ffi::mount,
    path: &CStr,
    size: i64,
) -> c_int {
    status((|| {
        // O_WRONLY, not O_RDWR: truncate(2) needs write permission and nothing
        // more, and asking for read as well made it fail with EACCES on a
        // write-only file that Linux truncates without complaint.
        let fd = rx(fs::openat(root(mount)?, at_path(path), OFlags::WRONLY, Mode::empty()))?;
        // Negative is `EINVAL`, which is what the host answered when it was
        // handed one; `rustix` takes a `u64`, so the refusal is here now.
        let size = u64::try_from(size).map_err(|_| errno::EINVAL)?;
        host_ftruncate(fd.as_fd(), size)?;
        record(path, ffi::FAKEFS_CHANGE_OP_TRUNCATE);
        Ok(())
    })())
}

/// A chown whose EPERM means "this host does not let us", not "the guest may
/// not".
///
/// The guest's idea of who owns a file is not the host's — a fakefs keeps it
/// in a database precisely because iOS gives an app no real ownership to set —
/// so a passthrough mount cannot enforce it and reporting failure would break
/// every archive extraction that restores ownership. Any other error is real.
fn chown_result(res: Result<()>) -> c_int {
    match res {
        Ok(_) => 0,
        Err(errno::EPERM) => 0,
        Err(e) => e,
    }
}

pub fn realfs_setattr(mount: &ffi::mount,
    path: &CStr,
    attr: ffi::Attr,
) -> c_int {
    let root = match root(mount) {
        Ok(root) => root,
        Err(e) => return e,
    };
    // **`AT_SYMLINK_NOFOLLOW`, always.** The VFS has already applied the
    // caller's follow semantics: `generic_setattrat` walks the path with or
    // without following, so what arrives here names the object the guest
    // meant. Following again at the host is a second resolution nobody
    // asked for, and for a `chown -h` of a symlink it resolves to the
    // *target* — which for a dangling one does not exist, so the host
    // answered `ENOENT` for a call Linux serves with 0.
    //
    // That is not an edge case. `apk` extracts each file to `.apk.<hash>`,
    // sets its ownership with `AT_SYMLINK_NOFOLLOW`, and renames it into
    // place; a package's symlinks point at names that are not there yet, so
    // **every package containing one failed to install** on a realfs mount.
    // `apk add gcc` was twelve of these errors and an aborted transaction.
    //
    // It is a no-op for everything that is not a symlink, which is why one
    // flag serves both directions.
    const NOFOLLOW: AtFlags = AtFlags::SYMLINK_NOFOLLOW;
    match attr {
        ffi::Attr::Uid(uid) => chown_result(rx(fs::chownat(
            root,
            at_path(path),
            Some(Uid::from_raw(uid)),
            None,
            NOFOLLOW,
        ))),
        // -1, not the gid, in the owner argument. The C passed the gid
        // there and -1 as the group, so a chgrp changed the owner instead
        // of the group — and then swallowed the EPERM that came back,
        // reporting success for an operation that did nothing at all.
        ffi::Attr::Gid(gid) => chown_result(rx(fs::chownat(
            root,
            at_path(path),
            None,
            Some(Gid::from_raw(gid)),
            NOFOLLOW,
        ))),
        ffi::Attr::Mode(mode) => status(rx(fs::chmodat(
            root,
            at_path(path),
            mode_of(mode.into()),
            AtFlags::empty(),
        ))),
        ffi::Attr::Size(size) => realfs_truncate(mount, path, size),
        // No default: the C's was a TODO(), which is die(), so an
        // attribute added to the enum and not to this switch killed the
        // emulator. An `enum` makes that a compile error instead.
    }
}

pub fn realfs_fsetattr(fd: &ffi::fd, attr: ffi::Attr) -> c_int {
    let host = match host(fd) {
        Ok(host) => host,
        Err(e) => return e,
    };
    match attr {
        ffi::Attr::Uid(uid) => chown_result(rx(fs::fchown(
            host,
            Some(Uid::from_raw(uid)),
            None,
        ))),
        // See realfs_setattr: the group goes in the group argument.
        ffi::Attr::Gid(gid) => chown_result(rx(fs::fchown(
            host,
            None,
            Some(Gid::from_raw(gid)),
        ))),
        ffi::Attr::Mode(mode) => status(rx(fs::fchmod(host, mode_of(mode.into())))),
        ffi::Attr::Size(size) => status(
            u64::try_from(size)
                .map_err(|_| errno::EINVAL)
                .and_then(|size| host_ftruncate(host, size)),
        ),
    }
}

pub fn realfs_utime(mount: &ffi::mount,
    path: &CStr,
    atime: ffi::timespec,
    mtime: ffi::timespec,
    follow_links: bool,
) -> c_int {
    // Already the host's encoding: `crates/kernel/pathcalls` turned the
    // guest's `UTIME_NOW`/`UTIME_OMIT` into Darwin's before this.
    let ts = |t: ffi::timespec| Timespec { tv_sec: t.tv_sec, tv_nsec: t.tv_nsec };
    let times = Timestamps { last_access: ts(atime), last_modification: ts(mtime) };
    // AT_SYMLINK_NOFOLLOW has to be passed on. Without it the host follows
    // the link, and a guest symlink holding an absolute path resolves
    // against the host root rather than the mount -- so stamping one
    // answered ENOENT for a target that plainly existed inside the guest.
    let flags = if follow_links {
        AtFlags::empty()
    } else {
        AtFlags::SYMLINK_NOFOLLOW
    };
    status(root(mount).and_then(|root| rx(fs::utimensat(root, at_path(path), &times, flags))))
}

// ---------------------------------------------------------------------------
// Descriptor operations
// ---------------------------------------------------------------------------

pub fn realfs_flock(fd: &ffi::fd, operation: c_int) -> c_int {
    use fs::FlockOperation as Op;
    // `sys_flock` has already refused anything but one of the three with an
    // optional `LOCK_NB` -- `fs_locks::decode_flock` is the rule -- so the
    // last arm is for a caller that did not come through it.
    let nb = operation as u32 & ffi::LOCK_NB_ != 0;
    let op = match (operation as u32 & !ffi::LOCK_NB_, nb) {
        (ffi::LOCK_SH_, false) => Op::LockShared,
        (ffi::LOCK_SH_, true) => Op::NonBlockingLockShared,
        (ffi::LOCK_EX_, false) => Op::LockExclusive,
        (ffi::LOCK_EX_, true) => Op::NonBlockingLockExclusive,
        (ffi::LOCK_UN_, false) => Op::Unlock,
        (ffi::LOCK_UN_, true) => Op::NonBlockingUnlock,
        _ => return errno::EINVAL,
    };
    // The C returned flock's own result, which is -1 on failure — and -1 is
    // the guest's EPERM. Every contended lock was reported to the guest as
    // "operation not permitted" instead of "already locked", so a lock file
    // looked like a permissions problem to everything that used one.
    status(host(fd).and_then(|host| rx(fs::flock(host, op))))
}

pub fn realfs_fsync(fd: &ffi::fd) -> c_int {
    status(host(fd).and_then(|host| rx(fs::fsync(host))))
}

pub fn realfs_setflags(fd: &ffi::fd, arg: u32) -> c_int {
    let flags = OFlags::from_bits_retain(flags::to_host_settable(arg) as _);
    status(host(fd).and_then(|host| rx(fs::fcntl_setfl(host, flags))))
}

pub fn realfs_mount(mount: &mut ffi::mount) -> c_int {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    // The source is canonicalised because getpath compares against it: a
    // path with a symlink in it would never match what F_GETPATH reports.
    let real = match std::fs::canonicalize(std::ffi::OsStr::from_bytes(mount.source.to_bytes())) {
        Ok(real) => real.into_os_string().into_vec(),
        Err(e) => return errno::io_err(e),
    };
    // A canonical path came from a C string and has no NUL in it.
    let Ok(real) = std::ffi::CString::new(real) else {
        return errno::EINVAL;
    };
    mount.source = real;
    match rx(fs::open(mount.source.as_c_str(), OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())) {
        Ok(fd) => {
            mount.root_fd = Some(fd);
            0
        }
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::AsFd;
    use std::os::unix::fs::FileTypeExt;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("realfs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// This machine has `mkfifoat`, so the lookup finds it -- which is the
    /// half that says the name and the lookup are right.
    #[test]
    fn mkfifoat_is_found_on_this_host() {
        assert!(mkfifoat().is_some());
    }

    /// Both ways make a FIFO where they were asked to, and the fallback --
    /// which is what an iPhone older than iOS 16 runs, and which nothing else
    /// here would -- leaves the working directory where it found it.
    #[test]
    fn both_ways_make_the_fifo_and_the_fallback_goes_back() {
        let dir = scratch("fifo");
        let root = File::open(&dir).unwrap();
        let before = std::env::current_dir().unwrap();

        make_fifo(root.as_fd(), c"direct", 0o600, mkfifoat()).expect("mkfifoat");
        make_fifo(root.as_fd(), c"fallback", 0o600, None).expect("chdir and mkfifo");

        assert_eq!(std::env::current_dir().unwrap(), before);
        for name in ["direct", "fallback"] {
            let meta = std::fs::symlink_metadata(dir.join(name)).unwrap();
            assert!(meta.file_type().is_fifo(), "{name} is not a FIFO");
        }
        assert_eq!(
            make_fifo(root.as_fd(), c"fallback", 0o600, None),
            Err(guest_errno::c_int_::EEXIST),
            "the fallback reports the host's error"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
