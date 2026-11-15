//! Descriptor durability and locking operations.

use super::*;

// ---------------------------------------------------------------------------
// Durability, locking and the filesystem
// ---------------------------------------------------------------------------

pub fn fsync_desc(fd: fs_fdobj::FdRef) -> Result<(), Errno> {
    let fd = Fd(fd);
    // Linux's rule is `if (!file->f_op->fsync) return -EINVAL;`, and the file
    // kinds with no `fsync` method are the ones with nothing on a disk behind
    // them: a pipe, a socket, an eventfd, a terminal, `/dev/null`. A regular
    // file and a directory have one on every filesystem, tmpfs included, where
    // it is `noop_fsync` and answers 0.
    //
    // Spelling it as the file type rather than as "this descriptor's `fs_ops`
    // has no `fsync`" is what keeps tmpfs right: it has no host file to flush,
    // so it has no entry, and Linux answers 0 for it. This answered **0 for
    // everything**, so a program fsyncing a socket to find out whether it could
    // was told yes.
    let kind = fd.kind() & S_IFMT;
    if kind != S_IFREG && kind != S_IFDIR {
        return Err(Errno::EINVAL);
    }
    flush(&fd)
}

pub fn sys_fsync(num: c_int) -> Result<(), Errno> {
    fsync_desc(Fd::get(num)?.0)
}

/// Ask the driver to flush.
///
/// Success for a driver with nothing to flush, which used to be the `None` arm
/// here and is [`ffi::FdOps::fsync`]'s default body now — the same answer,
/// stated once beside the operation instead of at this one call site.
fn flush(fd: &Fd) -> Result<(), Errno> {
    match fd.ops {
        Some(ops) => done(ops.fsync(fd)),
        None => Ok(()),
    }
}

/// `syncfs`.
///
/// Linux flushes the whole filesystem the descriptor is on. There is no such
/// call on Darwin, and no way to name "the filesystem" of a guest fd that spans
/// realfs, fakefs and tmpfs — so this flushes the descriptor itself, which is
/// the part of the promise that can be kept and the part a caller is usually
/// after.
///
/// It was a stub returning `ENOSYS`, and dnf treats that as fatal: an install
/// that had already resolved and downloaded everything ended on it.
///
/// It does **not** take `fsync`'s file-type check: `syncfs` is about the
/// filesystem the descriptor is on rather than about the file, so any open
/// descriptor is a valid way to name one. Linux answers 0 for `syncfs` on
/// `/dev/null` and `EINVAL` for `fsync` on it.
pub fn sys_syncfs(num: c_int) -> Result<(), Errno> {
    strace!("syncfs({num})");
    let fd = Fd::get(num)?;
    flush(&fd)
}

/// `sync_file_range(2)`'s three flags.
pub(crate) const SYNC_FILE_RANGE_WAIT_BEFORE: c_uint = 1;
pub(crate) const SYNC_FILE_RANGE_WRITE: c_uint = 2;
pub(crate) const SYNC_FILE_RANGE_WAIT_AFTER: c_uint = 4;

/// What a `sync_file_range` request asks for, once its arguments have been
/// judged: whether the caller waits for the data to be on disk.
///
/// A request that only *starts* writeback (`SYNC_FILE_RANGE_WRITE` alone)
/// promises nothing a caller can observe, so nothing is done for it -- and
/// dpkg makes exactly that call for every file it unpacks, before the `fsync`
/// it does anyway. A request that waits is a flush of the descriptor, which
/// is the whole file rather than the range; the host has no narrower call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncRange {
    StartOnly,
    Wait,
}

/// The argument rules, in Linux's order (`sync_file_range` in `fs/sync.c`):
/// the flags, then the two signs. They run **after** the descriptor has been
/// found: `ksys_sync_file_range` is `fdget` and then this, so a bad flag on a
/// closed descriptor is `EBADF`. The first version of this judged the flags
/// first and `atcall_probe` measured the difference. `nbytes == 0` means to
/// the end of the file, which is why the sum is checked rather than each
/// half: an `offset` of `LLONG_MAX` with a length of 1 is a range that does
/// not exist.
pub(crate) fn sync_file_range_request(
    offset: i64,
    nbytes: i64,
    flags: c_uint,
) -> Result<SyncRange, Errno> {
    const VALID: c_uint =
        SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    if flags & !VALID != 0 {
        return Err(Errno::EINVAL);
    }
    if offset < 0 {
        return Err(Errno::EINVAL);
    }
    if offset.checked_add(nbytes).is_none_or(|end| end < 0) {
        return Err(Errno::EINVAL);
    }
    let waits = flags & (SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WAIT_AFTER) != 0;
    Ok(if waits {
        SyncRange::Wait
    } else {
        SyncRange::StartOnly
    })
}

/// `sync_file_range(2)`.
///
/// Was `syscall_stub`, and dpkg calls it on every file it unpacks: `apt-get
/// install` of anything ended with "Sub-process /usr/bin/dpkg returned an
/// error code (1)" once `apt-get update` itself worked.
///
/// The descriptor first, then the arguments, then the file's kind: Linux
/// answers `ESPIPE` for anything that is not a regular file, a block device,
/// a directory or a symlink -- which is how it differs from `fsync`, whose
/// refusal is `EINVAL`.
pub fn sys_sync_file_range(
    num: c_int,
    offset: i64,
    nbytes: i64,
    flags: c_uint,
) -> Result<(), Errno> {
    strace!("sync_file_range({num}, {offset}, {nbytes}, {flags:#x})");
    let fd = Fd::get(num)?;
    let request = sync_file_range_request(offset, nbytes, flags)?;
    let kind = fd.kind() & S_IFMT;
    if kind != S_IFREG && kind != S_IFBLK && kind != S_IFDIR && kind != S_IFLNK {
        return Err(Errno::ESPIPE);
    }
    match request {
        SyncRange::StartOnly => Ok(()),
        SyncRange::Wait => flush(&fd),
    }
}

pub fn sys_flock(num: c_int, operation: c_uint) -> Result<(), Errno> {
    // The operation is judged before the descriptor is: `flock(-1, 0)` is
    // `EINVAL` on a real kernel and was `EBADF` here, which names the wrong
    // argument. The rule itself is `crates/fs/locks`'.
    fs_locks::decode_flock(operation as c_int).map_err(Errno::from_negative_or_eio)?;
    let fd = Fd::get(num)?;
    // A filesystem takes flock itself only when its files are host files: one
    // may be shared with a host process, and the host's lock is then the real
    // one. Everything else -- tmpfs, procfs, devpts -- has no host file, and
    // its locks live on the inode like the POSIX record locks do.
    //
    // This used to answer EBADF for those, which is not an errno flock can
    // return, so a lock file on /tmp looked like a closed descriptor.
    // `FsOps::flock` answers `None` rather than an errno for exactly this: the
    // fallback is a whole implementation rather than a refusal, and it lives a
    // layer above `crates/kernel/abi`, so the trait cannot default to it.
    done(
        match fd
            .fs()
            .and_then(|fs| fs.flock(&fd, operation as c_int))
        {
            Some(err) => {
                // The host holds it; the inode keeps a copy for
                // `/proc/<pid>/fdinfo`, which is the only reader of one.
                if err == 0 {
                    fs_locks::flock_granted_by_host(&fd, operation as c_int);
                }
                err
            }
            None => fs_locks::flock_generic(&fd, operation as c_int),
        },
    )
}
