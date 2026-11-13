//! File and directory I/O operations for tmpfs.

use super::*;

pub(crate) fn tmpfs_getpath(fd: &ffi::fd, buf: &mut [u8]) -> c_int {
    let Some(state) = fd_state(fd) else {
        return EBADF;
    };
    ffi::fill_path(buf, &state.dirent.path_within_mount())
}

// ============================================================
// fd_ops
// ============================================================

pub(crate) fn tmpfs_read(fd: &ffi::fd, buf: &mut [u8]) -> ssize_t {
    let Some(state) = fd_state(fd) else {
        return EBADF as ssize_t;
    };
    if !readable(fd) {
        return EBADF as ssize_t;
    }
    let mut body = lock(&state.dirent.inode.body);
    if body.is_dir() {
        return EISDIR as ssize_t;
    }
    // Refused rather than clamped, and rather than assumed: generic_seek is
    // the only thing that sets this and it rejects a negative result, but the
    // field is signed precisely so that "is it negative" is a question this
    // side can ask instead of a state it cannot represent.
    let Ok(offset) = u64::try_from(fd.offset()) else {
        return EINVAL as ssize_t;
    };

    // saturating_sub, not `size - offset`: in C both were unsigned, so an
    // offset past the end wrapped to a huge value, the clamp that followed
    // never fired, and the memcpy read off the end of the allocation. lseek
    // puts the offset entirely under the guest's control.
    let n = match state.dirent.inode.read_at(&body, offset, buf) {
        Ok(n) => n,
        Err(e) => return e as ssize_t,
    };
    if n > 0 {
        body.atime = Timespec::now();
    }
    drop(body);
    // `fetch_add`, not a read and a store: a concurrent reader on the same
    // description must not lose one of the two advances.
    fd.offset
        .fetch_add(n as ffi::off_t_, std::sync::atomic::Ordering::Relaxed);
    n as ssize_t
}

pub(crate) fn tmpfs_write(fd: &ffi::fd, buf: &[u8]) -> ssize_t {
    write_at(fd, buf, None)
}

/// A write at `off`, leaving the description's offset alone and ignoring its
/// `O_APPEND`: where a positional write goes is the caller's decision, which
/// `crates/kernel/rwcalls` makes (`pwrite` on an `O_APPEND` file appends, and
/// `RWF_NOAPPEND` says it must not). Through the stream form, seeking first,
/// the `O_APPEND` below would have overruled both.
pub(crate) fn tmpfs_pwrite(fd: &ffi::fd, buf: &[u8], off: ffi::off_t) -> ssize_t {
    match usize::try_from(off) {
        Ok(off) => write_at(fd, buf, Some(off)),
        Err(_) => EINVAL as ssize_t,
    }
}

/// `at` is a positional write's offset; `None` is the stream write's, at the
/// description's offset or under `O_APPEND` at the end, moving the offset.
fn write_at(fd: &ffi::fd, buf: &[u8], at: Option<usize>) -> ssize_t {
    let bufsize = buf.len();
    let Some(state) = fd_state(fd) else {
        return EBADF as ssize_t;
    };
    if !writable(fd) {
        return EBADF as ssize_t;
    }
    let mut body = lock(&state.dirent.inode.body);
    if body.is_dir() {
        return EISDIR as ssize_t;
    }
    // O_APPEND writes at the end no matter where the offset is, and moves the
    // offset to just past what was written. The C had no append support at
    // all, so `>>` overwrote from wherever the offset happened to be.
    let append = fd.flags() & ffi::O_APPEND_ != 0;
    let offset = match at {
        Some(at) => at,
        None if append => body.size() as usize,
        None => match usize::try_from(fd.offset()) {
            Ok(o) => o,
            Err(_) => return EINVAL as ssize_t,
        },
    };
    let Some(end) = offset.checked_add(bufsize) else {
        return EINVAL as ssize_t;
    };
    // Writing past the end zero-fills the gap.
    if let Err(e) = state.dirent.inode.write_at(&mut body, offset, buf) {
        return e as ssize_t;
    }
    if bufsize > 0 {
        body.touch_mtime();
    }
    drop(body);
    if at.is_none() {
        fd.set_offset(end as ffi::off_t_);
    }
    bufsize as ssize_t
}

pub(crate) fn tmpfs_lseek(fd: &ffi::fd,
    off: ffi::off_t_,
    whence: c_int,
) -> ffi::off_t_ {
    let Some(state) = fd_state(fd) else {
        return EBADF as ffi::off_t_;
    };
    // A directory's offset is a readdir cookie, not a byte position. musl's
    // rewinddir and seekdir both reach it through lseek rather than through the
    // seekdir op — and getdents drives the cursor this filesystem keeps, not
    // fd->offset — so seeking a directory has to move that cursor or
    // rewinddir does nothing at all.
    if state.dirent.is_dir() {
        let current = lock(&state.dir_pos).to_cookie();
        let target = match whence as u32 {
            ffi::LSEEK_SET => off as c_ulong,
            ffi::LSEEK_CUR => current.wrapping_add(off as c_ulong),
            // SEEK_END has no meaning for a cookie sequence.
            _ => return EINVAL as ffi::off_t_,
        };
        tmpfs_seekdir(fd, target);
        fd.set_offset(target as ffi::off_t_);
        return target as ffi::off_t_;
    }

    let size = lock(&state.dirent.inode.body).size();
    // generic_seek does the whence arithmetic and bounds checking every
    // filesystem shares.
    let err = fs_generic::generic_seek(fd, off, whence, size as size_t);
    if err < 0 {
        return err as ffi::off_t_;
    }
    fd.offset()
}

/// The DT_* value getdents64 reports, from a stat mode. Shared numbering with
/// Linux and BSD, so this is the same table everywhere.
fn dirent_type(mode: u32) -> u8 {
    const S_IFMT: u32 = 0o170000;
    match mode & S_IFMT {
        0o010000 => 1,  // DT_FIFO
        0o020000 => 2,  // DT_CHR
        0o040000 => 4,  // DT_DIR
        0o060000 => 6,  // DT_BLK
        0o100000 => 8,  // DT_REG
        0o120000 => 10, // DT_LNK
        0o140000 => 12, // DT_SOCK
        _ => 0,         // DT_UNKNOWN
    }
}

pub(crate) fn tmpfs_readdir(
    fd: &ffi::fd,
) -> std::result::Result<Option<ffi::dir_entry>, c_int> {
    let Some(state) = fd_state(fd) else {
        return Err(EBADF);
    };
    if !state.dirent.is_dir() {
        return Err(ENOTDIR);
    }
    let mut entry = ffi::dir_entry::default();
    let mut pos = lock(&state.dir_pos);
    // The first entry after `.` and `..`, or End for an empty directory.
    let first_child = || {
        state
            .dirent
            .children()
            .first()
            .map_or(DirPos::End, |d| DirPos::Child(d.index()))
    };

    let (name, ino, next): (&[u8], u64, DirPos) = match *pos {
        DirPos::End => return Ok(None),
        DirPos::Dot => (b".", state.dirent.inode.ino, DirPos::DotDot),
        DirPos::DotDot => {
            // The root of a mount has no parent here; Linux points its `..` at
            // itself, and the layer above resolves the real one.
            let parent_ino = state
                .dirent
                .parent()
                .map_or(state.dirent.inode.ino, |p| p.inode.ino);
            (b"..", parent_ino, first_child())
        }
        DirPos::Child(index) => {
            let children = state.dirent.children();
            let Some(current) = children.at_or_after(index) else {
                *pos = DirPos::End;
                return Ok(None);
            };
            let next = children
                .after(current.index())
                .map_or(DirPos::End, |d| DirPos::Child(d.index()));
            drop(children);
            // Copied out because `current` is an Arc this scope owns.
            let out = &mut entry;
            let current_name = current.name();
            if current_name.len() >= out.name.len() {
                return Err(ENAMETOOLONG);
            }
            out.inode = current.inode.ino;
            out.type_ = dirent_type(current.inode.mode());
            for (slot, &byte) in out.name.iter_mut().zip(current_name.iter()) {
                *slot = byte as c_char;
            }
            out.name[current_name.len()] = 0;
            *pos = next;
            return Ok(Some(entry));
        }
    };

    *pos = next;
    let out = &mut entry;
    // `.` and `..` are directories whatever they point at.
    out.type_ = 4; // DT_DIR
    // A name that does not fit cannot be reported; skipping it beats
    // truncating it into something that resolves to a different file.
    if name.len() >= out.name.len() {
        return Err(ENAMETOOLONG);
    }
    out.inode = ino;
    for (slot, &byte) in out.name.iter_mut().zip(name.iter()) {
        *slot = byte as c_char;
    }
    out.name[name.len()] = 0;
    Ok(Some(entry))
}

pub(crate) fn tmpfs_telldir(fd: &ffi::fd) -> c_ulong {
    let Some(state) = fd_state(fd) else {
        return c_ulong::MAX;
    };
    lock(&state.dir_pos).to_cookie()
}

pub(crate) fn tmpfs_seekdir(fd: &ffi::fd, ptr: c_ulong) {
    let Some(state) = fd_state(fd) else {
        return;
    };
    // A cookie naming a child that has since been removed lands on the next
    // one still there, which is what a directory scan across a deletion needs.
    let target = match DirPos::from_cookie(ptr) {
        DirPos::Child(index) => state
            .dirent
            .children()
            .at_or_after(index)
            .map_or(DirPos::End, |d| DirPos::Child(d.index())),
        other => other,
    };
    *lock(&state.dir_pos) = target;
}
