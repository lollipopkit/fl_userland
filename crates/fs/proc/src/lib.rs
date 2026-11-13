//! procfs: the VFS side.
//!
//! The entry tables and the `show` callbacks that fill a file stay in C
//! (`fs/proc/root.c`, `pid.c`, `net.c`, `ish.c`) — they read task, mm and
//! mount state that stable Rust cannot reach. What moves here is everything
//! around them: resolving a path to an entry, the descriptor's lifetime, and
//! the read/write/seek/readdir operations.
//!
//! Two things the C did that this does not:
//!
//! - **It wrote to the static entry tables at lookup time**, filling in
//!   `parent` and `inode` on first sight of each entry, from any thread, with
//!   no lock. Nothing here writes a table. `parent` is not needed because a
//!   descriptor remembers the path it was opened at, and `inode` is allocated
//!   in [`inode`].
//! - **It regenerated the whole file on every read.** The contents are
//!   generated once per descriptor and reused until a seek back to the start.

#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

pub mod data;
mod entry;
mod inode;
mod iul;
mod maps;
mod pid;
mod mapfiles;
mod pidentry;
pub mod pidmem;
mod pidns;
mod pidsnap;
mod pidstate;
mod root;
/// How `/proc/filesystems` reads the mount registry. `crates/fs/mountcalls`
/// installs it; see [`root::set_registered_name_hook`] for why it is a hook
/// rather than a call.
pub use root::{registered_name_hook_installed, set_registered_name_hook};
mod smaps;
mod sysctl;

mod net;
mod oom;

// bindgen's output, which is not written to this crate's standards and is not
// this crate's to fix. The block used to sit on `mod net` instead -- so the
// hand-written module that formats `/proc/net/*` had `clippy::all` and
// `unsafe_op_in_unsafe_fn` allowed and the generated one did not, which is the
// opposite of both intentions. Moved 2026-09-08; `cargo clippy` had two
// findings in `net` the moment it could see it.
/// The C ABI names this crate uses: procfs's own three, and the shared set.
///
/// Generated from sixteen headers until 2026-09-08. `fs/proc.h` was read by
/// nothing but that build script, so the three types it declared are
/// `src/abi.rs` now; everything else the run produced was already
/// `crates/kernel/taskview`'s, reached through the same glob.
pub mod ffi {
    pub use crate::abi::*;
    pub use crate::data::ProcData as proc_data;
    pub use taskview::ffi::*;
}

mod abi;
mod descriptor;
use descriptor::{ProcFd, lookup, open_of, state};

/// Definitions of the C symbols the *test* binary would otherwise have to link
/// the whole kernel to resolve.
///
/// `cargo test -p proc` links a standalone binary. Everything in it that C
/// provides is undefined, and the linker only complains about the ones the
/// entry tables keep alive — so the list here is short, and it grows only when
/// a `show` callback starts calling something new.
///
/// It is not decoration. Adding `/proc/filesystems` introduced a call to
/// `fs_registered_name`, and from that commit until this one `cargo test -p
/// proc` did not link at all: every unit test in the crate silently stopped
/// running. A suite that cannot be built reports nothing and looks like
/// nothing is wrong.
use std::ffi::CStr;

use libc::{c_char, c_int, c_ulong, ssize_t};

use guest_errno::Errno;
use guest_errno::c_int_::{EINVAL, EIO, EISDIR, ENAMETOOLONG, ENOENT, ENOTDIR, EPERM};

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

const MAX_PATH: usize = ffi::MAX_PATH as usize;
const MAX_NAME: usize = ffi::MAX_NAME as usize;

// ============================================================
// fs_ops
// ============================================================

fn proc_open(_mount: &ffi::mount,
    path: &CStr,
    _flags: c_int,
    _mode: c_int,
) -> Result<Box<ffi::fd>, Errno> {
    let path = path.to_bytes();
    let (entry, resolved) = lookup(path).map_err(Errno::from_negative_or_eio)?;
    // Opening a guarded directory is listing it.
    descriptor::guarded(&entry).map_err(Errno::from_negative_or_eio)?;

    let fd = Box::new(ffi::fd::with_ops(Some(&PROCFS_FDOPS)));
    fd.set_fs_data(ProcFd {
        path: resolved,
        open: std::sync::Mutex::new(descriptor::Open {
            entry,
            data: crate::data::ProcData::default(),
        }),
    });
    Ok(fd)
}

fn proc_stat(_mount: &ffi::mount, path: &CStr) -> Result<ffi::statbuf, c_int> {
    let (mut entry, _) = lookup(path.to_bytes())?;
    let mut stat = ffi::statbuf::default();
    match fill_stat(&mut entry, &mut stat) {
        0 => Ok(stat),
        e => Err(e),
    }
}

fn proc_fstat(fd: &ffi::fd) -> Result<ffi::statbuf, c_int> {
    let Some(state) = state(fd) else {
        return Err(EIO);
    };
    let mut stat = ffi::statbuf::default();
    match fill_stat(&mut open_of(state).entry, &mut stat) {
        0 => Ok(stat),
        e => Err(e),
    }
}

/// Fill `stat` for `entry`, overriding the inode the C helper derives.
fn fill_stat(entry: &mut ffi::proc_entry, stat: &mut ffi::statbuf) -> c_int {
    entry::proc_entry_stat(entry, stat)
}

fn proc_getpath(fd: &ffi::fd, buf: &mut [u8]) -> c_int {
    let Some(state) = state(fd) else {
        return EIO;
    };
    ffi::fill_path(buf, &state.path)
}

fn proc_readlink(_mount: &ffi::mount,
    path: &CStr,
    buf: &mut [u8],
) -> ssize_t {
    let path = path.to_bytes();
    let (mut entry, _) = match lookup(path) {
        Ok(v) => v,
        Err(e) => return e as ssize_t,
    };
    let mode = entry::proc_entry_mode(&mut entry) as u32;
    if mode & S_IFMT != S_IFLNK {
        return EINVAL as ssize_t;
    }
    // Following a link reads it, so this is the check for both.
    if let Err(e) = descriptor::guarded(&entry) {
        return e as ssize_t;
    }
    let Some(readlink) = entry.meta.and_then(|m| m.readlink) else {
        return EINVAL as ssize_t;
    };

    let mut target = vec![0u8; MAX_PATH + 1];
    let err = readlink(&mut entry, &mut target);
    drop(entry);
    if err < 0 {
        return err as ssize_t;
    }
    let target = ffi::path_bytes(&target);
    // readlink truncates rather than failing, and writes no terminator.
    let n = target.len().min(buf.len());
    buf[..n].copy_from_slice(&target[..n]);
    n as ssize_t
}

/// Linux's `proc_setattr`: a mode change is EPERM, and a size or an owner is
/// accepted and changes nothing -- a proc file's contents are generated and
/// its owner is the task's. The size is what makes `echo 5 > /proc/<pid>/x`
/// work: the shell opens with `O_TRUNC`, and the truncation was EPERM here
/// until 2026-10-18, so no writable proc file could be written from a shell.
fn proc_setattr(attr: ffi::Attr) -> c_int {
    match attr {
        ffi::Attr::Mode(_) => EPERM,
        ffi::Attr::Size(_) | ffi::Attr::Uid(_) | ffi::Attr::Gid(_) => 0,
    }
}

fn proc_unlink(_mount: &ffi::mount, path: &CStr) -> c_int {
    let path = path.to_bytes();
    let (mut entry, _) = match lookup(path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match entry.meta.and_then(|m| m.unlink) {
        Some(unlink) => unlink(&mut entry),
        None => EPERM,
    }
}

// ============================================================
// fd_ops
// ============================================================

/// Generate the file's contents, unless they are already there.
///
/// The C ran the `show` callback on every read, so reading a file of N bytes
/// in B-byte chunks generated N bytes N/B times — 1.8s for a 116 KB
/// `/proc/self/maps` in 64-byte chunks, against 0.03s in 4096-byte ones.
fn refresh(state: &mut descriptor::Open) -> c_int {
    let mode = state.mode();
    if mode & S_IFMT == S_IFDIR {
        return EISDIR;
    }
    if mode & S_IFMT != S_IFREG {
        return EINVAL;
    }
    if state.data.valid {
        return 0;
    }
    let show = state.meta().and_then(|m| m.show);
    // A file served entirely by `pread` has no `show`. The C called this
    // unconditionally from seek, so seeking one jumped through a null pointer.
    let Some(show) = show else {
        return EINVAL;
    };

    state.data.reset();
    let err = show(&mut state.entry, &mut state.data);
    if err < 0 {
        return err;
    }
    state.data.valid = true;
    0
}

fn proc_pread(fd: &ffi::fd, buf: &mut [u8], off: libc::off_t) -> ssize_t {
    let bufsize = buf.len();
    let Some(state) = state(fd) else {
        return EIO as ssize_t;
    };
    // Held for the whole operation: `refresh` clears the buffer and refills it,
    // and the read below indexes what it left. Two threads on one descriptor
    // reach here at once -- `sys_read` holds no `fd->lock`. See `ProcFd`.
    let state = &mut *open_of(state);

    // An entry with its own pread serves the bytes directly.
    let pread = state.meta().and_then(|m| m.pread);
    if let Some(pread) = pread {
        // Straight into the caller's buffer. The C wrapped it in a
        // `struct proc_data` whose `data` was this pointer and whose
        // `capacity` was this length, which is what the pretence cost.
        return pread(&mut state.entry, buf, off);
    }

    let err = refresh(state);
    if err < 0 {
        return err as ssize_t;
    }
    if off < 0 {
        return EINVAL as ssize_t;
    }
    let off = off as usize;
    // saturating: an offset past the end is end-of-file, not a huge length.
    let available = state.data.len().saturating_sub(off);
    let n = bufsize.min(available);
    if n > 0 {
        buf[..n].copy_from_slice(&state.data.as_slice()[off..off + n]);
    }
    n as ssize_t
}

fn proc_pwrite(fd: &ffi::fd, buf: &[u8], off: libc::off_t) -> ssize_t {
    let bufsize = buf.len();
    let Some(state) = state(fd) else {
        return EIO as ssize_t;
    };
    // As `proc_pread`: held across the callback and the invalidation below.
    let state = &mut *open_of(state);
    let mode = state.mode();
    if mode & S_IFMT == S_IFDIR {
        return EISDIR as ssize_t;
    }

    let pwrite = state.meta().and_then(|m| m.pwrite);
    if let Some(pwrite) = pwrite {
        let n = pwrite(&mut state.entry, buf, off);
        // A file with a `show` as well -- a writable sysctl -- describes what
        // was just written from now on.
        if n > 0 {
            state.data.valid = false;
        }
        return n;
    }

    // What `update` is given: the bytes the guest wrote, owned by the buffer
    // rather than borrowed from the caller. The C pointed a `struct proc_data`
    // at the caller's memory for both, which is what the borrow cost.
    let mut data = crate::data::ProcData::default();
    data.append(buf);

    let update = state.meta().and_then(|m| m.update);
    // No write method: Linux's `vfs_write` answers EINVAL for a file
    // without `FMODE_CAN_WRITE` that the open let through (root, or a mode
    // with `w`). `procstate_probe`.
    let Some(update) = update else {
        return EINVAL as ssize_t;
    };
    let err = update(&mut state.entry, &mut data);
    if err < 0 {
        return err as ssize_t;
    }
    // Whatever was shown before the write no longer describes this file.
    state.data.valid = false;
    bufsize as ssize_t
}

fn proc_seek(fd: &ffi::fd, off: ffi::off_t_, whence: c_int) -> ffi::off_t_ {
    let Some(state) = state(fd) else {
        return EIO as ffi::off_t_;
    };
    // `sys_lseek64` does take `fd->lock`, and `sys_read` does not -- so this
    // one is what excludes a concurrent reader rather than the other way
    // round.
    let state = &mut *open_of(state);
    // A directory's position is a **cookie**, not an offset into contents, so
    // `refresh` -- which generates a file's text -- is the wrong question to
    // ask about one. It answered `EISDIR` for every directory seek, including
    // offset zero, which is `rewinddir(3)` in both glibc and musl. `rewinddir`
    // returns `void`, so the refusal was silent and the next `readdir` carried
    // on from where it was instead of starting over.
    if state.mode() & S_IFMT == S_IFDIR {
        return dir_seek(fd, off, whence);
    }
    let err = refresh(state);
    if err < 0 {
        return err as ffi::off_t_;
    }
    let size = state.data.len();
    let err = fs_generic::generic_seek(fd, off, whence, size);
    if err < 0 {
        return err as ffi::off_t_;
    }
    let offset = fd.offset();
    // Rewinding is how a reader asks to see the file again.
    if offset == 0 {
        state.data.valid = false;
    }
    offset as ffi::off_t_
}

/// A directory's position, which is a 32-bit cookie.
///
/// **Measured against a real arm64 kernel on 2026-09-12**, because `lseek(2)`
/// does not mention directories at all:
///
/// ```text
/// /proc  SEEK_SET 0, 8, 1<<20, i32::MAX  -> accepted
/// /proc  SEEK_SET i32::MAX + 1 and above -> EINVAL
/// /proc  SEEK_END 0                      -> 0        (the size is zero)
/// /proc  SEEK_CUR -1, SEEK_END -1        -> EINVAL
/// ```
///
/// **The bound is not tidiness.** [`root_readdir`] computes
/// `(offset - ROOT_LEN) as c_int` and hands it to `task_next_listed_pid`,
/// which counts *up* from there **holding `pids_lock`**. An offset above
/// `i32::MAX` truncates to a negative and that loop runs two billion times with
/// the global pid lock held — a guest stalling every other thread with one
/// `lseek` and one `getdents64`. It was unreachable only because the `EISDIR`
/// above refused the seek first, so lifting that without this would have opened
/// it. Linux enforces the same boundary for the same reason: its procfs
/// directory cookie is 32 bits.
///
/// The refusal restores the old position rather than leaving the out-of-range
/// one in place, because `generic_seek` stores before this can object and a
/// failed `lseek` must not move the file.
fn dir_seek(fd: &ffi::fd, off: ffi::off_t_, whence: c_int) -> ffi::off_t_ {
    let was = fd.offset();
    // Size zero: `SEEK_END 0` answers 0 on Linux, which is what an empty size
    // gives. `generic_seek` is where the negative-result check lives.
    let err = fs_generic::generic_seek(fd, off, whence, 0);
    if err < 0 {
        return err as ffi::off_t_;
    }
    let offset = fd.offset();
    if offset > c_int::MAX as i64 {
        fd.set_offset(was);
        return EINVAL as ffi::off_t_;
    }
    offset as ffi::off_t_
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

/// Where the table's own children start in a directory's position: `.` is
/// at 0 and `..` at 1.
const DOTS: i64 = 2;

/// A procfs directory's next entry: `.`, `..`, then the table's children.
///
/// No procfs directory listed `.` or `..` until 2026-10-18, so `ls -a /proc`
/// began at `1` where Linux begins at `.` (`tests/guest` procfs_probe). `..`
/// at the mount's root is the root itself, as Linux's is: the root of a
/// superblock is its own parent.
fn proc_readdir(fd: &ffi::fd) -> Result<Option<ffi::dir_entry>, c_int> {
    let Some(state) = state(fd) else {
        return Err(EIO);
    };
    let pos = fd.offset();
    if pos < DOTS {
        let (name, mut entry): (&[u8], _) = if pos == 0 {
            (b".", open_of(state).entry.clone())
        } else {
            let path = &state.path;
            let parent = &path[..path.iter().rposition(|&b| b == b'/').unwrap_or(0)];
            (b"..", lookup(parent)?.0)
        };
        let mut stat = ffi::statbuf::default();
        match fill_stat(&mut entry, &mut stat) {
            0 => {}
            e => return Err(e),
        }
        fd.set_offset(pos + 1);
        return dir_entry(name, stat.inode, dirent_type(stat.mode)).map(Some);
    }
    // `sys_getdents64` holds no lock either, and `proc_dir_read` writes
    // `entry.child_names` for the `/proc/iul/defaults` directories.
    let state = &mut *open_of(state);
    // The directory position is a cookie this file owns, and `fd->offset` is
    // signed now that a file offset is. proc_dir_read counts up from zero and
    // never goes negative, so the round trip is exact.
    let mut index = (pos - DOTS) as c_ulong;
    let next = entry::proc_dir_read(&mut state.entry, &mut index);
    fd.set_offset(index as i64 + DOTS);
    let Some(mut next) = next else {
        return Ok(None);
    };

    let mut buf = [0u8; MAX_NAME + 1];
    entry::proc_entry_getname(&mut next, &mut buf);
    let inode = inode::for_entry(next.meta, next.pid, next.fd);
    let type_ = dirent_type(entry::proc_entry_mode(&mut next) as u32);
    dir_entry(ffi::path_bytes(&buf), inode, type_).map(Some)
}

fn dir_entry(name: &[u8], inode: u64, type_: u8) -> Result<ffi::dir_entry, c_int> {
    let mut out = ffi::dir_entry { inode, type_, ..Default::default() };
    if name.len() >= out.name.len() {
        return Err(ENAMETOOLONG);
    }
    for (slot, &byte) in out.name.iter_mut().zip(name) {
        *slot = byte as c_char;
    }
    out.name[name.len()] = 0;
    Ok(out)
}

// ============================================================
// Helpers and tables
// ============================================================

// `cstr(p: *const c_char) -> &'a [u8]` was here until 2026-09-14, as it was in
// `fs/devpts` and `fs/tmpfs`. `FsOps` hands over a `&CStr`, so there is no
// unbounded lifetime to invent and no null to guard.

/// procfs's descriptor driver.
///
/// Positional only: a procfs file is generated in full when it is first read
/// and then served out of that buffer, so `pread` is the natural operation and
/// the plain `read` is `crates/kernel/rwcalls` seeking and calling it — which
/// is what [`ffi::Caps`] saying `read_at` and `seek` but not `read` asks for.
struct ProcfsFd;

static PROCFS_FDOPS: ProcfsFd = ProcfsFd;

impl ffi::FdOps for ProcfsFd {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps {
            read_at: true,
            write_at: true,
            seek: true,
            read: false,
            write: false,
        }
    }
    fn pread(&self, fd: &ffi::fd, buf: &mut [u8], off: i64) -> isize {
        proc_pread(fd, buf, off)
    }
    fn pwrite(&self, fd: &ffi::fd, buf: &[u8], off: i64) -> isize {
        proc_pwrite(fd, buf, off)
    }
    fn lseek(&self, fd: &ffi::fd, off: i64, whence: c_int) -> i64 {
        proc_seek(fd, off, whence)
    }
    fn readdir(&self, fd: &ffi::fd) -> Result<Option<ffi::dir_entry>, c_int> {
        proc_readdir(fd)
    }
}

/// procfs: a generated tree. Seven operations out of twenty-three.
///
/// `unlink` is there because `/proc/<pid>/task/<tid>` and the like can be
/// removed in the sense Linux means; nothing else here makes or renames a
/// name, so those reach the trait's `_EPERM`.
///
/// **No extended attributes.** Linux's procfs and devpts have none either, and
/// the default is `_EOPNOTSUPP`: "this filesystem does not support extended
/// attributes", which is a different answer from the `_EPERM` a namespace rule
/// gives.
pub struct Procfs;

impl ffi::FsOps for Procfs {
    fn name(&self) -> Option<&'static std::ffi::CStr> {
        Some(c"proc")
    }
    fn magic(&self) -> u32 {
        0x9fa0
    }
    fn open(&self,
        mount: &ffi::mount,
        path: &CStr,
        flags: c_int,
        mode: c_int,
    ) -> Result<Box<ffi::fd>, Errno> {
        proc_open(mount, path, flags, mode)
    }
    fn readlink(&self,
        mount: &ffi::mount,
        path: &CStr,
        buf: &mut [u8],
    ) -> isize {
        proc_readlink(mount, path, buf)
    }
    fn magic_link(&self, _mount: &ffi::mount, path: &CStr) -> Result<Option<ffi::FdOwned>, c_int> {
        let Ok((mut entry, _)) = lookup(path.to_bytes()) else {
            return Ok(None);
        };
        // A refusal here is the readlink's too, which reports it.
        if descriptor::guarded(&entry).is_err() {
            return Ok(None);
        }
        match entry.meta.and_then(|m| m.magic) {
            Some(magic) => magic(&mut entry),
            None => Ok(None),
        }
    }
    fn is_magic_link(&self, _mount: &ffi::mount, path: &CStr) -> bool {
        lookup(path.to_bytes()).is_ok_and(|(entry, _)| entry.meta.is_some_and(|m| m.jumps))
    }
    /// Every link here is generated from the task table, which is memory.
    fn links_in_memory(&self) -> bool {
        true
    }
    fn unlink(&self, mount: &ffi::mount, path: &CStr) -> c_int {
        proc_unlink(mount, path)
    }
    fn setattr(&self, _mount: &ffi::mount, path: &CStr, attr: ffi::Attr) -> c_int {
        match lookup(path.to_bytes()) {
            Ok(_) => proc_setattr(attr),
            Err(e) => e,
        }
    }
    fn fsetattr(&self, _fd: &ffi::fd, attr: ffi::Attr) -> c_int {
        proc_setattr(attr)
    }
    fn stat(
        &self,
        mount: &ffi::mount,
        path: &CStr,
    ) -> Option<Result<ffi::statbuf, c_int>> {
        Some(proc_stat(mount, path))
    }
    fn fstat(&self, fd: &ffi::fd) -> Option<Result<ffi::statbuf, c_int>> {
        Some(proc_fstat(fd))
    }
    fn permits_despite_mode(&self, _mount: &ffi::mount, path: &CStr, _want: c_int) -> bool {
        lookup(path.to_bytes()).is_ok_and(|(entry, _)| pidentry::own_group_passes(&entry))
    }
    fn getpath(&self, fd: &ffi::fd, buf: &mut [u8]) -> c_int {
        proc_getpath(fd, buf)
    }
}

/// The filesystem, and `iul.h`'s `extern const struct fs_ops procfs`.
#[unsafe(no_mangle)]
pub static procfs: ffi::FsHandle = ffi::FsHandle(&Procfs);

#[cfg(test)]
mod tests;
