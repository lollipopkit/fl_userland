//! `getdents64`: the loop around the record format.
//!
//! `crates/fs/dirent` owns the format — a `Vec<u8>` that knows its own length,
//! after the C built each record into a stack buffer sized by an expression that
//! had to agree with the one inside the fill function and did not, once
//! eight-byte rounding was added to only one of them. What is here is the loop:
//! the descriptor, the mount's `readdir`, and the one write into guest memory
//! at the end.
//!
//! # The entry that did not fit goes back
//!
//! A directory stream has a position, and reading an entry advances it. So the
//! entry that overflows the caller's buffer has already been consumed by the
//! time it is known not to fit, and the position is rewound to before it.
//! Without that a caller whose buffer filled up on a long name lost that entry
//! **and every one after it**: the next call started from the same place, read
//! the same too-long entry, and answered zero again — which is what "end of
//! directory" means.
//!
//! And a buffer too small for even one entry is `EINVAL`. Answering zero said
//! the directory was empty.
//!
//! # The whole sequence is one operation, and is held under `fd->lock`
//!
//! A listing is a `telldir`, a run of `readdir`s and a `seekdir` back to the
//! entry that did not fit. None of that is atomic against another syscall on
//! the same descriptor by itself, and Linux serialises it twice over:
//! `getdents64` enters through `fdget_pos`, which takes `f_pos_lock` whenever
//! the description is shared, and `iterate_dir` takes the inode's `i_rwsem`.
//! Sharing a descriptor is ordinary — `dup`, or `CLONE_FILES`, which every
//! pthread is.
//!
//! This took no lock at all until 2026-09-14, and what that cost was not the
//! interleaved listing: **both mounts install per-descriptor state lazily, on
//! the first listing**, so two threads that reach it together both build one
//! and both store it. `crates/fs/realfs`'s `open_stream` leaked a `DIR *` and
//! the host descriptor inside it — 1990 times in 2000 rounds, measured — which
//! is a resource an unprivileged guest can exhaust; `crates/fs/fake`'s
//! `dir_path` leaked a four-kilobyte cache and left two threads writing one.
//!
//! The guest memory write is outside the lock, which is what `sys_pread` does
//! for the same reason: it takes the address space's lock, and there is no
//! reason to order that inside this one.


use std::ffi::{c_int, c_ulong};

use dirent::DirentBuf;
use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/// Where the stream is now.
///
/// The `fd->offset` fallback that used to be here is [`ffi::FdOps::telldir`]'s
/// default body, next to the operation it stands in for.
fn telldir(fd: &ffi::fd) -> c_ulong {
    match fd.ops {
        Some(ops) => ops.telldir(fd),
        None => fd.offset() as c_ulong,
    }
}

fn seekdir(fd: &ffi::fd, off: c_ulong) {
    fd.set_offset(off as _);
    if let Some(ops) = fd.ops {
        ops.seekdir(fd, off);
    }
}

// `name_of` was here until 2026-09-15: a second copy of `dir_entry::name`,
// which is the type's own now.
/// The one syscall here. See the module comment for the rewind.
pub fn sys_getdents64(f: c_int, dirents: u64, count: u32) -> Result<c_int, Errno> {
    strace!("getdents64({f}, {dirents:#x}, {count:#x})");
    let fd = fs_fdobj::f_get(f).ok_or(Errno::EBADF)?;
    // An O_PATH descriptor names the directory without being able to read it,
    // and Linux's `iterate_dir` reaches it through `f_op->iterate`, which an
    // O_PATH file does not have -- `EBADF`, the same answer every other
    // operation gives one. It used to read the directory.
    if fd.is_path_only() {
        return Err(Errno::EBADF);
    }
    let is_dir = fd.type_ as u32 & ffi::S_IFMT == ffi::S_IFDIR;
    // A driver with no directories answers `ENOTDIR` from
    // `FdOps::readdir`'s default body, so the type test is the only thing
    // that has to be made here.
    let Some(ops) = fd.ops.filter(|_| is_dir) else {
        return Err(Errno::ENOTDIR);
    };

    let mut buf = DirentBuf::new(count as usize);
    let mut too_small = false;

    {
        // See the module comment: the whole sequence is one operation on the
        // stream, and the guest memory write below is deliberately outside it.
        let fd = &*fd;
        let _guard = fs_fdobj::FdGuard::new(fd);
        // Where the entry that does not fit begins, so it can be put back.
        // Assigned at the top of every pass, and the loop always makes one.
        let mut ptr;
        loop {
            ptr = telldir(fd);
            // `readdir` answers the entry, `None` at the end, or a negative
            // guest errno -- three states in the type since 2026-09-16, where
            // they were `1`, `0` and a negative in one `int` beside a buffer
            // this loop had to zero first. The errno is passed on unaltered;
            // `from_negative_or_eio` is the one place that says a number
            // outside the errno range would have been read as success.
            let answer = ops.readdir(fd);
            let Some(entry) = answer.map_err(Errno::from_negative_or_eio)? else {
                break;
            };
            let offset = telldir(fd) as i64;
            if !buf.push(entry.inode, offset, entry.type_, entry.name()) {
                too_small = buf.as_slice().is_empty();
                break;
            }
        }

        // Put the entry that did not fit back before answering, so a caller
        // that grows its buffer and retries sees it.
        seekdir(fd, ptr);
    }

    if too_small {
        return Err(Errno::EINVAL);
    }
    let bytes = buf.as_slice();
    if bytes.is_empty() {
        return Ok(0);
    }
    if GuestMem::current().write(dirents, bytes) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(bytes.len() as c_int)
}

// The two tests that were here -- a name stops at its terminator, and an
// unterminated one stops at the array -- moved with `name_of` onto
// `ffi::dir_entry`, which is where the buffer is.
