//! `statfs` output and descriptor/path entry points.

use std::ffi::c_int;

use strace::strace;
use usercopy::GuestMem;

use guest_errno::Errno;

use crate::{Fd, ffi};

/// The 120 bytes `statfs` reports on aarch64, from the mount's own answer.
///
/// The guest's structure is 64-bit throughout (LP64), which is why this is not
/// `statfs64`: there is one layout here and it is the wide one.
///
/// Safe since 2026-10-01; it took the mount as a nullable raw pointer, and
/// both callers hold a reference.
fn write_statfs(mount: Option<&ffi::mount>, buf_addr: u64) -> Result<(), Errno> {
    let Some((mount, fs)) = mount.and_then(|m| Some((m, m.fs?))) else {
        return Err(Errno::EBADF);
    };
    // A filesystem with nothing to say about its own space reaches the
    // trait's default, which answers a `statfsbuf::default()` -- every
    // completable field `None`. The completions below are what then answer,
    // and each is an `unwrap_or` rather than a test against zero: the three
    // used to be `if x == 0`, and a filesystem that legitimately meant zero
    // could not say so.
    let buf = fs.statfs(mount).map_err(Errno::from_negative_or_eio)?;

    // What a mount that answered only about space leaves unset. Linux fills
    // all three for every filesystem there is, and a caller reads them:
    // `f_bsize` is what `du` multiplies by, `f_namelen` is what `pathconf`
    // answers for `_PC_NAME_MAX`, and `f_flags` is how a program asks whether
    // the mount is read-only *before* it tries to write.
    //
    // They were left at zero by procfs, devpts and every ad-hoc descriptor:
    // `du` on `/proc` counted nothing, and `statvfs()->f_flag` said a
    // read-only bind mount was writable. Measured by `statfs_probe`.
    let bsize = buf.bsize.unwrap_or(4096);
    let namelen = buf.namelen.unwrap_or(ffi::MAX_NAME as i64 - 1);
    // `ST_VALID` says the kernel filled the field at all -- without it a
    // caller cannot tell "no flags" from "this kernel does not answer". Linux
    // sets it unconditionally in `calculate_f_flags`, and the rest from the
    // mount's own.
    const ST_VALID: i64 = 0x0020;
    let flags = buf.flags.unwrap_or_else(|| {
        let mount_flags = mount.flags;
        // A table rather than a chain of `|` and `*`. The chain was correct --
        // Rust binds `&` tighter than `!=`, unlike C, so each test read the
        // way it looks -- but `clippy::precedence` is right that a reader has
        // to know that to see it, and adding a row is now adding a row.
        let mut f = ST_VALID;
        for (flag, st) in [
            (ffi::MS_READONLY_, 0x0001i64),
            (ffi::MS_NOSUID_, 0x0002),
            (ffi::MS_NODEV_, 0x0004),
            (ffi::MS_NOEXEC_, 0x0008),
        ] {
            if mount_flags & flag as c_int != 0 {
                f |= st;
            }
        }
        f
    });
    let out = ffi::statfs_arm64_ {
        // The filesystem's magic, from the one place that has it. It used to
        // arrive through a `statfsbuf::type_` that `write_statfs` filled from
        // here anyway whenever it was zero.
        type_: fs.magic() as _,
        bsize: bsize as _,
        blocks: buf.blocks as _,
        bfree: buf.bfree as _,
        bavail: buf.bavail as _,
        files: buf.files as _,
        ffree: buf.ffree as _,
        fsid: [(buf.fsid & 0xFFFF_FFFF) as _, (buf.fsid >> 32) as _],
        namelen: namelen as _,
        frsize: buf.frsize as _,
        flags: flags as _,
        ..Default::default()
    };
    if GuestMem.write_value(buf_addr, &out) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

pub fn sys_fstatfs_arm64(num: c_int, buf_addr: u64) -> Result<(), Errno> {
    strace!("fstatfs({num}, {buf_addr:#x})");
    let fd = Fd::get(num)?;
    write_statfs(fd.mount(), buf_addr)
}

/// The same, for `statfs`, which resolves a path first — in
/// `crates/kernel/pathcalls`, which calls this as Rust.
pub fn statfs_mount(mount: &ffi::mount, buf_addr: u64) -> Result<(), Errno> {
    write_statfs(Some(mount), buf_addr)
}
