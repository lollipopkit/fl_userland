//! Guest filesystem metadata layouts shared across ABI consumers.

use crate::{dword_t, qword_t, sdword_t, sqword_t};

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct statbuf {
    pub dev: qword_t,
    pub inode: qword_t,
    pub mode: dword_t,
    pub nlink: dword_t,
    pub uid: dword_t,
    pub gid: dword_t,
    pub rdev: qword_t,
    pub size: qword_t,
    pub blksize: dword_t,
    pub blocks: qword_t,
    pub atime: i64,
    pub atime_nsec: dword_t,
    pub btime_nsec: dword_t,
    pub mtime: i64,
    pub mtime_nsec: dword_t,
    pub has_btime: dword_t,
    pub ctime: i64,
    pub ctime_nsec: dword_t,
    pub mount_id: u32,
    pub btime: i64,
}
const _: () = {
    assert!(std::mem::size_of::<statbuf>() == 120, "Size of statbuf");
    assert!(std::mem::align_of::<statbuf>() == 8, "Alignment of statbuf");
    assert!(
        std::mem::offset_of!(statbuf, dev) == 0,
        "Offset of field: statbuf::dev"
    );
    assert!(
        std::mem::offset_of!(statbuf, inode) == 8,
        "Offset of field: statbuf::inode"
    );
    assert!(
        std::mem::offset_of!(statbuf, mode) == 16,
        "Offset of field: statbuf::mode"
    );
    assert!(
        std::mem::offset_of!(statbuf, nlink) == 20,
        "Offset of field: statbuf::nlink"
    );
    assert!(
        std::mem::offset_of!(statbuf, uid) == 24,
        "Offset of field: statbuf::uid"
    );
    assert!(
        std::mem::offset_of!(statbuf, gid) == 28,
        "Offset of field: statbuf::gid"
    );
    assert!(
        std::mem::offset_of!(statbuf, rdev) == 32,
        "Offset of field: statbuf::rdev"
    );
    assert!(
        std::mem::offset_of!(statbuf, size) == 40,
        "Offset of field: statbuf::size"
    );
    assert!(
        std::mem::offset_of!(statbuf, blksize) == 48,
        "Offset of field: statbuf::blksize"
    );
    assert!(
        std::mem::offset_of!(statbuf, blocks) == 56,
        "Offset of field: statbuf::blocks"
    );
    assert!(
        std::mem::offset_of!(statbuf, atime) == 64,
        "Offset of field: statbuf::atime"
    );
    assert!(
        std::mem::offset_of!(statbuf, atime_nsec) == 72,
        "Offset of field: statbuf::atime_nsec"
    );
    assert!(
        std::mem::offset_of!(statbuf, btime_nsec) == 76,
        "Offset of field: statbuf::btime_nsec"
    );
    assert!(
        std::mem::offset_of!(statbuf, mtime) == 80,
        "Offset of field: statbuf::mtime"
    );
    assert!(
        std::mem::offset_of!(statbuf, mtime_nsec) == 88,
        "Offset of field: statbuf::mtime_nsec"
    );
    assert!(
        std::mem::offset_of!(statbuf, has_btime) == 92,
        "Offset of field: statbuf::has_btime"
    );
    assert!(
        std::mem::offset_of!(statbuf, ctime) == 96,
        "Offset of field: statbuf::ctime"
    );
    assert!(
        std::mem::offset_of!(statbuf, ctime_nsec) == 104,
        "Offset of field: statbuf::ctime_nsec"
    );
    assert!(
        std::mem::offset_of!(statbuf, mount_id) == 108,
        "Offset of field: statbuf::mount_id"
    );
    assert!(
        std::mem::offset_of!(statbuf, btime) == 112,
        "Offset of field: statbuf::btime"
    );
};
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct stat_arm64 {
    pub dev: qword_t,
    pub ino: qword_t,
    pub mode: dword_t,
    pub nlink: dword_t,
    pub uid: dword_t,
    pub gid: dword_t,
    pub rdev: qword_t,
    pub __pad1: qword_t,
    pub size: sqword_t,
    pub blksize: sdword_t,
    pub __pad2: sdword_t,
    pub blocks: sqword_t,
    pub atime_: sqword_t,
    pub atime_nsec: qword_t,
    pub mtime_: sqword_t,
    pub mtime_nsec: qword_t,
    pub ctime_: sqword_t,
    pub ctime_nsec: qword_t,
    pub __unused4: dword_t,
    pub __unused5: dword_t,
}
const _: () = {
    assert!(
        std::mem::size_of::<stat_arm64>() == 128,
        "Size of stat_arm64"
    );
    assert!(
        std::mem::align_of::<stat_arm64>() == 8,
        "Alignment of stat_arm64"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, dev) == 0,
        "Offset of field: stat_arm64::dev"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, ino) == 8,
        "Offset of field: stat_arm64::ino"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, mode) == 16,
        "Offset of field: stat_arm64::mode"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, nlink) == 20,
        "Offset of field: stat_arm64::nlink"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, uid) == 24,
        "Offset of field: stat_arm64::uid"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, gid) == 28,
        "Offset of field: stat_arm64::gid"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, rdev) == 32,
        "Offset of field: stat_arm64::rdev"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, __pad1) == 40,
        "Offset of field: stat_arm64::__pad1"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, size) == 48,
        "Offset of field: stat_arm64::size"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, blksize) == 56,
        "Offset of field: stat_arm64::blksize"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, __pad2) == 60,
        "Offset of field: stat_arm64::__pad2"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, blocks) == 64,
        "Offset of field: stat_arm64::blocks"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, atime_) == 72,
        "Offset of field: stat_arm64::atime_"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, atime_nsec) == 80,
        "Offset of field: stat_arm64::atime_nsec"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, mtime_) == 88,
        "Offset of field: stat_arm64::mtime_"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, mtime_nsec) == 96,
        "Offset of field: stat_arm64::mtime_nsec"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, ctime_) == 104,
        "Offset of field: stat_arm64::ctime_"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, ctime_nsec) == 112,
        "Offset of field: stat_arm64::ctime_nsec"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, __unused4) == 120,
        "Offset of field: stat_arm64::__unused4"
    );
    assert!(
        std::mem::offset_of!(stat_arm64, __unused5) == 124,
        "Offset of field: stat_arm64::__unused5"
    );
};
/// What a filesystem knows about its own space.
///
/// **Not a wire format.** The guest sees `statfs_arm64_`, which
/// `crates/kernel/fdattr` builds field by field; this is the internal shape,
/// so it is an ordinary Rust struct. It was `#[repr(C)]` with a `spare:
/// [c_long; 4]` and eleven offset assertions until 2026-09-16 — the layout a C
/// `struct statfs` had, checked against nothing since the headers went on
/// 2026-09-09.
///
/// # The three `Option`s are "the filesystem did not answer"
///
/// They were `c_long` with **zero** meaning that, which is a sentinel three
/// ways wrong: a `bsize` of 0 is not a block size, a `namelen` of 0 is not a
/// name limit, and `flags` of 0 is a perfectly ordinary answer that no
/// filesystem could give — Linux has the same problem in its guest-facing
/// struct and solves it with an `ST_VALID` bit, which `fdattr` sets.
///
/// `crates/kernel/fdattr` completes each one; see `write_statfs`.
#[derive(Debug, Default, Copy, Clone)]
pub struct statfsbuf {
    /// The block size a caller multiplies a block count by. `None` from a
    /// filesystem with no blocks of its own.
    pub bsize: Option<std::ffi::c_long>,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: u64,
    /// `_PC_NAME_MAX`. `None` from one that does not bound a name itself.
    pub namelen: Option<std::ffi::c_long>,
    pub frsize: std::ffi::c_long,
    /// The `ST_*` mount flags. `None` from every filesystem here — the mount
    /// knows them, not the filesystem — which is why it has stayed a
    /// completion rather than becoming an argument.
    pub flags: Option<std::ffi::c_long>,
}

/* `type_` was the first field, and it was **`magic()` written twice**:
 * `write_statfs` filled it from `FsOps::magic` whenever a filesystem left it
 * at zero, and the one filesystem that set it — tmpfs — set it to
 * `0x01021994`, which is exactly what its own `magic()` answers, in another
 * file. One value, two owners, agreeing by luck. The field is gone and
 * `magic()` is the owner; see `tools/one-owner.py` for the class. */

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
/// The guest's `statfs`, LP64 throughout. This is the kernel's layout for a
/// 64-bit architecture, with one exception worth naming: `fsid_t` is still
/// `{ int val[2]; }` and so is **8 bytes, not 16**.
pub struct statfs_arm64_ {
    pub type_: u64,
    pub bsize: u64,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: [i32; 2usize],
    pub namelen: u64,
    pub frsize: u64,
    pub flags: u64,
    pub spare: [u64; 4usize],
}
const _: () = {
    assert!(
        std::mem::size_of::<statfs_arm64_>() == 120,
        "Size of statfs_arm64_"
    );
    assert!(
        std::mem::align_of::<statfs_arm64_>() == 8,
        "Alignment of statfs_arm64_"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, type_) == 0,
        "Offset of field: statfs_arm64_::type_"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, bsize) == 8,
        "Offset of field: statfs_arm64_::bsize"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, blocks) == 16,
        "Offset of field: statfs_arm64_::blocks"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, bfree) == 24,
        "Offset of field: statfs_arm64_::bfree"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, bavail) == 32,
        "Offset of field: statfs_arm64_::bavail"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, files) == 40,
        "Offset of field: statfs_arm64_::files"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, ffree) == 48,
        "Offset of field: statfs_arm64_::ffree"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, fsid) == 56,
        "Offset of field: statfs_arm64_::fsid"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, namelen) == 64,
        "Offset of field: statfs_arm64_::namelen"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, frsize) == 72,
        "Offset of field: statfs_arm64_::frsize"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, flags) == 80,
        "Offset of field: statfs_arm64_::flags"
    );
    assert!(
        std::mem::offset_of!(statfs_arm64_, spare) == 88,
        "Offset of field: statfs_arm64_::spare"
    );
};

plain::plain! {
    stat_arm64 {
        dev, ino, mode, nlink, uid, gid, rdev, __pad1, size, blksize, __pad2, blocks,
        atime_, atime_nsec, mtime_, mtime_nsec, ctime_, ctime_nsec, __unused4, __unused5,
    }
    statfs_arm64_ {
        type_, bsize, blocks, bfree, bavail, files, ffree, fsid, namelen, frsize, flags, spare,
    }
}
