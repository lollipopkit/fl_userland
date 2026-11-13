//! A host `struct stat` as the guest's `struct statbuf`.
//!
//! The two differ in field widths and in where the nanosecond parts of the
//! timestamps live — Darwin spells them `st_atimespec`, Linux `st_atim` —
//! which in C was a pair of macros selected by `#ifdef`. The `libc` crate
//! already picks the right one per target, so the choice does not have to be
//! made again here.

//! # `as i64` on a host `libc` field is not redundant
//!
//! `clippy::unnecessary_cast` reports the `time_t` and `suseconds_t` casts
//! here because those are already `i64` on this target. They are `i32` on a
//! 32-bit host, which this tree compiles on — `differential.sh` runs the
//! guest tests in a Linux container and the host tools build wherever they
//! are. The lint sees one target.
#![allow(clippy::unnecessary_cast)]

use crate::dev;
use crate::ffi;

pub fn convert(host: &libc::stat) -> ffi::statbuf {
    ffi::statbuf {
        dev: dev::fake_from_real(host.st_dev as libc::dev_t) as u64,
        inode: host.st_ino,
        mode: host.st_mode as u32,
        nlink: host.st_nlink as u32,
        uid: host.st_uid,
        gid: host.st_gid,
        rdev: dev::fake_from_real(host.st_rdev as libc::dev_t) as u64,
        size: host.st_size as u64,
        blksize: host.st_blksize as u32,
        blocks: host.st_blocks as u64,
        // i64, not u32. These were narrowed to unsigned 32 bits, so a file
        // dated before 1970 arrived as one dated after 2096 -- the host
        // reports -315619200 for 1960 and the guest was told 3979348096.
        atime: host.st_atime as i64,
        mtime: host.st_mtime as i64,
        ctime: host.st_ctime as i64,
        atime_nsec: host.st_atime_nsec as u32,
        mtime_nsec: host.st_mtime_nsec as u32,
        ctime_nsec: host.st_ctime_nsec as u32,
        // Creation time, which Darwin has and Linux's `struct stat` does not --
        // there it is `statx` only. This kernel's hosts are macOS and iOS, so
        // the `cfg` is about a build that does not exist rather than one that
        // does; it is here so the crate still compiles if one ever does, with
        // `has_btime` zero and `STATX_BTIME` staying clear, which is the
        // "we do not know" the flag exists for.
        btime: host.st_birthtime,
        btime_nsec: host.st_birthtime_nsec as u32,
        has_btime: 1,
        // Which mount, which a filesystem does not know about itself: the VFS
        // fills it in, in `generic_statat`.
        mount_id: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn a_real_file_survives_the_conversion() {
        let path = scratch("stat-test");
        std::fs::write(&path, b"0123456789").unwrap();
        let meta = std::fs::metadata(&path).unwrap();

        let host = rustix::fs::stat(&path).unwrap();

        let guest = convert(&host);
        assert_eq!(guest.size, 10);
        assert_eq!(guest.inode, meta.ino());
        assert_eq!(guest.uid, meta.uid());
        assert_eq!(guest.gid, meta.gid());
        assert_eq!(guest.nlink, meta.nlink() as u32);
        assert_eq!(guest.mode & 0o777, meta.mode() & 0o777);
        assert!(guest.mode & libc::S_IFMT as u32 == libc::S_IFREG as u32);
        // A regular file's rdev is 0, and 0 must not encode to anything else.
        assert_eq!(guest.rdev, 0);
        assert!(guest.mtime > 0);

        std::fs::remove_file(&path).ok();
    }

    /// A scratch path nothing else can be using.
    ///
    /// These were fixed names in the shared temp directory, and two `cargo
    /// test` runs at once then raced over the same file — one removed it while
    /// the other was about to `stat` it, and the failure reads as a bug in the
    /// conversion. It is the rule `CLAUDE.md` states for the guest probes,
    /// which applies here for the same reason: **give each run its own
    /// scratch**.
    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("realfs-rs-{name}-{}", std::process::id()))
    }

    #[test]
    fn nanoseconds_come_from_the_right_field() {
        // Whichever spelling the host uses, the nanosecond part has to be a
        // sub-second value and not, say, a whole timestamp copied twice.
        let path = scratch("stat-nsec");
        std::fs::write(&path, b"x").unwrap();
        let host = rustix::fs::stat(&path).unwrap();

        let guest = convert(&host);
        for nsec in [guest.atime_nsec, guest.mtime_nsec, guest.ctime_nsec] {
            assert!(nsec < 1_000_000_000, "{nsec} is not a nanosecond remainder");
        }
        std::fs::remove_file(&path).ok();
    }
}
