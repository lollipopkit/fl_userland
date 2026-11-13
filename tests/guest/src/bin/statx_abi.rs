//! `statx(2)`: the fields it fills, the mask it reports, and what it refuses.
//!
//! Modern glibc, musl and Rust's `std::fs::metadata` all reach `stat` through
//! this, so a wrong answer here is wrong for every program that looks at a
//! file. Two things are easy to get wrong and silent when you do:
//!
//! - **`stx_mask` must describe what was actually filled.** A caller reads a
//!   field only if its bit is set, so claiming a bit for a field left at zero
//!   reports a birth time of the epoch, or a link count of none, as fact.
//! - **The arguments are not validated by the caller.** `flags` and `mask`
//!   both have reserved ranges, and a kernel that ignores them tells a program
//!   probing for a feature that it has it.
//!
//! Every assertion here was established by running this against a real arm64
//! kernel, not from a man page — `statx(2)` does not say what the reserved
//! ranges are.

use guest_tests::{Harness, check, check_fails, cpath, sys};

/// `STATX_BASIC_STATS` is the eleven bits below it: type, mode, nlink, uid,
/// gid, atime, mtime, ctime, ino, size, blocks. Spelled as the constant rather
/// than one-by-one because that is how a caller asks for them.
const STATX_SIZE: u32 = 1 << 9;
const STATX_BASIC_STATS: u32 = 0x7ff;
const STATX_BTIME: u32 = 1 << 11;
/// The bit no caller may set. `statx(2)` does not name it.
const STATX_RESERVED: u32 = 0x8000_0000;

const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
const AT_EMPTY_PATH: i32 = 0x1000;
const AT_STATX_SYNC_AS_STAT: i32 = 0x0000;
const AT_STATX_FORCE_SYNC: i32 = 0x2000;
const AT_STATX_DONT_SYNC: i32 = 0x4000;
const AT_STATX_SYNC_TYPE: i32 = 0x6000;

/// The 256 bytes `statx` writes, read by offset rather than through a struct.
/// The offsets are what is under test.
struct Statx([u8; 256]);

impl Statx {
    fn new() -> Statx {
        Statx([0xAB; 256])
    }
    fn u16_at(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.0[at], self.0[at + 1]])
    }
    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
    }
    fn u64_at(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.0[at..at + 8].try_into().unwrap())
    }
    fn mask(&self) -> u32 {
        self.u32_at(0)
    }
}

fn statx(dirfd: i32, path: &str, flags: i32, mask: u32, buf: &mut Statx) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_statx,
            dirfd,
            cpath(path).as_ptr(),
            flags,
            mask,
            buf.0.as_mut_ptr(),
        )
    }
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/statx".into());
    let _ = std::fs::create_dir_all(&dir);
    let file = format!("{dir}/f");
    std::fs::write(&file, b"0123456789").expect("write the file");

    let mut h = Harness::new();

    h.group("basics");
    let mut sx = Statx::new();
    let r = statx(libc::AT_FDCWD, &file, 0, STATX_BASIC_STATS, &mut sx);
    check!(h, r == 0, "statx of a plain file: {r} errno {}", sys::errno());
    // Offsets from include/uapi/linux/stat.h.
    check!(h, sx.u32_at(4) > 0, "stx_blksize is set: {}", sx.u32_at(4));
    check!(h, sx.u32_at(16) >= 1, "stx_nlink is at least 1: {}", sx.u32_at(16));
    check!(h, u32::from(sx.u16_at(28)) & 0o170000 == 0o100000,
        "stx_mode says regular file: {:o}", sx.u16_at(28));
    check!(h, sx.u64_at(40) == 10, "stx_size is the file's: {}", sx.u64_at(40));
    check!(h, sx.u64_at(32) != 0, "stx_ino is set");

    h.group("mask");
    // Every bit the mask claims must name a field that was filled, and every
    // field a caller reads must have had its bit claimed. The two that catch a
    // kernel reporting a constant are BTIME -- which most filesystems do not
    // have -- and the basic set, which every one does.
    check!(
        h,
        sx.mask() & STATX_BASIC_STATS == STATX_BASIC_STATS,
        "the basic fields are all claimed: {:#x}",
        sx.mask()
    );
    check!(
        h,
        sx.mask() & STATX_RESERVED == 0,
        "and the reserved bit is not claimed: {:#x}",
        sx.mask()
    );
    // btime is the honest one: if the bit is clear the field is meaningless,
    // and if it is set the field must not be zero, because no file was created
    // at the epoch.
    let btime_claimed = sx.mask() & STATX_BTIME != 0;
    let btime = sx.u64_at(80);
    check!(
        h,
        !btime_claimed || btime != 0,
        "btime is claimed only when it is known: claimed={btime_claimed} sec={btime}"
    );

    // Asking for less than the basic set is allowed to return more -- Linux
    // says so -- but never fewer than were asked for *and* available.
    let mut small = Statx::new();
    let r = statx(libc::AT_FDCWD, &file, 0, STATX_SIZE, &mut small);
    check!(h, r == 0, "statx asking only for the size: {r}");
    check!(
        h,
        small.mask() & STATX_SIZE != 0,
        "reports the field that was asked for: {:#x}",
        small.mask()
    );
    check!(h, small.u64_at(40) == 10, "and fills it: {}", small.u64_at(40));

    // A mask of zero asks for nothing, which is not an error.
    let mut none = Statx::new();
    let r = statx(libc::AT_FDCWD, &file, 0, 0, &mut none);
    check!(h, r == 0, "a mask of zero is not an error: {r} errno {}", sys::errno());

    h.group("refusals");
    // The reserved bit is EINVAL, not ignored. A program probing for a field
    // this kernel does not have needs to be told.
    let mut buf = Statx::new();
    check_fails!(
        h,
        statx(libc::AT_FDCWD, &file, 0, STATX_RESERVED, &mut buf),
        libc::EINVAL,
        "a mask with the reserved bit"
    );
    check_fails!(
        h,
        statx(libc::AT_FDCWD, &file, 0, STATX_BASIC_STATS | STATX_RESERVED, &mut buf),
        libc::EINVAL,
        "the reserved bit alongside real ones"
    );
    // The sync-type field is two bits and all three of its values are legal;
    // both bits set at once is not.
    check_fails!(
        h,
        statx(libc::AT_FDCWD, &file, AT_STATX_SYNC_TYPE, STATX_BASIC_STATS, &mut buf),
        libc::EINVAL,
        "both sync-type bits at once"
    );
    // A flag outside the set statx defines.
    check_fails!(
        h,
        statx(libc::AT_FDCWD, &file, 0x8000, STATX_BASIC_STATS, &mut buf),
        libc::EINVAL,
        "a flag statx does not define"
    );
    // A path that is not there.
    check_fails!(
        h,
        statx(libc::AT_FDCWD, &format!("{dir}/absent"), 0, STATX_BASIC_STATS, &mut buf),
        libc::ENOENT,
        "statx of a path that does not exist"
    );

    h.group("flags-that-work");
    // Each sync type on its own is accepted; none of them changes the answer
    // for a local file.
    for (flag, name) in [
        (AT_STATX_SYNC_AS_STAT, "AT_STATX_SYNC_AS_STAT"),
        (AT_STATX_FORCE_SYNC, "AT_STATX_FORCE_SYNC"),
        (AT_STATX_DONT_SYNC, "AT_STATX_DONT_SYNC"),
    ] {
        let mut b = Statx::new();
        let r = statx(libc::AT_FDCWD, &file, flag, STATX_BASIC_STATS, &mut b);
        check!(h, r == 0, "{name} is accepted: {r} errno {}", sys::errno());
        check!(h, b.u64_at(40) == 10, "{name} still reports the size");
    }

    // AT_EMPTY_PATH with a descriptor and an empty path stats the descriptor.
    let fd = unsafe { libc::open(cpath(&file).as_ptr(), libc::O_RDONLY) };
    check!(h, fd >= 0, "open the file");
    let mut b = Statx::new();
    let r = statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &mut b);
    check!(h, r == 0, "AT_EMPTY_PATH on a descriptor: {r} errno {}", sys::errno());
    check!(h, b.u64_at(40) == 10, "and reports its size: {}", b.u64_at(40));
    // Without AT_EMPTY_PATH an empty path is ENOENT.
    check_fails!(
        h,
        statx(fd, "", 0, STATX_BASIC_STATS, &mut b),
        libc::ENOENT,
        "an empty path without AT_EMPTY_PATH"
    );

    // NOFOLLOW reports the link, not its target.
    let link = format!("{dir}/l");
    let _ = std::fs::remove_file(&link);
    unsafe { libc::symlink(cpath(&file).as_ptr(), cpath(&link).as_ptr()) };
    let mut lnk = Statx::new();
    let r = statx(libc::AT_FDCWD, &link, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS, &mut lnk);
    check!(h, r == 0, "statx of a symlink with NOFOLLOW: {r}");
    check!(
        h,
        u32::from(lnk.u16_at(28)) & 0o170000 == 0o120000,
        "reports the link itself: mode {:o}",
        lnk.u16_at(28)
    );
    let mut tgt = Statx::new();
    statx(libc::AT_FDCWD, &link, 0, STATX_BASIC_STATS, &mut tgt);
    check!(
        h,
        u32::from(tgt.u16_at(28)) & 0o170000 == 0o100000,
        "and without it, the target: mode {:o}",
        tgt.u16_at(28)
    );

    h.group("times-before-the-epoch");
    // A timestamp is signed. `struct statbuf` narrowed the seconds to an
    // unsigned 32-bit field, so a file dated before 1970 came back dated after
    // 2096 -- the host holds -315619200 for 1960 and the guest was told
    // 3979348096. Every program that compares timestamps then treats that file
    // as the newest thing on the disk: make, rsync, tar, git.
    let old_file = format!("{dir}/old");
    std::fs::write(&old_file, b"x").expect("write it");
    let want_sec: i64 = -315_619_200; // 1960-01-01
    let times = [
        libc::timespec { tv_sec: want_sec as _, tv_nsec: 0 },
        libc::timespec { tv_sec: want_sec as _, tv_nsec: 0 },
    ];
    let r = unsafe {
        libc::utimensat(libc::AT_FDCWD, cpath(&old_file).as_ptr(), times.as_ptr(), 0)
    };
    if r != 0 {
        println!("  SKIP  [times-before-the-epoch] utimensat refused it: errno {}", sys::errno());
    } else {
        let mut b = Statx::new();
        let r = statx(libc::AT_FDCWD, &old_file, 0, STATX_BASIC_STATS, &mut b);
        check!(h, r == 0, "statx of a file dated 1960: {r}");
        check!(
            h,
            b.u64_at(112) as i64 == want_sec,
            "stx_mtime is negative and unchanged: got {} want {want_sec}",
            b.u64_at(112) as i64
        );
        // And through the older stat too, whose field is also signed.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::stat(cpath(&old_file).as_ptr(), &mut st) };
        check!(h, r == 0, "stat of the same file: {r}");
        check!(
            h,
            st.st_mtime as i64 == want_sec,
            "st_mtime agrees: got {} want {want_sec}",
            st.st_mtime as i64
        );
    }

    h.group("whole-buffer");
    // statx writes all 256 bytes. A kernel that writes fewer leaves whatever
    // the caller had there, which a caller reads as a field.
    let mut probe = Statx::new();
    let r = statx(libc::AT_FDCWD, &file, 0, STATX_BASIC_STATS, &mut probe);
    check!(h, r == 0, "statx for the whole-buffer check");
    check!(
        h,
        !probe.0.iter().any(|&b| b == 0xAB) || probe.0[..0x100].iter().filter(|&&b| b == 0xAB).count() < 16,
        "the tail was written rather than left as the caller had it"
    );

    unsafe { libc::close(fd) };
    std::process::exit(h.finish());
}
