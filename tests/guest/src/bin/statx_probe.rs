//! What `statx(2)` answers for a mask and a flags word, bit by bit.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! `statx` is the one stat call whose *answer shape* is an argument. The caller
//! asks for a set of fields with `mask` and the kernel reports back in
//! `stx_mask` which it actually filled — so it may give **less** than was asked
//! for (a field it does not track) or **more** (a field it had anyway). A wrong
//! bit in that word is completely silent: the field beside it is zero, which is
//! a legal value for most of them, and every caller that checks the mask before
//! reading is then told the truth about a lie.
//!
//! Nothing swept it. `fs_metadata` and `fs_conformance` call `statx` with
//! `STATX_BASIC_STATS` and read the fields; the argument space is 12 mask bits,
//! a reserved bit, 5 flag bits and a three-valued sync field, and this walks it.
//!
//! # What is comparable and what is not
//!
//! Values are not: an inode number, a device number, a block count and a
//! timestamp all differ between a container and this emulator for reasons that
//! are not defects. So a value is printed only where it must agree — `stx_size`
//! and `stx_mode` of a file this probe just made, and `stx_nlink` — and
//! everything else is printed as **which bits of `stx_mask` came back**, which
//! is the question.
//!
//! `STATX_ATTR_*` in `stx_attributes` is deliberately not compared: it reports
//! filesystem features (compression, encryption, verity) that belong to the
//! host filesystem underneath, and `stx_attributes_mask` says which of them the
//! answer is even about. Both are printed for the record and both are in
//! `probe_diff.sh`'s KNOWN if they differ.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<56} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::EBADF => "EBADF",
        libc::ENOENT => "ENOENT",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::ELOOP => "ELOOP",
        libc::ENOTDIR => "ENOTDIR",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

// `struct statx` is 256 bytes. Read it as bytes rather than as a type, because
// the layout is the thing under test and a libc struct would hide a field that
// moved.
const STATX_BYTES: usize = 256;

const ATTRIBUTES: usize = 8; // u64
const NLINK: usize = 16; // u32
const MODE: usize = 28; // u16
const SIZE: usize = 40; // u64
// 56, not 32. Offset 32 is `stx_ino`, and printing that as
// `stx_attributes_mask` gave a value that changed between two runs of the same
// binary -- which is what said the offset was wrong, because a filesystem's
// feature set does not.
const ATTRIBUTES_MASK: usize = 56; // u64
// `struct statx_timestamp` is 16 bytes: atime at 64, btime at 80, ctime at 96,
// mtime at 112. `crates/fs/statx` asserts the same offsets from the other side.
const BTIME_SEC: usize = 80;
const CTIME_SEC: usize = 96;
const MTIME_SEC: usize = 112;

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

const STATX_TYPE: u32 = 0x0001;
const STATX_MODE: u32 = 0x0002;
const STATX_NLINK: u32 = 0x0004;
const STATX_UID: u32 = 0x0008;
const STATX_GID: u32 = 0x0010;
const STATX_ATIME: u32 = 0x0020;
const STATX_MTIME: u32 = 0x0040;
const STATX_CTIME: u32 = 0x0080;
const STATX_INO: u32 = 0x0100;
const STATX_SIZE: u32 = 0x0200;
const STATX_BLOCKS: u32 = 0x0400;
const STATX_BTIME: u32 = 0x0800;
const STATX_MNT_ID: u32 = 0x1000;
const STATX_DIOALIGN: u32 = 0x2000;
const STATX_RESERVED: u32 = 0x8000_0000;

/// `stx_mask` as names, so a diff names the field rather than a hex word.
fn mask_names(m: u32) -> String {
    let bits = [
        (STATX_TYPE, "TYPE"),
        (STATX_MODE, "MODE"),
        (STATX_NLINK, "NLINK"),
        (STATX_UID, "UID"),
        (STATX_GID, "GID"),
        (STATX_ATIME, "ATIME"),
        (STATX_MTIME, "MTIME"),
        (STATX_CTIME, "CTIME"),
        (STATX_INO, "INO"),
        (STATX_SIZE, "SIZE"),
        (STATX_BLOCKS, "BLOCKS"),
        (STATX_BTIME, "BTIME"),
        (STATX_MNT_ID, "MNT_ID"),
        (STATX_DIOALIGN, "DIOALIGN"),
    ];
    let mut out: Vec<&str> = bits.iter().filter(|(b, _)| m & b != 0).map(|(_, n)| *n).collect();
    let known: u32 = bits.iter().fold(0, |a, (b, _)| a | b);
    let rest = m & !known;
    let extra;
    if rest != 0 {
        extra = format!("+{rest:#x}");
        out.push(&extra);
    }
    if out.is_empty() { "(none)".into() } else { out.join("|") }
}

const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
const AT_NO_AUTOMOUNT: i32 = 0x800;
const AT_EMPTY_PATH: i32 = 0x1000;
const AT_STATX_SYNC_AS_STAT: i32 = 0x0000;
const AT_STATX_FORCE_SYNC: i32 = 0x2000;
const AT_STATX_DONT_SYNC: i32 = 0x4000;

fn statx(dirfd: i32, path: &str, flags: i32, mask: u32) -> Result<[u8; STATX_BYTES], i32> {
    let mut buf = [0u8; STATX_BYTES];
    let c = std::ffi::CString::new(path).unwrap();
    let r = unsafe {
        libc::syscall(
            libc::SYS_statx,
            dirfd,
            c.as_ptr(),
            flags,
            mask,
            buf.as_mut_ptr(),
        )
    };
    if r < 0 { Err(errno()) } else { Ok(buf) }
}

/// One case: **did the asked-for fields come back**, or the errno.
///
/// Not the raw `stx_mask`, and that is the difference between a probe that
/// finds something and one that has thirty entries in `probe_diff.sh`'s KNOWN.
/// A kernel may return more than was asked for and may leave out what it does
/// not track, so the raw word depends on the filesystem underneath: a container
/// on overlayfs omits `MTIME`/`CTIME` unless they were asked for, and a 6.10
/// kernel adds `STATX_SUBVOL`, neither of which says anything about this
/// emulator. What *is* comparable is whether a field the caller asked for
/// arrived, because that is a statement about the kernel rather than the disk.
fn case(what: &str, path: &str, flags: i32, mask: u32) {
    match statx(libc::AT_FDCWD, path, flags, mask) {
        Ok(b) => {
            let got = u32_at(&b, 0);
            // The bits nobody may set are not "not returned", they are refused,
            // and that case never reaches here.
            let asked = mask & !STATX_RESERVED;
            let missing = asked & !got;
            line(
                what,
                if missing == 0 {
                    "every asked-for field".to_string()
                } else {
                    format!("missing {}", mask_names(missing))
                },
            )
        }
        Err(e) => line(what, named(e)),
    }
}

fn main() {
    // A directory of its own, so nothing another test left behind is read.
    let dir = "/tmp/statxprobe";
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).expect("scratch directory");
    let file = format!("{dir}/f");
    std::fs::write(&file, b"0123456789").expect("a file of ten bytes");
    let link = format!("{dir}/l");
    let _ = std::os::unix::fs::symlink("f", &link);

    println!("########## every mask bit alone ##########");
    for (bit, name) in [
        (STATX_TYPE, "STATX_TYPE"),
        (STATX_MODE, "STATX_MODE"),
        (STATX_NLINK, "STATX_NLINK"),
        (STATX_UID, "STATX_UID"),
        (STATX_GID, "STATX_GID"),
        (STATX_ATIME, "STATX_ATIME"),
        (STATX_MTIME, "STATX_MTIME"),
        (STATX_CTIME, "STATX_CTIME"),
        (STATX_INO, "STATX_INO"),
        (STATX_SIZE, "STATX_SIZE"),
        (STATX_BLOCKS, "STATX_BLOCKS"),
        (STATX_BTIME, "STATX_BTIME"),
        (STATX_MNT_ID, "STATX_MNT_ID"),
        (STATX_DIOALIGN, "STATX_DIOALIGN"),
    ] {
        case(&format!("mask={name}"), &file, 0, bit);
    }

    println!("\n########## masks that are not a single bit ##########");
    // 0 is legal and means "tell me nothing"; a kernel may still fill fields it
    // had anyway, and what `stx_mask` then says is the question.
    case("mask=0", &file, 0, 0);
    case("mask=STATX_BASIC_STATS", &file, 0, 0x07ff);
    case("mask=STATX_ALL", &file, 0, 0x0fff);
    case("mask=0xffffffff (includes RESERVED)", &file, 0, 0xffff_ffff);
    case("mask=STATX_RESERVED alone", &file, 0, STATX_RESERVED);
    case("mask=STATX_RESERVED|BASIC", &file, 0, STATX_RESERVED | 0x07ff);
    // Bits above STATX_DIOALIGN that Linux has not defined. Not reserved, so
    // not an error -- they should come back clear.
    // 0x4000 is `STATX_MNT_ID_UNIQUE`, added in Linux 6.10 -- a mount id that is
    // not reused for the life of the system, where `STATX_MNT_ID` may be. Not
    // implemented here, so the bit comes back clear, which is the honest answer
    // and what a caller checks the mask for.
    case("mask=STATX_MNT_ID_UNIQUE (6.10)", &file, 0, 0x4000);
    case("mask=0x7fff0000 (all undefined)", &file, 0, 0x7fff_0000);

    println!("\n########## flags ##########");
    for (f, name) in [
        (0, "0"),
        (AT_SYMLINK_NOFOLLOW, "AT_SYMLINK_NOFOLLOW"),
        (AT_NO_AUTOMOUNT, "AT_NO_AUTOMOUNT"),
        (AT_STATX_SYNC_AS_STAT, "AT_STATX_SYNC_AS_STAT"),
        (AT_STATX_FORCE_SYNC, "AT_STATX_FORCE_SYNC"),
        (AT_STATX_DONT_SYNC, "AT_STATX_DONT_SYNC"),
        (AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC, "both sync bits"),
        (AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT, "NOFOLLOW|NO_AUTOMOUNT"),
        (0x2, "AT_SYMLINK_FOLLOW (not a statx flag)"),
        (0x200, "AT_REMOVEDIR (not a statx flag)"),
        (0x4000_0000, "a bit nothing defines"),
        (-1, "every bit"),
    ] {
        case(&format!("flags={name}"), &file, f, 0x07ff);
    }

    println!("\n########## the symlink, followed and not ##########");
    case("symlink, flags=0", &link, 0, 0x07ff);
    case("symlink, AT_SYMLINK_NOFOLLOW", &link, AT_SYMLINK_NOFOLLOW, 0x07ff);
    case("symlink, asking for BTIME", &link, AT_SYMLINK_NOFOLLOW, STATX_BTIME);
    // The type bits are what tells the two apart, and they are in the mode.
    for (name, f) in [("followed", 0), ("not followed", AT_SYMLINK_NOFOLLOW)] {
        match statx(libc::AT_FDCWD, &link, f, 0x07ff) {
            Ok(b) => line(
                &format!("symlink {name}: S_IFMT"),
                format!("{:#o}", u16_at(&b, MODE) & 0o170000),
            ),
            Err(e) => line(&format!("symlink {name}: S_IFMT"), named(e)),
        }
    }

    println!("\n########## AT_EMPTY_PATH ##########");
    let fd = unsafe { libc::open(std::ffi::CString::new(file.clone()).unwrap().as_ptr(), libc::O_RDONLY) };
    let mut buf = [0u8; STATX_BYTES];
    let empty = std::ffi::CString::new("").unwrap();
    let r = unsafe {
        libc::syscall(libc::SYS_statx, fd, empty.as_ptr(), AT_EMPTY_PATH, 0x07ffu32, buf.as_mut_ptr())
    };
    if r < 0 {
        line("AT_EMPTY_PATH on a file descriptor", named(errno()));
    } else {
        let missing = 0x07ffu32 & !u32_at(&buf, 0);
        line(
            "AT_EMPTY_PATH on a file descriptor",
            if missing == 0 { "every asked-for field".to_string() } else { format!("missing {}", mask_names(missing)) },
        );
        line("  its size", u64_at(&buf, SIZE));
    }
    // Without AT_EMPTY_PATH an empty path is ENOENT, and that is the pair that
    // says the flag is read rather than ignored.
    let r = unsafe {
        libc::syscall(libc::SYS_statx, fd, empty.as_ptr(), 0, 0x07ffu32, buf.as_mut_ptr())
    };
    line(
        "empty path without AT_EMPTY_PATH",
        if r < 0 { named(errno()) } else { "0".into() },
    );
    unsafe { libc::close(fd) };

    println!("\n########## the whole mask, once, for the record ##########");
    // The one line that is not comparable, and it is here rather than spread
    // over forty: `probe_diff.sh`'s KNOWN carries it with the reason.
    match statx(libc::AT_FDCWD, &file, 0, 0x0fff) {
        Ok(b) => line("stx_mask for STATX_ALL, raw", mask_names(u32_at(&b, 0))),
        Err(e) => line("stx_mask for STATX_ALL, raw", named(e)),
    }

    println!("\n########## the values that must agree ##########");
    match statx(libc::AT_FDCWD, &file, 0, 0x07ff) {
        Ok(b) => {
            line("stx_size of a ten-byte file", u64_at(&b, SIZE));
            line("stx_mode & 07777", format!("{:#o}", u16_at(&b, MODE) & 0o7777));
            line("stx_mode & S_IFMT", format!("{:#o}", u16_at(&b, MODE) & 0o170000));
            line("stx_nlink", u32_at(&b, NLINK));
            // Printed rather than compared: these are the host filesystem's
            // features, and probe_diff.sh's KNOWN carries the difference.
            line("stx_attributes", format!("{:#x}", u64_at(&b, ATTRIBUTES)));
            line("stx_attributes_mask", format!("{:#x}", u64_at(&b, ATTRIBUTES_MASK)));
            // The values themselves are not comparable, but their *relations*
            // are, and they are what says a timestamp is real rather than a
            // zero with the mask bit set beside it.
            let btime = u64_at(&b, BTIME_SEC);
            let mtime = u64_at(&b, MTIME_SEC);
            let ctime = u64_at(&b, CTIME_SEC);
            let has_btime = u32_at(&b, 0) & STATX_BTIME != 0;
            line("STATX_BTIME reported", has_btime);
            line("  btime is after the epoch", btime > 0);
            line("  btime <= mtime of a file just written", btime <= mtime);
            line("  btime <= ctime", btime <= ctime);
            line("  btime within an hour of mtime", mtime.saturating_sub(btime) < 3600);
        }
        Err(e) => line("a plain statx", named(e)),
    }

    println!("\n########## the directory and a missing name ##########");
    case("the directory itself", dir, 0, 0x07ff);
    case("a name that is not there", &format!("{dir}/nope"), 0, 0x07ff);
    case("a path through a non-directory", &format!("{file}/x"), 0, 0x07ff);

    println!("\n########## a bad buffer ##########");
    let c = std::ffi::CString::new(file.clone()).unwrap();
    let r = unsafe {
        libc::syscall(libc::SYS_statx, libc::AT_FDCWD, c.as_ptr(), 0, 0x07ffu32, 1usize as *mut u8)
    };
    line(
        "statx into address 1",
        if r < 0 { named(errno()) } else { "0".into() },
    );
    // A bad buffer with an invalid mask: which is checked first is observable,
    // and Linux checks the arguments before it looks anything up.
    let r = unsafe {
        libc::syscall(
            libc::SYS_statx, libc::AT_FDCWD, c.as_ptr(), 0, STATX_RESERVED, 1usize as *mut u8,
        )
    };
    line(
        "bad buffer AND reserved mask",
        if r < 0 { named(errno()) } else { "0".into() },
    );
    // And an invalid mask with a path that does not exist: EINVAL before
    // ENOENT says the mask is checked before the lookup.
    let nope = std::ffi::CString::new(format!("{dir}/nope")).unwrap();
    let r = unsafe {
        libc::syscall(
            libc::SYS_statx, libc::AT_FDCWD, nope.as_ptr(), 0, STATX_RESERVED, buf.as_mut_ptr(),
        )
    };
    line(
        "reserved mask AND a missing path",
        if r < 0 { named(errno()) } else { "0".into() },
    );

    println!("\n########## a bad descriptor ##########");
    let r = unsafe {
        libc::syscall(libc::SYS_statx, 9999, c.as_ptr(), 0, 0x07ffu32, buf.as_mut_ptr())
    };
    line(
        "statx(9999, \"/tmp/...\") -- an absolute path",
        if r < 0 { named(errno()) } else { "0".into() },
    );
    let rel = std::ffi::CString::new("f").unwrap();
    let r = unsafe {
        libc::syscall(libc::SYS_statx, 9999, rel.as_ptr(), 0, 0x07ffu32, buf.as_mut_ptr())
    };
    line(
        "statx(9999, \"f\") -- a relative path",
        if r < 0 { named(errno()) } else { "0".into() },
    );

    let _ = std::fs::remove_dir_all(dir);
}
