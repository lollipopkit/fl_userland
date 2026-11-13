//! Which operation moves which of a file's three timestamps, and what
//! `utimensat` accepts.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! # Why this exists
//!
//! `make`, `rsync`, `tar`, `git status` and every build system compare
//! timestamps, and a kernel that moves the wrong one — or fails to move one —
//! is a build that does not rebuild or one that never stops. The rules are
//! nobody's favourite reading: a write moves `mtime` and `ctime` and not
//! `atime`; a `chmod` moves `ctime` alone; a rename moves the *directory's*
//! and the file's `ctime`; `utimensat` with `UTIME_OMIT` moves neither but
//! still moves `ctime`.
//!
//! This tree has had one timestamp defect already — the seconds were `dword_t`,
//! so a file dated before 1970 came back dated after 2096 — and it was found by
//! reading. Nothing had compared the *rules* against a real kernel.
//!
//! # Nothing here prints a time
//!
//! A timestamp differs between two machines for reasons that are not
//! differences. Every answer is a classification: `moved`, `unchanged`, or
//! `set to what was asked`. Each case sleeps long enough that a coarse clock
//! still sees the change, which is what the second-granularity mounts need.

use std::ffi::{c_int, CString};
use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<54} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::ENOENT => "ENOENT",
        libc::EBADF => "EBADF",
        libc::EFAULT => "EFAULT",
        libc::EROFS => "EROFS",
        libc::ESRCH => "ESRCH",
        libc::ENOTDIR => "ENOTDIR",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn c(p: &str) -> CString {
    CString::new(p).unwrap()
}

#[derive(Clone, Copy, PartialEq)]
struct Times {
    atime: (i64, i64),
    mtime: (i64, i64),
    ctime: (i64, i64),
}

fn times(path: &str) -> Option<Times> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c(path).as_ptr(), &mut st) } < 0 {
        return None;
    }
    Some(Times {
        atime: (st.st_atime, st.st_atime_nsec),
        mtime: (st.st_mtime, st.st_mtime_nsec),
        ctime: (st.st_ctime, st.st_ctime_nsec),
    })
}

/// Which of the three moved. The order is fixed so the string is comparable.
fn moved(before: Times, after: Times) -> String {
    let mut out = Vec::new();
    if before.atime != after.atime {
        out.push("atime");
    }
    if before.mtime != after.mtime {
        out.push("mtime");
    }
    if before.ctime != after.ctime {
        out.push("ctime");
    }
    if out.is_empty() { "none".into() } else { out.join("+") }
}

/// Long enough that a mount with one-second timestamps still sees a change,
/// and short enough that the probe finishes.
fn tick() {
    std::thread::sleep(std::time::Duration::from_millis(1100));
}

const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

fn utimensat(path: &str, times: Option<[libc::timespec; 2]>, flags: c_int) -> c_int {
    let p = c(path);
    match times {
        Some(t) => unsafe { libc::utimensat(libc::AT_FDCWD, p.as_ptr(), t.as_ptr(), flags) },
        None => unsafe {
            libc::utimensat(libc::AT_FDCWD, p.as_ptr(), std::ptr::null(), flags)
        },
    }
}

fn rc(v: c_int) -> String {
    if v < 0 { named(errno()) } else { "0".into() }
}

fn main() {
    let dir = "/tmp/filetime_probe.d";
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();

    what_moves(dir);
    directory_times(dir);
    utimensat_rules(dir);
    old_and_odd_times(dir);

    let _ = std::fs::remove_dir_all(dir);
}

/// A fresh file for one case, so nothing carries over.
fn fresh(dir: &str, name: &str) -> String {
    let path = format!("{dir}/{name}");
    unsafe {
        let fd = libc::open(c(&path).as_ptr(), libc::O_CREAT | libc::O_TRUNC | libc::O_WRONLY, 0o644);
        libc::write(fd, b"hello".as_ptr().cast(), 5);
        libc::close(fd);
    }
    path
}

/// Which operation moves which timestamp.
fn what_moves(dir: &str) {
    println!("## what moves a timestamp");

    let p = fresh(dir, "w");
    let before = times(&p).unwrap();
    tick();
    unsafe {
        let fd = libc::open(c(&p).as_ptr(), libc::O_WRONLY | libc::O_APPEND);
        libc::write(fd, b"more".as_ptr().cast(), 4);
        libc::close(fd);
    }
    line("  a write", moved(before, times(&p).unwrap()));

    let p = fresh(dir, "r");
    let before = times(&p).unwrap();
    tick();
    unsafe {
        let fd = libc::open(c(&p).as_ptr(), libc::O_RDONLY);
        let mut buf = [0u8; 8];
        libc::read(fd, buf.as_mut_ptr().cast(), 8);
        libc::close(fd);
    }
    line("  a read", moved(before, times(&p).unwrap()));

    let p = fresh(dir, "o");
    let before = times(&p).unwrap();
    tick();
    unsafe {
        let fd = libc::open(c(&p).as_ptr(), libc::O_RDONLY);
        libc::close(fd);
    }
    line("  an open that reads nothing", moved(before, times(&p).unwrap()));

    let p = fresh(dir, "m");
    let before = times(&p).unwrap();
    tick();
    unsafe { libc::chmod(c(&p).as_ptr(), 0o600) };
    line("  a chmod", moved(before, times(&p).unwrap()));

    let p = fresh(dir, "t");
    let before = times(&p).unwrap();
    tick();
    unsafe { libc::truncate(c(&p).as_ptr(), 2) };
    line("  a truncate that shortens", moved(before, times(&p).unwrap()));

    let p = fresh(dir, "t2");
    let before = times(&p).unwrap();
    tick();
    unsafe { libc::truncate(c(&p).as_ptr(), 5) };
    line("  a truncate to the same size", moved(before, times(&p).unwrap()));

    let p = fresh(dir, "l");
    let before = times(&p).unwrap();
    tick();
    unsafe { libc::link(c(&p).as_ptr(), c(&format!("{dir}/l2")).as_ptr()) };
    line("  gaining a hard link", moved(before, times(&p).unwrap()));

    let p = fresh(dir, "n");
    let before = times(&p).unwrap();
    tick();
    unsafe { libc::rename(c(&p).as_ptr(), c(&format!("{dir}/n2")).as_ptr()) };
    line("  being renamed", moved(before, times(&format!("{dir}/n2")).unwrap()));

    // A read of a file that has just been written: with relatime, atime is
    // updated because it is older than mtime. This is the case that tells
    // relatime from noatime, and every distribution mounts relatime.
    let p = fresh(dir, "rel");
    tick();
    unsafe {
        let fd = libc::open(c(&p).as_ptr(), libc::O_RDONLY);
        let mut buf = [0u8; 8];
        libc::read(fd, buf.as_mut_ptr().cast(), 8);
        libc::close(fd);
    }
    let after_first = times(&p).unwrap();
    tick();
    unsafe {
        let fd = libc::open(c(&p).as_ptr(), libc::O_RDONLY);
        let mut buf = [0u8; 8];
        libc::read(fd, buf.as_mut_ptr().cast(), 8);
        libc::close(fd);
    }
    line("  a second read, atime already newer than mtime", moved(after_first, times(&p).unwrap()));
}

/// A directory's own times, which is what a program watching for new files
/// looks at.
fn directory_times(dir: &str) {
    println!("## a directory's times");
    let sub = format!("{dir}/d");
    let _ = std::fs::create_dir(&sub);

    let before = times(&sub).unwrap();
    tick();
    let _ = fresh(&sub, "a");
    line("  creating a file in it", moved(before, times(&sub).unwrap()));

    let before = times(&sub).unwrap();
    tick();
    unsafe { libc::unlink(c(&format!("{sub}/a")).as_ptr()) };
    line("  removing a file from it", moved(before, times(&sub).unwrap()));

    let before = times(&sub).unwrap();
    tick();
    let _ = fresh(&sub, "b");
    unsafe { libc::rename(c(&format!("{sub}/b")).as_ptr(), c(&format!("{sub}/c")).as_ptr()) };
    line("  a rename inside it", moved(before, times(&sub).unwrap()));

    let before = times(&sub).unwrap();
    tick();
    unsafe {
        let fd = libc::open(c(&sub).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        let mut buf = [0u8; 4096];
        libc::syscall(61, fd, buf.as_mut_ptr(), 4096usize);
        libc::close(fd);
    }
    line("  reading it", moved(before, times(&sub).unwrap()));

    let before = times(&sub).unwrap();
    tick();
    unsafe { libc::chmod(c(&sub).as_ptr(), 0o700) };
    line("  chmod on it", moved(before, times(&sub).unwrap()));
    unsafe { libc::chmod(c(&sub).as_ptr(), 0o755) };
}

/// `utimensat`'s own rules.
fn utimensat_rules(dir: &str) {
    println!("## utimensat");
    let p = fresh(dir, "u");

    // An explicit time, read back exactly.
    let want = [
        libc::timespec { tv_sec: 1_000_000_000, tv_nsec: 123_456_789 },
        libc::timespec { tv_sec: 1_100_000_000, tv_nsec: 987_654_321 },
    ];
    line("  setting both times", rc(utimensat(&p, Some(want), 0)));
    let t = times(&p).unwrap();
    line("    atime seconds are what was asked", (t.atime.0 == 1_000_000_000).to_string());
    line("    mtime seconds are what was asked", (t.mtime.0 == 1_100_000_000).to_string());
    line(
        "    the nanoseconds survived",
        (t.atime.1 == 123_456_789 && t.mtime.1 == 987_654_321).to_string(),
    );
    line("    ctime moved to now", (t.ctime.0 > 1_500_000_000).to_string());

    // UTIME_OMIT leaves one alone; UTIME_NOW sets the other to now.
    let before = times(&p).unwrap();
    tick();
    let mixed = [
        libc::timespec { tv_sec: 0, tv_nsec: UTIME_OMIT },
        libc::timespec { tv_sec: 0, tv_nsec: UTIME_NOW },
    ];
    line("  UTIME_OMIT on atime, UTIME_NOW on mtime", rc(utimensat(&p, Some(mixed), 0)));
    let after = times(&p).unwrap();
    line("    which moved", moved(before, after));

    // Both omitted: nothing changes, and Linux does not even move ctime.
    let before = times(&p).unwrap();
    tick();
    let both = [
        libc::timespec { tv_sec: 0, tv_nsec: UTIME_OMIT },
        libc::timespec { tv_sec: 0, tv_nsec: UTIME_OMIT },
    ];
    line("  both UTIME_OMIT", rc(utimensat(&p, Some(both), 0)));
    line("    which moved", moved(before, times(&p).unwrap()));

    // A null pointer means "both now".
    let before = times(&p).unwrap();
    tick();
    line("  a null times pointer", rc(utimensat(&p, None, 0)));
    line("    which moved", moved(before, times(&p).unwrap()));

    // The refusals.
    let bad_nsec = [
        libc::timespec { tv_sec: 0, tv_nsec: 1_000_000_000 },
        libc::timespec { tv_sec: 0, tv_nsec: 0 },
    ];
    line("  nsec = 1_000_000_000", rc(utimensat(&p, Some(bad_nsec), 0)));
    let neg_nsec = [
        libc::timespec { tv_sec: 0, tv_nsec: -1 },
        libc::timespec { tv_sec: 0, tv_nsec: 0 },
    ];
    line("  nsec = -1", rc(utimensat(&p, Some(neg_nsec), 0)));
    // A negative *second* is a date before 1970, which is legal.
    let old = [
        libc::timespec { tv_sec: -315_619_200, tv_nsec: 0 },
        libc::timespec { tv_sec: -315_619_200, tv_nsec: 0 },
    ];
    line("  a date in 1960", rc(utimensat(&p, Some(old), 0)));
    let t = times(&p).unwrap();
    line("    it reads back negative", (t.mtime.0 == -315_619_200).to_string());

    line("  a flag that means nothing", rc(utimensat(&p, Some(want), 0x40)));
    line("  a path that is not there", rc(utimensat(&format!("{dir}/nope"), Some(want), 0)));

    // futimens: the same rules through a descriptor.
    let fd = unsafe { libc::open(c(&p).as_ptr(), libc::O_RDONLY) };
    let now = [
        libc::timespec { tv_sec: 0, tv_nsec: UTIME_NOW },
        libc::timespec { tv_sec: 0, tv_nsec: UTIME_NOW },
    ];
    let r = unsafe { libc::futimens(fd, now.as_ptr()) };
    line("  futimens on a read-only descriptor", rc(r));
    unsafe { libc::close(fd) };
    // ...and on one that is not open at all.
    line("  futimens on -1", rc(unsafe { libc::futimens(-1, now.as_ptr()) }));
}

/// Times a program can set that a naive implementation cannot represent.
fn old_and_odd_times(dir: &str) {
    println!("## the range");
    let p = fresh(dir, "range");
    for (what, sec) in [
        ("1901", -2_177_452_800i64),
        ("1970 exactly", 0),
        ("2038, past a 32-bit time_t", 2_147_483_648),
        ("2262", 9_223_372_036),
    ] {
        let t = [
            libc::timespec { tv_sec: sec, tv_nsec: 0 },
            libc::timespec { tv_sec: sec, tv_nsec: 0 },
        ];
        let set = utimensat(&p, Some(t), 0);
        let back = times(&p).map(|t| t.mtime.0);
        line(
            &format!("  {what}"),
            match (set, back) {
                (0, Some(got)) if got == sec => "set and read back".into(),
                (0, Some(got)) => format!("set, read back as {}", if got == sec { "the same" } else { "something else" }),
                (0, None) => "set, but stat failed".into(),
                _ => rc(set),
            },
        );
    }
}
