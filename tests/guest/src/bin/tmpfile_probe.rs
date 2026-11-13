//! `O_TMPFILE`: an unnamed regular file in a directory, which `linkat` may
//! name later -- what CPython's `tempfile.TemporaryFile` and systemd try
//! first.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container and diffed by `tests/integration/probe_diff.sh`. Run against a
//! scratch directory under `/tmp`, and against `/dev/shm` when there is one.

use std::ffi::CString;

const AT_EMPTY_PATH: i32 = 0x1000;
const AT_SYMLINK_FOLLOW: i32 = 0x400;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL".into(),
        libc::ENOENT => "ENOENT".into(),
        libc::ENOTDIR => "ENOTDIR".into(),
        libc::EISDIR => "EISDIR".into(),
        libc::EOPNOTSUPP => "EOPNOTSUPP".into(),
        libc::EEXIST => "EEXIST".into(),
        libc::EACCES => "EACCES".into(),
        e => format!("errno {e}"),
    }
}

fn rc(r: i64) -> String {
    if r < 0 { named(errno()) } else { "ok".into() }
}

fn tmpfile(dir: &str, flags: i32, mode: u32) -> i32 {
    unsafe { libc::open(c(dir).as_ptr(), libc::O_TMPFILE | flags, mode) }
}

fn entries(dir: &str) -> usize {
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(usize::MAX)
}

fn fstat(fd: i32) -> libc::stat {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(fd, &mut st) };
    st
}

/// `/proc/self/fd/<fd>`'s target, with the inode number in it replaced.
fn link_name(fd: i32, ino: u64) -> String {
    match std::fs::read_link(format!("/proc/self/fd/{fd}")) {
        Ok(p) => p.to_string_lossy().replace(&ino.to_string(), "<ino>"),
        Err(e) => named(e.raw_os_error().unwrap_or(0)),
    }
}

fn cases(where_: &str, dir: &str) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let before = entries(dir);

    let fd = tmpfile(dir, libc::O_RDWR, 0o640);
    line(&format!("{where_}: O_TMPFILE|O_RDWR"), rc(fd as i64));
    if fd < 0 {
        return;
    }
    let st = fstat(fd);
    line(&format!("{where_}:   mode, nlink, size"), format!("{:o} {} {}", st.st_mode, st.st_nlink, st.st_size));
    line(&format!("{where_}:   the directory lists it"), entries(dir) != before);
    line(&format!("{where_}:   /proc/self/fd names it"), link_name(fd, st.st_ino));
    let w = unsafe { libc::write(fd, b"hello".as_ptr().cast(), 5) };
    let mut buf = [0u8; 8];
    let r = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), 8, 0) };
    line(&format!("{where_}:   write then pread"), format!("{w} {r} {:?}", String::from_utf8_lossy(&buf[..r.max(0) as usize])));

    let named_path = format!("{dir}/named");
    let r = unsafe { libc::linkat(fd, c"".as_ptr(), libc::AT_FDCWD, c(&named_path).as_ptr(), AT_EMPTY_PATH) };
    line(&format!("{where_}:   linkat(fd, \"\", AT_EMPTY_PATH)"), rc(r as i64));
    line(&format!("{where_}:   then its nlink"), fstat(fd).st_nlink);
    line(&format!("{where_}:   the name reads"), std::fs::read_to_string(&named_path).unwrap_or_else(|e| format!("{e}")));
    line(&format!("{where_}:   /proc/self/fd after"), link_name(fd, st.st_ino).replace(dir, "<dir>"));
    let again = unsafe { libc::linkat(fd, c"".as_ptr(), libc::AT_FDCWD, c(&format!("{dir}/second")).as_ptr(), AT_EMPTY_PATH) };
    line(&format!("{where_}:   a second link"), rc(again as i64));
    unsafe { libc::close(fd) };
    line(&format!("{where_}:   after close, entries added"), entries(dir) as i64 - before as i64);

    // Through /proc/self/fd, the fallback every caller has.
    let fd = tmpfile(dir, libc::O_WRONLY, 0o600);
    let proc = format!("/proc/self/fd/{fd}");
    let via = format!("{dir}/via-proc");
    let r = unsafe { libc::linkat(libc::AT_FDCWD, c(&proc).as_ptr(), libc::AT_FDCWD, c(&via).as_ptr(), AT_SYMLINK_FOLLOW) };
    line(&format!("{where_}: linkat(/proc/self/fd/N, AT_SYMLINK_FOLLOW)"), rc(r as i64));
    line(&format!("{where_}:   the name exists"), std::path::Path::new(&via).exists());
    unsafe { libc::close(fd) };

    // O_EXCL: never to be linked.
    let fd = tmpfile(dir, libc::O_RDWR | libc::O_EXCL, 0o600);
    let r = unsafe { libc::linkat(fd, c"".as_ptr(), libc::AT_FDCWD, c(&format!("{dir}/excl")).as_ptr(), AT_EMPTY_PATH) };
    line(&format!("{where_}: O_TMPFILE|O_EXCL, then linkat"), rc(r as i64));
    unsafe { libc::close(fd) };

    // Closed without a name: nothing left.
    let n = entries(dir);
    let fd = tmpfile(dir, libc::O_RDWR, 0o600);
    unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
    unsafe { libc::close(fd) };
    line(&format!("{where_}: closed unnamed, entries added"), entries(dir) as i64 - n as i64);

    // The umask applies, as to any creation.
    let old = unsafe { libc::umask(0o027) };
    let fd = tmpfile(dir, libc::O_RDWR, 0o666);
    line(&format!("{where_}: mode 0666 under umask 027"), format!("{:o}", fstat(fd).st_mode & 0o777));
    unsafe { libc::close(fd) };
    unsafe { libc::umask(old) };

    // ftruncate and the size it reports.
    let fd = tmpfile(dir, libc::O_RDWR, 0o600);
    let r = unsafe { libc::ftruncate(fd, 4096) };
    line(&format!("{where_}: ftruncate to 4096"), format!("{} {}", rc(r as i64), fstat(fd).st_size));
    unsafe { libc::close(fd) };

    // Refusals.
    line(&format!("{where_}: O_TMPFILE|O_RDONLY"), rc(tmpfile(dir, libc::O_RDONLY, 0o600) as i64));
    line(&format!("{where_}: O_TMPFILE on a file"), rc(tmpfile(&named_path, libc::O_RDWR, 0o600) as i64));
    line(&format!("{where_}: O_TMPFILE on a missing path"), rc(tmpfile(&format!("{dir}/nope"), libc::O_RDWR, 0o600) as i64));
    let r = unsafe { libc::open(c(dir).as_ptr(), libc::O_TMPFILE | libc::O_RDWR | libc::O_CREAT, 0o600) };
    line(&format!("{where_}: O_TMPFILE|O_CREAT"), rc(r as i64));
    if r >= 0 {
        unsafe { libc::close(r) };
    }
    let _ = std::fs::remove_dir_all(dir);
}

fn main() {
    cases("tmp", "/tmp/tmpfileprobe");
    if std::path::Path::new("/dev/shm").is_dir() {
        cases("shm", "/dev/shm/tmpfileprobe");
    }
}
