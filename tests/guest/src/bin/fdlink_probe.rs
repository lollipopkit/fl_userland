//! What opening and stat-ing `/proc/self/fd/<n>` gives for a descriptor that
//! has no path: a pipe, a socket, an eventfd.
//!
//! **A report, not a check**, diffed against a real kernel by
//! `tests/integration/probe_diff.sh`.
//!
//! Linux follows these links to the open file itself rather than reading the
//! link's text as a path. `/dev/stdin`, `/dev/stdout` and `/dev/stderr` are
//! links into `/proc/self/fd`, so `cat /dev/stdin` on a pipe and
//! `echo x > /dev/stderr` with stderr on a pipe both depend on it. Here both
//! were ENOENT until 2026-10-18: the walk read `pipe:[123]` as a relative path.

use std::ffi::CString;

fn errname(e: i32) -> String {
    match e {
        libc::ENOENT => "ENOENT".into(),
        libc::ENXIO => "ENXIO".into(),
        libc::EACCES => "EACCES".into(),
        libc::EINVAL => "EINVAL".into(),
        libc::ENOTDIR => "ENOTDIR".into(),
        libc::ELOOP => "ELOOP".into(),
        libc::EBADF => "EBADF".into(),
        e => format!("errno {e}"),
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn line(what: &str, v: &str) {
    println!("{what:<50} -> {v}");
}

fn path(fd: i32) -> CString {
    CString::new(format!("/proc/self/fd/{fd}")).unwrap()
}

/// What the file type is when the link is followed.
fn stat_kind(fd: i32) -> String {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a path and a buffer.
    if unsafe { libc::stat(path(fd).as_ptr(), &mut st) } != 0 {
        return errname(errno());
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFIFO => "fifo",
        libc::S_IFSOCK => "socket",
        libc::S_IFREG => "regular",
        0 => "no type",
        _ => "other",
    }
    .into()
}

/// Open the link with `mode` and say whether a byte goes through it in the
/// direction the mode allows.
fn reopen(fd: i32, mode: i32) -> String {
    // SAFETY: a path.
    let n = unsafe { libc::open(path(fd).as_ptr(), mode | libc::O_NONBLOCK) };
    if n < 0 {
        return errname(errno());
    }
    let same = n == fd;
    // SAFETY: an open descriptor.
    let flags = unsafe { libc::fcntl(n, libc::F_GETFL) } & libc::O_ACCMODE;
    // SAFETY: as above.
    unsafe { libc::close(n) };
    let acc = match flags {
        libc::O_RDONLY => "O_RDONLY",
        libc::O_WRONLY => "O_WRONLY",
        _ => "O_RDWR",
    };
    format!("opened, F_GETFL {acc}{}", if same { ", same number" } else { "" })
}

fn main() {
    println!("## a pipe");
    let mut p = [0; 2];
    // SAFETY: fills `p`.
    unsafe { libc::pipe(p.as_mut_ptr()) };
    for (end, fd) in [("read end", p[0]), ("write end", p[1])] {
        line(&format!("{end}: stat follows to"), &stat_kind(fd));
        for (name, mode) in [("O_RDONLY", libc::O_RDONLY), ("O_WRONLY", libc::O_WRONLY), ("O_RDWR", libc::O_RDWR)] {
            line(&format!("{end}: open {name}"), &reopen(fd, mode));
        }
        // SAFETY: a path; continuing through a pipe.
        let r = unsafe { libc::open(CString::new(format!("/proc/self/fd/{fd}/x")).unwrap().as_ptr(), libc::O_RDONLY) };
        line(&format!("{end}: a path through it"), &if r < 0 { errname(errno()) } else { "opened".into() });
    }
    // Data written through a reopened write end reaches the read end.
    // SAFETY: a path.
    let w = unsafe { libc::open(path(p[1]).as_ptr(), libc::O_WRONLY) };
    if w >= 0 {
        // SAFETY: plain I/O on open descriptors.
        unsafe { libc::write(w, b"z".as_ptr().cast(), 1) };
        let mut b = [0u8; 1];
        let n = unsafe { libc::read(p[0], b.as_mut_ptr().cast(), 1) };
        line("a byte through the reopened write end arrives", &(n == 1 && b[0] == b'z').to_string());
        unsafe { libc::close(w) };
    }

    println!("## a socket");
    let mut s = [0; 2];
    // SAFETY: fills `s`.
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, s.as_mut_ptr()) };
    line("stat follows to", &stat_kind(s[0]));
    line("open O_RDWR", &reopen(s[0], libc::O_RDWR));

    println!("## an eventfd");
    // SAFETY: no pointers.
    let e = unsafe { libc::eventfd(0, 0) };
    line("stat follows to", &stat_kind(e));
    line("open O_RDWR", &reopen(e, libc::O_RDWR));

    println!("## lstat does not follow");
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a path and a buffer.
    let r = unsafe { libc::lstat(path(p[0]).as_ptr(), &mut st) };
    line("lstat of the pipe's link", if r == 0 && st.st_mode & libc::S_IFMT == libc::S_IFLNK { "symlink" } else { "not a symlink" });
}
