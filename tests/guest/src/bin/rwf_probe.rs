//! Which `RWF_*` flags `preadv2`/`pwritev2` take, on a regular file, a pipe and
//! a socket, and what the ones with an effect do.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container and diffed by `tests/integration/probe_diff.sh`.
//!
//! `io_probe` asks the flags that existed before 6.9 on a file read. This asks
//! every bit a 7.x kernel defines -- `RWF_NOAPPEND` (6.9), `RWF_ATOMIC` (6.11),
//! `RWF_DONTCACHE` (6.14), `RWF_NOSIGNAL` (6.18) -- in both directions and on
//! three kinds of descriptor, because `kiocb_set_rw_flags` checks some of them
//! against the file (`FMODE_NOWAIT`, `FMODE_CAN_ATOMIC_WRITE`,
//! `FOP_DONTCACHE`). `RWF_NOWAIT` on a regular file is left to `io_probe`: it
//! is a property of the container's overlayfs.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EAGAIN => "EAGAIN",
        libc::EPIPE => "EPIPE",
        libc::ESPIPE => "ESPIPE",
        libc::EPERM => "EPERM",
        libc::EBADF => "EBADF",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn r(v: i64) -> String {
    if v < 0 { named(errno()) } else { v.to_string() }
}

const FLAGS: [(&str, i64); 11] = [
    ("RWF_HIPRI", 0x1),
    ("RWF_DSYNC", 0x2),
    ("RWF_SYNC", 0x4),
    ("RWF_NOWAIT", 0x8),
    ("RWF_APPEND", 0x10),
    ("RWF_NOAPPEND", 0x20),
    ("RWF_ATOMIC", 0x40),
    ("RWF_DONTCACHE", 0x80),
    ("RWF_NOSIGNAL", 0x100),
    ("0x200", 0x200),
    ("RWF_APPEND|RWF_NOAPPEND", 0x30),
];

#[repr(C)]
struct Iovec {
    base: *mut u8,
    len: usize,
}

fn preadv2(fd: i32, buf: &mut [u8], off: i64, flags: i64) -> i64 {
    let iov = Iovec { base: buf.as_mut_ptr(), len: buf.len() };
    unsafe { libc::syscall(libc::SYS_preadv2, fd, &iov, 1, off, off >> 32, flags) }
}

fn pwritev2(fd: i32, buf: &[u8], off: i64, flags: i64) -> i64 {
    let iov = Iovec { base: buf.as_ptr().cast_mut(), len: buf.len() };
    unsafe { libc::syscall(libc::SYS_pwritev2, fd, &iov, 1, off, off >> 32, flags) }
}

fn file(content: &[u8], extra: i32) -> i32 {
    let p = c"/tmp/rwf_probe.file";
    unsafe { libc::unlink(p.as_ptr()) };
    let fd = unsafe { libc::open(p.as_ptr(), libc::O_RDWR | libc::O_CREAT | extra, 0o644) };
    unsafe { libc::write(fd, content.as_ptr().cast(), content.len()) };
    fd
}

fn size(fd: i32) -> i64 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(fd, &mut st) };
    st.st_size
}

/// A readable end with four bytes waiting and a writable one with room, as
/// a fresh `(read, write)` pair.
fn pipe() -> (i32, i32) {
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    unsafe { libc::write(p[1], b"abcd".as_ptr().cast(), 4) };
    (p[0], p[1])
}

fn socketpair() -> (i32, i32) {
    let mut p = [0i32; 2];
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, p.as_mut_ptr()) };
    unsafe { libc::write(p[1], b"abcd".as_ptr().cast(), 4) };
    (p[0], p[1])
}

static SIGPIPES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

extern "C" fn on_sigpipe(_: i32) {
    SIGPIPES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

fn main() {
    println!("########## a regular file ##########");
    for (name, f) in FLAGS {
        if f == 0x8 {
            continue;
        }
        let fd = file(b"0123456789", 0);
        let mut b = [0u8; 4];
        line(&format!("file preadv2({name})"), r(preadv2(fd, &mut b, 0, f)));
        line(&format!("file pwritev2(offset 0, {name})"), r(pwritev2(fd, b"xyz", 0, f)));
        line("  the file is now this long", size(fd));
        unsafe { libc::close(fd) };
    }

    println!("########## O_APPEND and RWF_NOAPPEND ##########");
    for (name, f) in [("0", 0i64), ("RWF_NOAPPEND", 0x20), ("RWF_APPEND", 0x10)] {
        let fd = file(b"0123456789", libc::O_APPEND);
        line(&format!("O_APPEND pwritev2(offset 2, {name})"), r(pwritev2(fd, b"xyz", 2, f)));
        line("  the file is now this long", size(fd));
        let mut b = [0u8; 13];
        let n = unsafe { libc::pread(fd, b.as_mut_ptr().cast(), 13, 0) };
        line("  and holds", String::from_utf8_lossy(&b[..n.max(0) as usize]));
        unsafe { libc::close(fd) };
    }
    {
        let fd = file(b"0123456789", libc::O_APPEND);
        let n = unsafe { libc::pwrite(fd, b"xyz".as_ptr().cast(), 3, 2) };
        line("O_APPEND pwrite(offset 2)", r(n as i64));
        line("  the file is now this long", size(fd));
        line("  the file offset is now", unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) });
        unsafe { libc::close(fd) };
    }
    for (name, f, extra) in [
        ("O_APPEND pwritev2(offset -1, RWF_NOAPPEND)", 0x20i64, libc::O_APPEND),
        ("O_APPEND pwritev2(offset -1, 0)", 0, libc::O_APPEND),
        ("pwritev2(offset -1, RWF_APPEND)", 0x10, 0),
    ] {
        // From offset 2, so that the end and the position differ.
        let fd = file(b"0123456789", extra);
        unsafe { libc::lseek(fd, 2, libc::SEEK_SET) };
        line(name, r(pwritev2(fd, b"xyz", -1, f)));
        line("  the file is now this long", size(fd));
        line("  the file offset is now", unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) });
        unsafe { libc::close(fd) };
    }

    for (kind, make) in [("pipe", pipe as fn() -> (i32, i32)), ("socket", socketpair)] {
        println!("########## a {kind} ##########");
        for (name, f) in FLAGS {
            let (rd, wr) = make();
            let mut b = [0u8; 4];
            line(&format!("{kind} preadv2(offset -1, {name})"), r(preadv2(rd, &mut b, -1, f)));
            line(&format!("{kind} pwritev2(offset -1, {name})"), r(pwritev2(wr, b"xyz", -1, f)));
            unsafe {
                libc::close(rd);
                libc::close(wr);
            }
        }
        {
            // Nothing to read: RWF_NOWAIT answers at once.
            let (rd, wr) = make();
            let mut b = [0u8; 4];
            preadv2(rd, &mut b, -1, 0);
            line(&format!("{kind} preadv2(RWF_NOWAIT), nothing waiting"), r(preadv2(rd, &mut b, -1, 0x8)));
            unsafe {
                libc::close(rd);
                libc::close(wr);
            }
        }
    }

    println!("########## RWF_NOSIGNAL ##########");
    unsafe { libc::signal(libc::SIGPIPE, on_sigpipe as *const () as libc::sighandler_t) };
    for (kind, make) in [("pipe", pipe as fn() -> (i32, i32)), ("socket", socketpair)] {
        for (name, f) in [("0", 0i64), ("RWF_NOSIGNAL", 0x100)] {
            let (rd, wr) = make();
            unsafe { libc::close(rd) };
            SIGPIPES.store(0, std::sync::atomic::Ordering::SeqCst);
            line(&format!("{kind} with no reader, pwritev2({name})"), r(pwritev2(wr, b"xyz", -1, f)));
            line("  SIGPIPE delivered", SIGPIPES.load(std::sync::atomic::Ordering::SeqCst));
            unsafe { libc::close(wr) };
        }
    }
    unsafe { libc::unlink(c"/tmp/rwf_probe.file".as_ptr()) };
}
