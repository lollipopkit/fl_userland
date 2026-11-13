//! The `RWF_*` flags of `preadv2`/`pwritev2` that a 7.x kernel accepts, and
//! where a write lands on an `O_APPEND` file, checked against what a real
//! kernel answers (`rwf_probe`'s recording).
//!
//! `RWF_NOSIGNAL` was `EOPNOTSUPP` here until 2026-11-11, `RWF_APPEND |
//! RWF_NOAPPEND` was accepted, `RWF_APPEND` on a pipe was `ESPIPE`, and a
//! `pwrite` on an `O_APPEND` file wrote at its offset.
//!
//! The `RWF_NOAPPEND` cases use `/dev/shm`, a tmpfs in a container: the
//! container's overlayfs re-opens the lower file for every write with the
//! description's `O_APPEND`, so it appends there whatever the flag says.

use guest_tests::{Harness, check, cpath};
use std::sync::atomic::{AtomicU32, Ordering};

const RWF_APPEND: i64 = 0x10;
const RWF_NOAPPEND: i64 = 0x20;
const RWF_ATOMIC: i64 = 0x40;
const RWF_DONTCACHE: i64 = 0x80;
const RWF_NOSIGNAL: i64 = 0x100;

#[repr(C)]
struct Iovec {
    base: *const u8,
    len: usize,
}

fn pwritev2(fd: i32, buf: &[u8], off: i64, flags: i64) -> (i64, i32) {
    let iov = Iovec { base: buf.as_ptr(), len: buf.len() };
    let r = unsafe { libc::syscall(libc::SYS_pwritev2, fd, &iov, 1, off, off >> 32, flags) };
    (r, std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

static SIGPIPES: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_sigpipe(_: i32) {
    SIGPIPES.fetch_add(1, Ordering::SeqCst);
}

fn file(path: &str, flags: i32) -> i32 {
    let _ = std::fs::remove_file(path);
    let fd = unsafe { libc::open(cpath(path).as_ptr(), libc::O_RDWR | libc::O_CREAT | flags, 0o644) };
    unsafe { libc::write(fd, b"0123456789".as_ptr().cast(), 10) };
    fd
}

fn contents(fd: i32) -> Vec<u8> {
    let mut b = [0u8; 32];
    let n = unsafe { libc::pread(fd, b.as_mut_ptr().cast(), 32, 0) };
    b[..n.max(0) as usize].to_vec()
}

fn main() {
    let mut h = Harness::new();
    unsafe { libc::signal(libc::SIGPIPE, on_sigpipe as *const () as libc::sighandler_t) };

    h.group("RWF_NOSIGNAL");
    for kind in ["pipe", "socket"] {
        for (flags, signals) in [(0, 1), (RWF_NOSIGNAL, 0)] {
            let mut p = [0i32; 2];
            if kind == "pipe" {
                unsafe { libc::pipe(p.as_mut_ptr()) };
            } else {
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, p.as_mut_ptr()) };
            }
            let (rd, wr) = (p[0], p[1]);
            unsafe { libc::close(rd) };
            SIGPIPES.store(0, Ordering::SeqCst);
            let (r, e) = pwritev2(wr, b"xyz", -1, flags);
            check!(h, r == -1 && e == libc::EPIPE, "{kind} with no reader, flags {flags:#x}: EPIPE, got {r} errno {e}");
            check!(h, SIGPIPES.load(Ordering::SeqCst) == signals,
                "{kind}, flags {flags:#x}: {signals} SIGPIPE, got {}", SIGPIPES.load(Ordering::SeqCst));
            unsafe { libc::close(wr) };
        }
    }

    h.group("flags a pipe is asked");
    for (flags, want) in [
        (RWF_APPEND, Ok(3)),
        (RWF_NOSIGNAL, Ok(3)),
        (RWF_APPEND | RWF_NOAPPEND, Err(libc::EINVAL)),
        (RWF_ATOMIC, Err(libc::EOPNOTSUPP)),
        (RWF_DONTCACHE, Err(libc::EOPNOTSUPP)),
        (0x200, Err(libc::EOPNOTSUPP)),
    ] {
        let mut p = [0i32; 2];
        unsafe { libc::pipe(p.as_mut_ptr()) };
        let (r, e) = pwritev2(p[1], b"xyz", -1, flags);
        let got = if r < 0 { Err(e) } else { Ok(r) };
        check!(h, got == want, "pipe pwritev2 flags {flags:#x}: want {want:?}, got {got:?}");
        unsafe {
            libc::close(p[0]);
            libc::close(p[1]);
        }
    }

    h.group("pwrite on O_APPEND appends");
    let fd = file("/tmp/rwf_abi.file", libc::O_APPEND);
    let n = unsafe { libc::pwrite(fd, b"xyz".as_ptr().cast(), 3, 2) };
    check!(h, n == 3 && contents(fd) == b"0123456789xyz", "at the end: {:?}",
        String::from_utf8_lossy(&contents(fd)));
    check!(h, unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } == 10, "and the position is left alone");
    unsafe { libc::close(fd) };
    let fd = file("/tmp/rwf_abi.file", 0);
    let (r, _) = pwritev2(fd, b"xyz", 0, RWF_APPEND);
    check!(h, r == 3 && contents(fd) == b"0123456789xyz", "RWF_APPEND at offset 0 appends");
    unsafe { libc::close(fd) };
    let _ = std::fs::remove_file("/tmp/rwf_abi.file");

    h.group("RWF_NOAPPEND on O_APPEND writes at the offset");
    let shm = "/dev/shm/rwf_abi.file";
    let fd = file(shm, libc::O_APPEND);
    let (r, _) = pwritev2(fd, b"xyz", 2, RWF_NOAPPEND);
    check!(h, r == 3 && contents(fd) == b"01xyz56789", "at 2: {:?}", String::from_utf8_lossy(&contents(fd)));
    unsafe { libc::close(fd) };
    let fd = file(shm, libc::O_APPEND);
    unsafe { libc::lseek(fd, 2, libc::SEEK_SET) };
    let (r, _) = pwritev2(fd, b"xyz", -1, RWF_NOAPPEND);
    check!(h, r == 3 && contents(fd) == b"01xyz56789", "at the position: {:?}",
        String::from_utf8_lossy(&contents(fd)));
    check!(h, unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } == 5, "which moves past it");
    unsafe { libc::close(fd) };
    let fd = file(shm, 0);
    unsafe { libc::lseek(fd, 2, libc::SEEK_SET) };
    let (r, _) = pwritev2(fd, b"xyz", -1, RWF_APPEND);
    check!(h, r == 3 && contents(fd) == b"0123456789xyz", "RWF_APPEND at the position appends");
    check!(h, unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } == 13, "and moves the position to the end");
    unsafe { libc::close(fd) };
    let _ = std::fs::remove_file(shm);

    std::process::exit(h.finish());
}
