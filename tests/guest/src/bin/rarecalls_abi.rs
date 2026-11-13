//! `vmsplice`, `remap_file_pages`, `swapon`/`swapoff` and `quotactl`/
//! `quotactl_fd`: each was `ENOSYS` until 2026-11-11.
//!
//! Every expected value is what `rarecalls_probe` measured on a 7.2 arm64
//! kernel, as root, so this runs unchanged on both sides of
//! `tests/integration/differential.sh` (privileged, for the swap and quota
//! calls' `CAP_SYS_ADMIN`).

use guest_tests::{Harness, check, check_fails};

const PAGE: usize = 4096;
const SPLICE_F_NONBLOCK: i64 = 2;

#[repr(C)]
struct Iovec {
    base: *mut u8,
    len: usize,
}

fn vmsplice(fd: i32, v: *const Iovec, n: u64, flags: i64) -> i64 {
    unsafe { libc::syscall(libc::SYS_vmsplice, fd, v, n, flags) }
}

fn pipe() -> (i32, i32) {
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    (p[0], p[1])
}

fn queued(fd: i32) -> i32 {
    let mut n = 0i32;
    unsafe { libc::ioctl(fd, libc::FIONREAD, &mut n) };
    n
}

/// What is queued, without waiting for it: a kernel where the write did not
/// happen must fail the check, not hang.
fn drain(fd: i32) -> Vec<u8> {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut pfd, 1, 0) } != 1 {
        return Vec::new();
    }
    let mut buf = vec![0u8; 256];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    buf.truncate(n.max(0) as usize);
    buf
}

extern "C" fn on_alarm(_: i32) {}

/// `f` under a one-second alarm that does not restart: a call that blocks
/// comes back `EINTR`.
fn blocks(f: impl FnOnce() -> i64) -> bool {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_alarm as extern "C" fn(i32) as usize;
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
        libc::alarm(1);
    }
    let r = f();
    let e = std::io::Error::last_os_error().raw_os_error();
    unsafe { libc::alarm(0) };
    r == -1 && e == Some(libc::EINTR)
}

fn t_vmsplice(h: &mut Harness) {
    h.group("vmsplice-into-a-pipe");
    let (rd, wr) = pipe();
    let mut a = *b"ab";
    let mut b = *b"cde";
    let two = [Iovec { base: a.as_mut_ptr(), len: 2 }, Iovec { base: b.as_mut_ptr(), len: 3 }];
    let r = vmsplice(wr, two.as_ptr(), 2, 0);
    check!(h, r == 5, "two iovecs: {r}");
    let got = drain(rd);
    check!(h, got == b"abcde", "and they come out in order: {:?}", String::from_utf8_lossy(&got));
    check_fails!(h, vmsplice(-1, std::ptr::null(), 0, 0), libc::EBADF, "a bad descriptor before an empty iovec");
    check_fails!(h, vmsplice(-1, std::ptr::null(), 0, 0x10), libc::EINVAL, "an unknown flag before the descriptor");
    check!(h, vmsplice(wr, two.as_ptr(), 0, 0) == 0, "no iovecs is 0");
    check_fails!(h, vmsplice(wr, std::ptr::null(), 1, 0), libc::EFAULT, "an unreadable iovec array");
    check_fails!(h, vmsplice(wr, two.as_ptr(), 1025, 0), libc::EINVAL, "more than UIO_MAXIOV");
    let r = vmsplice(wr, two.as_ptr(), (1 << 32) | 1, 0);
    check!(h, r == 2, "nr_segs is truncated to 32 bits: {r}");
    drain(rd);
    let partial = [Iovec { base: a.as_mut_ptr(), len: 2 }, Iovec { base: 8 as *mut u8, len: 4 }];
    let r = vmsplice(wr, partial.as_ptr(), 2, 0);
    check!(h, r == 2 && queued(rd) == 2, "a good iovec then an unmapped one is a short count: {r}");
    drain(rd);
    let wild = Iovec { base: 8 as *mut u8, len: 4 };
    check_fails!(h, vmsplice(wr, &wild, 1, 0), libc::EFAULT, "only an unmapped one");

    let cap = unsafe { libc::fcntl(wr, libc::F_GETPIPE_SZ) } as usize;
    let big = unsafe {
        libc::mmap(std::ptr::null_mut(), 2 * cap, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    } as *mut u8;
    let vbig = Iovec { base: big, len: 2 * cap };
    let r = vmsplice(wr, &vbig, 1, 0);
    check!(h, r == cap as i64 && queued(rd) == cap as i32, "twice the capacity moves what fits: {r} of {}", 2 * cap);
    check_fails!(h, vmsplice(wr, two.as_ptr(), 1, SPLICE_F_NONBLOCK), libc::EAGAIN, "a full pipe with SPLICE_F_NONBLOCK");
    unsafe { libc::fcntl(wr, libc::F_SETFL, libc::O_NONBLOCK) };
    check!(h, blocks(|| vmsplice(wr, two.as_ptr(), 1, 0)), "a full pipe with O_NONBLOCK and no flag waits");
    unsafe { libc::close(rd) };
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    check_fails!(h, vmsplice(wr, two.as_ptr(), 1, 0), libc::EPIPE, "no readers");
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    unsafe { libc::close(wr) };

    h.group("vmsplice-out-of-a-pipe");
    let (rd, wr) = pipe();
    unsafe { libc::write(wr, b"123456".as_ptr().cast(), 6) };
    let mut p1 = [0u8; 2];
    let mut p2 = [0u8; 2];
    let split = [Iovec { base: p1.as_mut_ptr(), len: 2 }, Iovec { base: p2.as_mut_ptr(), len: 2 }];
    let r = vmsplice(rd, split.as_ptr(), 2, 0);
    check!(h, r == 4 && &p1 == b"12" && &p2 == b"34", "into two iovecs: {r}");
    check!(h, queued(rd) == 2, "and the rest stays queued: {}", queued(rd));
    let ro = unsafe {
        libc::mmap(std::ptr::null_mut(), PAGE, libc::PROT_READ, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    } as *mut u8;
    let vro = Iovec { base: ro, len: 2 };
    check_fails!(h, vmsplice(rd, &vro, 1, 0), libc::EFAULT, "into read-only memory");
    check!(h, queued(rd) == 2, "consumes nothing: {}", queued(rd));
    drain(rd);
    check_fails!(h, vmsplice(rd, split.as_ptr(), 1, SPLICE_F_NONBLOCK), libc::EAGAIN, "an empty pipe with SPLICE_F_NONBLOCK");
    unsafe { libc::fcntl(rd, libc::F_SETFL, libc::O_NONBLOCK) };
    check!(h, blocks(|| vmsplice(rd, split.as_ptr(), 1, 0)), "an empty pipe with O_NONBLOCK and no flag waits");
    unsafe { libc::close(wr) };
    check!(h, vmsplice(rd, split.as_ptr(), 1, 0) == 0, "no writers is end of file");
    unsafe { libc::close(rd) };

    h.group("vmsplice-not-a-pipe");
    let f = unsafe { libc::open(c"/tmp/rarecalls_abi.file".as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    check_fails!(h, vmsplice(f, two.as_ptr(), 1, 0), libc::EBADF, "a regular file");
    check!(h, vmsplice(f, two.as_ptr(), 0, 0) == 0, "with nothing to move, 0");
    unsafe { libc::close(f) };
    unsafe { libc::unlink(c"/tmp/rarecalls_abi.file".as_ptr()) };
    let (rd, wr) = pipe();
    let name = std::ffi::CString::new(format!("/proc/self/fd/{rd}")).unwrap();
    let both = unsafe { libc::open(name.as_ptr(), libc::O_RDWR) };
    let r = vmsplice(both, two.as_ptr(), 1, 0);
    check!(h, r == 2 && queued(rd) == 2, "an O_RDWR reopen of the read end is written to: {r}");
    for fd in [both, rd, wr] {
        unsafe { libc::close(fd) };
    }
}

fn remap(start: *mut u8, size: usize, prot: i64, pgoff: i64) -> i64 {
    unsafe { libc::syscall(libc::SYS_remap_file_pages, start, size, prot, pgoff, 0) }
}

fn t_remap_file_pages(h: &mut Harness) {
    h.group("remap-file-pages");
    let path = c"/tmp/rarecalls_abi.map";
    let f = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    for i in 0..4u8 {
        unsafe { libc::write(f, [b'a' + i; PAGE].as_ptr().cast(), PAGE) };
    }
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    let p = unsafe { libc::mmap(std::ptr::null_mut(), 4 * PAGE, rw, libc::MAP_SHARED, f, 0) } as *mut u8;
    let at = |q: *mut u8, i: usize| unsafe { *q.add(i * PAGE) };
    check!(h, remap(p, PAGE, 0, 3) == 0, "page 0 to the file's page 3");
    check!(h, at(p, 0) == b'd' && at(p, 1) == b'b', "page 0 reads page 3, page 1 is unchanged");
    unsafe { *p = b'Z' };
    let mut back = [0u8; 1];
    unsafe { libc::pread(f, back.as_mut_ptr().cast(), 1, 3 * PAGE as i64) };
    check!(h, back[0] == b'Z', "a store through it reaches the file's page 3");
    check!(h, remap(unsafe { p.add(5) }, PAGE, 0, 2) == 0, "an unaligned start is rounded down");
    check!(h, at(p, 0) == b'c', "and remapped");
    check_fails!(h, remap(p, PAGE, libc::PROT_READ as i64, 0), libc::EINVAL, "a non-zero prot");
    check_fails!(h, remap(p, PAGE - 1, 0, 0), libc::EINVAL, "less than a page");
    check_fails!(h, remap(p, 5 * PAGE, 0, 0), libc::EINVAL, "past the mapping");
    check_fails!(h, remap(p, 2 * PAGE, 0, -1), libc::EINVAL, "a page offset that wraps");
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };

    let p = unsafe { libc::mmap(std::ptr::null_mut(), 4 * PAGE, rw, libc::MAP_SHARED, f, 0) } as *mut u8;
    unsafe { libc::mmap(p.add(2 * PAGE).cast(), 2 * PAGE, rw, libc::MAP_SHARED | libc::MAP_FIXED, f, 0) };
    check!(h, remap(unsafe { p.add(PAGE) }, 2 * PAGE, 0, 0) == 0, "across two mappings of one description");
    check!(h, at(p, 1) == b'a' && at(p, 2) == b'b', "both remapped");
    let g = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    unsafe { libc::mmap(p.add(2 * PAGE).cast(), 2 * PAGE, rw, libc::MAP_SHARED | libc::MAP_FIXED, g, 0) };
    check_fails!(h, remap(unsafe { p.add(PAGE) }, 2 * PAGE, 0, 0), libc::EINVAL, "across two descriptions of one file");
    unsafe { libc::mprotect(p.add(2 * PAGE).cast(), 2 * PAGE, libc::PROT_READ) };
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };
    unsafe { libc::close(g) };

    let p = unsafe { libc::mmap(std::ptr::null_mut(), 4 * PAGE, rw, libc::MAP_PRIVATE, f, 0) } as *mut u8;
    check_fails!(h, remap(p, PAGE, 0, 2), libc::EINVAL, "a private file mapping");
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };
    check_fails!(h, remap(p, PAGE, 0, 2), libc::EINVAL, "nothing mapped");

    let anon = |flags: i32| unsafe {
        libc::mmap(std::ptr::null_mut(), 2 * PAGE, rw, flags | libc::MAP_ANONYMOUS, -1, 0) as *mut u8
    };
    let p = anon(libc::MAP_SHARED);
    unsafe { *p.add(PAGE) = b'S' };
    check!(h, remap(p, PAGE, 0, 1) == 0, "shared anonymous memory, page 0 to page 1");
    check!(h, at(p, 0) == b'S', "page 0 now reads page 1");
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { *p = b'C' };
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    check!(h, at(p, 1) == b'C', "and both addresses are one page, shared with a child");
    unsafe { libc::munmap(p.cast(), 2 * PAGE) };
    let p = anon(libc::MAP_PRIVATE);
    check_fails!(h, remap(p, PAGE, 0, 1), libc::EINVAL, "private anonymous memory");
    unsafe { libc::munmap(p.cast(), 2 * PAGE) };
    unsafe { libc::close(f) };
    unsafe { libc::unlink(path.as_ptr()) };
}

fn sys(n: i64, a: &[i64]) -> i64 {
    let g = |i: usize| a.get(i).copied().unwrap_or(0);
    unsafe { libc::syscall(n, g(0), g(1), g(2), g(3)) }
}

fn p(s: &std::ffi::CStr) -> i64 {
    s.as_ptr() as i64
}

fn t_swap_and_quota(h: &mut Harness) {
    let file = c"/tmp/rarecalls_abi.zeros";
    let f = unsafe { libc::open(file.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o400) };
    unsafe { libc::write(f, [0u8; PAGE].as_ptr().cast(), PAGE) };
    unsafe { libc::close(f) };
    let missing = c"/tmp/rarecalls_abi.missing";

    h.group("swapon-swapoff");
    check_fails!(h, sys(224, &[0, 0]), libc::EFAULT, "swapon(NULL)");
    check_fails!(h, sys(224, &[p(c""), 0]), libc::ENOENT, "swapon(\"\")");
    check_fails!(h, sys(224, &[p(missing), 0]), libc::ENOENT, "swapon(missing)");
    check_fails!(h, sys(224, &[p(c"/tmp"), 0]), libc::EISDIR, "swapon(a directory)");
    check_fails!(h, sys(224, &[p(file), 0]), libc::EINVAL, "swapon(a file with no swap signature)");
    check_fails!(h, sys(224, &[p(missing), 0x100000]), libc::EINVAL, "swapon's flags before its path");
    check_fails!(h, sys(225, &[0]), libc::EFAULT, "swapoff(NULL)");
    check_fails!(h, sys(225, &[p(missing)]), libc::ENOENT, "swapoff(missing)");
    check_fails!(h, sys(225, &[p(c"/tmp")]), libc::EISDIR, "swapoff(a directory)");
    check_fails!(h, sys(225, &[p(file)]), libc::EINVAL, "swapoff(a mode 0400 file that is not swap)");
    check_fails!(h, sys(225, &[p(c"/dev/null")]), libc::EINVAL, "swapoff(/dev/null)");

    h.group("quotactl");
    let qcmd = |c: i64, t: i64| (c << 8) | t;
    const Q_SYNC: i64 = 0x800001;
    const Q_GETFMT: i64 = 0x800004;
    let mut out = [0u8; 64];
    let o = out.as_mut_ptr() as i64;
    check!(h, sys(60, &[qcmd(Q_SYNC, 0), 0, 0, 0]) == 0, "Q_SYNC of every filesystem");
    check_fails!(h, sys(60, &[qcmd(Q_SYNC, 3), 0, 0, 0]), libc::EINVAL, "quota type 3");
    check_fails!(h, sys(60, &[qcmd(Q_GETFMT, 0), 0, 0, o]), libc::ENODEV, "any other command with no device");
    check_fails!(h, sys(60, &[qcmd(Q_GETFMT, 0), p(missing), 0, o]), libc::ENOENT, "a missing device");
    check_fails!(h, sys(60, &[qcmd(Q_GETFMT, 0), p(c"/dev/null"), 0, o]), libc::ENOTBLK, "a character device");
    check_fails!(h, sys(60, &[qcmd(Q_GETFMT, 0), p(c"/tmp"), 0, o]), libc::ENOTBLK, "a directory");
    check_fails!(h, sys(60, &[qcmd(Q_GETFMT, 0), 8, 0, o]), libc::EFAULT, "an unreadable name");
    let tmp = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_PATH) };
    check_fails!(h, sys(443, &[-1, qcmd(Q_GETFMT, 3), 0, o]), libc::EBADF, "quotactl_fd: the descriptor first");
    check_fails!(h, sys(443, &[tmp as i64, qcmd(Q_GETFMT, 3), 0, o]), libc::EINVAL, "quotactl_fd: then the type");
    check_fails!(h, sys(443, &[tmp as i64, qcmd(Q_GETFMT, 0), 0, o]), libc::ENOSYS, "quotactl_fd: no filesystem has quota");
    unsafe { libc::close(tmp) };
    unsafe { libc::unlink(file.as_ptr()) };
}

fn main() {
    let mut h = Harness::new();
    t_vmsplice(&mut h);
    t_remap_file_pages(&mut h);
    t_swap_and_quota(&mut h);
    std::process::exit(h.finish());
}
