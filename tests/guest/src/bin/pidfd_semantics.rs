//! What a pidfd does on a 7.x kernel, as checks: each was measured on 7.2 by
//! `pidfd_modern_probe` first, and each failed against this kernel before
//! 2026-11-11.
//!
//! - `PIDFD_NONBLOCK` makes `waitid(P_PIDFD)` answer `EAGAIN` for a child that
//!   is still running. It was accepted and ignored, so the wait blocked.
//! - `PIDFD_THREAD` names one thread, polls readable when that thread exits,
//!   and without it a non-leader tid is `ENOENT` (it was `EINVAL`).
//! - `pidfd_getfd` duplicates another process's descriptor (it was `ENOSYS`).
//! - `pidfd_send_signal` takes 6.9's scope flags (they were `EINVAL`).
//! - `PIDFD_GET_INFO` reports the ids, and the exit status once the process is
//!   reaped (it was `ENOTTY`).
//! - A reaped process's pidfd polls `POLLIN | POLLHUP` (it was `POLLIN`).
//! - A pidfd is `O_RDWR`, so a `write` is `EINVAL` (it was `EBADF`).
//! - `clone3` with `CLONE_INTO_CGROUP` is `EBADF` for a descriptor that is not
//!   a cgroup directory (it was `EINVAL`, an unknown flag).

use guest_tests::{Harness, check, check_fails, sys};

const PIDFD_NONBLOCK: u32 = libc::O_NONBLOCK as u32;
const PIDFD_THREAD: u32 = libc::O_EXCL as u32;
const P_PIDFD: i32 = 3;

fn pidfd_open(pid: i32, flags: u32) -> i64 {
    unsafe { libc::syscall(434, pid, flags) }
}

fn waitid(fd: i32, options: i32) -> i64 {
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe { libc::syscall(libc::SYS_waitid, P_PIDFD, fd, &mut si, options, std::ptr::null::<u8>()) }
}

fn revents(fd: i32) -> i16 {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    unsafe { libc::poll(&mut p, 1, 0) };
    p.revents
}

/// A child that exits 7 when its pipe is written to.
fn child() -> (i32, i32) {
    let mut p = [0; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let c = unsafe { libc::fork() };
    if c == 0 {
        unsafe {
            libc::close(p[1]);
            let mut b = 0u8;
            libc::read(p[0], (&raw mut b).cast(), 1);
            libc::_exit(7);
        }
    }
    unsafe { libc::close(p[0]) };
    (c, p[1])
}

fn release(w: i32) {
    unsafe {
        libc::write(w, b"x".as_ptr().cast(), 1);
        libc::close(w);
    }
}

fn zombie(pid: i32) {
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe { libc::waitid(libc::P_PID, pid as u32, &mut si, libc::WEXITED | libc::WNOWAIT) };
}

fn t_nonblock(h: &mut Harness) {
    h.group("pidfd-nonblock");
    let (c, w) = child();
    let fd = pidfd_open(c, PIDFD_NONBLOCK) as i32;
    check!(h, fd >= 0, "pidfd_open(PIDFD_NONBLOCK): errno {}", sys::errno());
    check!(h, unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0, "F_GETFL shows O_NONBLOCK");
    check_fails!(h, waitid(fd, libc::WEXITED), libc::EAGAIN, "waitid on a running child");
    check!(h, waitid(fd, libc::WEXITED | libc::WNOHANG) == 0, "with WNOHANG it is 0, as without the flag");
    release(w);
    zombie(c);
    check!(h, waitid(fd, libc::WEXITED) == 0, "and it reaps once the child has exited");
    check_fails!(h, waitid(-1, libc::WEXITED), libc::EINVAL, "waitid(P_PIDFD, -1)");
    unsafe { libc::close(fd) };
}

fn t_thread(h: &mut Harness) {
    h.group("pidfd-thread");
    let (tx, rx) = std::sync::mpsc::channel();
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let t = std::thread::spawn(move || {
        tx.send(unsafe { libc::gettid() }).unwrap();
        let _ = wait.recv();
    });
    let tid = rx.recv().unwrap();
    check_fails!(h, pidfd_open(tid, 0), libc::ENOENT, "a thread without PIDFD_THREAD");
    let fd = pidfd_open(tid, PIDFD_THREAD) as i32;
    check!(h, fd >= 0, "pidfd_open(tid, PIDFD_THREAD): errno {}", sys::errno());
    check!(h, unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_EXCL != 0, "F_GETFL shows PIDFD_THREAD");
    check!(h, revents(fd) == 0, "not readable while the thread runs");
    check!(h, unsafe { libc::syscall(424, fd, 0, 0usize, 0) } == 0, "signal 0 reaches it");
    go.send(()).unwrap();
    t.join().unwrap();
    let mut seen = 0;
    for _ in 0..500 {
        seen = revents(fd);
        if seen != 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    check!(h, seen == libc::POLLIN | libc::POLLHUP, "POLLIN|POLLHUP once the thread exits: {seen:#x}");
    check_fails!(h, unsafe { libc::syscall(424, fd, 0, 0usize, 0) }, libc::ESRCH, "signal 0 after it exits");
    unsafe { libc::close(fd) };
}

fn t_getfd(h: &mut Harness) {
    h.group("pidfd-getfd");
    let mut p = [0; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let c = unsafe { libc::fork() };
    if c == 0 {
        unsafe {
            libc::close(p[1]);
            let z = libc::open(c"/dev/zero".as_ptr(), libc::O_RDONLY);
            libc::dup2(z, 60);
            let mut b = 0u8;
            libc::read(p[0], (&raw mut b).cast(), 1);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(p[0]) };
    std::thread::sleep(std::time::Duration::from_millis(200));
    let fd = pidfd_open(c, 0) as i32;
    let got = unsafe { libc::syscall(438, fd, 60, 0) } as i32;
    check!(h, got >= 0, "pidfd_getfd(child, 60): errno {}", sys::errno());
    if got >= 0 {
        let mut b = [1u8; 4];
        let n = unsafe { libc::read(got, b.as_mut_ptr().cast(), 4) };
        check!(h, n == 4 && b == [0; 4], "it is the child's /dev/zero");
        check!(h, unsafe { libc::fcntl(got, libc::F_GETFD) } & libc::FD_CLOEXEC != 0, "close-on-exec");
        unsafe { libc::close(got) };
    }
    check_fails!(h, unsafe { libc::syscall(438, fd, 60, 1) }, libc::EINVAL, "flags 1");
    check_fails!(h, unsafe { libc::syscall(438, fd, 61, 0) }, libc::EBADF, "a number not open there");
    check_fails!(h, unsafe { libc::syscall(438, 0, 60, 0) }, libc::EBADF, "a descriptor that is not a pidfd");
    release(p[1]);
    zombie(c);
    check_fails!(h, unsafe { libc::syscall(438, fd, 60, 0) }, libc::ESRCH, "a child that has exited");
    let mut st = 0;
    unsafe { libc::waitpid(c, &mut st, 0) };
    unsafe { libc::close(fd) };
}

fn t_signal_scopes(h: &mut Harness) {
    h.group("pidfd-signal-flags");
    let me = pidfd_open(unsafe { libc::getpid() }, 0) as i32;
    for flags in [1u32, 2, 4] {
        check!(h, unsafe { libc::syscall(424, me, 0, 0usize, flags) } == 0, "scope flag {flags}: errno {}", sys::errno());
    }
    check_fails!(h, unsafe { libc::syscall(424, me, 0, 0usize, 3u32) }, libc::EINVAL, "two scopes at once");
    check!(h, unsafe { libc::syscall(424, -10001, 0, 0usize, 0) } == 0, "PIDFD_SELF_THREAD_GROUP");
    unsafe { libc::close(me) };
}

fn info(fd: i32, mask: u64) -> (i64, [u8; 88]) {
    let mut b = [0u8; 88];
    b[..8].copy_from_slice(&mask.to_le_bytes());
    let cmd = (3u64 << 30) | (88 << 16) | (0xFF << 8) | 11;
    (unsafe { libc::ioctl(fd, cmd as _, b.as_mut_ptr()) } as i64, b)
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn t_info(h: &mut Harness) {
    h.group("pidfd-get-info");
    let (c, w) = child();
    let fd = pidfd_open(c, 0) as i32;
    let (r, b) = info(fd, 0);
    check!(h, r == 0, "PIDFD_GET_INFO on a live child: errno {}", sys::errno());
    // Without PIDFD_INFO_CGROUPID, which is the container's cgroup and which
    // this kernel, with no cgroups, never reports.
    let mask = |b: &[u8; 88]| u64::from_le_bytes(b[..8].try_into().unwrap()) & !4;
    check!(h, mask(&b) == 3, "mask is PID|CREDS");
    check!(h, u32_at(&b, 16) == c as u32, "pid");
    check!(h, u32_at(&b, 24) == unsafe { libc::getpid() } as u32, "ppid is this process");
    release(w);
    let mut st = 0;
    unsafe { libc::waitpid(c, &mut st, 0) };
    let (r, b) = info(fd, 8);
    check!(h, r == 0, "with PIDFD_INFO_EXIT once reaped: errno {}", sys::errno());
    check!(h, mask(&b) == 8, "mask is EXIT alone");
    check!(h, u32_at(&b, 60) == 0x700, "exit_code is the wait status: {:#x}", u32_at(&b, 60));
    check_fails!(h, info(fd, 0).0, libc::ESRCH, "without PIDFD_INFO_EXIT once reaped");
    check!(h, revents(fd) == libc::POLLIN | libc::POLLHUP, "a reaped child polls POLLIN|POLLHUP");
    let small = (3u64 << 30) | (56 << 16) | (0xFF << 8) | 11;
    check_fails!(h, unsafe { libc::ioctl(fd, small as _, [0u8; 56].as_mut_ptr()) }, libc::ENOTTY, "a 56-byte struct");
    check_fails!(h, unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) }, libc::EINVAL, "a write");
    unsafe { libc::close(fd) };
}

fn t_cgroup(h: &mut Harness) {
    h.group("clone3-into-cgroup");
    let mut a = [0u64; 11];
    a[0] = 1 << 33; // CLONE_INTO_CGROUP
    a[4] = libc::SIGCHLD as u64;
    a[10] = 0; // descriptor 0, which is not a cgroup directory
    let r = unsafe { libc::syscall(435, a.as_ptr(), 88usize) };
    if r == 0 {
        unsafe { libc::_exit(0) };
    }
    check!(h, r < 0 && sys::errno() == libc::EBADF, "CLONE_INTO_CGROUP on fd 0: {r} errno {}", sys::errno());
    a[10] = 1 << 31;
    check_fails!(h, unsafe { libc::syscall(435, a.as_ptr(), 88usize) }, libc::EINVAL, "a cgroup above INT_MAX");
}

fn main() {
    let mut h = Harness::new();
    t_nonblock(&mut h);
    t_thread(&mut h);
    t_getfd(&mut h);
    t_signal_scopes(&mut h);
    t_info(&mut h);
    t_cgroup(&mut h);
    std::process::exit(h.finish());
}
