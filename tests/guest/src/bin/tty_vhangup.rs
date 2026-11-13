//! A hangup hangs up descriptions, not the terminal, and tells only the
//! session leader; the answers are `ttyhup_probe`'s recording of a real
//! kernel.
//!
//! - `vhangup`: the descriptions open at the time answer end of file, `EIO`
//!   and `POLLHUP`, the session loses the terminal, its leader gets `SIGHUP`
//!   and `SIGCONT` and nobody else does, and the terminal opens again and
//!   works. It was `ENOSYS`, and a hangup was a flag on the terminal that
//!   made it unusable for good.
//! - Every slave descriptor closing leaves the master reading what is queued
//!   and then `EIO`, writable, and back to normal when the slave is opened
//!   again. It read end of file at once, for ever.
//! - The session leader exiting sends the foreground group `SIGHUP` and takes
//!   the terminal from the session, and the pty keeps working. Nothing
//!   happened at all.
//!
//! Each part runs in a forked child that makes its own session.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

static HUPS: AtomicI32 = AtomicI32::new(0);
static CONTS: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_hup(_: i32) {
    HUPS.fetch_add(1, Ordering::SeqCst);
}
extern "C" fn on_cont(_: i32) {
    CONTS.fetch_add(1, Ordering::SeqCst);
}

fn count_signals() {
    for (sig, f) in [(libc::SIGHUP, on_hup as extern "C" fn(i32)), (libc::SIGCONT, on_cont)] {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = f as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
    HUPS.store(0, Ordering::SeqCst);
    CONTS.store(0, Ordering::SeqCst);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn settle() {
    std::thread::sleep(Duration::from_millis(100));
}

fn pty() -> (i32, i32, std::ffi::CString) {
    let m = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    unsafe {
        libc::grantpt(m);
        libc::unlockpt(m);
    }
    let name = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(m)) }.to_owned();
    let s = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK) };
    (m, s, name)
}

fn nonblock(fd: i32) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
}

fn read(fd: i32) -> (isize, i32) {
    let mut b = [0u8; 64];
    let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), b.len()) };
    (n, if n < 0 { errno() } else { 0 })
}

fn write(fd: i32, bytes: &[u8]) -> (isize, i32) {
    let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    (n, if n < 0 { errno() } else { 0 })
}

fn revents(fd: i32) -> i16 {
    let mut p = libc::pollfd { fd, events: libc::POLLIN | libc::POLLOUT, revents: 0 };
    unsafe { libc::poll(&mut p, 1, 0) };
    p.revents
}

fn dev_tty() -> i32 {
    let fd = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if fd < 0 {
        return errno();
    }
    unsafe { libc::close(fd) };
    0
}

/// A member of the caller's session in a process group of its own, made the
/// foreground group of `tty`, with `master` closed. It counts its signals
/// until told to stop, and exits with `HUP count * 10 + CONT count`.
fn member(tty: i32, master: i32) -> (i32, i32) {
    let mut go = [0i32; 2];
    let mut ready = [0i32; 2];
    unsafe {
        libc::pipe(go.as_mut_ptr());
        libc::pipe(ready.as_mut_ptr());
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        count_signals();
        unsafe {
            libc::close(master);
            libc::setpgid(0, 0);
            libc::write(ready[1], b"r".as_ptr().cast(), 1);
        }
        let mut b = [0u8; 1];
        while unsafe { libc::read(go[0], b.as_mut_ptr().cast(), 1) } < 0 && errno() == libc::EINTR {}
        settle();
        unsafe { libc::_exit(HUPS.load(Ordering::SeqCst) * 10 + CONTS.load(Ordering::SeqCst)) };
    }
    unsafe {
        libc::setpgid(pid, pid);
        let mut b = [0u8; 1];
        libc::read(ready[0], b.as_mut_ptr().cast(), 1);
        libc::tcsetpgrp(tty, pid);
    }
    (pid, go[1])
}

fn finish_member((pid, go): (i32, i32)) -> i32 {
    unsafe { libc::write(go, b"g".as_ptr().cast(), 1) };
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 }
}

fn vhangup(h: &mut Harness) {
    h.group("vhangup");
    count_signals();
    unsafe { libc::setsid() };
    let (m, s, name) = pty();
    nonblock(m);
    let r = unsafe { libc::ioctl(s, libc::TIOCSCTTY as _, 0) };
    check!(h, r == 0, "the pty is our controlling terminal: errno {}", errno());
    let t = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    check!(h, t >= 0, "/dev/tty opens before");
    let fg = member(s, m);

    let r = unsafe { libc::syscall(58) };
    check!(h, r == 0, "vhangup() succeeds: errno {}", errno());
    settle();
    check!(h, HUPS.load(Ordering::SeqCst) == 1 && CONTS.load(Ordering::SeqCst) == 1,
        "the session leader gets SIGHUP and SIGCONT: HUP {} CONT {}",
        HUPS.load(Ordering::SeqCst), CONTS.load(Ordering::SeqCst));
    let hup = libc::POLLIN | libc::POLLOUT | libc::POLLERR | libc::POLLHUP;
    check!(h, revents(s) == hup, "the old descriptor polls IN|OUT|ERR|HUP: {:#x}", revents(s));
    check!(h, read(s) == (0, 0), "reading it is end of file: {:?}", read(s));
    check!(h, write(s, b"x") == (-1, libc::EIO), "writing it is EIO: {:?}", write(s, b"x"));
    let mut pg = 0i32;
    let r = unsafe { libc::ioctl(s, libc::TIOCGPGRP as _, &mut pg) };
    check!(h, r == -1 && errno() == libc::EIO, "an ioctl on it is EIO");
    let pg = unsafe { libc::getpgrp() };
    let r = unsafe { libc::ioctl(s, libc::TIOCSPGRP as _, &pg) };
    check!(h, r == -1 && errno() == libc::ENOTTY, "TIOCSPGRP on it is ENOTTY");
    check!(h, read(t) == (0, 0), "so is the one /dev/tty opened: {:?}", read(t));
    check!(h, revents(m) == libc::POLLOUT, "the master is untouched: {:#x}", revents(m));
    check!(h, read(m) == (-1, libc::EAGAIN), "and reads EAGAIN: {:?}", read(m));
    check!(h, write(m, b"lost\n") == (5, 0), "a write to the master is accepted");
    let signals = finish_member(fg);
    check!(h, signals == 0, "the foreground member gets nothing: HUP*10+CONT = {signals}");
    check!(h, dev_tty() == libc::ENXIO, "/dev/tty is ENXIO: the session lost it ({})", dev_tty());

    let s2 = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK) };
    check!(h, s2 >= 0, "the slave opens again: errno {}", errno());
    check!(h, read(s2) == (-1, libc::EAGAIN), "with nothing queued from before: {:?}", read(s2));
    check!(h, write(s2, b"y") == (1, 0), "and writes");
    settle();
    check!(h, read(m) == (1, 0), "which the master reads");
    check!(h, read(s) == (0, 0), "while the old descriptor stays hung up");
    let r = unsafe { libc::ioctl(s2, libc::TIOCSCTTY as _, 0) };
    check!(h, r == 0, "and the terminal can be claimed again: errno {}", errno());
    check!(h, dev_tty() == 0, "after which /dev/tty opens");
}

fn vhangup_unprivileged(h: &mut Harness) {
    h.group("vhangup needs CAP_SYS_TTY_CONFIG");
    unsafe { libc::setsid() };
    let (_m, s, _) = pty();
    unsafe {
        libc::ioctl(s, libc::TIOCSCTTY as _, 0);
        libc::setresuid(65534, 65534, 65534);
    }
    let r = unsafe { libc::syscall(58) };
    check!(h, r == -1 && errno() == libc::EPERM, "EPERM for uid 65534: r={r} errno {}", errno());
    check!(h, write(s, b"x") == (1, 0), "and the terminal is untouched");
}

fn master_close(h: &mut Harness) {
    h.group("closing the master tells the leader alone");
    count_signals();
    unsafe { libc::setsid() };
    let (m, s, name) = pty();
    unsafe { libc::ioctl(s, libc::TIOCSCTTY as _, 0) };
    let fg = member(s, m);
    unsafe { libc::close(m) };
    settle();
    check!(h, HUPS.load(Ordering::SeqCst) == 1 && CONTS.load(Ordering::SeqCst) == 1,
        "the leader: HUP {} CONT {}", HUPS.load(Ordering::SeqCst), CONTS.load(Ordering::SeqCst));
    let signals = finish_member(fg);
    check!(h, signals == 0, "the foreground member gets nothing: {signals}");
    let again = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    check!(h, again == -1 && errno() == libc::ENOENT, "the slave's node is gone: errno {}", errno());
}

fn slave_close(h: &mut Harness) {
    h.group("every slave descriptor closing");
    let (m, s, name) = pty();
    nonblock(m);
    check!(h, write(s, b"a") == (1, 0), "the slave writes");
    unsafe { libc::close(s) };
    settle();
    let r = revents(m);
    check!(h, r & libc::POLLHUP != 0 && r & libc::POLLIN != 0, "the master polls IN|HUP: {r:#x}");
    check!(h, read(m) == (1, 0), "and reads what the slave left: {:?}", read(m));
    check!(h, read(m) == (-1, libc::EIO), "then EIO: {:?}", read(m));
    check!(h, revents(m) & (libc::POLLIN | libc::POLLHUP) == libc::POLLHUP, "and polls HUP alone: {:#x}", revents(m));
    check!(h, write(m, b"b") == (1, 0), "a write to it is accepted");
    let s2 = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK) };
    check!(h, s2 >= 0, "the slave opens again");
    settle();
    check!(h, revents(m) & libc::POLLHUP == 0, "and the master is not hung up: {:#x}", revents(m));
    check!(h, write(s2, b"c") == (1, 0), "the slave writes");
    settle();
    check!(h, read(m) == (2, 0), "the master reads the echo and the byte: {:?}", read(m));
}

fn leader_exit(h: &mut Harness) {
    h.group("the session leader exits");
    let (m, s, name) = pty();
    unsafe { libc::close(s) };
    nonblock(m);
    // go: us -> the member. report: the member -> us; it is the leader's
    // child, and outlives it.
    let (mut go, mut report, mut ready) = ([0i32; 2], [0i32; 2], [0i32; 2]);
    unsafe {
        libc::pipe(go.as_mut_ptr());
        libc::pipe(report.as_mut_ptr());
        libc::pipe(ready.as_mut_ptr());
    }
    let leader = unsafe { libc::fork() };
    if leader == 0 {
        unsafe {
            libc::close(m);
            libc::setsid();
        }
        let s = unsafe { libc::open(name.as_ptr(), libc::O_RDWR) };
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            count_signals();
            unsafe {
                libc::setpgid(0, 0);
                libc::write(ready[1], b"r".as_ptr().cast(), 1);
            }
            let mut b = [0u8; 1];
            while unsafe { libc::read(go[0], b.as_mut_ptr().cast(), 1) } < 0 && errno() == libc::EINTR {}
            settle();
            nonblock(s);
            let mut sid = 0i32;
            let gsid = unsafe { libc::ioctl(s, libc::TIOCGSID as _, &mut sid) };
            let gsid = if gsid < 0 { errno() } else { 0 };
            let words = [
                HUPS.load(Ordering::SeqCst),
                CONTS.load(Ordering::SeqCst),
                dev_tty(),
                write(s, b"m").0 as i32,
                gsid,
            ];
            let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
            unsafe {
                libc::write(report[1], bytes.as_ptr().cast(), bytes.len());
                libc::_exit(0);
            }
        }
        unsafe {
            libc::setpgid(pid, pid);
            let mut b = [0u8; 1];
            libc::read(ready[0], b.as_mut_ptr().cast(), 1);
            libc::tcsetpgrp(s, pid);
            libc::_exit(0);
        }
    }
    unsafe {
        libc::close(go[0]);
        libc::close(report[1]);
    }
    let mut st = 0;
    unsafe { libc::waitpid(leader, &mut st, 0) };
    settle();
    check!(h, libc::WIFEXITED(st), "the leader exited");
    check!(h, revents(m) == libc::POLLOUT, "the master is untouched: {:#x}", revents(m));
    unsafe { libc::write(go[1], b"g".as_ptr().cast(), 1) };
    let mut bytes = [0u8; 20];
    let mut got = 0;
    while got < bytes.len() {
        let n = unsafe { libc::read(report[0], bytes[got..].as_mut_ptr().cast(), bytes.len() - got) };
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    check!(h, got == bytes.len(), "the member reported: {got} bytes");
    let w: Vec<i32> = bytes.chunks(4).map(|c| i32::from_ne_bytes(c.try_into().unwrap())).collect();
    check!(h, w[0] == 1 && w[1] == 0, "the foreground member gets SIGHUP alone: HUP {} CONT {}", w[0], w[1]);
    check!(h, w[2] == libc::ENXIO, "and /dev/tty is ENXIO for it: {}", w[2]);
    check!(h, w[4] == libc::ENOTTY, "TIOCGSID on its descriptor is ENOTTY: {}", w[4]);
    check!(h, w[3] == 1, "but the terminal still writes: {}", w[3]);
    settle();
    check!(h, read(m) == (1, 0), "and the master reads it: {:?}", read(m));
}

fn run(f: fn(&mut Harness)) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let mut h = Harness::new();
        f(&mut h);
        std::process::exit(h.finish());
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 1 }
}

fn main() {
    let failed = [vhangup, vhangup_unprivileged, master_close, slave_close, leader_exit]
        .into_iter()
        .map(run)
        .fold(0, |acc, r| acc | r);
    std::process::exit(failed);
}
