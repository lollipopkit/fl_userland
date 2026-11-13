//! What happens to a session when its terminal goes away.
//!
//! Closing the last descriptor for a pty master hangs up the slave. That is
//! how a terminal application closing, or an ssh connection dropping, reaches
//! the shell inside: the kernel sends `SIGHUP` to every process in the session
//! the terminal belonged to, and `SIGCONT` after it so a stopped job wakes up
//! to receive it.
//!
//! Without that signal a program whose terminal is gone never finds out. It
//! keeps running, its jobs are never cleaned up, and the only sign is that
//! reads start failing -- which a program blocked on something else never sees.
//!
//! Everything runs in a forked child: `setsid` fails for a process group
//! leader, and a program started from a shell is one.

use guest_tests::{Harness, check};
use std::ffi::CString;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

const TIOCSCTTY: u64 = 0x540E;
const TIOCGPGRP: u64 = 0x540F;
const TIOCGSID: u64 = 0x5429;

static HUPS: AtomicI32 = AtomicI32::new(0);
static CONTS: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_hup(_sig: i32) {
    HUPS.fetch_add(1, Ordering::SeqCst);
}
extern "C" fn on_cont(_sig: i32) {
    CONTS.fetch_add(1, Ordering::SeqCst);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn install(sig: i32, f: extern "C" fn(i32)) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = f as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn open_pty() -> Option<(i32, i32)> {
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        return None;
    }
    if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
        unsafe { libc::close(master) };
        return None;
    }
    let mut name = [0u8; 128];
    if unsafe { libc::ptsname_r(master, name.as_mut_ptr().cast(), name.len()) } != 0 {
        unsafe { libc::close(master) };
        return None;
    }
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let path = CString::new(&name[..end]).ok()?;
    let slave = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave < 0 {
        unsafe { libc::close(master) };
        return None;
    }
    Some((master, slave))
}

fn within(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    f()
}

fn child() -> i32 {
    let mut h = Harness::new();
    install(libc::SIGHUP, on_hup);
    install(libc::SIGCONT, on_cont);

    h.group("setup");
    let sid = unsafe { libc::setsid() };
    check!(h, sid > 0, "a session of our own: sid={sid} errno={}", errno());
    let Some((master, slave)) = open_pty() else {
        check!(h, false, "a pty pair");
        return h.finish();
    };
    check!(h, true, "a pty pair");
    let r = unsafe { libc::syscall(libc::SYS_ioctl, slave, TIOCSCTTY, 0) };
    check!(h, r == 0, "it is our controlling terminal: r={r} errno={}", errno());
    // TIOCGSID was ENOTTY for every terminal until 2026-11-11.
    let mut got = 0i32;
    let r = unsafe { libc::syscall(libc::SYS_ioctl, slave, TIOCGSID, &raw mut got) };
    check!(h, r == 0 && got == sid, "TIOCGSID on it is our session: r={r} got={got} sid={sid}");
    let mut got = 0i32;
    let r = unsafe { libc::syscall(libc::SYS_ioctl, master, TIOCGSID, &raw mut got) };
    check!(h, r == 0 && got == sid, "and on the master: r={r} got={got} sid={sid}");
    // Working before it is broken. Everything below is about a terminal that
    // has gone away, and a terminal that never worked would satisfy all of it.
    let n = unsafe { libc::write(slave, b"hello".as_ptr().cast(), 5) };
    check!(h, n == 5, "the slave writes: n={n}");
    let mut buf = [0u8; 32];
    let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
    check!(h, n >= 5, "and the master reads it back: n={n}");

    h.group("closing-the-master-signals-the-session");
    HUPS.store(0, Ordering::SeqCst);
    CONTS.store(0, Ordering::SeqCst);
    let r = unsafe { libc::close(master) };
    check!(h, r == 0, "closing the master: r={r}");
    let hup = within(Duration::from_secs(2), || HUPS.load(Ordering::SeqCst) > 0);
    check!(h, hup, "the session gets SIGHUP");
    // SIGCONT follows so that a job stopped by SIGTSTP wakes up to take the
    // SIGHUP rather than sitting stopped for ever with a terminal that is gone.
    let cont = within(Duration::from_secs(2), || CONTS.load(Ordering::SeqCst) > 0);
    check!(h, cont, "and SIGCONT after it");

    h.group("the-slave-is-hung-up");
    // A read from a hung-up terminal is end of file, not an error: the writing
    // end is gone and there is nothing more to come.
    let mut buf = [0u8; 32];
    let n = unsafe { libc::read(slave, buf.as_mut_ptr().cast(), buf.len()) };
    let e = errno();
    check!(h, n == 0, "reading it is end of file: n={n} errno={e}");
    // A write has nowhere to go and says so.
    let n = unsafe { libc::write(slave, b"x".as_ptr().cast(), 1) };
    let e = errno();
    check!(h, n == -1 && e == libc::EIO, "writing it is EIO: n={n} errno={e}");
    // And so does an ioctl.
    let mut pgrp = 0i32;
    let r = unsafe { libc::syscall(libc::SYS_ioctl, slave, TIOCGPGRP, &raw mut pgrp) };
    let e = errno();
    check!(h, r == -1 && e == libc::EIO, "and an ioctl on it: r={r} errno={e}");

    h.group("a-second-hangup-is-not-a-second-signal");
    // Closing the slave too. There is nothing left to hang up, so nothing more
    // should be delivered -- a kernel that signals on every close would signal
    // a session that has already been told.
    let before = HUPS.load(Ordering::SeqCst);
    unsafe { libc::close(slave) };
    std::thread::sleep(Duration::from_millis(100));
    check!(h, HUPS.load(Ordering::SeqCst) == before,
        "closing the slave sends nothing more: {} vs {before}", HUPS.load(Ordering::SeqCst));

    h.finish()
}

fn main() {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        std::process::exit(child());
    }
    if pid < 0 {
        eprintln!("  FAIL  [fork] could not fork: errno={}", errno());
        std::process::exit(1);
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    std::process::exit(if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 1 });
}
