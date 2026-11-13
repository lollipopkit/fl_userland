//! What a *background* process group may do to a terminal.
//!
//! Reading is the well-known half: a background read raises `SIGTTIN`. The
//! other half is that changing a terminal's settings is treated the same way,
//! and always — `tcsetattr` from a background group raises `SIGTTOU` whether or
//! not `TOSTOP` is set, because a background process reconfiguring the terminal
//! the foreground one is using is never wanted. Writing is the case `TOSTOP`
//! actually governs, and it is off by default.
//!
//! Linux's `tty_check_change` is the whole rule, and its shape is surprising in
//! two places:
//!
//! - if the signal is *ignored*, the operation is allowed rather than refused.
//!   A program that has said it does not care is taken at its word.
//! - if the group is orphaned, it is `EIO`. There would be nobody left to send
//!   `SIGCONT`, so stopping it would be a hang.
//!
//! Everything runs in a forked child, because `setsid` fails for a process
//! group leader, and the background work in a grandchild of that.

use guest_tests::{Harness, check};
use std::ffi::CString;
use std::sync::atomic::{AtomicI32, Ordering};

const TIOCSCTTY: u64 = 0x540E;
const TOSTOP: libc::tcflag_t = 0o0000400;

static TTOU: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_ttou(_sig: i32) {
    TTOU.fetch_add(1, Ordering::SeqCst);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
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

/// What one probe reports back through the pipe.
#[derive(Default, Clone, Copy)]
#[repr(C)]
struct Report {
    result: i32,
    err: i32,
    signals: i32,
}

/// Runs `f` in a child that is in a process group of its own — the background
/// group, since the caller stays in the terminal's foreground one.
///
/// With `orphan`, that child forks once more and exits, so the group left
/// running has no parent in another group of the same session: nobody who could
/// ever send it `SIGCONT`, which is what makes stopping it a hang and what the
/// kernel answers `EIO` for instead.
fn in_background_maybe_orphaned(orphan: bool, f: impl FnOnce() -> Report) -> Option<Report> {
    let mut pipefd = [0i32; 2];
    if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
        return None;
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(pipefd[0]) };
        unsafe { libc::setpgid(0, 0) };
        if orphan {
            // The grandchild stays in this group and inherits the pipe; this
            // process leaves, so the group's only member has no parent in the
            // session at all.
            let g = unsafe { libc::fork() };
            if g != 0 {
                unsafe { libc::_exit(0) };
            }
            // Long enough for the parent above to have been reaped, so the
            // group really is orphaned by the time the probe runs.
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        let r = f();
        let bytes: [i32; 3] = [r.result, r.err, r.signals];
        unsafe { libc::write(pipefd[1], bytes.as_ptr().cast(), 12) };
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(pipefd[1]) };
    if pid < 0 {
        unsafe { libc::close(pipefd[0]) };
        return None;
    }
    // Nonblocking, because "bounded" is not what a blocking read is. A probe
    // whose child forks — one does, to show a whole group being signalled —
    // leaves the write end open in the grandchild, so a child that gets
    // stopped instead of answering leaves this read with a writer that never
    // writes, and the loop below never gets to its own limit. That hung the
    // whole test rather than failing one check.
    unsafe {
        let flags = libc::fcntl(pipefd[0], libc::F_GETFL);
        libc::fcntl(pipefd[0], libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    // Bounded: a child that got stopped instead of answering never writes, and
    // this must report that rather than hang.
    let mut got = [0i32; 3];
    let mut read_bytes = 0;
    for _ in 0..200 {
        let n = unsafe {
            libc::read(pipefd[0], (got.as_mut_ptr() as *mut u8).add(read_bytes).cast(),
                       12 - read_bytes)
        };
        if n > 0 {
            read_bytes += n as usize;
            if read_bytes == 12 {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    unsafe { libc::close(pipefd[0]) };
    // The child may be stopped; kill the whole group either way so nothing is
    // left behind. Negative pid is the group, which for the orphan case is
    // where the grandchild is.
    unsafe { libc::kill(-pid, libc::SIGCONT) };
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if read_bytes != 12 {
        return None;
    }
    Some(Report { result: got[0], err: got[1], signals: got[2] })
}

fn in_background(f: impl FnOnce() -> Report) -> Option<Report> {
    in_background_maybe_orphaned(false, f)
}

fn set_ttou(how: usize) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = match how {
            0 => libc::SIG_IGN,
            _ => on_ttou as *const () as usize,
        };
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGTTOU, &sa, std::ptr::null_mut());
    }
}

fn child() -> i32 {
    let mut h = Harness::new();
    unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };

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

    h.group("the-foreground-group-may-do-anything");
    // The control. Everything below is about being refused, and a terminal that
    // refuses everyone would satisfy all of it.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    check!(h, unsafe { libc::tcgetattr(slave, &mut t) } == 0, "tcgetattr from the foreground");
    check!(h, unsafe { libc::tcsetattr(slave, libc::TCSANOW, &t) } == 0,
        "tcsetattr from the foreground: errno={}", errno());
    let n = unsafe { libc::write(slave, b"fg".as_ptr().cast(), 2) };
    check!(h, n == 2, "and a write: n={n}");

    h.group("background-tcsetattr-with-the-signal-ignored");
    // Ignored means "I have said I do not care", and Linux takes that at its
    // word: the call goes through rather than being refused.
    let got = in_background(|| {
        set_ttou(0);
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(slave, &mut t) };
        let r = unsafe { libc::tcsetattr(slave, libc::TCSANOW, &t) };
        Report { result: r, err: errno(), signals: 0 }
    });
    match got {
        Some(r) => check!(h, r.result == 0, "it succeeds: r={} errno={}", r.result, r.err),
        None => check!(h, false, "the background child answered"),
    }

    h.group("background-tcsetattr-with-a-handler");
    // Handled means the signal is delivered and the call does not complete.
    // Whether the caller sees EINTR or the call is restarted is up to the
    // handler's SA_RESTART, which is off here.
    let got = in_background(|| {
        TTOU.store(0, Ordering::SeqCst);
        set_ttou(1);
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(slave, &mut t) };
        let r = unsafe { libc::tcsetattr(slave, libc::TCSANOW, &t) };
        Report { result: r, err: errno(), signals: TTOU.load(Ordering::SeqCst) }
    });
    match got {
        Some(r) => {
            check!(h, r.signals > 0, "SIGTTOU is delivered: signals={}", r.signals);
            check!(h, r.result == -1 && r.err == libc::EINTR,
                "and the call is interrupted: r={} errno={}", r.result, r.err);
        }
        None => {
            for _ in 0..2 {
                check!(h, false, "the background child answered");
            }
        }
    }

    h.group("background-write-without-TOSTOP");
    // The default. Writing from the background is allowed; only reading is
    // stopped, which is why a background job's output interleaves with the
    // shell's and its input does not.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    unsafe { libc::tcgetattr(slave, &mut t) };
    t.c_lflag &= !TOSTOP;
    unsafe { libc::tcsetattr(slave, libc::TCSANOW, &t) };
    let got = in_background(|| {
        set_ttou(1);
        TTOU.store(0, Ordering::SeqCst);
        let n = unsafe { libc::write(slave, b"bg".as_ptr().cast(), 2) };
        Report { result: n as i32, err: errno(), signals: TTOU.load(Ordering::SeqCst) }
    });
    match got {
        Some(r) => {
            check!(h, r.result == 2, "the write goes through: r={} errno={}", r.result, r.err);
            check!(h, r.signals == 0, "and nothing is signalled: signals={}", r.signals);
        }
        None => {
            for _ in 0..2 {
                check!(h, false, "the background child answered");
            }
        }
    }

    h.group("background-write-with-TOSTOP");
    // The case TOSTOP exists for, and the flag was read by nothing: it was
    // defined in fs/tty.h and never consulted, so `stty tostop` did not change
    // what a background job could do. Linux checks it in n_tty_write and
    // answers EINTR after signalling.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    unsafe { libc::tcgetattr(slave, &mut t) };
    t.c_lflag |= TOSTOP;
    unsafe { libc::tcsetattr(slave, libc::TCSANOW, &t) };
    let got = in_background(|| {
        set_ttou(1);
        TTOU.store(0, Ordering::SeqCst);
        let n = unsafe { libc::write(slave, b"bg".as_ptr().cast(), 2) };
        Report { result: n as i32, err: errno(), signals: TTOU.load(Ordering::SeqCst) }
    });
    match got {
        Some(r) => {
            check!(h, r.signals > 0, "SIGTTOU is delivered: signals={}", r.signals);
            check!(h, r.result == -1 && r.err == libc::EINTR,
                "and the write is interrupted: r={} errno={}", r.result, r.err);
        }
        None => {
            for _ in 0..2 {
                check!(h, false, "the background child answered");
            }
        }
    }
    // Back off, so the groups below are not all measuring this flag.
    t.c_lflag &= !TOSTOP;
    unsafe { libc::tcsetattr(slave, libc::TCSANOW, &t) };

    h.group("the-whole-background-group-is-signalled");
    // Linux's tty_check_change signals the process *group* (kill_pgrp), so a
    // background job of several processes stops together. This kernel signalled
    // only the caller, so the rest of a pipeline carried on and each member
    // stopped one at a time as it reached the terminal -- which for a pipeline
    // reading from the tty means the second one's read succeeds against input
    // meant for the first.
    //
    // The probe: the background child forks a sibling that does nothing but
    // wait, and reports whether that sibling was stopped by the read the child
    // made. Only a group-wide signal stops a process that never touched the
    // terminal.
    let got = in_background(|| {
        set_ttou(1);
        // The child must survive the signal to report, so it handles SIGTTIN;
        // the sibling must not, because being stopped is the whole answer.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_ttou as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(libc::SIGTTIN, &sa, std::ptr::null_mut());
        }
        let sibling = unsafe { libc::fork() };
        if sibling == 0 {
            // Nothing to do with the terminal at all: whether this stops is
            // entirely about who the signal was sent to.
            unsafe { libc::signal(libc::SIGTTIN, libc::SIG_DFL) };
            std::thread::sleep(std::time::Duration::from_millis(2000));
            unsafe { libc::_exit(0) };
        }
        // Give it time to be running before the read raises the signal.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut buf = [0u8; 4];
        unsafe { libc::read(slave, buf.as_mut_ptr().cast(), buf.len()) };
        // WUNTRACED reports a child that stopped rather than exited.
        let mut st = 0;
        let mut stopped = 0;
        for _ in 0..100 {
            let w = unsafe { libc::waitpid(sibling, &mut st, libc::WNOHANG | libc::WUNTRACED) };
            if w == sibling && libc::WIFSTOPPED(st) {
                stopped = 1;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        unsafe { libc::kill(sibling, libc::SIGCONT) };
        unsafe { libc::kill(sibling, libc::SIGKILL) };
        unsafe { libc::waitpid(sibling, &mut st, 0) };
        Report { result: stopped, err: 0, signals: 0 }
    });
    match got {
        Some(r) => check!(h, r.result == 1,
            "a group member that never touched the terminal was stopped too"),
        None => check!(h, false, "the background child answered"),
    }

    h.group("background-read-is-stopped");
    // The half that has always worked, kept here so the group above is not the
    // only evidence that "background" means anything at all.
    let got = in_background(|| {
        set_ttou(1);
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        unsafe {
            sa.sa_sigaction = on_ttou as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(libc::SIGTTIN, &sa, std::ptr::null_mut());
        }
        TTOU.store(0, Ordering::SeqCst);
        let mut buf = [0u8; 4];
        let n = unsafe { libc::read(slave, buf.as_mut_ptr().cast(), buf.len()) };
        Report { result: n as i32, err: errno(), signals: TTOU.load(Ordering::SeqCst) }
    });
    match got {
        Some(r) => {
            check!(h, r.signals > 0, "SIGTTIN is delivered: signals={}", r.signals);
            check!(h, r.result == -1 && r.err == libc::EINTR,
                "and the read is interrupted: r={} errno={}", r.result, r.err);
        }
        None => {
            for _ in 0..2 {
                check!(h, false, "the background child answered");
            }
        }
    }

    h.group("an-orphaned-group-that-ignores-the-signal");
    // The order of the last two checks, and it is not the order they read in.
    // Linux asks "is the signal ignored" *before* "is the group orphaned", so
    // this is allowed. Asking about the orphan first -- which reads just as
    // natural, and is what this kernel did -- refuses it with EIO.
    let got = in_background_maybe_orphaned(true, || {
        set_ttou(0);
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(slave, &mut t) };
        let r = unsafe { libc::tcsetattr(slave, libc::TCSANOW, &t) };
        Report { result: r, err: errno(), signals: 0 }
    });
    match got {
        Some(r) => check!(h, r.result == 0,
            "an orphaned group ignoring SIGTTOU proceeds: r={} errno={}", r.result, r.err),
        None => check!(h, false, "the orphaned child answered"),
    }

    h.group("an-orphaned-group-that-handles-the-signal");
    // With the signal not ignored, the orphan answer decides again: stopping a
    // group nobody can continue would be a hang, so it is EIO and no signal.
    let got = in_background_maybe_orphaned(true, || {
        TTOU.store(0, Ordering::SeqCst);
        set_ttou(1);
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(slave, &mut t) };
        let r = unsafe { libc::tcsetattr(slave, libc::TCSANOW, &t) };
        Report { result: r, err: errno(), signals: TTOU.load(Ordering::SeqCst) }
    });
    match got {
        Some(r) => {
            check!(h, r.result == -1 && r.err == libc::EIO,
                "an orphaned group handling SIGTTOU is EIO: r={} errno={}", r.result, r.err);
            check!(h, r.signals == 0, "and is not signalled: signals={}", r.signals);
        }
        None => {
            for _ in 0..2 {
                check!(h, false, "the orphaned child answered");
            }
        }
    }

    unsafe { libc::close(slave) };
    unsafe { libc::close(master) };
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
