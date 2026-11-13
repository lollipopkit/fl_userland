//! A terminal that reports itself writable must accept a write.
//!
//! `tty_poll` set `POLL_WRITE` unconditionally, under a comment saying so:
//! "now that we have ptys, you can't always write without blocking". Writing to
//! one end of a pty feeds the other end's line discipline, and when that buffer
//! is full `tty_input` waits on `tty->consumed`. So a program that polls before
//! writing — which is the entire point of polling — was told to go ahead and
//! then blocked.

use guest_tests::{Harness, check, cpath};

fn open_pty() -> Option<(i32, i32)> {
    unsafe {
        // O_NOCTTY: see the note in poll_events.rs.
        let master = libc::open(cpath("/dev/ptmx").as_ptr(),
                                libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK);
        if master < 0 {
            return None;
        }
        libc::grantpt(master);
        libc::unlockpt(master);
        let name = libc::ptsname(master);
        if name.is_null() {
            return None;
        }
        let path = std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned();
        // Non-blocking on both ends: the drain loop below reads until it runs
        // out, and a blocking read on a pty does not return 0 when it is empty
        // -- it waits. That hung the first version of this test.
        let slave = libc::open(cpath(&path).as_ptr(),
                               libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK);
        if slave < 0 {
            return None;
        }
        // Raw mode, so this measures the buffer rather than the line
        // discipline. In canonical mode the slave cannot read an unterminated
        // line at all, so the drain below got nothing and the "writable again"
        // half of the test proved nothing.
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(slave, &mut t) == 0 {
            libc::cfmakeraw(&mut t);
            libc::tcsetattr(slave, libc::TCSANOW, &t);
        }
        Some((master, slave))
    }
}

fn pollout(fd: i32) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    unsafe { libc::poll(&mut p, 1, 0) };
    p.revents & libc::POLLOUT != 0
}

fn main() {
    let mut h = Harness::new();
    h.group("pollout-means-writable");

    let Some((master, slave)) = open_pty() else {
        check!(h, false, "opening a pty");
        std::process::exit(h.finish());
    };

    // The control first: an empty pty is writable and a write goes through.
    check!(h, pollout(master), "an idle pty master reports POLLOUT");
    let n = unsafe { libc::write(master, b"x".as_ptr().cast(), 1) };
    check!(h, n == 1, "and one byte goes in: {n}");

    // Fill the slave's input buffer. Nobody reads it, so this ends in EAGAIN.
    let block = [b'a'; 256];
    let mut total = 0usize;
    let mut hit_eagain = false;
    for _ in 0..4096 {
        let n = unsafe { libc::write(master, block.as_ptr().cast(), block.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EAGAIN {
                hit_eagain = true;
                break;
            }
            check!(h, false, "unexpected errno while filling: {e}");
            break;
        }
        total += n as usize;
        if n < block.len() as isize {
            // A short write means the buffer took what it could: it is full.
            hit_eagain = true;
            break;
        }
    }
    check!(h, hit_eagain, "the buffer fills after {total} bytes");

    if hit_eagain {
        // This is the check. The buffer is full; a write would block. poll must
        // not claim otherwise.
        check!(h, !pollout(master),
            "a full pty master does not report POLLOUT (it wrote {total} bytes first)");
    }

    h.group("and-becomes-writable-again");
    // Drain the slave and the master must report writable once more, or the
    // fix would be "never writable".
    let mut sink = [0u8; 4096];
    let mut drained = 0;
    for _ in 0..4096 {
        let n = unsafe { libc::read(slave, sink.as_mut_ptr().cast(), sink.len()) };
        if n <= 0 { break; }
        drained += n as usize;
    }
    check!(h, drained > 0, "the slave read {drained} bytes back");
    check!(h, pollout(master), "and the master reports POLLOUT again");
    let n = unsafe { libc::write(master, b"y".as_ptr().cast(), 1) };
    check!(h, n == 1, "and accepts a write: {n}");

    unsafe { libc::close(slave); libc::close(master); }
    std::process::exit(h.finish());
}
