//! A failed `pipe2` or `socketpair` must not close somebody else's descriptor.
//!
//! `sys_pipe2` creates the host pipe, wraps each end in a `struct fd`, and then
//! writes the two guest descriptor numbers to the caller's buffer. If that
//! write faults, it has to undo the wrapping — and a `struct fd` **owns** the
//! host descriptor it was given, so closing it again by number closes a number
//! this process no longer owns.
//!
//! The error labels fell through into a `close(p[0]); close(p[1])` that had
//! already been done by `f_close`. Single-threaded that is harmless: the
//! numbers are free and the second close answers EBADF. With another thread
//! opening files, the second close lands on whatever has since been opened at
//! that number.
//!
//! Any guest can reach it: `pipe2(<address I cannot write>)`.
//!
//! The probe is two threads. One calls `pipe2` with an unmapped address over
//! and over; the other opens a file, reads it back, and closes it, checking
//! every time that what it read is what it wrote. A descriptor taken away
//! underneath it shows up as a short read, a wrong byte, or EBADF.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use guest_tests::{Harness, check, sys};

/// An address no guest mapping covers. `pipe2` gets far enough to make the
/// host pipe and wrap both ends before it finds out.
const UNMAPPED: usize = 0x7fff_0000_0000;

const ROUNDS: u32 = 30000;
/// Several, so that at any instant one of them is between its `open` and its
/// `read` — which is the window a stolen descriptor number falls into.
const OPENERS: usize = 8;

fn main() {
    let mut h = Harness::new();
    h.group("pipe2-badaddr");

    // They really do fail, and with EFAULT. If either ever starts succeeding
    // the rest of the test is measuring nothing.
    let r = unsafe { libc::syscall(libc::SYS_pipe2, UNMAPPED, 0) };
    check!(
        h,
        r == -1 && sys::errno() == libc::EFAULT,
        "pipe2 to an unmapped address is EFAULT: r={r} errno={}",
        sys::errno()
    );
    let r = unsafe {
        libc::syscall(
            libc::SYS_socketpair,
            libc::AF_UNIX,
            libc::SOCK_STREAM,
            0,
            UNMAPPED,
        )
    };
    check!(
        h,
        r == -1 && sys::errno() == libc::EFAULT,
        "socketpair to an unmapped address is EFAULT: r={r} errno={}",
        sys::errno()
    );

    // Written once, before anything opens it. Every opener writing it would
    // truncate the file another was reading, and a short read is what this
    // test uses to mean "a descriptor was taken away" -- so the probe would
    // have been reporting on itself.
    let path = "/tmp/pipe-badaddr-victim";
    let body: &[u8] = b"the quick brown fox jumps over the lazy dog";
    std::fs::write(path, body).expect("the file to watch");

    let stop = AtomicBool::new(false);
    let lost = AtomicU32::new(0);
    let short = AtomicU32::new(0);
    let wrong = AtomicU32::new(0);

    std::thread::scope(|scope| {
        // The threads whose descriptors must survive.
        let stop = &stop;
        let lost = &lost;
        let short = &short;
        let wrong = &wrong;
        for _ in 0..OPENERS {
        scope.spawn(move || {
            let c = std::ffi::CString::new(path).expect("no NUL");
            // One descriptor held for the whole run, and a fresh one each time
            // round. The held one is what the EMFILE phase below needs: it
            // lowers RLIMIT_NOFILE for the whole process, so during that phase
            // nothing can *open* anything -- and an opener with nothing open
            // has nothing to lose.
            let held = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
            let mut buf = [0u8; 64];
            while !stop.load(Ordering::Relaxed) {
                if held >= 0 {
                    let n = unsafe {
                        libc::pread(held, buf.as_mut_ptr().cast(), buf.len(), 0)
                    };
                    if n < 0 {
                        lost.fetch_add(1, Ordering::Relaxed);
                    } else if n as usize != body.len() {
                        short.fetch_add(1, Ordering::Relaxed);
                    } else if &buf[..body.len()] != body {
                        wrong.fetch_add(1, Ordering::Relaxed);
                    }
                }
                let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
                if fd < 0 {
                    continue; // the EMFILE phase; the held one still speaks
                }
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    lost.fetch_add(1, Ordering::Relaxed);
                } else if n as usize != body.len() {
                    short.fetch_add(1, Ordering::Relaxed);
                } else if &buf[..body.len()] != body {
                    wrong.fetch_add(1, Ordering::Relaxed);
                }
                unsafe { libc::close(fd) };
            }
            if held >= 0 {
                unsafe { libc::close(held) };
            }
        });
        }

        // The *other* way in, and the more reachable one: EMFILE.
        //
        // `f_install` closes the descriptor when the table refuses it, so
        // every creation path that then closed it again double-closed on the
        // limit -- which any program that opens enough pipes or sockets
        // reaches, with no bad address needed. The limit is lowered, the
        // process opens until it is refused, and then everything is given
        // back.
        {
            let mut old: libc::rlimit = unsafe { std::mem::zeroed() };
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut old) };
            let low = libc::rlimit {
                rlim_cur: old.rlim_cur.min(64),
                rlim_max: old.rlim_max,
            };
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const low) };
            for _ in 0..200 {
                let mut held = Vec::new();
                loop {
                    let mut p = [0i32; 2];
                    if unsafe { libc::pipe(p.as_mut_ptr()) } != 0 {
                        break;
                    }
                    held.push(p[0]);
                    held.push(p[1]);
                }
                loop {
                    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
                    if s < 0 {
                        break;
                    }
                    held.push(s);
                }
                loop {
                    let mut sp = [0i32; 2];
                    if unsafe {
                        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sp.as_mut_ptr())
                    } != 0
                    {
                        break;
                    }
                    held.push(sp[0]);
                    held.push(sp[1]);
                }
                for fd in held {
                    unsafe { libc::close(fd) };
                }
            }
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const old) };
        }

        // Both, alternating: they had the identical error path and the
        // identical mistake in it.
        for _ in 0..ROUNDS {
            unsafe { libc::syscall(libc::SYS_pipe2, UNMAPPED, 0) };
            unsafe {
                libc::syscall(
                    libc::SYS_socketpair,
                    libc::AF_UNIX,
                    libc::SOCK_STREAM,
                    0,
                    UNMAPPED,
                )
            };
        }
        stop.store(true, Ordering::Relaxed);
    });

    let (l, s, w) = (
        lost.load(Ordering::Relaxed),
        short.load(Ordering::Relaxed),
        wrong.load(Ordering::Relaxed),
    );
    check!(
        h,
        l == 0 && s == 0 && w == 0,
        "{ROUNDS} failed pipe2 and socketpair calls took no descriptor from \
         another thread: \
         {l} reads failed, {s} came up short, {w} read the wrong bytes"
    );

    // And the process still has its descriptors: a double close that hit the
    // wrong number would show up here too.
    let mut probe = [0u8; 8];
    let n = unsafe {
        libc::read(
            libc::open(
                std::ffi::CString::new("/tmp/pipe-badaddr-victim")
                    .expect("no NUL")
                    .as_ptr(),
                libc::O_RDONLY,
            ),
            probe.as_mut_ptr().cast(),
            probe.len(),
        )
    };
    check!(h, n == 8, "and a fresh open still reads: {n}");

    let _ = std::io::stdout().flush();
    std::process::exit(h.finish());
}
