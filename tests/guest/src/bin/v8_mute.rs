//! V8's fatal-abort chatter is dropped on the way out, and everything else is
//! not.
//!
//! V8 prints its fatal preamble to stderr *before* executing `BRK #0`, so by the
//! time the emulator's `SIGTRAP` handler runs the text is already on the host
//! terminal. The write path recognises the banner and reports that the bytes
//! went through while dropping them.
//!
//! Two things make this worth a test rather than a comment. The filter is
//! **sticky**: one match puts the whole thread group in abort mode and every
//! later stderr write is dropped, so a false positive costs a program the rest
//! of its output. And it is easy for it to stop firing at all without anything
//! failing — the signatures are a list, the check is one call, and a write path
//! that stopped consulting it would look exactly the same from outside.
//!
//! This is **not** comparable against a real kernel: Linux drops nothing. It is
//! in `differential.sh`'s `not_comparable()`.
//!
//! # Each case forks
//!
//! Because the flag is per thread group and never cleared, a process that has
//! matched once cannot test anything else. So the parent forks per case, and
//! the child replaces its stderr with a pipe the parent reads.

use guest_tests::{Harness, check};
use std::io::Read;
use std::os::fd::FromRawFd;

/// Run `body` in a child whose stderr is a pipe, and answer what came out of it
/// along with the child's exit status.
fn stderr_of(body: impl FnOnce()) -> String {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (read_end, write_end) = (fds[0], fds[1]);

    // SAFETY: the child only writes and exits.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::dup2(write_end, 2);
            libc::close(read_end);
            libc::close(write_end);
        }
        body();
        std::process::exit(0);
    }
    unsafe { libc::close(write_end) };
    let mut out = String::new();
    let mut file = unsafe { std::fs::File::from_raw_fd(read_end) };
    let _ = file.read_to_string(&mut out);
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    out
}

fn write_stderr(text: &str) -> isize {
    unsafe { libc::write(2, text.as_ptr().cast(), text.len()) as isize }
}

fn main() {
    let mut h = Harness::new();
    h.group("v8-mute");

    // The banner is dropped, the call reports the whole length, and everything
    // after it on that stderr is dropped too -- which is the sticky part.
    let banner = "# Fatal error in ../deps/v8/src/heap/heap.cc\n";
    let out = stderr_of(|| {
        let n = write_stderr(banner);
        // Printed on *stdout*, so it does not disturb what is measured.
        println!("banner write returned {n} of {}", banner.len());
        write_stderr("this line follows the banner\n");
    });
    check!(h, out.is_empty(), "the banner is dropped, and so is what follows it: {out:?}");

    // A program that prints something similar is not silenced. One match would
    // cost it every later line, and these are the strings the signature list
    // has to be narrow enough to miss.
    for line in [
        "abort: config not found\n",
        "FATAL ERROR: could not open the database\n",
        "Check failed: the user's own assertion\n",
        "# Fatal\n",
    ] {
        let out = stderr_of(|| {
            write_stderr(line);
            write_stderr("and the line after it\n");
        });
        check!(
            h,
            out == format!("{line}and the line after it\n"),
            "{:?} is not silenced: got {out:?}",
            line.trim_end()
        );
    }

    // The count is the whole write whether or not the bytes went anywhere: a
    // caller that got a short count would loop and print the tail.
    let out = stderr_of(|| {
        let n = write_stderr(banner);
        println!("{n}");
    });
    check!(h, out.is_empty(), "and the muted write is still reported in full");

    // Stdout is never filtered, whatever it says. The check is on fd 2 alone,
    // and a program's own stdout is not the emulator's business.
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::dup2(fds[1], 1);
            libc::close(fds[0]);
            libc::close(fds[1]);
            libc::write(1, banner.as_ptr().cast(), banner.len());
        }
        std::process::exit(0);
    }
    unsafe { libc::close(fds[1]) };
    let mut out = String::new();
    let mut file = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let _ = file.read_to_string(&mut out);
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    check!(h, out == banner, "stdout is never filtered: {out:?}");

    std::process::exit(h.finish());
}
