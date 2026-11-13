//! The mode of a pipe, a socket and an eventfd: set by `fchmod`, kept across
//! `dup`, and present at all on the stdio a host hands over.
//!
//! Two defects with one cause, fixed 2026-10-18. A description's mode, owner
//! and group are atomics a driver may change after creation, and they were
//! seeded from the creation-time `stat` **at each install** -- so a `dup` or
//! `F_DUPFD` put back the mode a `fchmod` had changed, and the CLI's stdio,
//! installed without that function, was never seeded and reported mode 0
//! (`stat` called it a "weird file"; node decides how to write to stdout from
//! that type).

use guest_tests::{Harness, check};

fn mode(fd: i32) -> u32 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a descriptor and a buffer.
    assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0, "fstat {fd}");
    st.st_mode
}

/// `fchmod` to 0640, then `dup` and `F_DUPFD`: all three report 0640.
fn kept_across_dup(h: &mut Harness, group: &'static str, fd: i32) {
    h.group(group);
    // SAFETY: plain syscalls on an open descriptor.
    let r = unsafe { libc::fchmod(fd, 0o640) };
    check!(h, r == 0, "fchmod: {r}");
    let d = unsafe { libc::dup(fd) };
    let f = unsafe { libc::fcntl(fd, libc::F_DUPFD, 100) };
    for (name, n) in [("the original", fd), ("dup", d), ("F_DUPFD", f)] {
        let m = mode(n) & 0o7777;
        check!(h, m == 0o640, "{name}: {m:o}");
    }
    unsafe {
        libc::close(d);
        libc::close(f);
    }
}

fn main() {
    let mut h = Harness::new();

    let mut p = [0; 2];
    // SAFETY: fills `p`.
    unsafe { libc::pipe(p.as_mut_ptr()) };
    kept_across_dup(&mut h, "pipe-fchmod-survives-dup", p[0]);

    let mut s = [0; 2];
    // SAFETY: fills `s`.
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, s.as_mut_ptr()) };
    kept_across_dup(&mut h, "socket-fchmod-survives-dup", s[0]);

    h.group("stdio-has-a-file-type");
    // Whatever the runner connected them to -- a pipe, a file, a terminal --
    // each has a type. Zero is not one.
    for fd in 0..3 {
        let t = mode(fd) & libc::S_IFMT;
        check!(h, t != 0, "fd {fd}: mode {:o}", mode(fd));
    }

    std::process::exit(h.finish());
}
