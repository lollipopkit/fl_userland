//! The `#!` line, and what happens at the end of the kernel's buffer.
//!
//! Every question here is about that end, and none of the answers is obvious.
//! All of them were measured against a real arm64 kernel:
//!
//! - The buffer is **256 bytes** — Linux's `BINPRM_BUF_SIZE`. This kernel read
//!   128, so a longer line had its argument silently cut in half.
//! - A **truncated interpreter path is `ENOEXEC`**, not something to execute.
//!   Running whatever the shortened name happens to hit is running a different
//!   program than the script asked for.
//! - A **truncated argument is fine**: the interpreter re-reads the script,
//!   which is what `env` and `awk` do.
//!
//! `execve` directly rather than through a shell, because a shell turns
//! `ENOEXEC` into "interpret it myself" and the errno is the thing being
//! checked.

use guest_tests::{Harness, check};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

/// Not `/tmp/shebang_abi`: the harness copies every test binary into `/tmp`
/// under its own name, so that path is *this program*. `create_dir_all` then
/// found a regular file where it wanted a directory and said so, which is
/// correct and took a minute to read as such.
const DIR: &str = "/tmp/shebang_abi.d";

fn script(name: &str, body: &[u8]) -> String {
    let path = format!("{DIR}/{name}");
    let mut f = std::fs::File::create(&path).expect("create");
    f.write_all(body).expect("write");
    drop(f);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

/// Run it and give back `(exit status, stdout)`, or the `execve` errno.
fn run(path: &str) -> Result<(i32, String), i32> {
    // Everything the child needs is built **before** the fork. A child of a
    // multithreaded process may call only async-signal-safe functions until it
    // execs, and `CString::new` allocates: doing it after the fork is a malloc
    // lock whose state is whatever the other threads left it in. The first
    // version did, and the child aborted silently -- exit 134 with nothing on
    // either stream, which reads as a kernel fault and is not one.
    let cpath = std::ffi::CString::new(path).unwrap();
    let argv = [cpath.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null()];

    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(-1);
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(fds[0]);
            libc::dup2(fds[1], 1);
            libc::close(fds[1]);
            libc::execve(cpath.as_ptr(), argv.as_ptr(), envp.as_ptr());
            // The errno goes back through the exit status, which is the only
            // channel a failed exec has.
            libc::_exit(128 + (*libc::__errno_location() & 0x7f));
        }
    }
    unsafe { libc::close(fds[1]) };
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    unsafe { libc::close(fds[0]) };
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = libc::WEXITSTATUS(status);
    if code >= 128 {
        return Err(code - 128);
    }
    Ok((code, String::from_utf8_lossy(&out).into_owned()))
}

fn main() {
    let mut h = Harness::new();
    let _ = std::fs::remove_dir_all(DIR);
    std::fs::create_dir_all(DIR).expect("mkdir");

    h.group("the-plain-case");
    let p = script("plain", b"#!/bin/echo hi\n");
    match run(&p) {
        Ok((code, out)) => {
            check!(h, code == 0, "exit {code}");
            check!(h, out.trim() == format!("hi {p}"), "output {out:?}");
        }
        Err(e) => check!(h, false, "execve failed: errno {e}"),
    }

    h.group("the-argument-is-one-string");
    // Everything after the interpreter is a single argument, internal spaces
    // included -- which is why `#!/usr/bin/env python3 -u` does not work.
    let p = script("inner", b"#!/bin/echo a b   c\n");
    match run(&p) {
        Ok((_, out)) => check!(h, out.trim() == format!("a b   c {p}"), "output {out:?}"),
        Err(e) => check!(h, false, "errno {e}"),
    }

    h.group("trailing-blanks-are-stripped");
    // Otherwise the interpreter gets an empty first argument.
    let p = script("trail", b"#!/bin/echo   \t  \n");
    match run(&p) {
        Ok((_, out)) => check!(
            h,
            out.trim() == p,
            "only the script's path, not an empty argument: {out:?}"
        ),
        Err(e) => check!(h, false, "errno {e}"),
    }

    h.group("tabs-are-blanks");
    let p = script("tabs", b"#!\t/bin/echo\thi\n");
    match run(&p) {
        Ok((_, out)) => check!(h, out.trim() == format!("hi {p}"), "output {out:?}"),
        Err(e) => check!(h, false, "errno {e}"),
    }

    h.group("a-file-with-no-trailing-newline-is-a-script");
    let p = script("nonewline", b"#!/bin/echo hi");
    match run(&p) {
        Ok((code, out)) => {
            check!(h, code == 0, "exit {code}");
            check!(h, out.contains("hi"), "output {out:?}");
        }
        Err(e) => check!(h, false, "errno {e}"),
    }

    h.group("the-buffer-is-256-bytes");
    // A line that fills it exactly: the whole argument comes through.
    let prefix = b"#!/bin/echo ";
    let pad = 256 - prefix.len() - 1;
    let mut body = prefix.to_vec();
    body.extend(std::iter::repeat_n(b'x', pad));
    body.push(b'\n');
    assert_eq!(body.len(), 256);
    let p = script("edge", &body);
    match run(&p) {
        Ok((_, out)) => {
            let xs = out.chars().filter(|&c| c == 'x').count();
            check!(h, xs == pad, "the whole {pad}-byte argument arrived, not {xs}");
        }
        Err(e) => check!(h, false, "errno {e}"),
    }

    h.group("a-truncated-interpreter-path-is-enoexec");
    // No newline, and the path runs past the buffer, so it may be the start of
    // a longer one. Executing what the shortened name hits is executing a
    // different program.
    let mut body = b"#!/bin/echo".to_vec();
    body.extend(std::iter::repeat_n(b'A', 400));
    let p = script("trunc", &body);
    match run(&p) {
        Ok((code, out)) => check!(
            h,
            false,
            "it ran a truncated path: exit {code}, output {out:?}"
        ),
        Err(e) => check!(h, e == libc::ENOEXEC, "errno {e}, want ENOEXEC"),
    }

    h.group("a-truncated-argument-is-still-a-script");
    // The path is complete because a blank follows it. Only the argument is in
    // doubt, and the interpreter can re-read the script.
    let mut body = b"#!/bin/echo ".to_vec();
    body.extend(std::iter::repeat_n(b'A', 400));
    let p = script("truncarg", &body);
    match run(&p) {
        Ok((code, out)) => {
            check!(h, code == 0, "exit {code}");
            let as_ = out.chars().filter(|&c| c == 'A').count();
            check!(h, as_ > 200, "as much of the argument as fit: {as_}");
        }
        Err(e) => check!(h, false, "errno {e}"),
    }

    h.group("what-is-not-a-script");
    for (name, body) in [
        ("hash", &b"#!\n"[..]),
        ("blanks", &b"#!   \t \n"[..]),
        ("nothash", &b"#x/bin/sh\n"[..]),
    ] {
        let p = script(name, body);
        match run(&p) {
            Ok((code, out)) => check!(h, false, "{name} ran: exit {code}, {out:?}"),
            Err(e) => check!(h, e == libc::ENOEXEC, "{name}: errno {e}, want ENOEXEC"),
        }
    }

    h.group("a-missing-interpreter-is-enoent");
    let p = script("missing", b"#!/nonexistent/interpreter\n");
    match run(&p) {
        Ok((code, out)) => check!(h, false, "it ran: exit {code}, {out:?}"),
        Err(e) => check!(h, e == libc::ENOENT, "errno {e}, want ENOENT"),
    }

    let _ = std::fs::remove_dir_all(DIR);
    std::process::exit(h.finish());
}
