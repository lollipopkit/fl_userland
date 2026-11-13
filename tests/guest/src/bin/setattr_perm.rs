//! Who may `chmod` and `chown`.
//!
//! Linux:
//!
//! - `chmod`: the file's owner, or privileged. `EPERM` otherwise.
//! - `chown` changing the **uid**: privileged only.
//! - `chown` changing the **gid**: the owner may name a group they belong to;
//!   privileged may name any.
//! - a non-privileged change clears `S_ISUID`/`S_ISGID` on the file, so that
//!   ownership cannot be laundered into a set-id binary.
//!
//! `generic_setattrat` had no check of any kind: it normalised the path and
//! called the mount's `setattr`. With set-id exec working, that is a privilege
//! escalation and not merely a permissions bug — an unprivileged user could
//! `chown` a shell to root, `chmod` it setuid, and execute it. The last group
//! here does exactly that and asserts it does not work.
//!
//! Setup runs as root; a child at uid 1000 does the asking.

use guest_tests::{Harness, check, check_fails, cpath, sys};

fn getuid_of(path: &str) -> (u32, u32, u32) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(cpath(path).as_ptr(), &mut st) } != 0 {
        return (u32::MAX, u32::MAX, u32::MAX);
    }
    (st.st_uid, st.st_gid, st.st_mode & 0o7777)
}

fn main() {
    let mut args = std::env::args();
    let me = args.next().unwrap_or_default();
    if args.next().as_deref() == Some("report") {
        let mut e = 0u32;
        let (mut r, mut s) = (0u32, 0u32);
        unsafe { libc::syscall(libc::SYS_getresuid, &mut r, &mut e, &mut s) };
        println!("{e}");
        return;
    }

    let dir = "/tmp/setattr";
    let _ = std::fs::create_dir_all(dir);
    unsafe { libc::chmod(cpath(dir).as_ptr(), 0o777) };

    // A file owned by root that the child does not own.
    let theirs = format!("{dir}/theirs");
    let _ = std::fs::write(&theirs, b"x");
    unsafe {
        libc::chown(cpath(&theirs).as_ptr(), 0, 0);
        libc::chmod(cpath(&theirs).as_ptr(), 0o644);
    }
    // A file the child owns.
    let ours = format!("{dir}/ours");
    let _ = std::fs::write(&ours, b"x");
    unsafe {
        libc::chown(cpath(&ours).as_ptr(), 1000, 1000);
        libc::chmod(cpath(&ours).as_ptr(), 0o644);
    }
    // A copy of this binary for the escalation attempt.
    let shell = format!("{dir}/shell");
    let _ = std::fs::copy(&me, &shell);
    unsafe {
        libc::chown(cpath(&shell).as_ptr(), 1000, 1000);
        libc::chmod(cpath(&shell).as_ptr(), 0o755);
    }

    unsafe {
        let child = libc::fork();
        if child == 0 {
            libc::setresgid(1000, 1000, 1000);
            libc::setresuid(1000, 1000, 1000);
            let mut h = Harness::new();

            h.group("chmod");
            check_fails!(h, libc::chmod(cpath(&theirs).as_ptr(), 0o666),
                         libc::EPERM, "chmod a file we do not own");
            check!(h, libc::chmod(cpath(&ours).as_ptr(), 0o600) == 0,
                   "chmod a file we do own, errno {}", sys::errno());

            h.group("chown");
            check_fails!(h, libc::chown(cpath(&ours).as_ptr(), 0, u32::MAX),
                         libc::EPERM, "give away a file we own");
            check_fails!(h, libc::chown(cpath(&theirs).as_ptr(), 1000, u32::MAX),
                         libc::EPERM, "take a file we do not own");
            // A no-op chown is allowed: -1 for both, or naming the ids a file
            // already has. Programs do this to touch ctime.
            check!(h, libc::chown(cpath(&ours).as_ptr(), u32::MAX, u32::MAX) == 0,
                   "chown(-1, -1) on a file we own, errno {}", sys::errno());

            h.group("escalation");
            // The whole point. Both steps must fail; the exec afterwards is
            // the check that matters even if one of them somehow does not.
            let a = libc::chown(cpath(&shell).as_ptr(), 0, 0);
            let b = libc::chmod(cpath(&shell).as_ptr(), 0o4755);
            check!(h, a != 0, "chown a binary to root is refused");
            check!(h, b == 0 || a != 0, "and chmod setuid on it is not a way round");

            // Run it and see who we are. This is the assertion the rest exists
            // to make true.
            let mut fds = [0i32; 2];
            libc::pipe(fds.as_mut_ptr());
            let g = libc::fork();
            if g == 0 {
                libc::close(fds[0]);
                libc::dup2(fds[1], 1);
                let p = cpath(&shell);
                let arg = cpath("report");
                let argv = [p.as_ptr(), arg.as_ptr(), std::ptr::null()];
                libc::execv(p.as_ptr(), argv.as_ptr());
                libc::_exit(127);
            }
            libc::close(fds[1]);
            let mut buf = [0u8; 64];
            let n = libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len());
            libc::close(fds[0]);
            let mut st = 0;
            libc::waitpid(g, &mut st, 0);
            let got = String::from_utf8_lossy(&buf[..n.max(0) as usize]).trim().to_string();
            check!(h, got == "1000",
                   "executing it leaves us unprivileged: effective uid [{got}], wanted [1000]");

            libc::_exit(h.finish());
        }
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);

        // Root's own chown must still take the set-id bits with it: Linux kills
        // S_ISUID on any non-directory that changes owner, and S_ISGID too when
        // a group-execute bit says it is a real setgid binary. Without that, a
        // setuid-root binary handed to a user stays set-id.
        let mut h2 = Harness::new();
        h2.group("chown-clears-setid");
        for (name, start_mode, want_mode) in [
            ("suid", 0o4755u32, 0o0755u32),
            ("sgid-with-xgrp", 0o2755, 0o0755),
            // No group-execute: the mandatory-locking marker, which stays.
            ("sgid-no-xgrp", 0o2705, 0o2705),
        ] {
            let f = format!("{dir}/{name}");
            let _ = std::fs::write(&f, b"x");
            libc::chown(cpath(&f).as_ptr(), 0, 0);
            libc::chmod(cpath(&f).as_ptr(), start_mode as libc::mode_t);
            let before = getuid_of(&f).2;
            libc::chown(cpath(&f).as_ptr(), 1000, 1000);
            let after = getuid_of(&f).2;
            check!(
                h2,
                after == want_mode,
                "{name}: mode {before:o} chowned to 1000 became {after:o}, wanted {want_mode:o}"
            );
        }
        let extra = h2.finish();

        let owner = getuid_of(&shell);
        if owner.0 == 0 {
            eprintln!("  the binary ended up owned by root: {owner:?}");
        }
        let child_failures = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 1 };
        std::process::exit(child_failures + extra);
    }
}
