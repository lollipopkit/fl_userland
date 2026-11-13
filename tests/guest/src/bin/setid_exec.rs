//! What `execve` does to the credentials.
//!
//! Linux, after any exec: the saved set-user-ID follows the effective one
//! (`cap_bprm_creds_from_file` ends with `new->suid = new->fsuid = new->euid`),
//! and on a `S_ISUID` file the effective id first becomes the file's owner. So
//! a root-owned setuid binary run by uid 1000 arrives at
//! `(real 1000, effective 0, saved 0)`.
//!
//! `kernel/exec.c` had it as `current->suid = current->euid; current->euid =
//! stat.uid;` — the saved id took the **old** effective id. That is more
//! restrictive rather than less, so it was not a hole, but it breaks the
//! drop-and-regain that every setuid helper does: `seteuid(user)` to do the
//! unprivileged part, `seteuid(0)` to do the privileged part. With the saved id
//! left at 1000 the second call fails.
//!
//! Also: `S_ISGID` on a file without `S_IXGRP` is not a setgid binary. Linux
//! reads that combination as the mandatory-locking marker and does not change
//! the effective group for it.
//!
//! Runs on fakefs, where the modes are this kernel's own. On a passthrough
//! mount the host owns the setuid bit and will not let a guest set it.

use guest_tests::{Harness, check, cpath};

fn getres() -> (u32, u32, u32, u32, u32, u32) {
    let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
    let (mut rg, mut eg, mut sg) = (0u32, 0u32, 0u32);
    unsafe {
        libc::syscall(libc::SYS_getresuid, &mut r, &mut e, &mut s);
        libc::syscall(libc::SYS_getresgid, &mut rg, &mut eg, &mut sg);
    }
    (r, e, s, rg, eg, sg)
}

/// The three per-thread attributes an `execve` is supposed to reset, read back
/// after one.
///
/// `keepcaps` goes on **every** exec; the parent-death signal and `dumpable`
/// only on one that gained privilege. The second rule is the one that matters:
/// without it an unprivileged process sets a parent-death signal, execs a
/// setuid binary, and the privileged program is signalled at a moment the
/// parent chooses by exiting.
fn attrs() -> (i32, i32, i32) {
    let mut pdeath = -1i32;
    unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut pdeath) };
    let keepcaps = unsafe { libc::prctl(libc::PR_GET_KEEPCAPS) };
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
    (pdeath, keepcaps, dumpable)
}

/// Runs `prog` as uid/gid 1000, having set all three attributes first, and
/// returns what it printed.
fn run_as_1000(prog: &str) -> String {
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(fds[0]);
            libc::dup2(fds[1], 1);
            libc::close(fds[1]);
            libc::setresgid(1000, 1000, 1000);
            libc::setresuid(1000, 1000, 1000);
            // Set in the child, before the exec, so what the report prints is
            // what the exec left behind.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGUSR1);
            libc::prctl(libc::PR_SET_KEEPCAPS, 1);
            libc::prctl(libc::PR_SET_DUMPABLE, 1);
            let p = cpath(prog);
            let arg = cpath("report");
            let argv = [p.as_ptr(), arg.as_ptr(), std::ptr::null()];
            libc::execv(p.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    unsafe { libc::close(fds[1]) };
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    unsafe {
        libc::close(fds[0]);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }
    String::from_utf8_lossy(&out).trim().to_string()
}

fn main() {
    let mut args = std::env::args();
    let me = args.next().unwrap_or_default();
    if args.next().as_deref() == Some("report") {
        let (r, e, s, rg, eg, sg) = getres();
        let (pdeath, keepcaps, dumpable) = attrs();
        println!("{r} {e} {s} {rg} {eg} {sg} {pdeath} {keepcaps} {dumpable}");
        return;
    }

    let dir = "/tmp/setid";
    let _ = std::fs::create_dir_all(dir);
    let setuid_bin = format!("{dir}/suid");
    let setgid_bin = format!("{dir}/sgid");
    let setgid_noxgrp = format!("{dir}/sgid_noxgrp");
    for (dst, uid, gid, mode) in [
        // Owned by root, setuid, executable by everyone.
        (&setuid_bin, 0u32, 0u32, 0o4755u32),
        // Group 4242, setgid *with* group-execute: a real setgid binary.
        (&setgid_bin, 0, 4242, 0o2755),
        // Setgid *without* group-execute: the mandatory-locking marker, which
        // is not a setgid binary. Other-execute so uid 1000 can still run it.
        (&setgid_noxgrp, 0, 4242, 0o2705),
    ] {
        if std::fs::copy(&me, dst).is_err() {
            eprintln!("could not copy {me} to {dst}");
            return;
        }
        unsafe {
            libc::chown(cpath(dst).as_ptr(), uid, gid);
            libc::chmod(cpath(dst).as_ptr(), mode as libc::mode_t);
        }
    }

    let mut h = Harness::new();
    h.group("setuid-exec");

    // real stays 1000; effective becomes the owner; saved follows the effective.
    let got = run_as_1000(&setuid_bin);
    check!(
        h,
        got.starts_with("1000 0 0 1000 1000 1000 "),
        "a root-owned setuid binary run by 1000: got [{got}], wanted [1000 0 0 1000 1000 1000 ...]"
    );

    h.group("setgid-exec");
    let got = run_as_1000(&setgid_bin);
    check!(
        h,
        got.starts_with("1000 1000 1000 1000 4242 4242 "),
        "a setgid binary with group-execute: got [{got}], wanted [1000 1000 1000 1000 4242 4242 ...]"
    );

    // The control, and the reason the S_IXGRP half matters: without it this is
    // not a setgid binary and the effective group must not move.
    let got = run_as_1000(&setgid_noxgrp);
    check!(
        h,
        got.starts_with("1000 1000 1000 1000 1000 1000 "),
        "setgid without group-execute changes nothing: got [{got}], wanted [1000 1000 1000 1000 1000 1000 ...]"
    );

    // The three attributes, read out of the same reports. The last three
    // numbers each line prints are the parent-death signal, keepcaps and
    // dumpable, all three of which the child set before exec'ing.
    h.group("what-an-exec-resets");
    let tail = |line: &str| -> String {
        line.split_whitespace().skip(6).collect::<Vec<_>>().join(" ")
    };

    // An ordinary exec: keepcaps goes, the parent-death signal stays, and
    // dumpable comes back to SUID_DUMP_USER.
    let plain = tail(&run_as_1000(&setgid_noxgrp));
    check!(h, plain == "10 0 1",
        "an ordinary exec keeps the parent-death signal and drops keepcaps: got [{plain}], wanted [10 0 1]");

    // A privileged one: the parent-death signal goes too, and dumpable is
    // lowered. Otherwise an unprivileged parent arranges a signal for a
    // program that has just gained privilege, and can read its memory.
    let suid = tail(&run_as_1000(&setuid_bin));
    check!(h, suid == "0 0 0",
        "a setuid exec drops the parent-death signal and lowers dumpable: got [{suid}], wanted [0 0 0]");
    let sgid = tail(&run_as_1000(&setgid_bin));
    check!(h, sgid == "0 0 0",
        "and so does a setgid one: got [{sgid}], wanted [0 0 0]");

    std::process::exit(h.finish());
}
