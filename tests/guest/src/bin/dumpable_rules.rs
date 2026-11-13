//! What a credential change does to `dumpable`, and what `dumpable` does to
//! `/proc/<pid>`. The expected values are a real arm64 kernel's
//! (`dumpable_probe`, and this file under `differential.sh`).
//!
//! No credential change touched the flag here until 2026-11-12: a root
//! process that called `setuid(65534)` stayed readable by every other
//! uid-65534 process, and its `/proc/<pid>` entries stayed owned by its real
//! uid rather than becoming root's.
//!
//! Run as root; every case forks, since a dropped identity cannot be undone.

use guest_tests::{Harness, check, cpath};

fn dumpable() -> i32 {
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }
}

const KEEP: u32 = u32::MAX;

fn setresuid(r: u32, e: u32, s: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_setresuid, r, e, s) }
}

fn setresgid(r: u32, e: u32, s: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_setresgid, r, e, s) }
}

/// Runs `f` in a child and answers the one line it wrote to the pipe.
fn in_child(f: impl FnOnce() -> String) -> String {
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(fds[0]) };
        let s = f();
        unsafe {
            libc::write(fds[1], s.as_ptr().cast(), s.len());
            libc::_exit(0);
        }
    }
    unsafe { libc::close(fds[1]) };
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
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
    String::from_utf8_lossy(&out).into_owned()
}

/// The flag after `f`, run in a fresh child of this root process.
fn after(f: impl FnOnce()) -> i32 {
    in_child(|| {
        f();
        dumpable().to_string()
    })
    .parse()
    .unwrap_or(-1)
}

fn owner(path: &str) -> (u32, u32) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(cpath(path).as_ptr(), &mut st) } != 0 {
        return (u32::MAX, u32::MAX);
    }
    (st.st_uid, st.st_gid)
}

fn errno_of<T>(r: std::io::Result<T>) -> i32 {
    match r {
        Ok(_) => 0,
        Err(e) => e.raw_os_error().unwrap_or(-1),
    }
}

/// Execs this program as `report` after `setup` and answers the flag the new
/// image starts with.
fn after_exec(me: &str, setup: impl FnOnce()) -> i32 {
    in_child(|| {
        setup();
        let p = cpath(me);
        let a = cpath("report");
        let argv = [p.as_ptr(), a.as_ptr(), std::ptr::null()];
        let mut fds = [0i32; 2];
        unsafe {
            libc::pipe(fds.as_mut_ptr());
            if libc::fork() == 0 {
                libc::close(fds[0]);
                libc::dup2(fds[1], 1);
                libc::execv(p.as_ptr(), argv.as_ptr());
                libc::_exit(127);
            }
            libc::close(fds[1]);
            let mut buf = [0u8; 16];
            let n = libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len());
            let mut st = 0;
            libc::wait(&mut st);
            String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned()
        }
    })
    .trim()
    .parse()
    .unwrap_or(-1)
}

/// Busybox, its `PT_INTERP` rewritten to name a private copy of musl's loader
/// of `mode`, run as uid 65534; answers the owner of its `/proc/self/status`.
fn owner_after_dynamic_exec(mode: u32) -> String {
    const LOADER: &str = "/lib/ld-musl-aarch64.so.1";
    // The same length as LOADER, so the name is rewritten in place.
    const PRIVATE: &str = "/tmp/ldrules-aarch64.so.1";
    const PROGRAM: &str = "/tmp/dumpable_rules.dyn";
    const _: () = assert!(PRIVATE.len() == LOADER.len());
    let private = PRIVATE;
    let Ok(mut elf) = std::fs::read("/bin/busybox") else {
        return "no /bin/busybox".into();
    };
    let Some(at) = elf
        .windows(LOADER.len() + 1)
        .position(|w| w[..LOADER.len()] == *LOADER.as_bytes() && w[LOADER.len()] == 0)
    else {
        return "no PT_INTERP naming the loader".into();
    };
    elf[at..at + LOADER.len()].copy_from_slice(private.as_bytes());
    let _ = std::fs::remove_file(private);
    let _ = std::fs::remove_file(PROGRAM);
    if std::fs::copy(LOADER, private).is_err() || std::fs::write(PROGRAM, elf).is_err() {
        return "copies".into();
    }
    unsafe {
        libc::chown(cpath(private).as_ptr(), 0, 0);
        libc::chmod(cpath(private).as_ptr(), mode);
        libc::chmod(cpath(PROGRAM).as_ptr(), 0o755);
    }
    let got = in_child(|| {
        setresgid(65534, 65534, 65534);
        setresuid(65534, 65534, 65534);
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
        let args = ["stat", "-c", "%u", "/proc/self/status"].map(cpath);
        let argv = [args[0].as_ptr(), args[1].as_ptr(), args[2].as_ptr(), args[3].as_ptr(), std::ptr::null()];
        let mut fds = [0i32; 2];
        unsafe {
            libc::pipe(fds.as_mut_ptr());
            if libc::fork() == 0 {
                libc::close(fds[0]);
                libc::dup2(fds[1], 1);
                libc::execv(cpath(PROGRAM).as_ptr(), argv.as_ptr());
                libc::_exit(127);
            }
            libc::close(fds[1]);
            let mut buf = [0u8; 16];
            let n = libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len());
            libc::wait(std::ptr::null_mut());
            String::from_utf8_lossy(&buf[..n.max(0) as usize]).trim().to_string()
        }
    });
    let _ = std::fs::remove_file(PROGRAM);
    let _ = std::fs::remove_file(private);
    got
}

fn main() {
    let me = std::env::args().next().unwrap_or_default();
    if std::env::args().nth(1).as_deref() == Some("report") {
        print!("{}", dumpable());
        return;
    }
    let mut h = Harness::new();

    h.group("credential-changes");
    let cases: [(&str, fn(), i32); 14] = [
        ("setuid(65534)", || { let _ = unsafe { libc::setuid(65534) }; }, 0),
        ("setuid(0), no change", || { let _ = unsafe { libc::setuid(0) }; }, 1),
        ("setresuid(-1, 65534, -1)", || { let _ = setresuid(KEEP, 65534, KEEP); }, 0),
        ("setresuid(65534, -1, -1), the real uid only", || { let _ = setresuid(65534, KEEP, KEEP); }, 1),
        ("setresuid(-1, -1, 65534), the saved uid only", || { let _ = setresuid(KEEP, KEEP, 65534); }, 1),
        ("setreuid(-1, 65534)", || { let _ = unsafe { libc::setreuid(KEEP, 65534) }; }, 0),
        ("setgid(65534)", || { let _ = unsafe { libc::setgid(65534) }; }, 0),
        ("setresgid(65534, -1, -1), the real gid only", || { let _ = setresgid(65534, KEEP, KEEP); }, 1),
        ("setregid(-1, 65534)", || { let _ = unsafe { libc::setregid(KEEP, 65534) }; }, 0),
        ("setfsuid(65534)", || { let _ = unsafe { libc::setfsuid(65534) }; }, 0),
        ("setfsuid(0), no change", || { let _ = unsafe { libc::setfsuid(0) }; }, 1),
        ("setfsgid(65534)", || { let _ = unsafe { libc::setfsgid(65534) }; }, 0),
        ("setgroups([1, 2])", || { let _ = unsafe { libc::setgroups(2, [1, 2].as_ptr()) }; }, 1),
        (
            "euid 65534, flag set back to 1, then euid 0 again",
            || {
                setresuid(KEEP, 65534, KEEP);
                unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
                setresuid(KEEP, 0, KEEP);
            },
            0,
        ),
    ];
    for (what, f, want) in cases {
        let got = after(f);
        check!(h, got == want, "{what}: dumpable {got}, wanted {want}");
    }
    let got = after(|| {
        setresgid(1000, 1000, 1000);
        setresuid(1000, 1000, 2000);
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
        unsafe { libc::setuid(0) };
    });
    check!(h, got == 1, "a refused setuid(0) changes nothing: dumpable {got}");
    let got = after(|| {
        unsafe { libc::setuid(65534) };
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
    });
    check!(h, got == 1, "PR_SET_DUMPABLE(1) gives it back: dumpable {got}");

    h.group("execve");
    let got = after_exec(&me, || { let _ = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) }; });
    check!(h, got == 1, "an ordinary exec makes it dumpable: {got}");
    let got = after_exec(&me, || { let _ = setresuid(65534, 0, 0); });
    check!(h, got == 0, "an exec with the euid not the real uid does not: {got}");
    let got = after_exec(&me, || { let _ = setresgid(65534, 0, 0); });
    check!(h, got == 0, "nor with the egid not the real gid: {got}");
    let got = after_exec(&me, || {
        unsafe { libc::setfsuid(65534) };
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
    });
    check!(h, got == 0, "an exec that resets a setfsuid commits a change of fsuid: {got}");
    let noread = "/tmp/dumpable_rules.noread";
    let _ = std::fs::remove_file(noread);
    let copied = std::fs::copy(&me, noread).is_ok()
        && unsafe { libc::chmod(cpath(noread).as_ptr(), 0o711) } == 0;
    check!(h, copied, "a copy of this program, mode 0711");
    let got = after_exec(noread, || {
        setresgid(65534, 65534, 65534);
        setresuid(65534, 65534, 65534);
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
    });
    check!(h, got == 0, "uid 65534 may run a 0711 file it cannot read, undumpable: {got}");

    // The interpreters are asked too (`would_dump`), and this kernel asked only
    // the program until 2026-11-12. A `#!` one: a readable script naming this
    // program as its interpreter, in a copy it can read and one it cannot.
    let script = "/tmp/dumpable_rules.sh";
    for (mode, want) in [(0o755, 1), (0o711, 0)] {
        let interp = "/tmp/dumpable_rules.interp";
        let _ = std::fs::remove_file(interp);
        let ready = std::fs::copy(&me, interp).is_ok()
            && unsafe { libc::chmod(cpath(interp).as_ptr(), mode) } == 0
            && std::fs::write(script, format!("#!{interp} report\n")).is_ok()
            && unsafe { libc::chmod(cpath(script).as_ptr(), 0o755) } == 0;
        check!(h, ready, "a script and an interpreter of mode {mode:o}");
        let got = after_exec(script, || {
            setresgid(65534, 65534, 65534);
            setresuid(65534, 65534, 65534);
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
        });
        check!(h, got == want, "a #! interpreter of mode {mode:o}: dumpable {got}, wanted {want}");
        let _ = std::fs::remove_file(interp);
    }
    let _ = std::fs::remove_file(script);
    // An ELF one: busybox with its PT_INTERP pointed at a private copy of the
    // loader. Its `stat` of `/proc/self/status` is the new image saying who
    // owns its entries, which is root exactly when it is not dumpable.
    for (mode, want) in [(0o755, "65534"), (0o711, "0")] {
        let got = owner_after_dynamic_exec(mode);
        check!(h, got == want, "an ELF interpreter of mode {mode:o}: status owned by {got}, wanted {want}");
    }
    let _ = std::fs::remove_file(noread);

    h.group("proc-owner");
    let got = in_child(|| {
        setresgid(1001, 2001, 1001);
        setresuid(1000, 2000, 1000);
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
        let a = (owner("/proc/self"), owner("/proc/self/status"));
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        let b = (owner("/proc/self"), owner("/proc/self/status"), owner("/proc/self/fd"));
        let c = (owner("/proc/self/fdinfo"), owner("/proc/self/task"), owner("/proc/self/maps"));
        format!("{a:?} {b:?} {c:?}")
    });
    let want = "((2000, 2001), (2000, 2001)) ((2000, 2001), (0, 0), (0, 0)) ((2000, 2001), (2000, 2001), (0, 0))";
    check!(h, got == want, "owned by the effective ids, and by root when not dumpable:\n    got  {got}\n    want {want}");
    let got = in_child(|| {
        unsafe { libc::setfsuid(65534) };
        let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        s.lines().find(|l| l.starts_with("Uid:")).unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ")
    });
    check!(h, got == "Uid: 0 0 0 65534", "status reports the fsuid: [{got}]");

    h.group("access");
    let got = in_child(|| {
        unsafe {
            libc::setgid(65534);
            libc::setuid(65534);
        }
        let own = (
            errno_of(std::fs::read("/proc/self/environ")),
            errno_of(std::fs::read_dir("/proc/self/fd")),
            errno_of(std::fs::read("/proc/self/fdinfo/0")),
        );
        let me = unsafe { libc::getpid() };
        let peer = in_child(|| {
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
            let p = format!("/proc/{me}");
            format!(
                "{:?}",
                (
                    errno_of(std::fs::read_dir(format!("{p}/fdinfo"))),
                    errno_of(std::fs::read_dir(format!("{p}/fd"))),
                    errno_of(std::fs::read(format!("{p}/environ"))),
                    errno_of(std::fs::read(format!("{p}/status"))),
                )
            )
        });
        format!("{own:?} {peer}")
    });
    let want = format!("({e}, 0, 0) ({e}, {e}, {e}, 0)", e = libc::EACCES);
    check!(
        h,
        got == want,
        "after setuid: its own environ is root's but its fd and fdinfo are its own; a peer is kept out:\n    got  {got}\n    want {want}"
    );

    std::process::exit(h.finish());
}
