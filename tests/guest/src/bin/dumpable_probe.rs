//! Which credential changes take a process's dumpable flag away, and what
//! that does to its `/proc/<pid>` directory.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container as root and diffed by `tests/integration/probe_diff.sh`.
//!
//! Linux's `commit_creds` sets the flag to `suid_dumpable` (0) whenever the
//! effective or fs user or group id changes, or the permitted capabilities
//! grow; `begin_new_exec` sets it to 1, or to `suid_dumpable` when the new
//! image is set-id or unreadable or the effective ids differ from the real
//! ones. Every case runs in a fresh child of a root process whose flag is 1.
//!
//! The set-id exec cases are `setid_exec`'s, on fakefs: probes run on a
//! passthrough mount, where the host owns the file and its setuid bit.

use std::ffi::CString;
use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<56} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::ENOENT => "ENOENT",
        libc::EINVAL => "EINVAL",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn ok(v: i64) -> String {
    if v < 0 { named(errno()) } else { "ok".into() }
}

fn dumpable() -> i32 {
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }
}

fn set_dumpable(v: u64) {
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, v) };
}

const KEEP: u32 = u32::MAX;

fn setresuid(r: u32, e: u32, s: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_setresuid, r, e, s) }
}

fn setresgid(r: u32, e: u32, s: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_setresgid, r, e, s) }
}

/// `capget` of the caller, then `capset` of `f` applied to it.
fn capset(f: impl FnOnce(&mut [u32; 6])) -> i64 {
    let mut hdr = [0x2008_0522u32, 0];
    let mut data = [0u32; 6];
    unsafe { libc::syscall(libc::SYS_capget, hdr.as_mut_ptr(), data.as_mut_ptr()) };
    f(&mut data);
    unsafe { libc::syscall(libc::SYS_capset, hdr.as_mut_ptr(), data.as_ptr()) }
}

/// Runs `f` in a forked child and waits for it.
fn child(f: impl FnOnce()) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

/// One credential change, and the flag after it.
fn case(what: &str, f: impl FnOnce() -> i64) {
    child(|| {
        let r = f();
        line(what, format!("{}, dumpable {}", ok(r), dumpable()));
    });
}

fn owner(path: &str) -> String {
    let c = CString::new(path).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c.as_ptr(), &mut st) } != 0 {
        return named(errno());
    }
    format!("{}:{}", st.st_uid, st.st_gid)
}

fn read(path: &str) -> String {
    match std::fs::read(path) {
        Ok(_) => "ok".into(),
        Err(e) => named(e.raw_os_error().unwrap_or(0)),
    }
}

fn list(path: &str) -> String {
    match std::fs::read_dir(path) {
        Ok(_) => "a listing".into(),
        Err(e) => named(e.raw_os_error().unwrap_or(0)),
    }
}

fn owners(prefix: &str) {
    for p in ["", "/status", "/environ", "/fd", "/fdinfo", "/task", "/maps"] {
        line(&format!("{prefix} /proc/self{p}"), owner(&format!("/proc/self{p}")));
    }
}

fn status_ids() -> String {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .filter(|l| l.starts_with("Uid:") || l.starts_with("Gid:"))
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join(" / ")
}

fn changes() {
    println!("########## a credential change, as root ##########");
    line("at start", format!("dumpable {}", dumpable()));
    case("setuid(0)", || unsafe { libc::setuid(0) } as i64);
    case("setuid(65534)", || unsafe { libc::setuid(65534) } as i64);
    case("setresuid(-1, 65534, -1)", || setresuid(KEEP, 65534, KEEP));
    case("setresuid(65534, -1, -1)", || setresuid(65534, KEEP, KEEP));
    case("setresuid(-1, -1, 65534)", || setresuid(KEEP, KEEP, 65534));
    case("setresuid(65534, 0, 0): real only, still root", || setresuid(65534, 0, 0));
    case("setreuid(65534, -1)", || unsafe { libc::setreuid(65534, KEEP) } as i64);
    case("setreuid(-1, 65534)", || unsafe { libc::setreuid(KEEP, 65534) } as i64);
    case("setgid(0)", || unsafe { libc::setgid(0) } as i64);
    case("setgid(65534)", || unsafe { libc::setgid(65534) } as i64);
    case("setresgid(65534, -1, -1)", || setresgid(65534, KEEP, KEEP));
    case("setresgid(-1, 65534, -1)", || setresgid(KEEP, 65534, KEEP));
    case("setresgid(-1, -1, 65534)", || setresgid(KEEP, KEEP, 65534));
    case("setregid(-1, 65534)", || unsafe { libc::setregid(KEEP, 65534) } as i64);
    case("setfsuid(0)", || unsafe { libc::setfsuid(0) }.min(0) as i64);
    case("setfsuid(65534)", || unsafe { libc::setfsuid(65534) }.min(0) as i64);
    case("setfsgid(0)", || unsafe { libc::setfsgid(0) }.min(0) as i64);
    case("setfsgid(65534)", || unsafe { libc::setfsgid(65534) }.min(0) as i64);
    case("setgroups([1, 2])", || unsafe { libc::setgroups(2, [1, 2].as_ptr()) } as i64);
    case("capset(the sets it has)", || capset(|_| {}));
    case("capset(no effective, no inheritable)", || {
        capset(|d| {
            d[0] = 0;
            d[3] = 0;
            d[2] = 0;
            d[5] = 0;
        })
    });
    case("PR_SET_DUMPABLE(1) after setuid(65534)", || {
        unsafe { libc::setuid(65534) };
        set_dumpable(1);
        0
    });
    case("euid 65534, flag set back to 1, then euid 0", || {
        setresuid(KEEP, 65534, KEEP);
        set_dumpable(1);
        setresuid(KEEP, 0, KEEP)
    });

    println!("########## a credential change, unprivileged ##########");
    let drop = || {
        setresgid(1000, 1000, 1000);
        setresuid(1000, 1000, 2000);
        set_dumpable(1);
    };
    case("setuid(0), refused", || {
        drop();
        (unsafe { libc::setuid(0) }) as i64
    });
    case("setresuid(-1, -1, -1)", || {
        drop();
        setresuid(KEEP, KEEP, KEEP)
    });
    case("setresuid(-1, 1000, -1): its own euid", || {
        drop();
        setresuid(KEEP, 1000, KEEP)
    });
    case("setresuid(-1, 2000, -1): its saved uid", || {
        drop();
        setresuid(KEEP, 2000, KEEP)
    });
    case("setresuid(2000, -1, -1): real only", || {
        drop();
        setresuid(2000, KEEP, KEEP)
    });
    case("setfsuid(1000): its own fsuid", || {
        drop();
        (unsafe { libc::setfsuid(1000) }).min(0) as i64
    });
    case("setfsuid(2000)", || {
        drop();
        (unsafe { libc::setfsuid(2000) }).min(0) as i64
    });
    case("setfsuid(3000), refused", || {
        drop();
        (unsafe { libc::setfsuid(3000) }).min(0) as i64
    });
}

fn proc_owner() {
    println!("########## who owns /proc/self ##########");
    child(|| {
        setresgid(1001, 2001, 1001);
        setresuid(1000, 2000, 1000);
        set_dumpable(1);
        owners("ids 1000/2000/1000, dumpable:");
        line("  status", status_ids());
        set_dumpable(0);
        owners("ids 1000/2000/1000, not dumpable:");
    });
    child(|| {
        unsafe { libc::setfsuid(65534) };
        line("setfsuid(65534): status", status_ids());
    });
    child(|| {
        unsafe { libc::setfsgid(65534) };
        line("setfsgid(65534): status", status_ids());
    });
}

/// A process of the same user looking at one whose flag was taken away by
/// `setuid` and never given back.
fn peer_access() {
    println!("########## another process of the same user ##########");
    for give_back in [false, true] {
        child(|| {
            unsafe {
                libc::setgid(65534);
                libc::setuid(65534);
            }
            if give_back {
                set_dumpable(1);
            }
            let state = if give_back { "dumpable again" } else { "after setuid" };
            line(&format!("{state}: its own environ"), read("/proc/self/environ"));
            line(&format!("{state}: its own fd"), list("/proc/self/fd"));
            line(&format!("{state}: its own fdinfo/0"), read("/proc/self/fdinfo/0"));
            let me = unsafe { libc::getpid() };
            child(|| {
                // Fork copies the flag; what matters is the target's.
                set_dumpable(1);
                let p = format!("/proc/{me}");
                line(&format!("{state}: a peer lists its fdinfo"), list(&format!("{p}/fdinfo")));
                line(&format!("{state}: a peer reads its fdinfo/0"), read(&format!("{p}/fdinfo/0")));
                line(&format!("{state}: a peer reads its status"), read(&format!("{p}/status")));
                line(&format!("{state}: a peer reads its environ"), read(&format!("{p}/environ")));
                line(&format!("{state}: a peer lists its fd"), list(&format!("{p}/fd")));
            });
        });
    }
}

/// Execs this program with `report <label>` after `setup`.
fn exec_case(label: &str, prog: &str, setup: impl FnOnce() -> Result<(), String>) {
    child(|| {
        if let Err(e) = setup() {
            line(label, format!("setup: {e}"));
            return;
        }
        let p = CString::new(prog).unwrap();
        let a1 = CString::new("report").unwrap();
        let a2 = CString::new(label).unwrap();
        let argv = [p.as_ptr(), a1.as_ptr(), a2.as_ptr(), std::ptr::null()];
        unsafe { libc::execv(p.as_ptr(), argv.as_ptr()) };
        line(label, format!("execv: {}", named(errno())));
    });
}

fn copy_to(dst: &str, uid: u32, mode: u32) -> Result<(), String> {
    let me = std::fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(dst);
    std::fs::copy(&me, dst).map_err(|e| e.to_string())?;
    let c = CString::new(dst).unwrap();
    if unsafe { libc::chown(c.as_ptr(), uid, uid) } != 0 {
        return Err(format!("chown {}", named(errno())));
    }
    if unsafe { libc::chmod(c.as_ptr(), mode) } != 0 {
        return Err(format!("chmod {}", named(errno())));
    }
    Ok(())
}

fn execs(me: &str) {
    println!("########## execve ##########");
    exec_case("not dumpable, then exec", me, || {
        set_dumpable(0);
        Ok(())
    });
    exec_case("setuid(65534), then exec", me, || {
        unsafe { libc::setuid(65534) };
        Ok(())
    });
    exec_case("real uid 65534, euid 0, then exec", me, || {
        setresuid(65534, 0, 0);
        Ok(())
    });
    exec_case("real gid 65534, egid 0, then exec", me, || {
        setresgid(65534, 0, 0);
        Ok(())
    });
    exec_case("setfsuid(65534), then exec", me, || {
        unsafe { libc::setfsuid(65534) };
        set_dumpable(1);
        Ok(())
    });
    exec_case("saved uid 65534 only, then exec", me, || {
        setresuid(0, 0, 65534);
        Ok(())
    });
    let unreadable = "/tmp/dumpable_probe.noread";
    exec_case("uid 65534 execs a binary it cannot read", unreadable, || {
        copy_to(unreadable, 0, 0o711)?;
        setresgid(65534, 65534, 65534);
        setresuid(65534, 65534, 65534);
        set_dumpable(1);
        Ok(())
    });
    let _ = std::fs::remove_file(unreadable);

    // A program it can read, run by an interpreter it cannot: `would_dump` is
    // asked of the ELF interpreter and of a `#!` one too.
    let interp = "/tmp/dumpable_probe.interp";
    let script = "/tmp/dumpable_probe.sh";
    for (label, mode) in [
        ("uid 65534 runs a script whose #! interpreter it can read", 0o755),
        ("uid 65534 runs a script whose #! interpreter it cannot read", 0o711),
    ] {
        exec_case(label, script, || {
            copy_to(interp, 0, mode)?;
            std::fs::write(script, format!("#!{interp} report\n")).map_err(|e| e.to_string())?;
            let c = CString::new(script).unwrap();
            unsafe { libc::chmod(c.as_ptr(), 0o755) };
            setresgid(65534, 65534, 65534);
            setresuid(65534, 65534, 65534);
            Ok(())
        });
    }
    let _ = std::fs::remove_file(interp);
    let _ = std::fs::remove_file(script);
    for (label, mode) in [
        ("uid 65534 execs a program whose ELF interpreter it can read", 0o755),
        ("uid 65534 execs a program whose ELF interpreter it cannot read", 0o711),
    ] {
        line(label, dynamic_case(mode));
    }
}

/// A private copy of musl's loader, `mode` and root's, and a copy of busybox
/// whose `PT_INTERP` names it. Busybox's `stat` of `/proc/self/status` is
/// the exec'd process reporting its own owner: 0 for one that is not
/// dumpable.
fn dynamic_case(mode: u32) -> String {
    const LOADER: &str = "/lib/ld-musl-aarch64.so.1";
    // The same length as LOADER, so the name can be rewritten in place.
    const PRIVATE: &str = "/tmp/ldprobe-aarch64.so.1";
    const PROGRAM: &str = "/tmp/dumpable_probe.dyn";
    let setup = || -> Result<(), String> {
        let _ = std::fs::remove_file(PRIVATE);
        std::fs::copy(LOADER, PRIVATE).map_err(|e| e.to_string())?;
        let c = CString::new(PRIVATE).unwrap();
        unsafe {
            libc::chown(c.as_ptr(), 0, 0);
            libc::chmod(c.as_ptr(), mode);
        }
        let mut elf = std::fs::read("/bin/busybox").map_err(|e| e.to_string())?;
        let at = elf
            .windows(LOADER.len() + 1)
            .position(|w| w[..LOADER.len()] == *LOADER.as_bytes() && w[LOADER.len()] == 0)
            .ok_or("no PT_INTERP naming the loader")?;
        elf[at..at + PRIVATE.len()].copy_from_slice(PRIVATE.as_bytes());
        let _ = std::fs::remove_file(PROGRAM);
        std::fs::write(PROGRAM, elf).map_err(|e| e.to_string())?;
        let c = CString::new(PROGRAM).unwrap();
        unsafe { libc::chmod(c.as_ptr(), 0o755) };
        Ok(())
    };
    if let Err(e) = setup() {
        return format!("setup: {e}");
    }
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::dup2(p[1], 1);
            libc::close(p[0]);
            setresgid(65534, 65534, 65534);
            setresuid(65534, 65534, 65534);
            set_dumpable(1);
            let prog = CString::new(PROGRAM).unwrap();
            let args = ["stat", "-c", "%u", "/proc/self/status"].map(|a| CString::new(a).unwrap());
            let argv = [args[0].as_ptr(), args[1].as_ptr(), args[2].as_ptr(), args[3].as_ptr(), std::ptr::null()];
            libc::execv(prog.as_ptr(), argv.as_ptr());
            let msg = format!("execv: {}", named(errno()));
            libc::write(1, msg.as_ptr().cast(), msg.len());
            libc::_exit(0);
        }
    }
    unsafe { libc::close(p[1]) };
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = unsafe { libc::read(p[0], buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    unsafe {
        libc::close(p[0]);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    let _ = std::fs::remove_file(PROGRAM);
    let _ = std::fs::remove_file(PRIVATE);
    format!("status owned by {}", String::from_utf8_lossy(&out).trim())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("report") {
        let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
        unsafe { libc::syscall(libc::SYS_getresuid, &mut r, &mut e, &mut s) };
        line(
            args.get(2).map_or("?", String::as_str),
            format!("dumpable {}, uids {r}/{e}/{s}, status owned by {}", dumpable(), owner("/proc/self/status")),
        );
        return;
    }
    let me = std::fs::read_link("/proc/self/exe").map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    changes();
    proc_owner();
    peer_access();
    execs(&me);
}
