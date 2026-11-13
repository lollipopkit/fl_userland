//! Which `/proc/<pid>` entries another process may open, read, follow or
//! list, and what `stat` leaves out for a reader without ptrace access.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container (`--privileged`, so the container's root has every capability
//! the guest's root has) and diffed by `tests/integration/probe_diff.sh`.
//!
//! Linux gates most of the directory on `ptrace_may_access` with the
//! caller's fs ids: same uid and gid in all three slots and a dumpable
//! target, or `CAP_SYS_PTRACE`, or the same thread group. Some entries ask at
//! `open`, some at `read`, the links at `readlink`; this records which.
//! The two entries this kernel does not have, `stack` and `pagemap`, are
//! listed so the comparison says so.

use std::ffi::CString;
use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
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
        libc::EIO => "EIO",
        libc::ESRCH => "ESRCH",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

const FILES: &[&str] = &[
    "auxv", "cmdline", "comm", "environ", "limits", "maps", "mem", "mountinfo", "mounts", "oom_adj",
    "oom_score_adj", "smaps", "smaps_rollup", "stat", "statm", "status",
    // `stack` and `pagemap` are not here, and listed so that the comparison
    // says so.
    "io", "numa_maps", "pagemap", "personality", "stack", "syscall", "timerslack_ns",
];
const LINKS: &[&str] = &["cwd", "exe", "root", "fd/0", "ns/uts"];
const DIRS: &[&str] = &["fd", "fdinfo", "task", "map_files", "ns"];

fn open_read(path: &str) -> String {
    let c = CString::new(path).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return format!("open {}", named(errno()));
    }
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    let r = if n < 0 { format!("open ok, read {}", named(errno())) } else { "open ok, read ok".into() };
    unsafe { libc::close(fd) };
    r
}

fn readlink(path: &str) -> String {
    let c = CString::new(path).unwrap();
    let mut buf = [0u8; 256];
    let n = unsafe { libc::readlink(c.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    let rl = if n < 0 { named(errno()) } else { "ok".into() };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let s = if unsafe { libc::stat(c.as_ptr(), &mut st) } != 0 { named(errno()) } else { "ok".into() };
    format!("readlink {rl}, stat {s}")
}

fn list(path: &str) -> String {
    match std::fs::read_dir(path) {
        Ok(d) => format!("lists {}", if d.count() > 0 { "entries" } else { "nothing" }),
        Err(e) => named(e.raw_os_error().unwrap_or(0)),
    }
}

/// Fields 26..=52 of `stat`, each as 0, 1 or N (anything larger): which
/// ones are blanked for a reader without access, without the values.
fn stat_fields(pid: i32) -> String {
    let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return named(errno());
    };
    let rest = s.rsplit_once(") ").map_or("", |(_, r)| r);
    // `rest` starts at field 3.
    let f: Vec<&str> = rest.split_whitespace().collect();
    // 39 is the processor it last ran on, which is the scheduler's.
    (26..=52)
        .map(|n| match f.get(n - 3).copied() {
            _ if n == 39 => "x",
            Some("0") => "0",
            Some("1") => "1",
            Some(_) => "N",
            None => "-",
        })
        .collect::<Vec<_>>()
        .join("")
}

fn report(who: &str, pid: i32, with_stat: bool) {
    for f in FILES {
        line(&format!("{who}: {f}"), open_read(&format!("/proc/{pid}/{f}")));
    }
    for l in LINKS {
        line(&format!("{who}: {l}"), readlink(&format!("/proc/{pid}/{l}")));
    }
    for d in DIRS {
        line(&format!("{who}: {d}/"), list(&format!("/proc/{pid}/{d}")));
    }
    // The thread's directory asks the same question.
    line(&format!("{who}: task/<tid>/maps"), open_read(&format!("/proc/{pid}/task/{pid}/maps")));
    line(&format!("{who}: task/<tid>/environ"), open_read(&format!("/proc/{pid}/task/{pid}/environ")));
    if with_stat {
        line(&format!("{who}: stat fields 26..52"), stat_fields(pid));
    }
}

fn setresuid(r: u32, e: u32, s: u32) {
    unsafe { libc::syscall(libc::SYS_setresuid, r, e, s) };
}

fn setresgid(r: u32, e: u32, s: u32) {
    unsafe { libc::syscall(libc::SYS_setresgid, r, e, s) };
}

fn become_user(uid: u32) {
    setresgid(uid, uid, uid);
    setresuid(uid, uid, uid);
}

/// A process that sets itself up and waits to be looked at.
fn target(setup: fn()) -> i32 {
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        setup();
        unsafe {
            libc::write(p[1], b"x".as_ptr().cast(), 1);
            loop {
                libc::pause();
            }
        }
    }
    let mut b = [0u8; 1];
    unsafe {
        libc::close(p[1]);
        libc::read(p[0], b.as_mut_ptr().cast(), 1);
        libc::close(p[0]);
    }
    pid
}

fn as_child(f: impl FnOnce()) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

fn modes() {
    println!("########## the modes, of a process's own directory ##########");
    let mut names: Vec<&str> = FILES.to_vec();
    names.extend(LINKS.iter().filter(|l| !l.contains('/')));
    names.extend(DIRS);
    for n in names {
        let c = CString::new(format!("/proc/self/{n}")).unwrap();
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let v = if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
            named(errno())
        } else {
            format!("{:o}", st.st_mode & 0o7777)
        };
        line(&format!("mode of {n}"), v);
    }
}

fn write_file(path: &str, bytes: &[u8]) -> String {
    let c = CString::new(path).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY) };
    if fd < 0 {
        return format!("open {}", named(errno()));
    }
    let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    let r = if n < 0 { format!("write {}", named(errno())) } else { format!("wrote {n}") };
    unsafe { libc::close(fd) };
    r
}

fn comm_of(path: &str) -> String {
    std::fs::read(path).map_or_else(|e| named(e.raw_os_error().unwrap_or(0)), |b| format!("{:?}", String::from_utf8_lossy(&b)))
}

/// `comm` is the one entry here a process may write, and only its own
/// thread group's.
fn comm(other: i32) {
    println!("########## writing comm ##########");
    let me = unsafe { libc::getpid() };
    for text in [&b"probe-name\n"[..], b"twenty-characters-ok", b"", b"a\0b"] {
        let w = write_file(&format!("/proc/{me}/comm"), text);
        line(&format!("write {:?} to its own", String::from_utf8_lossy(text)), format!("{w}, reads {}", comm_of(&format!("/proc/{me}/comm"))));
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let t = std::thread::spawn(move || {
        tx.send(unsafe { libc::syscall(libc::SYS_gettid) } as i32).unwrap();
        let _ = done_rx.recv();
    });
    let tid = rx.recv().unwrap();
    let w = write_file(&format!("/proc/{me}/task/{tid}/comm"), b"worker");
    line("write another thread's", format!("{w}, reads {}", comm_of(&format!("/proc/{me}/task/{tid}/comm"))));
    line("  and the process's is still", comm_of(&format!("/proc/{me}/comm")));
    let _ = done_tx.send(());
    let _ = t.join();
    line("write another process's, as root", write_file(&format!("/proc/{other}/comm"), b"x"));
}

fn main() {
    modes();
    let root = target(|| unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 1);
    });
    let user = target(|| {
        become_user(1000);
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
    });
    let undumpable = target(|| become_user(1000));

    println!("########## uid 1000, a root process ##########");
    as_child(|| {
        become_user(1000);
        report("1000 -> root", root, true);
    });
    println!("########## uid 1000, a uid 1000 process ##########");
    as_child(|| {
        become_user(1000);
        report("1000 -> 1000", user, true);
    });
    println!("########## uid 1000, a uid 1000 process that is not dumpable ##########");
    as_child(|| {
        become_user(1000);
        report("1000 -> 1000 undumpable", undumpable, false);
    });
    println!("########## fs ids 1000, real and saved 2000, a uid 1000 process ##########");
    as_child(|| {
        setresgid(2000, 1000, 2000);
        setresuid(2000, 1000, 2000);
        report("fs 1000 -> 1000", user, false);
    });
    println!("########## root, a uid 1000 process that is not dumpable ##########");
    as_child(|| report("root -> 1000 undumpable", undumpable, false));
    println!("########## uid 1000 and not dumpable, its own directory ##########");
    as_child(|| {
        become_user(1000);
        report("own, undumpable", unsafe { libc::getpid() }, false);
    });

    as_child(|| comm(root));

    for pid in [root, user, undumpable] {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
    }
}
