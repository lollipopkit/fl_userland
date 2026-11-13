//! Who may do what to another process, and what the `/proc/<pid>` entries
//! added on 2026-11-13 report. The expected values are a real arm64 kernel's
//! (`crossperm_probe`, `procstate_probe`, and this file under
//! `differential.sh`).
//!
//! Until 2026-11-13 `process_vm_readv`, `kcmp`, `pidfd_getfd` and `prlimit64`
//! each compared uids their own way and asked neither the gids nor the
//! target's dumpable flag, `sched_setaffinity`, `sched_setscheduler` and
//! `ioprio_set` asked nothing, and `get_robust_list` refused every other task.
//!
//! Run as root; every caller is a forked child that drops its ids.

use guest_tests::{Harness, check, cpath};

static mut SCRATCH: u64 = 0x5a5a;
static mut PAGE: u64 = 0;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> &'static str {
    match e {
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::EIO => "EIO",
        _ => "other",
    }
}

fn ok(v: i64) -> &'static str {
    if v < 0 { named(errno()) } else { "ok" }
}

fn ids(r: u32, e: u32, s: u32) {
    unsafe {
        libc::syscall(libc::SYS_setresgid, r, e, s);
        libc::syscall(libc::SYS_setresuid, r, e, s);
    }
}

fn set_dumpable(v: u64) {
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, v) };
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

/// Runs `f` in a child and answers what it wrote to the pipe.
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
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn proc_read(pid: i32, name: &str) -> String {
    let c = cpath(&format!("/proc/{pid}/{name}"));
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return format!("open:{}", named(errno()));
    }
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    let r = if n < 0 { format!("read:{}", named(errno())) } else { "ok".into() };
    unsafe { libc::close(fd) };
    r
}

/// The calls of `crossperm_probe`, one word each.
fn calls(pid: i32) -> String {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: &str| out.push(s.to_string());
    push(ok(unsafe { libc::kill(pid, 0) } as i64));
    for nr in [libc::SYS_process_vm_readv, libc::SYS_process_vm_writev] {
        let mut local = 0x5a5au64;
        let liov = libc::iovec { iov_base: (&raw mut local).cast(), iov_len: 8 };
        let riov = libc::iovec { iov_base: (&raw mut SCRATCH).cast(), iov_len: 8 };
        push(ok(unsafe { libc::syscall(nr, pid, &liov, 1, &riov, 1, 0) }));
    }
    push(ok(unsafe { libc::syscall(libc::SYS_kcmp, libc::getpid(), pid, 1, 0, 0) }));
    let r = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, 0, 0) };
    if r >= 0 {
        unsafe { libc::close(r as i32) };
    }
    push(ok(r));
    let (mut head, mut len) = (0u64, 0usize);
    push(ok(unsafe { libc::syscall(libc::SYS_get_robust_list, pid, &mut head, &mut len) }));
    let mut lim = [0u64; 2];
    push(ok(unsafe {
        libc::syscall(libc::SYS_prlimit64, pid, libc::RLIMIT_NOFILE, std::ptr::null::<u64>(), lim.as_mut_ptr())
    }));
    let iov = libc::iovec { iov_base: unsafe { PAGE } as *mut libc::c_void, iov_len: 4096 };
    push(ok(unsafe { libc::syscall(libc::SYS_process_madvise, pidfd, &iov, 1, libc::MADV_COLD, 0) }));
    let mut set = [0u8; 128];
    unsafe { libc::syscall(libc::SYS_sched_getaffinity, 0, set.len(), set.as_mut_ptr()) };
    push(ok(unsafe { libc::syscall(libc::SYS_sched_setaffinity, pid, set.len(), set.as_ptr()) }));
    push(ok(unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as u32, 0) } as i64));
    let param = 0i32;
    push(ok(unsafe { libc::syscall(libc::SYS_sched_setscheduler, pid, libc::SCHED_OTHER, &param) }));
    let mut attr = [0u32; 12];
    attr[0] = 48;
    push(ok(unsafe { libc::syscall(libc::SYS_sched_setattr, pid, attr.as_ptr(), 0) }));
    push(ok(unsafe { libc::syscall(libc::SYS_ioprio_set, 1, pid, (2 << 13) | 4) }));
    for f in ["environ", "io", "syscall", "personality"] {
        out.push(proc_read(pid, f));
    }
    unsafe { libc::close(pidfd) };
    out.join(" ")
}

type Rule = (&'static str, &'static str, &'static str);

/// kill, process_vm_readv, process_vm_writev, kcmp, pidfd_getfd,
/// get_robust_list, prlimit64, process_madvise, sched_setaffinity,
/// setpriority, sched_setscheduler, sched_setattr, ioprio_set, and reading
/// environ, io, syscall and personality.
const EXPECTED: [Rule; 22] = [
    ("root", "1000 undumpable", "ok ok ok ok ok ok ok ok ok ok ok ok ok ok ok ok ok"),
    ("1000", "root", "EPERM EPERM EPERM EPERM EPERM EPERM EPERM EACCES EPERM EPERM EPERM EPERM EPERM open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("1000", "1000", "ok ok ok ok ok ok ok EPERM ok ok ok ok ok ok ok ok ok"),
    ("1000", "1000 undumpable", "ok EPERM EPERM EPERM EPERM EPERM ok EACCES ok ok ok ok ok open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("1000", "1000 gid 1001", "ok EPERM EPERM EPERM EPERM EPERM EPERM EACCES ok ok ok ok ok open:EACCES read:EACCES read:EPERM read:EPERM"),
    ("1000", "1000 saved uid 0", "ok EPERM EPERM EPERM EPERM EPERM EPERM EACCES EPERM EPERM EPERM EPERM EPERM open:EACCES read:EACCES read:EPERM read:EPERM"),
    ("1000", "real 2000 eff 1000", "EPERM EPERM EPERM EPERM EPERM EPERM EPERM EACCES ok ok ok ok EPERM open:EACCES read:EACCES read:EPERM read:EPERM"),
    ("1000", "itself", "ok ok ok ok ok ok ok ok ok ok ok ok ok open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("fs 1000 real 2000", "root", "EPERM EPERM EPERM EPERM EPERM EPERM EPERM EACCES EPERM EPERM EPERM EPERM EPERM open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("fs 1000 real 2000", "1000", "ok EPERM EPERM EPERM EPERM EPERM EPERM EPERM ok ok ok ok ok ok ok ok ok"),
    ("fs 1000 real 2000", "1000 undumpable", "ok EPERM EPERM EPERM EPERM EPERM EPERM EACCES ok ok ok ok ok open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("fs 1000 real 2000", "1000 gid 1001", "ok EPERM EPERM EPERM EPERM EPERM EPERM EACCES ok ok ok ok ok open:EACCES read:EACCES read:EPERM read:EPERM"),
    ("fs 1000 real 2000", "1000 saved uid 0", "ok EPERM EPERM EPERM EPERM EPERM EPERM EACCES EPERM EPERM EPERM EPERM EPERM open:EACCES read:EACCES read:EPERM read:EPERM"),
    ("fs 1000 real 2000", "real 2000 eff 1000", "ok EPERM EPERM EPERM EPERM EPERM EPERM EACCES ok ok ok ok ok open:EACCES read:EACCES read:EPERM read:EPERM"),
    ("fs 1000 real 2000", "itself", "ok ok ok ok ok ok ok ok ok ok ok ok ok open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("real 1000 fs 2000", "root", "EPERM EPERM EPERM EPERM EPERM EPERM EPERM EACCES EPERM EPERM EPERM EPERM EPERM open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("real 1000 fs 2000", "1000", "ok ok ok ok ok ok ok EACCES EPERM EPERM EPERM EPERM ok open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("real 1000 fs 2000", "1000 undumpable", "ok EPERM EPERM EPERM EPERM EPERM ok EACCES EPERM EPERM EPERM EPERM ok open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("real 1000 fs 2000", "1000 gid 1001", "ok EPERM EPERM EPERM EPERM EPERM EPERM EACCES EPERM EPERM EPERM EPERM ok open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("real 1000 fs 2000", "1000 saved uid 0", "ok EPERM EPERM EPERM EPERM EPERM EPERM EACCES EPERM EPERM EPERM EPERM EPERM open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("real 1000 fs 2000", "real 2000 eff 1000", "ok EPERM EPERM EPERM EPERM EPERM EPERM EACCES ok ok ok ok ok open:EACCES open:EACCES open:EACCES open:EACCES"),
    ("real 1000 fs 2000", "itself", "ok ok ok ok ok ok ok ok ok ok ok ok ok open:EACCES open:EACCES open:EACCES open:EACCES"),
];

fn become_caller(name: &str) {
    match name {
        "root" => {}
        "1000" => ids(1000, 1000, 1000),
        "fs 1000 real 2000" => ids(2000, 1000, 2000),
        "real 1000 fs 2000" => ids(1000, 2000, 1000),
        _ => unreachable!(),
    }
}

fn permissions(h: &mut Harness) {
    h.group("permissions");
    unsafe {
        PAGE = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        ) as u64;
        *(PAGE as *mut u8) = 1;
    }
    let targets: [(&str, i32); 6] = [
        ("root", target(|| set_dumpable(1))),
        ("1000", target(|| {
            ids(1000, 1000, 1000);
            set_dumpable(1);
        })),
        ("1000 undumpable", target(|| ids(1000, 1000, 1000))),
        ("1000 gid 1001", target(|| unsafe {
            libc::syscall(libc::SYS_setresgid, 1001, 1001, 1001);
            libc::syscall(libc::SYS_setresuid, 1000, 1000, 1000);
            set_dumpable(1);
        })),
        ("1000 saved uid 0", target(|| unsafe {
            libc::syscall(libc::SYS_setresgid, 1000, 1000, 1000);
            libc::syscall(libc::SYS_setresuid, 1000, 1000, 0);
            set_dumpable(1);
        })),
        ("real 2000 eff 1000", target(|| {
            ids(2000, 1000, 2000);
            set_dumpable(1);
        })),
    ];
    for (caller, tname, want) in EXPECTED {
        let got = in_child(|| {
            become_caller(caller);
            if tname == "itself" {
                set_dumpable(0);
                calls(unsafe { libc::getpid() })
            } else {
                calls(targets.iter().find(|(n, _)| *n == tname).unwrap().1)
            }
        });
        check!(h, got == want, "{caller} -> {tname}\n      got  {got}\n      want {want}");
    }
    // A saved uid of 0 keeps the permitted set and empties the effective one.
    let saved = targets[4].1;
    let hdr = [0x2008_0522u32, saved as u32];
    let mut data = [0u32; 6];
    unsafe { libc::syscall(libc::SYS_capget, hdr.as_ptr(), data.as_mut_ptr()) };
    check!(h, data[0] == 0 && data[1] != 0, "capget of a saved uid of 0: effective {:#x}, permitted {:#x}", data[0], data[1]);
    for (_, pid) in targets {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
    }
}

fn read_once(path: &str) -> String {
    let c = cpath(path);
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return String::new();
    }
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    unsafe { libc::close(fd) };
    String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned()
}

fn io_field(text: &str, key: &str) -> u64 {
    text.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix(": ")?.parse().ok()).unwrap_or(u64::MAX)
}

fn entries(h: &mut Harness) {
    h.group("entries");
    let null = cpath("/dev/null");
    let sink = unsafe { libc::open(null.as_ptr(), libc::O_WRONLY) };
    let a = read_once("/proc/self/io");
    let buf = [0u8; 16];
    unsafe {
        libc::write(sink, buf.as_ptr().cast(), 16);
        libc::write(sink, buf.as_ptr().cast(), 3);
        libc::write(999, buf.as_ptr().cast(), 1);
        libc::close(sink);
    }
    let b = read_once("/proc/self/io");
    check!(h, io_field(&b, "syscw") - io_field(&a, "syscw") == 2, "io: two writes, and not the one on a bad descriptor\n{a}{b}");
    check!(h, io_field(&b, "wchar") - io_field(&a, "wchar") == 19, "io: wchar counts what was written\n{a}{b}");
    check!(h, io_field(&b, "syscr") - io_field(&a, "syscr") == 1, "io: the read of io itself\n{a}{b}");

    let persona = unsafe { libc::personality(0xffff_ffff) };
    check!(h, read_once("/proc/self/personality") == format!("{persona:08x}\n"), "personality");

    let slack = "/proc/self/timerslack_ns";
    let c = cpath(slack);
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY) };
    unsafe {
        libc::write(fd, b"123456".as_ptr().cast(), 6);
        libc::close(fd);
    }
    check!(h, unsafe { libc::prctl(libc::PR_GET_TIMERSLACK) } == 123456, "timerslack_ns: a write is PR_SET_TIMERSLACK");
    unsafe { libc::prctl(libc::PR_SET_TIMERSLACK, 0) };
    check!(h, read_once(slack) == "50000\n", "timerslack_ns: 0 is the default");

    let own = read_once("/proc/self/syscall");
    check!(h, own.starts_with("63 ") && own.split_whitespace().count() == 9, "syscall: its own read, {own:?}");
    let child = unsafe { libc::fork() };
    if child == 0 {
        loop {
            unsafe { libc::pause() };
        }
    }
    let mut seen = String::new();
    for _ in 0..2000 {
        seen = read_once(&format!("/proc/{child}/syscall"));
        if seen.starts_with("73 ") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    check!(h, seen.starts_with("73 0x0 0x0 0x0 0x0 "), "syscall: a child in pause() is in ppoll, {seen:?}");
    let ns = std::fs::read_link(format!("/proc/{child}/ns/uts")).ok();
    check!(h, ns.is_some() && ns == std::fs::read_link("/proc/self/ns/uts").ok(), "ns: one uts namespace, {ns:?}");
    use std::os::unix::fs::MetadataExt;
    let st = std::fs::metadata("/proc/self/ns/uts").map(|m| (m.ino(), m.mode())).ok();
    let num = ns.map(|p| p.to_string_lossy().trim_start_matches("uts:[").trim_end_matches(']').parse::<u64>().unwrap_or(0));
    check!(h, st.map(|s| s.0) == num && st.map(|s| s.1) == Some(0o100444), "ns: following the link is nsfs's inode, {st:?}");
    unsafe {
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, std::ptr::null_mut(), 0);
    }

    let maps = read_once("/proc/self/maps");
    let first = maps.lines().find(|l| l.split_whitespace().nth(5).is_some_and(|p| p.starts_with('/'))).unwrap_or("");
    let range = first.split_whitespace().next().unwrap_or("");
    let (s, e) = range.split_once('-').unwrap_or(("0", "0"));
    let name = format!(
        "/proc/self/map_files/{:x}-{:x}",
        u64::from_str_radix(s, 16).unwrap_or(0),
        u64::from_str_radix(e, 16).unwrap_or(0)
    );
    let path = first.split_whitespace().nth(5).unwrap_or("").to_string();
    check!(h, std::fs::read_link(&name).ok().map(|p| p.to_string_lossy().into_owned()) == Some(path.clone()), "map_files: {name} reads {path}");
    let unprivileged = in_child(|| {
        ids(1000, 1000, 1000);
        let rl = std::fs::read_link(&name).is_ok();
        let st = std::fs::metadata(&name).map_or_else(|e| e.raw_os_error().unwrap_or(0), |_| 0);
        format!("{rl} {}", named(st))
    });
    check!(h, unprivileged == "true EPERM", "map_files: its own, unprivileged, reads but does not follow: {unprivileged}");
}

fn main() {
    let mut h = Harness::new();
    permissions(&mut h);
    entries(&mut h);
    std::process::exit(h.finish());
}
