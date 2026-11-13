//! The process and security calls a 7.x kernel has that no other probe names:
//! `kcmp`, `sched_setattr`/`sched_getattr`, `seccomp`, `unshare`, `setns`,
//! `listns`, the `lsm_*` and landlock calls, `bpf`, `perf_event_open`,
//! `userfaultfd`, the keyring calls, `PR_SET_VMA`, and the `/proc/sys/kernel`
//! files programs read to find out which of these they may use.
//!
//! **A report, not a check**: one line per case, diffed against an arm64
//! container by `tests/integration/probe_diff.sh`, which runs this one with
//! seccomp off (the container's filter would otherwise answer for most of
//! these) and `CAP_SYS_NICE` added. The container keeps its other dropped
//! capabilities, so an answer that needs `CAP_SYS_ADMIN` there is the
//! container's and is named in that script's KNOWN list.
//!
//! Everything that changes the process -- a seccomp filter, an `unshare`, a
//! scheduling attribute -- happens in a forked child, so each section starts
//! from the same state on both sides.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<60} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EBADF => "EBADF",
        libc::EAGAIN => "EAGAIN",
        libc::EFAULT => "EFAULT",
        libc::EINVAL => "EINVAL",
        libc::ENOSYS => "ENOSYS",
        libc::E2BIG => "E2BIG",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EACCES => "EACCES",
        libc::ENODEV => "ENODEV",
        libc::ENOKEY => "ENOKEY",
        libc::EDQUOT => "EDQUOT",
        libc::EBUSY => "EBUSY",
        libc::ENOMEM => "ENOMEM",
        libc::EUSERS => "EUSERS",
        libc::ENOTTY => "ENOTTY",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn r(v: i64) -> String {
    if v < 0 { named(errno()) } else { v.to_string() }
}

fn ok(v: i64) -> String {
    if v < 0 { named(errno()) } else { "ok".into() }
}

/// Run `f` in a child and return what it printed through the pipe, one line
/// per case as `(what, value)`; or how it died.
fn in_child(f: impl FnOnce(&mut dyn FnMut(&str, String))) -> Vec<(String, String)> {
    let mut p = [0; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let c = unsafe { libc::fork() };
    if c == 0 {
        unsafe { libc::close(p[0]) };
        // A fixed number, so the strict-mode case can write to it raw.
        unsafe { libc::dup2(p[1], 99) };
        let w = 99;
        let mut say = |what: &str, v: String| {
            let s = format!("{what}\t{v}\n");
            unsafe { libc::write(w, s.as_ptr().cast(), s.len()) };
        };
        f(&mut say);
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(p[1]) };
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(p[0], buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    unsafe { libc::close(p[0]) };
    let mut st = 0;
    unsafe { libc::waitpid(c, &mut st, 0) };
    let mut v: Vec<(String, String)> = String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|l| l.split_once('\t').map(|(a, b)| (a.to_owned(), b.to_owned())))
        .collect();
    let how = if libc::WIFSIGNALED(st) {
        format!("killed by signal {}", libc::WTERMSIG(st))
    } else {
        format!("exit {}", libc::WEXITSTATUS(st))
    };
    v.push(("  the child".into(), how));
    v
}

fn show(v: Vec<(String, String)>) {
    for (a, b) in v {
        line(&a, b);
    }
}

fn kcmp(p1: i32, p2: i32, ty: i32, a: u64, b: u64) -> String {
    let v = unsafe { libc::syscall(272, p1, p2, ty, a, b) };
    match v {
        _ if v < 0 => named(errno()),
        0 => "equal".into(),
        1 | 2 => "ordered, not equal".into(),
        3 => "not equal".into(),
        _ => format!("{v}"),
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SchedAttr {
    size: u32,
    policy: u32,
    flags: u64,
    nice: i32,
    priority: u32,
    runtime: u64,
    deadline: u64,
    period: u64,
    util_min: u32,
    util_max: u32,
    tail: [u64; 2],
}

fn getattr(size: u32, flags: u32) -> (String, SchedAttr) {
    let mut a = SchedAttr::default();
    let v = unsafe { libc::syscall(275, 0, &mut a, size, flags) };
    (ok(v), a)
}

fn setattr(a: &SchedAttr) -> String {
    ok(unsafe { libc::syscall(274, 0, a, 0) })
}

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

/// A filter that answers `ret` for syscall `nr` and allows the rest.
fn filter_for(nr: u32, ret: u32) -> Vec<SockFilter> {
    vec![
        SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 0 },
        SockFilter { code: BPF_JEQ_K, jt: 0, jf: 1, k: nr },
        SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: ret },
        SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: 0x7fff_0000 },
    ]
}

fn install(f: &[SockFilter], flags: u64) -> i64 {
    let prog = SockFprog { len: f.len() as u16, filter: f.as_ptr() };
    unsafe { libc::syscall(277, 1, flags, &prog) }
}

fn status_field(name: &str) -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix(&format!("{name}:")).map(|v| v.trim().to_owned())))
        .unwrap_or_else(|| "absent".into())
}

fn main() {
    let me = unsafe { libc::getpid() };

    println!("########## kcmp ##########");
    {
        let a = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        let b = unsafe { libc::dup(a) };
        let c = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        line("FILE, fd and its dup", kcmp(me, me, 0, a as u64, b as u64));
        line("FILE, two opens of one file", kcmp(me, me, 0, a as u64, c as u64));
        line("FILE, a closed descriptor", kcmp(me, me, 0, a as u64, 9999));
        line("VM, self and self", kcmp(me, me, 1, 0, 0));
        line("FILES, self and self", kcmp(me, me, 2, 0, 0));
        line("FS, self and self", kcmp(me, me, 3, 0, 0));
        line("SIGHAND, self and self", kcmp(me, me, 4, 0, 0));
        line("IO, self and self", kcmp(me, me, 5, 0, 0));
        line("SYSVSEM, self and self", kcmp(me, me, 6, 0, 0));
        line("type 8", kcmp(me, me, 8, 0, 0));
        line("type -1", kcmp(me, me, -1, 0, 0));
        line("a pid that is not there", kcmp(me, 999_999, 1, 0, 0));
        // A thread shares everything a thread shares.
        let (tx, rx) = std::sync::mpsc::channel();
        let (gtx, grx) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            tx.send(unsafe { libc::gettid() }).unwrap();
            let _ = grx.recv();
        });
        let tid = rx.recv().unwrap();
        line("VM, self and own thread", kcmp(me, tid, 1, 0, 0));
        line("FILES, self and own thread", kcmp(me, tid, 2, 0, 0));
        line("FS, self and own thread", kcmp(me, tid, 3, 0, 0));
        line("SIGHAND, self and own thread", kcmp(me, tid, 4, 0, 0));
        line("FILE, the same fd through a thread", kcmp(me, tid, 0, a as u64, a as u64));
        gtx.send(()).unwrap();
        t.join().unwrap();
        // A forked child shares none of that, but its inherited descriptor
        // names the same open file description.
        let mut p = [0; 2];
        unsafe { libc::pipe(p.as_mut_ptr()) };
        let child = unsafe { libc::fork() };
        if child == 0 {
            unsafe {
                libc::close(p[1]);
                let mut x = 0u8;
                libc::read(p[0], (&raw mut x).cast(), 1);
                libc::_exit(0);
            }
        }
        line("VM, self and a forked child", kcmp(me, child, 1, 0, 0));
        line("FILES, self and a forked child", kcmp(me, child, 2, 0, 0));
        line("FS, self and a forked child", kcmp(me, child, 3, 0, 0));
        line("SIGHAND, self and a forked child", kcmp(me, child, 4, 0, 0));
        line("FILE, an inherited descriptor", kcmp(me, child, 0, a as u64, a as u64));
        line("FILE, inherited vs another open", kcmp(me, child, 0, a as u64, c as u64));
        // EPOLL_TFD: is `a` registered in epoll `e` as target fd `a`?
        // /dev/null cannot be polled, so the target is the pipe's read end.
        let e = unsafe { libc::epoll_create1(0) };
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: 0 };
        line("epoll_ctl(ADD, a pipe)", ok(unsafe { libc::epoll_ctl(e, libc::EPOLL_CTL_ADD, p[0], &mut ev) } as i64));
        let slot = [e as u32, p[0] as u32, 0u32];
        line("EPOLL_TFD, a registered target", kcmp(me, me, 7, p[0] as u64, slot.as_ptr() as u64));
        line("EPOLL_TFD, registered, compared with another file", kcmp(me, me, 7, a as u64, slot.as_ptr() as u64));
        let slot = [e as u32, a as u32, 0u32];
        line("EPOLL_TFD, an unregistered target", kcmp(me, me, 7, a as u64, slot.as_ptr() as u64));
        let slot = [e as u32, p[0] as u32, 1u32];
        line("EPOLL_TFD, a registered target, toff 1", kcmp(me, me, 7, p[0] as u64, slot.as_ptr() as u64));
        let slot = [a as u32, a as u32, 0u32];
        line("EPOLL_TFD, not an epoll descriptor", kcmp(me, me, 7, a as u64, slot.as_ptr() as u64));
        line("EPOLL_TFD, an unreadable slot", kcmp(me, me, 7, a as u64, 8));
        unsafe {
            libc::close(p[0]);
            libc::close(p[1]);
            let mut st = 0;
            libc::waitpid(child, &mut st, 0);
            libc::close(e);
        }
        line("VM, self and a reaped child", kcmp(me, child, 1, 0, 0));
    }

    println!("\n########## sched_getattr / sched_setattr ##########");
    {
        let (v, a) = getattr(56, 0);
        line("getattr(56)", v);
        line("  size policy flags nice prio", format!("{} {} {} {} {}", a.size, a.policy, a.flags, a.nice, a.priority));
        line("  util_min util_max", format!("{} {}", a.util_min, a.util_max));
        let (v, a) = getattr(48, 0);
        line("getattr(48), SCHED_ATTR_SIZE_VER0", format!("{v}, size {}", a.size));
        let (v, a) = getattr(72, 0);
        line("getattr(72), bigger than the kernel's", format!("{v}, size {}, tail {:?}", a.size, a.tail));
        line("getattr(47)", getattr(47, 0).0);
        line("getattr(0)", getattr(0, 0).0);
        line("getattr(56, flags 1)", getattr(56, 1).0);
        line("getattr(NULL)", ok(unsafe { libc::syscall(275, 0, 0usize, 56, 0) }));
        line("getattr(pid 999999)", ok(unsafe { libc::syscall(275, 999_999, &mut SchedAttr::default(), 56, 0) }));
        line("getattr(pid -1)", ok(unsafe { libc::syscall(275, -1, &mut SchedAttr::default(), 56, 0) }));
        show(in_child(|say| {
            let base = SchedAttr { size: 56, ..Default::default() };
            say("setattr(OTHER, nice 5)", setattr(&SchedAttr { nice: 5, ..base }));
            say("  getpriority after", unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) }.to_string());
            let (_, a) = getattr(56, 0);
            say("  getattr nice", a.nice.to_string());
            say("setattr(OTHER, nice -3)", setattr(&SchedAttr { nice: -3, ..base }));
            say("setattr(OTHER, nice 40), clamped", setattr(&SchedAttr { nice: 40, ..base }));
            say("  getattr nice", getattr(56, 0).1.nice.to_string());
            say("setattr(BATCH)", setattr(&SchedAttr { policy: 3, ..base }));
            say("  sched_getscheduler", r(unsafe { libc::syscall(120, 0) }));
            say("setattr(IDLE)", setattr(&SchedAttr { policy: 5, ..base }));
            say("  sched_getscheduler", r(unsafe { libc::syscall(120, 0) }));
            say("setattr(OTHER, priority 1)", setattr(&SchedAttr { priority: 1, ..base }));
            say("setattr(policy 99)", setattr(&SchedAttr { policy: 99, ..base }));
            say("setattr(RESET_ON_FORK)", setattr(&SchedAttr { flags: 1, ..base }));
            let (_, a) = getattr(56, 0);
            say("  getattr flags policy", format!("{} {}", a.flags, a.policy));
            say("setattr(KEEP_POLICY|KEEP_PARAMS, BATCH)", setattr(&SchedAttr { policy: 3, flags: 0x18, ..base }));
            say("  sched_getscheduler", r(unsafe { libc::syscall(120, 0) }));
            say("setattr(flag 0x80)", setattr(&SchedAttr { flags: 0x80, ..base }));
            say("setattr(UTIL_CLAMP_MIN, 100)", setattr(&SchedAttr { flags: 0x20, util_min: 100, ..base }));
            say("setattr(UTIL_CLAMP_MAX, 2000)", setattr(&SchedAttr { flags: 0x40, util_max: 2000, ..base }));
            say("setattr(size 0)", setattr(&SchedAttr { size: 0, ..base }));
            say("setattr(size 47)", setattr(&SchedAttr { size: 47, ..base }));
            let mut big = SchedAttr { size: 72, ..base };
            say("setattr(size 72, zero tail)", setattr(&big));
            big.tail[1] = 1;
            say("setattr(size 72, non-zero tail)", setattr(&big));
            // E2BIG writes the size this kernel knows back into the struct.
            unsafe { libc::syscall(274, 0, &raw mut big, 0) };
            say("  size written back", unsafe { std::ptr::read_volatile(&raw const big.size) }.to_string());
            say("setattr(syscall flags 1)", ok(unsafe { libc::syscall(274, 0, &base, 1) }));
            say("setattr(NULL)", ok(unsafe { libc::syscall(274, 0, 0usize, 0) }));
            say("setattr(DEADLINE, zero runtime)", setattr(&SchedAttr { policy: 6, ..base }));
        }));
    }

    println!("\n########## seccomp ##########");
    {
        for (n, a) in [
            ("KILL_PROCESS", 0x8000_0000u32), ("KILL_THREAD", 0), ("TRAP", 0x30000), ("ERRNO", 0x50000),
            ("USER_NOTIF", 0x7fc0_0000), ("TRACE", 0x7ff0_0000), ("LOG", 0x7ffc_0000), ("ALLOW", 0x7fff_0000),
            ("0x12340000", 0x1234_0000),
        ] {
            line(&format!("GET_ACTION_AVAIL({n})"), ok(unsafe { libc::syscall(277, 2, 0, &a) }));
        }
        line("GET_ACTION_AVAIL, flags 1", ok(unsafe { libc::syscall(277, 2, 1, &0u32) }));
        let mut sizes = [0u16; 3];
        let v = unsafe { libc::syscall(277, 3, 0, sizes.as_mut_ptr()) };
        line("GET_NOTIF_SIZES", format!("{} {:?}", ok(v), sizes));
        line("seccomp(99)", ok(unsafe { libc::syscall(277, 99, 0, 0) }));
        line("SET_MODE_STRICT with flags", ok(unsafe { libc::syscall(277, 0, 1, 0) }));
        line("PR_GET_SECCOMP", r(unsafe { libc::prctl(libc::PR_GET_SECCOMP) } as i64));
        line("Seccomp: in status", status_field("Seccomp"));
        show(in_child(|say| {
            say("in a child: SET_MODE_FILTER without no_new_privs, as root",
                ok(install(&filter_for(libc::SYS_getppid as u32, 0x7fff_0000), 0)));
        }));
        show(in_child(|say| {
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            say("filter: getppid -> ERRNO(EPERM)", ok(install(&filter_for(libc::SYS_getppid as u32, 0x50001), 0)));
            say("  getppid", r(unsafe { libc::syscall(libc::SYS_getppid) }));
            say("  getpid still works", (unsafe { libc::getpid() } > 0).to_string());
            say("  PR_GET_SECCOMP", r(unsafe { libc::prctl(libc::PR_GET_SECCOMP) } as i64));
            say("  Seccomp:", status_field("Seccomp"));
            say("  Seccomp_filters:", status_field("Seccomp_filters"));
            say("  NoNewPrivs:", status_field("NoNewPrivs"));
            say("second filter: gettid -> ERRNO(EACCES)", ok(install(&filter_for(libc::SYS_gettid as u32, 0x5000d), 0)));
            say("  gettid", r(unsafe { libc::syscall(libc::SYS_gettid) }));
            say("  getppid, the first filter still applies", r(unsafe { libc::syscall(libc::SYS_getppid) }));
            say("  Seccomp_filters:", status_field("Seccomp_filters"));
            say("  SET_MODE_STRICT on top of a filter", ok(unsafe { libc::syscall(277, 0, 0, 0) }));
            let g = unsafe { libc::fork() };
            if g == 0 {
                let v = unsafe { libc::syscall(libc::SYS_getppid) };
                unsafe { libc::_exit(if v < 0 { errno() } else { 0 }) };
            }
            let mut st = 0;
            unsafe { libc::waitpid(g, &mut st, 0) };
            say("  getppid in a grandchild", named(libc::WEXITSTATUS(st)));
            say("ERRNO(0) data", {
                install(&filter_for(libc::SYS_getuid as u32, 0x50000), 0);
                r(unsafe { libc::syscall(libc::SYS_getuid) })
            });
            say("ERRNO(4096), clamped", {
                install(&filter_for(libc::SYS_getgid as u32, 0x5ffff), 0);
                r(unsafe { libc::syscall(libc::SYS_getgid) })
            });
        }));
        show(in_child(|say| {
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            let empty: [SockFilter; 0] = [];
            say("filter with 0 instructions", ok(install(&empty, 0)));
            let bad = [SockFilter { code: 0xffff, jt: 0, jf: 0, k: 0 }];
            say("filter with an invalid opcode", ok(install(&bad, 0)));
            let noret = [SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 0 }];
            say("filter that does not end in a return", ok(install(&noret, 0)));
            let oob = [SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 64 }, SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: 0x7fff_0000 }];
            say("filter loading past seccomp_data", ok(install(&oob, 0)));
            let mis = [SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 2 }, SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: 0x7fff_0000 }];
            say("filter loading an unaligned word", ok(install(&mis, 0)));
            let jmp = [SockFilter { code: BPF_JEQ_K, jt: 5, jf: 0, k: 0 }, SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: 0x7fff_0000 }];
            say("filter jumping past its end", ok(install(&jmp, 0)));
            let big: Vec<SockFilter> = (0..4097).map(|_| SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: 0x7fff_0000 }).collect();
            say("filter with 4097 instructions", ok(install(&big, 0)));
            say("unreadable fprog", ok(unsafe { libc::syscall(277, 1, 0, 8usize) }));
            say("flag 0x100", ok(install(&filter_for(0, 0x7fff_0000), 0x100)));
            say("TSYNC with one thread", r(install(&filter_for(0, 0x7fff_0000), 1)));
            say("LOG flag", ok(install(&filter_for(0, 0x7fff_0000), 2)));
            say("SPEC_ALLOW flag", ok(install(&filter_for(0, 0x7fff_0000), 4)));
            // The arch and the instruction pointer are readable.
            let arch = [
                SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 4 },
                SockFilter { code: BPF_JEQ_K, jt: 1, jf: 0, k: 0xc000_00b7 },
                SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: 0x50000 | 22 },
                SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: 0x7fff_0000 },
            ];
            say("filter: refuse every syscall unless arch is AUDIT_ARCH_AARCH64", ok(install(&arch, 0)));
            say("  getpid after it", (unsafe { libc::getpid() } > 0).to_string());
            // An argument: refuse dup(1000).
            let arg = [
                SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 0 },
                SockFilter { code: BPF_JEQ_K, jt: 0, jf: 3, k: libc::SYS_dup as u32 },
                SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 16 },
                SockFilter { code: BPF_JEQ_K, jt: 0, jf: 1, k: 1000 },
                SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: 0x50000 | 7 },
                SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: 0x7fff_0000 },
            ];
            say("filter: dup(1000) -> E2BIG", ok(install(&arg, 0)));
            say("  dup(1000)", r(unsafe { libc::dup(1000) } as i64));
            say("  dup(1001)", r(unsafe { libc::dup(1001) } as i64));
        }));
        show(in_child(|say| {
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            say("filter: getppid -> TRAP", ok(install(&filter_for(libc::SYS_getppid as u32, 0x30000 | 42), 0)));
            unsafe { libc::syscall(libc::SYS_getppid) };
            say("  survived getppid", "true".into());
        }));
        show(in_child(|say| {
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            say("filter: getppid -> KILL_PROCESS", ok(install(&filter_for(libc::SYS_getppid as u32, 0x8000_0000), 0)));
            unsafe { libc::syscall(libc::SYS_getppid) };
            say("  survived getppid", "true".into());
        }));
        show(in_child(|say| {
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            say("filter: getppid -> TRACE, no tracer", ok(install(&filter_for(libc::SYS_getppid as u32, 0x7ff0_0000), 0)));
            say("  getppid", r(unsafe { libc::syscall(libc::SYS_getppid) }));
            say("filter: getuid -> LOG", ok(install(&filter_for(libc::SYS_getuid as u32, 0x7ffc_0000), 0)));
            say("  getuid", r(unsafe { libc::syscall(libc::SYS_getuid) }));
            say("filter: gettid -> USER_NOTIF, no listener", ok(install(&filter_for(libc::SYS_gettid as u32, 0x7fc0_0000), 0)));
            say("  gettid", r(unsafe { libc::syscall(libc::SYS_gettid) }));
        }));
        show(in_child(|say| {
            // SIGSYS with a handler: the siginfo says which call and where.
            static SEEN: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
            extern "C" fn h(_: i32, si: *mut libc::siginfo_t, _: *mut libc::c_void) {
                let p = si.cast::<i32>();
                // si_code at +8; _sigsys: si_call_addr at +16, si_syscall at +24, si_arch at +28.
                let code = unsafe { p.add(2).read() };
                let nr = unsafe { p.add(6).read() };
                let arch = unsafe { p.add(7).read() } as u32;
                let errno_ = unsafe { p.add(1).read() };
                SEEN.store(((code as i64) << 48) | ((nr as i64) << 32) | ((errno_ as i64 & 0xffff) << 16) | ((arch == 0xc000_00b7) as i64), std::sync::atomic::Ordering::SeqCst);
            }
            let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
            sa.sa_sigaction = h as *const () as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            unsafe { libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut()) };
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            say("filter: getppid -> TRAP|42, with a handler", ok(install(&filter_for(libc::SYS_getppid as u32, 0x30000 | 42), 0)));
            let v = unsafe { libc::syscall(libc::SYS_getppid) };
            say("  getppid returned", r(v));
            let s = SEEN.load(std::sync::atomic::Ordering::SeqCst);
            say("  si_code (SYS_SECCOMP is 1)", (s >> 48).to_string());
            say("  si_syscall", ((s >> 32) & 0xffff).to_string());
            say("  si_errno, the filter's data", ((s >> 16) & 0xffff).to_string());
            say("  si_arch is AUDIT_ARCH_AARCH64", (s & 1 == 1).to_string());
        }));
        show(in_child(|say| {
            // Strict mode allows read, write, exit and sigreturn and nothing
            // else -- not even the allocation `say` would make -- so the lines
            // are formatted first and written raw.
            say("PR_SET_SECCOMP(STRICT)", "next line".into());
            let ok_line = "  prctl returned\tok\n";
            let after = "  survived getpid\ttrue\n";
            let v = unsafe { libc::prctl(libc::PR_SET_SECCOMP, 1) };
            if v == 0 {
                unsafe { libc::syscall(libc::SYS_write, 99, ok_line.as_ptr(), ok_line.len()) };
            }
            unsafe { libc::syscall(libc::SYS_getpid) };
            unsafe { libc::syscall(libc::SYS_write, 99, after.as_ptr(), after.len()) };
        }));
    }

    println!("\n########## unshare ##########");
    show(in_child(|say| {
        say("unshare(0)", ok(unsafe { libc::unshare(0) } as i64));
        say("unshare(CLONE_FILES)", ok(unsafe { libc::unshare(libc::CLONE_FILES) } as i64));
        say("unshare(CLONE_FS)", ok(unsafe { libc::unshare(libc::CLONE_FS) } as i64));
        say("unshare(CLONE_SYSVSEM)", ok(unsafe { libc::unshare(libc::CLONE_SYSVSEM) } as i64));
        say("unshare(CLONE_VM), single-threaded", ok(unsafe { libc::unshare(libc::CLONE_VM) } as i64));
        say("unshare(CLONE_SIGHAND), single-threaded", ok(unsafe { libc::unshare(libc::CLONE_SIGHAND) } as i64));
        say("unshare(CLONE_THREAD), single-threaded", ok(unsafe { libc::unshare(libc::CLONE_THREAD) } as i64));
        say("unshare(SIGCHLD), not an unshare flag", ok(unsafe { libc::unshare(libc::SIGCHLD) } as i64));
        say("unshare(CLONE_PARENT)", ok(unsafe { libc::unshare(libc::CLONE_PARENT) } as i64));
        say("unshare(CLONE_NEWNS)", ok(unsafe { libc::unshare(libc::CLONE_NEWNS) } as i64));
        say("unshare(CLONE_NEWUTS)", ok(unsafe { libc::unshare(libc::CLONE_NEWUTS) } as i64));
        say("unshare(CLONE_NEWIPC)", ok(unsafe { libc::unshare(libc::CLONE_NEWIPC) } as i64));
        say("unshare(CLONE_NEWNET)", ok(unsafe { libc::unshare(libc::CLONE_NEWNET) } as i64));
        say("unshare(CLONE_NEWPID)", ok(unsafe { libc::unshare(libc::CLONE_NEWPID) } as i64));
        say("unshare(CLONE_NEWCGROUP)", ok(unsafe { libc::unshare(libc::CLONE_NEWCGROUP) } as i64));
        say("unshare(CLONE_NEWTIME)", ok(unsafe { libc::unshare(0x80) } as i64));
    }));
    show(in_child(|say| {
        // CLONE_FILES really gives this process its own table: a thread that
        // shared it no longer sees a descriptor opened after.
        let (tx, rx) = std::sync::mpsc::channel::<i32>();
        let (back_tx, back_rx) = std::sync::mpsc::channel::<String>();
        let t = std::thread::spawn(move || {
            let fd = rx.recv().unwrap();
            let v = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            back_tx.send(if v < 0 { named(errno()) } else { "open".into() }).unwrap();
            let fd = rx.recv().unwrap();
            let v = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            back_tx.send(if v < 0 { named(errno()) } else { "open".into() }).unwrap();
        });
        let a = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        tx.send(a).unwrap();
        say("a thread sees a descriptor opened before", back_rx.recv().unwrap());
        say("unshare(CLONE_FILES) with a thread sharing the table", ok(unsafe { libc::unshare(libc::CLONE_FILES) } as i64));
        let b = unsafe { libc::open(c"/dev/zero".as_ptr(), libc::O_RDONLY) };
        tx.send(b).unwrap();
        say("  the thread sees one opened after", back_rx.recv().unwrap());
        t.join().unwrap();
        let (tx2, rx2) = std::sync::mpsc::channel::<()>();
        let t2 = std::thread::spawn(move || { let _ = rx2.recv(); });
        say("unshare(CLONE_VM) with two threads", ok(unsafe { libc::unshare(libc::CLONE_VM) } as i64));
        say("unshare(CLONE_SIGHAND) with two threads", ok(unsafe { libc::unshare(libc::CLONE_SIGHAND) } as i64));
        say("unshare(CLONE_THREAD) with two threads", ok(unsafe { libc::unshare(libc::CLONE_THREAD) } as i64));
        tx2.send(()).unwrap();
        t2.join().unwrap();
        // CLONE_FS: a thread's chdir no longer moves this one.
        let t3 = std::thread::spawn(|| {
            let v = unsafe { libc::unshare(libc::CLONE_FS) };
            let w = unsafe { libc::chdir(c"/proc".as_ptr()) };
            (v, w)
        });
        unsafe { libc::chdir(c"/".as_ptr()) };
        let (v, _) = t3.join().unwrap();
        say("unshare(CLONE_FS) in a thread", ok(v as i64));
        let mut cwd = [0u8; 64];
        unsafe { libc::getcwd(cwd.as_mut_ptr().cast(), 64) };
        say("  the thread's chdir did not move the process",
            (std::ffi::CStr::from_bytes_until_nul(&cwd).unwrap().to_bytes() == b"/").to_string());
    }));

    println!("\n########## setns ##########");
    {
        let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        line("setns(/dev/null, 0)", ok(unsafe { libc::setns(null, 0) } as i64));
        line("setns(9999, 0)", ok(unsafe { libc::setns(9999, 0) } as i64));
        line("setns(-1, 0)", ok(unsafe { libc::setns(-1, 0) } as i64));
        let pfd = unsafe { libc::syscall(434, me, 0) } as i32;
        line("setns(pidfd of self, 0)", ok(unsafe { libc::setns(pfd, 0) } as i64));
        line("setns(pidfd of self, CLONE_NEWUTS)", ok(unsafe { libc::setns(pfd, libc::CLONE_NEWUTS) } as i64));
        line("setns(pidfd of self, CLONE_VM)", ok(unsafe { libc::setns(pfd, libc::CLONE_VM) } as i64));
        let ns = unsafe { libc::open(c"/proc/self/ns/uts".as_ptr(), libc::O_RDONLY) };
        line("open /proc/self/ns/uts", if ns < 0 { named(errno()) } else { "a descriptor".into() });
        // Printed either way, so that both sides have the same lines.
        let join = |t| if ns < 0 { "no descriptor".to_string() } else { ok(unsafe { libc::setns(ns, t) } as i64) };
        line("setns(own uts ns, CLONE_NEWUTS)", join(libc::CLONE_NEWUTS));
        line("setns(own uts ns, CLONE_NEWNET)", join(libc::CLONE_NEWNET));
        if ns >= 0 {
            unsafe { libc::close(ns) };
        }
        unsafe { libc::close(pfd) };
        unsafe { libc::close(null) };
    }

    println!("\n########## listns ##########");
    {
        #[repr(C)]
        struct Req { size: u32, spare: u32, ns_id: u64, ns_type: u32, spare2: u32, user_ns_id: u64 }
        let mut ids = [0u64; 64];
        let req = Req { size: 32, spare: 0, ns_id: 0, ns_type: 0, spare2: 0, user_ns_id: 0 };
        let v = unsafe { libc::syscall(470, &req, ids.as_mut_ptr(), 64usize, 0) };
        line("listns(all types, 64 slots)", if v < 0 { named(errno()) } else { "a count".into() });
        let v = unsafe { libc::syscall(470, &req, ids.as_mut_ptr(), 64usize, 1) };
        line("listns(flags 1)", ok(v));
        let bad = Req { size: 8, ..req };
        line("listns(size 8)", ok(unsafe { libc::syscall(470, &bad, ids.as_mut_ptr(), 64usize, 0) }));
        line("listns(NULL req)", ok(unsafe { libc::syscall(470, 0usize, ids.as_mut_ptr(), 64usize, 0) }));
        line("listns(0 slots)", ok(unsafe { libc::syscall(470, &req, ids.as_mut_ptr(), 0usize, 0) }));
    }

    println!("\n########## the LSM calls ##########");
    {
        let mut ids = [0u64; 16];
        let mut size: u32 = 128;
        let v = unsafe { libc::syscall(461, ids.as_mut_ptr(), &mut size, 0) };
        line("lsm_list_modules", if v < 0 { named(errno()) } else { "a count".into() });
        line("  capability is listed", ids.contains(&100));
        line("lsm_list_modules(flags 1)", ok(unsafe { libc::syscall(461, ids.as_mut_ptr(), &mut size, 1) }));
        let mut small: u32 = 0;
        let v = unsafe { libc::syscall(461, ids.as_mut_ptr(), &mut small, 0) };
        line("lsm_list_modules(size 0)", format!("{}, size became a multiple of 8: {}", ok(v), small % 8 == 0 && small > 0));
        let mut buf = [0u64; 64];
        let mut sz: u32 = 512;
        let v = unsafe { libc::syscall(459, 100, buf.as_mut_ptr(), &mut sz, 0) };
        line("lsm_get_self_attr(LSM_ATTR_CURRENT)", r(v));
        let v = unsafe { libc::syscall(459, 999, buf.as_mut_ptr(), &mut sz, 0) };
        line("lsm_get_self_attr(999)", r(v));
        let v = unsafe { libc::syscall(459, 100, buf.as_mut_ptr(), &mut sz, 2) };
        line("lsm_get_self_attr(flags 2)", r(v));
        let ctx = [100u64, 0, 40, 8, 0];
        let v = unsafe { libc::syscall(460, 100, ctx.as_ptr(), 40u32, 0) };
        line("lsm_set_self_attr(CURRENT, capability)", r(v));
        let v = unsafe { libc::syscall(460, 100, ctx.as_ptr(), 40u32, 1) };
        line("lsm_set_self_attr(flags 1)", r(v));
    }

    println!("\n########## landlock ##########");
    {
        let v = unsafe { libc::syscall(444, 0usize, 0usize, 1u32) };
        line("landlock_create_ruleset(VERSION)", if v < 0 { named(errno()) } else { "an ABI version".into() });
        let v = unsafe { libc::syscall(444, 0usize, 0usize, 2u32) };
        line("landlock_create_ruleset(ERRATA)", if v < 0 { named(errno()) } else { "an errata mask".into() });
        let attr = [1u64, 0, 0];
        let v = unsafe { libc::syscall(444, attr.as_ptr(), 8usize, 0u32) };
        line("landlock_create_ruleset(fs EXECUTE)", if v < 0 { named(errno()) } else { "a descriptor".into() });
        line("landlock_add_rule(-1)", ok(unsafe { libc::syscall(445, -1, 1, 0usize, 0) }));
        line("landlock_restrict_self(-1)", ok(unsafe { libc::syscall(446, -1, 0) }));
    }

    println!("\n########## bpf, perf_event_open, userfaultfd ##########");
    {
        line("bpf(BPF_MAP_CREATE, NULL, 0)", ok(unsafe { libc::syscall(280, 0, 0usize, 0) }));
        let attr = [0u64; 16];
        line("bpf(BPF_MAP_CREATE, zeroed, 128)", ok(unsafe { libc::syscall(280, 0, attr.as_ptr(), 128) }));
        line("bpf(999)", ok(unsafe { libc::syscall(280, 999, attr.as_ptr(), 128) }));
        line("perf_event_open(NULL)", ok(unsafe { libc::syscall(241, 0usize, 0, -1, -1, 0) }));
        // PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK, this process, any CPU.
        let mut pa = [0u8; 128];
        pa[0..4].copy_from_slice(&1u32.to_ne_bytes());
        pa[4..8].copy_from_slice(&128u32.to_ne_bytes());
        pa[8..16].copy_from_slice(&1u64.to_ne_bytes());
        let v = unsafe { libc::syscall(241, pa.as_ptr(), 0, -1, -1, 0) };
        line("perf_event_open(SW_TASK_CLOCK, self)", if v < 0 { named(errno()) } else { "a descriptor".into() });
        line("userfaultfd(0)", ok(unsafe { libc::syscall(282, 0) }));
        line("userfaultfd(UFFD_USER_MODE_ONLY)", ok(unsafe { libc::syscall(282, 1) }));
        line("userfaultfd(0x100)", ok(unsafe { libc::syscall(282, 0x100) }));
        let u = unsafe { libc::open(c"/dev/userfaultfd".as_ptr(), libc::O_RDWR) };
        line("open /dev/userfaultfd", if u < 0 { named(errno()) } else { "a descriptor".into() });
    }

    println!("\n########## the keyring calls ##########");
    {
        line("keyctl(GET_KEYRING_ID, SESSION, 0)", if unsafe { libc::syscall(219, 0, -3, 0) } < 0 { named(errno()) } else { "an id".into() });
        line("keyctl(99)", ok(unsafe { libc::syscall(219, 99, 0, 0) }));
        let v = unsafe { libc::syscall(217, c"user".as_ptr(), c"probe".as_ptr(), b"v".as_ptr(), 1usize, -2) };
        line("add_key(user, probe, PROCESS keyring)", if v < 0 { named(errno()) } else { "an id".into() });
        let v = unsafe { libc::syscall(218, c"user".as_ptr(), c"nothing-has-this".as_ptr(), 0usize, 0) };
        line("request_key(user, an absent key)", ok(v));
    }

    println!("\n########## PR_SET_VMA ##########");
    {
        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), 2 * 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        let name_of = || {
            let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
            let a = format!("{:08x}-", p as usize);
            maps.lines().find(|l| l.starts_with(&a)).map(|l| l.split_whitespace().nth(5).unwrap_or("").to_owned()).unwrap_or_else(|| "no line".into())
        };
        let set = |n: *const libc::c_char, len: usize| unsafe { libc::prctl(0x53564d41, 0, p as usize, len, n as usize) } as i64;
        line("PR_SET_VMA_ANON_NAME(\"probe\")", ok(set(c"probe".as_ptr(), 4096)));
        line("  /proc/self/maps names it", name_of());
        line("  smaps too", std::fs::read_to_string("/proc/self/smaps").unwrap_or_default().contains("[anon:probe]"));
        line("PR_SET_VMA_ANON_NAME(NULL), clearing", ok(set(std::ptr::null(), 4096)));
        line("  /proc/self/maps after", name_of());
        line("PR_SET_VMA_ANON_NAME(with a \\x01)", ok(set(c"a\x01b".as_ptr(), 4096)));
        line("PR_SET_VMA_ANON_NAME(with a [)", ok(set(c"a[b".as_ptr(), 4096)));
        line("PR_SET_VMA_ANON_NAME(with a $)", ok(set(c"a$b".as_ptr(), 4096)));
        line("PR_SET_VMA_ANON_NAME(with a space)", ok(set(c"a b".as_ptr(), 4096)));
        let long = std::ffi::CString::new("x".repeat(80)).unwrap();
        line("PR_SET_VMA_ANON_NAME(80 bytes)", ok(set(long.as_ptr(), 4096)));
        let long = std::ffi::CString::new("x".repeat(79)).unwrap();
        line("PR_SET_VMA_ANON_NAME(79 bytes)", ok(set(long.as_ptr(), 4096)));
        line("PR_SET_VMA_ANON_NAME(unaligned start)", ok(unsafe { libc::prctl(0x53564d41, 0, p as usize + 1, 4096usize, c"x".as_ptr() as usize) } as i64));
        line("PR_SET_VMA_ANON_NAME(unmapped)", ok(unsafe { libc::prctl(0x53564d41, 0, 0x1000usize, 4096usize, c"x".as_ptr() as usize) } as i64));
        line("PR_SET_VMA_ANON_NAME(unreadable name)", ok(set(8 as *const libc::c_char, 4096)));
        line("PR_SET_VMA(1), not ANON_NAME", ok(unsafe { libc::prctl(0x53564d41, 1, p as usize, 4096usize, 0usize) } as i64));
        // On the first page only: the mapping splits into two lines.
        set(c"half".as_ptr(), 4096);
        line("  naming one page of two splits the line", name_of());
        let f = unsafe { libc::open(c"/dev/zero".as_ptr(), libc::O_RDONLY) };
        let q = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ, libc::MAP_PRIVATE, f, 0) };
        line("PR_SET_VMA_ANON_NAME on a file mapping", ok(unsafe { libc::prctl(0x53564d41, 0, q as usize, 4096usize, c"x".as_ptr() as usize) } as i64));
        let s = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0) };
        line("PR_SET_VMA_ANON_NAME on shared anon", ok(unsafe { libc::prctl(0x53564d41, 0, s as usize, 4096usize, c"x".as_ptr() as usize) } as i64));
    }

    println!("\n########## /proc/sys files that say what is allowed ##########");
    for f in [
        "kernel/ostype", "kernel/osrelease", "kernel/cap_last_cap", "kernel/ngroups_max", "kernel/overflowuid",
        "kernel/overflowgid", "kernel/pid_max", "kernel/threads-max", "kernel/random/boot_id", "kernel/random/uuid",
        "kernel/random/entropy_avail", "kernel/random/poolsize", "kernel/yama/ptrace_scope", "kernel/perf_event_paranoid",
        "kernel/unprivileged_bpf_disabled", "kernel/seccomp/actions_avail", "kernel/keys/maxkeys",
        "kernel/kptr_restrict", "kernel/dmesg_restrict", "kernel/randomize_va_space", "kernel/shmmax", "kernel/shmall",
        "kernel/shmmni", "kernel/msgmax", "kernel/msgmnb", "kernel/msgmni", "kernel/sem", "kernel/core_pattern",
        "kernel/hostname", "kernel/domainname", "kernel/tainted", "kernel/printk", "kernel/sched_child_runs_first",
        "kernel/unprivileged_userns_clone", "user/max_user_namespaces", "vm/overcommit_memory",
        "vm/max_map_count", "vm/mmap_min_addr", "vm/unprivileged_userfaultfd", "fs/file-max", "fs/nr_open",
        "fs/pipe-max-size", "fs/inotify/max_user_watches", "fs/protected_symlinks",
    ] {
        let v = std::fs::read_to_string(format!("/proc/sys/{f}"));
        let shown = match &v {
            Err(e) => named(e.raw_os_error().unwrap_or(0)),
            Ok(s) => match f {
                // Values that are this machine's rather than the kernel's.
                "kernel/ostype" | "kernel/cap_last_cap" | "kernel/ngroups_max" | "kernel/overflowuid"
                | "kernel/overflowgid" | "kernel/seccomp/actions_avail" | "vm/mmap_min_addr"
                | "kernel/random/poolsize" | "fs/nr_open" | "kernel/sched_child_runs_first" => s.trim().to_owned(),
                "kernel/random/boot_id" | "kernel/random/uuid" => format!("a uuid: {}", s.trim().len() == 36),
                "kernel/osrelease" => format!("starts with a digit: {}", s.starts_with(|c: char| c.is_ascii_digit())),
                _ => "readable".into(),
            },
        };
        line(&format!("/proc/sys/{f}"), shown);
    }
}
