//! Capability sets: `capget`/`capset`, the capability `prctl`s, what a uid
//! change and an `execve` do to the five sets, and a sample of operations
//! gated on exactly one capability.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container (`--privileged`, so the bounding set is full and seccomp is off)
//! and diffed by `tests/integration/probe_diff.sh`. Every case runs in a
//! fresh child of a root process with full permitted and effective sets, so
//! nothing a case drops is seen by the next one.
//!
//! Re-executed as `caps_probe report <case>` it prints the sets the new image
//! started with, which is how the exec cases read the transition.
//!
//! Run by `probe_diff.sh` on realfs, which reports the host's owner for every
//! file: the set-user-ID-root and set-group-ID cases differ there for that
//! reason and are in its KNOWN list; `caps_setid` asserts them on fakefs.

use std::ffi::CString;
use std::io::Write;

const V1: u32 = 0x1998_0330;
const V2: u32 = 0x2007_1026;
const V3: u32 = 0x2008_0522;

const CHOWN: u32 = 0;
const DAC_OVERRIDE: u32 = 1;
const DAC_READ_SEARCH: u32 = 2;
const FOWNER: u32 = 3;
const FSETID: u32 = 4;
const KILL: u32 = 5;
const SETGID: u32 = 6;
const SETUID: u32 = 7;
const SETPCAP: u32 = 8;
const NET_BIND_SERVICE: u32 = 10;
const NET_ADMIN: u32 = 12;
const NET_RAW: u32 = 13;
const IPC_LOCK: u32 = 14;
const IPC_OWNER: u32 = 15;
const SYS_CHROOT: u32 = 18;
const SYS_PTRACE: u32 = 19;
const SYS_ADMIN: u32 = 21;
const SYS_BOOT: u32 = 22;
const SYS_NICE: u32 = 23;
const SYS_RESOURCE: u32 = 24;
const SYS_TIME: u32 = 25;
const SYS_TTY_CONFIG: u32 = 26;
const MKNOD: u32 = 27;
const SETFCAP: u32 = 31;
const SYSLOG: u32 = 34;

const DIR: &str = "/tmp/capsprobe";

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
        libc::ESRCH => "ESRCH",
        libc::EFAULT => "EFAULT",
        libc::ENODATA => "ENODATA",
        libc::ERANGE => "ERANGE",
        libc::ENOSYS => "ENOSYS",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EADDRINUSE => "EADDRINUSE",
        libc::ENOMEM => "ENOMEM",
        libc::EBUSY => "EBUSY",
        libc::ENODEV => "ENODEV",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn ok(v: i64) -> String {
    if v < 0 { named(errno()) } else { format!("ok {v}") }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Header {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[derive(Clone, Copy, Default)]
struct Sets {
    e: u64,
    p: u64,
    i: u64,
}

fn capget(pid: i32) -> Option<Sets> {
    let mut h = Header { version: V3, pid };
    let mut d = [Data::default(); 2];
    let r = unsafe { libc::syscall(libc::SYS_capget, &raw mut h, d.as_mut_ptr()) };
    (r == 0).then(|| Sets {
        e: d[0].effective as u64 | (d[1].effective as u64) << 32,
        p: d[0].permitted as u64 | (d[1].permitted as u64) << 32,
        i: d[0].inheritable as u64 | (d[1].inheritable as u64) << 32,
    })
}

fn capset(s: Sets) -> String {
    let mut h = Header { version: V3, pid: 0 };
    let d = [
        Data { effective: s.e as u32, permitted: s.p as u32, inheritable: s.i as u32 },
        Data {
            effective: (s.e >> 32) as u32,
            permitted: (s.p >> 32) as u32,
            inheritable: (s.i >> 32) as u32,
        },
    ];
    ok(unsafe { libc::syscall(libc::SYS_capset, &raw mut h, d.as_ptr()) })
}

fn me() -> Sets {
    capget(0).unwrap_or_default()
}

fn bit(cap: u32) -> u64 {
    1 << cap
}

fn sets(s: Sets) -> String {
    format!("e={:#x} p={:#x} i={:#x}", s.e, s.p, s.i)
}

fn prctl(op: i32, a2: u64, a3: u64, a4: u64, a5: u64) -> String {
    ok(unsafe { libc::prctl(op, a2, a3, a4, a5) } as i64)
}

/// The `Cap*`, `NoNewPrivs` and `Seccomp` lines of a status file, joined.
fn status(pid: &str) -> String {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let keep = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp:"];
    text.lines()
        .filter(|l| keep.iter().any(|k| l.starts_with(k)))
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn ids() -> String {
    let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
    unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
    let fs = unsafe { libc::setfsuid(u32::MAX as libc::uid_t) };
    format!("uid {r}/{e}/{s} fs {fs}")
}

fn setresuid(r: u32, e: u32, s: u32) -> String {
    ok(unsafe { libc::syscall(libc::SYS_setresuid, r, e, s) })
}

fn setresgid(r: u32, e: u32, s: u32) -> String {
    ok(unsafe { libc::syscall(libc::SYS_setresgid, r, e, s) })
}

fn as_child(f: impl FnOnce()) {
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

/// A child that runs `setup` and waits to be killed.
fn target(setup: impl FnOnce()) -> i32 {
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

fn reap(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
}

/// Drop `caps` from the effective set only; the permitted set stays full.
fn without(caps: &[u32]) {
    let mut s = me();
    for &cap in caps {
        s.e &= !bit(cap);
    }
    capset(s);
}

/// `with` and `without` one capability, each in a child of its own.
fn gated(name: &str, cap: u32, f: impl Fn() -> String) {
    as_child(|| line(&format!("{name}: with"), f()));
    as_child(|| {
        without(&[cap]);
        line(&format!("{name}: without"), f())
    });
}

// ------------------------------------------------------------------ report

fn report() {
    let s = me();
    let keep = unsafe { libc::prctl(libc::PR_GET_KEEPCAPS, 0, 0, 0, 0) };
    let bits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) };
    let mut amb = 0u64;
    let mut bnd = 0u64;
    for cap in 0..64 {
        if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET as u64, cap, 0, 0) } == 1 {
            amb |= 1 << cap;
        }
        if unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) } == 1 {
            bnd |= 1 << cap;
        }
    }
    let secure = unsafe { libc::getauxval(libc::AT_SECURE) };
    let euid = unsafe { libc::getauxval(libc::AT_EUID) };
    let name = std::env::args().nth(2).unwrap_or_default();
    line(
        &format!("exec {name}"),
        format!(
            "{} {} a={amb:#x} b={bnd:#x} keepcaps={keep} securebits={bits:#x} AT_SECURE={secure} AT_EUID={euid}",
            ids(),
            sets(s)
        ),
    );
}

/// Exec `path` as `caps_probe report`, from a child that ran `setup`.
fn exec_case(name: &str, path: &str, setup: impl FnOnce()) {
    as_child(|| {
        setup();
        let p = c(path);
        let label = c(name);
        let argv = [p.as_ptr(), c"report".as_ptr(), label.as_ptr(), std::ptr::null()];
        let r = unsafe { libc::execv(p.as_ptr(), argv.as_ptr()) };
        line(&format!("exec {name}"), ok(r as i64));
    });
}

fn copy_self(to: &str) -> bool {
    let Ok(bytes) = std::fs::read("/proc/self/exe") else { return false };
    let _ = std::fs::remove_file(to);
    std::fs::write(to, bytes).is_ok() && unsafe { libc::chmod(c(to).as_ptr(), 0o755) } == 0
}

/// A `security.capability` value: v2 when `rootid` is `None`, v3 otherwise.
fn vfs_cap(eff: bool, p: u32, i: u32, rootid: Option<u32>) -> Vec<u8> {
    let rev: u32 = if rootid.is_some() { 0x0300_0000 } else { 0x0200_0000 };
    let mut v = Vec::new();
    v.extend_from_slice(&(rev | eff as u32).to_le_bytes());
    v.extend_from_slice(&p.to_le_bytes());
    v.extend_from_slice(&i.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    if let Some(r) = rootid {
        v.extend_from_slice(&r.to_le_bytes());
    }
    v
}

fn setcap(path: &str, value: &[u8]) -> String {
    ok(unsafe {
        libc::setxattr(c(path).as_ptr(), c"security.capability".as_ptr(), value.as_ptr().cast(), value.len(), 0)
    } as i64)
}

fn getcap(path: &str) -> String {
    let mut buf = [0u8; 64];
    let n = unsafe {
        libc::getxattr(c(path).as_ptr(), c"security.capability".as_ptr(), buf.as_mut_ptr().cast(), buf.len())
    };
    if n < 0 {
        return named(errno());
    }
    let hex: Vec<String> = buf[..n as usize]
        .chunks(4)
        .map(|w| format!("{:08x}", u32::from_le_bytes(w.try_into().unwrap_or([0; 4]))))
        .collect();
    format!("{n} bytes {}", hex.join(" "))
}

fn amb_raise(cap: u32) -> String {
    prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as u64, cap as u64, 0, 0)
}

fn set_inheritable(i: u64) -> String {
    let mut s = me();
    s.i = i;
    capset(s)
}

// ------------------------------------------------------------------ cases

fn initial() {
    line("cap_last_cap", std::fs::read_to_string("/proc/sys/kernel/cap_last_cap").unwrap_or_default().trim());
    line("initial capget", sets(me()));
    line("initial status", status("self"));
    line("initial keepcaps", prctl(libc::PR_GET_KEEPCAPS, 0, 0, 0, 0));
    line("initial securebits", prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0));
}

fn header_rules() {
    let probe = |v: u32, pid: i32, data: bool| {
        let mut h = Header { version: v, pid };
        let mut d = [Data { effective: 0x5a5a, permitted: 0x5a5a, inheritable: 0x5a5a }; 2];
        let ptr = if data { d.as_mut_ptr() } else { std::ptr::null_mut() };
        let r = ok(unsafe { libc::syscall(libc::SYS_capget, &raw mut h, ptr) });
        format!("{r} header {:#x} {} second e={:#x}", h.version, h.pid, d[1].effective)
    };
    line("capget bad version, data NULL", probe(0x1234, 0, false));
    line("capget bad version, data", probe(0x1234, 0, true));
    line("capget v1, data NULL", probe(V1, 0, false));
    line("capget v2, data NULL", probe(V2, 0, false));
    line("capget v3, data NULL", probe(V3, 0, false));
    line("capget v1", probe(V1, 0, true));
    line("capget v2", probe(V2, 0, true));
    line("capget v3 pid -1", probe(V3, -1, true));
    line("capget v3 pid -1, data NULL", probe(V3, -1, false));
    line("capget v3 missing pid", probe(V3, 999_999, true));
    line("capget v3 missing pid, data NULL", probe(V3, 999_999, false));
    line("capget v3 own pid", probe(V3, unsafe { libc::getpid() }, true));
    line("capget header NULL", ok(unsafe { libc::syscall(libc::SYS_capget, 0usize, 0usize) }));

    let set = |v: u32, pid: i32, d: Option<[Data; 2]>| {
        let mut h = Header { version: v, pid };
        let r = match d {
            Some(d) => unsafe { libc::syscall(libc::SYS_capset, &raw mut h, d.as_ptr()) },
            None => unsafe { libc::syscall(libc::SYS_capset, &raw mut h, 0usize) },
        };
        format!("{} header {:#x}", ok(r), h.version)
    };
    let full = me();
    let same = [
        Data { effective: full.e as u32, permitted: full.p as u32, inheritable: 0 },
        Data { effective: (full.e >> 32) as u32, permitted: (full.p >> 32) as u32, inheritable: 0 },
    ];
    line("capset bad version", set(0x1234, 0, Some(same)));
    line("capset data NULL", set(V3, 0, None));
    line("capset another pid", set(V3, unsafe { libc::getppid() }.max(1) + 100_000, Some(same)));
    line("capset own pid", set(V3, unsafe { libc::getpid() }, Some(same)));
    as_child(|| {
        line("capset v1 low word only", set(V1, 0, Some(same)));
        line("  after", sets(me()));
    });
    as_child(|| {
        let mut high = same;
        high[1].effective |= 0xffff_0000;
        high[1].permitted |= 0xffff_0000;
        line("capset bits past the last cap", set(V3, 0, Some(high)));
        line("  after", sets(me()));
    });
}

fn capset_rules() {
    let full = me();
    let x = bit(NET_BIND_SERVICE);
    as_child(|| {
        line("drop E only", capset(Sets { e: full.e & !x, ..full }));
        line("  after", sets(me()));
        line("raise E back (in P)", capset(full));
    });
    as_child(|| {
        line("E beyond P", capset(Sets { e: full.e, p: full.p & !x, i: 0 }));
        line("drop P", capset(Sets { e: full.e & !x, p: full.p & !x, i: 0 }));
        line("P back after drop", capset(full));
        line("  after", sets(me()));
        line("I outside P with SETPCAP", capset(Sets { e: full.e & !x, p: full.p & !x, i: x }));
        line("  after", sets(me()));
    });
    as_child(|| {
        capset(Sets { e: full.e & !x & !bit(SETPCAP), p: full.p & !x, i: 0 });
        line("I outside P without SETPCAP", capset(Sets { e: full.e & !x & !bit(SETPCAP), p: full.p & !x, i: x }));
        line("I inside P without SETPCAP", capset(Sets { e: 0, p: full.p & !x, i: bit(CHOWN) }));
    });
    as_child(|| {
        line("bset drop", prctl(libc::PR_CAPBSET_DROP, NET_BIND_SERVICE as u64, 0, 0, 0));
        line("  after", sets(me()));
        line("I outside bset, in P", capset(Sets { i: x, ..full }));
    });
    as_child(|| {
        set_inheritable(x);
        line("ambient raise", amb_raise(NET_BIND_SERVICE));
        line("  status", status("self"));
        line("capset drops I, ambient follows", capset(Sets { i: 0, ..full }));
        line("  status", status("self"));
    });
    as_child(|| {
        set_inheritable(x);
        amb_raise(NET_BIND_SERVICE);
        line("capset drops P, ambient follows", capset(Sets { e: full.e & !x, p: full.p & !x, i: x }));
        line("  status", status("self"));
    });
}

fn prctls() {
    for cap in [0u64, 40, 41, 63, 64, u64::MAX] {
        line(&format!("CAPBSET_READ {cap:#x}"), prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0));
    }
    line("CAPBSET_READ junk in arg3", prctl(libc::PR_CAPBSET_READ, 1, 1, 0, 0));
    as_child(|| {
        line("CAPBSET_DROP 41", prctl(libc::PR_CAPBSET_DROP, 41, 0, 0, 0));
        without(&[SETPCAP]);
        line("CAPBSET_DROP without SETPCAP", prctl(libc::PR_CAPBSET_DROP, 1, 0, 0, 0));
        line("CAPBSET_DROP 41 without SETPCAP", prctl(libc::PR_CAPBSET_DROP, 41, 0, 0, 0));
    });
    as_child(|| {
        line("CAPBSET_DROP CHOWN", prctl(libc::PR_CAPBSET_DROP, CHOWN as u64, 0, 0, 0));
        line("  read back", prctl(libc::PR_CAPBSET_READ, CHOWN as u64, 0, 0, 0));
        line("  sets", sets(me()));
        line("  status", status("self"));
    });

    let amb = |op: u64, a3: u64, a4: u64, a5: u64| prctl(libc::PR_CAP_AMBIENT, op, a3, a4, a5);
    use libc::{PR_CAP_AMBIENT_CLEAR_ALL as CLEAR, PR_CAP_AMBIENT_IS_SET as IS_SET, PR_CAP_AMBIENT_LOWER as LOWER, PR_CAP_AMBIENT_RAISE as RAISE};
    let (is_set, raise, lower, clear) = (IS_SET as u64, RAISE as u64, LOWER as u64, CLEAR as u64);
    as_child(|| {
        line("AMBIENT IS_SET", amb(is_set, 10, 0, 0));
        line("AMBIENT IS_SET 41", amb(is_set, 41, 0, 0));
        line("AMBIENT IS_SET arg4", amb(is_set, 10, 1, 0));
        line("AMBIENT RAISE without I", amb(raise, 10, 0, 0));
        line("AMBIENT LOWER unset", amb(lower, 10, 0, 0));
        line("AMBIENT op 0", amb(0, 10, 0, 0));
        line("AMBIENT op 5", amb(5, 10, 0, 0));
        line("AMBIENT CLEAR_ALL arg3", amb(clear, 1, 0, 0));
        line("AMBIENT CLEAR_ALL", amb(clear, 0, 0, 0));
        set_inheritable(bit(10) | bit(12));
        line("AMBIENT RAISE", amb(raise, 10, 0, 0));
        line("AMBIENT RAISE 12", amb(raise, 12, 0, 0));
        line("AMBIENT IS_SET after", amb(is_set, 10, 0, 0));
        line("AMBIENT LOWER", amb(lower, 10, 0, 0));
        line("AMBIENT IS_SET after LOWER", amb(is_set, 10, 0, 0));
        line("AMBIENT CLEAR_ALL", amb(clear, 0, 0, 0));
        line("AMBIENT IS_SET 12 after CLEAR_ALL", amb(is_set, 12, 0, 0));
        line("AMBIENT RAISE, bset dropped", {
            prctl(libc::PR_CAPBSET_DROP, 10, 0, 0, 0);
            amb(raise, 10, 0, 0)
        });
        let s = me();
        capset(Sets { e: s.e & !bit(12), p: s.p & !bit(12), i: s.i });
        line("AMBIENT RAISE, not in P", amb(raise, 12, 0, 0));
    });
    as_child(|| {
        set_inheritable(bit(10));
        let bits = libc::SECBIT_NO_CAP_AMBIENT_RAISE as u64;
        line("SECUREBITS NO_CAP_AMBIENT_RAISE", prctl(libc::PR_SET_SECUREBITS, bits, 0, 0, 0));
        line("AMBIENT RAISE under it", amb(raise, 10, 0, 0));
    });

    as_child(|| {
        line("GET_KEEPCAPS", prctl(libc::PR_GET_KEEPCAPS, 0, 0, 0, 0));
        line("SET_KEEPCAPS 2", prctl(libc::PR_SET_KEEPCAPS, 2, 0, 0, 0));
        line("SET_KEEPCAPS 1 arg3 junk", prctl(libc::PR_SET_KEEPCAPS, 1, 7, 0, 0));
        line("GET_KEEPCAPS after", prctl(libc::PR_GET_KEEPCAPS, 0, 0, 0, 0));
        line("GET_SECUREBITS after", prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0));
        line("SET_KEEPCAPS 0", prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0));
        line("SET_SECUREBITS KEEP_CAPS|LOCKED", prctl(libc::PR_SET_SECUREBITS, 0x30, 0, 0, 0));
        line("GET_KEEPCAPS after", prctl(libc::PR_GET_KEEPCAPS, 0, 0, 0, 0));
        line("SET_KEEPCAPS 0 when locked", prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0));
        line("SET_KEEPCAPS 1 when locked", prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0));
    });
    as_child(|| {
        line("SET_SECUREBITS NOROOT", prctl(libc::PR_SET_SECUREBITS, 0x1, 0, 0, 0));
        line("SET_SECUREBITS NOROOT|LOCKED", prctl(libc::PR_SET_SECUREBITS, 0x3, 0, 0, 0));
        line("SET_SECUREBITS clear locked", prctl(libc::PR_SET_SECUREBITS, 0x2, 0, 0, 0));
        line("SET_SECUREBITS unlock", prctl(libc::PR_SET_SECUREBITS, 0x1, 0, 0, 0));
        line("SET_SECUREBITS unknown bit", prctl(libc::PR_SET_SECUREBITS, 0x3 | 0x1000, 0, 0, 0));
        line("SET_SECUREBITS same", prctl(libc::PR_SET_SECUREBITS, 0x3, 0, 0, 0));
        line("GET_SECUREBITS", prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0));
    });
    as_child(|| {
        without(&[SETPCAP]);
        line("SECUREBITS no SETPCAP: NO_CAP_AMBIENT_RAISE", prctl(libc::PR_SET_SECUREBITS, 0x40, 0, 0, 0));
        line("SECUREBITS no SETPCAP: EXEC_RESTRICT_FILE", prctl(libc::PR_SET_SECUREBITS, 0x100, 0, 0, 0));
        line("SECUREBITS no SETPCAP: same", prctl(libc::PR_SET_SECUREBITS, 0x100, 0, 0, 0));
        line("SECUREBITS no SETPCAP: KEEP_CAPS", prctl(libc::PR_SET_SECUREBITS, 0x110, 0, 0, 0));
        line("GET_SECUREBITS", prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0));
    });
}

fn setuid_fixups() {
    let full = me();
    as_child(|| {
        set_inheritable(bit(10));
        amb_raise(10);
        line("setresuid 1000 x3", setresuid(1000, 1000, 1000));
        line("  status", status("self"));
    });
    as_child(|| {
        set_inheritable(bit(10));
        amb_raise(10);
        prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        line("KEEPCAPS, setresuid 1000 x3", setresuid(1000, 1000, 1000));
        line("  status", status("self"));
        line("  raise E from P", capset(Sets { e: me().p, ..me() }));
        line("  status", status("self"));
    });
    as_child(|| {
        set_inheritable(bit(10));
        amb_raise(10);
        line("seteuid 1000 (saved 0)", setresuid(u32::MAX, 1000, u32::MAX));
        line("  status", status("self"));
        line("seteuid 0", setresuid(u32::MAX, 0, u32::MAX));
        line("  status", status("self"));
    });
    as_child(|| {
        capset(Sets { e: full.e & !bit(CHOWN), ..full });
        setresuid(u32::MAX, 1000, u32::MAX);
        line("partial E, seteuid 1000 then 0", setresuid(u32::MAX, 0, u32::MAX));
        line("  sets", sets(me()));
    });
    as_child(|| {
        line("setfsuid 1000", unsafe { libc::setfsuid(1000) });
        line("  sets", sets(me()));
        line("setfsuid 0", unsafe { libc::setfsuid(0) });
        line("  sets", sets(me()));
        capset(Sets { e: full.e, p: full.p & !bit(DAC_OVERRIDE), i: 0 });
        unsafe { libc::setfsuid(1000) };
        unsafe { libc::setfsuid(0) };
        line("  after dropping DAC_OVERRIDE from P, 1000 and back", sets(me()));
    });
    as_child(|| {
        line("SECUREBITS NO_SETUID_FIXUP", prctl(libc::PR_SET_SECUREBITS, 0x4, 0, 0, 0));
        line("setresuid 1000 x3 under it", setresuid(1000, 1000, 1000));
        line("  status", status("self"));
        line("  setresuid 0 x3 back", setresuid(0, 0, 0));
        line("  ids", ids());
    });
    as_child(|| {
        prctl(libc::PR_SET_SECUREBITS, 0x4, 0, 0, 0);
        line("NO_SETUID_FIXUP, setfsuid 1000", unsafe { libc::setfsuid(1000) });
        line("  sets", sets(me()));
    });
    as_child(|| {
        setresuid(1000, 1000, 1000);
        line("uid 1000: setuid 0", setresuid(0, 0, 0));
        line("uid 1000: capset raise", capset(full));
        line("uid 1000: CAPBSET_DROP", prctl(libc::PR_CAPBSET_DROP, 1, 0, 0, 0));
        line("uid 1000: status", status("self"));
    });
    as_child(|| {
        without(&[SETUID]);
        line("root without SETUID: setresuid 1000 x3", setresuid(1000, 1000, 1000));
        line("root without SETUID: setfsuid 1000", unsafe { libc::setfsuid(1000) });
        line("  fs now", unsafe { libc::setfsuid(u32::MAX) });
        line("root without SETUID: setresgid 1000 x3", setresgid(1000, 1000, 1000));
    });
    as_child(|| {
        without(&[SETGID]);
        line("root without SETGID: setresgid 1000 x3", setresgid(1000, 1000, 1000));
        line("root without SETGID: setgroups", ok(unsafe { libc::setgroups(0, std::ptr::null()) } as i64));
        line("root without SETGID: setresuid 1000 x3", setresuid(1000, 1000, 1000));
    });
    as_child(|| {
        setresuid(1000, 1000, 1000);
        let child = target(|| {});
        line("uid 1000 reads a child's status", status(&child.to_string()));
        reap(child);
    });
}

fn exec_cases() {
    let rep = format!("{DIR}/rep");
    if !copy_self(&rep) {
        line("copy self", "failed");
        return;
    }
    let full = me();
    exec_case("root", &rep, || {});
    exec_case("root, bset without CHOWN", &rep, || {
        prctl(libc::PR_CAPBSET_DROP, CHOWN as u64, 0, 0, 0);
    });
    exec_case("root, I has CHOWN, bset without it", &rep, || {
        set_inheritable(bit(CHOWN));
        prctl(libc::PR_CAPBSET_DROP, CHOWN as u64, 0, 0, 0);
    });
    exec_case("root, E partial", &rep, || {
        without(&[CHOWN]);
    });
    exec_case("root, NOROOT", &rep, || {
        prctl(libc::PR_SET_SECUREBITS, 0x1, 0, 0, 0);
    });
    exec_case("root, KEEPCAPS", &rep, || {
        prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
    });
    exec_case("real root, euid 1000", &rep, || {
        setresuid(0, 1000, 0);
    });
    exec_case("euid 0, real 1000", &rep, || {
        setresuid(1000, 0, 0);
    });
    exec_case("uid 1000", &rep, || {
        setresuid(1000, 1000, 1000);
    });
    exec_case("uid 1000, kept P", &rep, || {
        prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
    });
    exec_case("uid 1000, ambient NET_BIND_SERVICE", &rep, || {
        set_inheritable(bit(NET_BIND_SERVICE));
        prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
        line("  ambient raise as 1000", amb_raise(NET_BIND_SERVICE));
    });
    let sgid = format!("{DIR}/sgid0");
    copy_self(&sgid);
    unsafe {
        libc::chown(c(&sgid).as_ptr(), 0, 0);
        libc::chmod(c(&sgid).as_ptr(), 0o2755);
    }
    exec_case("uid 1000 groups [0], setgid-0, ambient set", &sgid, || {
        set_inheritable(bit(CHOWN));
        let g = [0u32];
        unsafe { libc::setgroups(1, g.as_ptr()) };
        setresgid(1000, 1000, 1000);
        prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
        amb_raise(CHOWN);
    });
    exec_case("uid 1000 no groups, setgid-0, ambient set", &sgid, || {
        set_inheritable(bit(CHOWN));
        unsafe { libc::setgroups(0, std::ptr::null()) };
        setresgid(1000, 1000, 1000);
        prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
        amb_raise(CHOWN);
    });
    exec_case("uid 1000, I has NET_BIND_SERVICE, no file caps", &rep, || {
        set_inheritable(bit(NET_BIND_SERVICE));
        prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
    });

    // File capabilities.
    let fcap = format!("{DIR}/fcap");
    copy_self(&fcap);
    as_child(|| {
        without(&[SETFCAP]);
        line("setxattr security.capability without SETFCAP", setcap(&fcap, &vfs_cap(true, 1 << 10, 0, None)));
        line("setxattr bad size without SETFCAP", setcap(&fcap, &[1, 0, 0, 2, 0, 0, 0]));
    });
    line("setxattr bad size", setcap(&fcap, &[1, 0, 0, 2, 0, 0, 0]));
    line("setxattr v1 (12 bytes)", setcap(&fcap, &[0, 0, 0, 1, 0, 4, 0, 0, 0, 0, 0, 0]));
    line("setxattr bad revision", {
        let mut v = vfs_cap(true, 1 << 10, 0, None);
        v[3] = 7;
        setcap(&fcap, &v)
    });
    line("setxattr v3 rootid 0", setcap(&fcap, &vfs_cap(true, 1 << 10, 0, Some(0))));
    line("  getxattr", getcap(&fcap));
    line("  getxattr size 0", ok(unsafe {
        libc::getxattr(c(&fcap).as_ptr(), c"security.capability".as_ptr(), std::ptr::null_mut(), 0)
    } as i64));
    exec_case("uid 1000, v3 rootid 0 fP=NET_BIND_SERVICE fE", &fcap, || {
        setresuid(1000, 1000, 1000);
    });
    line("setxattr v3 rootid 1000", setcap(&fcap, &vfs_cap(true, 1 << 10, 0, Some(1000))));
    line("  getxattr", getcap(&fcap));
    exec_case("uid 1000, v3 rootid 1000", &fcap, || {
        setresuid(1000, 1000, 1000);
    });
    line("setxattr v2 fP=NET_BIND_SERVICE fE", setcap(&fcap, &vfs_cap(true, 1 << 10, 0, None)));
    line("  getxattr", getcap(&fcap));
    exec_case("uid 1000, v2 fE", &fcap, || {
        setresuid(1000, 1000, 1000);
    });
    exec_case("uid 1000, v2 fE, ambient set", &fcap, || {
        set_inheritable(bit(CHOWN));
        prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
        amb_raise(CHOWN);
    });
    exec_case("uid 1000, v2 fE, bset without it", &fcap, || {
        prctl(libc::PR_CAPBSET_DROP, NET_BIND_SERVICE as u64, 0, 0, 0);
        setresuid(1000, 1000, 1000);
    });
    exec_case("uid 1000, v2 fE, no_new_privs", &fcap, || {
        prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
    });
    exec_case("root, v2 fE", &fcap, || {});
    exec_case("root NOROOT, v2 fE", &fcap, || {
        prctl(libc::PR_SET_SECUREBITS, 0x1, 0, 0, 0);
    });
    line("setxattr v2 fP=NET_BIND_SERVICE, no fE", setcap(&fcap, &vfs_cap(false, 1 << 10, 0, None)));
    exec_case("uid 1000, v2 no fE", &fcap, || {
        setresuid(1000, 1000, 1000);
    });
    exec_case("uid 1000, v2 no fE, bset without it", &fcap, || {
        prctl(libc::PR_CAPBSET_DROP, NET_BIND_SERVICE as u64, 0, 0, 0);
        setresuid(1000, 1000, 1000);
    });
    line("setxattr v2 fI=NET_RAW|CHOWN", setcap(&fcap, &vfs_cap(false, 0, bit(NET_RAW) as u32 | 1, None)));
    exec_case("uid 1000, I=NET_RAW, v2 fI", &fcap, || {
        set_inheritable(bit(NET_RAW));
        prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
    });
    line("setxattr v2 fP=0, no fE", setcap(&fcap, &vfs_cap(false, 0, 0, None)));
    exec_case("uid 1000, v2 empty, ambient set", &fcap, || {
        set_inheritable(bit(CHOWN));
        prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
        amb_raise(CHOWN);
    });
    as_child(|| {
        without(&[SETFCAP]);
        line("removexattr without SETFCAP", ok(unsafe { libc::removexattr(c(&fcap).as_ptr(), c"security.capability".as_ptr()) } as i64));
    });
    line("setxattr empty value", setcap(&fcap, &[]));
    line("  getxattr", getcap(&fcap));
    as_child(|| {
        without(&[SETFCAP]);
        line("setxattr empty value without SETFCAP", setcap(&fcap, &[]));
    });
    line("setxattr v2 again", setcap(&fcap, &vfs_cap(false, 0, 0, None)));
    line("removexattr", ok(unsafe { libc::removexattr(c(&fcap).as_ptr(), c"security.capability".as_ptr()) } as i64));
    line("  getxattr", getcap(&fcap));

    // Set-user-ID root.
    let suid = format!("{DIR}/suid");
    copy_self(&suid);
    unsafe {
        libc::chown(c(&suid).as_ptr(), 0, 0);
        libc::chmod(c(&suid).as_ptr(), 0o4755);
    }
    exec_case("uid 1000, setuid-root", &suid, || {
        setresuid(1000, 1000, 1000);
    });
    exec_case("uid 1000, setuid-root, NOROOT", &suid, || {
        prctl(libc::PR_SET_SECUREBITS, 0x1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
    });
    exec_case("uid 1000, setuid-root, no_new_privs", &suid, || {
        prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
    });
    exec_case("uid 1000, setuid-root, bset without CHOWN", &suid, || {
        prctl(libc::PR_CAPBSET_DROP, CHOWN as u64, 0, 0, 0);
        setresuid(1000, 1000, 1000);
    });
    exec_case("uid 1000, setuid-root, ambient set", &suid, || {
        set_inheritable(bit(CHOWN));
        prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
        setresuid(1000, 1000, 1000);
        amb_raise(CHOWN);
    });
    setcap(&suid, &vfs_cap(true, 1 << 10, 0, None));
    let kill = format!("{DIR}/killpriv");
    copy_self(&kill);
    setcap(&kill, &vfs_cap(true, 1 << 10, 0, None));
    unsafe { libc::chown(c(&kill).as_ptr(), 1000, u32::MAX) };
    line("file caps after chown", getcap(&kill));
    setcap(&kill, &vfs_cap(true, 1 << 10, 0, None));
    {
        let fd = unsafe { libc::open(c(&kill).as_ptr(), libc::O_WRONLY | libc::O_APPEND) };
        unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
        unsafe { libc::close(fd) };
    }
    line("file caps after a write", getcap(&kill));
    line("setuid-root with file caps: mode", format!("{:o}", sys_mode(&suid)));
    exec_case("uid 1000, setuid-root with file caps", &suid, || {
        setresuid(1000, 1000, 1000);
    });
    let _ = full;
}

fn sys_mode(path: &str) -> u32 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(c(path).as_ptr(), &mut st) };
    st.st_mode
}

fn gated_ops() {
    let file = format!("{DIR}/file");
    let theirs = format!("{DIR}/theirs");
    let dir = format!("{DIR}/dir");
    std::fs::write(&file, b"x").ok();
    std::fs::write(&theirs, b"x").ok();
    unsafe {
        libc::chmod(c(&theirs).as_ptr(), 0o600);
        libc::chown(c(&theirs).as_ptr(), 1000, 1000);
        libc::mkdir(c(&dir).as_ptr(), 0o700);
        libc::chown(c(&dir).as_ptr(), 1000, 1000);
    }
    std::fs::write(format!("{dir}/inside"), b"x").ok();

    gated("chown to 1000", CHOWN, || ok(unsafe { libc::chown(c(&file).as_ptr(), 1000, u32::MAX) } as i64));
    gated("chgrp to 1000", CHOWN, || ok(unsafe { libc::chown(c(&file).as_ptr(), u32::MAX, 1000) } as i64));
    let open = |path: &str, flags: i32| {
        let fd = unsafe { libc::open(c(path).as_ptr(), flags) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        ok(fd.min(0) as i64)
    };
    gated("open another's 0600 O_RDONLY", DAC_OVERRIDE, || open(&theirs, libc::O_RDONLY));
    gated("open another's 0600 O_WRONLY", DAC_OVERRIDE, || open(&theirs, libc::O_WRONLY));
    as_child(|| {
        without(&[DAC_OVERRIDE, DAC_READ_SEARCH]);
        line("open another's 0600 O_RDONLY: neither DAC", open(&theirs, libc::O_RDONLY));
        line("open in another's 0700 dir: neither DAC", open(&format!("{dir}/inside"), libc::O_RDONLY));
    });
    as_child(|| {
        without(&[DAC_OVERRIDE]);
        line("open in another's 0700 dir: READ_SEARCH only", open(&format!("{dir}/inside"), libc::O_RDONLY));
        line("list another's 0700 dir: READ_SEARCH only", open(&dir, libc::O_RDONLY | libc::O_DIRECTORY));
        line("create in another's 0700 dir: READ_SEARCH only", {
            let fd = unsafe { libc::open(c(&format!("{dir}/new")).as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o600) };
            if fd >= 0 {
                unsafe { libc::close(fd) };
                unsafe { libc::unlink(c(&format!("{dir}/new")).as_ptr()) };
            }
            ok(fd.min(0) as i64)
        });
        line("access(R_OK) another's 0600: READ_SEARCH only", ok(unsafe { libc::access(c(&theirs).as_ptr(), libc::R_OK) } as i64));
    });
    as_child(|| {
        without(&[DAC_READ_SEARCH]);
        line("open another's 0600 O_RDONLY: OVERRIDE only", open(&theirs, libc::O_RDONLY));
    });
    gated("chmod another's file", FOWNER, || ok(unsafe { libc::chmod(c(&theirs).as_ptr(), 0o600) } as i64));
    gated("utimensat explicit on another's file", FOWNER, || {
        let ts = [libc::timespec { tv_sec: 1, tv_nsec: 0 }; 2];
        ok(unsafe { libc::utimensat(libc::AT_FDCWD, c(&theirs).as_ptr(), ts.as_ptr(), 0) } as i64)
    });
    gated("chmod g+s, file group not ours", FSETID, || {
        let f = format!("{DIR}/sgid");
        std::fs::write(&f, b"x").ok();
        unsafe { libc::chown(c(&f).as_ptr(), u32::MAX, 1000) };
        let r = ok(unsafe { libc::chmod(c(&f).as_ptr(), 0o2755) } as i64);
        let mode = sys_mode(&f) & 0o7777;
        unsafe { libc::unlink(c(&f).as_ptr()) };
        format!("{r} mode {mode:o}")
    });
    gated("kill another uid", KILL, || {
        let t = target(|| {
            setresuid(2000, 2000, 2000);
        });
        let r = ok(unsafe { libc::kill(t, 0) } as i64);
        capset(Sets { e: me().p, ..me() });
        reap(t);
        r
    });
    // Docker starts unprivileged ports at 0; a netns of its own can say 1024
    // again. The emulator has no such file and asks for the capability below
    // 1024, which is Linux's default.
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_unprivileged_port_start", "1024");
    gated("bind 0.0.0.0:81", NET_BIND_SERVICE, || {
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let one = 1i32;
        unsafe { libc::setsockopt(s, libc::SOL_SOCKET, libc::SO_REUSEADDR, (&raw const one).cast(), 4) };
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 81u16.to_be(),
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        let r = ok(unsafe { libc::bind(s, (&raw const addr).cast(), 16) } as i64);
        unsafe { libc::close(s) };
        r
    });
    gated("SO_RCVBUFFORCE", NET_ADMIN, || {
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        let v = 65536i32;
        let r = ok(unsafe { libc::setsockopt(s, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, (&raw const v).cast(), 4) } as i64);
        unsafe { libc::close(s) };
        r
    });
    gated("socket AF_INET SOCK_RAW", NET_RAW, || {
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
        if s >= 0 {
            unsafe { libc::close(s) };
        }
        ok(s.min(0) as i64)
    });
    gated("chroot /", SYS_CHROOT, || ok(unsafe { libc::chroot(c"/".as_ptr()) } as i64));
    gated("mknod char 1:3", MKNOD, || {
        let p = format!("{DIR}/null");
        let r = ok(unsafe { libc::mknod(c(&p).as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(1, 3)) } as i64);
        unsafe { libc::unlink(c(&p).as_ptr()) };
        r
    });
    gated("mknod fifo", MKNOD, || {
        let p = format!("{DIR}/fifo");
        let r = ok(unsafe { libc::mknod(c(&p).as_ptr(), libc::S_IFIFO | 0o600, 0) } as i64);
        unsafe { libc::unlink(c(&p).as_ptr()) };
        r
    });
    gated("setpriority -5", SYS_NICE, || ok(unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, -5) } as i64));
    gated("settimeofday NULL NULL", SYS_TIME, || {
        ok(unsafe { libc::syscall(libc::SYS_settimeofday, 0usize, 0usize) })
    });
    gated("setrlimit NOFILE above hard", SYS_RESOURCE, || {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
        let lower = libc::rlimit { rlim_cur: 64, rlim_max: 128 };
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lower) };
        let higher = libc::rlimit { rlim_cur: 64, rlim_max: 256 };
        ok(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &higher) } as i64)
    });
    gated("sethostname (same name)", SYS_ADMIN, || {
        let mut buf = [0u8; 65];
        unsafe { libc::gethostname(buf.as_mut_ptr().cast(), 64) };
        let n = buf.iter().position(|b| *b == 0).unwrap_or(0);
        ok(unsafe { libc::sethostname(buf.as_ptr().cast(), n) } as i64)
    });
    gated("setxattr trusted.x", SYS_ADMIN, || {
        ok(unsafe { libc::setxattr(c(&file).as_ptr(), c"trusted.x".as_ptr(), b"1".as_ptr().cast(), 1, 0) } as i64)
    });
    gated("reboot bad magic", SYS_BOOT, || ok(unsafe { libc::syscall(libc::SYS_reboot, 1usize, 2usize, 0usize, 0usize) }));
    gated("vhangup", SYS_TTY_CONFIG, || ok(unsafe { libc::syscall(libc::SYS_vhangup) }));
    as_child(|| line("syslog SIZE_UNREAD: with", ok(unsafe { libc::syscall(libc::SYS_syslog, 9, 0usize, 0) }.min(0))));
    as_child(|| {
        without(&[SYSLOG]);
        line("syslog SIZE_UNREAD: SYS_ADMIN only", ok(unsafe { libc::syscall(libc::SYS_syslog, 9, 0usize, 0) }.min(0)));
        without(&[SYS_ADMIN]);
        line("syslog SIZE_UNREAD: neither", ok(unsafe { libc::syscall(libc::SYS_syslog, 9, 0usize, 0) }.min(0)));
    });
    gated("mlock with RLIMIT_MEMLOCK 0", IPC_LOCK, || {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) };
        let page = [0u8; 4096];
        ok(unsafe { libc::mlock(page.as_ptr().cast(), 1) } as i64)
    });
    let shm = {
        let mut p = [0i32; 2];
        unsafe { libc::pipe(p.as_mut_ptr()) };
        as_child(|| unsafe {
            setresuid(1000, 1000, 1000);
            let id = libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600);
            libc::write(p[1], (&raw const id).cast(), 4);
        });
        let mut id = -1i32;
        unsafe {
            libc::read(p[0], (&raw mut id).cast(), 4);
            libc::close(p[0]);
            libc::close(p[1]);
        }
        id
    };
    gated("shmat another's 0600 segment", IPC_OWNER, || {
        let a = unsafe { libc::shmat(shm, std::ptr::null(), libc::SHM_RDONLY) };
        if a as isize == -1 {
            named(errno())
        } else {
            unsafe { libc::shmdt(a) };
            "ok".into()
        }
    });
    unsafe { libc::shmctl(shm, libc::IPC_RMID, std::ptr::null_mut()) };
    gated("/proc/<pid>/mem of another uid", SYS_PTRACE, || {
        let t = target(|| {
            setresuid(2000, 2000, 2000);
        });
        let r = match std::fs::File::open(format!("/proc/{t}/mem")) {
            Ok(_) => "ok".to_string(),
            Err(e) => named(e.raw_os_error().unwrap_or(0)),
        };
        capset(Sets { e: me().p, ..me() });
        reap(t);
        r
    });
    gated("setgroups", SETGID, || ok(unsafe { libc::setgroups(0, std::ptr::null()) } as i64));
    let roots = format!("{DIR}/roots");
    let open_rw = format!("{DIR}/open");
    let mine = format!("{DIR}/mine1000");
    for f in [&roots, &open_rw, &mine] {
        std::fs::write(f, b"x").ok();
    }
    unsafe {
        libc::chmod(c(&roots).as_ptr(), 0o644);
        libc::chmod(c(&open_rw).as_ptr(), 0o666);
        libc::chown(c(&mine).as_ptr(), 1000, 0);
    }
    let owner = {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        unsafe { libc::stat(c(&roots).as_ptr(), &mut st) };
        st.st_uid
    };
    as_child(|| {
        setresgid(1000, 1000, 1000);
        setresuid(1000, 1000, 1000);
        line("uid 1000: chown another's file to its owner", ok(unsafe { libc::chown(c(&roots).as_ptr(), owner, u32::MAX) } as i64));
        line("uid 1000: utimensat NULL on another's 0644", ok(unsafe { libc::utimensat(libc::AT_FDCWD, c(&roots).as_ptr(), std::ptr::null(), 0) } as i64));
        line("uid 1000: utimensat NULL on another's 0666", ok(unsafe { libc::utimensat(libc::AT_FDCWD, c(&open_rw).as_ptr(), std::ptr::null(), 0) } as i64));
        let ts = [libc::timespec { tv_sec: 1, tv_nsec: 0 }; 2];
        line("uid 1000: utimensat explicit on another's 0666", ok(unsafe { libc::utimensat(libc::AT_FDCWD, c(&open_rw).as_ptr(), ts.as_ptr(), 0) } as i64));
        let now = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_NOW }; 2];
        line("uid 1000: utimensat NOW/NOW on another's 0666", ok(unsafe { libc::utimensat(libc::AT_FDCWD, c(&open_rw).as_ptr(), now.as_ptr(), 0) } as i64));
        let half = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_NOW }, libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }];
        line("uid 1000: utimensat NOW/OMIT on another's 0666", ok(unsafe { libc::utimensat(libc::AT_FDCWD, c(&open_rw).as_ptr(), half.as_ptr(), 0) } as i64));
        line("uid 1000: chmod g+s own file of group 0", {
            let r = ok(unsafe { libc::chmod(c(&mine).as_ptr(), 0o2755) } as i64);
            format!("{r} mode {:o}", sys_mode(&mine) & 0o7777)
        });
    });
    gated("CAPBSET_DROP 40", SETPCAP, || prctl(libc::PR_CAPBSET_DROP, 40, 0, 0, 0));
    gated("open a TIOCEXCL pty slave again", SYS_ADMIN, || unsafe {
        let m = libc::open(c"/dev/ptmx".as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        let mut n = 0u32;
        let mut unlock = 0i32;
        libc::ioctl(m, 0x8004_5430u32 as i32, &mut n);
        libc::ioctl(m, 0x4004_5431, &mut unlock);
        let p = c(&format!("/dev/pts/{n}"));
        let s = libc::open(p.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        libc::ioctl(s, 0x540c, 0);
        let again = libc::open(p.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        let r = ok(again.min(0) as i64);
        for fd in [again, s, m] {
            if fd >= 0 {
                libc::close(fd);
            }
        }
        r
    });
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("report") {
        report();
        return;
    }
    unsafe { libc::setgroups(0, std::ptr::null()) };
    let _ = std::fs::remove_dir_all(DIR);
    std::fs::create_dir_all(DIR).ok();
    unsafe { libc::chmod(c(DIR).as_ptr(), 0o755) };

    initial();
    header_rules();
    capset_rules();
    prctls();
    setuid_fixups();
    exec_cases();
    gated_ops();

    let _ = std::fs::remove_dir_all(DIR);
}
