//! Capability sets, asserted: the rows of `caps_probe` a real arm64 kernel
//! answered, run on realfs and fakefs.
//!
//! Until 2026-11-13 the sets were derived from the uids -- effective full for
//! an effective uid of 0, permitted full for any uid of 0 -- so a root process
//! that dropped a capability kept every one of them, `capset` stored nothing,
//! and no `execve` could gain one.
//!
//! What needs a file owned by root or by another user's group -- set-user-ID
//! root, `chmod g+s` -- is `caps_setid`, which runs on fakefs: realfs reports
//! the host's owner. Everything here is the same on any mount.

use guest_tests::caps::*;
use guest_tests::{Harness, check};

const DIR: &str = "/tmp/capsrules";

fn main() {
    if std::env::args().nth(1).as_deref() == Some("report") {
        report();
        return;
    }
    unsafe { libc::setgroups(0, std::ptr::null()) };
    let _ = std::fs::remove_dir_all(DIR);
    std::fs::create_dir_all(DIR).unwrap();
    unsafe { libc::chmod(c(DIR).as_ptr(), 0o755) };
    let mut h = Harness::new();
    let eperm = -(libc::EPERM as i64);
    let eacces = -(libc::EACCES as i64);
    let einval = -(libc::EINVAL as i64);

    h.group("a root login");
    let me = capget(0);
    check!(h, me == Sets { e: FULL, p: FULL, i: 0 }, "full permitted and effective, no inheritable: {me:?}");
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    check!(h, status.contains("CapBnd:\t000001ffffffffff") && status.contains("CapAmb:\t0000000000000000"), "{status}");

    h.group("capset");
    let rows = child(|| {
        let e_beyond_p = capset(Sets { e: FULL, p: FULL & !X, i: 0 });
        capset(Sets { e: FULL & !X, p: FULL & !X, i: 0 });
        let p_back = capset(Sets { e: FULL, p: FULL, i: 0 });
        let i_with_setpcap = capset(Sets { e: FULL & !X, p: FULL & !X, i: X });
        capset(Sets { e: FULL & !X & !bit(SETPCAP), p: FULL & !X, i: 0 });
        let i_without = capset(Sets { e: 0, p: FULL & !X, i: X });
        [e_beyond_p, p_back, i_with_setpcap, i_without, capget(0).p as i64]
    });
    check!(h, rows[0] == eperm, "E beyond P: {}", rows[0]);
    check!(h, rows[1] == eperm, "P back after a drop: {}", rows[1]);
    check!(h, rows[2] == 0, "I outside P with SETPCAP: {}", rows[2]);
    check!(h, rows[3] == eperm, "I outside P without it: {}", rows[3]);
    check!(h, rows[4] as u64 == FULL & !X, "the drop is kept: {:#x}", rows[4]);
    let rows = child(|| {
        prctl(libc::PR_CAPBSET_DROP, NET_BIND_SERVICE as u64, 0);
        [capset(Sets { i: X, ..capget(0) })]
    });
    check!(h, rows[0] == eperm, "I outside the bounding set: {}", rows[0]);
    let rows = child(|| {
        set_inheritable(X);
        let raised = prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as u64, NET_BIND_SERVICE as u64);
        let before = ambient();
        set_inheritable(0);
        [raised, before as i64, ambient() as i64]
    });
    check!(h, rows == [0, X as i64, 0], "dropping I takes the ambient bit with it: {rows:?}");

    h.group("prctl");
    let rows = child(|| {
        let bad = prctl(libc::PR_CAPBSET_DROP, 41, 0);
        let dropped = prctl(libc::PR_CAPBSET_DROP, CHOWN as u64, 0);
        let read = prctl(libc::PR_CAPBSET_READ, CHOWN as u64, 0);
        without(&[SETPCAP]);
        let unpriv = prctl(libc::PR_CAPBSET_DROP, 1, 0);
        let unpriv_bad = prctl(libc::PR_CAPBSET_DROP, 41, 0);
        let exec_bit = prctl(libc::PR_SET_SECUREBITS, 0x100, 0);
        let raise_bit = prctl(libc::PR_SET_SECUREBITS, 0x140, 0);
        [bad, dropped, read, unpriv, unpriv_bad, exec_bit, raise_bit, capget(0).p as i64]
    });
    check!(h, rows[0] == einval && rows[1] == 0 && rows[2] == 0, "drop and read: {rows:?}");
    check!(h, rows[3] == eperm && rows[4] == eperm, "SETPCAP before the number: {rows:?}");
    check!(h, rows[5] == 0 && rows[6] == eperm, "without SETPCAP only the exec bits: {rows:?}");
    check!(h, rows[7] as u64 == FULL, "the bounding set is not the permitted one: {:#x}", rows[7]);
    let rows = child(|| {
        let no_i = prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as u64, 10);
        set_inheritable(X);
        prctl(libc::PR_SET_SECUREBITS, 0x40, 0);
        let locked_out = prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as u64, 10);
        prctl(libc::PR_SET_SECUREBITS, 0x30, 0);
        let keep = prctl(libc::PR_GET_KEEPCAPS, 0, 0);
        let set_locked = prctl(libc::PR_SET_KEEPCAPS, 0, 0);
        [no_i, locked_out, keep, set_locked]
    });
    check!(h, rows == [eperm, eperm, 1, eperm], "ambient and keepcaps refusals: {rows:?}");

    h.group("uid changes");
    let rows = child(|| {
        set_inheritable(X);
        prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as u64, 10);
        setresuid(1000);
        let s = capget(0);
        [s.e as i64, s.p as i64, ambient() as i64]
    });
    check!(h, rows == [0, 0, 0], "every uid leaving 0 empties P, E and A: {rows:?}");
    let rows = child(|| {
        prctl(libc::PR_SET_KEEPCAPS, 1, 0);
        setresuid(1000);
        let s = capget(0);
        [s.e as i64, s.p as i64]
    });
    check!(h, rows == [0, FULL as i64], "KEEPCAPS keeps P and not E: {rows:?}");
    let rows = child(|| {
        set_inheritable(X);
        prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as u64, 10);
        capset(Sets { e: FULL & !1, ..capget(0) });
        unsafe { libc::syscall(libc::SYS_setresuid, -1i32, 1000, -1i32) };
        let away = capget(0);
        unsafe { libc::syscall(libc::SYS_setresuid, -1i32, 0, -1i32) };
        [away.e as i64, away.p as i64, ambient() as i64, capget(0).e as i64]
    });
    check!(h, rows == [0, FULL as i64, X as i64, FULL as i64], "seteuid away and back: {rows:?}");
    let rows = child(|| {
        unsafe { libc::setfsuid(1000) };
        let away = capget(0).e;
        unsafe { libc::setfsuid(0) };
        [away as i64, capget(0).e as i64]
    });
    check!(h, rows == [0x1fef7fffde0, FULL as i64], "setfsuid takes the fs set: {rows:x?}");
    let rows = child(|| {
        prctl(libc::PR_SET_SECUREBITS, 0x4, 0);
        setresuid(1000);
        [capget(0).e as i64, setresuid(0)]
    });
    check!(h, rows == [FULL as i64, 0], "NO_SETUID_FIXUP: {rows:?}");
    let rows = child(|| {
        without(&[SETUID]);
        [setresuid(1000), r(unsafe { libc::syscall(libc::SYS_setresgid, 1000, 1000, 1000) })]
    });
    check!(h, rows == [eperm, 0], "CAP_SETUID and not the effective uid: {rows:?}");

    h.group("exec");
    let rep = format!("{DIR}/rep");
    copy_self(&rep);
    let full = FULL as i64;
    let x = X as i64;
    check!(h, exec_as(&rep, || {}) == [full, full, 0, 0, 0, 0], "root");
    let got = exec_as(&rep, || {
        prctl(libc::PR_CAPBSET_DROP, CHOWN as u64, 0);
    });
    check!(h, got[1] == full & !1, "the bounding set bounds root's: {got:?}");
    let got = exec_as(&rep, || {
        prctl(libc::PR_SET_SECUREBITS, 1, 0);
    });
    check!(h, got[..2] == [0, 0], "NOROOT: {got:?}");
    let got = exec_as(&rep, || {
        unsafe { libc::syscall(libc::SYS_setresuid, 0, 1000, 0) };
    });
    check!(h, got[..2] == [0, full] && got[4] == 1, "a real root alone: {got:?}");
    let got = exec_as(&rep, || {
        set_inheritable(X);
        prctl(libc::PR_SET_KEEPCAPS, 1, 0);
        setresuid(1000);
        prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as u64, 10);
    });
    check!(h, got == [x, x, x, x, 0, 1000], "uid 1000 keeps its ambient set: {got:?}");
    let got = exec_as(&rep, || {
        prctl(libc::PR_SET_KEEPCAPS, 1, 0);
        setresuid(1000);
    });
    check!(h, got[..2] == [0, 0], "and nothing else: {got:?}");

    h.group("file capabilities");
    let fcap = format!("{DIR}/fcap");
    copy_self(&fcap);
    let r_no = child(|| {
        without(&[SETFCAP]);
        [setcap(&fcap, &vfs_cap(true, X as u32, None)), setcap(&fcap, &[1, 0, 0, 2])]
    });
    check!(h, r_no == [eperm, einval], "SETFCAP, after the header: {r_no:?}");
    check!(h, setcap(&fcap, &vfs_cap(true, X as u32, None)[..12]) == einval, "a v1 is not written");
    check!(h, setcap(&fcap, &vfs_cap(true, X as u32, Some(0))) == 0, "a v3 of root");
    check!(h, getcap_len(&fcap) == 20, "reads back as a v2: {}", getcap_len(&fcap));
    let got = exec_as(&fcap, || {
        setresuid(1000);
    });
    check!(h, got == [x, x, 0, 0, 1, 1000], "fP with fE, as uid 1000: {got:?}");
    let got = exec_as(&fcap, || {
        prctl(libc::PR_CAPBSET_DROP, NET_BIND_SERVICE as u64, 0);
        setresuid(1000);
    });
    check!(h, got[0] == eperm, "fE with fP outside the bounding set: {got:?}");
    let got = exec_as(&fcap, || {
        prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0);
        setresuid(1000);
    });
    check!(h, got[..2] == [0, 0], "no_new_privs: {got:?}");
    check!(h, setcap(&fcap, &vfs_cap(true, X as u32, Some(1000))) == 0, "a v3 of another root");
    let got = exec_as(&fcap, || {
        setresuid(1000);
    });
    check!(h, got[..2] == [0, 0] && got[4] == 0, "does not apply: {got:?}");
    check!(h, setcap(&fcap, &vfs_cap(false, X as u32, None)) == 0, "fP without fE");
    let got = exec_as(&fcap, || {
        set_inheritable(1);
        prctl(libc::PR_SET_KEEPCAPS, 1, 0);
        setresuid(1000);
        prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as u64, 0);
    });
    check!(h, got[..4] == [0, x, 1, 0], "permitted, not effective, ambient cleared: {got:?}");
    check!(h, unsafe { libc::chown(c(&fcap).as_ptr(), 1000, u32::MAX) } == 0, "chown");
    check!(h, getcap_len(&fcap) == -(libc::ENODATA as i64), "takes the file capabilities: {}", getcap_len(&fcap));

    h.group("one capability dropped");
    let theirs = format!("{DIR}/theirs");
    let dir = format!("{DIR}/dir");
    std::fs::write(&theirs, b"x").unwrap();
    unsafe {
        libc::chmod(c(&theirs).as_ptr(), 0o600);
        libc::chown(c(&theirs).as_ptr(), 1000, 1000);
        libc::mkdir(c(&dir).as_ptr(), 0o700);
        libc::chown(c(&dir).as_ptr(), 1000, 1000);
    }
    let open = |path: &str, flags: i32| {
        let fd = unsafe { libc::open(c(path).as_ptr(), flags, 0o600) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        r(fd as i64)
    };
    let rows = child(|| {
        without(&[DAC_OVERRIDE]);
        [
            open(&theirs, libc::O_RDONLY),
            open(&theirs, libc::O_WRONLY),
            open(&dir, libc::O_RDONLY | libc::O_DIRECTORY),
            open(&format!("{dir}/new"), libc::O_CREAT | libc::O_WRONLY),
        ]
    });
    check!(h, rows == [0, eacces, 0, eacces], "DAC_READ_SEARCH reads and searches: {rows:?}");
    let rows = child(|| {
        without(&[DAC_OVERRIDE, DAC_READ_SEARCH]);
        [open(&theirs, libc::O_RDONLY), r(unsafe { libc::access(c(&theirs).as_ptr(), libc::R_OK) } as i64)]
    });
    check!(h, rows == [eacces, 0], "neither; access(2) checks with the permitted set: {rows:?}");
    let file = format!("{DIR}/file");
    std::fs::write(&file, b"x").unwrap();
    // A container starts unprivileged ports at 0; its own netns can say 1024,
    // Linux's default and the only one here.
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_unprivileged_port_start", "1024");
    let cases: [(&str, u32, Box<dyn Fn() -> i64>, i64); 8] = [
        ("chown", CHOWN, Box::new(|| r(unsafe { libc::chown(c(&file).as_ptr(), 1000, u32::MAX) } as i64)), eperm),
        ("chroot", SYS_CHROOT, Box::new(|| r(unsafe { libc::chroot(c"/".as_ptr()) } as i64)), eperm),
        ("setpriority -5", SYS_NICE, Box::new(|| r(unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, -5) } as i64)), eacces),
        (
            "sethostname",
            SYS_ADMIN,
            Box::new(|| {
                let mut b = [0u8; 65];
                unsafe { libc::gethostname(b.as_mut_ptr().cast(), 64) };
                let n = b.iter().position(|&x| x == 0).unwrap_or(0);
                r(unsafe { libc::sethostname(b.as_ptr().cast(), n) } as i64)
            }),
            eperm,
        ),
        (
            "setxattr trusted.x",
            SYS_ADMIN,
            Box::new(|| r(unsafe { libc::setxattr(c(&file).as_ptr(), c"trusted.x".as_ptr(), b"1".as_ptr().cast(), 1, 0) } as i64)),
            eperm,
        ),
        (
            "bind 0.0.0.0:81",
            NET_BIND_SERVICE,
            Box::new(|| unsafe {
                let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                let a = libc::sockaddr_in { sin_family: libc::AF_INET as u16, sin_port: 81u16.to_be(), sin_addr: libc::in_addr { s_addr: 0 }, sin_zero: [0; 8] };
                let v = r(libc::bind(s, (&raw const a).cast(), 16) as i64);
                libc::close(s);
                v
            }),
            eacces,
        ),
        (
            "mlock under RLIMIT_MEMLOCK 0",
            IPC_LOCK,
            Box::new(|| unsafe {
                let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim);
                let page = [0u8; 64];
                r(libc::mlock(page.as_ptr().cast(), 1) as i64)
            }),
            eperm,
        ),
        ("setgroups", 6, Box::new(|| r(unsafe { libc::setgroups(0, std::ptr::null()) } as i64)), eperm),
    ];
    for (name, cap, f, refused) in &cases {
        let with = one(f);
        let without_it = one(|| {
            without(&[*cap]);
            f()
        });
        check!(h, with == 0 && without_it == *refused, "{name}: with {with}, without {without_it}");
    }
    // realfs makes no device node for anyone, so only the refusal is the
    // capability's there.
    let mknod = || {
        let p = c(&format!("{DIR}/null"));
        let v = r(unsafe { libc::mknod(p.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(1, 3)) } as i64);
        unsafe { libc::unlink(p.as_ptr()) };
        v
    };
    let rows = [one(mknod), one(|| {
        without(&[MKNOD]);
        mknod()
    })];
    if root_mount_is("real") {
        check!(h, rows[1] == eperm, "mknod a char device without MKNOD: {rows:?}");
    } else {
        check!(h, rows == [0, eperm], "mknod a char device: {rows:?}");
    }
    let other = |cap: u32, f: fn(i32) -> i64| {
        child(move || {
            let mut p = [0i32; 2];
            unsafe { libc::pipe(p.as_mut_ptr()) };
            let t = unsafe { libc::fork() };
            if t == 0 {
                setresuid(2000);
                unsafe {
                    libc::write(p[1], b"x".as_ptr().cast(), 1);
                    libc::pause();
                }
            }
            let mut b = [0u8];
            unsafe { libc::read(p[0], b.as_mut_ptr().cast(), 1) };
            let with = f(t);
            without(&[cap]);
            let without_it = f(t);
            capset(Sets { e: FULL, ..capget(0) });
            unsafe {
                libc::kill(t, libc::SIGKILL);
                libc::waitpid(t, std::ptr::null_mut(), 0);
            }
            [with, without_it]
        })
    };
    let rows = other(KILL, |t| r(unsafe { libc::kill(t, 0) } as i64));
    check!(h, rows == [0, eperm], "kill another uid: {rows:?}");
    let rows = other(SYS_PTRACE, |t| match std::fs::File::open(format!("/proc/{t}/mem")) {
        Ok(_) => 0,
        Err(e) => -(e.raw_os_error().unwrap_or(0) as i64),
    });
    check!(h, rows == [0, eacces], "/proc/<pid>/mem of another uid: {rows:?}");

    h.group("owners");
    let roots = format!("{DIR}/roots");
    let open_rw = format!("{DIR}/open");
    std::fs::write(&roots, b"x").unwrap();
    std::fs::write(&open_rw, b"x").unwrap();
    unsafe {
        libc::chmod(c(&roots).as_ptr(), 0o644);
        libc::chmod(c(&open_rw).as_ptr(), 0o666);
    }
    let owner = owner_of(&roots);
    let rows = child(|| unsafe {
        libc::syscall(libc::SYS_setresgid, 1000, 1000, 1000);
        setresuid(1000);
        let now = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_NOW }; 2];
        let half = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_NOW }, libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }];
        [
            r(libc::chown(c(&roots).as_ptr(), owner, u32::MAX) as i64),
            r(libc::utimensat(libc::AT_FDCWD, c(&roots).as_ptr(), std::ptr::null(), 0) as i64),
            r(libc::utimensat(libc::AT_FDCWD, c(&open_rw).as_ptr(), std::ptr::null(), 0) as i64),
            r(libc::utimensat(libc::AT_FDCWD, c(&open_rw).as_ptr(), now.as_ptr(), 0) as i64),
            r(libc::utimensat(libc::AT_FDCWD, c(&open_rw).as_ptr(), half.as_ptr(), 0) as i64),
        ]
    });
    check!(h, rows == [eperm, eacces, 0, 0, eperm], "a stranger's chown and utimensat: {rows:?}");
    let _ = std::fs::remove_dir_all(DIR);
    std::process::exit(h.finish());
}
