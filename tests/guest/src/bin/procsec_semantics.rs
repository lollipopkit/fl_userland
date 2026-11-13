//! `kcmp`, `sched_setattr`/`sched_getattr`, `unshare`, `seccomp` and
//! `lsm_list_modules`, as checks. Each answer was measured on 7.2 by
//! `procsec_probe` first, and every one of these calls was `ENOSYS` here
//! before 2026-11-11 (`seccomp` included, with `PR_SET_SECCOMP` `EINVAL`).
//!
//! Every case that changes the process runs in a forked child.

use guest_tests::{Harness, check, check_fails, sys};

/// Run `f` in a child and answer its exit status, or 128 + the signal.
fn in_child(f: impl FnOnce() -> i32) -> i32 {
    let c = unsafe { libc::fork() };
    if c == 0 {
        let code = f();
        unsafe { libc::_exit(code) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(c, &mut st, 0) };
    if libc::WIFSIGNALED(st) { 128 + libc::WTERMSIG(st) } else { libc::WEXITSTATUS(st) }
}

fn kcmp(p1: i32, p2: i32, ty: i32, a: u64, b: u64) -> i64 {
    unsafe { libc::syscall(272, p1, p2, ty, a, b) }
}

fn t_kcmp(h: &mut Harness) {
    h.group("kcmp");
    let me = unsafe { libc::getpid() };
    let a = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    let b = unsafe { libc::dup(a) };
    let c = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    check!(h, kcmp(me, me, 0, a as u64, b as u64) == 0, "a descriptor and its dup are one file: errno {}", sys::errno());
    let other = kcmp(me, me, 0, a as u64, c as u64);
    check!(h, other == 1 || other == 2, "two opens are two files, ordered: {other}");
    check_fails!(h, kcmp(me, me, 0, a as u64, 9999), libc::EBADF, "a closed descriptor");
    check!(h, kcmp(me, me, 1, 0, 0) == 0, "KCMP_VM with itself");
    check_fails!(h, kcmp(me, me, 8, 0, 0), libc::EINVAL, "type 8");
    check_fails!(h, kcmp(me, 999_999, 1, 0, 0), libc::ESRCH, "a pid that is not there");
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
    for (ty, what) in [(1, "VM"), (2, "FILES"), (3, "FS"), (4, "SIGHAND")] {
        let r = kcmp(me, child, ty, 0, 0);
        check!(h, r == 1 || r == 2, "a forked child has its own {what}: {r}");
    }
    check!(h, kcmp(me, child, 0, a as u64, a as u64) == 0, "an inherited descriptor is the same file");
    unsafe {
        libc::close(p[0]);
        libc::close(p[1]);
        let mut st = 0;
        libc::waitpid(child, &mut st, 0);
    }
}

/// Into a buffer of 72 bytes filled with 0xff, so what was written is visible.
fn getattr(size: u32) -> (i64, [u8; 72]) {
    let mut b = [0xffu8; 72];
    (unsafe { libc::syscall(275, 0, b.as_mut_ptr(), size, 0) }, b)
}

fn setattr(policy: u32, flags: u64, nice: i32) -> i64 {
    let mut b = [0u8; 56];
    b[0..4].copy_from_slice(&56u32.to_le_bytes());
    b[4..8].copy_from_slice(&policy.to_le_bytes());
    b[8..16].copy_from_slice(&flags.to_le_bytes());
    b[16..20].copy_from_slice(&nice.to_le_bytes());
    unsafe { libc::syscall(274, 0, b.as_ptr(), 0) }
}

fn t_sched_attr(h: &mut Harness) {
    h.group("sched-attr");
    let (r, b) = getattr(56);
    check!(h, r == 0, "sched_getattr(56): errno {}", sys::errno());
    check!(h, u32::from_le_bytes(b[0..4].try_into().unwrap()) == 56, "it writes its size back");
    // A bigger struct than the kernel's: its size says 56, and the part past
    // that is zeroed -- 7.2's `copy_struct_to_user`, which wrote past a
    // 64-byte buffer told it was 72 when this test first ran on Linux.
    let (r, b) = getattr(72);
    check!(h, r == 0 && b[0] == 56, "a bigger struct gets size 56: {r} {}", b[0]);
    check!(h, b[56..72] == [0; 16], "and its tail zeroed: {:?}", &b[56..72]);
    let (_, b) = getattr(48);
    check!(h, b[48..72] == [0xff; 24], "a 48-byte struct gets 48 bytes and no more");
    check_fails!(h, getattr(47).0, libc::EINVAL, "a struct below SCHED_ATTR_SIZE_VER0");
    check_fails!(h, unsafe { libc::syscall(275, 0, [0u8; 56].as_mut_ptr(), 56, 1) }, libc::EINVAL, "flags 1");
    let status = in_child(|| {
        if setattr(0, 0, 5) != 0 || unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) } != 5 {
            return 1;
        }
        if setattr(3, 1, 5) != 0 {
            return 2;
        }
        // SCHED_BATCH | SCHED_RESET_ON_FORK, read back both ways.
        if unsafe { libc::syscall(120, 0) } != 3 | 0x4000_0000 {
            return 3;
        }
        if getattr(56).1[8] != 1 {
            return 4;
        }
        // KEEP_POLICY keeps the flag too.
        if setattr(0, 0x18, 0) != 0 || unsafe { libc::syscall(120, 0) } != 3 | 0x4000_0000 {
            return 5;
        }
        if setattr(0, 0x20, 0) >= 0 || sys::errno() != libc::EOPNOTSUPP {
            return 6;
        }
        if setattr(1, 0, 0) >= 0 || sys::errno() != libc::EINVAL {
            return 7;
        }
        0
    });
    check!(h, status == 0, "nice, BATCH, RESET_ON_FORK, KEEP_POLICY, UTIL_CLAMP and FIFO: step {status}");
    let status = in_child(|| {
        // A negative nice does not survive a fork under RESET_ON_FORK.
        if setattr(0, 1, -3) != 0 {
            return 1;
        }
        in_child(|| {
            let n = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
            if n != 0 { 10 + n.unsigned_abs() as i32 } else if unsafe { libc::syscall(120, 0) } != 0 { 3 } else { 0 }
        })
    });
    check!(h, status == 0, "RESET_ON_FORK gives the child nice 0 and no flag: {status}");
}

fn t_unshare(h: &mut Harness) {
    h.group("unshare");
    let status = in_child(|| {
        let (tx, rx) = std::sync::mpsc::channel::<i32>();
        let (back, seen) = std::sync::mpsc::channel::<bool>();
        let t = std::thread::spawn(move || {
            while let Ok(fd) = rx.recv() {
                back.send(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0).unwrap();
            }
        });
        if unsafe { libc::unshare(libc::CLONE_FILES) } != 0 {
            return 1;
        }
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        tx.send(fd).unwrap();
        let visible = seen.recv().unwrap();
        drop(tx);
        t.join().unwrap();
        if visible { 2 } else { 0 }
    });
    check!(h, status == 0, "CLONE_FILES splits the table a thread shares: step {status}");
    let status = in_child(|| {
        let t = std::thread::spawn(|| unsafe {
            if libc::unshare(libc::CLONE_FS) != 0 {
                return 1;
            }
            libc::chdir(c"/proc".as_ptr())
        });
        unsafe { libc::chdir(c"/".as_ptr()) };
        let r = t.join().unwrap();
        let mut cwd = [0u8; 8];
        unsafe { libc::getcwd(cwd.as_mut_ptr().cast(), 8) };
        if r != 0 { 1 } else if &cwd[..2] != b"/\0" { 2 } else { 0 }
    });
    check!(h, status == 0, "CLONE_FS gives a thread its own working directory: step {status}");
    let status = in_child(|| {
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            let _ = wait.recv();
        });
        let r = unsafe { libc::unshare(libc::CLONE_VM) };
        let e = sys::errno();
        go.send(()).unwrap();
        t.join().unwrap();
        if r == 0 { 1 } else if e != libc::EINVAL { 2 } else { 0 }
    });
    check!(h, status == 0, "CLONE_VM with a second thread is EINVAL: step {status}");
    check!(h, in_child(|| unsafe { libc::unshare(libc::CLONE_NEWNS) }.abs()) != 0, "a namespace is refused");
    check_fails!(h, unsafe { libc::unshare(libc::CLONE_PARENT) }, libc::EINVAL, "CLONE_PARENT");
}

#[repr(C)]
struct Fprog {
    len: u16,
    filter: *const [u16; 4],
}

/// `nr == n ? ret : ALLOW`, as four `sock_filter`s of (code, jt|jf<<8, k lo, k hi).
fn filter(n: u32, ret: u32) -> [[u16; 4]; 4] {
    let ins = |code: u16, jt: u8, jf: u8, k: u32| [code, jt as u16 | (jf as u16) << 8, k as u16, (k >> 16) as u16];
    [ins(0x20, 0, 0, 0), ins(0x15, 0, 1, n), ins(0x06, 0, 0, ret), ins(0x06, 0, 0, 0x7fff_0000)]
}

fn install(n: u32, ret: u32) -> i64 {
    let f = filter(n, ret);
    let prog = Fprog { len: 4, filter: f.as_ptr() };
    unsafe { libc::syscall(277, 1, 0, &prog) }
}

fn t_seccomp(h: &mut Harness) {
    h.group("seccomp");
    check!(h, unsafe { libc::syscall(277, 2, 0, &0x7fff_0000u32) } == 0, "ALLOW is available: errno {}", sys::errno());
    check_fails!(h, unsafe { libc::syscall(277, 2, 0, &0x1234_0000u32) }, libc::EOPNOTSUPP, "an action no kernel has");
    let status = in_child(|| {
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if install(libc::SYS_getppid as u32, 0x50000 | libc::EPERM as u32) != 0 {
            return 1;
        }
        if unsafe { libc::syscall(libc::SYS_getppid) } != -1 || sys::errno() != libc::EPERM {
            return 2;
        }
        if unsafe { libc::prctl(libc::PR_GET_SECCOMP) } != 2 {
            return 3;
        }
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        if !status.contains("Seccomp:\t2\n") || !status.contains("Seccomp_filters:\t1\n") {
            return 4;
        }
        // Inherited by a child.
        let inherited = in_child(|| (unsafe { libc::syscall(libc::SYS_getppid) } == -1) as i32);
        if inherited != 1 {
            return 5;
        }
        0
    });
    check!(h, status == 0, "an ERRNO filter, PR_GET_SECCOMP, status and inheritance: step {status}");
    check!(
        h,
        in_child(|| {
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            install(libc::SYS_getppid as u32, 0x8000_0000);
            unsafe { libc::syscall(libc::SYS_getppid) };
            0
        }) == 128 + libc::SIGSYS,
        "KILL_PROCESS dies of SIGSYS"
    );
    check!(
        h,
        in_child(|| {
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            install(libc::SYS_getppid as u32, 0x7ff0_0000);
            (unsafe { libc::syscall(libc::SYS_getppid) } == -1 && sys::errno() == libc::ENOSYS) as i32
        }) == 1,
        "TRACE with no tracer is ENOSYS"
    );
    check!(
        h,
        in_child(|| {
            unsafe { libc::prctl(libc::PR_SET_SECCOMP, 1) };
            unsafe { libc::syscall(libc::SYS_getpid) };
            0
        }) == 128 + libc::SIGKILL,
        "strict mode kills a syscall it does not allow"
    );
    check!(
        h,
        in_child(|| {
            let bad = [[0x20u16, 0, 2, 0], [0x06, 0, 0, 0x7fff]];
            let prog = Fprog { len: 2, filter: bad.as_ptr() };
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            (unsafe { libc::syscall(277, 1, 0, &prog) } == -1 && sys::errno() == libc::EINVAL) as i32
        }) == 1,
        "an unaligned load is refused"
    );
}

fn t_lsm(h: &mut Harness) {
    h.group("lsm");
    let mut ids = [0u64; 4];
    let mut size: u32 = 32;
    let n = unsafe { libc::syscall(461, ids.as_mut_ptr(), &mut size, 0) };
    check!(h, n >= 1 && ids[..n as usize].contains(&100), "lsm_list_modules lists capability: {n}");
    let mut small: u32 = 0;
    check_fails!(h, unsafe { libc::syscall(461, ids.as_mut_ptr(), &mut small, 0) }, libc::E2BIG, "a buffer too small");
    check!(h, small >= 8 && small % 8 == 0, "and the size it needs written back: {small}");
    let mut sz: u32 = 64;
    check_fails!(h, unsafe { libc::syscall(459, 100, [0u64; 8].as_mut_ptr(), &mut sz, 0) }, libc::EOPNOTSUPP, "no module has LSM_ATTR_CURRENT");
}

fn main() {
    let mut h = Harness::new();
    t_kcmp(&mut h);
    t_sched_attr(&mut h);
    t_unshare(&mut h);
    t_seccomp(&mut h);
    t_lsm(&mut h);
    std::process::exit(h.finish());
}
