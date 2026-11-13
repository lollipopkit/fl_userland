//! The syscalls that are answered without being implemented.
//!
//! `mlock`, `mlockall`, `mbind` and `ioprio_set` do nothing here and cannot:
//! guest pages are host memory this process already manages, there is one NUMA
//! node, and there is no I/O scheduler to prioritise against. Answering 0 is
//! the right call — `ENOSYS` would stop a program over a request that is
//! already satisfied.
//!
//! Answering 0 to a request that is *malformed* is a different thing. A program
//! that passes a flag the kernel does not know is asking a question, and
//! "success" is the wrong answer to it: `mlockall(0)` is `EINVAL` on Linux
//! because locking nothing is not a thing to ask for, and a caller that gets 0
//! believes it locked something.
//!
//! `set_tid_address` is not in that category at all. It returns a number the
//! caller uses, and it was returning the wrong one — see below.
//!
//! # What a container will not answer
//!
//! `mbind` is in Docker's default seccomp profile's blocked set along with the
//! rest of the NUMA calls, and answers `EPERM` for every argument. There is no
//! `mbind` check here for that reason; adding `--security-opt seccomp=unconfined`
//! would answer it and would also let a mistake in this file reach the host's
//! memory policy.
//!
//! `mlockall(MCL_CURRENT)` is not checked either, in either direction: it would
//! really lock this process's memory, and whether it succeeds depends on
//! `RLIMIT_MEMLOCK`, which the two sides do not share. Only the malformed
//! requests are compared.

use guest_tests::{Harness, check, sys};

/// Named but not exercised, and the module comment says why: locking this process's memory for real
/// depends on `RLIMIT_MEMLOCK`, which the two sides do not share.
#[allow(dead_code)]
const MCL_CURRENT: i32 = 1;
const MCL_FUTURE: i32 = 2;
const MCL_ONFAULT: i32 = 4;
const MLOCK_ONFAULT: u32 = 1;

const IOPRIO_WHO_PROCESS: i32 = 1;
const IOPRIO_CLASS_SHIFT: i32 = 13;
const IOPRIO_CLASS_BE: i32 = 2;
const IOPRIO_CLASS_IDLE: i32 = 3;

fn sc3(n: libc::c_long, a: u64, b: u64, c: u64) -> i64 {
    sys::clear_errno();
    unsafe { libc::syscall(n, a, b, c) as i64 }
}

fn main() {
    let mut h = Harness::new();

    h.group("set-tid-address");
    // Linux returns `task_pid_vnr(current)` -- the caller's **thread** id, not
    // its thread group id. This returned sys_getpid(), which is the tgid, and
    // the two are the same number for a main thread, so nothing noticed.
    //
    // Done in a forked child because the call replaces this thread's
    // clear_child_tid, which is what the pthread implementation set up for
    // pthread_join to wait on. The child leaves by _exit from inside the
    // thread, so nothing joins it.
    let mut dummy: i32 = 0;
    let r = sc3(libc::SYS_set_tid_address, &mut dummy as *mut i32 as u64, 0, 0);
    let me = unsafe { libc::syscall(libc::SYS_gettid) } as i64;
    check!(h, r == me, "in the main thread it answers this thread's id: {r} vs gettid {me}");

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // In the child: a second thread, whose tid differs from the tgid.
        extern "C" fn body(_: *mut libc::c_void) -> *mut libc::c_void {
            let mut d: i32 = 0;
            let r = unsafe {
                libc::syscall(libc::SYS_set_tid_address, &mut d as *mut i32 as u64)
            } as i64;
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i64;
            let tgid = unsafe { libc::getpid() } as i64;
            // 0: right. 1: it answered the tgid. 2: something else. 3: this
            // thread's tid was not distinct, so the check proves nothing.
            let code = if tid == tgid { 3 } else if r == tid { 0 } else if r == tgid { 1 } else { 2 };
            unsafe { libc::_exit(code) };
        }
        let mut t: libc::pthread_t = unsafe { std::mem::zeroed() };
        unsafe {
            if libc::pthread_create(&mut t, std::ptr::null(), body, std::ptr::null_mut()) != 0 {
                libc::_exit(4);
            }
            loop {
                libc::pause();
            }
        }
    }
    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 };
    check!(h, code != 3, "the probe thread has a tid of its own (code {code})");
    check!(h, code != 4, "the probe thread started (code {code})");
    check!(
        h,
        code == 0,
        "in a second thread it answers the *thread* id, not the thread group's \
         (0 right, 1 answered the tgid, 2 answered neither): {code}"
    );

    h.group("mlockall");
    // Linux: !flags, or a bit outside the three, or ONFAULT without one of the
    // other two. All EINVAL, all before anything is locked.
    for (name, flags) in [
        ("mlockall(0)", 0),
        ("mlockall(8)", 8),
        ("mlockall(MCL_ONFAULT alone)", MCL_ONFAULT),
        ("mlockall(-1)", -1),
    ] {
        let r = sc3(libc::SYS_mlockall, flags as i64 as u64, 0, 0);
        check!(
            h,
            r == -1 && sys::errno() == libc::EINVAL,
            "{name} is EINVAL: r={r} errno={}",
            sys::errno()
        );
    }
    // The valid combinations are not asked to actually lock anything: MCL_FUTURE
    // alone locks nothing that exists, so it costs nothing on either side.
    let r = sc3(libc::SYS_mlockall, MCL_FUTURE as u64, 0, 0);
    check!(h, r == 0, "mlockall(MCL_FUTURE) is accepted: r={r} errno={}", sys::errno());
    let r = sc3(libc::SYS_mlockall, (MCL_FUTURE | MCL_ONFAULT) as u64, 0, 0);
    check!(
        h,
        r == 0,
        "MCL_ONFAULT alongside MCL_FUTURE is accepted: r={r} errno={}",
        sys::errno()
    );
    let r = sc3(libc::SYS_munlockall, 0, 0, 0);
    check!(h, r == 0, "munlockall undoes it: r={r} errno={}", sys::errno());

    h.group("mlock2");
    // A page this process really has, so the only thing under test is the flag.
    let page = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE,
                   libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    };
    check!(h, page != libc::MAP_FAILED, "a page to lock");
    if page != libc::MAP_FAILED {
        let addr = page as u64;
        for (name, flags) in [("2", 2u32), ("0x80000000", 0x8000_0000), ("~0", u32::MAX)] {
            let r = sc3(libc::SYS_mlock2, addr, 4096, flags as u64);
            check!(
                h,
                r == -1 && sys::errno() == libc::EINVAL,
                "mlock2 with flags {name} is EINVAL: r={r} errno={}",
                sys::errno()
            );
        }
        // MLOCK_ONFAULT is the one defined flag, and 0 is also legal. Neither is
        // asserted to *succeed* -- RLIMIT_MEMLOCK decides that and the two sides
        // do not share it -- only that neither is refused as an unknown flag.
        for (name, flags) in [("0", 0u32), ("MLOCK_ONFAULT", MLOCK_ONFAULT)] {
            let r = sc3(libc::SYS_mlock2, addr, 4096, flags as u64);
            let e = sys::errno();
            check!(
                h,
                r == 0 || e != libc::EINVAL,
                "mlock2 with flags {name} is not refused as unknown: r={r} errno={e}"
            );
        }
        unsafe {
            libc::munlock(page, 4096);
            libc::munmap(page, 4096);
        }
    }

    h.group("ioprio");
    // Nothing here schedules I/O, so this is another remembered-and-reported
    // attribute. What is under test is the shape of the answers, and every
    // number below came from asking a real arm64 kernel rather than from the
    // man page -- which describes a `data` field of 0..7 and is describing a
    // kernel from before the field was split.
    //
    // On 6.x the low **three** bits are the level and bits 3..12 are a "hint":
    //
    //   #define IOPRIO_LEVEL_NR_BITS 3
    //   #define IOPRIO_PRIO_LEVEL(ioprio) ((ioprio) & IOPRIO_LEVEL_MASK)
    //
    // so `IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 8)` has a level of *zero* and is
    // accepted, while 7 and 15 are refused. That is asserted below precisely
    // because it is the sort of thing a reimplementation gets wrong by writing
    // the obvious `level > 7`.
    //
    // IOPRIO_CLASS_RT is **not** checked. It needs CAP_SYS_ADMIN, and a
    // container's root does not have it -- the sweep would report the
    // container's capability set. Privilege here is an effective uid of zero,
    // so a root guest is allowed it; that is this emulator's model of privilege
    // and not something a container can arbitrate.
    for which in [0i32, 4, 99, -1] {
        let r = sc3(libc::SYS_ioprio_get, which as i64 as u64, 0, 0);
        check!(
            h,
            r == -1 && sys::errno() == libc::EINVAL,
            "ioprio_get(which={which}) is EINVAL: r={r} errno={}",
            sys::errno()
        );
    }
    // A fresh process is IOPRIO_CLASS_NONE at level 0, which is the value 0.
    let r = sc3(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS as u64, 0, 0);
    check!(h, r == 0, "a fresh process has no I/O priority: r={r} errno={}", sys::errno());

    // A pid that does not exist is ESRCH, for both halves.
    for (name, n) in [("ioprio_get", libc::SYS_ioprio_get), ("ioprio_set", libc::SYS_ioprio_set)] {
        let r = sc3(n, IOPRIO_WHO_PROCESS as u64, 999_999, ((IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 4) as u64);
        check!(
            h,
            r == -1 && sys::errno() == libc::ESRCH,
            "{name} on a pid that does not exist is ESRCH: r={r} errno={}",
            sys::errno()
        );
    }

    // The priority is judged before `who` is resolved: Linux calls
    // ioprio_check_cap at the top of ioprio_set, above the switch on `which`.
    // So a malformed priority aimed at a pid that does not exist is EINVAL and
    // not ESRCH -- which is the check that the two are in that order, since
    // either alone would give a plausible answer.
    let r = sc3(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS as u64, 999_999, 7);
    check!(
        h,
        r == -1 && sys::errno() == libc::EINVAL,
        "a malformed priority is refused before the pid is looked up: r={r} errno={}",
        sys::errno()
    );

    // Class 7 is not one of the four. IOPRIO_PRIO_CLASS masks to three bits, so
    // this is genuinely class 7 rather than something that wraps to a real one.
    let r = sc3(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS as u64, 0, (7 << IOPRIO_CLASS_SHIFT) as u64);
    check!(
        h,
        r == -1 && sys::errno() == libc::EINVAL,
        "ioprio_set with an unknown class is EINVAL: r={r} errno={}",
        sys::errno()
    );
    for which in [0i32, 4, -1] {
        let r = sc3(libc::SYS_ioprio_set, which as i64 as u64, 0,
                    (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) as u64);
        check!(
            h,
            r == -1 && sys::errno() == libc::EINVAL,
            "ioprio_set(which={which}) is EINVAL: r={r} errno={}",
            sys::errno()
        );
    }

    // IOPRIO_CLASS_NONE carries no level, and the level is the low three bits.
    for lvl in [1u64, 7, 15, 8191] {
        let r = sc3(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS as u64, 0, lvl);
        check!(
            h,
            r == -1 && sys::errno() == libc::EINVAL,
            "IOPRIO_CLASS_NONE with a level of {lvl} is EINVAL: r={r} errno={}",
            sys::errno()
        );
    }
    // 8 has a level of zero once the low three bits are taken, so it is not a
    // level at all -- this is the check that the mask is three bits and not the
    // 0..7 range the man page describes.
    let r = sc3(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS as u64, 0, 8);
    check!(
        h,
        r == 0,
        "IOPRIO_CLASS_NONE with 8 has a level of zero and is accepted: r={r} errno={}",
        sys::errno()
    );

    // BE and IDLE take any level, because the check is on the class.
    for (cname, class) in [("BE", IOPRIO_CLASS_BE), ("IDLE", IOPRIO_CLASS_IDLE)] {
        for lvl in [0i32, 4, 7, 8, 8191] {
            let v = ((class << IOPRIO_CLASS_SHIFT) | lvl) as u64;
            let r = sc3(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS as u64, 0, v);
            check!(
                h,
                r == 0,
                "ioprio_set({cname}, {lvl}) is accepted: r={r} errno={}",
                sys::errno()
            );
            let g = sc3(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS as u64, 0, 0);
            check!(h, g == v as i64, "and reads back whole: {g:#x} vs {v:#x}");
        }
    }

    // The group and user forms are answered rather than refused. What they
    // answer is the best priority among the matching tasks, and which tasks
    // those are differs between a container and this, so only the shape is
    // compared.
    for which in [2i32, 3] {
        let r = sc3(libc::SYS_ioprio_get, which as u64, 0, 0);
        check!(
            h,
            r >= 0,
            "ioprio_get(which={which}) is answered: r={r} errno={}",
            sys::errno()
        );
    }

    h.group("fadvise");
    let fd = unsafe { libc::open(c"/dev/zero".as_ptr(), libc::O_RDONLY) };
    check!(h, fd >= 0, "opened /dev/zero");
    if fd >= 0 {
        let r = unsafe { libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_NORMAL) };
        check!(h, r == 0, "posix_fadvise(NORMAL) is 0: r={r}");
        // An advice value nothing defines.
        let r = sc3(libc::SYS_fadvise64, fd as u64, 0, 0);
        let _ = r;
        let r = unsafe { libc::syscall(libc::SYS_fadvise64, fd, 0i64, 0i64, 99) as i64 };
        check!(
            h,
            r == -libc::EINVAL as i64 || r == -1,
            "an undefined advice is refused: r={r}"
        );
        unsafe { libc::close(fd) };
    }
    let r = unsafe { libc::syscall(libc::SYS_fadvise64, 9999, 0i64, 0i64, 0) as i64 };
    check!(h, r == -1 || r < 0, "fadvise on a closed descriptor is refused: r={r}");

    std::process::exit(h.finish());
}
