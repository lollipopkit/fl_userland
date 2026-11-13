//! What `getrlimit`, `setrlimit` and `prlimit64` do with their arguments.
//!
//! # Why this exists
//!
//! A resource limit is a rule the kernel is asked to enforce, and every way of
//! getting it wrong is silent: a limit reported as something other than what
//! was set, a soft limit accepted above its hard one, a resource number nobody
//! validates. A program that sets `RLIMIT_NOFILE` and carries on believing it
//! has 65536 descriptors finds out at the worst moment.
//!
//! aarch64 has **one** of the three as a real syscall — `prlimit64` (261) —
//! and glibc's `getrlimit`/`setrlimit` are wrappers over it. That makes the
//! argument handling of one call the whole interface, which is the shape this
//! suite keeps finding defects in.
//!
//! # What is compared
//!
//! Not the *values*: the two kernels have different defaults, and a container's
//! `RLIMIT_NOFILE` is whatever docker chose. What is compared is the shape of
//! the answers — which resources exist, which changes are refused and with what
//! errno, and whether what comes back is what went in.

use std::io::Write;

unsafe fn sys(n: i64, a: i64, b: i64, c: i64, d: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b, in("x2") c, in("x3") d,
            options(nostack)
        );
    }
    ret
}

const NR_PRLIMIT64: i64 = 261;
const NR_GETRLIMIT: i64 = 163;
const NR_SETRLIMIT: i64 = 164;

fn errname(e: i32) -> String {
    let n = match e {
        1 => "EPERM", 3 => "ESRCH", 9 => "EBADF", 13 => "EACCES", 14 => "EFAULT",
        22 => "EINVAL", 38 => "ENOSYS",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 && v > -4096 {
        format!("-{}", errname(-v as i32))
    } else {
        v.to_string()
    }
}

fn say(what: &str, s: String) {
    println!("  {what:<50} {s}");
    let _ = std::io::stdout().flush();
}

const INF: u64 = u64::MAX;

/// The sixteen Linux names, and two past the end.
const RESOURCES: &[(i64, &str)] = &[
    (0, "RLIMIT_CPU"),
    (1, "RLIMIT_FSIZE"),
    (2, "RLIMIT_DATA"),
    (3, "RLIMIT_STACK"),
    (4, "RLIMIT_CORE"),
    (5, "RLIMIT_RSS"),
    (6, "RLIMIT_NPROC"),
    (7, "RLIMIT_NOFILE"),
    (8, "RLIMIT_MEMLOCK"),
    (9, "RLIMIT_AS"),
    (10, "RLIMIT_LOCKS"),
    (11, "RLIMIT_SIGPENDING"),
    (12, "RLIMIT_MSGQUEUE"),
    (13, "RLIMIT_NICE"),
    (14, "RLIMIT_RTPRIO"),
    (15, "RLIMIT_RTTIME"),
    (16, "one past the last"),
    (99, "resource 99"),
    (-1, "resource -1"),
];

/// `prlimit64(pid, resource, new, old)`.
unsafe fn prlimit(pid: i64, res: i64, new: Option<&[u64; 2]>, old: Option<&mut [u64; 2]>) -> i64 {
    let n = new.map_or(0, |v| v.as_ptr() as i64);
    let o = old.map_or(0, |v| v.as_mut_ptr() as i64);
    unsafe { sys(NR_PRLIMIT64, pid, res, n, o) }
}

fn main() {
    println!("## prlimit64");

    println!("## which resources exist");
    for &(res, name) in RESOURCES {
        let mut got = [0u64; 2];
        let e = unsafe { prlimit(0, res, None, Some(&mut got)) };
        // The *values* differ between the two kernels and are not the point;
        // whether the resource exists, and whether its soft limit is within its
        // hard one, are.
        let shape = if e < 0 {
            r(e)
        } else {
            format!("ok, soft<=hard {}", got[0] <= got[1] || got[1] == INF)
        };
        say(&format!("get {name}"), shape);
    }

    println!("## the arguments");
    let mut got = [0u64; 2];
    say("neither new nor old", r(unsafe { prlimit(0, 7, None, None) }));
    say("old is unmapped", r(unsafe {
        sys(NR_PRLIMIT64, 0, 7, 0, 0x10)
    }));
    say("new is unmapped", r(unsafe {
        sys(NR_PRLIMIT64, 0, 7, 0x10, 0)
    }));
    say("pid -1", r(unsafe { prlimit(-1, 7, None, Some(&mut got)) }));
    say("pid 999999", r(unsafe { prlimit(999999, 7, None, Some(&mut got)) }));
    // A pid naming this very process is the same as 0 and must answer the same.
    let me = std::process::id() as i64;
    say("this process by pid", r(unsafe { prlimit(me, 7, None, Some(&mut got)) }));

    println!("## setting");
    // **RLIMIT_CORE throughout, never RLIMIT_NOFILE.** Lowering the descriptor
    // limit to 8 to watch it read back is a case that breaks every later one --
    // and the probe itself opens files. `fs_probe` learned this about
    // filenames; a resource limit is the same hazard with a wider blast radius,
    // because it is the *process* that is changed rather than a file. Core
    // dumps do not exist here or in a container, so this one is inert.
    const CORE: i64 = 4;
    let mut cur = [0u64; 2];
    unsafe { prlimit(0, CORE, None, Some(&mut cur)) };
    let lower = [8u64, cur[1]];
    say("lower the soft limit", r(unsafe { prlimit(0, CORE, Some(&lower), None) }));
    let mut back = [0u64; 2];
    unsafe { prlimit(0, CORE, None, Some(&mut back)) };
    say("  it reads back as 8", format!("{}", back[0] == 8));
    say("  the hard limit did not move", format!("{}", back[1] == cur[1]));
    // Raising the soft limit again, which is allowed up to the hard limit.
    let restore = [cur[0], cur[1]];
    say("raise the soft limit to what it was", r(unsafe {
        prlimit(0, CORE, Some(&restore), None)
    }));

    // A soft limit above the hard one is EINVAL, for root as well.
    let inverted = [cur[1].saturating_add(1), cur[1]];
    say("soft above hard", r(unsafe { prlimit(0, CORE, Some(&inverted), None) }));
    // Both infinite is the one case where "soft above hard" is not.
    let both_inf = [INF, INF];
    say("both RLIM_INFINITY", r(unsafe { prlimit(0, CORE, Some(&both_inf), None) }));

    // Lowering a hard limit is always allowed and is one-way: an unprivileged
    // caller cannot put it back. This process is root in both kernels, so what
    // is being asked here is whether *root* can, which Linux allows.
    let lowered_hard = [0u64, 4096];
    say("lower the hard limit", r(unsafe {
        prlimit(0, CORE, Some(&lowered_hard), None)
    }));
    let raise_again = [0u64, INF];
    say("raise it back to infinity", r(unsafe {
        prlimit(0, CORE, Some(&raise_again), None)
    }));

    // Setting a resource that does not exist.
    let anything = [0u64, 0];
    say("set resource 99", r(unsafe { prlimit(0, 99, Some(&anything), None) }));
    say("set resource -1", r(unsafe { prlimit(0, -1, Some(&anything), None) }));

    println!("## the other two doors");
    // aarch64 keeps `getrlimit` and `setrlimit` as well as `prlimit64`, so the
    // same rules have three entry points. A rule enforced in one and not the
    // others is the shape `syscall_aliases` warns about, one level up: these
    // are different implementations rather than one at two numbers.
    // **A resource of its own**, untouched by the section above. The first
    // version reused RLIMIT_CORE and the "soft above hard" case then depended
    // on whether the *previous* case had managed to raise the hard limit back
    // to infinity -- which it can here and cannot in a container, so the two
    // sides disagreed about a case that was really asking the earlier question
    // twice. `fs_probe`'s rule about files, applied to process state.
    const LOCKS: i64 = 10;
    let mut via_get = [0u64; 2];
    say("getrlimit(RLIMIT_LOCKS)", r(unsafe {
        sys(NR_GETRLIMIT, LOCKS, via_get.as_mut_ptr() as i64, 0, 0)
    }));
    let mut via_pr = [0u64; 2];
    unsafe { prlimit(0, LOCKS, None, Some(&mut via_pr)) };
    say("  it agrees with prlimit64", format!("{}", via_get == via_pr));
    say("getrlimit(resource 99)", r(unsafe {
        sys(NR_GETRLIMIT, 99, via_get.as_mut_ptr() as i64, 0, 0)
    }));
    say("getrlimit(NULL)", r(unsafe { sys(NR_GETRLIMIT, LOCKS, 0, 0, 0) }));
    say("getrlimit(unmapped)", r(unsafe { sys(NR_GETRLIMIT, LOCKS, 0x10, 0, 0) }));
    // A soft limit one above the hard one. Stated as a *lowered* hard limit so
    // that the pair is inverted whatever the resource started at -- with an
    // infinite hard limit there is no value above it to name.
    let inverted2 = [4097u64, 4096];
    say("setrlimit soft above hard", r(unsafe {
        sys(NR_SETRLIMIT, LOCKS, inverted2.as_ptr() as i64, 0, 0)
    }));
    say("setrlimit(resource 99)", r(unsafe {
        sys(NR_SETRLIMIT, 99, anything.as_ptr() as i64, 0, 0)
    }));
    say("setrlimit(NULL)", r(unsafe { sys(NR_SETRLIMIT, LOCKS, 0, 0, 0) }));
    let via_set = [512u64, via_pr[1]];
    say("setrlimit lowers the soft limit", r(unsafe {
        sys(NR_SETRLIMIT, LOCKS, via_set.as_ptr() as i64, 0, 0)
    }));
    let mut after = [0u64; 2];
    unsafe { prlimit(0, LOCKS, None, Some(&mut after)) };
    say("  prlimit64 sees it", format!("{}", after[0] == 512));

    println!("## old and new together");
    // The `old` a set reports is what the limit was *before* -- and the two
    // happen under one call, so a caller cannot see a value that never was.
    let mut before = [0u64; 2];
    unsafe { prlimit(0, 4, None, Some(&mut before)) };
    let target = [1024u64, before[1]];
    let mut reported = [0u64; 2];
    say("set with old", r(unsafe { prlimit(0, 4, Some(&target), Some(&mut reported)) }));
    say("  old is what it was", format!("{}", reported == before));
    let mut now = [0u64; 2];
    unsafe { prlimit(0, 4, None, Some(&mut now)) };
    say("  and the new value took", format!("{}", now[0] == 1024));
}
