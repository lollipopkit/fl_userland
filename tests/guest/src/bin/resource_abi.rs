//! `getrlimit`/`setrlimit`/`prlimit64`/`getrusage`: the ABI a guest observes.

use guest_tests::{Harness, check};

fn main() {
    let mut h = Harness::new();

    h.group("getrusage-is-initialised");
    // Dirty the stack first: the fields below are only wrong if something was
    // left there, and a quiet stack can be zero by luck.
    let mut deep = [0u8; 4096];
    for (i, b) in deep.iter_mut().enumerate() { *b = (i % 251) as u8 + 1; }
    std::hint::black_box(&deep);
    let mut path = [0u8; 3000];
    path.fill(b'a');
    path[0] = b'/';
    let _ = std::fs::metadata(std::str::from_utf8(&path).unwrap());

    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    check!(h, r == 0, "getrusage(RUSAGE_SELF) succeeds");
    let named: [(&str, i64); 14] = [
        ("maxrss", ru.ru_maxrss as i64), ("ixrss", ru.ru_ixrss as i64),
        ("idrss", ru.ru_idrss as i64), ("isrss", ru.ru_isrss as i64),
        ("minflt", ru.ru_minflt as i64), ("majflt", ru.ru_majflt as i64),
        ("nswap", ru.ru_nswap as i64), ("inblock", ru.ru_inblock as i64),
        ("oublock", ru.ru_oublock as i64), ("msgsnd", ru.ru_msgsnd as i64),
        ("msgrcv", ru.ru_msgrcv as i64), ("nsignals", ru.ru_nsignals as i64),
        ("nvcsw", ru.ru_nvcsw as i64), ("nivcsw", ru.ru_nivcsw as i64),
    ];
    let junk: Vec<&str> = named.iter().filter(|(_, v)| *v < 0 || *v > 1 << 40).map(|(n, _)| *n).collect();
    check!(h, junk.is_empty(), "no rusage field is uninitialised stack: {junk:?}");
    // Two calls in a row must not disagree about fields nothing changed.
    let mut ru2: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru2) };
    check!(h, ru.ru_maxrss == ru2.ru_maxrss && ru.ru_nvcsw == ru2.ru_nvcsw,
        "and two calls agree: maxrss {} vs {}, nvcsw {} vs {}",
        ru.ru_maxrss, ru2.ru_maxrss, ru.ru_nvcsw, ru2.ru_nvcsw);

    h.group("prlimit-own-pid");
    // `prlimit(getpid(), ...)` is the ordinary spelling -- util-linux's prlimit(1)
    // and anything raising its own NOFILE writes it that way. Only 0 worked.
    let mut old: libc::rlimit = unsafe { std::mem::zeroed() };
    let pid = unsafe { libc::getpid() };
    let r = unsafe { libc::prlimit(pid, libc::RLIMIT_NOFILE, std::ptr::null(), &mut old) };
    check!(h, r == 0, "prlimit(getpid()) works: r={r} errno={}", std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    let r0 = unsafe { libc::prlimit(0, libc::RLIMIT_NOFILE, std::ptr::null(), &mut old) };
    check!(h, r0 == 0, "and prlimit(0) still works");
    // A pid that is not there is ESRCH, not EINVAL.
    let r_bad = unsafe { libc::prlimit(0x7ffffff0, libc::RLIMIT_NOFILE, std::ptr::null(), &mut old) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r_bad == -1 && e == libc::ESRCH, "an absent pid is ESRCH, not {e}");

    h.group("prlimit-another-process");
    // The case prlimit exists for, and the one that was untested: naming a
    // *different* process. It is also the only call here that has to hold the
    // pid lock across the lookup *and* the use of what it found -- a task can
    // exit and be freed the moment that lock is dropped.
    //
    // The child parks on a pipe so it is certainly alive while the parent asks
    // about it, then reports what it sees its own limit to be. That last part
    // is what makes this a test of the *write* path rather than only the read:
    // the parent changes the child's limit and the child reads it back.
    let mut ask = [0; 2];
    let mut tell = [0; 2];
    assert_eq!(unsafe { libc::pipe(ask.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { libc::pipe(tell.as_mut_ptr()) }, 0);
    let mut before: libc::rlimit = unsafe { std::mem::zeroed() };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut before) };
    let target = before.rlim_cur.min(64);

    // SAFETY: the child uses only read, getrlimit, write and _exit.
    let kid = unsafe { libc::fork() };
    if kid == 0 {
        unsafe {
            libc::close(ask[1]);
            libc::close(tell[0]);
            let mut go = [0u8; 1];
            libc::read(ask[0], go.as_mut_ptr().cast(), 1);
            let mut mine: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut mine);
            let n = mine.rlim_cur as u64;
            libc::write(tell[1], (&raw const n).cast(), 8);
            libc::_exit(0);
        }
    }
    unsafe {
        libc::close(ask[0]);
        libc::close(tell[1]);
    }

    // Read the child's limit from outside it.
    let mut kid_limit: libc::rlimit = unsafe { std::mem::zeroed() };
    let r_read =
        unsafe { libc::prlimit(kid, libc::RLIMIT_NOFILE, std::ptr::null(), &mut kid_limit) };
    check!(
        h,
        r_read == 0 && kid_limit.rlim_cur == before.rlim_cur,
        "prlimit reads another process's limit: r={r_read} got={} want={}",
        kid_limit.rlim_cur,
        before.rlim_cur
    );

    // Change it, and check that the value reported back is the one from
    // *before* the change -- which is what Linux answers when both pointers are
    // given, and the reason the read happens first.
    let new_limit = libc::rlimit {
        rlim_cur: target,
        rlim_max: before.rlim_max,
    };
    let mut reported: libc::rlimit = unsafe { std::mem::zeroed() };
    let r_set = unsafe { libc::prlimit(kid, libc::RLIMIT_NOFILE, &new_limit, &mut reported) };
    check!(
        h,
        r_set == 0 && reported.rlim_cur == before.rlim_cur,
        "and reports the value from before the change: r={r_set} got={} want={}",
        reported.rlim_cur,
        before.rlim_cur
    );

    // Now let the child look at itself.
    unsafe { libc::write(ask[1], b"g".as_ptr().cast(), 1) };
    let mut seen = 0u64;
    let got = unsafe { libc::read(tell[0], (&raw mut seen).cast(), 8) };
    let mut status = 0;
    unsafe { libc::waitpid(kid, &mut status, 0) };
    check!(
        h,
        got == 8 && seen == target,
        "the child sees the limit its parent set: read={got} seen={seen} want={target}"
    );
    unsafe {
        libc::close(ask[1]);
        libc::close(tell[0]);
    }

    h.group("children-rusage");
    // A child does not inherit its parent's accumulated CPU time. `tgroup_copy`
    // resets `children_rusage` but copies `rusage`, so a child that does
    // nothing was reported to have used everything the parent had used before
    // the fork -- and the parent's grandparent counted it a second time.
    //
    // `group->rusage` only accumulates when a *thread* exits, so a parent that
    // has merely run has nothing there yet and the copy copies zero. Burn the
    // CPU in a thread and join it: that is the shape where the parent's group
    // holds a non-zero total at the moment it forks.
    let burner = std::thread::spawn(|| {
        let mut acc = 0u64;
        for i in 0..40_000_000u64 { acc = acc.wrapping_add(i ^ acc.rotate_left(7)); }
        std::hint::black_box(acc);
    });
    burner.join().unwrap();
    let mut before: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut before) };
    let burnt_us = before.ru_utime.tv_sec as i64 * 1_000_000 + before.ru_utime.tv_usec as i64;
    // What the exited thread left in the group -- that is what a fork would
    // hand the child. Read it through RUSAGE_CHILDREN's baseline.
    let mut kids0: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut kids0) };
    let base_us = kids0.ru_utime.tv_sec as i64 * 1_000_000 + kids0.ru_utime.tv_usec as i64;

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    let mut kids: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut kids) };
    let kid_us = kids.ru_utime.tv_sec as i64 * 1_000_000 + kids.ru_utime.tv_usec as i64;
    check!(h, burnt_us > 20_000, "the probe burnt measurable cpu in a thread first: {burnt_us}us");
    check!(h, kid_us - base_us < 20_000,
        "a child that did nothing did not inherit the group's accumulated cpu time: child added {}us (children {kid_us}us, baseline {base_us}us, thread burnt {burnt_us}us)",
        kid_us - base_us);

    h.group("times-children");
    // `tms_cutime`/`tms_cstime` were assigned from `tms_utime`/`tms_stime` --
    // the caller's own -- so times() told every process it had spent exactly as
    // long in its children as in itself, a process with no children included.
    let mut t0: libc::tms = unsafe { std::mem::zeroed() };
    unsafe { libc::times(&mut t0) };
    let kid = unsafe { libc::fork() };
    if kid == 0 {
        let mut acc = 0u64;
        for i in 0..80_000_000u64 { acc = acc.wrapping_add(i ^ acc.rotate_left(7)); }
        std::hint::black_box(acc);
        unsafe { libc::_exit(0) };
    }
    let mut st2 = 0;
    unsafe { libc::waitpid(kid, &mut st2, 0) };
    let mut t1: libc::tms = unsafe { std::mem::zeroed() };
    unsafe { libc::times(&mut t1) };
    let d_cutime = t1.tms_cutime - t0.tms_cutime;
    let d_utime = t1.tms_utime - t0.tms_utime;
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    check!(h, d_cutime >= 3,
        "a child that burnt cpu shows up in tms_cutime: +{d_cutime} ticks (hz={hz}, own +{d_utime})");
    check!(h, d_cutime > d_utime,
        "and the child's time is not just the caller's own read back: cutime +{d_cutime} vs utime +{d_utime}");

    std::process::exit(h.finish());
}
