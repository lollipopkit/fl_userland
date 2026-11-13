//! Process attributes a runtime reads at startup: CPU affinity, resource
//! limits, scheduling, umask, credentials, getrandom.
//!
//! These are the numbers language runtimes size themselves from. Node, Go and
//! rayon all pick a thread-pool size from the affinity mask, so a wrong answer
//! there is a performance bug that never reports itself — a runtime that thinks
//! it has one CPU is single-threaded, and one that thinks it has 128
//! oversubscribes. `getrlimit(RLIMIT_NOFILE)` sizes descriptor tables the same
//! way, and a wrong `umask` silently changes the mode of every file a build
//! writes.
//!
//! None of it was covered.

use guest_tests::{Harness, check, check_fails, sys};

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn t_affinity(h: &mut Harness) {
    h.group("affinity");
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set)
    };
    if r != 0 {
        check!(h, false, "sched_getaffinity failed: errno {}", sys::errno());
        return;
    }
    let n = unsafe { libc::CPU_COUNT(&set) };
    check!(h, n >= 1, "the affinity mask names at least one CPU, got {n}");
    // A runtime divides work by this. An emulator reporting hundreds would have
    // Node and Go spawn hundreds of threads onto however many the host has.
    check!(h, n <= 1024, "and a plausible number of them, got {n}");
    check!(
        h,
        unsafe { libc::CPU_ISSET(0, &set) },
        "including CPU 0, which everything assumes"
    );

    // The same question about another process: pid 1 exists.
    let mut other: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::sched_getaffinity(1, std::mem::size_of::<libc::cpu_set_t>(), &mut other)
    };
    check!(h, r == 0, "sched_getaffinity of pid 1: {r} errno {}", sys::errno());

    check_fails!(
        h,
        unsafe {
            libc::sched_getaffinity(0x7fff_fff0, std::mem::size_of::<libc::cpu_set_t>(), &mut other)
        },
        libc::ESRCH,
        "a pid that does not exist"
    );

    // Setting a mask and reading it back. This used to accept any mask and
    // store nothing, so a program that pinned itself was told, by the next
    // call, that it had not.
    let mut one: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::CPU_SET(0, &mut one) };
    let r = unsafe {
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &one)
    };
    check!(h, r == 0, "sched_setaffinity to CPU 0 alone: {r} errno {}", sys::errno());
    let mut back: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut back)
    };
    check!(
        h,
        unsafe { libc::CPU_COUNT(&back) } == 1 && unsafe { libc::CPU_ISSET(0, &back) },
        "and it reads back as exactly CPU 0, got {} CPUs",
        unsafe { libc::CPU_COUNT(&back) }
    );

    // An empty mask names no processor to run on, which is EINVAL rather than
    // a thread that may run nowhere.
    let empty: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    check_fails!(
        h,
        unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &empty) },
        libc::EINVAL,
        "an empty affinity mask"
    );

    // Put it back, so the checks after this see the machine as it is.
    let r = unsafe {
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
    };
    check!(h, r == 0, "restoring the original mask: {r}");

    // _SC_NPROCESSORS_ONLN comes from the same place and must agree, or a
    // runtime that asks one way sizes itself differently from one that asks the
    // other.
    let sysconf_n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    check!(
        h,
        sysconf_n >= 1,
        "_SC_NPROCESSORS_ONLN is at least 1, got {sysconf_n}"
    );

    // The length rules, through the raw syscall: musl's wrapper returns 0 on
    // success and zero-fills the tail itself, so the number the kernel returns
    // -- how many bytes it wrote -- is invisible through it.
    //
    // Linux refuses a length that is not a whole number of `unsigned long`s.
    // The mask is an array of them, and a partial one is a request it has no
    // way to answer, so `len & (sizeof(unsigned long) - 1)` is EINVAL before
    // anything else.
    let mut buf = [0u8; 128];
    for len in [1usize, 3, 7, 9] {
        check_fails!(
            h,
            unsafe { libc::syscall(libc::SYS_sched_getaffinity, 0, len, buf.as_mut_ptr()) },
            libc::EINVAL,
            "sched_getaffinity with a length of {len}, which is not a whole number of longs"
        );
    }

    // And what it does return is that many bytes, which is a multiple of the
    // same thing and no more than was asked for.
    let r = unsafe { libc::syscall(libc::SYS_sched_getaffinity, 0, 128usize, buf.as_mut_ptr()) };
    check!(
        h,
        r > 0 && r <= 128 && r % (std::mem::size_of::<libc::c_ulong>() as i64) == 0,
        "sched_getaffinity returns the byte count it wrote: {r}"
    );
    // A length below what the mask needs is EINVAL rather than a short answer.
    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_sched_getaffinity, 0, 0usize, buf.as_mut_ptr()) },
        libc::EINVAL,
        "sched_getaffinity with a length of zero"
    );
}

fn t_rlimits(h: &mut Harness) {
    h.group("rlimit");
    let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
    check!(
        h,
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0,
        "getrlimit(RLIMIT_NOFILE): errno {}",
        sys::errno()
    );
    check!(
        h,
        lim.rlim_cur >= 16,
        "the soft descriptor limit is usable, got {}",
        lim.rlim_cur
    );
    check!(
        h,
        lim.rlim_cur <= lim.rlim_max,
        "soft {} does not exceed hard {}",
        lim.rlim_cur,
        lim.rlim_max
    );

    // Lowering the soft limit and reading it back.
    let saved = lim.rlim_cur;
    let mut lower = lim;
    lower.rlim_cur = 64.min(lim.rlim_max);
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lower) } == 0 {
        let mut back: libc::rlimit = unsafe { std::mem::zeroed() };
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut back) };
        check!(
            h,
            back.rlim_cur == lower.rlim_cur,
            "a lowered soft limit reads back: {} wanted {}",
            back.rlim_cur,
            lower.rlim_cur
        );
        let mut restore = lower;
        restore.rlim_cur = saved;
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &restore) };
    } else {
        check!(h, false, "setrlimit(RLIMIT_NOFILE): errno {}", sys::errno());
    }

    // Raising the soft limit above the hard limit is EINVAL, not a silent clamp
    // -- a runtime that asks for more than it may have needs to be told.
    let mut too_much = lim;
    if lim.rlim_max != libc::RLIM_INFINITY {
        too_much.rlim_cur = lim.rlim_max + 1;
        check_fails!(
            h,
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &too_much) },
            libc::EINVAL,
            "a soft limit above the hard limit"
        );
    }

    // RLIMIT_STACK is what a threading library reads to size thread stacks.
    let mut st: libc::rlimit = unsafe { std::mem::zeroed() };
    check!(
        h,
        unsafe { libc::getrlimit(libc::RLIMIT_STACK, &mut st) } == 0,
        "getrlimit(RLIMIT_STACK): errno {}",
        sys::errno()
    );
    check!(
        h,
        st.rlim_cur == libc::RLIM_INFINITY || st.rlim_cur >= 64 * 1024,
        "the stack limit is usable, got {}",
        st.rlim_cur
    );

    // prlimit64 on self is the modern spelling of both.
    let mut got: libc::rlimit = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::syscall(
            libc::SYS_prlimit64,
            0,
            libc::RLIMIT_NOFILE,
            std::ptr::null::<libc::rlimit>(),
            &mut got,
        )
    };
    check!(h, r == 0, "prlimit64 reads: {r} errno {}", sys::errno());
    check!(
        h,
        got.rlim_cur == saved,
        "and agrees with getrlimit: {} vs {saved}",
        got.rlim_cur
    );
}

fn t_scheduling(h: &mut Harness) {
    h.group("sched");
    check!(h, unsafe { libc::sched_yield() } == 0, "sched_yield");

    // Through the raw syscall, not musl's wrapper: musl does not implement the
    // SCHED_* API and its sched_getscheduler is a stub that returns ENOSYS
    // regardless of what the kernel would have said. Asking it says nothing
    // about the emulator.
    let pol = unsafe { libc::syscall(libc::SYS_sched_getscheduler, 0) };
    check!(
        h,
        pol == libc::SCHED_OTHER as i64,
        "the scheduling policy is SCHED_OTHER, got {pol} errno {}",
        sys::errno()
    );

    let max = unsafe { libc::syscall(libc::SYS_sched_get_priority_max, libc::SCHED_OTHER) };
    let min = unsafe { libc::syscall(libc::SYS_sched_get_priority_min, libc::SCHED_OTHER) };
    check!(
        h,
        max == 0 && min == 0,
        "SCHED_OTHER has one priority, got min {min} max {max}"
    );

    // **The real-time policies, because SCHED_OTHER cannot tell the two calls
    // apart.** Both answer 0 there, so an implementation that read `max` where
    // it meant `min` passed the check above and nothing else looked: they share
    // one table and differ only by which element of the tuple they take.
    // SCHED_FIFO and SCHED_RR are 1..99 on Linux, which is where a swap shows.
    for (policy, name) in [(libc::SCHED_FIFO, "SCHED_FIFO"), (libc::SCHED_RR, "SCHED_RR")] {
        let max = unsafe { libc::syscall(libc::SYS_sched_get_priority_max, policy) };
        let min = unsafe { libc::syscall(libc::SYS_sched_get_priority_min, policy) };
        check!(h, max == 99, "{name} priority max is 99, got {max}");
        check!(h, min == 1, "{name} priority min is 1, got {min}");
    }

    // The rest of the policies answer 0, and one that does not exist answers
    // EINVAL. SCHED_ISO is 4 and Linux has never implemented it.
    for (policy, name) in [(libc::SCHED_BATCH, "SCHED_BATCH"), (libc::SCHED_IDLE, "SCHED_IDLE")] {
        let max = unsafe { libc::syscall(libc::SYS_sched_get_priority_max, policy) };
        let min = unsafe { libc::syscall(libc::SYS_sched_get_priority_min, policy) };
        check!(h, max == 0 && min == 0, "{name} has one priority, got min {min} max {max}");
    }
    // And `sched_setscheduler` must accept the two it has priorities for.
    //
    // It refused them until 2026-09-07, which was inconsistent with the four
    // lines above: the same crate's priority table has known `SCHED_BATCH` and
    // `SCHED_IDLE` since it was written. Neither needs privilege, neither
    // promises anything a guest can observe -- they weight a runnable task --
    // so the contract is to remember and report, like `ioprio` and the timer
    // slack. A program that puts a background worker on `SCHED_IDLE` was
    // getting an error from a call that cannot fail on Linux for an
    // unprivileged valid request.
    //
    // In a **child** each time: Linux will not let an unprivileged thread leave
    // `SCHED_IDLE` again, so setting it here would change every later check.
    for (policy, name) in [
        (libc::SCHED_OTHER, "SCHED_OTHER"),
        (libc::SCHED_BATCH, "SCHED_BATCH"),
        (libc::SCHED_IDLE, "SCHED_IDLE"),
    ] {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let param: [i32; 1] = [0];
            let set = unsafe {
                libc::syscall(libc::SYS_sched_setscheduler, 0, policy, param.as_ptr())
            };
            let back = unsafe { libc::syscall(libc::SYS_sched_getscheduler, 0) };
            // Exit 0 only if both halves held; the parent turns that into the
            // check, because a child's `check!` writes to its own harness.
            let ok = set == 0 && back == policy as i64;
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        check!(
            h,
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
            "{name} is accepted and read back, status {st:#x}"
        );
    }

    // The realtime ones stay EINVAL, and that is the pair that makes the four
    // checks above a statement rather than a blanket "accept everything": this
    // kernel cannot preempt, so a program told it has SCHED_FIFO would build on
    // a guarantee that is not there.
    for (policy, name) in [(libc::SCHED_FIFO, "SCHED_FIFO"), (libc::SCHED_RR, "SCHED_RR")] {
        let param: [i32; 1] = [0];
        sys::clear_errno();
        let r = unsafe { libc::syscall(libc::SYS_sched_setscheduler, 0, policy, param.as_ptr()) };
        check!(
            h,
            r == -1 && sys::errno() == libc::EINVAL,
            "{name} is refused with EINVAL, got {r} errno {}",
            sys::errno()
        );
    }

    sys::clear_errno();
    let r = unsafe { libc::syscall(libc::SYS_sched_get_priority_max, 4) };
    check!(
        h,
        r == -1 && sys::errno() == libc::EINVAL,
        "sched_get_priority_max(4) is EINVAL, got {r} errno {}",
        sys::errno()
    );

    // getpriority answers through errno, so it has to be cleared first.
    sys::clear_errno();
    let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
    check!(
        h,
        sys::errno() == 0,
        "getpriority succeeded: errno {}",
        sys::errno()
    );
    check!(
        h,
        (-20..=19).contains(&nice),
        "and returned a nice value in range, got {nice}"
    );

    // Raising the nice value is always allowed; lowering it needs privilege, so
    // only the direction that must work is checked.
    let r = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice + 1) };
    if r == 0 {
        sys::clear_errno();
        let after = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
        check!(
            h,
            after == nice + 1,
            "a raised nice value reads back: {after} wanted {}",
            nice + 1
        );
        unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };
    } else {
        check!(h, false, "setpriority: errno {}", sys::errno());
    }
}

fn t_umask(h: &mut Harness, dir: &str) {
    h.group("umask");
    let old = unsafe { libc::umask(0o022) };
    check!(
        h,
        (0..=0o777).contains(&(old as i32)),
        "umask returns the previous mask, got {old:o}"
    );
    let again = unsafe { libc::umask(0o077) };
    check!(h, again == 0o022, "and it is the one just set, got {again:o}");

    // The mask is applied to a created file, which is the whole point of it.
    let path = format!("{dir}/masked");
    let _ = std::fs::remove_file(&path);
    let fd = unsafe {
        libc::open(cstr(&path).as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o666)
    };
    check!(h, fd >= 0, "creating a file under umask 077");
    if fd >= 0 {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        unsafe { libc::fstat(fd, &mut st) };
        let mode = st.st_mode & 0o777;
        check!(
            h,
            mode == 0o600,
            "0666 under umask 077 gives 0600, got {mode:o}"
        );
        sys::close(fd);
    }

    // And to a directory.
    let dpath = format!("{dir}/maskeddir");
    let _ = std::fs::remove_dir_all(&dpath);
    check!(
        h,
        unsafe { libc::mkdir(cstr(&dpath).as_ptr(), 0o777) } == 0,
        "creating a directory under umask 077"
    );
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(cstr(&dpath).as_ptr(), &mut st) } == 0 {
        let mode = st.st_mode & 0o777;
        check!(
            h,
            mode == 0o700,
            "0777 under umask 077 gives 0700, got {mode:o}"
        );
    }
    unsafe { libc::umask(old) };
}

fn t_credentials(h: &mut Harness) {
    h.group("credentials");
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getgid() };
    let egid = unsafe { libc::getegid() };
    check!(h, uid == euid, "uid {uid} and euid {euid} agree at startup");
    check!(h, gid == egid, "gid {gid} and egid {egid} agree at startup");

    let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
    check!(
        h,
        unsafe { libc::getresuid(&mut r, &mut e, &mut s) } == 0,
        "getresuid: errno {}",
        sys::errno()
    );
    check!(
        h,
        r == uid && e == euid,
        "getresuid agrees with getuid/geteuid: {r} {e} vs {uid} {euid}"
    );
    let (mut gr, mut ge, mut gs) = (0u32, 0u32, 0u32);
    check!(
        h,
        unsafe { libc::getresgid(&mut gr, &mut ge, &mut gs) } == 0,
        "getresgid: errno {}",
        sys::errno()
    );
    check!(
        h,
        gr == gid && ge == egid,
        "getresgid agrees: {gr} {ge} vs {gid} {egid}"
    );
    let _ = (s, gs);

    // A list of our own, so the checks below run wherever this does.
    //
    // They used to be inside `if n > 0`, and the emulator's first process has
    // no supplementary groups while a container's has eleven -- so the block
    // ran on Linux and never here, and the two checks it holds covered
    // nothing. That is what differential.sh's check *count* is for; the names
    // of the failing checks matched perfectly, because a check that does not
    // run does not fail.
    let want: [libc::gid_t; 3] = [11, 22, 33];
    let set = unsafe { libc::setgroups(want.len(), want.as_ptr()) };
    check!(h, set == 0, "setgroups of three groups: {set} errno {}", sys::errno());

    // getgroups with a zero count reports how many there are without writing.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    check!(h, n == want.len() as i32, "getgroups(0, NULL) counts them: {n} errno {}", sys::errno());
    let mut buf = vec![0 as libc::gid_t; want.len()];
    let got = unsafe { libc::getgroups(buf.len() as i32, buf.as_mut_ptr()) };
    check!(h, got == want.len() as i32, "and reading them back gives the same count: {got}");
    buf.sort_unstable();
    check!(h, buf == want, "and the same groups: {buf:?}");
    // Too small a buffer is EINVAL, not a truncated answer.
    check_fails!(
        h,
        unsafe { libc::getgroups(buf.len() as i32 - 1, buf.as_mut_ptr()) },
        libc::EINVAL,
        "getgroups with a buffer one too small"
    );
    // A count of zero is the "how many" form even when there are some, so it
    // must not be read as "a buffer one too small" and refused.
    check!(
        h,
        unsafe { libc::getgroups(0, std::ptr::null_mut()) } == want.len() as i32,
        "and a zero count still counts rather than failing"
    );

    check!(h, unsafe { libc::getpid() } > 0, "getpid is positive");
    check!(h, unsafe { libc::getppid() } >= 0, "getppid is not negative");
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    check!(
        h,
        tid == unsafe { libc::getpid() } as i64,
        "the main thread's tid is the pid: {tid}"
    );
    let sid = unsafe { libc::getsid(0) };
    check!(h, sid > 0, "getsid: {sid} errno {}", sys::errno());
    let pgid = unsafe { libc::getpgid(0) };
    check!(h, pgid > 0, "getpgid: {pgid} errno {}", sys::errno());
}

fn t_getrandom(h: &mut Harness) {
    h.group("getrandom");
    // Every runtime seeds its hash tables from this. Zeros would be a security
    // problem that nothing reports.
    let mut a = [0u8; 32];
    let n = unsafe {
        libc::syscall(libc::SYS_getrandom, a.as_mut_ptr(), a.len(), 0) as isize
    };
    check!(h, n == 32, "getrandom filled the buffer: {n} errno {}", sys::errno());
    check!(h, a.iter().any(|&b| b != 0), "and not with zeroes: {a:02x?}");

    let mut b = [0u8; 32];
    unsafe { libc::syscall(libc::SYS_getrandom, b.as_mut_ptr(), b.len(), 0) };
    check!(h, a != b, "two calls differ");

    // A request larger than any internal buffer must still be answered. Linux
    // fills up to 32 MB in one call; this used to return EIO past one megabyte,
    // so a program asking for two megabytes of randomness simply failed.
    let mut big = vec![0u8; 2 * 1024 * 1024];
    let n = unsafe {
        libc::syscall(libc::SYS_getrandom, big.as_mut_ptr(), big.len(), 0) as isize
    };
    check!(
        h,
        n == big.len() as isize,
        "getrandom of two megabytes: {n} errno {}",
        sys::errno()
    );
    if n > 0 {
        let filled = &big[..n as usize];
        check!(
            h,
            filled.iter().any(|&b| b != 0),
            "and it is not all zeroes"
        );
        // Randomness across the whole range, not just the first chunk.
        check!(
            h,
            filled[filled.len() - 1024..].iter().any(|&b| b != 0),
            "including the far end of the buffer"
        );
    }

    // A zero-length request is legal and returns 0.
    let n = unsafe { libc::syscall(libc::SYS_getrandom, a.as_mut_ptr(), 0usize, 0) };
    check!(h, n == 0, "a zero-length getrandom returns 0, got {n}");

    // An unknown flag is EINVAL rather than being ignored.
    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_getrandom, a.as_mut_ptr(), a.len(), 0xffff) },
        libc::EINVAL,
        "an unknown getrandom flag"
    );
}

/// `prctl`, and whether a thread name can be read back.
///
/// Two options were implemented -- `PR_SET_KEEPCAPS` as a stub and
/// `PR_SET_NAME` -- and everything else answered `EINVAL`, including
/// `PR_GET_NAME`. A program could set its name and never read it, and there
/// was no `/proc/<pid>/comm` either, so the name went nowhere observable at
/// all. Every threaded runtime names its threads; `ps`, a profiler and a
/// crash reporter all read them back.
fn t_prctl(h: &mut Harness) {
    h.group("prctl");
    const PR_SET_PDEATHSIG: i32 = 1;
    const PR_GET_PDEATHSIG: i32 = 2;
    const PR_GET_DUMPABLE: i32 = 3;
    const PR_SET_DUMPABLE: i32 = 4;
    const PR_SET_NAME: i32 = 15;
    const PR_GET_NAME: i32 = 16;
    const PR_SET_CHILD_SUBREAPER: i32 = 36;
    const PR_GET_CHILD_SUBREAPER: i32 = 37;
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    const PR_GET_NO_NEW_PRIVS: i32 = 39;

    let set = unsafe { libc::prctl(PR_SET_NAME, c"shellbox-t".as_ptr()) };
    check!(h, set == 0, "PR_SET_NAME: {set} errno {}", sys::errno());

    let mut name = [0u8; 32];
    let got = unsafe { libc::prctl(PR_GET_NAME, name.as_mut_ptr()) };
    check!(h, got == 0, "PR_GET_NAME: {got} errno {}", sys::errno());
    let end = name.iter().position(|&c| c == 0).unwrap_or(0);
    check!(
        h,
        &name[..end] == b"shellbox-t",
        "and it reads back what was set: {:?}",
        String::from_utf8_lossy(&name[..end])
    );

    // The same name through procfs, which is where everything else looks.
    let comm = std::fs::read_to_string("/proc/self/comm").unwrap_or_default();
    check!(
        h,
        comm.trim_end() == "shellbox-t",
        "/proc/self/comm agrees: {comm:?}"
    );

    // A name longer than the field is truncated, not refused.
    let long = c"0123456789abcdefghij";
    check!(
        h,
        unsafe { libc::prctl(PR_SET_NAME, long.as_ptr()) } == 0,
        "a name longer than 16 bytes is accepted"
    );
    let mut name = [0u8; 32];
    unsafe { libc::prctl(PR_GET_NAME, name.as_mut_ptr()) };
    let end = name.iter().position(|&c| c == 0).unwrap_or(0);
    check!(
        h,
        end == 15,
        "and truncated to fifteen characters and a NUL, got {end}: {:?}",
        String::from_utf8_lossy(&name[..end])
    );

    // The parent-death signal, stored and reported.
    check!(
        h,
        unsafe { libc::prctl(PR_SET_PDEATHSIG, libc::SIGTERM) } == 0,
        "PR_SET_PDEATHSIG: errno {}",
        sys::errno()
    );
    let mut sig: i32 = -1;
    check!(
        h,
        unsafe { libc::prctl(PR_GET_PDEATHSIG, &raw mut sig) } == 0 && sig == libc::SIGTERM,
        "PR_GET_PDEATHSIG reads it back, got {sig}"
    );
    check_fails!(
        h,
        unsafe { libc::prctl(PR_SET_PDEATHSIG, 999) },
        libc::EINVAL,
        "a signal number that does not exist"
    );
    // The boundary, which is where the bug was.
    //
    // 999 is refused by any check that is roughly right. 65 is refused only by
    // one that is exactly right: the signal arrays are indexed by the number
    // itself and sized MAX_SIG + 1, so 64 is the last valid index and 65 is one
    // past the end. This checked `sig > NUM_SIGS`, which is 65 -- so 65 was
    // stored, and when the parent exited it was used to index the disposition
    // array and to build a mask by shifting 1 left 64 places.
    //
    // A bound test that does not test the bound proves the bound is
    // approximately somewhere.
    check!(
        h,
        unsafe { libc::prctl(PR_SET_PDEATHSIG, 64) } == 0,
        "the highest real signal is accepted: errno {}",
        sys::errno()
    );
    check_fails!(
        h,
        unsafe { libc::prctl(PR_SET_PDEATHSIG, 65) },
        libc::EINVAL,
        "one past the highest real signal"
    );
    check_fails!(
        h,
        unsafe { libc::prctl(PR_SET_PDEATHSIG, -1) },
        libc::EINVAL,
        "a negative signal number"
    );
    // Zero disarms it.
    check!(
        h,
        unsafe { libc::prctl(PR_SET_PDEATHSIG, 0) } == 0,
        "disarming it"
    );

    // no_new_privs is one-way: once set it cannot be cleared.
    check!(
        h,
        unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 0,
        "PR_GET_NO_NEW_PRIVS starts at 0: errno {}",
        sys::errno()
    );
    check!(
        h,
        unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
        "setting it: errno {}",
        sys::errno()
    );
    check!(
        h,
        unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1,
        "and it reads back as 1"
    );
    check_fails!(
        h,
        unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) },
        libc::EINVAL,
        "clearing it, which Linux does not allow"
    );

    // dumpable, stored and reported.
    check!(
        h,
        unsafe { libc::prctl(PR_GET_DUMPABLE) } == 1,
        "PR_GET_DUMPABLE starts at 1: errno {}",
        sys::errno()
    );
    check!(h, unsafe { libc::prctl(PR_SET_DUMPABLE, 0) } == 0, "clearing it");
    check!(h, unsafe { libc::prctl(PR_GET_DUMPABLE) } == 0, "and it reads back as 0");
    unsafe { libc::prctl(PR_SET_DUMPABLE, 1) };
    check_fails!(
        h,
        unsafe { libc::prctl(PR_SET_DUMPABLE, 7) },
        libc::EINVAL,
        "a value that is not 0, 1 or 2"
    );

    // child_subreaper, stored and reported.
    check!(
        h,
        unsafe { libc::prctl(PR_SET_CHILD_SUBREAPER, 1) } == 0,
        "PR_SET_CHILD_SUBREAPER: errno {}",
        sys::errno()
    );
    let mut sub: i32 = -1;
    check!(
        h,
        unsafe { libc::prctl(PR_GET_CHILD_SUBREAPER, &raw mut sub) } == 0 && sub == 1,
        "and reads back, got {sub}"
    );
    unsafe { libc::prctl(PR_SET_CHILD_SUBREAPER, 0) };

    // An option that is genuinely not implemented is still EINVAL.
    check_fails!(
        h,
        unsafe { libc::prctl(0x7fff_0000, 0, 0, 0, 0) },
        libc::EINVAL,
        "an option that does not exist"
    );
}

/// Whether `PR_SET_PDEATHSIG` and `PR_SET_CHILD_SUBREAPER` do anything, as
/// opposed to being stored and reported.
///
/// The checks above only ask that a value written comes back. That is exactly
/// the shape that let `SCM_RIGHTS` and inotify pass their tests while doing
/// nothing, so these two ask what actually happens.
fn t_prctl_behaviour(h: &mut Harness) {
    h.group("prctl-effect");
    const PR_SET_PDEATHSIG: i32 = 1;
    const PR_SET_CHILD_SUBREAPER: i32 = 36;

    // --- the parent-death signal ---
    // A grandchild arms it, its parent exits, and the signal should arrive.
    let mut pipefd = [0i32; 2];
    let mut readyfd = [0i32; 2];
    if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0
        || unsafe { libc::pipe(readyfd.as_mut_ptr()) } != 0
    {
        check!(h, false, "pipe");
        return;
    }
    let (r, w) = (pipefd[0], pipefd[1]);
    // The middle process must not exit before the grandchild has armed
    // itself, or there is no parent death left to hear about. Linux has the
    // same race, which is why its manual says to check getppid() afterwards.
    let (ready_r, ready_w) = (readyfd[0], readyfd[1]);

    match unsafe { libc::fork() } {
        0 => {
            // The middle process: fork once more, wait to be told the
            // grandchild is ready, and exit.
            if unsafe { libc::fork() } == 0 {
                // The grandchild. SIGUSR1's default action would kill it, so
                // the report has to come from a handler.
                unsafe {
                    extern "C" fn on_usr1(_: i32) {}
                    let mut sa: libc::sigaction = std::mem::zeroed();
                    sa.sa_sigaction = on_usr1 as *const () as usize;
                    libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
                    libc::prctl(PR_SET_PDEATHSIG, libc::SIGUSR1);
                    libc::close(r);
                    libc::close(ready_r);
                    // Armed. The parent may now go.
                    let go: [u8; 1] = [b'!'];
                    libc::write(ready_w, go.as_ptr().cast(), 1);
                    libc::close(ready_w);
                    // Wait to be signalled, then say so. A bounded sleep, so a
                    // signal that never comes ends the test rather than the
                    // harness.
                    let mut ts = libc::timespec { tv_sec: 5, tv_nsec: 0 };
                    let mut rem = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                    let slept = libc::nanosleep(&mut ts, &mut rem);
                    let byte: [u8; 1] = if slept < 0 && sys::errno() == libc::EINTR {
                        [b'y']
                    } else {
                        [b'n']
                    };
                    libc::write(w, byte.as_ptr().cast(), 1);
                    libc::_exit(0);
                }
            }
            unsafe {
                libc::close(ready_w);
                let mut go = [0u8; 1];
                libc::read(ready_r, go.as_mut_ptr().cast(), 1);
                libc::_exit(0)
            };
        }
        child if child > 0 => {
            sys::close(w);
            sys::close(ready_r);
            sys::close(ready_w);
            // Reap the middle process so it is not left a zombie.
            let mut status = 0;
            unsafe { libc::waitpid(child, &mut status, 0) };
            let mut byte = [0u8; 1];
            let n = sys::read(r, &mut byte);
            check!(
                h,
                n == 1 && byte[0] == b'y',
                "a grandchild armed with PR_SET_PDEATHSIG is signalled when its parent exits: n={n} {:?}",
                byte[0] as char
            );
            sys::close(r);
        }
        _ => check!(h, false, "fork"),
    }

    // --- the subreaper ---
    // Without one, an orphan reparents to pid 1. With one, it stops here.
    if unsafe { libc::getpid() } == 1 {
        println!("  SKIP  [prctl-effect] running as pid 1: a subreaper cannot be told from init");
        return;
    }
    let mut pipefd = [0i32; 2];
    if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
        check!(h, false, "pipe");
        return;
    }
    let (r, w) = (pipefd[0], pipefd[1]);
    let me = unsafe { libc::getpid() };
    check!(
        h,
        unsafe { libc::prctl(PR_SET_CHILD_SUBREAPER, 1) } == 0,
        "becoming a subreaper"
    );

    match unsafe { libc::fork() } {
        0 => {
            if unsafe { libc::fork() } == 0 {
                // The grandchild: wait for its parent to go, then report who
                // it belongs to now.
                unsafe {
                    libc::close(r);
                    let start = libc::getppid();
                    for _ in 0..500 {
                        let now = libc::getppid();
                        if now != start {
                            break;
                        }
                        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 10_000_000 };
                        libc::nanosleep(&mut ts, std::ptr::null_mut());
                    }
                    let ppid = libc::getppid();
                    libc::write(w, (&raw const ppid).cast(), 4);
                    libc::_exit(0);
                }
            }
            unsafe { libc::_exit(0) };
        }
        child if child > 0 => {
            sys::close(w);
            let mut status = 0;
            unsafe { libc::waitpid(child, &mut status, 0) };
            let mut buf = [0u8; 4];
            let n = sys::read(r, &mut buf);
            let ppid = i32::from_le_bytes(buf);
            check!(
                h,
                n == 4 && ppid == me,
                "an orphaned grandchild reparents to the subreaper and not to init: got {ppid}, wanted {me}"
            );
            sys::close(r);
            // Reap it, since it is ours now.
            unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        }
        _ => check!(h, false, "fork"),
    }
    unsafe { libc::prctl(PR_SET_CHILD_SUBREAPER, 0) };
}

/// `capget`, which is asked what capabilities a process has.
///
/// It used to return 0 and write nothing, so the caller read its own buffer
/// back — whatever had been on its stack — and took that for a capability set.
/// A container runtime or a privilege-dropping tool asking "do I have
/// CAP_SYS_ADMIN?" got an answer from uninitialised memory.
fn t_capabilities(h: &mut Harness) {
    h.group("capabilities");
    const VERSION_1: u32 = 0x1998_0330;
    const VERSION_3: u32 = 0x2008_0522;

    #[repr(C)]
    #[derive(Clone, Copy)]
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

    // Poisoned, so "wrote nothing" is visible rather than looking like zero.
    let mut data = [Data { effective: 0xA5A5_A5A5, permitted: 0xA5A5_A5A5, inheritable: 0xA5A5_A5A5 }; 2];
    let mut hdr = Header { version: VERSION_3, pid: 0 };
    let r = unsafe {
        libc::syscall(libc::SYS_capget, &raw mut hdr, data.as_mut_ptr())
    };
    check!(h, r == 0, "capget: {r} errno {}", sys::errno());
    check!(
        h,
        data[0].effective != 0xA5A5_A5A5,
        "and it wrote the buffer: effective {:#x}",
        data[0].effective
    );
    check!(
        h,
        data[0].permitted != 0xA5A5_A5A5 && data[0].inheritable != 0xA5A5_A5A5,
        "all three sets: permitted {:#x} inheritable {:#x}",
        data[0].permitted,
        data[0].inheritable
    );
    // Version 3 has two elements, so the second must be written too.
    check!(
        h,
        data[1].effective != 0xA5A5_A5A5,
        "including the second element that version 3 asks for: {:#x}",
        data[1].effective
    );
    // The guest runs as root, so it has capabilities; effective must not
    // exceed permitted whoever it is.
    check!(
        h,
        data[0].effective & !data[0].permitted == 0,
        "effective is within permitted: {:#x} vs {:#x}",
        data[0].effective,
        data[0].permitted
    );
    if unsafe { libc::geteuid() } == 0 {
        check!(
            h,
            data[0].permitted != 0,
            "and root holds some, got {:#x}",
            data[0].permitted
        );
    }

    // Version 1 has one element, and the second must be left alone.
    let mut data1 = [Data { effective: 0xA5A5_A5A5, permitted: 0xA5A5_A5A5, inheritable: 0xA5A5_A5A5 }; 2];
    let mut hdr1 = Header { version: VERSION_1, pid: 0 };
    let r = unsafe {
        libc::syscall(libc::SYS_capget, &raw mut hdr1, data1.as_mut_ptr())
    };
    check!(h, r == 0, "capget with version 1: {r} errno {}", sys::errno());
    check!(
        h,
        data1[0].effective != 0xA5A5_A5A5 && data1[1].effective == 0xA5A5_A5A5,
        "writes one element and not two: {:#x} {:#x}",
        data1[0].effective,
        data1[1].effective
    );

    // An unsupported version is refused, with the preferred one written back
    // -- which is how a caller discovers what to ask for.
    let mut bad = Header { version: 0xdead_beef, pid: 0 };
    let r = unsafe {
        libc::syscall(libc::SYS_capget, &raw mut bad, data.as_mut_ptr())
    };
    check!(
        h,
        r < 0 && sys::errno() == libc::EINVAL,
        "an unsupported version is EINVAL: {r} errno {}",
        sys::errno()
    );
    check!(
        h,
        bad.version == VERSION_3,
        "and the preferred version is written back, got {:#x}",
        bad.version
    );

    // A negative pid is EINVAL.
    let mut neg = Header { version: VERSION_3, pid: -1 };
    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_capget, &raw mut neg, data.as_mut_ptr()) },
        libc::EINVAL,
        "a negative pid"
    );

    // capset on another process is EPERM, as on Linux.
    let mut other = Header { version: VERSION_3, pid: 1 };
    if unsafe { libc::getpid() } != 1 {
        check_fails!(
            h,
            unsafe { libc::syscall(libc::SYS_capset, &raw mut other, data.as_ptr()) },
            libc::EPERM,
            "capset naming another process"
        );
    }
    // And setting what is already held succeeds.
    let mut mine = Header { version: VERSION_3, pid: 0 };
    let r = unsafe { libc::syscall(libc::SYS_capset, &raw mut mine, data.as_ptr()) };
    check!(h, r == 0, "capset of the set already held: {r} errno {}", sys::errno());
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/pattrs".into());
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };
    let mut h = Harness::new();
    t_affinity(&mut h);
    t_rlimits(&mut h);
    t_scheduling(&mut h);
    t_umask(&mut h, &dir);
    t_credentials(&mut h);
    t_getrandom(&mut h);
    t_prctl(&mut h);
    t_prctl_behaviour(&mut h);
    t_capabilities(&mut h);
    std::process::exit(h.finish());
}
