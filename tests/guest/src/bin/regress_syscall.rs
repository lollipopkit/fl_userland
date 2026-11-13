//! The fs and wait fixes that had a user-visible symptom, each pinned so a
//! change that reintroduces one fails here rather than in somebody's shell.
//!
//! `tests/regress/regress_syscall.c` until 2026-09-09, where it needed an
//! aarch64 cross-compiler that is usually not installed — `tests/regress/run.sh`
//! *skipped* the whole thing when `aarch64-linux-musl-gcc` was absent, which is
//! how "regress: the cp cases passed; the compiled cases did not run" came to be
//! the normal outcome. It is cross-compiled with the rest of `tests/guest` now
//! and runs in `guest_tests.sh`.
//!
//! Some of these overlap `wait_semantics` and `wait_probe`, deliberately: what
//! is written here is the *shape a real program hit*, and the value of a
//! regression test is that it fails for the reason it was written for.
//!
//! The comment above each group records what the bug looked like before the
//! fix.

use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, Ordering};
use std::time::Instant;

use guest_tests::{check, check_fails, cpath, sys, Harness};

const FILE: &str = "/tmp/regress_file.txt";
const DIR: &str = "/tmp/regress_dir";
const LINK: &str = "/tmp/regress_link";

fn spawn(body: impl FnOnce() -> i32) -> i32 {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let code = body();
            libc::_exit(code);
        }
        pid
    }
}

fn waitpid(pid: i32, options: i32) -> (i32, i32) {
    let mut status = 0;
    let got = unsafe { libc::waitpid(pid, &mut status, options) };
    (got, status)
}

/// Reap every child that is ready, so a group whose checks are about *which*
/// child a wildcard wait answers is not answered by an earlier group's
/// leftover.
///
/// Six checks failed on both the emulator **and** a real kernel without this,
/// which is what said they were the test's fault: `waitid(P_ALL, ...)` reaps
/// whatever is ready, and what was ready was the child two cases earlier.
fn drain_children() {
    loop {
        let mut status = 0;
        // SAFETY: a non-blocking wildcard wait into a local.
        let got = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if got <= 0 {
            return;
        }
    }
}

fn nap(seconds: f64) {
    let t = libc::timespec {
        tv_sec: seconds as _,
        tv_nsec: ((seconds - seconds.trunc()) * 1e9) as _,
    };
    unsafe { libc::nanosleep(&t, std::ptr::null_mut()) };
}

/// Burn CPU rather than sleep, so the child is genuinely *running*. That is
/// what `cc1` does, and it is the shape that triggered the waitpid bug.
fn burn(seconds: f64) {
    let start = Instant::now();
    let mut x = 0u64;
    while start.elapsed().as_secs_f64() < seconds {
        for _ in 0..2000 {
            x = std::hint::black_box(x.wrapping_add(1));
        }
    }
}

/// Spend measurable user time and exit, for the cases that read a child's
/// accumulated CPU.
///
/// By *wall time*, not by an iteration count: the same count that registers
/// several ticks under the emulator is below one on a host, so a fixed count
/// makes these checks pass here and fail against a real kernel for a reason
/// that has nothing to do with the kernel.
fn spend_cpu() -> i32 {
    burn(0.15);
    0
}

/// The `siginfo_t` accessors, which `libc` declares `unsafe` because the
/// struct is a union and the fields are only meaningful for some `si_code`s.
///
/// Every call here follows a `waitid` or a `SIGCHLD` handler entry, which is
/// exactly the case these three are the right union arm for — so the obligation
/// is discharged once, here, rather than at forty call sites.
fn si_status(si: &libc::siginfo_t) -> i32 {
    // SAFETY: filled by `waitid` or by the kernel delivering SIGCHLD.
    unsafe { libc::siginfo_t::si_status(si) }
}

fn si_pid(si: &libc::siginfo_t) -> i32 {
    // SAFETY: as above.
    unsafe { libc::siginfo_t::si_pid(si) }
}

fn si_uid(si: &libc::siginfo_t) -> u32 {
    // SAFETY: as above.
    unsafe { libc::siginfo_t::si_uid(si) }
}

fn siginfo_zeroed() -> libc::siginfo_t {
    // SAFETY: `siginfo_t` is plain data and the kernel fills it.
    unsafe { std::mem::zeroed() }
}

/// #30 — `O_DIRECTORY` had the wrong value, so it was read as some other flag
/// and never enforced. `1 << 16` is `O_DIRECT` on aarch64 and was the one it
/// collided with.
fn t_o_directory(h: &mut Harness) {
    h.group("o-directory");

    check_fails!(
        h,
        sys::open(FILE, libc::O_RDONLY | libc::O_DIRECTORY, 0),
        libc::ENOTDIR,
        "open(regular file, O_DIRECTORY)"
    );
    check_fails!(
        h,
        sys::open(FILE, libc::O_PATH | libc::O_DIRECTORY, 0),
        libc::ENOTDIR,
        "open(regular file, O_PATH|O_DIRECTORY)"
    );

    // The other direction: the fix must not break real directories.
    let fd = sys::open(DIR, libc::O_RDONLY | libc::O_DIRECTORY, 0);
    check!(h, fd >= 0, "open(directory, O_DIRECTORY) still succeeds: {fd}");
    if fd >= 0 {
        sys::close(fd);
    }

    // SAFETY: a NUL-terminated path; the handle is closed below.
    let dp = unsafe { libc::opendir(cpath(DIR).as_ptr()) };
    check!(h, !dp.is_null(), "opendir(directory) still succeeds");
    if !dp.is_null() {
        let mut entries = 0;
        // SAFETY: `dp` is an open directory handle.
        while !unsafe { libc::readdir(dp) }.is_null() {
            entries += 1;
        }
        check!(h, entries > 0, "readdir() returns entries: {entries}");
        // SAFETY: as above.
        unsafe { libc::closedir(dp) };
    }

    check_fails!(
        h,
        sys::open(DIR, libc::O_WRONLY, 0),
        libc::EISDIR,
        "open(directory, O_WRONLY)"
    );

    let fd = sys::open(FILE, libc::O_RDONLY | libc::O_DIRECT, 0);
    check!(
        h,
        fd >= 0,
        "open(regular file, O_DIRECT) succeeds, so it is not read as O_DIRECTORY: {fd}"
    );
    if fd >= 0 {
        sys::close(fd);
    }

    // The values themselves, which is what was wrong. `libc`'s are the guest
    // ABI's, so this asks whether the kernel agrees with the program.
    check!(
        h,
        libc::O_DIRECTORY == 0x4000,
        "O_DIRECTORY is 0x4000 on aarch64, got {:#x}",
        libc::O_DIRECTORY
    );
    check!(
        h,
        libc::O_DIRECTORY & libc::O_DIRECT == 0,
        "O_DIRECTORY does not overlap O_DIRECT"
    );
    check!(
        h,
        libc::O_DIRECTORY & libc::O_NOFOLLOW == 0,
        "O_DIRECTORY does not overlap O_NOFOLLOW"
    );
    check!(
        h,
        libc::O_DIRECTORY & libc::O_PATH == 0,
        "O_DIRECTORY does not overlap O_PATH"
    );
}

/// #30 follow-up — `O_NOFOLLOW` was translated to the host `open()`, but the
/// VFS resolves the final component itself before the filesystem's `open()`
/// runs, so the host flag was a no-op and `open(symlink, O_NOFOLLOW)` returned
/// an fd to the *target*.
fn t_o_nofollow(h: &mut Harness) {
    h.group("o-nofollow");

    sys::unlink(LINK);
    if sys::symlink(FILE, LINK) != 0 {
        println!("  SKIP  cannot create {LINK}: {}", sys::strerror(sys::errno()));
        return;
    }

    check_fails!(
        h,
        sys::open(LINK, libc::O_RDONLY | libc::O_NOFOLLOW, 0),
        libc::ELOOP,
        "open(symlink, O_NOFOLLOW)"
    );

    let fd = sys::open(FILE, libc::O_RDONLY | libc::O_NOFOLLOW, 0);
    check!(h, fd >= 0, "open(regular file, O_NOFOLLOW) still succeeds: {fd}");
    if fd >= 0 {
        sys::close(fd);
    }

    let fd = sys::open(LINK, libc::O_RDONLY, 0);
    check!(h, fd >= 0, "open(symlink) without O_NOFOLLOW still follows: {fd}");
    if fd >= 0 {
        sys::close(fd);
    }

    sys::unlink(LINK);
}

/// #31 — `fakefs_stat`'s hook-routed branch zeroed the buffer and filled fields
/// by hand, and never set `st_dev`, `st_nlink` or `st_blksize`. `fstat` went
/// through realfs and did set them, so the two disagreed about one file — which
/// coreutils' `psame_inode()` reads as "replaced while being copied", and `cp`
/// refuses.
fn t_stat_fstat_agreement(h: &mut Harness, path: &str) {
    h.group("stat-fstat");

    let Some(s) = sys::stat(path) else {
        println!("  SKIP  stat({path}): {}", sys::strerror(sys::errno()));
        return;
    };
    let fd = sys::open(path, libc::O_RDONLY, 0);
    if fd < 0 {
        println!("  SKIP  open({path}): {}", sys::strerror(sys::errno()));
        return;
    }
    let Some(f) = sys::fstat(fd) else {
        println!("  SKIP  fstat({path}): {}", sys::strerror(sys::errno()));
        sys::close(fd);
        return;
    };

    check!(h, s.st_dev == f.st_dev, "stat.st_dev == fstat.st_dev");
    check!(h, s.st_ino == f.st_ino, "stat.st_ino == fstat.st_ino");
    check!(h, s.st_dev != 0, "stat.st_dev is not 0");
    check!(
        h,
        s.st_nlink > 0,
        "stat.st_nlink > 0, because 0 reads as an unlinked file"
    );
    check!(
        h,
        s.st_blksize > 0,
        "stat.st_blksize > 0, because 0 breaks cp's buffer sizing"
    );
    // Fields that were already right must stay right.
    check!(h, s.st_size == f.st_size, "stat.st_size == fstat.st_size");
    check!(h, s.st_mode == f.st_mode, "stat.st_mode == fstat.st_mode");
    check!(h, s.st_mtime == f.st_mtime, "stat.st_mtime == fstat.st_mtime");
    sys::close(fd);
}

/// #29 — `do_wait` waits with a one-second bounded timeout, a workaround for
/// macOS condvars, and tested `if (wait_for(...))`, which is true for `_EINTR`
/// **and** `_ETIMEDOUT`. So every expiry of that internal timeout was reported
/// to the guest as a signal: any child running longer than a second broke its
/// parent, and gcc died with "failed to get exit status: Interrupted system
/// call" at about 1.01 s.
fn t_waitpid_across_timeout(h: &mut Harness) {
    h.group("waitpid-timeout");

    // Straddle the boundary: the bug appears the moment a child outlives it.
    const POINTS: [f64; 6] = [0.2, 0.9, 1.0, 1.1, 1.5, 2.0];
    let mut bad = 0;
    for (i, &secs) in POINTS.iter().enumerate() {
        let pid = spawn(move || {
            // Alternate sleeping and burning, so a blocked child and a runnable
            // one are both covered.
            if i % 2 == 1 {
                burn(secs);
            } else {
                nap(secs);
            }
            40 + i as i32
        });
        sys::clear_errno();
        let (got, status) = waitpid(pid, 0);
        let ok = got == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 40 + i as i32;
        if !ok {
            bad += 1;
            println!(
                "  child {secs:.1}s -> waitpid={got} errno={} exited={} code={}",
                sys::errno(),
                libc::WIFEXITED(status),
                libc::WEXITSTATUS(status)
            );
        }
    }
    check!(
        h,
        bad == 0,
        "children at 0.2/0.9/1.0/1.1/1.5/2.0s are all reaped with no EINTR: {bad} were not"
    );

    // The zombie must actually be gone once waitpid returns.
    let pid = spawn(|| {
        nap(1.2);
        44
    });
    let (got, status) = waitpid(pid, 0);
    check!(
        h,
        got == pid && libc::WEXITSTATUS(status) == 44,
        "a slow child is reaped: {got}"
    );
    check_fails!(
        h,
        waitpid(pid, libc::WNOHANG).0,
        libc::ECHILD,
        "and leaves no zombie behind"
    );

    // Several concurrent slow children, reaped through wait().
    let kids: Vec<i32> = (0..3)
        .map(|i| {
            spawn(move || {
                burn(1.1 + 0.2 * f64::from(i));
                50 + i
            })
        })
        .collect();
    let mut reaped = 0;
    for _ in 0..kids.len() {
        let mut status = 0;
        // SAFETY: a plain `wait(2)` into a local.
        let got = unsafe { libc::wait(&mut status) };
        if got > 0 && libc::WIFEXITED(status) && (50..=52).contains(&libc::WEXITSTATUS(status)) {
            reaped += 1;
        }
    }
    check!(h, reaped == 3, "3 concurrent slow children all reaped by wait(): {reaped}");

    let mut status = 0;
    // SAFETY: as above.
    check_fails!(
        h,
        unsafe { libc::wait(&mut status) },
        libc::ECHILD,
        "wait() with no children left"
    );
}

/// A real signal must still interrupt `waitpid`. The #29 fix narrows the
/// "was interrupted" test to `_EINTR` alone, so this guards against
/// over-correcting it away.
fn t_signal_still_interrupts(h: &mut Harness) {
    h.group("signal-interrupts-wait");

    static HANDLER_RAN: AtomicU32 = AtomicU32::new(0);
    extern "C" fn on_usr1(_sig: i32) {
        HANDLER_RAN.store(1, Ordering::SeqCst);
    }
    // `sigaction` with no flags, **not** `signal()`: musl's `signal()` sets
    // `SA_RESTART`, so `waitpid` would be restarted rather than interrupted and
    // this case would assert the opposite of what it is for. It reported
    // "SIGUSR1 during waitpid gives EINTR: got=13 errno=0" the first time it
    // ran, which is the child being reaped normally four seconds later.
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = on_usr1 as *const () as libc::sighandler_t;
    sa.sa_flags = 0;
    // SAFETY: `on_usr1` only stores to an atomic, which is async-signal-safe.
    unsafe { libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) };
    HANDLER_RAN.store(0, Ordering::SeqCst);

    let child = spawn(|| {
        nap(4.0);
        7
    });
    let killer = spawn(|| {
        nap(0.3);
        // SAFETY: signalling this process's parent.
        unsafe { libc::kill(libc::getppid(), libc::SIGUSR1) };
        0
    });

    let start = Instant::now();
    sys::clear_errno();
    let (got, _) = waitpid(child, 0);
    let errno = sys::errno();
    let elapsed = start.elapsed().as_secs_f64();

    check!(
        h,
        got < 0 && errno == libc::EINTR,
        "SIGUSR1 during waitpid gives EINTR: got={got} errno={errno}"
    );
    check!(h, HANDLER_RAN.load(Ordering::SeqCst) == 1, "the handler ran");
    // If this fires at about a second, the internal timeout is being
    // misreported again.
    check!(
        h,
        elapsed < 1.0,
        "interrupted at the signal, not at the 1s internal timeout: {elapsed:.2}s"
    );
    let (got, status) = waitpid(child, 0);
    check!(
        h,
        got == child && libc::WEXITSTATUS(status) == 7,
        "the child is still reapable after EINTR: {got}"
    );
    waitpid(killer, 0);
    // SAFETY: restoring the default disposition.
    unsafe { libc::signal(libc::SIGUSR1, libc::SIG_DFL) };
}

/// `do_wait` produces the raw `wait(2)` status word, which is what `wait4`
/// wants. `sys_waitid` handed that straight to userspace instead of decoding
/// it, so `si_status` was 7936 for `exit(31)` — 31 << 8 — and `si_code` was
/// always 0, leaving a killed child indistinguishable from an exited one.
/// `si_uid` was never assigned at all on the wait path.
fn t_waitid_siginfo(h: &mut Harness) {
    h.group("waitid-siginfo");

    // SAFETY: no arguments, no failure mode.
    let me = unsafe { libc::getuid() };

    for (i, &code) in [0, 31, 255].iter().enumerate() {
        let pid = spawn(move || code);
        let mut si = siginfo_zeroed();
        // SAFETY: `si` is a live `siginfo_t`.
        let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED) };
        check!(
            h,
            r == 0 && si.si_code == libc::CLD_EXITED && si_status(&si) == code,
            "exit({code}) is CLD_EXITED with si_status={code}: r={r} code={} status={}",
            si.si_code,
            si_status(&si)
        );
        if i == 1 {
            check!(h, si.si_signo == libc::SIGCHLD, "si_signo is SIGCHLD");
            check!(h, si_pid(&si) == pid, "si_pid is the child: {}", si_pid(&si));
            check!(h, si_uid(&si) == me, "si_uid is the child's uid: {}", si_uid(&si));
        }
    }

    for (i, &sig) in [libc::SIGKILL, libc::SIGTERM].iter().enumerate() {
        let pid = spawn(|| {
            nap(10.0);
            0
        });
        nap(0.3);
        // SAFETY: signalling a child of this process.
        unsafe { libc::kill(pid, sig) };
        let mut si = siginfo_zeroed();
        // SAFETY: as above.
        let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED) };
        check!(
            h,
            r == 0 && si.si_code == libc::CLD_KILLED && si_status(&si) == sig,
            "killed by {sig} is CLD_KILLED with si_status={sig}: code={} status={}",
            si.si_code,
            si_status(&si)
        );
        if i == 0 {
            check!(h, si_uid(&si) == me, "si_uid is set on CLD_KILLED too");
        }
    }

    // A stop.
    {
        let pid = spawn(|| {
            nap(10.0);
            0
        });
        nap(0.3);
        // SAFETY: signalling a child of this process.
        unsafe { libc::kill(pid, libc::SIGSTOP) };
        let mut si = siginfo_zeroed();
        // SAFETY: `si` is a live `siginfo_t`.
        let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WSTOPPED) };
        check!(
            h,
            r == 0 && si.si_code == libc::CLD_STOPPED && si_status(&si) == libc::SIGSTOP,
            "SIGSTOP is CLD_STOPPED with si_status=SIGSTOP: code={} status={}",
            si.si_code,
            si_status(&si)
        );
        // SAFETY: as above.
        unsafe {
            libc::kill(pid, libc::SIGCONT);
            libc::kill(pid, libc::SIGKILL);
        }
        let mut reap = siginfo_zeroed();
        // SAFETY: as above.
        unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut reap, libc::WEXITED) };
    }

    // A child that drops privileges must report its **own** uid. This is the
    // only case that can distinguish the si_uid bug, since everything else here
    // runs as one uid.
    {
        let pid = spawn(|| {
            // SAFETY: a plain setuid in a child about to exit.
            if unsafe { libc::setuid(1000) } != 0 {
                return 99;
            }
            12
        });
        let mut si = siginfo_zeroed();
        // SAFETY: `si` is a live `siginfo_t`.
        let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED) };
        if r == 0 && si_status(&si) == 99 {
            println!("  SKIP  setuid(1000) not permitted here; cannot test a uid change");
        } else {
            check!(h, r == 0 && si_status(&si) == 12, "the child reached exit(12) after setuid(1000)");
            check!(
                h,
                si_uid(&si) == 1000,
                "si_uid is the child's 1000, not the parent's: {}",
                si_uid(&si)
            );
        }
    }

    // WNOHANG with nothing ready must not report a scanned candidate's uid.
    {
        let pid = spawn(|| {
            nap(1.0);
            13
        });
        nap(0.2);
        let mut si = siginfo_zeroed();
        // SAFETY: `si` is a live `siginfo_t`.
        let r = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut si,
                libc::WEXITED | libc::WNOHANG,
            )
        };
        check!(
            h,
            r == 0 && si_pid(&si) == 0,
            "WNOHANG reports si_pid=0 while the child runs: r={r} pid={}",
            si_pid(&si)
        );
        check!(h, si_uid(&si) == 0, "and leaves si_uid at 0, with no stale uid");
        let mut reap = siginfo_zeroed();
        // SAFETY: as above.
        unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut reap, libc::WEXITED) };
    }

    // wait4 and waitpid must keep seeing the *raw* encoding; only waitid
    // decodes.
    {
        let pid = spawn(|| 31);
        let (got, status) = waitpid(pid, 0);
        check!(
            h,
            got == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 31,
            "waitpid still sees the raw status: WIFEXITED/WEXITSTATUS"
        );

        let pid = spawn(|| {
            nap(10.0);
            0
        });
        nap(0.3);
        // SAFETY: signalling a child of this process.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let (got, status) = waitpid(pid, 0);
        check!(
            h,
            got == pid && libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL,
            "waitpid still sees the raw status: WIFSIGNALED/WTERMSIG"
        );
    }
}

/// #11 — Linux ignores `dirfd` when the path is absolute rather than validating
/// it. Every `*at` syscall here checked the descriptor first, so
/// `openat(-1, "/", ...)` answered `EBADF` where Linux opens the root. rpm's
/// file-state machine does exactly that, and every package in a dnf transaction
/// failed to unpack.
fn t_at_ignores_dirfd_for_absolute_paths(h: &mut Harness) {
    h.group("at-absolute");

    // SAFETY: NUL-terminated paths; each descriptor is closed.
    let fd = unsafe {
        libc::openat(-1, cpath("/").as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY)
    };
    check!(h, fd >= 0, "openat(-1, \"/\", O_DIRECTORY): {fd}");
    if fd >= 0 {
        sys::close(fd);
    }

    // A descriptor that is merely closed, rather than -1.
    let closed = sys::open("/", libc::O_RDONLY | libc::O_DIRECTORY, 0);
    if closed >= 0 {
        sys::close(closed);
    }
    // SAFETY: as above.
    let fd = unsafe {
        libc::openat(closed, cpath("/etc").as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY)
    };
    check!(h, fd >= 0, "openat(<closed fd>, \"/etc\", O_DIRECTORY): {fd}");
    if fd >= 0 {
        sys::close(fd);
    }

    // And the rule is not open()'s alone.
    let mut st: libc::stat = siginfo_stat();
    // SAFETY: a NUL-terminated path and a live `stat`.
    let r = unsafe { libc::fstatat(-1, cpath("/").as_ptr(), &mut st, 0) };
    check!(h, r == 0, "fstatat(-1, \"/\"): {r}");

    // A *relative* path with a bad descriptor is still EBADF.
    check_fails!(
        h,
        // SAFETY: as above.
        unsafe { libc::openat(-1, cpath("etc").as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) },
        libc::EBADF,
        "openat(-1, \"etc\") with a relative path"
    );
}

fn siginfo_stat() -> libc::stat {
    // SAFETY: `stat` is plain data and the kernel fills it.
    unsafe { std::mem::zeroed() }
}

/// #18 — what `waitid` is required to reject, report and preserve.
fn t_waitid_conformance(h: &mut Harness) {
    h.group("waitid-conformance");

    let pid = spawn(|| 3);
    check!(h, pid > 0, "fork: {pid}");
    nap(0.3);
    let mut si = siginfo_zeroed();

    // An option set that selects no event is EINVAL, not a wait.
    check_fails!(
        h,
        // SAFETY: `si` is a live `siginfo_t`.
        unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WNOHANG) },
        libc::EINVAL,
        "waitid with no WEXITED/WSTOPPED/WCONTINUED"
    );

    check_fails!(
        h,
        // SAFETY: as above.
        unsafe { libc::waitid(libc::P_PID, 0, &mut si, libc::WEXITED | libc::WNOHANG) },
        libc::EINVAL,
        "waitid(P_PID, 0)"
    );

    // The child is still there, and WNOWAIT leaves it there.
    let mut si = siginfo_zeroed();
    // SAFETY: as above.
    let r = unsafe {
        libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED | libc::WNOWAIT)
    };
    check!(h, r == 0 && si_status(&si) == 3, "WNOWAIT reports the exited child");
    let mut si = siginfo_zeroed();
    // SAFETY: as above.
    let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED) };
    check!(h, r == 0 && si_status(&si) == 3, "and leaves it for the next wait");

    // P_PGID with id 0 means the caller's own group.
    let pid = spawn(|| 5);
    nap(0.3);
    let mut si = siginfo_zeroed();
    // SAFETY: as above.
    let r = unsafe { libc::waitid(libc::P_PGID, 0, &mut si, libc::WEXITED | libc::WNOHANG) };
    check!(
        h,
        r == 0 && si_pid(&si) == pid,
        "waitid(P_PGID, 0) means this process group: r={r} pid={}",
        si_pid(&si)
    );

    // The times, which waitid does **not** report. This asserted the opposite
    // until 2026-09-09, from a comment in the kernel saying "waitid has no
    // rusage argument and reports these in the siginfo instead" -- and Linux's
    // `kernel_waitid` builds five fields and copies those. A container run
    // reads zero here for a child that burned 1.7 seconds.
    //
    // The SIGCHLD *signal* is the path that carries them; `t_sigchld_siginfo`
    // is where that is checked.
    let pid = spawn(spend_cpu);
    nap(0.7);
    let mut si = siginfo_zeroed();
    // SAFETY: as above.
    unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED) };
    check!(
        h,
        si_utime(&si) == 0,
        "waitid leaves si_utime alone, as Linux does: {}",
        si_utime(&si)
    );

    // A stop, reported twice under WNOWAIT, and then a continue.
    let pid = spawn(|| loop {
        // SAFETY: no arguments.
        unsafe { libc::pause() };
    });
    nap(0.3);
    // SAFETY: signalling a child of this process.
    unsafe { libc::kill(pid, libc::SIGSTOP) };
    nap(0.3);
    let mut si = siginfo_zeroed();
    // SAFETY: `si` is a live `siginfo_t`.
    let r1 = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut si,
            libc::WSTOPPED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    let first = si_status(&si);
    let mut si = siginfo_zeroed();
    // SAFETY: as above.
    let r2 = unsafe {
        libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WSTOPPED | libc::WNOHANG)
    };
    check!(
        h,
        r1 == 0 && first == libc::SIGSTOP && r2 == 0 && si_status(&si) == libc::SIGSTOP,
        "WNOWAIT leaves a stop for the next wait: r1={r1} first={first} r2={r2} second={}",
        si_status(&si)
    );

    // SAFETY: as above.
    unsafe { libc::kill(pid, libc::SIGCONT) };
    nap(0.4);
    let mut si = siginfo_zeroed();
    // SAFETY: as above.
    let r = unsafe {
        libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WCONTINUED | libc::WNOHANG)
    };
    check!(
        h,
        r == 0 && si.si_code == libc::CLD_CONTINUED,
        "WCONTINUED reports a continued child: r={r} code={}",
        si.si_code
    );
    // SAFETY: as above.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    waitpid(pid, 0);

    // **P_ALL does not look at the id**: Linux's `kernel_waitid` sets the type
    // and breaks without reading `upid`, so an id here is ignored rather than
    // rejected. This asserted EINVAL until 2026-09-09 -- written from this
    // kernel's implementation, and wrong about the kernel it is emulating.
    //
    // Last in the group, with a drain before it, because it reaps whatever is
    // ready and the check is *which* child it answered.
    drain_children();
    let only = spawn(|| 4);
    nap(0.3);
    let mut si = siginfo_zeroed();
    // SAFETY: `si` is a live `siginfo_t`.
    let r = unsafe { libc::waitid(libc::P_ALL, 12345, &mut si, libc::WEXITED | libc::WNOHANG) };
    check!(
        h,
        r == 0 && si_pid(&si) == only,
        "waitid(P_ALL) ignores the id and reaps: r={r} pid={} vs {only}",
        si_pid(&si)
    );
}

/// `si_utime`, which `libc`'s `siginfo_t` does not expose an accessor for.
///
/// #16: it and `si_stime` were 32-bit at offsets 28 and 32, where an AArch64
/// guest reads 64-bit ones at 32 and 40 — so a handler read `si_stime` as
/// `si_utime`. That hid #15, which is that nothing filled either.
fn si_utime(si: &libc::siginfo_t) -> i64 {
    // SAFETY: reading eight bytes at offset 32 of a 128-byte `siginfo_t`. The
    // offset is the AArch64 ABI's and is asserted in `t_sigchld_siginfo`.
    unsafe { (si as *const libc::siginfo_t).cast::<u8>().add(32).cast::<i64>().read_unaligned() }
}

/// #15 — `si_code` was `SI_KERNEL` (128) and `si_status` the raw `wait(2)` word
/// (7936 for a child that exited 31), because `do_exit` built the siginfo by
/// hand while `waitid` had been taught to decode it.
fn t_sigchld_siginfo(h: &mut Harness) {
    h.group("sigchld-siginfo");

    static SEEN: AtomicU32 = AtomicU32::new(0);
    static CODE: AtomicI32 = AtomicI32::new(0);
    static STATUS: AtomicI32 = AtomicI32::new(0);
    static PID: AtomicI32 = AtomicI32::new(0);
    static UTIME: AtomicI64 = AtomicI64::new(0);

    extern "C" fn on_sigchld(_sig: i32, si: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
        // SAFETY: the kernel hands a live `siginfo_t`; every store is atomic,
        // which is what makes this async-signal-safe.
        unsafe {
            CODE.store((*si).si_code, Ordering::SeqCst);
            STATUS.store(si_status(&*si), Ordering::SeqCst);
            PID.store(si_pid(&*si), Ordering::SeqCst);
            UTIME.store(si_utime(&*si), Ordering::SeqCst);
        }
        SEEN.store(1, Ordering::SeqCst);
    }

    let mut saved: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: reading the current disposition into a local.
    let r = unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut saved) };
    check!(h, r == 0, "read the SIGCHLD disposition: {r}");

    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = on_sigchld as *const () as usize;
    sa.sa_flags = libc::SA_SIGINFO;
    // SAFETY: installing a handler that only stores to atomics.
    let r = unsafe { libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut()) };
    check!(h, r == 0, "install an SA_SIGINFO handler: {r}");

    SEEN.store(0, Ordering::SeqCst);
    let pid = spawn(|| {
        spend_cpu();
        31
    });
    check!(h, pid > 0, "fork for the SIGCHLD case: {pid}");
    for _ in 0..150 {
        if SEEN.load(Ordering::SeqCst) == 1 {
            break;
        }
        nap(0.02);
    }
    let seen = SEEN.load(Ordering::SeqCst) == 1;
    check!(h, seen, "the handler ran");
    if seen {
        check!(h, PID.load(Ordering::SeqCst) == pid, "si_pid is the child");
        check!(
            h,
            CODE.load(Ordering::SeqCst) == libc::CLD_EXITED,
            "si_code is CLD_EXITED and not SI_KERNEL: {}",
            CODE.load(Ordering::SeqCst)
        );
        check!(
            h,
            STATUS.load(Ordering::SeqCst) == 31,
            "si_status is 31 and not the raw 31<<8: {}",
            STATUS.load(Ordering::SeqCst)
        );
        // The child spent real time; reading zero means the offset is wrong
        // again, since `do_exit` does fill this one.
        check!(
            h,
            UTIME.load(Ordering::SeqCst) > 0,
            "si_utime is where the guest reads it: {}",
            UTIME.load(Ordering::SeqCst)
        );
    }
    waitpid(pid, 0);

    // 128 bytes, which is what the guest's libc allocates. A short write leaves
    // the caller's own bytes in the tail.
    check!(
        h,
        size_of::<libc::siginfo_t>() == 128,
        "the guest siginfo_t is 128 bytes, got {}",
        size_of::<libc::siginfo_t>()
    );

    // SAFETY: putting back what was read above.
    let r = unsafe { libc::sigaction(libc::SIGCHLD, &saved, std::ptr::null_mut()) };
    check!(h, r == 0, "SIGCHLD disposition restored: {r}");
}

/// #17 — signal 64 is `SIGRTMAX` on AArch64, and the signal count made the
/// range 1..63.
fn t_sigrtmax(h: &mut Harness) {
    h.group("sigrtmax");

    let rtmax = libc::SIGRTMAX();
    check!(h, rtmax == 64, "the guest libc says SIGRTMAX is 64, got {rtmax}");

    for sig in 62..=rtmax {
        let mut saved: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = libc::SIG_IGN;
        // SAFETY: reading and then ignoring one real-time signal.
        let ok = unsafe {
            libc::sigaction(sig, std::ptr::null(), &mut saved) == 0
                && libc::sigaction(sig, &sa, std::ptr::null_mut()) == 0
        };
        check!(h, ok, "sigaction({sig})");
        // SAFETY: signalling this process with a signal it is ignoring.
        let r = unsafe { libc::kill(libc::getpid(), sig) };
        check!(h, r == 0, "kill(self, {sig}): {r}");
        if ok {
            // SAFETY: putting back what was read above.
            unsafe { libc::sigaction(sig, &saved, std::ptr::null_mut()) };
        }
    }
}

/// A parent that says it will never wait does not get zombies.
///
/// POSIX gives two ways to say it — `SIGCHLD` set to `SIG_IGN`, or
/// `SA_NOCLDWAIT` — and both mean a child is released as it exits rather than
/// kept for a wait that is not coming. Neither was implemented: `do_exit`
/// marked every child a zombie without consulting the parent's disposition, and
/// the only path that released one ran inside `wait(2)`. So
/// `signal(SIGCHLD, SIG_IGN); fork();` — the ordinary shape of a forking server
/// that does not collect its children — held a task, a tgroup and a pid per
/// child for the parent's life.
///
/// The probe is `waitpid`, not `/proc`: this procfs answers for live tasks
/// only, so a zombie is already invisible there and the obvious test passes
/// against the bug.
fn t_no_zombies_when_parent_will_not_wait(h: &mut Harness) {
    h.group("child-release");

    let mut saved: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: reading the current disposition into a local. Put back at the
    // end: every case after this one forks and waits, and SIG_DFL is not
    // necessarily what was here.
    let r = unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut saved) };
    check!(h, r == 0, "read the SIGCHLD disposition: {r}");

    let set = |handler: libc::sighandler_t, flags: libc::c_int| {
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = handler;
        sa.sa_flags = flags;
        // SAFETY: setting a disposition to one of the two constants.
        unsafe { libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut()) }
    };

    // Set it rather than assume it: if this program was launched by something
    // that had already ignored SIGCHLD, the control below would be auto-reaped
    // and would fail against a *correct* kernel. A suite has to own the state
    // it makes assertions about.
    check!(h, set(libc::SIG_DFL, 0) == 0, "SIGCHLD forced to SIG_DFL first");

    // The control. A parent that has not said anything keeps its zombie, and
    // must: it is still entitled to wait for it. Every check in this group uses
    // a wildcard wait, so nothing else may be pending.
    drain_children();
    let child = spawn(|| 0);
    nap(0.3);
    let (got, _) = waitpid(-1, libc::WNOHANG);
    check!(
        h,
        got == child,
        "the default disposition still keeps the zombie: {got} vs {child}"
    );

    check!(h, set(libc::SIG_IGN, 0) == 0, "sigaction(SIGCHLD, SIG_IGN)");
    spawn(|| 0);
    nap(0.3);
    check_fails!(
        h,
        waitpid(-1, libc::WNOHANG).0,
        libc::ECHILD,
        "SIG_IGN releases the child"
    );

    check!(
        h,
        set(libc::SIG_DFL, libc::SA_NOCLDWAIT) == 0,
        "sigaction(SIGCHLD, SA_NOCLDWAIT)"
    );
    spawn(|| 0);
    nap(0.3);
    check_fails!(
        h,
        waitpid(-1, libc::WNOHANG).0,
        libc::ECHILD,
        "SA_NOCLDWAIT releases the child"
    );

    // A released child's CPU time is **lost**, and its being lost is the
    // check: `wait_task_zombie` is the only place Linux moves a child's times
    // into the parent's `cutime`, and an auto-reaped child never reaches it.
    // This asserted the opposite until 2026-09-09, on the reasoning that
    // "releasing the child early is not a reason to lose them" -- true, and not
    // what Linux does.
    //
    // With the reaped case beside it as the control, because "unchanged" on its
    // own is also what a broken `getrusage` says.
    {
        let children_utime = || {
            let mut r: libc::rusage = unsafe { std::mem::zeroed() };
            // SAFETY: a live `rusage`.
            unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut r) };
            r.ru_utime.tv_sec * 1_000_000 + i64::from(r.ru_utime.tv_usec)
        };

        set(libc::SIG_IGN, 0);
        let before = children_utime();
        spawn(spend_cpu);
        nap(1.0);
        let released = children_utime() - before;
        check!(
            h,
            released == 0,
            "a released child's CPU time does not reach RUSAGE_CHILDREN: {released}us"
        );

        set(libc::SIG_DFL, 0);
        let before = children_utime();
        let pid = spawn(spend_cpu);
        waitpid(pid, 0);
        let reaped = children_utime() - before;
        check!(
            h,
            reaped > 0,
            "and a reaped one's does, which is what says the first is not a broken getrusage: {reaped}us"
        );
    }

    // A group whose leader exits first still has to be released whole. The
    // release names the leader rather than the last thread out for this reason:
    // naming the last one freed the group and left the leader's task and pid
    // waitable for the rest of the parent's life.
    {
        set(libc::SIG_IGN, 0);
        let pid = spawn(|| {
            let mut t: libc::pthread_t = std::ptr::null_mut();
            extern "C" fn worker(_: *mut libc::c_void) -> *mut libc::c_void {
                // SAFETY: a plain sleep.
                unsafe { libc::usleep(400_000) };
                std::ptr::null_mut()
            }
            // SAFETY: a thread whose body only sleeps.
            if unsafe { libc::pthread_create(&mut t, std::ptr::null(), worker, std::ptr::null_mut()) }
                != 0
            {
                return 1;
            }
            // The leader goes first; the worker is last out.
            // SAFETY: exiting this thread and leaving the process to the worker.
            unsafe { libc::pthread_exit(std::ptr::null_mut()) };
        });
        check!(h, pid > 0, "fork for the leader-exits-first case: {pid}");
        if pid > 0 {
            nap(1.5);
            check_fails!(
                h,
                waitpid(-1, libc::WNOHANG).0,
                libc::ECHILD,
                "a group whose leader exited first is released whole"
            );
        }
    }

    // SAFETY: putting back what was read above.
    let r = unsafe { libc::sigaction(libc::SIGCHLD, &saved, std::ptr::null_mut()) };
    check!(h, r == 0, "SIGCHLD disposition restored: {r}");
}

/// A write of nothing still asks the descriptor: `write(-1, p, 0)` answered 0
/// here until 2026-11-12, where Linux answers `EBADF`, and a pipe with no
/// reader answers 0 without a `SIGPIPE`.
fn t_empty_write(h: &mut Harness) {
    h.group("empty-write");
    let buf = [0u8; 1];
    check_fails!(h, unsafe { libc::write(-1, buf.as_ptr().cast(), 0) }, libc::EBADF, "write(-1, p, 0)");
    check_fails!(h, unsafe { libc::pwrite(-1, buf.as_ptr().cast(), 0, 0) }, libc::EBADF, "pwrite(-1, p, 0, 0)");
    unsafe {
        let mut old: libc::sigset_t = std::mem::zeroed();
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGPIPE);
        libc::sigprocmask(libc::SIG_BLOCK, &set, &mut old);
        let mut fds = [0i32; 2];
        libc::pipe(fds.as_mut_ptr());
        libc::close(fds[0]);
        let n = libc::write(fds[1], buf.as_ptr().cast(), 0);
        let mut pending: libc::sigset_t = std::mem::zeroed();
        libc::sigpending(&mut pending);
        check!(h, n == 0, "an empty write to a pipe with no reader is 0: {n}");
        check!(h, libc::sigismember(&pending, libc::SIGPIPE) == 0, "and raises no SIGPIPE");
        libc::close(fds[1]);
        libc::sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
    }
}

fn main() {
    let mut h = Harness::new();

    sys::unlink(FILE);
    sys::unlink(LINK);
    sys::rmdir(DIR);
    if !sys::write_file(FILE, b"regression\n") {
        println!("setup: cannot create {FILE}: {}", sys::strerror(sys::errno()));
        std::process::exit(2);
    }
    if sys::mkdir(DIR, 0o755) != 0 && sys::errno() != libc::EEXIST {
        println!("setup: cannot create {DIR}: {}", sys::strerror(sys::errno()));
        std::process::exit(2);
    }

    t_o_directory(&mut h);
    t_o_nofollow(&mut h);
    t_stat_fstat_agreement(&mut h, FILE);
    t_waitpid_across_timeout(&mut h);
    t_signal_still_interrupts(&mut h);
    t_waitid_siginfo(&mut h);
    t_at_ignores_dirfd_for_absolute_paths(&mut h);
    t_waitid_conformance(&mut h);
    t_sigchld_siginfo(&mut h);
    t_sigrtmax(&mut h);
    t_no_zombies_when_parent_will_not_wait(&mut h);
    t_empty_write(&mut h);

    sys::unlink(FILE);
    sys::unlink(LINK);
    sys::rmdir(DIR);
    std::process::exit(h.finish());
}
