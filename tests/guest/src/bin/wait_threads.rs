//! `wait` finds the children of every thread in the process, not just the
//! caller's.
//!
//! A process's children belong to the *thread* that forked them, and `wait()`
//! with no pid is defined over the whole thread group: a worker thread forks,
//! the main thread reaps. That is how a thread pool that spawns subprocesses
//! works, and how every `posix_spawn` from a non-main thread is collected.
//!
//! `__WNOTHREAD` is the flag that asks for the other behaviour — only this
//! thread's own children — and `__WCLONE`/`__WALL` select which kinds of child
//! count. All three were rejected outright with `EINVAL`.
//!
//! The probes here all use a pipe to hand the child's pid back from the thread
//! that made it, and none of them waits without a bound: the failure this is
//! about is `wait` answering `ECHILD` for a child that exists, and a test that
//! blocks for ever cannot tell that apart from a slow one.

use guest_tests::{Harness, check};
use std::sync::mpsc;

const WNOHANG: i32 = 1;
const WEXITED: i32 = 4;
const WNOTHREAD: i32 = 1 << 29;
const WALL: i32 = 1 << 30;
const WCLONE: i32 = 1 << 31;
const P_ALL: i32 = 0;
const P_PID: i32 = 1;
const P_PIDFD: i32 = 3;
/// Report the child's status but leave it waitable.
const WNOWAIT: i32 = 0x01000000;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A worker thread that forks on request and **stays alive**.
///
/// Staying alive is the whole point. A thread that exits has its children
/// reparented to another thread of the same group -- Linux's `find_new_reaper`
/// returns `find_alive_thread(father)` first -- so a test that joins the worker
/// before waiting is asking about the main thread's own children and would pass
/// against a kernel that never looks at anyone else's. The first version of
/// this did exactly that, and `__WNOTHREAD` found the child on Linux.
struct Forker {
    req: mpsc::Sender<i32>,
    rep: mpsc::Receiver<i32>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Forker {
    fn new() -> Forker {
        let (req_tx, req_rx) = mpsc::channel::<i32>();
        let (rep_tx, rep_rx) = mpsc::channel::<i32>();
        let handle = std::thread::spawn(move || {
            while let Ok(code) = req_rx.recv() {
                if code < 0 {
                    break;
                }
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    unsafe { libc::_exit(code) };
                }
                rep_tx.send(pid).ok();
            }
        });
        Forker { req: req_tx, rep: rep_rx, handle: Some(handle) }
    }

    fn fork(&self, exit_code: i32) -> i32 {
        if self.req.send(exit_code).is_err() {
            return -1;
        }
        self.rep.recv().unwrap_or(-1)
    }

    fn stop(&mut self) {
        self.req.send(-1).ok();
        if let Some(h) = self.handle.take() {
            h.join().ok();
        }
    }
}

/// `waitpid` in a loop with a deadline, so a missing child is a failed check
/// rather than a hang.
fn wait_within(pid: i32, options: i32, ms: u64) -> (i32, i32, i32) {
    let start = std::time::Instant::now();
    loop {
        let mut st = 0;
        let r = unsafe { libc::waitpid(pid, &mut st, options | WNOHANG) };
        let e = errno();
        if r != 0 {
            return (r, st, e);
        }
        if start.elapsed().as_millis() as u64 > ms {
            return (0, 0, 0);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn main() {
    let mut h = Harness::new();
    let mut forker = Forker::new();

    h.group("wait-finds-another-threads-child");
    let pid = forker.fork(7);
    check!(h, pid > 0, "a child forked on a worker thread: pid={pid}");
    if pid > 0 {
        let (r, st, e) = wait_within(-1, 0, 2000);
        check!(h, r == pid, "wait(-1) on the main thread reaps it: r={r} want={pid} errno={e}");
        check!(h, libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 7,
            "with its status: {st:#x}");
    } else {
        for _ in 0..2 {
            check!(h, false, "a child forked on a worker thread");
        }
    }

    h.group("waitpid-by-number-finds-it-too");
    // The path that names the child explicitly. It was already right, and it is
    // here so the group above is not the only evidence that anything works.
    let pid = forker.fork(3);
    check!(h, pid > 0, "another one: pid={pid}");
    if pid > 0 {
        let (r, st, e) = wait_within(pid, 0, 2000);
        check!(h, r == pid, "waitpid(pid) reaps it: r={r} errno={e}");
        check!(h, libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 3, "with its status: {st:#x}");
    } else {
        for _ in 0..2 {
            check!(h, false, "another one");
        }
    }

    h.group("a-third-thread-may-reap-it");
    // Neither the forker nor the main thread: any thread of the process.
    let pid = forker.fork(5);
    check!(h, pid > 0, "a third child: pid={pid}");
    if pid > 0 {
        let reaped = std::thread::spawn(move || wait_within(-1, 0, 2000))
            .join()
            .unwrap_or((-1, 0, 0));
        check!(h, reaped.0 == pid, "a third thread reaps it: r={} want={pid}", reaped.0);
        check!(h, libc::WIFEXITED(reaped.1) && libc::WEXITSTATUS(reaped.1) == 5,
            "with its status: {:#x}", reaped.1);
    } else {
        for _ in 0..2 {
            check!(h, false, "a third child");
        }
    }

    h.group("__WNOTHREAD-restricts-it-to-this-thread");
    // The flag that asks for the behaviour the kernel had by accident. A child
    // of another thread must *not* be found, and must still be there after.
    let pid = forker.fork(9);
    check!(h, pid > 0, "a fourth child: pid={pid}");
    if pid > 0 {
        // Give it time to become a zombie, so "not found" cannot be "not yet".
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut st = 0;
        let r = unsafe { libc::waitpid(-1, &mut st, WNOHANG | WNOTHREAD) };
        let e = errno();
        check!(h, r == 0 || (r == -1 && e == libc::ECHILD),
            "__WNOTHREAD does not see another thread's child: r={r} errno={e}");
        // And an ordinary wait still finds it, which proves it was there.
        let (r2, st2, e2) = wait_within(-1, 0, 2000);
        check!(h, r2 == pid, "and an ordinary wait still does: r={r2} errno={e2}");
        check!(h, libc::WIFEXITED(st2) && libc::WEXITSTATUS(st2) == 9,
            "with its status: {st2:#x}");
    } else {
        for _ in 0..3 {
            check!(h, false, "a fourth child");
        }
    }

    h.group("the-clone-selection-flags-are-accepted");
    // __WCLONE selects children that do not send SIGCHLD, __WALL selects both
    // kinds. An ordinary fork()ed child is not a __WCLONE one, so asking for
    // only those must not find it -- and asking for all must.
    let pid = forker.fork(11);
    check!(h, pid > 0, "a fifth child: pid={pid}");
    if pid > 0 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut st = 0;
        let r = unsafe { libc::waitpid(-1, &mut st, WNOHANG | WCLONE) };
        let e = errno();
        check!(h, r == 0 || (r == -1 && e == libc::ECHILD),
            "__WCLONE is accepted and does not match a fork()ed child: r={r} errno={e}");
        let mut st = 0;
        let r = unsafe { libc::waitpid(-1, &mut st, WNOHANG | WALL) };
        let e = errno();
        check!(h, r == pid, "__WALL is accepted and matches it: r={r} errno={e}");
        check!(h, libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 11,
            "with its status: {st:#x}");
    } else {
        for _ in 0..3 {
            check!(h, false, "a fifth child");
        }
    }

    h.group("waitid-takes-the-same-flags");
    let pid = forker.fork(13);
    check!(h, pid > 0, "a sixth child: pid={pid}");
    if pid > 0 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::syscall(libc::SYS_waitid, P_ALL, 0, &raw mut si,
                          WEXITED | WNOHANG | WALL, std::ptr::null_mut::<libc::rusage>())
        };
        let e = errno();
        check!(h, r == 0, "waitid with __WALL: r={r} errno={e}");
        check!(h, unsafe { si.si_pid() } == pid, "reports the child: {} want={pid}", unsafe { si.si_pid() });
        // P_PID with __WNOTHREAD on a child of another thread. Linux takes the
        // flag; whether it matches is the same question as above.
        let mut si2: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r2 = unsafe {
            libc::syscall(libc::SYS_waitid, P_PID, pid as libc::c_long, &raw mut si2,
                          WEXITED | WNOHANG | WNOTHREAD, std::ptr::null_mut::<libc::rusage>())
        };
        let e2 = errno();
        check!(h, r2 == -1 && e2 == libc::ECHILD,
            "and P_PID with __WNOTHREAD after it is gone is ECHILD: r={r2} errno={e2}");
    } else {
        for _ in 0..3 {
            check!(h, false, "a sixth child");
        }
    }

    h.group("pidfd-of-a-zombie");
    // A pidfd for a child that has already exited and not been reaped.
    //
    // This is the case P_PIDFD exists for -- open a descriptor that names the
    // process, then wait on it, with no window for a reused pid -- and the
    // child exiting first is not a race to lose, it is the normal order. Linux
    // detaches a pid's PIDTYPE_TGID at `release_task`, which is *reaping*, so a
    // zombie still answers `pidfd_open`.
    //
    // This kernel looked the pid up with `pid_get_task`, which returns NULL for
    // a zombie, and answered ESRCH. It showed up as `waitid-by-pidfd` failing
    // about one release-build run in ten -- whenever the child got to exit
    // before the parent called pidfd_open -- and the "nothing is left behind"
    // check at the end then reaped the child nobody could open.
    {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(19) };
        }
        check!(h, pid > 0, "a child to let die: pid={pid}");
        if pid > 0 {
            // Wait for it to be a zombie, without reaping it. WNOWAIT leaves
            // it waitable, which is what makes this deterministic rather than
            // a sleep and a hope.
            let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let r = unsafe {
                libc::syscall(libc::SYS_waitid, P_PID, pid as libc::c_long,
                              &raw mut si, WEXITED | WNOWAIT,
                              std::ptr::null_mut::<libc::rusage>())
            };
            check!(h, r == 0, "waitid(WNOWAIT) sees it exit: r={r} errno={}", errno());

            let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            check!(h, pidfd >= 0,
                "pidfd_open on the zombie: fd={pidfd} errno={}", errno());
            if pidfd >= 0 {
                let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let r = unsafe {
                    libc::syscall(libc::SYS_waitid, P_PIDFD, pidfd as libc::c_long,
                                  &raw mut si, WEXITED,
                                  std::ptr::null_mut::<libc::rusage>())
                };
                check!(h, r == 0, "and it reaps: r={r} errno={}", errno());
                check!(h, unsafe { si.si_status() } == 19,
                    "with its status: {}", unsafe { si.si_status() });
                unsafe { libc::close(pidfd) };
            } else {
                // Reap it anyway, so the check at the end of this file is
                // about what it says it is.
                let mut st = 0;
                unsafe { libc::waitpid(pid, &mut st, 0) };
                for _ in 0..2 {
                    check!(h, false, "pidfd_open on the zombie");
                }
            }
        }
    }

    h.group("waitid-by-pidfd");
    // The fourth idtype, and the reason it exists: a pidfd names the process
    // itself, so nothing can slip a reused pid in between opening it and
    // waiting on it. The child is forked on the worker thread, so this also
    // covers the cross-thread rule through a third entry point.
    let pid = forker.fork(17);
    check!(h, pid > 0, "a seventh child: pid={pid}");
    if pid > 0 {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        check!(h, pidfd >= 0, "pidfd_open: fd={pidfd} errno={}", errno());
        if pidfd >= 0 {
            let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // Blocking, deliberately: a pidfd is exactly the case where there
            // is no race to lose, so there is nothing to poll for.
            let r = unsafe {
                libc::syscall(libc::SYS_waitid, P_PIDFD, pidfd as libc::c_long,
                              &raw mut si, WEXITED, std::ptr::null_mut::<libc::rusage>())
            };
            let e = errno();
            check!(h, r == 0, "waitid(P_PIDFD) reaps it: r={r} errno={e}");
            check!(h, unsafe { si.si_pid() } == pid,
                "and reports the child: {} want={pid}", unsafe { si.si_pid() });
            check!(h, unsafe { si.si_status() } == 17, "with its status: {}", unsafe { si.si_status() });
            unsafe { libc::close(pidfd) };
        } else {
            for _ in 0..3 {
                check!(h, false, "pidfd_open");
            }
        }

        // A descriptor that is not a pidfd, and a number that is not a
        // descriptor. Linux answers EBADF for both, where EINVAL would be the
        // guess for the first.
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::syscall(libc::SYS_waitid, P_PIDFD, 1i64, &raw mut si,
                          WEXITED | WNOHANG, std::ptr::null_mut::<libc::rusage>())
        };
        let e = errno();
        check!(h, r == -1 && e == libc::EBADF,
            "waitid(P_PIDFD) on stdout is EBADF: r={r} errno={e}");
        let r = unsafe {
            libc::syscall(libc::SYS_waitid, P_PIDFD, 9999i64, &raw mut si,
                          WEXITED | WNOHANG, std::ptr::null_mut::<libc::rusage>())
        };
        let e = errno();
        check!(h, r == -1 && e == libc::EBADF,
            "and on a closed number: r={r} errno={e}");
    } else {
        for _ in 0..6 {
            check!(h, false, "a seventh child");
        }
    }

    forker.stop();

    h.group("nothing-is-left-behind");
    // The control for every "not found" above: a child that was reported as
    // absent and really was still there would be reaped here.
    //
    // `<= 0` rather than `== -1 && ECHILD`, and the difference is the point.
    // ECHILD means "no children at all", which this process cannot promise: a
    // runtime that has ever spawned a thread leaves the kernel with something
    // it counts as an eligible child but never reports, so waitpid answers 0.
    // Measured, not assumed -- it does it on a real kernel too. A *positive*
    // return is the failure, because that is a child nobody claimed.
    let mut st = 0;
    let r = unsafe { libc::waitpid(-1, &mut st, WNOHANG) };
    let e = errno();
    check!(h, r <= 0,
        "no child was left unreaped: r={r} status={st:#x} errno={e}");

    std::process::exit(h.finish());
}
