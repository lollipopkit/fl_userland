//! wait, waitpid, waitid and what a child's exit looks like from outside.
//!
//! Every shell and every supervisor is built on this, and it is delicate here:
//! the tree's own notes record three probes that were wrong before one was
//! right while confirming a single zombie-reaping bug. `/proc/<pid>` is not a
//! usable probe — this procfs answers through `pid_get_task`, which returns
//! nothing for a zombie — so every check below asks `waitpid`, which is the
//! one that distinguishes a kept child from a released one.

use guest_tests::{Harness, check, check_fails, sys};

/// Fork a child that runs `body` and returns its pid.
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

fn t_exit_status(h: &mut Harness) {
    h.group("exit-status");

    let pid = spawn(|| 42);
    let (got, status) = waitpid(pid, 0);
    check!(h, got == pid, "waitpid returns the pid: {got} vs {pid}");
    check!(h, libc::WIFEXITED(status), "WIFEXITED for a normal exit");
    check!(
        h,
        libc::WEXITSTATUS(status) == 42,
        "the exit code, got {}",
        libc::WEXITSTATUS(status)
    );
    check!(h, !libc::WIFSIGNALED(status), "and not WIFSIGNALED");

    // Only the low eight bits of the exit code survive.
    let pid = spawn(|| 0x1ff);
    let (_, status) = waitpid(pid, 0);
    check!(
        h,
        libc::WEXITSTATUS(status) == 0xff,
        "an exit code is truncated to eight bits, got {}",
        libc::WEXITSTATUS(status)
    );

    // A child killed by a signal.
    let pid = spawn(|| {
        unsafe { libc::raise(libc::SIGKILL) };
        0
    });
    let (got, status) = waitpid(pid, 0);
    check!(h, got == pid, "reaping a killed child");
    check!(h, libc::WIFSIGNALED(status), "WIFSIGNALED for a killed child");
    check!(
        h,
        libc::WTERMSIG(status) == libc::SIGKILL,
        "WTERMSIG names the signal, got {}",
        libc::WTERMSIG(status)
    );
    check!(h, !libc::WIFEXITED(status), "and not WIFEXITED");
}

fn t_selectors(h: &mut Harness) {
    h.group("selectors");

    // WNOHANG with a child that has not exited.
    let pid = spawn(|| {
        unsafe { libc::usleep(400_000) };
        7
    });
    let (got, _) = waitpid(pid, libc::WNOHANG);
    check!(h, got == 0, "WNOHANG with a running child returns 0, got {got}");
    let (got, status) = waitpid(pid, 0);
    check!(
        h,
        got == pid && libc::WEXITSTATUS(status) == 7,
        "and blocking then reaps it: {got}"
    );

    // waitpid(-1) takes any child.
    let a = spawn(|| 1);
    let b = spawn(|| 2);
    let mut seen = Vec::new();
    for _ in 0..2 {
        let (got, status) = waitpid(-1, 0);
        seen.push((got, libc::WEXITSTATUS(status)));
    }
    seen.sort();
    check!(
        h,
        seen.len() == 2 && seen.iter().any(|&(p, _)| p == a) && seen.iter().any(|&(p, _)| p == b),
        "waitpid(-1) reaps both children: {seen:?}"
    );

    // A pid that is not our child.
    check_fails!(h, waitpid(1, 0).0 as i64, libc::ECHILD, "waiting for pid 1");
    // No children at all.
    check_fails!(h, waitpid(-1, 0).0 as i64, libc::ECHILD, "waiting with no children");
    check_fails!(
        h,
        waitpid(-1, libc::WNOHANG).0 as i64,
        libc::ECHILD,
        "and with WNOHANG too"
    );

    // waitpid(0) is "any child in my process group".
    let c = spawn(|| 3);
    let (got, status) = waitpid(0, 0);
    check!(
        h,
        got == c && libc::WEXITSTATUS(status) == 3,
        "waitpid(0) takes a child of this process group: {got} vs {c}"
    );

    // waitpid(-pgid) names a group.
    let d = spawn(|| {
        unsafe { libc::setpgid(0, 0) };
        4
    });
    // The child may or may not have run setpgid yet; wait for it by pid to
    // avoid racing its own group change, then check the group form on a
    // second child that stays in ours.
    let (got, _) = waitpid(d, 0);
    check!(h, got == d, "reaping a child that changed its group");
    let e = spawn(|| 5);
    let mygroup = unsafe { libc::getpgrp() };
    let (got, status) = waitpid(-mygroup, 0);
    check!(
        h,
        got == e && libc::WEXITSTATUS(status) == 5,
        "waitpid(-pgid) takes a child of that group: {got} vs {e}"
    );
}

fn t_stop_and_continue(h: &mut Harness) {
    h.group("stopped");
    // A child that stops, is noticed, is continued, and is noticed again.
    let pid = spawn(|| {
        unsafe { libc::raise(libc::SIGSTOP) };
        // Reached only once continued.
        unsafe { libc::usleep(50_000) };
        11
    });
    let (got, status) = waitpid(pid, libc::WUNTRACED);
    check!(h, got == pid, "WUNTRACED reports the stop: {got}");
    check!(h, libc::WIFSTOPPED(status), "WIFSTOPPED");
    check!(
        h,
        libc::WSTOPSIG(status) == libc::SIGSTOP,
        "WSTOPSIG names SIGSTOP, got {}",
        libc::WSTOPSIG(status)
    );

    unsafe { libc::kill(pid, libc::SIGCONT) };
    let (got, status) = waitpid(pid, libc::WCONTINUED);
    if got == pid && libc::WIFCONTINUED(status) {
        check!(h, true, "WCONTINUED reports the continue");
        let (got, status) = waitpid(pid, 0);
        check!(
            h,
            got == pid && libc::WEXITSTATUS(status) == 11,
            "and then the exit: {got}"
        );
    } else {
        // Some kernels coalesce; accept the exit arriving directly, but say so.
        check!(
            h,
            got == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 11,
            "the continued child ran to completion: got={got} status={status:#x}"
        );
    }
}

fn t_waitid(h: &mut Harness) {
    h.group("waitid");

    let pid = spawn(|| 23);
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::syscall(
            libc::SYS_waitid,
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED,
            std::ptr::null_mut::<libc::rusage>(),
        )
    };
    check!(h, r == 0, "waitid returned {r} errno {}", sys::errno());
    check!(h, unsafe { info.si_pid() } == pid, "si_pid is the child, got {}", unsafe { info.si_pid() });
    check!(
        h,
        info.si_code == libc::CLD_EXITED,
        "si_code is CLD_EXITED, got {}",
        info.si_code
    );
    check!(
        h,
        unsafe { info.si_status() } == 23,
        "si_status is the exit code, not the wait word, got {}",
        unsafe { info.si_status() }
    );
    check!(
        h,
        info.si_signo == libc::SIGCHLD,
        "si_signo is SIGCHLD, got {}",
        info.si_signo
    );

    // A killed child.
    let pid = spawn(|| {
        unsafe { libc::raise(libc::SIGKILL) };
        0
    });
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::syscall(
            libc::SYS_waitid,
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED,
            std::ptr::null_mut::<libc::rusage>(),
        )
    };
    check!(h, r == 0, "waitid on a killed child returned {r}");
    check!(
        h,
        info.si_code == libc::CLD_KILLED,
        "si_code is CLD_KILLED, got {}",
        info.si_code
    );
    check!(
        h,
        unsafe { info.si_status() } == libc::SIGKILL,
        "si_status is the signal, got {}",
        unsafe { info.si_status() }
    );

    // WNOWAIT leaves the child reapable.
    let pid = spawn(|| 31);
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::syscall(
            libc::SYS_waitid,
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOWAIT,
            std::ptr::null_mut::<libc::rusage>(),
        )
    };
    check!(h, r == 0, "waitid with WNOWAIT returned {r}");
    check!(h, unsafe { info.si_status() } == 31, "and reports the status");
    let (got, status) = waitpid(pid, 0);
    check!(
        h,
        got == pid && libc::WEXITSTATUS(status) == 31,
        "and the child is still there to reap: {got}"
    );

    // waitid without any of WEXITED/WSTOPPED/WCONTINUED is EINVAL.
    let child = spawn(|| 0);
    check_fails!(
        h,
        unsafe {
            libc::syscall(
                libc::SYS_waitid,
                libc::P_PID,
                child,
                std::ptr::null_mut::<libc::siginfo_t>(),
                0,
                std::ptr::null_mut::<libc::rusage>(),
            )
        },
        libc::EINVAL,
        "waitid with no state selected"
    );
    waitpid(child, 0);
}

/// SIGCHLD set to SIG_IGN means children are reaped automatically and there is
/// nothing left to wait for.
fn t_no_zombies(h: &mut Harness) {
    h.group("sigchld-ignore");
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
    let pid = spawn(|| 17);
    // Give it time to exit and be collected.
    unsafe { libc::usleep(200_000) };
    let (got, _) = waitpid(pid, 0);
    check!(
        h,
        got == -1 && sys::errno() == libc::ECHILD,
        "with SIGCHLD ignored the child is gone: got={got} errno={}",
        sys::errno()
    );
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };

    // And with the default disposition it is not.
    let pid = spawn(|| 19);
    unsafe { libc::usleep(200_000) };
    let (got, status) = waitpid(pid, 0);
    check!(
        h,
        got == pid && libc::WEXITSTATUS(status) == 19,
        "with the default it waits to be reaped: {got}"
    );
}

/// A child that outlives its parent is reparented, and the new parent can reap
/// it. Run from a grandchild so this process stays the reaper of record.
fn t_orphan_reparenting(h: &mut Harness) {
    h.group("orphan");
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };

    let child = spawn(|| unsafe {
        libc::close(fds[0]);
        // A grandchild that outlives this process.
        let g = libc::fork();
        if g == 0 {
            libc::usleep(150_000);
            libc::_exit(29);
        }
        // Tell the top process which pid to look for, then exit immediately.
        let msg = format!("{g}\n");
        libc::write(fds[1], msg.as_ptr().cast(), msg.len());
        libc::close(fds[1]);
        0
    });
    unsafe { libc::close(fds[1]) };
    let mut buf = [0u8; 32];
    let n = sys::read(fds[0], &mut buf);
    sys::close(fds[0]);
    let grandchild: i32 = std::str::from_utf8(&buf[..n.max(0) as usize])
        .unwrap_or("")
        .trim()
        .parse()
        .unwrap_or(-1);
    check!(h, grandchild > 0, "the grandchild's pid arrived: {grandchild}");
    let (got, _) = waitpid(child, 0);
    check!(h, got == child, "the middle process is reaped");

    // Where the orphan goes depends on who is running the test. Under the
    // guest gate this process *is* pid 1, so the orphan is reparented to it
    // and reaping it is the check; run under a shell that is pid 1, it is not
    // ours and the answer is ECHILD.
    //
    // The first version assumed the second case and failed, because `sh -c`
    // execs the test rather than forking it — which is the tree's own note
    // about the probe being where it goes wrong.
    if unsafe { libc::getpid() } == 1 {
        let (got, status) = waitpid(grandchild, 0);
        check!(
            h,
            got == grandchild && libc::WEXITSTATUS(status) == 29,
            "an orphan is reparented to init, which is this process: got={got} \
             want={grandchild} status={status:#x}"
        );
    } else {
        check!(
            h,
            waitpid(grandchild, 0).0 == -1 && sys::errno() == libc::ECHILD,
            "an orphaned grandchild is not this process's to reap"
        );
        // And it really was adopted rather than left unreapable: it is gone
        // within a couple of seconds, which needs someone to have collected it.
        let mut alive = true;
        for _ in 0..40 {
            unsafe { libc::usleep(50_000) };
            if unsafe { libc::kill(grandchild, 0) } != 0 && sys::errno() == libc::ESRCH {
                alive = false;
                break;
            }
        }
        check!(h, !alive, "and it is collected by its new parent");
    }
}

fn main() {
    let mut h = Harness::new();
    t_exit_status(&mut h);
    t_selectors(&mut h);
    t_stop_and_continue(&mut h);
    t_waitid(&mut h);
    t_no_zombies(&mut h);
    t_orphan_reparenting(&mut h);
    std::process::exit(h.finish());
}
