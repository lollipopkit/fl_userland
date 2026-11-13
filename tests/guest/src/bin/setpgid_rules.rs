//! `setpgid`: the rules a shell depends on to put a pipeline in one group.
//!
//! The one that matters most is not an errno. When a second child *joins* the
//! group the first one made, the kernel has to record it under **that group's**
//! number — otherwise `kill(-pgid, …)` never reaches it, the terminal's
//! foreground signals miss it, and nothing anywhere reports a problem. A shell
//! sending `^C` to a two-process pipeline would stop one of them.
//!
//! The errnos around it are all Linux's and are checked here because each is a
//! different mistake: `EINVAL` for a negative group, `ESRCH` for a process that
//! is not the caller's to move, `EPERM` for a group in another session or for a
//! session leader, and `EACCES` for a child that has already `exec`ed.

use guest_tests::{Harness, check, sys};
use std::sync::mpsc;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn setpgid(pid: i32, pgid: i32) -> (i32, i32) {
    let r = unsafe { libc::setpgid(pid, pgid) };
    (r, errno())
}

/// A child that blocks until the pipe's write end is closed, then exits 0.
fn spawn_waiter(pipefd: [i32; 2]) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(pipefd[1]) };
        let mut b = [0u8; 1];
        while unsafe { libc::read(pipefd[0], b.as_mut_ptr().cast(), 1) } > 0 {}
        unsafe { libc::_exit(0) };
    }
    pid
}

/// A child that `exec`s straight away and then sleeps, so `setpgid` on it is the
/// `EACCES` case. Returns its pid; the caller must reap it.
fn spawn_execed() -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let path = c"/bin/sleep";
        let arg = c"10";
        let argv = [path.as_ptr(), arg.as_ptr(), std::ptr::null()];
        unsafe { libc::execv(path.as_ptr(), argv.as_ptr()) };
        unsafe { libc::_exit(127) };
    }
    pid
}

fn main() {
    let mut h = Harness::new();

    // Everything runs in a child, so this process can setsid without being a
    // process group leader and so the harness's own group is left alone.
    let outer = unsafe { libc::fork() };
    if outer != 0 {
        let mut st = 0;
        unsafe { libc::waitpid(outer, &mut st, 0) };
        std::process::exit(if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 1 });
    }

    h.group("setup");
    let sid = unsafe { libc::setsid() };
    check!(h, sid > 0, "a session of our own: sid={sid} errno={}", errno());
    let me = unsafe { libc::getpid() };
    let mut pipefd = [0i32; 2];
    check!(h, unsafe { libc::pipe(pipefd.as_mut_ptr()) } == 0, "a pipe to hold children open");

    h.group("a-child-starts-where-its-parent-is");
    // Before anything moves it. A child inherits both numbers, and nothing else
    // in this file checks that -- every other group calls setsid or setpgid
    // first, so a kernel that gave a child a process group of zero would
    // satisfy all of them.
    let my_pgid = unsafe { libc::getpgrp() };
    let my_sid = unsafe { libc::getsid(0) };
    let mut ids = [0i32; 2];
    let mut idpipe = [0i32; 2];
    check!(h, unsafe { libc::pipe(idpipe.as_mut_ptr()) } == 0, "a pipe");
    let kid = unsafe { libc::fork() };
    if kid == 0 {
        unsafe { libc::close(idpipe[0]) };
        let out = [unsafe { libc::getpgrp() }, unsafe { libc::getsid(0) }];
        unsafe { libc::write(idpipe[1], out.as_ptr().cast(), 8) };
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(idpipe[1]) };
    let got = unsafe { libc::read(idpipe[0], ids.as_mut_ptr().cast(), 8) };
    unsafe { libc::close(idpipe[0]) };
    let mut st = 0;
    unsafe { libc::waitpid(kid, &mut st, 0) };
    check!(h, got == 8, "the child answers: got={got}");
    check!(h, ids[0] == my_pgid, "its process group is its parent's: {} want={my_pgid}", ids[0]);
    check!(h, ids[1] == my_sid, "and its session: {} want={my_sid}", ids[1]);

    h.group("a-session-leader-may-not-leave-its-group");
    // This process is the session leader now, so it may not be moved -- not
    // even into a group of its own, which is what setpgid(0, 0) asks for.
    let (r, e) = setpgid(0, 0);
    check!(h, r == -1 && e == libc::EPERM, "setpgid(0, 0) on a session leader: r={r} errno={e}");

    h.group("bad-arguments");
    let (r, e) = setpgid(0, -1);
    check!(h, r == -1 && e == libc::EINVAL, "a negative group is EINVAL: r={r} errno={e}");
    let (r, e) = setpgid(0, i32::MIN);
    check!(h, r == -1 && e == libc::EINVAL, "and so is the most negative: r={r} errno={e}");
    let (r, e) = setpgid(30000, 30000);
    check!(h, r == -1 && e == libc::ESRCH, "a process that is not there is ESRCH: r={r} errno={e}");
    // Our own parent: a real process, and not ours to move.
    let parent = unsafe { libc::getppid() };
    let (r, e) = setpgid(parent, parent);
    check!(h, r == -1 && e == libc::ESRCH,
        "a process that is not the caller or its child is ESRCH: r={r} errno={e}");

    h.group("kill-a-group-that-is-not-there");
    // `kill(-N)` where process group N has no members. The errno is Linux's
    // and is the ABI check; what it caught was not an errno at all.
    //
    // kill_group released pids_lock on this path and do_kill released it
    // again, so any guest could double-unlock the global process-table lock --
    // and a pthread mutex does not check ownership, so the second release
    // handed it away from whichever thread had since acquired it. Deterministic
    // only under a LOCK_DEBUG build, where it aborts; see the changelog.
    unsafe {
        let r = libc::kill(-30000, 0);
        let e = sys::errno();
        check!(h, r == -1 && e == libc::ESRCH,
            "kill(-30000, 0) on an empty process group: r={r} errno={e}");
        // And the process table still works afterwards.
        check!(h, libc::getppid() >= 0, "and the process table is still usable");
    }

    h.group("a-child-may-be-given-a-group-of-its-own");
    let first = spawn_waiter(pipefd);
    check!(h, first > 0, "a first child: pid={first}");
    let (r, e) = setpgid(first, first);
    check!(h, r == 0, "setpgid(child, child): r={r} errno={e}");
    check!(h, unsafe { libc::getpgid(first) } == first,
        "and it is in it: {}", unsafe { libc::getpgid(first) });

    h.group("a-second-child-joins-that-group");
    // The one that is not an errno. Joining a group has to be recorded under
    // *that group's* number, or the group's members are not reachable through
    // it -- and every way of finding that out is silent.
    let second = spawn_waiter(pipefd);
    check!(h, second > 0, "a second child: pid={second}");
    let (r, e) = setpgid(second, first);
    check!(h, r == 0, "setpgid(second, first): r={r} errno={e}");
    check!(h, unsafe { libc::getpgid(second) } == first,
        "getpgid agrees: {}", unsafe { libc::getpgid(second) });

    // The check getpgid cannot make: a signal to the *group*.
    let r = unsafe { libc::kill(-first, libc::SIGTERM) };
    check!(h, r == 0, "kill(-pgid, SIGTERM): r={r} errno={}", errno());
    let mut reaped = Vec::new();
    for _ in 0..2 {
        let mut st = 0;
        let start = std::time::Instant::now();
        loop {
            let w = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
            if w > 0 {
                reaped.push((w, st));
                break;
            }
            if start.elapsed().as_millis() > 2000 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    // Which one survived, and what the kernel still believes about it. This
    // check failed once, in one run out of a hundred and two, and said only
    // "1 of 2 died" -- which does not distinguish a signal that missed a group
    // member from one that arrived at a process too slow to be reaped inside
    // two seconds, so the extra text was added for the next occurrence.
    //
    // The next occurrence was a rate: one run in ten, once anything ran the
    // test in a loop. It needed one more thing to be a diagnosis -- which of
    // the two possible faults it is. So the survivor is signalled *directly*.
    // If it dies then, the group send did not reach it and the fault is in how
    // a group's members are found; if it does not, the fault is in delivering
    // a signal to a process blocked in a host read.
    //
    // It did not die, which is what identified the fault.
    // Both probes stay, because the fix narrows the window rather than closing
    // it, and if this fires again the same question has to be asked again.
    let survivor = if reaped.len() < 2 {
        let alive: Vec<i32> = [first, second].into_iter()
            .filter(|p| !reaped.iter().any(|(r, _)| r == p))
            .collect();
        alive.iter()
            .map(|p| {
                let before = format!("pid {p} pgid {} kill(0) {}",
                    unsafe { libc::getpgid(*p) },
                    unsafe { libc::kill(*p, 0) });
                unsafe { libc::kill(*p, libc::SIGTERM) };
                let mut st = 0;
                let start = std::time::Instant::now();
                let mut direct = "survived a direct SIGTERM too";
                while start.elapsed().as_millis() < 2000 {
                    if unsafe { libc::waitpid(*p, &mut st, libc::WNOHANG) } == *p {
                        direct = "died on a direct SIGTERM";
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                format!("{before}, {direct}")
            })
            .collect::<Vec<_>>().join("; ")
    } else {
        String::new()
    };
    check!(h, reaped.len() == 2,
        "the group signal reaches both members: {} of 2 died, group is {first}, \
         still here: [{survivor}]", reaped.len());
    check!(h,
        reaped.iter().all(|(_, st)| libc::WIFSIGNALED(*st) && libc::WTERMSIG(*st) == libc::SIGTERM),
        "and both by SIGTERM: {:?}",
        reaped.iter().map(|(p, st)| (*p, *st)).collect::<Vec<_>>());

    h.group("a-group-in-another-session");
    // The parent is in the session this process left, so its group is a real
    // group that this one may not join.
    let third = spawn_waiter(pipefd);
    check!(h, third > 0, "a third child: pid={third}");
    let parent_pgid = unsafe { libc::getpgid(parent) };
    check!(h, parent_pgid > 0, "the parent's group: {parent_pgid}");
    let (r, e) = setpgid(third, parent_pgid);
    check!(h, r == -1 && e == libc::EPERM,
        "joining a group in another session is EPERM: r={r} errno={e}");
    check!(h, unsafe { libc::getpgid(third) } != parent_pgid, "and it did not move");

    h.group("a-thread-that-is-not-a-leader");
    // setpgid names a *process*, so a tid that is not a thread group leader is
    // EINVAL -- not ESRCH, which is what a kernel that looks the number up and
    // finds nothing would say.
    let (tid_tx, tid_rx) = mpsc::channel::<i32>();
    let (tstop_tx, tstop_rx) = mpsc::channel::<i32>();
    let tid_thread = std::thread::spawn(move || {
        tid_tx.send(unsafe { libc::syscall(libc::SYS_gettid) } as i32).ok();
        tstop_rx.recv().ok();
    });
    let tid = tid_rx.recv().unwrap_or(-1);
    check!(h, tid > 0 && tid != me, "a thread of our own: tid={tid} pid={me}");
    let (r, e) = setpgid(tid, tid);
    check!(h, r == -1 && e == libc::EINVAL,
        "setpgid on a non-leader thread is EINVAL: r={r} errno={e}");
    tstop_tx.send(0).ok();
    tid_thread.join().ok();

    h.group("a-child-in-another-session");
    // A child that has left for a session of its own is no longer ours to
    // place, even though it is still our child.
    let mut ready = [0i32; 2];
    check!(h, unsafe { libc::pipe(ready.as_mut_ptr()) } == 0, "a pipe for the handshake");
    let away = unsafe { libc::fork() };
    if away == 0 {
        unsafe { libc::close(ready[0]) };
        // The write end, like every other child here. Without it the pipe never
        // reaches end of file and the wait at the bottom of this file blocks
        // for ever -- which has now cost two container runs.
        unsafe { libc::close(pipefd[1]) };
        unsafe { libc::setsid() };
        unsafe { libc::write(ready[1], b"x".as_ptr().cast(), 1) };
        unsafe { libc::close(ready[1]) };
        let mut b = [0u8; 1];
        while unsafe { libc::read(pipefd[0], b.as_mut_ptr().cast(), 1) } > 0 {}
        unsafe { libc::_exit(0) };
    }
    check!(h, away > 0, "a child that leaves for its own session: pid={away}");
    unsafe { libc::close(ready[1]) };
    let mut b = [0u8; 1];
    let got = unsafe { libc::read(ready[0], b.as_mut_ptr().cast(), 1) };
    check!(h, got == 1, "which says when it has: got={got}");
    unsafe { libc::close(ready[0]) };
    let (r, e) = setpgid(away, away);
    check!(h, r == -1 && (e == libc::EPERM || e == libc::EACCES),
        "placing it is refused: r={r} errno={e}");

    h.group("a-child-that-has-execed");
    let execed = spawn_execed();
    check!(h, execed > 0, "a child that execs: pid={execed}");
    // Long enough that the exec has certainly happened. Before it, setpgid is
    // allowed, which is exactly how a shell puts a child in a group before
    // handing it over.
    std::thread::sleep(std::time::Duration::from_millis(400));
    let (r, e) = setpgid(execed, execed);
    check!(h, r == -1 && e == libc::EACCES,
        "setpgid on a child that has exec'd is EACCES: r={r} errno={e}");
    unsafe { libc::kill(execed, libc::SIGKILL) };
    let mut st = 0;
    unsafe { libc::waitpid(execed, &mut st, 0) };

    h.group("another-threads-child-counts-as-ours");
    // A child belongs to the thread that forked it, and setpgid is defined over
    // the whole process: a shell whose job control runs on one thread and whose
    // spawning runs on another must still be able to place its children.
    let (tx, rx) = mpsc::channel::<i32>();
    let (stop_tx, stop_rx) = mpsc::channel::<i32>();
    let pipefd_copy = pipefd;
    let worker = std::thread::spawn(move || {
        tx.send(spawn_waiter(pipefd_copy)).ok();
        // Stays alive: a thread that exits reparents its children to another
        // thread of the group, which would make this test ask nothing.
        stop_rx.recv().ok();
    });
    let fourth = rx.recv().unwrap_or(-1);
    check!(h, fourth > 0, "a child forked on a worker thread: pid={fourth}");
    let (r, e) = setpgid(fourth, fourth);
    check!(h, r == 0, "the main thread may set its group: r={r} errno={e}");
    check!(h, unsafe { libc::getpgid(fourth) } == fourth,
        "and it took: {}", unsafe { libc::getpgid(fourth) });
    stop_tx.send(0).ok();
    worker.join().ok();

    h.group("getsid-answers-about-the-process-it-is-given");
    // getsid takes a pid. Ignoring it and answering about the caller is right
    // for getsid(0) and silently wrong for everything else -- and getsid(0) is
    // what almost every caller passes, so nothing notices.
    let my_sid = unsafe { libc::getsid(0) };
    check!(h, my_sid == me, "getsid(0) is our own session: {my_sid} pid={me}");
    check!(h, unsafe { libc::getsid(me) } == my_sid, "and getsid(self) agrees: {}",
        unsafe { libc::getsid(me) });
    // `away` left for a session of its own a moment ago.
    let away_sid = unsafe { libc::getsid(away) };
    check!(h, away_sid == away,
        "getsid(a child in its own session) is that child's: {away_sid} want={away}");
    check!(h, away_sid != my_sid, "and not the caller's: {away_sid} vs {my_sid}");
    let r = unsafe { libc::getsid(30000) };
    let e = errno();
    check!(h, r == -1 && e == libc::ESRCH, "getsid of a process that is not there: r={r} errno={e}");

    h.group("setsid-from-a-thread-that-is-not-the-leader");
    // The session and group are the *process's*, so they are recorded under the
    // thread group leader's number whichever thread asks. Recording them under
    // the calling thread's puts them on a list nothing walks, and the only way
    // to see that is to signal the group.
    let mut ready = [0i32; 2];
    check!(h, unsafe { libc::pipe(ready.as_mut_ptr()) } == 0, "a pipe for the handshake");
    let leader = unsafe { libc::fork() };
    if leader == 0 {
        unsafe { libc::close(ready[0]) };
        unsafe { libc::close(pipefd[1]) };
        let w = ready[1];
        let t = std::thread::spawn(move || {
            let sid = unsafe { libc::setsid() };
            unsafe { libc::write(w, (&sid as *const i32).cast(), 4) };
        });
        t.join().ok();
        unsafe { libc::close(ready[1]) };
        let mut b = [0u8; 1];
        while unsafe { libc::read(pipefd[0], b.as_mut_ptr().cast(), 1) } > 0 {}
        unsafe { libc::_exit(0) };
    }
    check!(h, leader > 0, "a child whose worker thread calls setsid: pid={leader}");
    unsafe { libc::close(ready[1]) };
    let mut sid_bytes = [0u8; 4];
    let got = unsafe { libc::read(ready[0], sid_bytes.as_mut_ptr().cast(), 4) };
    unsafe { libc::close(ready[0]) };
    check!(h, got == 4, "which tells us the answer: got={got}");
    let reported = i32::from_ne_bytes(sid_bytes);
    check!(h, reported == leader,
        "setsid returns the *process's* pid, not the thread's: {reported} want={leader}");
    check!(h, unsafe { libc::getsid(leader) } == leader,
        "and getsid agrees: {}", unsafe { libc::getsid(leader) });
    // The check that a list is right rather than a field: signal the group.
    let r = unsafe { libc::kill(-leader, libc::SIGTERM) };
    let e = errno();
    check!(h, r == 0, "kill(-pgid) finds the new group: r={r} errno={e}");
    let mut st = 0;
    let mut reaped_leader = 0;
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < 2000 {
        let w = unsafe { libc::waitpid(leader, &mut st, libc::WNOHANG) };
        if w == leader {
            reaped_leader = w;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    check!(h, reaped_leader == leader, "and reaches it: reaped={reaped_leader}");
    check!(h, libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGTERM,
        "by SIGTERM: status={st:#x}");

    // Release everyone still waiting on the pipe.
    unsafe { libc::close(pipefd[1]) };
    loop {
        let mut st = 0;
        let w = unsafe { libc::waitpid(-1, &mut st, 0) };
        if w <= 0 {
            break;
        }
    }
    unsafe { libc::close(pipefd[0]) };

    std::process::exit(h.finish());
}
