//! `RLIMIT_NPROC`: how many processes a user may have.
//!
//! The limit is what stops a guest that forks and never waits from filling the
//! kernel's pid table. It was defined here, given a default of 1024, and
//! enforced nowhere — so the table filled with zombies and the allocation loop
//! then spun for ever holding the kernel-wide lock. Not a failed fork: the
//! whole emulator, and whatever application is embedding it, stopped.
//!
//! Three things about the counting that are easy to get wrong, and are what
//! this pins down:
//!
//! - a **zombie still counts**. The count is dropped when the parent reaps, not
//!   when the child exits, which is exactly the case the limit exists for.
//! - the limit is the count, not the count plus one: a limit of N admits N.
//! - `fork` past it is `EAGAIN`, not `ENOMEM`.
//!
//! Privilege is dropped to an ordinary user before any of it, because root is
//! exempt from this limit on Linux and both the container and the emulator's
//! guest run as root -- without dropping, no fork is ever refused and every
//! check below would pass for the wrong reason.

use guest_tests::{Harness, check};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Forks a child that waits to be told to exit. Returns its pid, or -errno.
///
/// The child closes the *write* end first. Without that every child holds one
/// open, so closing the parent's copy produces no end of file and the wait at
/// the bottom of this file never returns -- which is how the first version of
/// this hung a container for ten minutes.
fn spawn_waiter(pipefd: [i32; 2]) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(pipefd[1]) };
        let mut b = [0u8; 1];
        while unsafe { libc::read(pipefd[0], b.as_mut_ptr().cast(), 1) } > 0 {}
        unsafe { libc::_exit(0) };
    }
    if pid < 0 {
        return -errno();
    }
    pid
}

fn main() {
    let mut h = Harness::new();

    // A child of our own, because setting the limit for this process affects
    // every fork it makes -- including the ones the harness itself might want.
    // Everything below runs in it.
    let outer = unsafe { libc::fork() };
    if outer != 0 {
        let mut st = 0;
        unsafe { libc::waitpid(outer, &mut st, 0) };
        std::process::exit(if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 1 });
    }

    h.group("setup");
    // The pipe first, because the limit is set before any forking and the
    // children need it.
    let mut pipefd = [0i32; 2];
    check!(h, unsafe { libc::pipe(pipefd.as_mut_ptr()) } == 0, "a pipe to hold them open");

    h.group("the-limit-is-honoured");
    // Small, so the test is quick and so the number of children is bounded
    // whatever the default happens to be.
    const LIMIT: u64 = 6;
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    check!(h, unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut lim) } == 0,
        "reading RLIMIT_NPROC");
    let want = libc::rlimit { rlim_cur: LIMIT, rlim_max: lim.rlim_max };
    check!(h, unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &want) } == 0,
        "setting it to {LIMIT}: errno={}", errno());
    let mut back = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut back) };
    check!(h, back.rlim_cur == LIMIT, "and it reads back: {}", back.rlim_cur);

    // Privilege dropped *after* the limit is set, so rlim_max stays where it
    // was and the raise at the bottom is allowed. Root is exempt from this
    // limit on Linux, and the container this is compared against runs as root:
    // without dropping, no fork is ever refused there and the whole test would
    // pass for the wrong reason on one side and fail on the other.
    check!(h, unsafe { libc::setuid(1000) } == 0, "dropping to an ordinary user: errno={}", errno());
    check!(h, unsafe { libc::getuid() } == 1000, "which took: uid={}", unsafe { libc::getuid() });

    // Fork until refused. The limit counts *this* process too, and whatever
    // else the user already has, so the number that get through is not
    // predictable -- what is, is that it stops, and stops with EAGAIN.
    let mut kids = Vec::new();
    let mut refused = 0;
    let mut refused_errno = 0;
    for _ in 0..(LIMIT as usize + 8) {
        let pid = spawn_waiter(pipefd);
        if pid > 0 {
            kids.push(pid);
        } else {
            refused += 1;
            refused_errno = -pid;
            break;
        }
    }
    check!(h, refused > 0, "fork is refused before the limit is left behind: {} got through",
        kids.len());
    check!(h, refused_errno == libc::EAGAIN,
        "and the refusal is EAGAIN: errno={refused_errno}");
    check!(h, kids.len() < (LIMIT as usize + 8),
        "which is fewer than were asked for: {}", kids.len());

    h.group("a-zombie-still-counts");
    // The case the limit exists for. One child exits but is not reaped; the
    // room it was using does not come back until it is.
    let dead = spawn_waiter(pipefd);
    let had_room = dead > 0;
    if had_room {
        // Should not happen -- we are at the limit -- but if it does, use it.
        kids.push(dead);
    }
    // Let one of the live ones exit without reaping it.
    let victim = kids.pop().unwrap_or(-1);
    check!(h, victim > 0, "a child to release: {victim}");
    if victim > 0 {
        unsafe { libc::kill(victim, libc::SIGKILL) };
        // It is a zombie now: dead, unreaped, and still holding its number.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let pid = spawn_waiter(pipefd);
        check!(h, pid < 0 && -pid == libc::EAGAIN,
            "a zombie still counts against the limit: pid={pid}");
        if pid > 0 {
            kids.push(pid);
        }
        // Reaping it gives the room back.
        let mut st = 0;
        let w = unsafe { libc::waitpid(victim, &mut st, 0) };
        check!(h, w == victim, "reaping it: w={w}");
        let pid = spawn_waiter(pipefd);
        check!(h, pid > 0, "and then there is room again: pid={pid} errno={}", -pid);
        if pid > 0 {
            kids.push(pid);
        }
    } else {
        for _ in 0..4 {
            check!(h, false, "a child to release");
        }
    }

    h.group("raising-it-makes-room");
    let want = libc::rlimit { rlim_cur: LIMIT + 4, rlim_max: lim.rlim_max };
    check!(h, unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &want) } == 0,
        "raising the limit: errno={}", errno());
    let pid = spawn_waiter(pipefd);
    check!(h, pid > 0, "a fork that was refused now works: pid={pid} errno={}", -pid);
    if pid > 0 {
        kids.push(pid);
    }

    // Release everyone.
    unsafe { libc::close(pipefd[1]) };
    for pid in &kids {
        let mut st = 0;
        unsafe { libc::waitpid(*pid, &mut st, 0) };
    }
    unsafe { libc::close(pipefd[0]) };

    std::process::exit(h.finish());
}
