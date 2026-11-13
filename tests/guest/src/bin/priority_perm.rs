//! `setpriority`, and the two different refusals it has.
//!
//! Linux's `set_one_prio` splits them, and the errnos differ:
//!
//! - `set_one_prio_perm`: the target's real or effective uid must equal the
//!   caller's effective uid, or `CAP_SYS_NICE`. Otherwise **`EPERM`**.
//! - lowering the nice value below what the target already has needs
//!   `CAP_SYS_NICE` as well. Otherwise **`EACCES`**.
//!
//! Neither was checked. `priority_target` looked a task up by pid and handed
//! back its group, so any process could renice any other, in either direction.
//!
//! The code carried a comment saying this was fine because "there are no
//! capabilities here and the guest is root". That was true when it was written
//! and is not any more: a guest can hold a genuine unprivileged uid.
//!
//! Raising the nice value — being *more* polite — is always allowed, which is
//! the control that keeps the fix from being "refuse everything".

use guest_tests::{Harness, check, check_fails, sys};

const PRIO_PROCESS: libc::c_int = 0;

fn setprio(who: i32, prio: i32) -> i32 {
    unsafe { libc::setpriority(PRIO_PROCESS, who as u32, prio) }
}

fn getprio(who: i32) -> i32 {
    unsafe { libc::getpriority(PRIO_PROCESS, who as u32) }
}

fn main() {
    // A root process for the unprivileged child to aim at, parked.
    let mut pipefd = [0i32; 2];
    unsafe { libc::pipe(pipefd.as_mut_ptr()) };
    let root_victim = unsafe { libc::fork() };
    if root_victim == 0 {
        unsafe {
            libc::close(pipefd[0]);
            let pid = libc::getpid();
            libc::write(pipefd[1], (&raw const pid).cast(), 4);
            libc::close(pipefd[1]);
            libc::pause();
            libc::_exit(0);
        }
    }
    let victim = unsafe {
        libc::close(pipefd[1]);
        let mut pid = 0i32;
        let n = libc::read(pipefd[0], (&raw mut pid).cast(), 4);
        libc::close(pipefd[0]);
        if n == 4 { pid } else { -1 }
    };

    unsafe {
        let child = libc::fork();
        if child == 0 {
            libc::setresgid(1000, 1000, 1000);
            libc::setresuid(1000, 1000, 1000);
            let mut h = Harness::new();

            h.group("setpriority");
            // Another user's process: EPERM, whichever direction.
            if victim > 0 {
                check_fails!(h, setprio(victim, 5), libc::EPERM,
                             "renice a root process from uid 1000");
            }

            // Lowering our own nice value: EACCES, a different refusal from
            // the one above and one a caller may want to tell apart.
            check_fails!(h, setprio(0, -5), libc::EACCES,
                         "lower our own nice value without privilege");

            // Raising it is always allowed. Without this the two checks above
            // are satisfied by refusing everything.
            check!(h, setprio(0, 5) == 0,
                   "raise our own nice value, errno {}", sys::errno());
            check!(h, getprio(0) == 5, "and it took effect: {}", getprio(0));

            // Having raised it, lowering back toward 0 is still a lowering and
            // still needs privilege.
            check_fails!(h, setprio(0, 0), libc::EACCES,
                         "lower it back again without privilege");

            libc::_exit(h.finish());
        }
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);

        let mut h = Harness::new();
        h.group("root-may");
        check!(h, libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
               "the unprivileged child's checks all passed");
        check!(h, setprio(0, -5) == 0, "root may lower its own nice, errno {}", sys::errno());
        check!(h, getprio(0) == -5, "and it took effect: {}", getprio(0));
        if victim > 0 {
            check!(h, setprio(victim, 7) == 0,
                   "root may renice another process, errno {}", sys::errno());
            libc::kill(victim, libc::SIGKILL);
            let mut st = 0;
            libc::waitpid(victim, &mut st, 0);
        }
        std::process::exit(h.finish());
    }
}
