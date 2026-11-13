//! Who may signal whom.
//!
//! Linux: "For a process to have permission to send a signal, it must either be
//! privileged, or the real or effective user ID of the sending process must
//! equal the real or saved set-user-ID of the target process."
//!
//! `do_kill` had no such check. Any process could signal any other, whatever
//! their ids — so an unprivileged guest process could `SIGKILL` a root one.
//!
//! Note which ids the rule names. The **sender's** real or effective, against
//! the **target's** real or saved. The target's *effective* id is not in it,
//! which is what stops a process that has temporarily dropped its effective id
//! from becoming signalable by whoever it dropped to. That case is checked here
//! because comparing against the effective id is the plausible wrong version.
//!
//! `kill(pid, 0)` sends nothing and reports only the permission answer, so the
//! denials can be probed without the test killing itself.

use guest_tests::{Harness, check, check_fails, sys};

fn kill0(pid: i32) -> i32 {
    unsafe { libc::kill(pid, 0) }
}

fn main() {
    // A child that keeps a real and saved uid of 0 while dropping its
    // *effective* one to 1000, and parks. The rule must still refuse a sender
    // at 1000, because it looks at the real and saved ids.
    let mut pipefd = [0i32; 2];
    unsafe { libc::pipe(pipefd.as_mut_ptr()) };
    let masked = unsafe { libc::fork() };
    if masked == 0 {
        unsafe {
            libc::close(pipefd[0]);
            libc::setresuid(u32::MAX, 1000, u32::MAX);
            let pid = libc::getpid();
            libc::write(pipefd[1], (&raw const pid).cast(), 4);
            libc::close(pipefd[1]);
            libc::pause();
            libc::_exit(0);
        }
    }
    let masked_pid = unsafe {
        libc::close(pipefd[1]);
        let mut pid = 0i32;
        let n = libc::read(pipefd[0], (&raw mut pid).cast(), 4);
        libc::close(pipefd[0]);
        if n == 4 { pid } else { -1 }
    };

    let root_pid = unsafe { libc::getpid() };

    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::setresgid(1000, 1000, 1000);
            libc::setresuid(1000, 1000, 1000);
        }
        let mut h = Harness::new();
        h.group("kill-permission");

        // The hole: an unprivileged process signalling a root one.
        check_fails!(h, kill0(root_pid), libc::EPERM, "kill(root process, 0) from uid 1000");

        // Itself, which shares its ids.
        check!(h, kill0(unsafe { libc::getpid() }) == 0, "kill(self, 0)");

        // A process whose *effective* id is 1000 but whose real and saved are
        // 0. The rule names real and saved, so this is still refused.
        if masked_pid > 0 {
            check_fails!(
                h,
                kill0(masked_pid),
                libc::EPERM,
                "kill(a process that only dropped its effective uid, 0)"
            );
        }

        // A process that really does share our uid: permitted. Without this the
        // checks above are satisfied by refusing everything.
        let grand = unsafe { libc::fork() };
        if grand == 0 {
            let parent = unsafe { libc::getppid() };
            unsafe { libc::_exit(if kill0(parent) == 0 { 0 } else { 1 }) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(grand, &mut status, 0) };
        check!(
            h,
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "a process of the same uid may signal us"
        );

        // ESRCH, not EPERM, for something that is not there at all: a caller
        // probing for a process must be able to tell the two apart.
        check_fails!(h, kill0(0x3fff_0000), libc::ESRCH, "kill(a pid that does not exist, 0)");

        unsafe { libc::_exit(h.finish()) };
    }

    let mut h = Harness::new();
    h.group("kill-permission-root");
    // Root may signal anyone, including the unprivileged child.
    check!(h, kill0(child) == 0, "root may signal an unprivileged process");
    if masked_pid > 0 {
        check!(h, kill0(masked_pid) == 0, "root may signal the masked process");
    }

    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, 0) };
    let child_failures = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 99 };
    check!(h, child_failures == 0, "the unprivileged child's checks: {child_failures} failed");

    if masked_pid > 0 {
        unsafe {
            libc::kill(masked_pid, libc::SIGKILL);
            libc::waitpid(masked_pid, &mut status, 0);
        }
    }
    let _ = sys::errno();
    std::process::exit(h.finish());
}
