//! `capget` for a process other than the caller.
//!
//! Linux lets any process read any other's capability sets, and reports the
//! **target's**. `sys_capget` looked the target up only to check it existed,
//! then filled the answer in from `superuser()` — the *caller's* privilege.
//!
//! So root asking about an unprivileged process was told it holds every
//! capability, and an unprivileged process asking about root was told it holds
//! none. Both are the caller's own answer wearing someone else's pid.
//!
//! This is the shape of defect the credential work opened up: while every guest
//! process was root, the caller's privilege and the target's were the same
//! thing, and reading one for the other could not be observed.

use guest_tests::{Harness, check, sys};

#[repr(C)]
#[derive(Clone, Copy, Default)]
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

const CAP_VERSION_3: u32 = 0x2008_0522;

/// The permitted set of `pid`, or None if the call failed.
fn permitted_of(pid: i32) -> Option<u32> {
    let mut header = Header { version: CAP_VERSION_3, pid };
    let mut data = [Data::default(); 2];
    let r = unsafe {
        libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr())
    };
    if r == 0 { Some(data[0].permitted) } else { None }
}

fn main() {
    let mut pipefd = [0i32; 2];
    unsafe { libc::pipe(pipefd.as_mut_ptr()) };

    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::close(pipefd[0]);
            let parent = libc::getppid();
            libc::setresgid(1000, 1000, 1000);
            libc::setresuid(1000, 1000, 1000);
            // Asking about root, as an unprivileged process.
            let of_root = permitted_of(parent).unwrap_or(0);
            let mine = permitted_of(0).unwrap_or(0);
            let pid = libc::getpid();
            let msg = [pid as u32, of_root, mine];
            libc::write(pipefd[1], msg.as_ptr().cast(), 12);
            libc::close(pipefd[1]);
            libc::pause();
            libc::_exit(0);
        }
    }

    let (child_pid, of_root, child_of_self) = unsafe {
        libc::close(pipefd[1]);
        let mut msg = [0u32; 3];
        let n = libc::read(pipefd[0], msg.as_mut_ptr().cast(), 12);
        libc::close(pipefd[0]);
        if n == 12 { (msg[0] as i32, msg[1], msg[2]) } else { (-1, 0, 0) }
    };

    let mut h = Harness::new();
    h.group("capget-cross-process");
    check!(h, child_pid > 0, "the child reported its pid");

    // Root's own set, for comparison. This is what the child should have seen.
    let of_self = permitted_of(0).unwrap_or(0);
    check!(h, of_self != 0, "root holds capabilities: {of_self:#x}");

    check!(
        h,
        of_root == of_self,
        "an unprivileged process reading root's set sees root's: got {of_root:#x}, wanted {of_self:#x}"
    );
    check!(
        h,
        child_of_self == 0,
        "and reading its own sees none: got {child_of_self:#x}"
    );

    if child_pid > 0 {
        let of_child = permitted_of(child_pid).unwrap_or(0xdead);
        check!(
            h,
            of_child == 0,
            "root reading an unprivileged process's set sees none: got {of_child:#x}"
        );
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
            let mut st = 0;
            libc::waitpid(child_pid, &mut st, 0);
        }
    }

    // A pid that does not exist is ESRCH, so the checks above cannot be
    // satisfied by a call that quietly answers zero for everything.
    let gone = permitted_of(0x3fff_0000);
    check!(
        h,
        gone.is_none() && sys::errno() == libc::ESRCH,
        "capget of a pid that does not exist is ESRCH, errno {}",
        sys::errno()
    );

    std::process::exit(h.finish());
}
