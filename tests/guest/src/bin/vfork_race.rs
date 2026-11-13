//! A `vfork` parent must not touch the child's task after it wakes.
//!
//! `do_clone` used to put a `struct vfork_info` on the **parent's stack**, hand
//! the child a pointer to it, wait, and then clear that pointer:
//!
//! ```c
//! while (!vfork.done)
//!     wait_for_ignore_signals(&vfork.cond, &vfork.lock, NULL);
//! unlock(&vfork.lock);
//! lock(&task->general_lock);      // <-- `task` may already be freed
//! task->vfork = NULL;
//! ```
//!
//! `vfork_notify` is what wakes the parent, and in the exit case it is called
//! from `do_exit` a dozen lines above `task_destroy`. So the child can finish
//! exiting, be reaped and have its `struct task` zeroed and freed while the
//! parent is on its way to that `lock()`. The file even says so, about the pid
//! it saves for exactly this reason: "task might be destroyed by the time we
//! finish".
//!
//! # What makes the window reachable
//!
//! `signal(SIGCHLD, SIG_IGN)`. A parent that has said it will never wait gets
//! its children released as they exit -- `do_exit`'s auto-reap path -- so the
//! child runs `vfork_notify`, then `tgroup_release`, then `task_destroy`, all
//! in one stretch on its own thread. Without it the child parks as a zombie and
//! only a `wait` frees it, which needs a second thread and a much luckier race.
//!
//! Found by reading, then reproduced with this: it aborts on the first
//! iteration of every run under `-DLOCK_DEBUG=1`, which is not a race at all
//! once `SIGCHLD` is ignored -- the child is simply always ahead.
//!
//! # What it guards now
//!
//! The handoff is `crates/kernel/vforkhandoff`, an `Arc` held by each side, so
//! there is no longer a stack frame for anyone to outlive. This is what says
//! the C half of that -- the handle in `struct task`, the release on each side,
//! and the notify from both `execve` and `do_exit` -- is wired up.

use guest_tests::{Harness, check};

const CLONE_VM: u64 = 0x00000100;
const CLONE_VFORK: u64 = 0x00004000;
const SIGCHLD: u64 = 17;

/// `clone(CLONE_VM|CLONE_VFORK|SIGCHLD)`, returning the child's pid in the
/// parent and 0 in the child.
///
/// Raw, not `libc::fork`: `CLONE_VFORK` is the whole subject and nothing in
/// libc exposes it on its own. `CLONE_VM` comes with it because that is what
/// makes a vfork a vfork -- the two share an address space until the child
/// execs or exits, which is why the parent has to be stopped meanwhile.
unsafe fn vfork_clone() -> i64 {
    // aarch64 clone(flags, stack, ptid, tls, ctid). A null stack means the
    // child resumes on the caller's, which is what vfork does.
    unsafe {
        libc::syscall(libc::SYS_clone, CLONE_VM | CLONE_VFORK | SIGCHLD, 0u64, 0u64, 0u64, 0u64)
    }
}

fn main() {
    let mut h = Harness::new();

    // The auto-reap path: the child frees its own task rather than waiting to
    // be collected, which is what closes the window to a few instructions.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
    h.group("vfork-with-sigchld-ignored");

    let rounds = 400;
    let mut made = 0;
    for _ in 0..rounds {
        let rc = unsafe { vfork_clone() };
        if rc == 0 {
            // Straight out. Anything else here runs in the parent's address
            // space with the parent stopped, and the point is to reach do_exit
            // as fast as possible.
            unsafe { libc::_exit(0) };
        }
        if rc < 0 {
            break;
        }
        made += 1;
    }

    // Reaching here at all is the check: the failure is the emulator trapping
    // or faulting inside the parent's `lock(&task->general_lock)`, which ends
    // the process rather than any assertion.
    check!(h, made == rounds, "{made} of {rounds} vforks completed");

    // And the parent is still able to do ordinary work afterwards -- a task
    // struct scribbled on rather than freed does not necessarily crash at once.
    let pid = unsafe { libc::getpid() };
    check!(h, pid > 0, "the parent still answers getpid(): {pid}");

    // The other caller of vfork_notify. A child that execs reports in from
    // kernel/exec.c and then keeps running, so the parent resumes while the
    // child is alive -- and the child's later exit notifies a second time,
    // which is why the notify has to be idempotent rather than merely
    // unrepeated.
    h.group("vfork-that-execs");
    let mut execed = 0;
    for _ in 0..50 {
        let rc = unsafe { vfork_clone() };
        if rc == 0 {
            unsafe {
                let path = c"/bin/true";
                let argv = [path.as_ptr(), core::ptr::null()];
                libc::execv(path.as_ptr(), argv.as_ptr());
                // execv only returns on failure, and the parent is stopped
                // until this task leaves the address space either way.
                libc::_exit(127);
            }
        }
        if rc < 0 {
            break;
        }
        execed += 1;
    }
    check!(h, execed == 50, "{execed} of 50 vfork+exec pairs completed");

    std::process::exit(h.finish());
}
