//! A thread is not a child.
//!
//! `clone(CLONE_THREAD)` makes a thread of the calling process, and Linux gives
//! it the **caller's parent** rather than the caller:
//!
//! ```c
//! if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {
//!     p->real_parent = current->real_parent;
//! } else {
//!     p->real_parent = current;
//! }
//! ```
//!
//! Everything in this file follows from that one line, and every check here
//! failed before it was true:
//!
//! - `getppid()` is the same number in every thread of a process, because
//!   the process has one parent.
//! - `wait()` in a thread that created another thread is `ECHILD`. A thread is
//!   not something anybody waits for.
//! - **A process whose second thread exits the group actually exits.** This is
//!   the one that mattered. With a thread recorded as a child of its creator,
//!   the creator's exit path reparented its children to "the first surviving
//!   thread of my group" -- which is that same thread -- so the thread became
//!   its own parent, and the ancestor walk in the next exit never terminated.
//!   A guest process whose worker thread called `exit()` hung forever, holding
//!   whatever it held.
//!
//! Which is any Go program calling `os.Exit` off the main goroutine, any Node
//! worker calling `process.exit`, and any C program calling `exit()` from a
//! thread. It is not an edge case.
//!
//! The last group has no assertion of its own: it either returns or the harness
//! does not finish. That is deliberate -- a hang is the failure, and there is
//! nothing to compare.

use guest_tests::{Harness, check, sys};

fn gettid() -> i64 {
    unsafe { libc::syscall(libc::SYS_gettid) as i64 }
}

fn main() {
    let mut h = Harness::new();

    h.group("a-thread-has-the-process-parent");
    let main_ppid = unsafe { libc::getppid() };
    let main_tid = gettid();
    let (t_ppid, t_tid) = std::thread::spawn(|| (unsafe { libc::getppid() }, gettid()))
        .join()
        .unwrap();
    check!(h, t_tid != main_tid, "the thread has a tid of its own: {t_tid} vs {main_tid}");
    check!(
        h,
        t_ppid == main_ppid,
        "and the same parent as this thread, because the *process* has one \
         parent: {t_ppid} vs {main_ppid}"
    );

    h.group("a-thread-is-not-a-child");
    // wait() in the thread that created one. On Linux a thread is not in
    // anybody's children list, so this is ECHILD -- and if it is not, whatever
    // it returns is a thread being reported as a dead child.
    let (r, e) = std::thread::spawn(|| {
        // A thread of our own, so this thread has "created" something.
        let inner = std::thread::spawn(|| gettid());
        let _ = inner.join();
        sys::clear_errno();
        let mut status = 0i32;
        let r = unsafe { libc::wait(&mut status) };
        (r, sys::errno())
    })
    .join()
    .unwrap();
    check!(
        h,
        r == -1 && e == libc::ECHILD,
        "wait() in a thread that spawned a thread is ECHILD: r={r} errno={e}"
    );

    h.group("the-group-exits-when-a-thread-exits-it");
    // A child process whose *second* thread calls exit_group. The parent waits
    // for it with a bounded number of tries; on the emulator this used to never
    // return, because the exiting thread looped in its own reparenting walk.
    //
    // Run four times: the shape depends on which thread wins a race to exit,
    // and once is not much of a sample.
    for round in 0..4 {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            extern "C" fn body(_: *mut libc::c_void) -> *mut libc::c_void {
                unsafe {
                    libc::usleep(50_000);
                    libc::syscall(libc::SYS_exit_group, 42);
                }
                unreachable!()
            }
            let mut t: libc::pthread_t = unsafe { std::mem::zeroed() };
            unsafe {
                if libc::pthread_create(&mut t, std::ptr::null(), body, std::ptr::null_mut()) != 0 {
                    libc::_exit(9);
                }
                // The main thread waits to be killed. Whether it is blocked or
                // running should not matter, and it did not: every variant hung.
                loop {
                    libc::pause();
                }
            }
        }
        // Bounded, so a hang is a failed check rather than a stuck suite.
        let mut status: i32 = 0;
        let mut reaped = 0;
        for _ in 0..200 {
            let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if r == pid {
                reaped = r;
                break;
            }
            unsafe { libc::usleep(50_000) };
        }
        check!(
            h,
            reaped == pid,
            "round {round}: a process whose second thread calls exit_group exits \
             (waited 10s)"
        );
        if reaped != pid {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
            }
            continue;
        }
        check!(
            h,
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 42,
            "round {round}: with the status that thread asked for: exited={} code={}",
            libc::WIFEXITED(status),
            libc::WEXITSTATUS(status)
        );
    }

    h.group("and-a-thread-calling-exit-does-not");
    // The other half, so the fix above is not "kill the process whenever a
    // thread leaves". SYS_exit ends the thread only.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        extern "C" fn body(_: *mut libc::c_void) -> *mut libc::c_void {
            unsafe {
                libc::syscall(libc::SYS_exit, 1);
            }
            unreachable!()
        }
        let mut t: libc::pthread_t = unsafe { std::mem::zeroed() };
        unsafe {
            if libc::pthread_create(&mut t, std::ptr::null(), body, std::ptr::null_mut()) != 0 {
                libc::_exit(9);
            }
            // Long enough that a process which was going to die would have.
            libc::usleep(400_000);
            libc::_exit(5);
        }
    }
    let mut status: i32 = 0;
    let mut reaped = 0;
    for _ in 0..200 {
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            reaped = r;
            break;
        }
        unsafe { libc::usleep(50_000) };
    }
    check!(h, reaped == pid, "the process is reaped");
    check!(
        h,
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 5,
        "one thread's SYS_exit leaves the process running: code={} (5 means the \
         main thread got to finish, 1 means the thread took the process with it)",
        libc::WEXITSTATUS(status)
    );

    std::process::exit(h.finish());
}
