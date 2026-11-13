//! A blocking syscall can be interrupted by a signal.
//!
//! This is the end-to-end half of the wiring tests in `crates/util/waitfor` and
//! `crates/kernel/taskview`, and it exists because **those cannot be checked by
//! their answer**. Three things have to be in place for a guest thread parked
//! in `wait_for` to wake with `EINTR`, and a test binary can observe none of
//! them:
//!
//! 1. `bind_current` installs `waitfor`'s `signal_pending` hook. With none
//!    installed the hook answers "no signal pending".
//! 2. `set_current` takes a reference to the task's disposition table for this
//!    thread, which is what `signal_pending` reads (2026-09-12,
//!    `docs/object-model-arc.md` step 8). With the maintenance deleted the
//!    thread has no table and the answer is the same "no signal pending".
//! 3. The delivery path wakes the condition variable the thread is parked on.
//!
//! In a `cargo test` binary there is no current task, so the real hook and an
//! absent hook both answer "no". Delete either install and every Rust test in
//! the workspace stays green — and a guest's blocking syscalls stop being
//! interruptible, which is what this program is here to notice. **In a running
//! guest it looks like this**: `read` on an empty pipe never returns, `^C` does
//! nothing, and a shell that types a command and waits for it hangs for ever
//! with the handler installed and the signal pending.
//!
//! **The two halves fail differently, measured on 2026-09-12 by backing each
//! out.** Deleting `waitfor`'s hook install is the quiet one: everything runs
//! and nothing is interruptible, which is what the paragraph above describes
//! and what this program is for.
//!
//! Deleting `set_current`'s maintenance of the cached reference is **not quiet
//! at all**, and that was not predicted. `current_sighand()` then answers null
//! for every task, so `rt_sigaction` fails too — and Rust's own runtime start-up
//! asserts that `signal(SIGPIPE, …)` succeeds, so every Rust program in the
//! guest aborts before `main` with
//!
//! ```text
//! fatal runtime error: assertion failed: signal(libc::SIGPIPE, handler) != libc::SIG_ERR
//! ```
//!
//! while busybox `sh` runs on regardless. So that half is covered by the whole
//! suite rather than only by this program — which is worth knowing, because it
//! means a reviewer looking at a green suite is entitled to more confidence
//! about the cached reference than about the hook.
//!
//! Each case is a thread parked in a *different* kind of wait, because they
//! reach `wait_for` by different routes: a pipe read is `crates/fs/pipe`'s
//! `GuestLock`, `waitpid` is `crates/kernel/waitcalls`', and `pause` is the
//! task's own condition. Every one of them is bounded by an alarm, so a
//! regression is a failed check rather than a suite that hangs.
//!
//! Not `nanosleep`, deliberately: that one is answered by the host's own
//! `nanosleep` returning `EINTR` without passing through this kernel's wait at
//! all, so it would pass against exactly the defect this is about.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicI32, Ordering};

static GOT: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_usr1(sig: i32) {
    GOT.store(sig, Ordering::SeqCst);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A handler **without** `SA_RESTART`, so an interrupted call reports `EINTR`
/// rather than being re-issued. With `SA_RESTART` this whole program would pass
/// against a kernel that never interrupts anything, because "the call returned
/// normally" is what a restart looks like from here.
fn install(sig: i32) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_usr1 as *const () as libc::sighandler_t;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(libc::sigaction(sig, &sa, std::ptr::null_mut()), 0);
    }
}

/// Send `SIGUSR1` to this thread from another one, after it has had time to
/// park.
///
/// A separate *thread* rather than `alarm`, because the point is a signal
/// arriving at a thread that is already inside the wait; and the 200 ms is
/// generous rather than tuned, since the failure this guards against is "never"
/// rather than "late".
fn signal_me_shortly() -> std::thread::JoinHandle<()> {
    let target = unsafe { libc::pthread_self() };
    let target = target as usize;
    std::thread::spawn(move || unsafe {
        libc::usleep(200_000);
        libc::pthread_kill(target as libc::pthread_t, libc::SIGUSR1);
    })
}

/// The whole program is bounded: if a wait is not interrupted, `SIGALRM`'s
/// default action ends the process rather than leaving the suite hanging. A
/// timeout is therefore a loud failure and not a stall.
fn arm_deadline(secs: u32) {
    unsafe { libc::alarm(secs) };
}

fn pipe_read(h: &mut Harness) {
    h.group("pipe-read");
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        check!(h, false, "pipe: errno {}", errno());
        return;
    }
    GOT.store(0, Ordering::SeqCst);
    let waker = signal_me_shortly();
    let mut buf = [0u8; 8];
    // Nothing ever writes it and the write end stays open, so there is no EOF
    // either: the only way out is the signal.
    let r = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
    let e = errno();
    let _ = waker.join();
    check!(
        h,
        r == -1 && e == libc::EINTR,
        "read on an empty pipe is interrupted: r={r} errno={e}"
    );
    check!(
        h,
        GOT.load(Ordering::SeqCst) == libc::SIGUSR1,
        "and the handler ran: got={}",
        GOT.load(Ordering::SeqCst)
    );
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

fn wait_for_a_child(h: &mut Harness) {
    h.group("waitpid");
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Long enough that the parent is certainly inside waitpid when the
        // signal lands, and short enough that it is reaped below.
        unsafe {
            libc::sleep(3);
            libc::_exit(0);
        }
    }
    if pid < 0 {
        check!(h, false, "fork: errno {}", errno());
        return;
    }
    GOT.store(0, Ordering::SeqCst);
    let waker = signal_me_shortly();
    let mut status = 0;
    let got = unsafe { libc::waitpid(pid, &mut status, 0) };
    let e = errno();
    let _ = waker.join();
    check!(
        h,
        got < 0 && e == libc::EINTR,
        "waitpid is interrupted: got={got} errno={e}"
    );
    check!(
        h,
        GOT.load(Ordering::SeqCst) == libc::SIGUSR1,
        "and the handler ran: got={}",
        GOT.load(Ordering::SeqCst)
    );
    // The child is still reapable, which is the other half of an interruption
    // being an interruption rather than a loss.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, &mut status, 0);
    }
}

fn pause_returns(h: &mut Harness) {
    h.group("pause");
    GOT.store(0, Ordering::SeqCst);
    let waker = signal_me_shortly();
    let r = unsafe { libc::pause() };
    let e = errno();
    let _ = waker.join();
    check!(
        h,
        r == -1 && e == libc::EINTR,
        "pause returns once a handler has run: r={r} errno={e}"
    );
}

fn main() {
    // Ten seconds covers three cases whose own waits are 200 ms each plus a
    // 3 s child. A run that reaches this limit has failed to interrupt
    // something, and dying on SIGALRM says so in the suite's exit status.
    arm_deadline(10);
    install(libc::SIGUSR1);

    let mut h = Harness::new();
    pipe_read(&mut h);
    wait_for_a_child(&mut h);
    pause_returns(&mut h);
    let rc = h.finish();
    unsafe { libc::alarm(0) };
    std::process::exit(rc);
}
