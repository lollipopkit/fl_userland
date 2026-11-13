//! `WUNTRACED` and `WCONTINUED` have to be reported when they happen.
//!
//! Three events make a `wait` return: a child exits, a child stops, a stopped
//! child is continued. In this kernel the first two notify the parent's
//! `child_exit` condition variable and the third does not — `SIGCONT` sets
//! `group->continued` and notifies `stopped_cond`, which belongs to the
//! *stopped* group and is not what the parent is waiting on.
//!
//! It works anyway, because `do_wait` waits with a **one-second timeout** and
//! rescans on every tick:
//!
//! ```c
//! // Use a bounded 1-second timeout to work around macOS condvar issues
//! struct timespec waitpid_timeout = {.tv_sec = 1, .tv_nsec = 0};
//! ```
//!
//! So a missing notify is invisible in a pass/fail sense and shows up only as
//! latency. This measures it. A real Linux kernel answers in microseconds and
//! `differential.sh` compares the two, so the assertion is one both sides can
//! meet if the notify is there.
//!
//! # Why the threshold is 800 ms
//!
//! Each measurement starts 300 ms before its signal, because the signal has to
//! be sent from another thread *after* this one is blocked — otherwise the flag
//! is already set when the wait begins, its first scan finds it, and a missing
//! wakeup is invisible. So the budget is 300 ms of deliberate delay plus 500 ms,
//! which is well under the second a poll tick costs and well over anything a
//! correct implementation needs. Tightening it further would measure the
//! emulator's speed rather than whether the wakeup happened.
//!
//! POSIX also says a stopped child being continued generates `SIGCHLD` for the
//! parent, which is checked separately: the stop path sends one and the
//! continue path does not.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

static SIGCHLD_COUNT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_sigchld(_: libc::c_int) {
    SIGCHLD_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// How long the waker waits before signalling. Long enough that the main
/// thread is certainly inside `waitpid` by then, short enough that four of
/// these do not dominate the run.
const WAKE_DELAY_US: u32 = 300_000;

/// Send `sig` to `pid` once the caller has had time to block in `waitpid`.
///
/// A thread rather than a helper process: a second child would generate
/// `SIGCHLD` of its own when it exited, and the counts below are what two of
/// these checks are about.
fn signal_after(pid: i32, sig: libc::c_int) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || unsafe {
        libc::usleep(WAKE_DELAY_US);
        libc::kill(pid, sig);
    })
}

/// A child that stops when told and otherwise does nothing expensive.
fn spawn_child() -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // `pause` returns on every signal; the loop is what makes SIGCONT
        // resume something rather than end it. SIGSTOP and SIGKILL are not
        // deliverable to a handler, so nothing here has to cooperate.
        loop {
            unsafe { libc::pause() };
        }
    }
    pid
}

fn main() {
    let mut h = Harness::new();

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigchld as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut());
    }

    let pid = spawn_child();
    check!(h, pid > 0, "forked a child to stop and continue");

    // Give it time to reach pause(). Not part of what is measured: every
    // timing below starts after the signal that the wait is about.
    unsafe { libc::usleep(200_000) };

    h.group("a-stop-is-reported-promptly");
    SIGCHLD_COUNT.store(0, Ordering::SeqCst);
    // The signal is sent from a thread *after* this one is already blocked in
    // waitpid, which is the whole point. Sending it first and then waiting
    // measures nothing: the flag is already set, so the wait's first scan finds
    // it and a missing wakeup is invisible. The first version of this file did
    // exactly that and reported 0ms against code with no notify at all.
    let started = Instant::now();
    let waker = signal_after(pid, libc::SIGSTOP);
    let mut st = 0i32;
    let r = unsafe { libc::waitpid(pid, &mut st, libc::WUNTRACED) };
    let stop_ms = started.elapsed().as_millis();
    waker.join().unwrap();
    check!(h, r == pid, "waitpid(WUNTRACED) returned the child: {r}");
    check!(h, libc::WIFSTOPPED(st), "and says it is stopped: status {st:#x}");
    check!(
        h,
        libc::WSTOPSIG(st) == libc::SIGSTOP,
        "with SIGSTOP as the stop signal: {}",
        libc::WSTOPSIG(st)
    );
    check!(h, stop_ms < 800, "reported {}ms after the signal, not after a poll tick",
           stop_ms.saturating_sub(300));
    check!(
        h,
        SIGCHLD_COUNT.load(Ordering::SeqCst) >= 1,
        "and the parent was sent SIGCHLD for the stop"
    );

    h.group("a-continue-is-reported-promptly");
    SIGCHLD_COUNT.store(0, Ordering::SeqCst);
    let started = Instant::now();
    let waker = signal_after(pid, libc::SIGCONT);
    let mut st = 0i32;
    let r = unsafe { libc::waitpid(pid, &mut st, libc::WCONTINUED) };
    let cont_ms = started.elapsed().as_millis();
    waker.join().unwrap();
    check!(h, r == pid, "waitpid(WCONTINUED) returned the child: {r}");
    check!(h, libc::WIFCONTINUED(st), "and says it was continued: status {st:#x}");
    // The one this file exists for. SIGCONT notifies the stopped group's own
    // stopped_cond and never the parent's child_exit, so the parent sleeps
    // until do_wait's one-second poll tick rescans and finds the flag.
    check!(h, cont_ms < 800, "reported {}ms after the signal, not after a poll tick",
           cont_ms.saturating_sub(300));
    check!(
        h,
        SIGCHLD_COUNT.load(Ordering::SeqCst) >= 1,
        "and the parent was sent SIGCHLD for the continue"
    );

    h.group("the-event-is-consumed-by-the-wait-that-reports-it");
    // A second WCONTINUED with WNOHANG must find nothing: the continue was
    // already reported. Otherwise a loop over wait() reports one continue for
    // ever.
    let mut st = 0i32;
    let r = unsafe { libc::waitpid(pid, &mut st, libc::WCONTINUED | libc::WNOHANG) };
    check!(h, r == 0, "the same continue is not reported twice: {r}");

    h.group("an-exit-is-still-reported");
    let started = Instant::now();
    let waker = signal_after(pid, libc::SIGKILL);
    let mut st = 0i32;
    let r = unsafe { libc::waitpid(pid, &mut st, 0) };
    let exit_ms = started.elapsed().as_millis();
    waker.join().unwrap();
    check!(h, r == pid, "waitpid returned the killed child: {r}");
    check!(h, libc::WIFSIGNALED(st), "and says it was signalled: {st:#x}");
    check!(h, exit_ms < 800, "reported {}ms after the signal", exit_ms.saturating_sub(300));

    std::process::exit(h.finish());
}
