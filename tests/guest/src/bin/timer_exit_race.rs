//! A process that exits while one of its timers is firing.
//!
//! `timer_free` **waits** for an expiry in flight — that is what stops a
//! timerfd firing after its descriptor is closed. The exit path calls it with
//! `pids_lock` held (one deliberate hold from detach to destroy, see
//! `crates/kernel/exitcalls`' `do_exit`), and a POSIX timer's notification
//! takes `pids_lock` to resolve its target.
//!
//! So: the exiting thread holds the lock and waits for the expiry; the timer
//! service thread is inside the expiry waiting for the lock. Three lines apart
//! in two crates, and neither says the other's name.
//!
//! The window is one expiry wide, so this drives it: a child arms a 1ms
//! repeating timer, lets it fire, and exits while it is still running. The
//! parent gives each child a bounded wait and reports how many never came back.
//! A hang here is the finding; a clean run is not evidence of much, which is
//! why the count is printed rather than asserted on one round.

use guest_tests::{Harness, check};
use std::time::{Duration, Instant};

const ROUNDS: usize = 300;

fn child() -> ! {
    let mut sev: libc::sigevent = unsafe { std::mem::zeroed() };
    sev.sigev_notify = libc::SIGEV_SIGNAL;
    sev.sigev_signo = libc::SIGUSR1;
    let mut id: libc::timer_t = std::ptr::null_mut();
    if unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut id) } != 0 {
        unsafe { libc::_exit(3) };
    }
    // Ignored rather than handled: what matters is that the notification runs,
    // not what it does.
    unsafe { libc::signal(libc::SIGUSR1, libc::SIG_IGN) };
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 },
        it_value: libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 },
    };
    if unsafe { libc::timer_settime(id, 0, &spec, std::ptr::null_mut()) } != 0 {
        unsafe { libc::_exit(4) };
    }
    // Long enough for the timer to be firing steadily, short enough that the
    // exit lands in the middle of one.
    std::thread::sleep(Duration::from_millis(12));
    // No `timer_delete`: exiting with it still armed is the case.
    unsafe { libc::_exit(0) };
}

fn main() {
    let mut h = Harness::new();

    h.group("exit-while-a-timer-is-firing");
    let mut stuck = 0;
    let mut wrong = 0;
    for _ in 0..ROUNDS {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            child();
        }
        if pid < 0 {
            break;
        }
        // A bounded wait: WNOHANG in a loop, so a child that never exits is a
        // count rather than a suite that hangs for ever.
        let start = Instant::now();
        let mut status = 0;
        loop {
            let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if r == pid {
                if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                    wrong += 1;
                }
                break;
            }
            if start.elapsed() > Duration::from_secs(5) {
                stuck += 1;
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    check!(h, stuck == 0, "{stuck} of {ROUNDS} children never exited");
    check!(h, wrong == 0, "{wrong} of {ROUNDS} children exited wrongly");

    std::process::exit(h.finish());
}
