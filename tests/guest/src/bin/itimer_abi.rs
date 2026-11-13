//! `setitimer` and `getitimer`: the three timers, and what asking about one
//! that was never set answers.
//!
//! A program that wants a periodic signal checks whether a timer is already
//! armed before it arms its own. `getitimer` on a timer nobody has set is
//! **zeroes and success** — not an error — and a kernel that refuses instead
//! turns that check into a failure the caller cannot tell from a real one.
//!
//! `ITIMER_REAL` is wall-clock and is what `alarm` is built on. `ITIMER_VIRTUAL`
//! and `ITIMER_PROF` count CPU time.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

static ALARMS: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_alarm(_: i32) {
    ALARMS.fetch_add(1, Ordering::SeqCst);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn zero() -> libc::itimerval {
    libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: 0, tv_usec: 0 },
    }
}

fn get(which: i32) -> (i32, libc::itimerval, i32) {
    let mut v = zero();
    let r = unsafe { libc::getitimer(which, &mut v) };
    (r, v, errno())
}

fn set(which: i32, v: &libc::itimerval) -> (i32, libc::itimerval, i32) {
    let mut old = zero();
    let r = unsafe { libc::setitimer(which, v, &mut old) };
    (r, old, errno())
}

fn main() {
    let mut h = Harness::new();

    h.group("asking-about-a-timer-nobody-set");
    // Zeroes and success, for all three. This is the check a program makes
    // before it arms its own.
    for (which, name) in [
        (libc::ITIMER_REAL, "ITIMER_REAL"),
        (libc::ITIMER_VIRTUAL, "ITIMER_VIRTUAL"),
        (libc::ITIMER_PROF, "ITIMER_PROF"),
    ] {
        let (r, v, e) = get(which);
        check!(h, r == 0, "getitimer({name}) succeeds: r={r} errno={e}");
        check!(h, v.it_value.tv_sec == 0 && v.it_value.tv_usec == 0
                  && v.it_interval.tv_sec == 0 && v.it_interval.tv_usec == 0,
            "and reports nothing armed: {} {} {} {}",
            v.it_value.tv_sec, v.it_value.tv_usec,
            v.it_interval.tv_sec, v.it_interval.tv_usec);
    }

    h.group("which-numbers-exist");
    for bad in [3i32, 4, -1] {
        let (r, _, e) = get(bad);
        check!(h, r == -1 && e == libc::EINVAL, "getitimer({bad}) is EINVAL: r={r} errno={e}");
        let v = zero();
        let (r, _, e) = set(bad, &v);
        check!(h, r == -1 && e == libc::EINVAL, "setitimer({bad}) is EINVAL: r={r} errno={e}");
    }

    h.group("arming-and-reading-back");
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = on_alarm as *const () as usize;
    unsafe { libc::sigemptyset(&mut act.sa_mask) };
    unsafe { libc::sigaction(libc::SIGALRM, &act, std::ptr::null_mut()) };

    let want = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: 10, tv_usec: 0 },
    };
    let (r, old, e) = set(libc::ITIMER_REAL, &want);
    check!(h, r == 0, "setitimer(ITIMER_REAL, 10s): r={r} errno={e}");
    check!(h, old.it_value.tv_sec == 0 && old.it_value.tv_usec == 0,
        "the old value was nothing: {} {}", old.it_value.tv_sec, old.it_value.tv_usec);
    let (r, v, _) = get(libc::ITIMER_REAL);
    check!(h, r == 0, "getitimer reads it back: r={r}");
    check!(h, v.it_value.tv_sec > 8 && v.it_value.tv_sec <= 10,
        "with the time remaining, counting down: {}s {}us", v.it_value.tv_sec, v.it_value.tv_usec);

    h.group("disarming");
    let (r, old, e) = set(libc::ITIMER_REAL, &zero());
    check!(h, r == 0, "setitimer with zeroes disarms: r={r} errno={e}");
    check!(h, old.it_value.tv_sec > 8, "and reports what was left: {}s", old.it_value.tv_sec);
    let (_, v, _) = get(libc::ITIMER_REAL);
    check!(h, v.it_value.tv_sec == 0 && v.it_value.tv_usec == 0,
        "nothing is armed now: {}s {}us", v.it_value.tv_sec, v.it_value.tv_usec);

    h.group("a-malformed-request");
    // A microsecond field of a whole second or more, and a negative one. Both
    // for the value and for the interval -- the interval is what every re-arm
    // after the first one uses, so an unchecked one is a bad timespec later.
    for (sec, usec, what) in [
        (0i64, 1_000_000i64, "a whole second of microseconds"),
        (0, -1, "a negative microsecond"),
        (-1, 0, "a negative second"),
    ] {
        let v = libc::itimerval {
            it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
            it_value: libc::timeval { tv_sec: sec as _, tv_usec: usec as _ },
        };
        let (r, _, e) = set(libc::ITIMER_REAL, &v);
        check!(h, r == -1 && e == libc::EINVAL, "{what} in the value: r={r} errno={e}");
        let v = libc::itimerval {
            it_interval: libc::timeval { tv_sec: sec as _, tv_usec: usec as _ },
            it_value: libc::timeval { tv_sec: 0, tv_usec: 1000 },
        };
        let (r, _, e) = set(libc::ITIMER_REAL, &v);
        check!(h, r == -1 && e == libc::EINVAL, "{what} in the interval: r={r} errno={e}");
    }
    let (_, v, _) = get(libc::ITIMER_REAL);
    check!(h, v.it_value.tv_sec == 0 && v.it_value.tv_usec == 0,
        "and a refused request armed nothing: {}s {}us", v.it_value.tv_sec, v.it_value.tv_usec);

    h.group("it-fires");
    ALARMS.store(0, Ordering::SeqCst);
    let want = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: 0, tv_usec: 80_000 },
    };
    let (r, _, e) = set(libc::ITIMER_REAL, &want);
    check!(h, r == 0, "setitimer(80ms): r={r} errno={e}");
    let start = Instant::now();
    while ALARMS.load(Ordering::SeqCst) == 0 && start.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(5));
    }
    let ms = start.elapsed().as_millis();
    check!(h, ALARMS.load(Ordering::SeqCst) >= 1, "SIGALRM arrives: after {ms}ms");
    check!(h, ms < 2000, "promptly: {ms}ms");
    let (_, v, _) = get(libc::ITIMER_REAL);
    check!(h, v.it_value.tv_sec == 0 && v.it_value.tv_usec == 0,
        "and a one-shot is disarmed after it fires: {}s {}us",
        v.it_value.tv_sec, v.it_value.tv_usec);

    h.group("repeating");
    ALARMS.store(0, Ordering::SeqCst);
    let want = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 40_000 },
        it_value: libc::timeval { tv_sec: 0, tv_usec: 40_000 },
    };
    let (r, _, e) = set(libc::ITIMER_REAL, &want);
    check!(h, r == 0, "setitimer with an interval: r={r} errno={e}");
    let start = Instant::now();
    while ALARMS.load(Ordering::SeqCst) < 3 && start.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(5));
    }
    check!(h, ALARMS.load(Ordering::SeqCst) >= 3,
        "it repeats: {} in {}ms", ALARMS.load(Ordering::SeqCst), start.elapsed().as_millis());
    let (_, v, _) = get(libc::ITIMER_REAL);
    check!(h, v.it_interval.tv_usec == 40_000,
        "and the interval is reported: {}us", v.it_interval.tv_usec);
    set(libc::ITIMER_REAL, &zero());

    h.group("armed-by-a-thread-that-exits");
    // `ITIMER_REAL` is the **process's** timer, not the arming thread's:
    // Linux's `it_real_fn` signals `signal->leader_pid`, so a thread that arms
    // one and then exits still leaves a timer that signals the process.
    //
    // **In a fresh child, and that is the whole difficulty.** This kernel makes
    // the group's host timer lazily, on the first `setitimer` the process does,
    // and records the arming task then. Doing this in the parent would have the
    // main thread's earlier `it-fires` group create it, so the spawned thread
    // below would only re-arm a timer that already points somewhere else — a
    // check that passes whatever the answer is. The first version of this was
    // exactly that, and it passed here and on Linux alike.
    //
    // So: fork, and in the child let a *thread* be the first to arm it, then
    // let that thread exit before it fires.
    let child = unsafe { libc::fork() };
    if child == 0 {
        let want = libc::itimerval {
            it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
            it_value: libc::timeval { tv_sec: 0, tv_usec: 120_000 },
        };
        ALARMS.store(0, Ordering::SeqCst);
        let armer = std::thread::spawn(move || set(libc::ITIMER_REAL, &want));
        let (r, _, _) = armer.join().expect("the arming thread finished");
        if r != 0 {
            unsafe { libc::_exit(2) };
        }
        // Joined, so the arming thread is gone. Its timer is not.
        let start = Instant::now();
        while ALARMS.load(Ordering::SeqCst) == 0 && start.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(5));
        }
        unsafe { libc::_exit(i32::from(ALARMS.load(Ordering::SeqCst) == 0)) };
    }
    check!(h, child > 0, "fork: {child}");
    let mut status = 0;
    let waited = unsafe { libc::waitpid(child, &mut status, 0) };
    let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 };
    check!(h, waited == child && code == 0,
        "a timer armed by a thread still signals the process after that thread exits: \
         waited={waited} status={status:#x} code={code}");

    std::process::exit(h.finish());
}
