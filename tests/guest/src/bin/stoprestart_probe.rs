//! A sleep a stop interrupts: what a call with a deadline answers once the
//! process is continued, with no handler run -- `^Z` then `fg`, a debugger
//! attaching. Linux restarts each for what is left of its time
//! (`ERESTART_RESTARTBLOCK`, `restart_syscall`), or from the top for one
//! whose deadline is absolute, so the caller sees no `EINTR` and the full
//! duration.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container and diffed by `tests/integration/probe_diff.sh`. Each case is a
//! child that sleeps 400 ms; it is stopped 60 ms in and continued 60 ms
//! later, and reports its return and whether it slept the whole time.

use std::io::Write;
use std::time::{Duration, Instant};

const MS: u64 = 400;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<44} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn rc(r: i64) -> String {
    if r < 0 {
        match errno() {
            libc::EINTR => "EINTR".into(),
            libc::ETIMEDOUT => "ETIMEDOUT".into(),
            e => format!("errno {e}"),
        }
    } else {
        format!("{r}")
    }
}

fn ts(ms: u64) -> libc::timespec {
    libc::timespec { tv_sec: (ms / 1000) as _, tv_nsec: ((ms % 1000) * 1_000_000) as _ }
}

fn now(clock: libc::clockid_t) -> libc::timespec {
    let mut t = ts(0);
    unsafe { libc::clock_gettime(clock, &mut t) };
    t
}

fn plus(t: libc::timespec, ms: u64) -> libc::timespec {
    let ns = t.tv_nsec as u64 + (ms % 1000) * 1_000_000;
    libc::timespec { tv_sec: t.tv_sec + (ms / 1000 + ns / 1_000_000_000) as i64, tv_nsec: (ns % 1_000_000_000) as _ }
}

/// Run `sleep` in a child that is stopped and continued part-way through.
fn case(name: &str, sleep: fn() -> i64) {
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let t0 = Instant::now();
        let r = sleep();
        let e = errno();
        let full = t0.elapsed() >= Duration::from_millis(MS - 20);
        let out = [r, e as i64, full as i64];
        unsafe {
            libc::write(p[1], out.as_ptr().cast(), 24);
            libc::_exit(0);
        }
    }
    std::thread::sleep(Duration::from_millis(60));
    unsafe { libc::kill(pid, libc::SIGSTOP) };
    std::thread::sleep(Duration::from_millis(60));
    unsafe { libc::kill(pid, libc::SIGCONT) };
    let mut out = [0i64; 3];
    unsafe {
        libc::close(p[1]);
        libc::read(p[0], out.as_mut_ptr().cast(), 24);
        libc::close(p[0]);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    unsafe { *libc::__errno_location() = out[1] as i32 };
    line(name, format!("{}, slept the whole time {}", rc(out[0]), out[2] == 1));
}

static mut WORD: u32 = 0;

fn main() {
    case("nanosleep", || unsafe { libc::nanosleep(&ts(MS), std::ptr::null_mut()) as i64 });
    case("clock_nanosleep MONOTONIC, relative", || unsafe {
        -(libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &ts(MS), std::ptr::null_mut()) as i64)
    });
    case("clock_nanosleep MONOTONIC, TIMER_ABSTIME", || unsafe {
        let at = plus(now(libc::CLOCK_MONOTONIC), MS);
        -(libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &at, std::ptr::null_mut()) as i64)
    });
    case("futex WAIT, 400 ms timeout", || unsafe {
        libc::syscall(libc::SYS_futex, &raw mut WORD, libc::FUTEX_WAIT, 0, &ts(MS), 0, 0)
    });
    case("poll, no fds, 400 ms", || unsafe { libc::poll(std::ptr::null_mut(), 0, MS as i32) as i64 });
    case("ppoll, no fds, 400 ms", || unsafe {
        libc::ppoll(std::ptr::null_mut(), 0, &ts(MS), std::ptr::null()) as i64
    });
    case("select, no fds, 400 ms", || unsafe {
        let mut tv = libc::timeval { tv_sec: 0, tv_usec: (MS * 1000) as _ };
        libc::select(0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut tv) as i64
    });
    case("epoll_wait, empty set, 400 ms", || unsafe {
        let ep = libc::epoll_create1(0);
        let mut ev: libc::epoll_event = std::mem::zeroed();
        libc::epoll_wait(ep, &mut ev, 1, MS as i32) as i64
    });
}
