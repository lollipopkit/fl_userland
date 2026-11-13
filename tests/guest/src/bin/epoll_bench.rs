//! What an `epoll_wait` costs when almost nothing is ready.
//!
//! This is the measurement behind a standing note that `fs/poll.c` walks every
//! member of the set on every wakeup. `epoll` exists precisely so that it does
//! not have to: a set of a thousand descriptors with one ready should cost
//! about what a set of ten with one ready costs, because the kernel keeps a
//! *ready list* and reports from that.
//!
//! # The control
//!
//! `poll()` is the control, and it is the whole reason this file can conclude
//! anything. `poll()`'s ABI *requires* a walk of all N — the caller hands over
//! an array and gets it back annotated — so its per-descriptor cost is the
//! floor for "an O(N) implementation on this machine, in this emulator, under
//! this load". If `epoll_wait` tracks it, `epoll_wait` is doing the walk that
//! `epoll` is for. If `epoll_wait` stays flat while `poll` climbs, it is not.
//!
//! Without that column a slow `epoll_wait` says nothing: everything in an
//! emulator is slow, and a number with nothing beside it is not a finding.
//! (A previous measurement in this tree blamed a lock for a 4.6x slowdown that
//! a control showed was not there at all.)
//!
//! Both columns wait on the same set of pipes with the same single writer, so
//! the readiness, the wakeup and the syscall entry are common to both and the
//! difference is the scan.
//!
//! # What it measured
//!
//! Before the ready list, `epoll_wait` tracked the control -- it was doing the
//! walk `epoll` exists to avoid:
//!
//!     N     epoll_wait   poll     ratio
//!     8       4.71 us    6.34 us   0.74
//!     64     16.95      27.99      0.61
//!     256    57.34     115.90      0.49
//!
//! After, it is flat, and the control still climbs -- which is what says the
//! machine did not change underneath the measurement:
//!
//!     8       3.46 us    6.96 us   0.50
//!     64      4.28      31.54      0.14
//!     256     4.06     117.40      0.03
//!
//! # The second dimension: how big an answer the caller made room for
//!
//! `max_events` is what a caller is *willing* to handle in one pass, not what
//! it gets. libuv and Go both pass 1024 and almost always get one event back.
//! A kernel that does work proportional to the array rather than to the answer
//! pays it on every wakeup of every event loop, and nothing measured it until
//! 2026-08-31 -- this ran only at 8, which is small enough to hide it.
//!
//! It found one immediately. `crates/kernel/epollcalls` zeroed the whole array
//! per call, because `Vec::resize` does and the C it replaced used a stack VLA:
//!
//!     max_events   C     first Rust   reused array
//!         8      0.93 us   1.08 us      0.93 us
//!        64      0.93      0.96         0.92
//!       256      0.92      1.02         0.92
//!      1024      0.93      1.30         0.92
//!
//! Flat is the answer. A column that climbs with `max_events` means the array
//! is being touched rather than the answer.

use std::time::Instant;

const ROUNDS: usize = 200;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

struct Set {
    /// Read ends, all registered; only the last one is ever written to.
    r: Vec<i32>,
    w: Vec<i32>,
}

impl Set {
    fn new(n: usize) -> Set {
        let mut s = Set { r: Vec::with_capacity(n), w: Vec::with_capacity(n) };
        for _ in 0..n {
            let mut p = [0i32; 2];
            if unsafe { libc::pipe(p.as_mut_ptr()) } != 0 {
                eprintln!("pipe failed at {} descriptors: errno={}", s.r.len(), errno());
                break;
            }
            s.r.push(p[0]);
            s.w.push(p[1]);
        }
        s
    }

    /// Make exactly one member readable, wait, and drain it again.
    fn poke(&self) {
        let last = *self.w.last().unwrap();
        unsafe { libc::write(last, b"x".as_ptr().cast(), 1) };
    }
    fn drain(&self) {
        let last = *self.r.last().unwrap();
        let mut b = [0u8; 1];
        unsafe { libc::read(last, b.as_mut_ptr().cast(), 1) };
    }
}

impl Drop for Set {
    fn drop(&mut self) {
        for fd in self.r.iter().chain(self.w.iter()) {
            unsafe { libc::close(*fd) };
        }
    }
}

/// Microseconds per `epoll_wait` that returns one event out of `n` registered,
/// with an output array of `max_events`.
///
/// `max_events` is a dimension of its own and not a detail. A caller asks for
/// as many events as it is willing to handle in one pass and gets however many
/// are ready — libuv and Go both pass 1024 and almost always get one — so a
/// kernel that does work proportional to *the array* rather than to the answer
/// pays it on every wakeup of every event loop. This ran only at 8 until
/// 2026-08-31, and 8 is small enough to hide it.
fn epoll_us(set: &Set, max_events: usize) -> f64 {
    let ep = unsafe { libc::epoll_create1(0) };
    if ep < 0 {
        return f64::NAN;
    }
    for (i, fd) in set.r.iter().enumerate() {
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: i as u64 };
        unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, *fd, &mut ev) };
    }
    let mut out = vec![libc::epoll_event { events: 0, u64: 0 }; max_events];
    // One untimed pass first, so the first measured call is not the one that
    // creates the notify pipe and registers it.
    set.poke();
    unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), max_events as i32, 1000) };
    set.drain();

    let start = Instant::now();
    for _ in 0..ROUNDS {
        set.poke();
        let n = unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), max_events as i32, 1000) };
        if n < 1 {
            eprintln!("epoll_wait returned {n} errno={}", errno());
        }
        set.drain();
    }
    let el = start.elapsed();
    unsafe { libc::close(ep) };
    el.as_secs_f64() * 1e6 / ROUNDS as f64
}

/// The control: the same wait, with an ABI that cannot avoid the walk.
fn poll_us(set: &Set) -> f64 {
    let mut pfds: Vec<libc::pollfd> = set.r.iter()
        .map(|fd| libc::pollfd { fd: *fd, events: libc::POLLIN, revents: 0 })
        .collect();
    set.poke();
    unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as _, 1000) };
    set.drain();

    let start = Instant::now();
    for _ in 0..ROUNDS {
        set.poke();
        let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as _, 1000) };
        if n < 1 {
            eprintln!("poll returned {n} errno={}", errno());
        }
        set.drain();
    }
    start.elapsed().as_secs_f64() * 1e6 / ROUNDS as f64
}

fn main() {
    // The default is 1024 and a set of N needs 2N descriptors, so the 512 row
    // ran out at 510 and printed a skip. The point of the large sizes is what
    // happens at them.
    let lim = libc::rlimit {
        rlim_cur: 8192,
        rlim_max: 8192,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) };

    println!("{:>8} {:>14} {:>14} {:>10}", "N", "epoll_wait us", "poll us", "ratio");
    let mut first: Option<(f64, f64)> = None;
    for n in [8usize, 64, 256, 512] {
        let set = Set::new(n);
        if set.r.len() < n {
            println!("{n:>8}  (only {} descriptors available)", set.r.len());
            continue;
        }
        let e = epoll_us(&set, 8);
        let p = poll_us(&set);
        println!("{n:>8} {e:>14.2} {p:>14.2} {:>10.2}", e / p);
        if first.is_none() {
            first = Some((e, p));
        }
    }
    // What the size of the *output array* costs, with the set held at 64 and
    // one event ready every time. A caller that asks for 1024 and gets 1 must
    // pay the same as one that asks for 8 and gets 1: the answer is the same
    // size either way. It did not -- crates/kernel/epollcalls zeroed the whole
    // array on every call, because Rust's Vec::resize does.
    println!("\n{:>14} {:>14}", "max_events", "epoll_wait us");
    let set = Set::new(64);
    if set.r.len() == 64 {
        for m in [8usize, 64, 256, 1024] {
            println!("{m:>14} {:>14.2}", epoll_us(&set, m));
        }
    }

    // The conclusion, in one line: how each scaled from the smallest set. An
    // epoll that keeps a ready list stays near 1; one that walks the set grows
    // with the same slope as the control.
    if let Some((e0, p0)) = first {
        let set = Set::new(512);
        if set.r.len() == 512 {
            let e = epoll_us(&set, 8);
            let p = poll_us(&set);
            println!("\n64x the set: epoll_wait {:.1}x slower, poll {:.1}x slower",
                e / e0, p / p0);
        }
    }
}
