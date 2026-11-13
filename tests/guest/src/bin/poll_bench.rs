//! What one `poll()` costs per descriptor.
//!
//! `poll()` and `select()` build a set, wait on it once, and destroy it. The
//! kernel used to register every member of that set with the host's event
//! queue on the way in and take it out again on the way out -- two `kevent`
//! calls per descriptor, for a set that exists for the duration of one
//! syscall.
//!
//! The two columns are what isolate that cost. A pipe is host-backed, so it
//! needed the registration; an eventfd is not, so it never did. The difference
//! between the columns is the registration and nothing else: the set walk, the
//! guest memory copies and the readiness scan are the same for both.
//!
//! Measured on this machine before the transient path existed:
//!
//!     N      pipe        eventfd
//!     500    0.956 us/fd  0.239 us/fd
//!     1000   0.976        0.253
//!     1800   1.029        0.309
//!
//! Every call is made ready before it is timed, so nothing here blocks and the
//! number is the cost of the set rather than of the wait.
//!
//! The small sizes measure something else: what one `poll()` costs *at all*.
//! The number is per descriptor, so at N=1 it is the whole fixed cost of a
//! call — the syscall, the set, and whatever the wait sets up before deciding
//! it does not need to wait. A single-connection event loop makes this call
//! millions of times and never has more than a handful of members.

use std::time::Instant;

fn ms_now() -> Instant {
    Instant::now()
}

/// N pipes, each with a byte in it, so every member is readable. The write
/// ends come back too: left open they are half the descriptors this opens, and
/// leaking them across the three sizes ran the process out of them.
fn pipes(n: usize) -> (Vec<libc::pollfd>, Vec<i32>) {
    let mut fds = Vec::with_capacity(n);
    let mut writers = Vec::with_capacity(n);
    for _ in 0..n {
        let mut p = [0i32; 2];
        if unsafe { libc::pipe(p.as_mut_ptr()) } != 0 {
            break;
        }
        unsafe { libc::write(p[1], b"x".as_ptr().cast(), 1) };
        writers.push(p[1]);
        fds.push(libc::pollfd { fd: p[0], events: libc::POLLIN, revents: 0 });
    }
    (fds, writers)
}

/// N eventfds, each with a count in it. Not host-backed: this kernel answers
/// for them itself.
fn eventfds(n: usize) -> Vec<libc::pollfd> {
    let mut fds = Vec::with_capacity(n);
    for _ in 0..n {
        let fd = unsafe { libc::eventfd(1, 0) };
        if fd < 0 {
            break;
        }
        fds.push(libc::pollfd { fd, events: libc::POLLIN, revents: 0 });
    }
    fds
}

fn time_poll(fds: &mut [libc::pollfd], rounds: usize) -> f64 {
    // One untimed call first: the first one through a path pays for whatever
    // it allocates, and that is not what this is measuring.
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 0) };
    let t = ms_now();
    let mut ready = 0i64;
    for _ in 0..rounds {
        let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 0) };
        ready += r as i64;
    }
    let elapsed = t.elapsed().as_secs_f64();
    // Asserted, not printed as a footnote: a poll that answered nothing costs
    // almost nothing, and a benchmark that ran out of descriptors and measured
    // the refusal reads as a speedup. This has happened twice in this tree.
    assert_eq!(ready, (ready / rounds as i64) * rounds as i64);
    assert!(
        ready >= (fds.len() * rounds) as i64,
        "poll answered {ready} for {} fds over {rounds} rounds -- not every member was ready",
        fds.len()
    );
    elapsed / (rounds as f64) / (fds.len() as f64) * 1e6
}

fn main() {
    // The container's default is often 1024, and the point of the large sizes
    // is what happens above it.
    let lim = libc::rlimit { rlim_cur: 8192, rlim_max: 8192 };
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) };

    println!("{:<8}{:>14}{:>14}", "N", "pipe us/fd", "eventfd us/fd");
    for n in [1usize, 8, 64, 500, 1000, 1800] {
        // Enough rounds that the small sizes are not measuring the clock.
        let rounds = match n {
            _ if n >= 1800 => 50,
            _ if n >= 500 => 100,
            _ => 20000 / n,
        };

        let (mut p, writers) = pipes(n);
        let pipe_us = if p.len() == n { time_poll(&mut p, rounds) } else { f64::NAN };
        for f in &p {
            unsafe { libc::close(f.fd) };
        }
        for w in &writers {
            unsafe { libc::close(*w) };
        }

        let mut e = eventfds(n);
        let event_us = if e.len() == n { time_poll(&mut e, rounds) } else { f64::NAN };
        for f in &e {
            unsafe { libc::close(f.fd) };
        }

        println!("{n:<8}{pipe_us:>14.3}{event_us:>14.3}");
    }
}
