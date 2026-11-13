//! A blocking `poll()`/`select()` has to come back when something becomes
//! ready, and come back *then*.
//!
//! The kernel's wait loop is bounded by a time slice -- it wakes every second
//! to re-check pending signals -- so a wakeup that goes missing does not hang.
//! It arrives a second late instead, and every check about *whether* the call
//! returned still passes. That is the failure this is shaped around: the
//! latency is asserted, not just the result.
//!
//! Both kinds of member are covered, because they are woken by different
//! machinery. A pipe is host-backed and the host's own wait sees it; an
//! eventfd is not, and this kernel wakes the waiter itself. A set holding both
//! has to work for either reason.

use guest_tests::{Harness, check};
use std::time::{Duration, Instant};

/// Long enough that the writer is definitely still asleep when the poll
/// blocks, short enough that a missed wakeup (a whole slice, ~1s) is not
/// mistaken for it.
const DELAY: Duration = Duration::from_millis(60);
/// A wakeup delivered through the kernel's own notification, plus scheduling.
/// A missed one costs a full slice, so anything under this is unambiguous.
const LIMIT_MS: u128 = 500;

fn spawn_after<F: FnOnce() + Send + 'static>(f: F) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(DELAY);
        f();
    })
}

fn main() {
    let mut h = Harness::new();

    h.group("pipe");
    {
        let mut p = [0i32; 2];
        check!(h, unsafe { libc::pipe(p.as_mut_ptr()) } == 0, "a pipe");
        let (r, w) = (p[0], p[1]);
        let t = spawn_after(move || {
            unsafe { libc::write(w, b"x".as_ptr().cast(), 1) };
        });
        let mut pfd = libc::pollfd { fd: r, events: libc::POLLIN, revents: 0 };
        let start = Instant::now();
        let n = unsafe { libc::poll(&mut pfd, 1, 5000) };
        let ms = start.elapsed().as_millis();
        check!(h, n == 1, "a blocking poll on a pipe returns when it is written: n={n}");
        check!(h, pfd.revents & libc::POLLIN != 0, "and reports POLLIN: revents={}", pfd.revents);
        check!(h, ms < LIMIT_MS, "and does so promptly: {ms}ms");
        t.join().ok();
        unsafe { libc::close(r) };
        unsafe { libc::close(w) };
    }

    h.group("eventfd");
    {
        let efd = unsafe { libc::eventfd(0, 0) };
        check!(h, efd >= 0, "an eventfd");
        let t = spawn_after(move || {
            let one: u64 = 1;
            unsafe { libc::write(efd, (&one as *const u64).cast(), 8) };
        });
        let mut pfd = libc::pollfd { fd: efd, events: libc::POLLIN, revents: 0 };
        let start = Instant::now();
        let n = unsafe { libc::poll(&mut pfd, 1, 5000) };
        let ms = start.elapsed().as_millis();
        check!(h, n == 1, "a blocking poll on an eventfd returns when it is posted: n={n}");
        check!(h, pfd.revents & libc::POLLIN != 0, "and reports POLLIN: revents={}", pfd.revents);
        check!(h, ms < LIMIT_MS, "and does so promptly: {ms}ms");
        t.join().ok();
        unsafe { libc::close(efd) };
    }

    h.group("mixed-set");
    {
        // Sixteen members, only one of which ever becomes ready, and it is the
        // one that is not host-backed. A wait that only listens to the host
        // sleeps through this.
        let mut pipes = Vec::new();
        let mut fds = Vec::new();
        for _ in 0..15 {
            let mut p = [0i32; 2];
            if unsafe { libc::pipe(p.as_mut_ptr()) } != 0 {
                break;
            }
            fds.push(libc::pollfd { fd: p[0], events: libc::POLLIN, revents: 0 });
            pipes.push(p);
        }
        check!(h, pipes.len() == 15, "fifteen quiet pipes: {}", pipes.len());
        let efd = unsafe { libc::eventfd(0, 0) };
        check!(h, efd >= 0, "and an eventfd");
        fds.push(libc::pollfd { fd: efd, events: libc::POLLIN, revents: 0 });
        let t = spawn_after(move || {
            let one: u64 = 1;
            unsafe { libc::write(efd, (&one as *const u64).cast(), 8) };
        });
        let start = Instant::now();
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 5000) };
        let ms = start.elapsed().as_millis();
        check!(h, n == 1, "the one member that became ready is reported: n={n}");
        check!(h, fds[15].revents & libc::POLLIN != 0, "and it is the eventfd");
        check!(h, fds[..15].iter().all(|f| f.revents == 0), "and only it");
        check!(h, ms < LIMIT_MS, "promptly, in a set of sixteen: {ms}ms");
        t.join().ok();
        unsafe { libc::close(efd) };
        for p in &pipes {
            unsafe { libc::close(p[0]) };
            unsafe { libc::close(p[1]) };
        }
    }

    h.group("select");
    {
        // The same wait, reached the other way. select() and poll() share the
        // kernel's set machinery, so a change to it has to be checked through
        // both entry points.
        let mut p = [0i32; 2];
        check!(h, unsafe { libc::pipe(p.as_mut_ptr()) } == 0, "a pipe");
        let (r, w) = (p[0], p[1]);
        let t = spawn_after(move || {
            unsafe { libc::write(w, b"x".as_ptr().cast(), 1) };
        });
        let mut set: libc::fd_set = unsafe { std::mem::zeroed() };
        unsafe { libc::FD_SET(r, &mut set) };
        let mut tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
        let start = Instant::now();
        let n = unsafe { libc::select(r + 1, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), &mut tv) };
        let ms = start.elapsed().as_millis();
        check!(h, n == 1, "a blocking select returns when the pipe is written: n={n}");
        check!(h, unsafe { libc::FD_ISSET(r, &set) }, "and names the descriptor");
        check!(h, ms < LIMIT_MS, "and does so promptly: {ms}ms");
        t.join().ok();
        unsafe { libc::close(r) };
        unsafe { libc::close(w) };
    }

    h.group("timeout-is-honoured");
    {
        // Nothing ever becomes ready. The call must come back at its deadline
        // rather than at the next slice boundary, and must not come back early
        // -- the wait loop re-polls on every slice and an early return would
        // mean the deadline arithmetic is being redone wrongly each pass.
        let mut p = [0i32; 2];
        check!(h, unsafe { libc::pipe(p.as_mut_ptr()) } == 0, "a pipe nobody writes");
        let mut pfd = libc::pollfd { fd: p[0], events: libc::POLLIN, revents: 0 };
        let start = Instant::now();
        let n = unsafe { libc::poll(&mut pfd, 1, 250) };
        let ms = start.elapsed().as_millis();
        check!(h, n == 0, "poll times out: n={n}");
        check!(h, ms >= 240, "not before its timeout: {ms}ms");
        check!(h, ms < 900, "and not a slice late: {ms}ms");
        unsafe { libc::close(p[0]) };
        unsafe { libc::close(p[1]) };
    }

    std::process::exit(h.finish());
}
