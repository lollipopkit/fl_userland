//! Destroying an epoll set while its members are being closed.
//!
//! The race this was written for: the registration node linking a set to a
//! member was reachable from both, so whichever tore down second found it
//! freed. The teardown walks could not hold both locks at once — the order was
//! fd then poll — so each read a member, dropped its lock, took the two in
//! order and looked the entry up again, and in that gap the member's last
//! reference could go.
//!
//! **This test never reproduced it.** The window was found by reading, and this
//! was written to try: two threads close epoll sets and their members as fast
//! as they can, with the member closed from a different thread than the set.
//!
//! It is now a guard on a shape rather than on a fix. Both reverse edges are
//! refcounted lists that each side holds, so neither teardown can free what the
//! other is walking and there is no gap to cross — see
//! `docs/changelog/2026-08-28-transient-poll-set-moved-to-rust.md` and the
//! epoll one beside it. What this still checks every run is that all of it is
//! survivable: a crash, a hang or a descriptor leak here is a failure whether
//! or not it is *the* race.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

const ROUNDS: usize = 400;

fn main() {
    let mut h = Harness::new();
    h.group("epoll-destroy-vs-member-close");

    let stop = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(AtomicI64::new(0));

    // A second thread churning its own epoll sets, so the timer service, the
    // poll sets and the descriptor table are all being touched at once.
    let churn = {
        let stop = Arc::clone(&stop);
        let errors = Arc::clone(&errors);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let ep = unsafe { libc::epoll_create1(0) };
                if ep < 0 {
                    errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut p = [0i32; 2];
                if unsafe { libc::pipe(p.as_mut_ptr()) } == 0 {
                    let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: 0 };
                    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, p[0], &mut ev) };
                    // The set goes first here, the member first in the main
                    // thread: both orders, at once.
                    unsafe { libc::close(ep) };
                    unsafe { libc::close(p[0]); libc::close(p[1]) };
                } else {
                    unsafe { libc::close(ep) };
                }
            }
        })
    };

    for _ in 0..ROUNDS {
        let ep = unsafe { libc::epoll_create1(0) };
        if ep < 0 {
            errors.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        // Several members, so the destroy walk has more than one gap to cross.
        let mut pipes = Vec::new();
        for i in 0..8 {
            let mut p = [0i32; 2];
            if unsafe { libc::pipe(p.as_mut_ptr()) } != 0 {
                break;
            }
            let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: i };
            unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, p[0], &mut ev) };
            pipes.push(p);
        }

        // Close the members from another thread while this one closes the set.
        let closer = std::thread::spawn(move || {
            for p in &pipes {
                unsafe { libc::close(p[0]); libc::close(p[1]) };
            }
        });
        unsafe { libc::close(ep) };
        let _ = closer.join();
    }

    stop.store(true, Ordering::Relaxed);
    let _ = churn.join();

    check!(h, errors.load(Ordering::Relaxed) == 0,
        "no epoll_create failed: {}", errors.load(Ordering::Relaxed));
    check!(h, true, "{ROUNDS} rounds of destroy-vs-close survived");

    // And the descriptor table is not leaking: a fresh pipe should land at a
    // low number if everything above was released.
    let mut p = [0i32; 2];
    check!(h, unsafe { libc::pipe(p.as_mut_ptr()) } == 0, "a pipe afterwards");
    check!(h, p[0] < 64, "descriptors were released: got {}", p[0]);
    unsafe { libc::close(p[0]); libc::close(p[1]) };

    std::process::exit(h.finish());
}
