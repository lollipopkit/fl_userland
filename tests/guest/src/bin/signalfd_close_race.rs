//! A signal made pending while signalfds are being closed.
//!
//! `signalfd_notify` copied the registered descriptions out under its lock and
//! woke each one after releasing it, so a close on another thread could free a
//! description between the two. Run the emulator with `MallocScribble=1`: a
//! freed description then reads as 0x55 bytes and the wakeup crashes instead of
//! reading stale memory quietly.
//!
//! The check is that the emulator is still alive at the end.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn usr1() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        set
    }
}

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let set = usr1();
    // Blocked before any thread exists, so every thread inherits it and the
    // signal stays pending for a signalfd to report.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };

    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let set = usr1();
            let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    libc::kill(libc::getpid(), libc::SIGUSR1);
                    // Collected again, so the next `kill` is a new pending
                    // signal and notifies again.
                    libc::sigtimedwait(&set, std::ptr::null_mut(), &zero);
                }
                n += 1;
            }
            n
        }));
    }
    for _ in 0..3 {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let set = usr1();
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let fd = unsafe { libc::signalfd(-1, &set, libc::SFD_NONBLOCK) };
                if fd >= 0 {
                    unsafe { libc::close(fd) };
                }
                n += 1;
            }
            n
        }));
    }

    std::thread::sleep(std::time::Duration::from_secs(seconds));
    stop.store(true, Ordering::Relaxed);
    let counts: Vec<u64> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    println!("signalfd_close_race: ok {counts:?}");
}
