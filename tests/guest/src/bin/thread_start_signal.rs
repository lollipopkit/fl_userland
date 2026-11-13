//! Signals a thread group while it is creating threads.
//!
//! The emulator interrupts a guest thread's blocking host call by sending it
//! `SIGUSR1`, and a thread that has only just been created is a valid target:
//! `do_clone` puts the task in the table before `task_start` runs it. So the
//! signal can land in `task_thread`'s first instructions.
//!
//! That is where a `__thread` variable on Darwin is **allocated**: reading one
//! goes through dyld's `_tlv_get_addr`, which `malloc()`s the block on first
//! touch. `task_set_current` is the first touch, and the handler touches a
//! thread-local of its own — so a signal in that window called `malloc` from a
//! signal handler, inside a `malloc` that was already running. The captured
//! stack was
//!
//! ```text
//! task_set_current -> _tlv_get_addr -> malloc -> [SIGUSR1]
//!   sigusr1_handler -> _tlv_get_addr -> malloc      <- reentrant
//! ```
//!
//! and the process died with SIGTRAP inside libsystem_malloc.
//!
//! This never fails on its own: it prints a line and the emulator either
//! survives it or does not. Run it in a loop.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

extern "C" fn ignore(_sig: i32) {}

fn main() {
    let rounds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(400);

    // Every signal used below has to be caught rather than default: the point
    // is the delivery, not what it does.
    for sig in [libc::SIGCONT, libc::SIGUSR2, libc::SIGWINCH] {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = ignore as *const () as usize;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));

    // One thread doing nothing but signalling the group, as fast as it can.
    // A process-directed signal is delivered to whichever thread has it
    // unblocked, which includes one that started a microsecond ago.
    let storm = {
        let (stop, sent) = (stop.clone(), sent.clone());
        std::thread::spawn(move || {
            let me = unsafe { libc::getpid() };
            while !stop.load(Ordering::Relaxed) {
                for sig in [libc::SIGCONT, libc::SIGUSR2, libc::SIGWINCH] {
                    unsafe { libc::kill(me, sig) };
                    sent.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    };

    // And the churn: threads created and joined, so there is always one in its
    // first instructions.
    let mut made = 0u64;
    for _ in 0..rounds {
        let mut batch = Vec::new();
        for _ in 0..8 {
            batch.push(std::thread::spawn(|| {
                // Enough to still be here when the signal lands, and short
                // enough that the next batch starts soon.
                std::thread::yield_now();
            }));
            made += 1;
        }
        for t in batch {
            let _ = t.join();
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = storm.join();
    println!(
        "started {made} threads under {} signals; survived",
        sent.load(Ordering::Relaxed)
    );
}
