//! What a *blocked* thread costs while nothing is happening.
//!
//! The other futex benchmark measures how long a wake takes. This measures the
//! thing that has no wake in it at all: eight threads parked on a condition
//! variable, for three seconds, while the process does nothing.
//!
//! On a real kernel that is free — a parked thread is off the run queue and
//! costs no CPU until something notifies it. It was not free here: `futex_wait`
//! polled a pipe with a 100 ms timeout and re-read the group-exit flag, the
//! pending signals and the futex word on every expiry, so eight parked threads
//! were 240 wakeups over three seconds and three system calls each.
//!
//! **The number to look at is the host's, not the guest's.** Time this binary
//! from outside:
//!
//! ```sh
//! time ./build-arm64-release/iul -r rootfs /tmp/futex_idle
//! ```
//!
//! Wall time is three seconds either way; what changes is `user` and `sys`.
//! A guest cannot see it, because the work is the emulator's.
//!
//! A measurement, not a check: it prints and never fails.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Both from argv, because the interesting question is where the cost becomes
/// visible: `futex_idle 64 10` is 64 threads for 10 seconds.
fn args() -> (usize, Duration) {
    let mut a = std::env::args().skip(1);
    let threads = a.next().and_then(|s| s.parse().ok()).unwrap_or(8);
    let secs: u64 = a.next().and_then(|s| s.parse().ok()).unwrap_or(3);
    (threads, Duration::from_secs(secs))
}

fn main() {
    let (threads, idle_for) = args();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let parked = Arc::new(AtomicU32::new(0));

    let mut handles = Vec::new();
    for _ in 0..threads {
        let (gate, parked) = (Arc::clone(&gate), Arc::clone(&parked));
        handles.push(std::thread::spawn(move || {
            let (lock, cv) = &*gate;
            let mut open = lock.lock().unwrap();
            parked.fetch_add(1, Ordering::SeqCst);
            // One wait, and one wake at the end of it. Everything in between is
            // the thing being measured: a thread that is asleep.
            while !*open {
                open = cv.wait(open).unwrap();
            }
        }));
    }

    // All of them asleep before the clock starts.
    while parked.load(Ordering::SeqCst) < threads as u32 {
        std::thread::sleep(Duration::from_millis(1));
    }
    // The counter is incremented under the lock and before the wait, so the
    // last thread to report may not be parked yet.
    std::thread::sleep(Duration::from_millis(50));

    let started = Instant::now();
    std::thread::sleep(idle_for);
    let idle = started.elapsed();

    {
        let (lock, cv) = &*gate;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    for h in handles {
        h.join().unwrap();
    }

    println!("{threads} threads parked for {} ms", idle.as_millis());
    println!("(the cost is the host's; time this binary from outside)");
}
