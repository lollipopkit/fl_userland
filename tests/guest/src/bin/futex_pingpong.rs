//! How long it takes to wake a thread that is waiting.
//!
//! Every threaded runtime is built on this: a mutex that is contended, a
//! condition variable, a channel, a thread pool handing out work. The guest
//! reaches it through `FUTEX_WAIT`/`FUTEX_WAKE`, and this kernel implements the
//! wait as a condition variable in `crates/kernel/futex` — so a wake is a
//! broadcast and a recheck.
//!
//! It used to be `poll()` on a pipe the waker wrote a byte to, with a 100 ms
//! timeout underneath. This is what said the change was worth making: 8798 ns
//! a round trip then, 7541 now, and 5610 to 4618 for a broadcast to eight.
//!
//! A measurement, not a check: it prints numbers and never fails, so it is not
//! in the gate. Run the same binary in an arm64 Linux container for the number
//! to compare against — `tests/integration/differential.sh` cannot, because
//! there are no checks to compare.
//!
//! Two shapes, because they cost differently:
//!
//! - **ping-pong**, where each side waits for the other. Every hand-off is a
//!   wait and a wake, so this is the latency of one.
//! - **broadcast**, where one thread wakes many at once. This is what a thread
//!   pool does when work arrives, and it is where a wake that walks a queue
//!   under a lock shows up.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

const ROUNDS: u32 = 20000;

fn ping_pong() {
    // A turn counter and a condvar over it: the plainest thing that makes each
    // side wait for the other.
    let state = Arc::new((Mutex::new(0u32), Condvar::new()));
    let theirs = state.clone();
    let worker = std::thread::spawn(move || {
        let (lock, cv) = &*theirs;
        for turn in 0..ROUNDS {
            let mut n = lock.lock().expect("not poisoned");
            while *n != turn * 2 + 1 {
                n = cv.wait(n).expect("not poisoned");
            }
            *n += 1;
            cv.notify_all();
        }
    });

    let (lock, cv) = &*state;
    let start = Instant::now();
    for turn in 0..ROUNDS {
        {
            let mut n = lock.lock().expect("not poisoned");
            *n = turn * 2 + 1;
            cv.notify_all();
        }
        let mut n = lock.lock().expect("not poisoned");
        while *n != turn * 2 + 2 {
            n = cv.wait(n).expect("not poisoned");
        }
    }
    let elapsed = start.elapsed();
    worker.join().expect("the worker");
    println!(
        "  ping-pong                    {:>9.0} ns/round-trip   ({ROUNDS} rounds)",
        elapsed.as_nanos() as f64 / ROUNDS as f64
    );
}

fn broadcast(waiters: usize) {
    let generation = Arc::new(AtomicU32::new(0));
    let state = Arc::new((Mutex::new(0u32), Condvar::new()));
    let done = Arc::new(AtomicU32::new(0));
    const ROUNDS: u32 = 2000;

    let mut threads = Vec::new();
    for _ in 0..waiters {
        let state = state.clone();
        let done = done.clone();
        let generation = generation.clone();
        threads.push(std::thread::spawn(move || {
            let (lock, cv) = &*state;
            let mut seen = 0u32;
            while seen < ROUNDS {
                let mut n = lock.lock().expect("not poisoned");
                while *n == seen {
                    n = cv.wait(n).expect("not poisoned");
                }
                seen = *n;
                drop(n);
                done.fetch_add(1, Ordering::SeqCst);
                generation.fetch_add(0, Ordering::Relaxed);
            }
        }));
    }

    let (lock, cv) = &*state;
    let start = Instant::now();
    for round in 1..=ROUNDS {
        {
            let mut n = lock.lock().expect("not poisoned");
            *n = round;
            cv.notify_all();
        }
        // Every waiter has to have seen it before the next one goes out, or
        // this measures how fast a counter increments rather than how fast a
        // wake arrives.
        while done.load(Ordering::SeqCst) < round as u32 * waiters as u32 {
            std::hint::spin_loop();
        }
    }
    let elapsed = start.elapsed();
    for t in threads {
        t.join().expect("a waiter");
    }
    println!(
        "  broadcast to {waiters:<2}              {:>9.0} ns/wake        ({ROUNDS} rounds)",
        elapsed.as_nanos() as f64 / (ROUNDS as f64 * waiters as f64)
    );
}

fn main() {
    println!("futex wake latency:");
    ping_pong();
    for waiters in [1usize, 4, 8] {
        broadcast(waiters);
    }
}
