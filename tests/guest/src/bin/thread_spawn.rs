//! How long it takes to create a thread while other threads are running.
//!
//! `pthread_create` mmaps a stack. `sys_mmap64` takes the **write** lock on the
//! address space, and every running guest thread holds that lock for *reading*
//! across each JIT quantum. `util/sync.h` explains at length why the writer may
//! not block — a writer that queues on a writer-preferring `pthread_rwlock`
//! stops every reader, and if it is itself waiting for those readers to reach a
//! GC safepoint the VM deadlocks — so it spins on `trywrlock` instead.
//!
//! Spinning does not deadlock. It starves.
//!
//! It prints the numbers *and* fails if they are absurd. The bound is loose on
//! purpose: five spawns take under 10 ms here with eight threads running, and
//! the defect this guards against made one spawn take longer than twenty
//! seconds. Anything in between is a performance question and not this test's
//! to answer; anything above [`ABSURD_MS`] is the starvation coming back.
//!
//! Every line is flushed, because the interesting runs are the ones that do not
//! finish and a buffered line is one nobody sees.
//!
//! Not comparable to a real kernel: a host `pthread_create` has no address
//! space lock to lose against, so Linux answers this in microseconds whatever
//! else is running.

/// Five spawns must take less than this. See the module comment.
const ABSURD_MS: u128 = 2000;

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Arithmetic in registers, so a background thread stays in the JIT and never
/// makes a syscall — which is the case that starves the writer hardest, because
/// a syscall is the one thing that reliably drops the read lock.
fn spin() -> u64 {
    let mut acc = 0u64;
    for i in 0..4000u64 {
        acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
    }
    std::hint::black_box(acc)
}

fn say(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

fn main() {
    let background: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let spawns: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    say(&format!(
        "spawning {spawns} threads with {background} running"
    ));

    let stop = AtomicBool::new(false);
    let mut failed = false;
    std::thread::scope(|scope| {
        for _ in 0..background {
            let stop = &stop;
            scope.spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    spin();
                }
            });
        }
        // Let them reach the JIT before the clock starts. Spawning them is the
        // very thing being measured, so it must not be inside the measurement.
        for _ in 0..200 {
            spin();
        }

        let all = Instant::now();
        for i in 0..spawns {
            let one = Instant::now();
            let t = std::thread::spawn(|| {});
            let _ = t.join();
            say(&format!(
                "  spawn {i}: {:>9.0} us",
                one.elapsed().as_micros()
            ));
        }
        let total = all.elapsed();
        say(&format!("  total for {spawns}: {:.0} us", total.as_micros()));
        stop.store(true, Ordering::Relaxed);
        failed = total.as_millis() > ABSURD_MS;
        if failed {
            say(&format!(
                "  FAIL  {spawns} spawns took {} ms with {background} threads running; \
                 the JIT is holding the address space lock again",
                total.as_millis()
            ));
        }
    });
    say("done");
    std::process::exit(if failed { 1 } else { 0 });
}
