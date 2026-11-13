//! Reading `/proc/<pid>/fd` for a process that is exiting.
//!
//! `do_exit` released the task's descriptor table before it set `exiting`, and
//! without the lock `/proc/<pid>/fd` holds while it reads that pointer. So a
//! reader could pass `proc_get_task`'s "not exiting" check and then either
//! retain a table another thread was freeing, or read the pointer as NULL just
//! after it was cleared and dereference it.
//!
//! Reproduced as a SIGSEGV at address zero inside `sys_getdents64`. The `mm`
//! beside it in `do_exit` had already been given the treatment this needed,
//! for the same reason and with the same symptom.
//!
//! The check is that the emulator is still alive: it prints `survived`, and the
//! gate looks for that. A crash prints a stack trace instead and never gets
//! there.

use std::sync::atomic::{AtomicI32, AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);
/// The pid currently being torn down, for the scanners to aim at.
static TARGET: AtomicI32 = AtomicI32::new(0);

fn scan_loop() {
    while !STOP.load(Ordering::Relaxed) {
        let pid = TARGET.load(Ordering::Relaxed);
        if pid <= 0 {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        // Both readers: the directory listing and the per-descriptor link.
        let dir = format!("/proc/{pid}/fd");
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let _ = std::fs::read_link(e.path());
            }
        }
    }
}

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);

    let scanners: Vec<_> = (0..2).map(|_| std::thread::spawn(scan_loop)).collect();

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut spawned = 0u64;
    while Instant::now() < deadline {
        match unsafe { libc::fork() } {
            0 => unsafe {
                // A few descriptors for the scanners to find, then go away at
                // once -- the window being aimed at is inside do_exit.
                for _ in 0..8 {
                    libc::dup(0);
                }
                libc::_exit(0)
            },
            child if child > 0 => {
                TARGET.store(child, Ordering::Relaxed);
                let mut status = 0;
                unsafe { libc::waitpid(child, &mut status, 0) };
                spawned += 1;
            }
            _ => break,
        }
    }

    STOP.store(true, Ordering::Relaxed);
    for s in scanners {
        let _ = s.join();
    }
    println!("spawned {spawned}");
    println!("survived");
}
