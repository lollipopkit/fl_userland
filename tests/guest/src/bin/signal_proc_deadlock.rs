//! Signal delivery against a reader of `/proc/<pid>/stat`.
//!
//! `receive_signals` takes `sighand->lock` and, for a stopping signal, calls
//! `receive_signal` which takes `group->lock` underneath it.
//! `proc_pid_stat_snapshot` takes `general_lock`, then `group->lock`, then
//! `sighand->lock`. Opposite order on the two inner locks.
//!
//! `pids_lock` does not serialise them: the procfs side holds it for the whole
//! snapshot, but `receive_signals` never takes it at all.
//!
//! The check is that the emulator is still alive; a deadlock never prints.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    let secs: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3);

    // A child that does nothing but exist and be stopped and continued.
    let child = unsafe { libc::fork() };
    if child == 0 {
        loop {
            unsafe { libc::pause() };
        }
    }
    if child < 0 {
        println!("fork failed");
        return;
    }

    let stop = Arc::new(AtomicBool::new(false));
    // One thread reads the child's /proc entry, which takes group->lock then
    // sighand->lock under pids_lock.
    let reader = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let path = format!("/proc/{child}/stat");
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                if std::fs::read_to_string(&path).is_ok() {
                    n += 1;
                }
            }
            n
        })
    };

    // And the main thread drives the child through the stopping path, which is
    // where receive_signal takes group->lock with sighand->lock held.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut signals = 0u64;
    while std::time::Instant::now() < deadline {
        unsafe {
            libc::kill(child, libc::SIGSTOP);
            libc::kill(child, libc::SIGCONT);
        }
        signals += 2;
    }

    stop.store(true, Ordering::Relaxed);
    let reads = reader.join().unwrap_or(0);
    unsafe {
        libc::kill(child, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(child, &mut st, 0);
    }
    println!("signals {signals}, reads {reads}");
    println!("survived");
}
