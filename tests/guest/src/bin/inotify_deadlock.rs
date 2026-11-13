//! A reader of an inotify descriptor against a thread generating events.
//!
//! `inotify_read` takes `fd->lock` and then `inotify_lock`;
//! `inotify_notify_path` takes `inotify_lock` and then `fd->lock`. That is a
//! cycle, and the comment beside the second one asserts it cannot happen:
//! "nothing takes inotify_lock while holding an fd lock".
//!
//! The check is that the emulator is still alive: it prints `survived`, and a
//! deadlock never gets there.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/inodl".into());
    let secs: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);

    let ino = unsafe { libc::inotify_init1(0) };
    if ino < 0 {
        println!("inotify_init1 failed");
        return;
    }
    let c = std::ffi::CString::new(dir.clone()).unwrap();
    let wd = unsafe { libc::inotify_add_watch(ino, c.as_ptr(), libc::IN_ALL_EVENTS) };
    if wd < 0 {
        println!("inotify_add_watch failed");
        return;
    }

    let stop = Arc::new(AtomicBool::new(false));

    // Churn: every operation here produces an event, so the notifier is
    // walking the instance list and taking fd->lock constantly.
    let churn = {
        let stop = stop.clone();
        let dir = dir.clone();
        std::thread::spawn(move || {
            let mut i = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let p = format!("{dir}/f{}", i % 8);
                let _ = std::fs::write(&p, b"x");
                let _ = std::fs::remove_file(&p);
                i += 1;
            }
            i
        })
    };

    // A second churner, so the notifier is contended as well.
    let churn2 = {
        let stop = stop.clone();
        let dir = dir.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let p = format!("{dir}/g");
                let _ = std::fs::write(&p, b"y");
                let _ = std::fs::remove_file(&p);
            }
        })
    };

    // The reader, in the main thread: blocking reads, which is what holds
    // fd->lock across the wait and re-takes inotify_lock on every pass.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut buf = vec![0u8; 8192];
    let mut reads = 0u64;
    while std::time::Instant::now() < deadline {
        let n = unsafe { libc::read(ino, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            reads += 1;
        }
    }

    stop.store(true, Ordering::Relaxed);
    let ops = churn.join().unwrap_or(0);
    let _ = churn2.join();

    // Drain, then check that a *blocking* read wakes on a single event.
    //
    // This is the property the lock handover in inotify_read protects: fd->lock
    // is taken before inotify_lock is released, so a notifier cannot signal
    // between the empty read and the wait. The churn above cannot show that --
    // a missed wakeup there is covered by the next event a millisecond later --
    // and the exact window is too narrow to hit on purpose. What this does
    // catch is any gross version of the same mistake.
    unsafe { libc::fcntl(ino, libc::F_SETFL, libc::O_NONBLOCK) };
    while unsafe { libc::read(ino, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
    unsafe { libc::fcntl(ino, libc::F_SETFL, 0) };

    let one = {
        let dir = dir.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = std::fs::write(format!("{dir}/single"), b"z");
        })
    };
    let start = std::time::Instant::now();
    let n = unsafe { libc::read(ino, buf.as_mut_ptr().cast(), buf.len()) };
    let waited = start.elapsed();
    let _ = one.join();
    let woke = n > 0 && waited < std::time::Duration::from_secs(5);
    println!("single-event wake: n={n} after {waited:?} -> {}", if woke { "ok" } else { "MISSED" });

    unsafe { libc::close(ino) };
    println!("reads {reads}, ops {ops}");
    if !woke {
        println!("a blocking read did not wake on a single event");
        std::process::exit(1);
    }
    println!("survived");
}
