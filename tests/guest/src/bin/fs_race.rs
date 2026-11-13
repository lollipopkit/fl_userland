//! Races `chdir()` against relative-path resolution.
//!
//! `path_normalize` used to take `current->fs->pwd` under `fs->lock`, drop the
//! lock, and only then call `generic_getpath` on it. `fs_chdir` and
//! `sys_chroot` close the descriptor they replace while holding that same
//! lock, and a thread created with `CLONE_FS` — every pthread — shares the
//! `struct fs_info` they close it in. So one thread's chdir could free the
//! descriptor another was about to resolve against.
//!
//! Without the fix this segfaults the emulator within a second or two, in
//! `path_normalize`; with it, five seconds of the same load print "survived".
//!
//! The same race, on the other path: **`fork` copies the context**. Without
//! `CLONE_FS` a child gets a separate `struct fs_info` whose two descriptors
//! are the parent's, retained — and `fs_info_copy` read both *without the
//! lock*, so a chdir on another thread of the parent could free one between the
//! read and the retain. `path_normalize` had been fixed for this and the copy
//! had not. `forker` below is that case.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use guest_tests::sys;

static STOP: AtomicBool = AtomicBool::new(false);

fn churn() {
    while !STOP.load(Ordering::Relaxed) {
        if sys::chdir("/tmp/ra") != 0 {
            break;
        }
        if sys::chdir("/tmp/rb") != 0 {
            break;
        }
    }
}

/// A fork per pass, so `fs_info_copy` runs against the churn above.
///
/// The child does nothing but exit: what is being raced is the copy itself,
/// which happens in the parent before the child runs at all.
fn forker() {
    while !STOP.load(Ordering::Relaxed) {
        // SAFETY: the child calls only _exit, which is async-signal-safe.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        if pid < 0 {
            break;
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }
}

fn resolve() {
    while !STOP.load(Ordering::Relaxed) {
        // Relative, so it goes through pwd.
        sys::stat_raw("probe");
    }
}

fn main() {
    sys::mkdir("/tmp/ra", 0o755);
    sys::mkdir("/tmp/rb", 0o755);
    sys::write_file("/tmp/ra/probe", b"x");
    sys::write_file("/tmp/rb/probe", b"x");
    sys::chdir("/tmp/ra");

    let mut threads = Vec::new();
    for _ in 0..4 {
        threads.push(thread::spawn(churn));
    }
    for _ in 0..4 {
        threads.push(thread::spawn(resolve));
    }
    // One is enough: a fork is expensive and four chdir threads are already
    // replacing the descriptor as fast as the copy can read it.
    threads.push(thread::spawn(forker));
    thread::sleep(Duration::from_secs(5));
    STOP.store(true, Ordering::Relaxed);
    for t in threads {
        let _ = t.join();
    }
    println!("survived");
}
