//! Two processes hammering one `MAP_SHARED` page with the atomics a lock is
//! made of.
//!
//! **A report, not a check** -- one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! `atomics_probe` covers the instructions in one thread of one process, which
//! is where a decoder defect shows. This asks the other question: does an
//! atomic on a page two *processes* share make progress? A spinlock is a
//! compare-exchange in a loop, and a process that never wins it spins with no
//! syscall at all -- which is what PostgreSQL 18's IO worker does here, and
//! why this exists. The page is `MAP_SHARED|MAP_ANONYMOUS` inherited across
//! `fork`, which is how PostgreSQL's main shared memory is made.
//!
//! Every case is bounded: a loop that cannot finish prints how far it got
//! rather than hanging, because a probe that hangs tells the reader nothing and
//! takes the sweep with it.

use std::io::Write;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
    let _ = std::io::stdout().flush();
}

/// A page both processes see. `MAP_SHARED|MAP_ANONYMOUS`, so a `fork` after
/// this shares it rather than copying it.
fn shared_page() -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED { std::ptr::null_mut() } else { p.cast() }
}

fn u32_at(p: *mut u8, off: usize) -> &'static AtomicU32 {
    unsafe { AtomicU32::from_ptr(p.add(off).cast()) }
}

fn u64_at(p: *mut u8, off: usize) -> &'static AtomicU64 {
    unsafe { AtomicU64::from_ptr(p.add(off).cast()) }
}

/// Runs `child` in a forked child and waits up to `secs`. Answers the child's
/// exit status, or `None` if it had to be killed.
fn with_child(secs: u32, child: impl FnOnce()) -> Option<i32> {
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        child();
        unsafe { libc::_exit(0) };
    }
    for _ in 0..(secs * 100) {
        let mut status = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            return Some(status);
        }
        unsafe { libc::usleep(10_000) };
    }
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
    None
}

fn main() {
    let p = shared_page();
    line("a shared anonymous page", (!p.is_null()).to_string());
    if p.is_null() {
        return;
    }

    // The control: a write on one side is visible on the other. Everything
    // below is meaningless if this is not true.
    u32_at(p, 0).store(0, Ordering::SeqCst);
    let seen = with_child(5, || {
        u32_at(p, 0).store(0x5a5a5a5a, Ordering::SeqCst);
    });
    line("a child's store is visible to the parent", format!(
        "{} value {:#x}",
        if seen.is_some() { "exited" } else { "killed" },
        u32_at(p, 0).load(Ordering::SeqCst)
    ));

    // A compare-exchange each side runs until it wins once. This is a spinlock
    // acquire, and it is the shape PostgreSQL's LWLock has.
    const ROUNDS: u32 = 2000;
    u32_at(p, 64).store(0, Ordering::SeqCst);
    u32_at(p, 128).store(0, Ordering::SeqCst); // how far the child got
    let status = with_child(10, || {
        for i in 0..ROUNDS {
            // Take it, then give it back.
            while u32_at(p, 64)
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                std::hint::spin_loop();
            }
            u32_at(p, 64).store(0, Ordering::Release);
            u32_at(p, 128).store(i + 1, Ordering::Relaxed);
        }
    });
    let mut mine = 0u32;
    for _ in 0..ROUNDS {
        while u32_at(p, 64)
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
        u32_at(p, 64).store(0, Ordering::Release);
        mine += 1;
    }
    line("a 32-bit compare-exchange lock, taken 2000 times each", format!(
        "parent {mine} child {} {}",
        u32_at(p, 128).load(Ordering::Relaxed),
        if status.is_some() { "exited" } else { "killed" }
    ));

    // The same with a 64-bit word, which is what a counter or a generation
    // number is: a different instruction pair on this machine.
    u64_at(p, 192).store(0, Ordering::SeqCst);
    let status = with_child(10, || {
        for _ in 0..ROUNDS {
            u64_at(p, 192).fetch_add(1, Ordering::AcqRel);
        }
    });
    for _ in 0..ROUNDS {
        u64_at(p, 192).fetch_add(1, Ordering::AcqRel);
    }
    line("a 64-bit fetch_add from both, 2000 each", format!(
        "{} {}",
        u64_at(p, 192).load(Ordering::SeqCst),
        if status.is_some() { "exited" } else { "killed" }
    ));

    // A flag one side sets and the other waits for, with no syscall in the
    // wait. This is what an IO worker's "is there work" loop is, and a bounded
    // version of the hang this probe was written for.
    u32_at(p, 256).store(0, Ordering::SeqCst);
    let status = with_child(10, || {
        unsafe { libc::usleep(50_000) };
        u32_at(p, 256).store(1, Ordering::Release);
    });
    let mut spun = 0u64;
    while u32_at(p, 256).load(Ordering::Acquire) == 0 && spun < 200_000_000 {
        spun += 1;
        std::hint::spin_loop();
    }
    line("a flag another process sets, waited for without a syscall", format!(
        "{} {}",
        if u32_at(p, 256).load(Ordering::Acquire) == 1 { "seen" } else { "never seen" },
        if status.is_some() { "exited" } else { "killed" }
    ));

    // And the same page after an execve, which is where a MAP_SHARED mapping
    // is *not* inherited: it should be gone, and the child's own new mapping
    // is its own.
    line("the page is still ours after all that", format!(
        "{:#x}",
        u32_at(p, 0).load(Ordering::SeqCst)
    ));
    unsafe { libc::munmap(p.cast(), 4096) };
}
