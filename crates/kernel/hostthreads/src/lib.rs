//! How many host threads a guest thread group still has running, and waiting
//! for that number to come down.
//!
//! Every guest thread is a host pthread. When a thread group exits, the thread
//! that called `exit_group` has to know when the others are really gone — not
//! merely when they have left the group's thread list, which happens partway
//! through `do_exit`, but when the host pthread has finished unwinding.
//!
//! `kernel/exit.c` used to answer that with two waits, one after the other:
//!
//! ```c
//! while (waited_ms < max_wait_ms) {          // poll the thread list
//!     ...
//!     if (remaining == 0) break;
//!     nanosleep(&(struct timespec){0, 10 * 1000000L}, NULL);
//!     waited_ms += 10;
//! }
//! ...
//! // Give extra time for pthread cleanup on host system
//! struct timespec extra_delay = {0, 50 * 1000000L};
//! nanosleep(&extra_delay, NULL);
//! ```
//!
//! An unconditional 50 ms on the path every multithreaded process takes to
//! exit, plus one or more 10 ms polls. Measured: a `fork` of a process with one
//! extra thread, to `waitpid` returning, took **69 ms**. The same binary on a
//! real arm64 kernel took **78 µs**.
//!
//! Sleeping for a fixed time is also not the guarantee the comment claims. It
//! is longer than the event usually takes, which is not the same as being long
//! enough.
//!
//! # Why this is refcounted
//!
//! The exit path has a timeout, and past it the group gives up on threads stuck
//! in uninterruptible host syscalls: it marks them exiting, takes them out of
//! the thread list and frees the group. Those threads are still running. When
//! one finally returns and its pthread cleanup handler runs, it has to be able
//! to say so — against an object whose group has been gone for minutes.
//!
//! So the count lives behind an [`Arc`]. The thread group holds one reference
//! and each thread holds one; the last one out drops the allocation. That is
//! the same shape as the reverse edge in `crates/fs/pollset`, and for the same
//! reason: two owners with independent lifetimes.
//!
//! # What it does not cover
//!
//! A task that has been created but has not reached `task_run_current` yet.
//! Its handle is taken in `copy_task`, under the same `pids_lock` that adds it
//! to the group, so there is no window — a task that exists is counted.

#![forbid(unsafe_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// The live-thread count for one thread group.
#[derive(Debug, Default)]
pub struct HostThreads {
    live: Mutex<usize>,
    cond: Condvar,
}

impl HostThreads {
    pub fn new() -> Arc<HostThreads> {
        Arc::new(HostThreads::default())
    }

    /// A thread of this group now exists. Balanced by [`HostThreads::finished`].
    pub fn started(self: &Arc<Self>) -> Arc<HostThreads> {
        *self.live.lock().unwrap() += 1;
        Arc::clone(self)
    }

    /// This thread's host pthread is done. Consumes the handle `started` gave.
    pub fn finished(self: Arc<Self>) {
        let mut live = self.live.lock().unwrap();
        // Saturating rather than wrapping: an unbalanced call is a bug in the
        // caller, and a count of `usize::MAX` would hang every later wait
        // instead of only being wrong.
        *live = live.saturating_sub(1);
        drop(live);
        self.cond.notify_all();
    }

    pub fn live(&self) -> usize {
        *self.live.lock().unwrap()
    }

    /// Wait until at most `want` threads are live. True if that happened,
    /// false if `timeout` ran out first.
    ///
    /// `want` is 1 for the thread calling `exit_group`: itself, and nobody
    /// else. A timeout is not an error here — the caller's next move is the
    /// force-kill path, which is what the emulator did before this existed.
    pub fn wait_for(&self, want: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut live = self.live.lock().unwrap();
        while *live > want {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (guard, r) = self.cond.wait_timeout(live, deadline - now).unwrap();
            live = guard;
            if r.timed_out() && *live > want {
                return false;
            }
        }
        true
    }
}

// The C binding -- `Handle = *const HostThreads`, `Arc::into_raw`, and five
// `host_threads_*` functions over it -- was here until 2026-09-30. Its callers
// were all Rust: `struct tgroup` holds an `Arc<HostThreads>` and each task an
// `Option<Arc<HostThreads>>`, so the reference counts are the `Arc`'s own.

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
