//! Exiting a group while one of its threads is stuck in a host syscall.
//!
//! This is the path the group-exit safety valve exists for, and the one
//! `task_race` does not reach: `do_exit_group` finds a thread it cannot
//! interrupt — inside an uninterruptible host syscall, holding `mem->lock` and
//! a `struct fd` taken by `f_get` — and cannot release its address space or
//! descriptor table there without a use-after-free. It hands them to that
//! thread's own pthread cleanup handler instead, which runs when the host
//! thread finally terminates.
//!
//! Each round forks a child that blocks a thread on a pipe nothing will ever
//! write to, then exits the group from the main thread. The parent reaps and
//! checks the exit status, which is what says the group exit completed rather
//! than hanging or dying.
//!
//! Run under AddressSanitizer: the handoff frees an address space and a
//! descriptor table from a thread that is being torn down, which is where a
//! double free or a stale pointer would show. It is clean, and was clean
//! before the handoff was restructured too — this is coverage for a path that
//! had none, not the reproduction of a known fault. The use-after-free in the
//! cleanup handler was found by task_race, which reaches that handler on
//! every thread exit rather than only on the deferred path.
//!
//! **And it does not reach the valve any more**, measured 2026-09-12 over 40
//! rounds with `IUL_EXEC_TRACE=1`: not one `leaked N stuck host threads` line.
//! The line below used to say "confirm it is doing something with
//! IUL_EXEC_TRACE=1, which makes the valve announce itself: 'leaked 2 stuck
//! host threads' once per round", and that was true when it was written.
//!
//! Why it stopped is the design working. `abandon_stuck_threads` runs only
//! after a thread has failed to report in for ~520 ms *and* three rounds of
//! `SIGUSR1` and `cpu_poke`; the emulator installs `SIGUSR1` deliberately
//! **without `SA_RESTART`** (`crates/kernel/boot`'s comment says so), so a host
//! syscall it lands in returns `EINTR` and the thread leaves. On top of that a
//! pipe is this kernel's own object since `crates/fs/pipe`, so the read here
//! parks on a `GuestLock` and is interruptible by construction rather than by
//! luck.
//!
//! So what this program still covers is real — a group exit with threads in
//! blocking syscalls completes and reports the right status — and the valve
//! half of its comment was describing a tree that no longer exists. Finding a
//! workload that genuinely sticks a thread is open; `guest_tests.sh` prints the
//! valve round count on every run so the gap is visible rather than assumed
//! away.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// In the child: block a thread on a pipe read that can never complete, hold a
/// second one on a blocking read of a real file descriptor, then exit.
fn child(exit_code: i32) -> ! {
    unsafe {
        let mut pipefd = [0i32; 2];
        if libc::pipe(pipefd.as_mut_ptr()) != 0 {
            libc::_exit(70);
        }
        let read_end = pipefd[0];
        let ready = Arc::new(AtomicBool::new(false));

        // The stuck thread. It never returns: nothing writes the pipe, and the
        // write end stays open here so it does not even see EOF.
        {
            let ready = ready.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 16];
                ready.store(true, Ordering::SeqCst);
                // Blocks for ever.
                libc::read(read_end, buf.as_mut_ptr().cast(), buf.len());
            });
        }
        // A second one in epoll_wait. This reaches the separate persistent
        // backend wait loop rather than poll_wait's explicit group-exit check.
        std::thread::spawn(move || {
            let epoll = libc::epoll_create1(0);
            if epoll < 0 {
                return;
            }
            let mut event: libc::epoll_event = std::mem::zeroed();
            libc::epoll_wait(epoll, &raw mut event, 1, -1);
            libc::close(epoll);
        });

        while !ready.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        // Give the reads time to be inside the host syscall rather than on
        // their way to it.
        libc::usleep(20_000);

        // exit_group from the main thread, with two threads blocked.
        libc::_exit(exit_code);
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("child") {
        child(43);
    }
    let rounds: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    let exe = std::env::args().next().unwrap_or_default();
    let mut bad = 0;
    for i in 0..rounds {
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                let c = std::ffi::CString::new(exe.clone()).unwrap();
                let arg = c"child";
                libc::execl(
                    c.as_ptr(),
                    c.as_ptr(),
                    arg.as_ptr(),
                    std::ptr::null::<libc::c_char>(),
                );
                libc::_exit(71);
            }
            if pid < 0 {
                continue;
            }
            let mut status = 0;
            let got = libc::waitpid(pid, &mut status, 0);
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            };
            if got != pid || code != 43 {
                println!("LOST: round {i} pid {pid} waitpid={got} status={status:#x} code={code}");
                bad += 1;
            }
        }
    }
    println!("rounds: {rounds}, bad: {bad}");
    println!("survived");
}
