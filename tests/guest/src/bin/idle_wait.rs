//! A process that is only waiting must not be killed for it.
//!
//! `fs/poll.c` carried a safety valve: a process whose group had done no "real
//! work" for 60 seconds, with no live child processes, was force-exited from
//! inside the poll wait loop. It was written for "V8/libuv exit cleanup hangs
//! where the event loop spins idle forever".
//!
//! Waiting is not a hang. A daemon waiting for a connection, a worker waiting
//! on a socket and any program in a long `select()` all sit in exactly that
//! loop doing exactly nothing, and none of the three exemptions — pid 1, a
//! controlling terminal, a live child — covers a background process. Measured:
//! a child that blocks in `poll()` was gone at 60 seconds and its parent saw
//! **exit status 0**, so a supervisor would not even restart it.
//!
//! It is off unless `IUL_IDLE_EXIT` names a number of seconds, which is what
//! makes this test quick: the harness runs it once with the valve on at three
//! seconds and once with it off.
//!
//! # Why the child does nothing else
//!
//! "Real work" is any syscall that is not one of the blocking ones, so a loop
//! that checks the clock refreshes the timer and hides the whole thing. The
//! first version of this probe called `Instant::now()` once per iteration and
//! survived 75 seconds for that reason alone. The child here makes one `poll`
//! call with no timeout and nothing else.

use guest_tests::{Harness, check};

/// Blocks in `poll()` on a pipe nothing will ever write to, and makes no other
/// syscall. Never returns unless something kills it.
fn wait_forever() -> ! {
    let mut fds = [0i32; 2];
    unsafe {
        libc::pipe(fds.as_mut_ptr());
        let mut pfd = libc::pollfd { fd: fds[0], events: libc::POLLIN, revents: 0 };
        libc::poll(&mut pfd, 1, -1);
        libc::_exit(9);
    }
}

/// Whether `pid` is still there, waiting up to `secs` for it not to be.
/// `Some(status)` if it exited, `None` if it outlasted the wait.
fn outcome(pid: i32, secs: u64) -> Option<i32> {
    for _ in 0..(secs * 10) {
        let mut st = 0i32;
        if unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) } == pid {
            return Some(st);
        }
        unsafe { libc::usleep(100_000) };
    }
    None
}

fn main() {
    let mut h = Harness::new();
    // "killed" is the harness's run with IUL_IDLE_EXIT=3; the default run
    // expects the opposite and is what a real kernel also does.
    // argv[1] is "killed" or "alive"; argv[2] is how long the "alive" run
    // waits, which the harness leaves at the default.
    let expect_killed = std::env::args().nth(1).as_deref() == Some("killed");

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Not pid 1, no controlling terminal, no children of its own: none of
        // the valve's exemptions applies.
        unsafe { libc::setsid() };
        wait_forever();
    }
    check!(h, pid > 0, "forked a child that only waits");

    if expect_killed {
        h.group("with-the-valve-on-it-fires");
        let st = outcome(pid, 15);
        check!(h, st.is_some(), "the child is gone within 15s of a 3s idle limit");
        if let Some(st) = st {
            // What it does is do_exit_group(0), so the parent sees a *success*.
            // Asserted rather than left implicit: that is the part that makes it
            // invisible to anything supervising the process.
            check!(
                h,
                libc::WIFEXITED(st),
                "and it exited rather than being signalled: status {st:#x}"
            );
            check!(
                h,
                libc::WEXITSTATUS(st) == 0,
                "reporting success, which is what hides it: {}",
                libc::WEXITSTATUS(st)
            );
        }
    } else {
        h.group("a-process-that-only-waits-keeps-waiting");
        // **Longer than the limit this guards**, which was sixty seconds. Six
        // would run in a tenth of the time and prove nothing: a valve still on
        // at sixty would let a six-second wait through, and the check would
        // pass against exactly the thing it is about. `CLAUDE.md`: a bound test
        // that does not test the bound proves the bound is approximately
        // somewhere.
        //
        // It is the reason this file takes a minute. The other run, which
        // *does* fire, is over in four seconds because the harness gives it a
        // three-second limit -- so the mechanism is tested quickly and only the
        // absence of it costs the wait.
        let secs: u64 = std::env::args()
            .nth(2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(65);
        let st = outcome(pid, secs);
        check!(
            h,
            st.is_none(),
            "still waiting after {secs}s, not killed for it (status {:?})",
            st
        );
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            let mut s = 0i32;
            libc::waitpid(pid, &mut s, 0);
        }
    }

    std::process::exit(h.finish());
}
