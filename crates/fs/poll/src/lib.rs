//! The poll layer over `struct fd`: what a descriptor answers about its own
//! readiness, and the wait loop a `poll()` or `select()` sits in.
//!
//! The *set* is `crates/fs/pollset` and the durable watchers are
//! `crates/kernel/epoll`; both keep member handles behind typed trait
//! boundaries and never dereference one. This is the half that knows what a
//! `struct fd` is — three
//! questions, asked through an operation table — and the loop that reads
//! `current`.
//!
//! # The `POLL_*` numbers are generated, and that is not incidental
//!
//! `fs/poll.h` `#undef`s `<signal.h>`'s `POLL_ERR`, `POLL_PRI` and `POLL_HUP` —
//! the `si_code` values a `SIGIO` carries, 4, 5 and 6 — and defines its own 8, 2
//! and 16. bindgen records a macro where it first *sees* one and keeps that
//! value through the undef, so a crate that allowlisted `POLL_[A-Z]+` got
//! signal.h's, and **the wrong `POLL_ERR` is 4, which is `POLL_WRITE`**: every
//! member of a set was implicitly listening for writability, so an empty
//! eventfd satisfied a `poll()` waiting to read it. The values come from
//! `enum iul_poll_bits`, whose enumerators are evaluated after every include.
//! `tools/bindgen-shadowed.py` is the check.
//!
//! # The idle-exit valve, and why it is off
//!
//! `IUL_IDLE_EXIT` names a number of seconds; without it nothing here gives up.
//! It was on at 60 seconds, and what it does is `do_exit_group(0)` — the process
//! is killed and reports **success**. Waiting is not a hang: a daemon waiting
//! for a connection, a worker on a socket and any program in a long `select()`
//! all sit here doing nothing, and none of the exemptions covers one. Measured:
//! a process that is not pid 1, has no controlling terminal and blocks in
//! `poll()` is gone at 60 seconds and its parent sees status 0. Narrowing it to
//! whatever V8 exit-cleanup hang it was written for needs a reproducer, and
//! there is not one here.
//!
//! The rules — the exemptions, the boundary, the saturating idle time — are
//! `crates/fs/pollset`'s `wait` module and have tests. What is here is the three
//! questions only a task can answer.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_int, c_short};

mod members;
pub use members::{
    EpollFd, EpollMember, Fd, Set, epoll_copy_ready, epoll_watch_add, epoll_watch_del,
    epoll_watch_mod, poll_add_fd, poll_create_transient, poll_wakeup,
    set_epoll_fd_hook,
};

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

use guest_errno::c_int_::EINTR;

/// The `POLL_*` bits, which are this kernel's own numbering.
///
/// **Rust, since 2026-09-04.** They were `#define`s in `fs/poll.h` plus an
/// `enum iul_poll_bits` that existed only so bindgen could see them — the
/// comment there said as much — and no C read either. Eight crates got them
/// through their own bindgen; they take them from here now.
///
/// The values are Linux's `POLLIN`, `POLLPRI`, `POLLOUT`, `POLLERR`,
/// `POLLHUP`, `POLLNVAL`, `POLLRDNORM`, `POLLWRNORM` and `POLLRDHUP`, which is
/// what a guest passes and receives. `ONESHOT` and `EDGETRIGGERED` are epoll's
/// and are in the same word because a registration carries both.
pub mod bits {
    pub const READ: i32 = 1;
    pub const PRI: i32 = 2;
    pub const WRITE: i32 = 4;
    pub const ERR: i32 = 8;
    pub const HUP: i32 = 16;
    pub const NVAL: i32 = 32;
    pub const RDNORM: i32 = 1 << 6;
    pub const WRNORM: i32 = 1 << 8;
    pub const RDHUP: i32 = 1 << 13;
    pub const ONESHOT: i32 = 1 << 30;
    /// Does not fit an `i32`, which is why the C enum left it out.
    pub const EDGETRIGGERED: u32 = 1 << 31;

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The values a guest passes and receives, which are Linux's `POLL*`.
        ///
        /// Written out rather than derived, because they *are* the ABI: a
        /// guest's `struct pollfd` carries them and `epoll_event` carries the
        /// two above them. They were `#define`s in `fs/poll.h` until
        /// 2026-09-04 and this is what replaced the compiler's check of them.
        #[test]
        fn the_bits_are_linuxs() {
            assert_eq!((READ, PRI, WRITE, ERR, HUP, NVAL), (1, 2, 4, 8, 16, 32));
            assert_eq!(RDNORM, 0x40);
            assert_eq!(WRNORM, 0x100);
            assert_eq!(RDHUP, 0x2000);
            // epoll's two, which share the word.
            assert_eq!(ONESHOT, 0x4000_0000);
            assert_eq!(EDGETRIGGERED, 0x8000_0000);
            // And they do not overlap: a registration holds the union.
            let all = [
                READ, PRI, WRITE, ERR, HUP, NVAL, RDNORM, WRNORM, RDHUP, ONESHOT,
            ];
            let mut seen = 0i32;
            for b in all {
                assert_eq!(seen & b, 0, "{b:#x} overlaps");
                seen |= b;
            }
            assert_eq!(seen as u32 & EDGETRIGGERED, 0);
        }
    }
}

/* `now_ns` was defined here until 2026-09-15 — one of five private copies,
 * all asking `CLOCK_MONOTONIC` and answering `u64` nanoseconds. It is
 * `util_timeabi::monotonic_ns` now, which saturates where three of the five
 * multiplied plainly. */
use util_timeabi::monotonic_ns as now_ns;

/// `POLLIN` implies `POLLRDNORM` and `POLLOUT` implies `POLLWRNORM` for every
/// file type this emulator has — the distinction is about priority bands, which
/// only STREAMS ever used. Linux's own poll methods set them together.
///
/// A negative argument is an errno passing through.
pub fn poll_add_aliases(types: c_int) -> c_int {
    if types < 0 {
        return types;
    }
    let mut t = types;
    if t & bits::READ != 0 {
        t |= bits::RDNORM;
    }
    if t & bits::WRITE != 0 {
        t |= bits::WRNORM;
    }
    t
}

/// What a descriptor says about itself. 0 for one with no `poll` operation,
/// which is every descriptor that is always ready in both directions and whose
/// caller treats 0 as "ask the host".
/// Not `#[unsafe(no_mangle)]` since 2026-09-06. No C source calls it, no
/// `ffi::` reaches it, and no header the embedder example compiles against
/// declares it -- so the export was a second interface with nobody on the
/// other side, and an optimisation barrier: LTO must emit an externally
/// visible function as written and cannot specialise the call.
pub fn fd_poll_types(fd: &ffi::fd) -> c_int {
    match fd.ops.and_then(|ops| ops.poll(fd)) {
        None => 0,
        Some(types) => poll_add_aliases(types),
    }
}

/// Whether this descriptor's readiness is the host's answer about `real_fd`.
///
/// # It was an address comparison until 2026-09-11
///
/// `fn_addr_eq(ops->poll, realfs_poll)` — the **operation**, not the table,
/// because a fakefs descriptor has a driver of its own and forwards `poll` to
/// realfs, so comparing tables answered no for every file in a fakefs.
///
/// The argument for it was that a release link folds two functions only when
/// their code is identical, so anything sharing `realfs_poll`'s address *is*
/// `realfs_poll`'s code. That made it sound and it never made it right: an
/// address comparison can answer "does this behave like that one" and never
/// "is this the one I mean", which is the question being asked. The three
/// drivers whose readiness really is the host's say so themselves now, and the
/// fakefs case that forced the shape is one line in that driver rather than a
/// property of the linker.
fn is_realfs(fd: &ffi::fd) -> bool {
    fd.ops.is_some_and(|ops| ops.poll_follows_host_fd())
}

// ---------------------------------------------------------------- the loop

/// `pids_lock`, held for a scope.
///
/// `crates/kernel/pids` owns the lock and the guard. This was the sixth
/// private copy of the type; a guard duplicated is a place the release can
/// drift from the acquire, and the copies could not see each other to drift
/// visibly.
use kernel_pids::PidsGuard;

/// Whether this thread group has a child process that is still alive.
///
/// Walks every thread's children, which is why it is asked *after* the cheap
/// exemptions: this takes `pids_lock`, which fork, exit, wait and kill all need.
fn has_live_children(group: &ffi::tgroup) -> (bool, i32) {
    let pids = PidsGuard::take();
    let group = kernel_pids::Group::from_ref(pids.held(), group);
    let mut live = false;
    let mut threads = 0;
    for t in group.threads() {
        threads += 1;
        live |= t
            .children()
            .any(|child| child.group().map(kernel_pids::Group::raw) != Some(group.raw()) && !child.is_zombie());
    }
    (live, threads)
}

/// The idle-exit valve, for the calling thread's group. See the module comment
/// for why it is off by default.
///
/// Safe since 2026-10-01: it took the task as a raw pointer and read its group
/// through it four times. The group is the calling thread's, which
/// `with_current_group` lends.
fn should_give_up() -> bool {
    let limit = util_iulenv::env().idle_exit_secs;
    if limit <= 0 {
        return false;
    }
    let pid = taskview::current_pid();
    let decided = taskview::with_current_group(|group| {
        // Relaxed, as the C's atomic_load_explicit was: this is a timestamp
        // read for a heuristic, not a handshake.
        let last = group.last_progress_ns.load(std::sync::atomic::Ordering::Relaxed);
        let idle_s = pollset::wait::poll_idle_secs(last, now_ns());

        // Asked before the walk, which takes pids_lock: the exemptions and the
        // limit are cheap and the walk is not.
        if !pollset::wait::poll_should_give_up(i64::from(limit), idle_s, pid == 1, group.ctty.has(), false) {
            return false;
        }
        let (live, threads) = has_live_children(group);
        if live {
            return false;
        }
        if util_iulenv::env().exec_trace {
            logline::printk(&format!(
                "SAFETY-VALVE[poll]: pid={pid} idle {idle_s}s, {threads} threads -> exit_group"
            ));
        }
        true
    });
    decided.unwrap_or(false)
}

/// How a wait ended.
///
/// **The idle valve is why this is an enum and not an `int`.** A `poll` that
/// has made no progress for long enough is treated as a stuck process and the
/// process is ended -- and the call that ends it, `do_exit_group`, is the
/// *syscall* layer's, while this is the wait loop. Calling it from here made
/// `fs-poll` depend on `kernel-exitcalls`, which depends on
/// `kernel-signaldeliver`, which depends on `kernel-signalfdcalls`, which
/// depends on `fs-poll`: a cycle, and a cycle because a wait loop was deciding
/// a process's fate. The decision stays here, where the idle time is measured;
/// the action is the caller's, and being an enum is what stops a caller
/// forgetting it.
pub enum Waited {
    /// A count of ready members, or a negative guest errno.
    Done(c_int),
    /// The valve fired: end the process with status 0. The set is **already
    /// released**, because `do_exit_group` does not come back and leaving it
    /// claimed kept the wake pipe open for the life of the set -- the next
    /// `poll_wait` on it then tripped the assert that the pipe is -1 when the
    /// first waiter arrives.
    GiveUp,
}

/// Calls `callback` for every ready registration and sums what it makes ready,
/// or answers a negative guest errno.
///
/// Safe since 2026-10-01: the timeout was a nullable `*const timespec` and the
/// group was read through the raw task.
pub fn poll_wait(
    set: &mut Set,
    callback: &mut impl FnMut(c_int, u64) -> c_int,
    timeout: Option<&libc::timespec>,
) -> Waited {
    // The first thing the wait needs is somewhere for a wakeup to land.
    let err = set.acquire();
    if err < 0 {
        return Waited::Done(err);
    }

    // The guest's timeout as a deadline, fixed once. Each pass below waits at
    // most a second so signals and group exit stay responsive, and the C used
    // to deduct a flat second per *timed-out* pass -- which left every other
    // way of going round the loop free. A wakeup that turned out not to be for
    // us restarted the whole second, so a stream of unrelated wakeups held a
    // timed wait open indefinitely. The caller's struct is not written through
    // either.
    // Saturating, every step. `timespec_valid` puts no upper bound on
    // `tv_sec` -- Linux's does not either, and its `timespec64_add_safe`
    // saturates -- so a guest may pass `LLONG_MAX` and this multiplied it by a
    // billion. In a debug build that is a panic inside an `extern "C"` function
    // that cannot unwind, which aborts: **one `pselect6` from any guest killed
    // the emulator**. In a release build it wraps, and a wait meant to be
    // effectively infinite returns at an arbitrary time instead.
    //
    // Found by `tests/guest/src/bin/poll_probe.rs`, whose LLONG_MAX case exists
    // because Linux accepts it.
    let timed = timeout.is_some();
    let deadline_ns = timeout.map_or(0, |t| {
        now_ns()
            .saturating_add((t.tv_sec as u64).saturating_mul(1_000_000_000))
            .saturating_add(t.tv_nsec as u64)
    });

    let mut res: c_int = 0;
    loop {
        // poll()/select() are transient by construction: one batched host poll
        // answers every host-backed member and the virtual members are
        // rechecked through their fd_ops after a wake.
        let ready = set.scan(&mut *callback);
        if ready < 0 {
            res = ready;
            break;
        }
        res += ready;
        if res > 0 {
            break;
        }

        if taskview::current_signal_pending() {
            res = EINTR;
            break;
        }

        let slice_ms = pollset::wait::poll_slice_ms(timed, deadline_ns, now_ns());
        if slice_ms < 0 {
            break; // the guest's timeout is up; res stays 0
        }

        let mut saved_errno: c_int = 0;
        taskview::set_blocking(true);
        let err = set.block(slice_ms, &mut saved_errno);
        taskview::set_blocking(false);

        // Only on real events. A timeout return is the loop cycling, not
        // progress, and counting it would let an idle poll_wait during exit
        // cleanup fool the deadlock detector.
        if err > 0 {
            taskview::with_current_group(|g| {
                g.last_progress_ns.store(now_ns(), std::sync::atomic::Ordering::Relaxed)
            });
        }

        if err < 0 {
            // EINTR here is the host's own wakeup signal. SIGUSR1 is how signal
            // delivery gets a thread out of the host poll, and it is sent for a
            // guest signal *and* for a signalfd that has become readable.
            // Neither is by itself a reason to fail the call: whether the guest
            // sees EINTR is decided by the pending-signal check at the top of
            // this loop, and a wakeup that was only about readiness must not
            // turn into a syscall error the guest never asked for. Going round
            // again re-polls and answers correctly either way.
            if saved_errno == libc::EINTR {
                continue;
            }
            res = kernel_errno::raised(saved_errno);
            break;
        }

        if err > 0 {
            set.drain();
            continue;
        }

        // Timed out on this pass' slice. Loop back to re-check readiness and
        // pending signals; the deadline check above is what ends a timed wait.
        // Group exit is checked here so blocking threads unblock promptly.
        if taskview::current_must_leave().is_some() {
            res = EINTR;
            break;
        }
        if should_give_up() {
            set.release();
            return Waited::GiveUp;
        }
    }

    set.release();
    Waited::Done(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_poll_bits_are_this_headers_and_not_signal_hs() {
        // signal.h's POLL_ERR, POLL_PRI and POLL_HUP are 4, 5 and 6 -- the
        // si_code values a SIGIO carries -- and 4 is this header's POLL_WRITE.
        // A set built from the wrong one listens for writability on every
        // member, so an empty eventfd satisfies a wait to read it.
        assert_eq!(bits::READ, 1);
        assert_eq!(bits::WRITE, 4);
        assert_eq!(bits::ERR, 8);
        assert_eq!(bits::HUP, 16);
        assert_eq!(bits::RDNORM, 1 << 6);
        assert_eq!(bits::WRNORM, 1 << 8);
    }

    #[test]
    fn an_alias_follows_its_principal_and_nothing_else() {
        assert_eq!(poll_add_aliases(bits::READ), bits::READ | bits::RDNORM);
        assert_eq!(poll_add_aliases(bits::WRITE), bits::WRITE | bits::WRNORM);
        assert_eq!(
            poll_add_aliases(bits::READ | bits::WRITE),
            bits::READ | bits::RDNORM | bits::WRITE | bits::WRNORM
        );
        assert_eq!(
            poll_add_aliases(bits::HUP),
            bits::HUP,
            "no principal, no alias"
        );
        assert_eq!(poll_add_aliases(0), 0);
    }

    #[test]
    fn a_negative_argument_is_an_errno_passing_through() {
        // The callers chain this onto a poll operation that may have failed, so
        // it has to leave a negative alone rather than set bits in it.
        assert_eq!(poll_add_aliases(-4), -4);
        assert_eq!(poll_add_aliases(-1), -1);
    }
}
