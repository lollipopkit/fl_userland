//! Building a thread group, and unbuilding one that was never used.
//!
//! There were two copies of this: `construct_task` in `kernel/init.c` for the
//! first process and whatever an embedder starts, and `tgroup_copy` in
//! `kernel/fork.c` for every other. The same six allocations in the same
//! order, and **the two failure paths had already drifted**: fork's freed all
//! six, and init's freed three and forgot `groupstop`, `grouprusage`, `ctty`,
//! `itimer` and the condition variable.
//!
//! That is exactly why `tgroup_release` was made one function — its comment says
//! "it was two copies of the same nine calls in the same order, and a group has
//! acquired something new four times this month". Teardown was unified and
//! construction was not, so this is the other half.
//!
//! Only an allocation failure reaches either path, so nothing observed the leak.
//! It is recorded because the *next* thing a group acquires would have had to be
//! remembered in three places instead of one.
//!
//! # What a child inherits
//!
//! `like` is the group to inherit from, or null for a process with no parent.
//! The list is Linux's and each entry says why:
//!
//! - the session and the process group, which the registry copies rather than
//!   the caller naming either;
//! - the niceness;
//! - `fs_context`, which an embedder registers the meaning of and expects to
//!   follow the process tree — `execve` does not reset it and `fork` does not
//!   clear it;
//! - the per-process `prctl` attributes **whole**, and then `child_subreaper`
//!   cleared. Copied rather than named field by field, because a designated
//!   initialiser that names some fields zeroes the rest and `dumpable`'s zero is
//!   `SUID_DUMP_DISABLE` — a value that means something, not an absence.
//!
//! And what it does not: the limits are a *copy* (sharing meant a child's
//! `setrlimit` moved its parent's), the POSIX timers are empty (sharing the
//! array meant a child's `timer_delete` destroyed a timer its parent still
//! owned), the interval timer is empty, the stop is its own object, and the
//! times start at zero. Everything else is left zeroed rather than named, which
//! is what `crates/kernel/groupexit`'s "a zeroed one *is* not exiting" test is
//! about.

#![deny(unsafe_op_in_unsafe_fn)]

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/* An `unsafe extern "C" {}` block with **nothing in it** was here, under a
 * marker saying the definitions are in another crate and a Rust call would be a
 * cycle. Its last declaration went at some point in the conversion and the
 * block, the marker and the paragraph explaining the marker stayed — which
 * makes this crate read as having a C ABI edge it has not had for weeks.
 * Removed 2026-09-09. */

/* `now_ns` was defined here until 2026-09-15 — one of five private copies,
 * all asking `CLOCK_MONOTONIC` and answering `u64` nanoseconds. It is
 * `util_timeabi::monotonic_ns` now, which saturates where three of the five
 * multiplied plainly. */
use std::sync::atomic::{AtomicBool, AtomicI32};
use util_timeabi::monotonic_ns as now_ns;
/// How many `struct tgroup` are allocated, for `/proc/iul/objects`.
///
/// **Not the same number as `tgroup` in that file**, which counts
/// `crates/kernel/proctree`'s registry entries: an entry is forgotten one step
/// before the struct is freed, so a leak of the allocation is invisible to it.
static LIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many `struct tgroup` exist.
pub fn tgroup_live_count() -> usize {
    LIVE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Give the struct itself back.
///
/// **One owner for the pair**, because there are two teardown paths in two
/// crates — this crate's [`tgroup_free_new`] for a group that was never used,
/// and `crates/kernel/exitcalls`' `tgroup_release` for a dead one — and they
/// free what they own in different orders for a stated reason. What they must
/// not do differently is the struct, which was `libc::free` in both until
/// 2026-09-12: a `Box` runs a field's destructor where `free` leaks it, and a
/// second `libc::free` would be a second place to remember that.
///
/// Its fields' destructors are what release what it owns, so this is where
/// the controlling terminal's reference and the rest go back.
///
/// # Safety
/// `g` came from [`tgroup_new`], nothing holds it, its condition variable has
/// been destroyed, and `posix_timers` has been taken out if it may hold armed
/// timers -- dropping it waits for an expiry, which needs `pids_lock`.
pub unsafe fn tgroup_free_struct(g: *mut ffi::tgroup) {
    // SAFETY: the caller's contract.
    drop(unsafe { Box::from_raw(g) });
    LIVE.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
}

// `release_owned` was here until 2026-09-30: the objects a group owned by
// pointer, freed by hand on the failure path of a construction that got
// partway and by `tgroup_free_new`. Six until that day, and none now -- `ctty`,
// `times`, `itimer`, `stop` and `hosts` are held by value and `posix_timers` is
// an `Option<Box>`, so the struct's own drop gives each back, and nothing
// after the allocation can fail.

/// A new thread group. Null when anything it needs could not be allocated,
/// having freed whatever it had.
///
/// **Not registered**: nothing can find it until [`tgroup_publish`], which the
/// caller makes under the same `pids_lock` hold that publishes its first
/// thread. It registered itself in the process-group index until 2026-09-30,
/// so a `kill` to the parent's process group could reach a group whose leader
/// was not built yet.
///
/// `like` is the group it copies its inherited state from, and `leader` the
/// task being built to lead it -- an address recorded, not read.
pub fn tgroup_new(like: Option<&ffi::tgroup>, leader: *mut ffi::task) -> std::ptr::NonNull<ffi::tgroup> {
    let template = like;

    // **Every one of the eighteen fields named**, where `libc::calloc` named
    // nine and left the rest to the zeroing until 2026-09-12. Two of the nine
    // were a zero nobody had decided, and this is where they are decided:
    //
    // - `attr` — the *thread* group's `prctl` attributes. `ProcAttr::default()`
    //   is `dumpable: SUID_DUMP_USER`, which is 1; `calloc` made a fresh group
    //   `SUID_DUMP_DISABLE`, and it was `procattr_proc_init` a few lines later
    //   that put it right. Naming the field is the same value from one place
    //   instead of two.
    //
    // The rest of the zeros are decisions and stay: `exit` zeroed is "not
    // exiting", which `crates/kernel/groupexit` has a test for; `v8_aborting`, `nice` and `fs_context` are each the
    // absence of a setting; and the owned pointer starts null so that the
    // failure path below can release a construction that got partway.
    let stop = groupstop::GroupStop::new();
    let fresh = ffi::tgroup {
        // The task `construct_task` or `copy_task` is building. They wrote it
        // through the pointer this returns until 2026-10-17.
        leader: std::sync::atomic::AtomicPtr::new(leader),
        // The session and the process group, which the registry copies rather
        // than the caller naming either.
        sid: AtomicI32::new(template.map_or(0, |t| t.sid())),
        pgid: AtomicI32::new(template.map_or(0, |t| t.pgid())),
        attr: match template {
            None => ffi::proc_attr::default(),
            Some(t) => {
                // The per-process `prctl` attributes **whole**, and then
                // `child_subreaper` cleared: a designated initialiser that
                // names some fields zeroes the rest, and `dumpable`'s zero
                // means something.
                let attr = t.attr.clone();
                attr.set_child_subreaper(0);
                attr
            }
        },
        nice: AtomicI32::new(template.map_or(0, |t| t.nice())),
        oom_score_adj: AtomicI32::new(template.map_or(0, |t| t.oom_score_adj())),
        oom_score_adj_min: AtomicI32::new(template.map_or(0, |t| t.oom_score_adj_min())),
        // The one this group owns by pointer, filled in below so that the
        // failure path has something it can release whatever it got to.
        stop,
        // And the controlling terminal, held by value: the parent's, with a
        // reference of its own.
        ctty: template.map_or_else(ctty::Ctty::new, |t| ctty::Ctty::from_parent(&t.ctty)),
        itimer: itimer::Itimer::new(),
        posix_timers: Some(Box::new(kernel_posixtimers::Timers::new())),
        // A *copy*: sharing meant a child's `setrlimit` moved its parent's.
        limits: match template {
            None => kernel_rlimitstate::Limits::defaults(ffi::MAX_PID as u64),
            Some(t) => t.limits.clone(),
        },
        // A zeroed one is not exiting, which is what
        // `crates/kernel/groupexit`'s test says.
        exit: ffi::group_exit::default(),
        v8_aborting: AtomicBool::new(false),
        // Only the first process is init; a fork's child never is.
        unkillable: AtomicBool::new(false),
        // A new process has nothing pending: fork(2) clears it.
        shared_signals: Default::default(),
        times: grouprusage::GroupRusage::new(),
        child_exit: ffi::cond_t::new(),
        // An `AtomicU64` so that every access to the field reads the same way
        // -- which is what the field's own type says now, where a C `_Atomic`
        // and a grep used to.
        last_progress_ns: std::sync::atomic::AtomicU64::new(now_ns()),
        // An embedder registers the meaning of this and expects it to follow
        // the process tree: `execve` does not reset it and `fork` does not
        // clear it.
        fs_context: template.map_or(0, |t| t.fs_context),
        // No threads yet: a new process starts with the one thread that is
        // about to run in it, and the caller counts that.
        hosts: kernel_hostthreads::HostThreads::new(),
    };

    // **A `Box`, never null, since 2026-10-01.** It was `std::alloc::alloc`
    // with a null test so that a `fork` could answer `ENOMEM` -- for this one
    // allocation, while `HostThreads::new` above and the task, the address
    // space and the descriptor table beside it allocate the way every Rust
    // allocation does, aborting. `tgroup_free_struct`'s `Box::from_raw` owns
    // it as before.
    let g = Box::new(fresh);
    LIVE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::ptr::NonNull::from(Box::leak(g))
}

/// Register a group [`tgroup_new`] made from `like` in the process-group and
/// session index: it starts where its parent is, and the registry copies both
/// numbers rather than the caller naming either. A group made from nothing is
/// registered by `setsid` instead.
///
/// `group` came from `tgroup_new`, made from `like`. Safe: the two pointers
/// become registry ids and are not read.
pub fn tgroup_publish(pids: &kernel_pids::PidsHeld, group: *mut ffi::tgroup, like: *mut ffi::tgroup) {
    let (Some(g), Some(t)) = (ffi::TgroupId::from_ptr(group), ffi::TgroupId::from_ptr(like)) else {
        return;
    };
    kernel_pids::insert_like(pids, g, t);
}

/// Undoes [`tgroup_new`] for a construction that failed *afterwards*: the group
/// has no threads and a leader that is about to be destroyed.
///
/// The `&PidsHeld` was "the caller holds `pids_lock`" in prose until
/// 2026-09-16 — one of the seven that said it that way, which is why
/// `clippy::unnecessary_safety_doc` could not count them. The terminal
/// reference is the one `tgroup_new` took and the parent still holds its own,
/// so this cannot be the last.
///
/// # Safety
/// `g` is null or a group [`tgroup_new`] answered, with no threads, and is not
/// used afterwards.
pub unsafe fn tgroup_free_new(pids: &kernel_pids::PidsHeld, g: *mut ffi::tgroup) {
    if g.is_null() {
        return;
    }
    unsafe {
        kernel_pids::remove(pids, ffi::TgroupId::of(&*g));
        // The group is going: its thread list goes with it, or a later
        // allocation returning the same address inherits it.
        proctree::group_forget(g);
        // A group no thread ran in has armed no POSIX timer, so dropping its
        // table here does not wait.
        tgroup_free_struct(g);
    }
}

// ---------------------------------------------------------------------------
// The one pthread object a thread group has
// ---------------------------------------------------------------------------
//
// `child_exit` is ready from `cond_t::new` and destroyed with the struct since
// 2026-10-16; there was an init and a destroy function here.

/// Wake every thread waiting for a child of this group to exit.
///
/// The caller holds `pids_lock`, which is what the waiters park under -- a
/// wakeup given without it can land between a waiter's check and its park;
/// the handle is the proof.
///
/// It took a `&mut ffi::tgroup` until 2026-09-30, and all four callers made
/// one out of *another process's* group -- a parent or a tracer -- whose
/// threads were running and reading it. A `&mut` asserts that nothing else
/// touches the whole struct, which is the licence the release-build hang in
/// `docs/changelog/2026-08-31-a-release-build-hung-closing-a-descriptor.md`
/// was the optimiser taking. What the function needs is one field.
pub fn tgroup_notify_child_exit(group: kernel_pids::Group<'_>) {
    waitfor::notify_all(group.child_exit());
}

#[cfg(test)]
mod tests {
    use super::*;

    // `the_owned_objects_are_the_six_this_frees` and
    // `a_zeroed_group_owns_nothing` went on 2026-09-30, with five of the six
    // fields they named: what was left asserted that a zeroed pointer is null
    // and that a field's offset is inside its struct.

    /// A zeroed `tgroup`, as memory: its pointer and plain fields can be read,
    /// and it is not a value -- `ctty` holds a `Mutex`.
    fn zeroed() -> std::mem::MaybeUninit<ffi::tgroup> {
        std::mem::MaybeUninit::zeroed()
    }

    /// A fresh group's `prctl` attributes are `ProcAttr::default()`, not zero.
    ///
    /// `dumpable`'s zero is `SUID_DUMP_DISABLE` — a value that means something,
    /// not an absence — and `ProcAttr::default()` is `SUID_DUMP_USER`, whose
    /// value is 1. Until 2026-09-12 `tgroup_new` `calloc`ed the struct and put
    /// the field right a few lines later with `procattr_proc_init`; it is named
    /// at the initialiser now, and this is what says the two values were the
    /// same.
    ///
    /// `tgroup_new` itself cannot be called here — it reaches the pid registry,
    /// the process tree and four allocating crates — so what is asserted is the
    /// value the initialiser names against the value the zeroing gave.
    #[test]
    fn a_fresh_groups_attributes_are_not_the_zeroed_ones() {
        assert_eq!(ffi::proc_attr::default().dumpable(), 1);
        let g = zeroed();
        // SAFETY: `attr` is a `#[repr(C)]` struct of integers, for which zero
        // is a value.
        let attr = unsafe { (&raw const (*g.as_ptr()).attr).read() };
        assert_eq!(attr.dumpable(), 0);
        assert!(!ffi::proc_attr::default().child_subreaper());
    }
}
