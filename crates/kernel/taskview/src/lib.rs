//! The shared Rust view of `struct task` and `struct tgroup`.
//!
//! # Why this exists
//!
//! Step 4 of the migration is `struct task`, and the way it was attempted first
//! was a field group at a time: the field leaves for a Rust object, `struct
//! task` keeps an opaque pointer, and C keeps an accessor. Measured on
//! 2026-08-29, five such moves **grew the C by 58 lines** — because every
//! function body that used the field was untouched and now had a call in front
//! of it.
//!
//! The tax is the accessor, and the accessor exists for one reason: Rust could
//! not see the struct. `kernel/fs.c` is 153 lines and almost all of it is that
//! shape — three functions whose whole content is `current->creds` followed by a
//! call into `crates/kernel/creds`, which already owns the rules.
//!
//! So the structs are **defined in Rust** instead. `#[repr(C)]` and compile-time
//! layout assertions make their ownership explicit, while the C headers keep
//! only forward declarations because no C code reads their fields.
//!
//! # What this is not
//!
//! It is **not** ownership. C still allocates a task, frees it, and holds it in
//! `current`; nothing here changes who decides when a task exists. What it
//! changes is that a crate migrating a syscall family can read the fields that
//! family needs without a C function per field.
//!
//! It is also not safety. Reading `task->exiting` from Rust is exactly as
//! unchecked as reading it from C, and the locking discipline is the same one
//! the `// locked by X` comments describe. What Rust gets is the ability to
//! delete the C, which is the thing that was not happening.
//!
//! # `current` is this crate's, and the old measurement was of a tree that no
//! longer exists
//!
//! It was a C `__thread` variable until 2026-09-06, kept by a measurement from
//! 2026-08-29: `-DIUL_CURRENT_VIA_CALL=1` builds the shape where Rust owns it
//! and C reaches it through an accessor, and that cost **3–5% of every
//! syscall**. The number was real. What it priced was turning **758 direct
//! reads of `current` across 45 C files** into calls that cannot be inlined.
//!
//! By 2026-09-06 the C read it **once** — inside `task_self`, which no C called
//! either. The 758 were gone, and with them everything the measurement was
//! about. What was left was the mirror image: 57 Rust call sites paying a
//! cross-language call each, to reach a variable whose only other user was the
//! function they were calling.
//!
//! **Measured again, and it is neither.** Eight alternating rounds of
//! `syscall_bench` between the two binaries on a quiet machine, medians:
//! −0.9%, +0.9%, −0.2%, +1.2%, +2.2%, with `compute_bench` as the control
//! moving −0.6% by itself. The signs disagree and the sizes are the control's,
//! so there is no effect here to report in either direction. Removing 57
//! cross-language calls was expected to show up and did not — `task_self` was
//! four instructions under LTO and `_tlv_get_addr` is the part that costs,
//! which both shapes pay.
//!
//! So the reason to do it is not speed. It is that the C is gone, [`current`]
//! is a safe function, and the accessor is not a boundary any more.
//!
//! **The first touch still has to happen with `SIGUSR1` blocked.** On Darwin a
//! thread-local is allocated on first use, through `_tlv_get_addr`, which
//! `malloc`s — and `malloc` is not async-signal-safe. Rust's `thread_local!` is
//! the same mechanism as C's `__thread` here, so the constraint is unchanged
//! and so is what satisfies it: `crates/kernel/taskcalls`' `task_thread` calls
//! [`set_current`] before it unblocks the wake signal. The crash that made this
//! a rule came from a *signal handler* touching a thread-local first; the
//! handler has been an empty function since 2026-09-06.

#![deny(unsafe_op_in_unsafe_fn)]

/// The shared C ABI surface: what every other crate imports from here.
///
/// Nothing in it is generated. `abi.rs` holds the types the headers used to
/// define and the four sibling modules hold the ones this crate wrote by hand;
/// which file a name is in is a question about its history, not about how a
/// consumer names it, so they are one namespace.
/// The C ABI types, as one namespace.
///
/// Four crates own them now — `crates/kernel/abi` the guest wire formats,
/// `crates/util/synctypes` the mutex, `crates/emu/abi` the CPU, and this crate
/// `struct task` — and which file a name is in is a question about its history
/// rather than about how a consumer writes it. So they are one module and every
/// consumer still writes `taskview::ffi::task`.
pub mod ffi {
    pub use crate::task_types::*;
    pub use iul_abi::*;

    /// Which task, as a key. See [`iul_abi::Identity`].
    ///
    /// The alias is here rather than beside `MountId` because `struct task` is
    /// here: `Identity<T>` is generic in `crates/kernel/abi`, and a name for
    /// one instantiation belongs where its `T` is defined.
    pub type TaskId = Identity<task>;
    /// Which thread group, as a key. See [`iul_abi::Identity`].
    pub type TgroupId = Identity<tgroup>;
}

mod current_accessors;
mod task_accessors;
mod task_types;

pub use current_accessors::*;
/// The capability numbers [`capable`] takes.
pub use kernel_creds::caps;
pub use util_arcslot::ArcSlot;
pub use kernel_nsproxy as nsproxy;
pub use task_accessors::*;

// `current`, `set_current`, `task_self` and `current_pid` are the foundation's
// since 2026-09-09 -- see `crates/kernel/abi`'s comment on why -- and are
// re-exported so no consumer changed.
pub use task_types::{clear_current, current, current_pid, set_current, task_self, with_current_nsproxy, with_current_task};

// The wiring assertion for the cached signal-disposition reference. Exported
// rather than private because the thing it guards is `set_current`'s, and
// nothing outside this crate can see that the maintenance is still there --
// see `current.rs` and the test at the bottom of this file.
pub use task_types::current_sighand_is_held;

pub mod cpu;

// ---------------------------------------------------------------------------
// The signal questions, which are two field reads of the calling task
// ---------------------------------------------------------------------------
//
// The install point is [`bind_current`] below, which every guest thread calls
// before it can run and therefore before it can wait -- the same argument
// `sighand_new` used to make, one crate over.

/// Make `task` this thread's, and tell `crates/util/waitfor` how to ask whether
/// a signal should end a wait.
///
/// The hook install is here because this is the earliest moment a wait becomes
/// possible: a thread with no current task does not park on a guest condition.
/// It was `kernel-sighand`'s `sighand_new` until 2026-09-09, which is the same
/// point one crate over -- what moved is which crate can see both ends.
///
/// **[`set_current`] is the write without the hook**, for the boot transient
/// that rebinds a half-built task for one `generic_open`; [`clear_current`] is
/// how a thread on its way out says it is no longer running one.
///
/// # Safety
///
/// As [`set_current`]: `task` is live, or null.
pub unsafe fn bind_current(task: *mut ffi::task) {
    waitfor::set_signal_pending_hook(signal_pending);
    // SAFETY: the caller's contract.
    unsafe { set_current(task) };
}
//
// Both moved here from `crates/kernel/sighand` on 2026-09-09, and the move is
// what turned that crate's dependency on this one around. `signal_pending` is
// the hook `crates/util/waitfor` calls; it read `current()` and
// `(*task).sighand`, which is this crate's subject and was that crate's only
// reason to depend on it.

/// Whether a signal should interrupt a wait on `lock` — the hook
/// `crates/util/waitfor` calls, installed by [`bind_current`].
///
/// Three things it is worth saying about the shape.
///
/// **Why a hook and not a call.** `waitfor` is layer 0 and this is layer 3;
/// the edge genuinely runs both ways, because a wait has to ask whether a
/// signal is pending and delivering a signal has to end a wait. Cargo refuses
/// the cycle, and the answer this tree gives to that is the leaf crate holding
/// a hook the upper layer installs — `inotify::set_notify_hook` and
/// `kernel_pidfd::set_wake_hook` are the same pattern.
///
/// **Why it replaced three `extern "C"` declarations.** Those were the same
/// call resolved by the linker on name alone, so `waitfor` had to read
/// `task.sighand` and `task.signals` to make them — which is a layer-0 crate
/// needing the *definition* of `struct task`, and that is what pinned the type
/// to the foundation. The task fields are read here now, where the task layer
/// already is.
///
/// **The lock comparison.** A waiter that already holds *this* sighand's lock
/// must not take it again, so the queue is asked directly in that case; any
/// other lock means the sighand's own has to be acquired first.
fn signal_pending(lock: &ffi::lock_t) -> bool {
    // This thread's own reference to its table, not a load of the task's
    // `sighand` field: the group-exit valve empties that field from another
    // thread, and this runs inside `wait_for` holding arbitrary locks, so it
    // can take neither `pids_lock` nor `general_lock` to exclude it. See
    // `current_sighand`. It loaded both fields and called
    // `sigqueue_interrupts_a_wait` and `Queue::from_raw` itself until
    // 2026-10-16.
    //
    // SAFETY: `waitfor` calls this hook holding `lock`.
    with_current_queue(|queue| unsafe { queue.interrupts_a_wait_under(lock) }).unwrap_or(false)
        || ptrace_trap_pending()
}

/// `PTRACE_INTERRUPT`, or a seized task's first stop, ends a wait as a signal
/// does (Linux's `signal_wake_up` from `ptrace_trap_notify`); the syscall is
/// then restarted after the stop, since no handler ran.
/// Whether `PTRACE_INTERRUPT` has asked the calling thread for a trap.
pub fn current_ptrace_trap_pending() -> bool {
    ptrace_trap_pending()
}

fn ptrace_trap_pending() -> bool {
    with_current_ptrace(|p| p.trap_pending()).unwrap_or(false)
}

///
/// **Here rather than in `crates/kernel/taskcalls`, where it was.** It is two
/// field reads of the calling task and a call to
/// `Queue::deliverable` just below, and having it in the syscall crate made
/// four wait loops in the descriptor layer depend on the syscall layer --
/// `fs-poll` -> `kernel-taskcalls` -> `kernel-exitcalls` -> ... -> `fs-poll`
/// was one of the cycles that came out of it.
pub fn current_signal_pending() -> bool {
    with_current_queue(|queue| queue.deliverable()).unwrap_or(false) || ptrace_trap_pending()
}

#[cfg(test)]
mod tests {
    use super::*;

    /* `the_fields_this_crate_names_exist` was here until 2026-09-09: four
     * `assert!(offset_of!(ffi::task, <field>) > 0)`, written when `struct task`
     * was generated from `kernel/task.h` and the risk was a rename in the
     * header silently reading a neighbour.
     *
     * Both halves of that stopped being true. The struct is hand-written Rust
     * in `crates/kernel/abi`, so naming a field that does not exist is a
     * compile error and there is nothing for a test to catch — CLAUDE.md's
     * "a test that restates its subject". And it is `#[repr(Rust)]` as of the
     * same day, which makes `> 0` an assertion about whichever field the
     * compiler chose to put first: it passed, and it would have failed for a
     * reason that is not a defect. */

    /* `the_mount_refcount_counts_both_ways` was here until 2026-10-01, with
     * the three raw-pointer mount accessors it tested. `crates/fs/mounttable`
     * reads the fields through a `&mount` now. */

    /// `bind_current` installs the wait hook, and nothing else can catch it if
    /// it stops.
    ///
    /// The hook is invisible to an answer-checking test: with none installed
    /// `crates/util/waitfor` answers "no signal pending", and in a test binary
    /// — where there is no current task — the real hook answers "no signal
    /// pending" too. Delete the install and the whole suite stays green while a
    /// guest's blocking syscalls stop being interruptible.
    ///
    /// It lived in `crates/kernel/sighand` until 2026-09-09, installed from
    /// `sighand_new`. Same argument, one crate over: what moved is which crate
    /// can see both `waitfor` and the current task.
    #[test]
    fn binding_the_current_task_installs_the_wait_hook() {
        // SAFETY: null, which is the argument with no obligation.
        unsafe { bind_current(std::ptr::null_mut()) };
        assert!(waitfor::hooks_installed().0);
    }

    /// `set_current` takes the task's disposition table for this thread, and
    /// `set_current(null)` gives it back.
    ///
    /// **This cannot be tested by its answer**, which is the same objection the
    /// hook test above records, one level in. `signal_pending` answers "no
    /// signal pending" for a thread with no cached table *and* for a thread
    /// whose table has nothing queued, so deleting the maintenance in
    /// `set_current` leaves every test in the workspace green — and leaves a
    /// running guest with a thread that reads null for its dispositions the
    /// moment the group-exit valve empties the field, so a blocking syscall
    /// stops being interruptible and `rt_sigaction` starts answering as if the
    /// process had no handlers. The count is the observable, so the count is
    /// what this asserts.
    ///
    /// The strong count is the second half and is not decoration: a
    /// maintenance that stored the pointer without taking a reference would
    /// pass a presence check and is exactly the bug this design exists to
    /// avoid, because the whole point is that the thread **owns** one.
    #[test]
    fn binding_a_task_takes_a_reference_to_its_signal_dispositions() {
        let table = kernel_sighand::SigHand::new();
        // Storage, not a `task`: zero is not a valid value for every field
        // (the signal queue holds a `Vec`), and `set_current` reads only
        // `sighand`, which is written in place and emptied by hand at the end.
        let mut storage = std::mem::MaybeUninit::<ffi::task>::zeroed();
        let task = storage.as_mut_ptr();
        // SAFETY: an aligned field of this frame's storage; the zeroed bytes
        // there are an empty slot, which owns nothing to leak.
        unsafe { (*task).sighand.set(Some(std::sync::Arc::clone(&table))) };
        assert_eq!(std::sync::Arc::strong_count(&table), 2);

        // SAFETY: `task` is this frame's and outlives every use below.
        unsafe { set_current(task) };
        assert!(
            current_sighand_is_held(),
            "a bound thread holds its task's table"
        );
        assert_eq!(
            current_sighand(),
            std::sync::Arc::as_ptr(&table).cast_mut(),
            "and it is that task's, not some other"
        );
        assert_eq!(
            std::sync::Arc::strong_count(&table),
            3,
            "held, not merely pointed at"
        );

        clear_current();
        assert!(!current_sighand_is_held(), "unbinding gives it back");
        assert_eq!(std::sync::Arc::strong_count(&table), 2);

        // The task's own reference, which `task_destroy` would drop.
        // SAFETY: as above; the field holds the value written there.
        drop(unsafe { (*task).sighand.take() });
        assert_eq!(std::sync::Arc::strong_count(&table), 1);
    }
}
