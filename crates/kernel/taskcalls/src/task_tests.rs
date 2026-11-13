//! Tests for task lifecycle, wait, and interrupt helpers.

use std::ffi::c_void;
use std::sync::atomic::Ordering;
use super::*;
/// Creating a task installs the parking hook, and nothing else can catch it if
/// it stops.
///
/// The hook is invisible to an answer-checking test: with none installed
/// `crates/util/waitfor` records nothing when a thread parks, and a test
/// binary has no current task so the real one records nothing either. The
/// difference only shows in a running guest, where a thread parked on a
/// condition nobody wrote down cannot be woken by `task_wake_waiting` — a
/// hang, far from the deleted line. So this asserts the wiring.
#[test]
fn creating_a_task_installs_the_parking_hook() {
    install_parked_hook();
    assert!(waitfor::hooks_installed().1);
}

/// The platform guarantee [`OnExit`] rests on, and the reason it replaced
/// `pthread_cleanup_push`.
///
/// The guest loop leaves through `pthread_exit`, which on Darwin does
/// **not** unwind — so a scope guard's `Drop` never runs and the TLB would
/// leak. A thread-local's destructor is a `pthread_key_create` destructor
/// instead, which POSIX runs on thread termination including that path.
///
/// This asserts the mechanism rather than [`OnExit`] itself: the real one
/// frees a TLB and needs a whole task. What can be got wrong here is the
/// platform behaviour, and that is what is checked — on **both** exit
/// paths, because a test that only covered the normal return would pass
/// against a scope guard and prove nothing.
#[test]
fn a_thread_locals_destructor_runs_through_pthread_exit() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RAN: AtomicUsize = AtomicUsize::new(0);

    struct Probe;
    impl Drop for Probe {
        fn drop(&mut self) {
            RAN.fetch_add(1, Ordering::SeqCst);
        }
    }
    thread_local! {
        static SLOT: std::cell::RefCell<Option<Probe>> =
            const { std::cell::RefCell::new(None) };
    }

    // Leaves through pthread_exit from a nested call, as the guest loop
    // does from inside handle_interrupt.
    extern "C" fn exits(_: *mut c_void) -> *mut c_void {
        SLOT.with(|s| *s.borrow_mut() = Some(Probe));
        fn deep(n: u32) {
            if n == 0 {
                unsafe { libc::pthread_exit(std::ptr::null_mut()) };
            }
            deep(n - 1);
        }
        deep(4);
        unreachable!()
    }

    extern "C" fn returns(_: *mut c_void) -> *mut c_void {
        SLOT.with(|s| *s.borrow_mut() = Some(Probe));
        std::ptr::null_mut()
    }

    // A raw pthread, not `std::thread::spawn`: std notices a thread that
    // terminated behind its back and panics the joiner. `task_start` uses
    // `pthread_create` directly, which is the shape being modelled.
    fn run(f: extern "C" fn(*mut c_void) -> *mut c_void) {
        unsafe {
            let mut t: libc::pthread_t = std::mem::zeroed();
            assert_eq!(
                libc::pthread_create(&mut t, std::ptr::null(), f, std::ptr::null_mut()),
                0
            );
            assert_eq!(libc::pthread_join(t, std::ptr::null_mut()), 0);
        }
    }

    run(exits);
    assert_eq!(
        RAN.load(Ordering::SeqCst),
        1,
        "a thread-local destructor must run when the thread leaves through \
         pthread_exit -- this is what OnExit replaced pthread_cleanup_push with"
    );
    run(returns);
    assert_eq!(RAN.load(Ordering::SeqCst), 2, "and on a normal return too");
}

// `a_negative_errno_survives_the_round_trip_through_a_pointer` was here until
// 2026-09-14. It asserted `(p as usize) > usize::MAX - 0xfff` -- which was
// itself a sixth rendering of the predicate, and the one that disagreed with
// `iul.h` by a value. The convention is `crates/kernel/abi`'s `err_ptr` module
// now and its own tests assert the boundary from both sides.

/// The one field where `calloc`'s zero was not the value anybody had chosen.
///
/// The first process's task was `libc::calloc` until 2026-09-12 and
/// [`lifecycle::blank_task`] names every field now. Of the nineteen that the
/// zeroing used to decide, eighteen were decisions — a null pointer, an absent
/// setting, a value the caller fills in — and `attr` was not: a zeroed
/// `ThreadAttr` is an **empty** capability bounding set against
/// `CAP_BSET_FULL`, and zero timer slack against 50 µs.
///
/// Nothing was ever wrong, because `crates/kernel/boot`'s `construct_task`
/// calls `ThreadAttr::init` immediately afterwards — for a second reason,
/// which is that `become_new_init_child` passes a real parent and the fork arm
/// would otherwise leave the child with init's attributes. That call stays.
/// What this asserts is that the parentless arm no longer depends on it.
#[test]
fn a_fresh_tasks_attributes_are_not_the_zeroed_ones() {
    let mut task = lifecycle::blank_task();
    let fresh = *task.attr.get_mut();
    assert_eq!(fresh, ffi::thread_attr::default());
    assert_ne!(
        fresh,
        unsafe { std::mem::zeroed::<ffi::thread_attr>() },
        "a zeroed ThreadAttr is an empty capability bounding set; if these are \
         equal, ThreadAttr::default() has stopped deciding anything and this \
         test is checking nothing"
    );
}

/// `struct task` owns something, and both ways of building one say so.
///
/// This asserted `!needs_drop::<task>()` until 2026-09-12, as a tripwire for
/// the day a field owned something while the fork arm was a byte copy; then
/// `task.sighand` became an `Arc` and two source-reading gates stood in for
/// it. Since 2026-09-30 neither arm copies bytes -- [`lifecycle::forked_task`]
/// is a struct literal -- so what is left to say about the parentless arm is
/// that it owns nothing, and the fork arm has its own test below.
#[test]
fn the_parentless_arm_owns_nothing_and_the_fork_arm_is_the_only_question() {
    // The mechanism, before the example -- `needs_drop` answering false for
    // everything would make the assertions below vacuous, and this is the
    // cheapest thing that says it does not.
    assert!(std::mem::needs_drop::<Box<u8>>());
    assert!(
        std::mem::needs_drop::<ffi::task>(),
        "no field of `struct task` owns anything any more. If that is on \
         purpose `forked_task`'s clone of `sighand` is a copy of a pointer; \
         if it is not, a field lost its `Arc`."
    );
    assert!(
        lifecycle::blank_task().sighand.as_ptr().is_null(),
        "the first process's task claims a reference it was never given"
    );
}

/// A fork takes a counted share of the parent's signal handle, and none of the
/// parent's other owned fields.
///
/// The byte copy this replaced duplicated each `Arc` without its count, and
/// the four `ptr::write`s after it were the whole defence; this was only
/// checkable by reading until the child became a literal. Backed out -- the
/// `sighand` line as `std::ptr::read(&raw const (*parent).sighand)` -- the
/// count assertion fails at 1, and the drop at the end is the double free.
#[test]
fn a_fork_counts_the_signal_handle_and_takes_nothing_else_it_owns() {
    let mut parent = lifecycle::blank_task();
    let hand = kernel_sighand::SigHand::new();
    parent.sighand.set(Some(hand.clone()));
    parent.vfork.set(Some(kernel_vforkhandoff::Handoff::new()));
    assert!(!parent.vfork.as_ptr().is_null());
    parent.pid = 7.into();
    parent.tgid = 7.into();

    // SAFETY: `parent` is this test's and nothing else can reach it.
    let child = unsafe { lifecycle::forked_task(&parent) };
    assert_eq!(std::sync::Arc::strong_count(&hand), 3, "the test's, the parent's, the child's");
    assert!(child.hosts.as_ptr().is_null() && child.ptrace.is_none() && child.vfork.as_ptr().is_null());
    assert_eq!((child.pid(), child.tgid.load(Ordering::Relaxed)), (0, 7), "a pid is task_create_'s; tgid copy_task's");

    drop(child);
    assert_eq!(std::sync::Arc::strong_count(&hand), 2, "the child gave its own back");
    drop(parent);
    assert_eq!(std::sync::Arc::strong_count(&hand), 1);
}

#[test]
fn the_deferred_list_is_the_size_the_c_had() {
    // One round of delay for 64 concurrent exits; past that a struct is
    // freed immediately, which is the rare case the C named.
    assert_eq!(DEFERRED_MAX, 64);
}
