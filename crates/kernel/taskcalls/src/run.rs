//! Guest task execution loop and deferred cleanup.

use super::*;

// ---------------------------------------------------------------------------
// Running one
// ---------------------------------------------------------------------------

/// Runs [`run_tlb_cleanup`] when this thread ends, however it ends.
///
/// # Why a thread-local and not `pthread_cleanup_push`
///
/// The guest loop does not return: it leaves through `pthread_exit`, from deep
/// inside `handle_interrupt`. On Darwin that terminates the thread **without
/// unwinding**, so every Rust frame below is abandoned and no `Drop` on the
/// stack runs — which is why `crates/kernel/exitcalls` drops its guards by hand
/// before exiting, and why a scope guard here would free nothing.
///
/// A thread-local's destructor is a different mechanism: it is a
/// `pthread_key_create` destructor, which POSIX runs on thread termination
/// **including** `pthread_exit`. Verified on this platform, both paths, before
/// this replaced the C: `tests/thread_exit_cleanup.rs`.
///
/// So `kernel/task.c`'s `task_run_with_cleanup` — which existed because
/// `pthread_cleanup_push` opens a brace and a crate cannot express a scope
/// spanning two macros — is a `Drop` impl, and the "body" is an ordinary call.
struct OnExit(*mut ffi::task_cleanup);

impl OnExit {
    /// Arm the cleanup for this thread.
    ///
    /// Overwrites any previous arming, which cannot happen: one guest task runs
    /// per host thread and `task_run_current` is its whole body.
    fn arm(cl: *mut ffi::task_cleanup) {
        ON_EXIT.with(|slot| *slot.borrow_mut() = Some(OnExit(cl)));
    }
}

impl Drop for OnExit {
    fn drop(&mut self) {
        unsafe { run_tlb_cleanup(self.0) };
    }
}

thread_local! {
    /// Not `const`-initialised, unlike `crates/kernel/taskview`'s `CURRENT`:
    /// this one *has* a destructor, which is the entire point, and a
    /// `const`-initialised non-`Drop` type is the case that has none.
    static ON_EXIT: std::cell::RefCell<Option<OnExit>> =
        const { std::cell::RefCell::new(None) };
}

/// What the cleanup frees, and what a stuck thread was handed.
///
/// Everything comes out of here rather than out of the task: see the module
/// comment.
///
/// # Safety
/// `cl` is the exiting thread's own cleanup record, and live.
unsafe fn run_tlb_cleanup(cl: *mut ffi::task_cleanup) {
    unsafe { emu_tlb::tlb_free((*cl).tlb) };

    // If the group-exit valve orphaned this thread -- stuck in an
    // uninterruptible host syscall -- it deferred these releases to here. This
    // runs only when the host pthread really terminates, so after the thread
    // has left the address space's read lock and after there is no syscall left
    // to be inside. That both avoids the use-after-free the valve's comment
    // describes and, unlike the old "accept the leak" path, reclaims the whole
    // guest address space.
    // Each is taken *out* rather than read: the valve on another thread wrote
    // it here under general_lock and may still be looking, and a thread that
    // unblocked instead reaches do_exit and releases the same pointer. An
    // exchange means exactly one of the two ends up with it.
    unsafe {
        drop((*cl).mm.take());
        // What the syscall this thread was stuck in had looked up. A
        // thread-local of its own, which may already have drained itself.
        fs_fdobj::syscall_refs_drain();
        drop((*cl).files.take());
        drop((*cl).fs.take());
        // The disposition table, since 2026-09-09. The valve released it in
        // place before that; see the note where it is handed over.
        drop((*cl).sighand.take());

        // Last, and after every release above: this is what tells a thread
        // waiting in do_exit_group that this host thread is really finished.
        // Doing it before the releases would let the waiter proceed while this
        // thread was still handing back an mm or a descriptor table.
        //
        // The handle is refcounted, so this is safe even when the group has
        // been freed -- which is exactly what happens to a thread the
        // group-exit valve gave up on and then stopped waiting for.
        if let Some(hosts) = (*cl).hosts.take() {
            hosts.finished();
        }
        // A `Box` since 2026-09-12, where it was `libc::free`. Every release
        // above is still by hand and has to be: each is an *exchange* against
        // a writer on another thread, and the order between them is what the
        // comments here are about. What the `Box` adds is the field nobody has
        // added yet — a handle with a destructor is run here rather than
        // leaked, which is the whole reason the allocation moved.
        drop(Box::from_raw(cl));
    }
    CLEANUPS.fetch_sub(1, Ordering::Relaxed);
}

/// How many cleanup structs are allocated, for `/proc/iul/objects`.
///
/// One per guest thread that reached the run loop, freed by that thread's own
/// `pthread_exit` handler — so this and `tlb` beside it are the pair that says
/// whether a host thread really finished unwinding.
static CLEANUPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many `struct task_cleanup` exist.
pub fn task_cleanup_live_count() -> usize {
    CLEANUPS.load(Ordering::Relaxed)
}

/// The guest loop: refresh the TLB, run until an interrupt, handle it.
///
/// Never returns — it leaves through `pthread_exit`, which is what runs
/// [`OnExit`]'s destructor.
///
/// It was an `extern "C" fn(*mut c_void)` until 2026-09-06 because
/// `kernel/task.c` called it through a function pointer, and the argument was
/// unused even then: the task comes from `current()`. Now that the caller is
/// Rust, the signature says what the function is — `-> !`, no parameters, no
/// C ABI, and the compiler checks the "never returns" the doc used to assert.
fn run_loop() -> ! {
    let cpu = taskview::current_cpu();
    let tlb = unsafe { (*(*current()).cleanup.load(Ordering::Relaxed)).tlb };
    loop {
        // Before entering the JIT, because this catches a thread returning from
        // a blocking host syscall -- futex, nanosleep -- that SIGUSR1 from
        // do_exit_group interrupted. And bail if this task's struct was
        // destroyed under us, which is what a leaked thread finds.
        if taskview::current_group().is_null() {
            // Exit the host thread silently; the handler frees the TLB.
            unsafe { libc::pthread_exit(std::ptr::null_mut()) };
        }
        // A group exit, or another thread's execve ending this one.
        if let Some(status) = taskview::current_must_leave() {
            (run_hooks().leave_group)(status as c_int);
        }
        // Not a cache lookup: this is **the "the valve gave up on me" flag**,
        // and it is why the read has to happen each time round the loop. The
        // group-exit valve takes a stuck sibling's address space away from
        // another thread, and a null here is this thread being told its task is
        // no longer running. It read `task.mem` until 2026-09-11, which was the
        // same word one indirection in.
        let mem = taskview::current_mem();
        if mem.is_null() {
            unsafe { libc::pthread_exit(std::ptr::null_mut()) };
        }
        let interrupt = unsafe {
            let _guard = pagetable::memlock::ReadGuard::new(mem);
            emu_tlb::tlb_refresh(tlb, &raw mut (*mem).mmu);
            asbestos_dispatch::cpu_run_to_interrupt(cpu, tlb)
        };
        unsafe { (run_hooks().handle_interrupt)(interrupt) };
    }
}

/// Run the calling thread's task until it exits.
///
/// # Safety
/// Called on a guest thread whose `current` is set.
pub unsafe fn task_run_current() {
    // This host thread starts with the architectural default FP control, and a
    // cloned task inherits its parent's. Tell the hardware which one it is.
    taskview::with_current_cpu(taskview::cpu::fp_sync_to_host);

    // `crates/emu/tlb` allocates its own since 2026-09-12: the free was already
    // there, and an allocation whose `free` is two crates away is how a field
    // with a destructor gets leaked with nothing to say so.
    let tlb = emu_tlb::tlb_new();
    // **Every field named**, where `libc::calloc` left five of the seven to the
    // zeroing until 2026-09-12. The five are the handover slots, and a null in
    // one means "the group-exit valve did not give me this" -- a decision, not
    // an accident, and the only one of the seven `calloc` got right by itself.
    // Naming them is what makes the compiler ask about the next field somebody
    // adds; `Box` is what makes its destructor run when the struct goes.
    //
    // `Box::new` aborts on allocation failure where `calloc` answered null, and
    // the null answer here was `die("could not allocate task cleanup")` --
    // which is an abort with a message. Nothing is lost and the message is,
    // which is why this is the one of the four that may use `Box::new`.
    let cl = Box::into_raw(Box::new(ffi::task_cleanup {
        tlb,
        // Moved, not copied: from here on it is the *handler* that gives the
        // count back, because that runs after the host pthread has finished
        // unwinding -- which is the event do_exit_group actually needs to wait
        // for, and the one a 50 ms sleep used to stand in for.
        hosts: taskview::ArcSlot::new(taskview::with_current_task(|t| t.hosts.take()).flatten()),
        mm: taskview::ArcSlot::empty(),
        files: taskview::ArcSlot::empty(),
        fs: taskview::ArcSlot::empty(),
        sighand: taskview::ArcSlot::empty(),
    }));
    CLEANUPS.fetch_add(1, Ordering::Relaxed);
    unsafe {
        (*current()).cleanup.store(cl, Ordering::Relaxed);
    }

    // The cleanup frees the TLB (and its fiber frame) even when the thread
    // exits through pthread_exit from deep inside handle_interrupt -- do_exit
    // after a native-offloaded execve, or the SIGKILL path. Without it every
    // guest process leaked about 304 KB of TLB and 48 KB of fiber frame, which
    // dominated app memory after repeated ffmpeg invocations.
    //
    // Arming it is a *store*, and the loop below is then an ordinary call. It
    // was `kernel/task.c`'s `task_run_with_cleanup` until 2026-09-06, wrapping
    // `pthread_cleanup_push`/`pop` -- see [`OnExit`] for why a thread-local
    // does the same job.
    OnExit::arm(cl);
    run_loop()
}
