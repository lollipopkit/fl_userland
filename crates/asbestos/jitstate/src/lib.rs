//! What a crash handler needs to know about the thread it interrupted.
//!
//! Three facts, all per-thread: whether this thread is inside JIT-compiled
//! code, which block it entered, and whether it is a guest thread at all
//! rather than an embedder's own.
//!
//! # Why this is not `thread_local!`
//!
//! `asbestos/asbestos.c` held these as three `__thread` variables plus two
//! functions returning their addresses, and the blocker written beside them
//! was precise:
//!
//! > **The reason is the address, not the initialisation.** […] `__thread`
//! > gives a **stable address** and `LocalKey` deliberately does not: its
//! > reference is only promised for the closure body. This design needs the
//! > address — `crates/asbestos/dispatch` takes both **once per quantum**
//! > rather than calling in per block […] A `LocalKey` cannot promise that
//! > pointer outlives the `with`.
//!
//! That is right, and it rules out one mechanism rather than the goal. A
//! **`pthread_key_create` destructor slot** gives a per-thread pointer to
//! storage this crate allocated, so the address is as stable as any heap
//! allocation — and `pthread_getspecific` is on POSIX's async-signal-safe
//! list, which is the property a crash handler actually needs and which
//! `_tlv_get_addr` does *not* have (it `malloc`s on first touch; `util/sync.c`
//! records the crash).
//!
//! # One slot replaces three variables
//!
//! `iul_thread_marker` existed so the handler could tell a guest thread from
//! an embedder's. A thread with no slot is exactly that thread, so
//! [`current`] answering null is the same answer with nothing extra stored.
//!
//! # The handler allocates nothing
//!
//! [`install`] is called by the dispatch loop before it enters a block, which
//! is ordinary context. [`current`] is what the handler calls, and it only
//! reads.

use std::sync::OnceLock;

/// The per-thread facts, in the order the handler reads them.
///
/// `#[repr(C)]` because a crash handler walks it with the machine in an
/// unusual state and a stable layout is one less thing to reason about.
#[repr(C)]
pub struct JitState {
    /// Non-zero while `fiber_enter` is on this thread's stack. A fault then is
    /// the *guest's*, and the handler redirects to the trampoline rather than
    /// the emulator `_setjmp`ing on every block entry.
    pub in_jit: std::sync::atomic::AtomicI32,
    /// The guest PC the current block starts at, which the handler restores
    /// so the block is re-executed after the fault is turned into a guest
    /// signal.
    pub saved_pc: std::sync::atomic::AtomicU64,
}

impl JitState {
    const fn new() -> JitState {
        JitState {
            in_jit: std::sync::atomic::AtomicI32::new(0),
            saved_pc: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

/// The key, created once.
///
/// [`current`] reads [`KEY`] directly rather than calling this, because a
/// signal handler must not run `pthread_key_create`.
fn key() -> libc::pthread_key_t {
    *KEY.get_or_init(|| {
        let mut k: libc::pthread_key_t = 0;
        // A destructor, so a thread that ends gives its slot back. It runs on
        // `pthread_exit` too, which is how a guest thread normally leaves —
        // see `crates/kernel/taskcalls`' `OnExit`.
        // SAFETY: `k` is a valid out-parameter.
        let rc = unsafe { libc::pthread_key_create(&mut k, Some(free_slot)) };
        assert_eq!(rc, 0, "pthread_key_create for the JIT crash state failed");
        k
    })
}

/// Give a departed thread's slot back.
///
/// # Safety
/// Called by pthreads with the value this thread's slot held.
unsafe extern "C" fn free_slot(p: *mut libc::c_void) {
    if !p.is_null() {
        // SAFETY: the only thing ever put in the slot is this Box.
        drop(unsafe { Box::from_raw(p.cast::<JitState>()) });
    }
}

/// This thread's state, creating it if this is the first call.
///
/// **Not for a signal handler** — it allocates. The dispatch loop calls it
/// once per quantum, which is ordinary context; a handler calls [`current`].
pub fn install() -> *mut JitState {
    let k = key();
    // SAFETY: `k` came from `pthread_key_create`.
    let existing = unsafe { libc::pthread_getspecific(k) };
    if !existing.is_null() {
        return existing.cast();
    }
    let fresh = Box::into_raw(Box::new(JitState::new()));
    // SAFETY: `k` is this crate's key and `fresh` outlives the thread, or is
    // freed by `free_slot`.
    if unsafe { libc::pthread_setspecific(k, fresh.cast()) } != 0 {
        // Nothing sensible to do but not leak: without a slot the handler
        // treats this thread as an embedder's, which is the safe answer.
        // SAFETY: just allocated here and not stored anywhere.
        drop(unsafe { Box::from_raw(fresh) });
        return std::ptr::null_mut();
    }
    fresh
}

/// This thread's state, or null if it has none.
///
/// **Async-signal-safe**: `pthread_getspecific` is on POSIX's list and this
/// does nothing else. Null means the thread never entered the dispatch loop —
/// an embedder's own thread — which is what `iul_thread_marker` was for.
pub fn current() -> *mut JitState {
    let k = match KEY.get() {
        // Reading the key without creating one: a handler must not run
        // `pthread_key_create`, and a thread that has a slot proves the key
        // exists already.
        Some(k) => *k,
        None => return std::ptr::null_mut(),
    };
    // SAFETY: `k` came from `pthread_key_create`.
    unsafe { libc::pthread_getspecific(k) }.cast()
}

/// The key, filled by [`key`] on the first [`install`].
///
/// A module-level `static` rather than one inside `key()` so that [`current`]
/// can *read* it without the `get_or_init` that would create one — the
/// difference between a signal-safe read and a call that allocates.
static KEY: OnceLock<libc::pthread_key_t> = OnceLock::new();

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn a_thread_that_never_installed_has_no_state() {
        let seen = std::thread::spawn(|| current().is_null()).join().unwrap();
        assert!(seen, "an embedder's own thread must look like one");
    }

    #[test]
    fn install_is_idempotent_and_current_finds_it() {
        std::thread::spawn(|| {
            let a = install();
            assert!(!a.is_null());
            let b = install();
            assert_eq!(a, b, "a second install must not replace the slot");
            assert_eq!(current(), a, "current must find what install made");
        })
        .join()
        .unwrap();
    }

    /// The address has to survive being kept — that is the whole reason this
    /// is not a `thread_local!`.
    #[test]
    fn the_address_survives_being_kept() {
        std::thread::spawn(|| {
            let p = install();
            // Keep it across unrelated work, as the dispatch loop keeps it
            // across a whole quantum of block executions.
            let mut sink = 0u64;
            for i in 0..1000u64 {
                sink = sink.wrapping_add(i);
            }
            std::hint::black_box(sink);
            assert_eq!(current(), p);
            // SAFETY: `p` is this thread's slot and still live.
            unsafe { (*p).saved_pc.store(0xdead_beef, Ordering::Relaxed) };
            assert_eq!(
                unsafe { (*current()).saved_pc.load(Ordering::Relaxed) },
                0xdead_beef
            );
        })
        .join()
        .unwrap();
    }

    /// Two threads must not see each other's.
    #[test]
    fn each_thread_has_its_own() {
        let handles: Vec<_> = (1..=4u64)
            .map(|n| {
                std::thread::spawn(move || {
                    let p = install();
                    unsafe { (*p).saved_pc.store(n, Ordering::Relaxed) };
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    unsafe { (*p).saved_pc.load(Ordering::Relaxed) }
                })
            })
            .collect();
        let mut got: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        got.sort_unstable();
        assert_eq!(got, vec![1, 2, 3, 4]);
    }
}
