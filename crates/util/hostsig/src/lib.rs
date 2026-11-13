//! The calling thread's host signal mask, and the process's host handlers.
//!
//! Three crates changed the mask, each building a `sigset_t` from `mem::zeroed` and
//! two libc calls and then calling `pthread_sigmask`, every step in `unsafe`.
//! None of it touches memory but the set on the stack and the calling thread's
//! own mask, so it is safe here, once. All of it is async-signal-safe, which
//! the crash handler relies on.
//!
//! Three more installed handlers, each with a `mem::zeroed` `sigaction` and
//! `sa_sigaction = f as *const () as usize`. That cast erases the handler's
//! type: a missing `extern "C"` and an `SA_SIGINFO` that disagrees with the
//! handler's arity both compiled and failed only when a signal arrived.
//! [`Handler`] keeps the type, and [`install`] derives `SA_SIGINFO` from it.

use std::ffi::{c_int, c_void};

/// The set holding exactly `signals`.
pub fn set_of(signals: &[c_int]) -> libc::sigset_t {
    let mut set: libc::sigset_t = 0;
    // SAFETY: `set` is a local `sigset_t`.
    unsafe {
        libc::sigemptyset(&mut set);
        for &s in signals {
            libc::sigaddset(&mut set, s);
        }
    }
    set
}

fn change(how: c_int, set: &libc::sigset_t) -> libc::sigset_t {
    let mut old: libc::sigset_t = 0;
    // SAFETY: both are local sets; this changes the calling thread's mask only.
    unsafe { libc::pthread_sigmask(how, set, &mut old) };
    old
}

/// Block `signals` in this thread, answering the mask it had.
pub fn block(signals: &[c_int]) -> libc::sigset_t {
    change(libc::SIG_BLOCK, &set_of(signals))
}

/// Unblock `signals` in this thread.
pub fn unblock(signals: &[c_int]) {
    change(libc::SIG_UNBLOCK, &set_of(signals));
}

/// Put back a mask [`block`] answered.
pub fn restore(old: &libc::sigset_t) {
    change(libc::SIG_SETMASK, old);
}

/// A host signal handler, typed so the convention and arity are checked.
#[derive(Clone, Copy)]
pub enum Handler {
    Plain(extern "C" fn(c_int)),
    /// Installed with `SA_SIGINFO`.
    Info(unsafe extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void)),
}

/// Run `handler` for each of `signals`, with `mask` blocked while it runs,
/// on the alternate stack if `on_stack`.
///
/// # Safety
/// `handler` may run at any instruction of any thread: it must be
/// async-signal-safe, or end the process without returning to the code it
/// interrupted.
pub unsafe fn install(signals: &[c_int], handler: Handler, mask: &[c_int], on_stack: bool) {
    let (addr, info) = match handler {
        Handler::Plain(f) => (f as usize, 0),
        Handler::Info(f) => (f as usize, libc::SA_SIGINFO),
    };
    let sa = libc::sigaction {
        sa_sigaction: addr,
        sa_mask: set_of(mask),
        sa_flags: info | if on_stack { libc::SA_ONSTACK } else { 0 },
    };
    for &sig in signals {
        // SAFETY: `sa` is a complete local action; the handler's contract is
        // the caller's.
        unsafe { libc::sigaction(sig, &sa, std::ptr::null_mut()) };
    }
}

/// Ignore `sig` in the whole process.
pub fn ignore(sig: c_int) {
    // SAFETY: `SIG_IGN` runs no code.
    unsafe { libc::signal(sig, libc::SIG_IGN) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(sig: c_int) -> bool {
        let now = block(&[]);
        // SAFETY: a local set.
        unsafe { libc::sigismember(&now, sig) == 1 }
    }

    /// Block, see it blocked, restore, see it not; and unblock undoes a block.
    #[test]
    fn a_block_is_undone_by_restoring_or_unblocking() {
        std::thread::spawn(|| {
            assert!(!blocked(libc::SIGUSR2));
            let old = block(&[libc::SIGUSR2, libc::SIGHUP]);
            assert!(blocked(libc::SIGUSR2) && blocked(libc::SIGHUP));
            restore(&old);
            assert!(!blocked(libc::SIGUSR2) && !blocked(libc::SIGHUP));
            block(&[libc::SIGUSR2]);
            unblock(&[libc::SIGUSR2]);
            assert!(!blocked(libc::SIGUSR2));
        })
        .join()
        .unwrap();
    }

    static SEEN: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

    extern "C" fn plain(sig: c_int) {
        SEEN.store(sig, std::sync::atomic::Ordering::SeqCst);
    }

    extern "C" fn info(_: c_int, si: *mut libc::siginfo_t, _: *mut c_void) {
        // SAFETY: the kernel's argument to an `SA_SIGINFO` handler.
        SEEN.store(unsafe { (*si).si_signo }, std::sync::atomic::Ordering::SeqCst);
    }

    fn flags(sig: c_int) -> c_int {
        let mut old = std::mem::MaybeUninit::<libc::sigaction>::uninit();
        // SAFETY: a query; `old` is filled on success.
        assert_eq!(unsafe { libc::sigaction(sig, std::ptr::null(), old.as_mut_ptr()) }, 0);
        // SAFETY: filled above.
        unsafe { old.assume_init() }.sa_flags
    }

    /// Both kinds run, and the flags follow the kind: Darwin's trampoline
    /// passes a `siginfo_t` either way, so only the flag shows a mismatch.
    /// One test, since handlers are process-wide.
    #[test]
    fn install_runs_each_kind_of_handler() {
        use std::sync::atomic::Ordering::SeqCst;
        // SAFETY: both handlers store one atomic.
        unsafe { install(&[libc::SIGUSR1], Handler::Info(info), &[], true) };
        assert_eq!(flags(libc::SIGUSR1), libc::SA_SIGINFO | libc::SA_ONSTACK);
        // SAFETY: a handler is installed.
        unsafe { libc::raise(libc::SIGUSR1) };
        assert_eq!(SEEN.swap(0, SeqCst), libc::SIGUSR1, "siginfo carries the signal");
        // SAFETY: as above.
        unsafe { install(&[libc::SIGUSR1], Handler::Plain(plain), &[], false) };
        assert_eq!(flags(libc::SIGUSR1), 0);
        // SAFETY: as above.
        unsafe { libc::raise(libc::SIGUSR1) };
        assert_eq!(SEEN.swap(0, SeqCst), libc::SIGUSR1);
    }
}
