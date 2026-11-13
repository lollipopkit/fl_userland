//! `signalfd`'s blocking read.
//!
//! The record format is `crates/kernel/signalfd`. What is here is the part that
//! belongs to the *task* — the queue, the lock, and the wait — because a
//! signalfd reports the **reading thread's** pending signals and its
//! process's, rather than the creating one's, and so has no state of its own
//! beyond the mask.
//!
//! It moved *out of C* because of the wait. It used to be the second caller of
//! the raw lock escape hatch in `crates/kernel/sighand`, which was needed by a
//! caller that holds the lock across more than one operation. The reason was
//! exactly this loop: park, wake, re-read. `SigHandGuard::wait` expresses that,
//! so the lock identity check now lives in `SigHand::owns_lock`.
//!
//! It moved *here*, from `crates/kernel/signalcalls`, on 2026-09-09, and that
//! was a layering fix rather than a tidy-up. This module was the only thing
//! `crates/kernel/signalfdcalls` needed from `signalcalls`, and that one edge
//! was half of a cycle — `signaldeliver` calls this crate's `signalfd_notify`
//! for every signal that becomes pending. Cargo reported it the moment the
//! `signalcalls` ↔ `signaldeliver` C ABI declaration became a Rust call, which
//! is `CLAUDE.md`'s point about a C ABI call needing no dependency edge: the
//! graph that would have reported this never saw it.
//!
//! The `signalcalls_signalfd_read` facade went with the move — it took `sh` as
//! `*mut c_void` and cast it back, which is what a call across a crate boundary
//! used to cost. `signalfd_read` calls [`read`] with a `&SigHand`.

use std::sync::atomic::{AtomicU64, Ordering};

use kernel_sighand::{Queue, Woke};

use guest_errno::c_int_::{EAGAIN, EINTR, EINVAL};

/// One `signalfd_siginfo`.
const RECORD: usize = kernel_signalfd::RECORD_BYTES;

/// Fill `out` with as many records as fit, waiting for the first.
///
/// `out` is the kernel's own buffer, not guest memory: `fd_ops.read` is handed
/// one and the VFS copies it out. Returns bytes written, or a negative errno.
///
/// It was `unsafe` from 2026-09-06 -- `clippy::not_unsafe_ptr_arg_deref`
/// caught it dereferencing whatever address it was handed -- until
/// 2026-09-30, when the queue became a [`Queue`], which carries that
/// obligation from where it is made.
pub fn read(
    queue: Queue<'_>,
    mask: &AtomicU64,
    nonblock: bool,
    out: &mut [u8],
) -> isize {
    if out.len() < RECORD {
        return EINVAL as isize;
    }
    let room = out.len() / RECORD;

    let mut guard = queue.lock();

    // Naming the mask in `waiting` is what makes a *blocked* signal wake this
    // thread: the delivery path tests `blocked & ~waiting`, so a signal named
    // here counts as one worth announcing. Saved and restored rather than
    // assigned, because `sigtimedwait` uses the same field and a handler can
    // nest the two.
    let saved_waiting = guard.queue().waiting();
    guard.queue_mut().set_waiting(saved_waiting | mask.load(Ordering::Relaxed));

    let mut n = 0usize;
    let mut err = 0;
    let mut interrupted = false;
    loop {
        // Reloaded on every pass: `signalfd4` can retarget the descriptor while
        // this read is parked, which is why the field is atomic.
        let want = mask.load(Ordering::Relaxed);
        while n < room {
            // The reading thread's own, then its process's: Linux's
            // `signalfd_dequeue` is `dequeue_signal`.
            let (own, shared) = guard.both_mut();
            let Some(info) = own.dequeue_either(want, shared) else {
                break;
            };
            let record = kernel_signalfd::describe(kernel_sigqueue::as_bytes(&info));
            kernel_signalfd::encode(&mut out[n * RECORD..(n + 1) * RECORD], &record);
            n += 1;
        }
        if n > 0 {
            break;
        }
        // Tested *after* the dequeue, which is the order Linux has: the signal
        // that interrupted the wait may itself be one this descriptor reports,
        // and answering EINTR with it sitting in the queue makes a read that
        // had an answer report that it did not.
        if interrupted {
            err = EINTR;
            break;
        }
        if nonblock {
            err = EAGAIN;
            break;
        }
        // Widened again with the reloaded mask, for the same reason it was
        // widened above.
        let waiting = guard.queue().waiting();
        guard.queue_mut().set_waiting(waiting | want);
        // A timeout cannot happen with no deadline; a notify means look again.
        interrupted = guard.wait(None) == Woke::Interrupted;
    }

    guard.queue_mut().set_waiting(saved_waiting);
    drop(guard);

    if n > 0 {
        (n * RECORD) as isize
    } else if err != 0 {
        err as isize
    } else {
        EAGAIN as isize
    }
}
