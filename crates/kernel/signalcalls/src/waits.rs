//! Signal wait syscall helpers.

use super::*;

// ---------------------------------------------------------------------------
// The waits
//
// All three park on sighand's lock, which is why they could not be one-question
// entry points on `SigHand` and had to wait for the guard to be reachable from
// Rust. `SigHandGuard::wait` releases the lock while parked, so the queue is
// re-read on every pass.
// ---------------------------------------------------------------------------

/// `pause(2)`: wait until a signal arrives that this thread must act on.
///
/// Always `EINTR`. There is no other way out — a `pause` no signal reaches
/// waits for ever, which is the call's whole definition.
pub fn pause(sh: &SigHand) -> c_int {
    let mut guard = sh.lock();
    // A loop, because a wakeup is not an answer. Anything that notifies the
    // condition this thread happens to be parked on returns `Notified`, and a
    // signal the thread is *waiting for* rather than interrupted by — a
    // `sigtimedwait` set, a `signalfd` mask — wakes it without qualifying.
    while guard.wait(None) != Woke::Interrupted {}
    EINTR
}

/// `rt_sigsuspend(2)`: swap the mask, wait, and let `receive_signals` put the
/// old one back.
///
/// The restore is deliberately *not* here. A handler has to run with the
/// temporary mask in place — that is what the call is for — and it runs from
/// the interrupt path, after this returns. `Signals::save_mask` records the old
/// one and the delivery path takes it back with `take_saved_mask`.
pub fn rt_sigsuspend<M: usercopy::GuestIo>(
    queue: Queue<'_>,
    mem: &M,
    mask_addr: u64,
    size: u64,
) -> c_int {
    let mask = match read_sigset(mem, mask_addr, size) {
        Ok(m) => m,
        Err(e) => return e,
    };
    let mut guard = queue.lock();
    let queue = guard.queue_mut();
    queue.save_mask();
    queue.set_blocked(kernel_sigdisp::maskable(mask));
    while guard.wait(None) != Woke::Interrupted {}
    EINTR
}

/// `rt_sigtimedwait(2)`: take a signal off the queue, waiting for one if the
/// set is empty.
///
/// Returns the signal number, or a negative errno: `EAGAIN` for the timeout,
/// `EINTR` for a signal that was not in the set.
pub fn rt_sigtimedwait<M: usercopy::GuestIo>(
    queue: Queue<'_>,
    mem: &M,
    set_addr: u64,
    info_addr: u64,
    timeout: Option<Duration>,
    set_size: u64,
) -> c_int {
    let set = match read_sigset(mem, set_addr, set_size) {
        Ok(s) => s,
        Err(e) => return e,
    };
    // SIGKILL and SIGSTOP cannot be waited for. Taking one off the queue is
    // what consumes it, so a thread naming them here would swallow its own kill
    // and could not be stopped or killed at all. Linux drops them silently, and
    // `signalfd` does the same for the same reason.
    let set = kernel_sigdisp::maskable(set);

    // A deadline, not a duration. A wakeup does not mean anything arrived, and
    // re-arming the full timeout on each pass made the call wait arbitrarily
    // longer than it was asked to.
    let deadline = timeout.map(|t| Instant::now() + t);

    let mut guard = queue.lock();
    // Saved and restored rather than asserted to be zero: a handler running on
    // this thread while the wait is interrupted can call `sigwaitinfo` again,
    // and the assert this replaces turned that into an abort.
    let saved_waiting = guard.queue().waiting();
    guard.queue_mut().set_waiting(saved_waiting | set);

    let mut found;
    let mut timed_out = false;
    loop {
        // Checked before the first wait as well: this is the path a signal that
        // arrived *before* the call takes, and no amount of waiting will
        // announce it again.
        found = {
            let (own, shared) = guard.both_mut();
            own.dequeue_either(set, shared)
        };
        if found.is_some() {
            break;
        }
        let remaining = match deadline {
            Some(d) => match d.checked_duration_since(Instant::now()) {
                Some(left) if !left.is_zero() => Some(left),
                _ => {
                    timed_out = true;
                    break;
                }
            },
            None => None,
        };
        match guard.wait(remaining) {
            Woke::Notified => continue,
            Woke::TimedOut => {
                timed_out = true;
                break;
            }
            // One more look before giving up: the signal that interrupted the
            // wait may be the one asked for.
            Woke::Interrupted => {
                found = {
                    let (own, shared) = guard.both_mut();
                    own.dequeue_either(set, shared)
                };
                break;
            }
        }
    }

    guard.queue_mut().set_waiting(saved_waiting);
    let Some(info) = found else {
        return if timed_out { EAGAIN } else { EINTR };
    };
    // The signal is off the queue by now, so nothing above may return early:
    // dropping the lock and then failing the copy loses it. Linux has the same
    // shape and the same answer — the signal is consumed and EFAULT reported.
    drop(guard);

    if info_addr != 0 && mem.write(info_addr, kernel_sigqueue::as_bytes(&info)) != 0 {
        return EFAULT;
    }
    info.sig
}

/* The six `signalcalls_*` entry points were here until 2026-09-09: one per
 * syscall, each doing `&*(sh as *const SigHand)`, `&GuestMem::current()` and a
 * call to the function a few hundred lines above.
 *
 * They existed because the `sys_*` wrappers were in `crates/kernel/signaldeliver`
 * and had to reach across a crate boundary. Those wrappers are in this file
 * now, so the facade was a same-crate indirection, and the test that drove it
 * (`the_c_entry_points_reach_the_same_code`) only passed because a
 * `#[no_mangle] user_read` double intercepted `GuestMem`. Folding it into the
 * six callers deleted the layer and the duplicate symbol together. */
