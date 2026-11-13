//! `signalfd4`, and the descriptor it hands out.
//!
//! A descriptor that becomes readable when a signal in its mask is pending, and
//! yields one 128-byte record per signal when read. It is the only way to fold
//! signal delivery into a poll loop, which is why libevent, glib and systemd all
//! reach for it, and why it was the largest remaining gap in the syscall table:
//! without it a program either writes a self-pipe from a handler or does not
//! integrate signals at all.
//!
//! The shape a caller uses is: block the signals, then create a signalfd for
//! them. A blocked signal stays pending instead of being delivered, and reading
//! the descriptor is what consumes it — so no handler runs and the event arrives
//! through `poll` like any other. Two things elsewhere exist for that to work:
//! `send_signal` keeps a blocked signal pending even when its disposition says
//! ignore (`SIGCHLD`'s default, and the single most common thing to watch this
//! way), and `deliver_signal_unlocked` wakes a thread for a blocked signal that
//! some signalfd of its is watching.
//!
//! # It answers for the reading task
//!
//! Not the creating one. That is Linux's rule too, and it is why there is no
//! task pointer on the descriptor: a signalfd inherited across `fork` answers
//! for the child. All the descriptor holds is the mask.
//!
//! The record layout and the `siginfo` union rule that fills it are
//! `crates/kernel/signalfd`; the blocking read is `crates/kernel/signalcalls`,
//! because it parks on sighand's lock and rechecks, which no one-question entry
//! point can express.


use std::ffi::c_int;
use std::sync::Weak;
use std::sync::atomic::{AtomicU64, Ordering};

use guest_errno::Errno;
use kernel_signalfd as signalfd;
use strace::strace;
use usercopy::GuestMem;

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/// `signalfd`'s blocking read, which was `crates/kernel/signalcalls`'s until
/// 2026-09-09. See its module comment for why it moved.
mod read;
#[cfg(test)]
mod read_tests;

// ---------------------------------------------------------------------------
// Which descriptions to wake when a signal arrives
// ---------------------------------------------------------------------------
//
// Linux's `signalfd_notify`, called from `__send_signal`: a signal that becomes
// pending has to make every `signalfd` watching it *readable*, which means
// waking that description's pollers. Without it a thread already blocked in
// `poll()` still worked -- `send_signal` wakes the thread and the loop
// re-polls -- and `epoll_wait` did not, because an epoll set is woken by a
// description telling its watchers, and nothing told them.
//
// That is not a corner: `signalfd` exists to be put in an event loop, and an
// event loop here means epoll. PostgreSQL 18 hangs on it -- `SetLatch` is
// `kill(pid, SIGURG)` with SIGURG blocked and read through a signalfd, so a
// backend waiting for an IO worker waited for ever and answered "canceling
// authentication due to timeout". systemd, libevent and glib use the same
// shape.
//
// **Every signalfd is woken, not the target process's.** Linux keeps the list
// on the `sighand` and wakes that one; a description here holds no task by
// design -- it answers for whoever reads it, which is what makes one inherited
// across `fork` answer for the child -- so there is nothing to filter on. The
// cost of the difference is a poller in another process waking, asking
// `signalfd_poll`, being told nothing is pending and sleeping again. The mask
// is still checked, so a signalfd watching other signals is not disturbed.

/// The live signalfd descriptions.
///
/// Weak, and upgraded under the lock by whoever wakes them, since 2026-10-17.
/// They were `ffi::FdId`s borrowed back into descriptions after the lock was
/// released, on the argument that a close "cannot have run since without
/// taking it" -- but nothing held the lock across the wakeup, so a close on
/// another thread freed a description `signalfd_notify` was about to wake.
/// `tests/guest/src/bin/signalfd_close_race.rs` is the reproduction.
static SIGNALFDS: std::sync::Mutex<Vec<Weak<ffi::fd>>> = std::sync::Mutex::new(Vec::new());

fn with_registry<R>(f: impl FnOnce(&mut Vec<Weak<ffi::fd>>) -> R) -> R {
    let mut guard = SIGNALFDS.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

/// A signal has been made pending somewhere. Wake every signalfd watching it.
///
/// Called from `crates/kernel/signaldeliver` with no sighand lock held:
/// `poll_wakeup` reaches an epoll set's own state, and the order is the
/// description's watcher list first.
///
pub fn signalfd_notify(sig: c_int) {
    if sig <= 0 || sig > 64 {
        return;
    }
    let bit = 1u64 << (sig - 1);
    // The list is copied out from under the lock: `poll_wakeup` reaches an
    // epoll's state and a close reaches this list, so holding both would put
    // this lock inside one that is taken before it.
    // A description already on its way to its finalizer does not upgrade.
    let watching: Vec<fs_fdobj::Owned> = with_registry(|reg| {
        reg.iter()
            .filter_map(fs_fdobj::Owned::upgrade)
            .filter(|fd| mask_cell(fd).is_some_and(|m| m.load(Ordering::Relaxed) & bit != 0))
            .collect()
    });
    for fd in &watching {
        fs_poll::poll_wakeup(fd, fs_poll::bits::READ as c_int);
    }
    // Dropped outside the lock: one of these can be the last reference, and
    // its close takes the lock to deregister.
    drop(watching);
}

/// A signalfd exists. Paired with [`forget_signalfd`] in `close`.
fn remember_signalfd(fd: &fs_fdobj::Owned) {
    with_registry(|reg| {
        if reg.try_reserve(1).is_ok() {
            reg.push(fd.downgrade());
        }
    });
}

fn forget_signalfd(fd: &ffi::fd) {
    with_registry(|reg| reg.retain(|w| !std::ptr::eq(w.as_ptr(), fd)));
}

/// A signalfd's `fd_ops`: a read, a poll, and a close that has nothing to free.
///
/// The close is present rather than null because the descriptor has no state of
/// its own — the mask lives in the union and goes with the `struct fd` — and a
/// null close would read as an oversight next to the other descriptor kinds.
struct SignalfdOps;

static SIGNALFD_FDOPS: SignalfdOps = SignalfdOps;

fn signalfd_fdops() -> Option<&'static dyn ffi::FdOps> {
    Some(&SIGNALFD_FDOPS)
}

impl ffi::FdOps for SignalfdOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::READ_ONLY_STREAM
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        signalfd_read(fd, buf)
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(signalfd_poll(fd))
    }
    /// Written out rather than left to the default, for the reason above: the
    /// descriptor has nothing to free, and a driver with no close at all would
    /// read as an oversight next to the other descriptor kinds.
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        signalfd_close(fd)
    }
    /// `signalfd_show_fdinfo`: the mask as `render_sigset_t` prints it, sixteen
    /// hex digits with signal 1 in the lowest bit.
    fn show_fdinfo(&self, fd: &ffi::fd, out: &mut String) {
        if let Some(mask) = mask_cell(fd) {
            out.push_str(&format!("sigmask:\t{:016x}\n", mask.load(Ordering::Relaxed)));
        }
    }
}

/// The descriptor's mask, which **is** an atomic: `signalfd4` can retarget a
/// descriptor another thread is reading.
///
/// It was `_Atomic uint64_t` in the C, which bindgen emits as a plain word, so
/// this cast to an `AtomicU64` was the thing that made every access atomic and
/// `tools/atomic-fields.py` was the check that nobody skipped it. The field is
/// an `AtomicU64` since 2026-09-05 and the cast is a borrow. It is the
/// description's driver state since 2026-09-29, so the question "is this a
/// signalfd" and the read are one downcast: `None` for any other kind.
fn mask_cell(fd: &ffi::fd) -> Option<&AtomicU64> {
    fd.driver_state::<AtomicU64>()
}

fn signalfd_poll(fd: &ffi::fd) -> c_int {
    let Some(mask) = mask_cell(fd).map(|m| m.load(Ordering::Relaxed)) else {
        return 0;
    };
    let ready = taskview::with_current_queue(|queue| queue.pending_in(mask)).unwrap_or(false);
    if ready {
        fs_poll::bits::READ as c_int
    } else {
        0
    }
}

fn signalfd_read(fd: &ffi::fd, buf: &mut [u8]) -> isize {
    // The loop parks on sighand's lock and rechecks, which no one-question entry
    // point can express. `buf` is the kernel's own buffer -- fd_ops.read
    // is handed one and the VFS copies it out -- so nothing here touches guest
    // memory. It is a slice since 2026-09-14, so that sentence is now the
    // signature rather than a comment and the `from_raw_parts_mut` is gone.
    let Some(mask) = mask_cell(fd) else {
        return guest_errno::isize_::EINVAL;
    };
    let nonblock = (fd.flags() & ffi::O_NONBLOCK_) != 0;
    taskview::with_current_queue(|queue| read::read(queue, mask, nonblock, buf)).unwrap_or(guest_errno::isize_::EINVAL)
}

fn signalfd_close(fd: &ffi::fd) -> c_int {
    // Nothing to free: the mask is the description's and goes with it.
    // What has to happen is leaving the registry, before the description is
    // freed and a notify could reach it.
    forget_signalfd(fd);
    0
}

/// The descriptor, new or retargeted. `f_install` still answers a negative
/// errno, which is what `Errno::split` reads.
pub fn sys_signalfd4(
    fd_no: c_int,
    mask_addr: u64,
    mask_size: u64,
    flags: c_int,
) -> Result<i64, Errno> {
    strace!("signalfd4({fd_no}, {mask_addr:#x}, {mask_size}, {flags:#x})");
    // SFD_CLOEXEC and SFD_NONBLOCK are O_CLOEXEC and O_NONBLOCK, and which
    // flags are accepted is crates/kernel/signalfd.
    if !signalfd::flags_valid(flags as u32) {
        return Err(Errno::EINVAL);
    }
    if mask_size != 8 {
        return Err(Errno::EINVAL);
    }
    let Ok(raw) = GuestMem::current().read_u64(mask_addr) else {
        return Err(Errno::EFAULT);
    };
    let mask = signalfd::usable_mask(raw);

    // Widen the task's wakeup mask before the descriptor can be read, so no
    // signal that arrives in between is queued without a wakeup.
    taskview::with_current_queue(|queue| queue.watch_signalfd(mask));

    // -1 asks for a new descriptor; anything else retargets one that exists,
    // which is how a program changes what it watches without losing what has
    // already arrived.
    if fd_no != -1 {
        let Some(fd) = fs_fdobj::f_get(fd_no) else {
            return Err(Errno::EBADF);
        };
        let fd = &*fd;
        let Some(cell) = mask_cell(fd) else {
            return Err(Errno::EINVAL);
        };
        cell.store(mask, Ordering::Relaxed);
        return Ok(fd_no.into());
    }

    let mut fd = fs_adhoc::adhoc_anon(signalfd_fdops(), Some(c"[signalfd]"));
    fd.set_driver_state(Box::new(AtomicU64::new(mask)));
    let fd = fd.into_owned();
    // Registered before it is installed, so that a signal arriving between the
    // two finds it: `f_install` consumes the descriptor however it ends, and a
    // failure runs `signalfd_close`, which takes it out again.
    remember_signalfd(&fd);
    Errno::split(fs_fdobj::f_install(fd, flags) as i64)
}

#[cfg(test)]
mod tests {
    /// The descriptor's mask is one 64-bit word in `struct fd`'s union, and it
    /// is `_Atomic` on the C side. Reading it as a plain `u64` would be a data
    /// race with `signalfd4` retargeting a descriptor another thread is
    /// reading, which is the case the atomic exists for — so the layout has to
    /// match what `AtomicU64` expects.
    #[test]
    fn the_mask_is_an_atomic_word() {
        assert_eq!(std::mem::size_of::<std::sync::atomic::AtomicU64>(), 8);
        assert_eq!(std::mem::align_of::<std::sync::atomic::AtomicU64>(), 8);
    }
}
