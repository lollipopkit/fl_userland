//! Socket detection, listen registration, and per-thread wait state.

use std::cell::{Cell, RefCell};
use std::ptr::NonNull;

use super::*;

thread_local! {
    /// How many nested waits this thread is inside. `sys_accept` brackets its
    /// own wait and the poll loop brackets its, and the answer is only ever
    /// compared against zero.
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    /// This thread's handle, made on its first wait and kept afterwards.
    static WAITER: RefCell<Option<Arc<Waiter>>> = const { RefCell::new(None) };
}

pub(super) fn my_waiter() -> Arc<Waiter> {
    WAITER.with(|slot| {
        let mut slot = slot.borrow_mut();
        slot.get_or_insert_with(|| {
            Arc::new(Waiter {
                // `None` for a thread with no task; see [`Waiter::task`] for
                // why that is a state rather than a mistake.
                task: NonNull::new(taskview::current()),
                punt: AtomicBool::new(false),
                accepting: Mutex::new(None),
            })
        })
        .clone()
    })
}

/// Whether this descriptor is one of `crates/fs/sock`'s.
///
/// Safe, and takes a borrow: it reads one field. It was an
/// `fn(*mut ffi::fd)` with a null test, and every caller below wrapped it in
/// an `unsafe fn` of its own that added nothing.
fn is_socket(fd: &ffi::fd) -> bool {
    let Some(&want) = SOCKET_FDOPS.get() else {
        return false;
    };
    fd.ops.is_some_and(|ops| ops.as_any().type_id() == want)
}

// ------------------------------------------------------------ the registrations

/// A socket started listening, or changed its backlog.
///
/// `listen()` may be called repeatedly on one listening socket. This records the
/// socket, not the call: the C used an intrusive node and a second insertion
/// would have self-linked it, leaving a dangling registry head on close.
pub fn sockrestart_begin_listen(sock: &fs_fdobj::Owned, backlog: c_int, protocol: c_int) {
    if !is_socket(sock) {
        return;
    }
    let id = ffi::FdId::of(sock);
    let mut r = registry().lock().unwrap();
    match r.listening.iter_mut().find(|l| l.sock == id) {
        Some(l) => {
            l.backlog = backlog;
            l.protocol = protocol;
        }
        None => r.listening.push(Listening {
            sock: id,
            weak: sock.downgrade(),
            backlog,
            protocol,
        }),
    }
}

pub fn sockrestart_end_listen(sock: &ffi::fd) {
    if !is_socket(sock) {
        return;
    }
    let id = ffi::FdId::of(sock);
    let mut r = registry().lock().unwrap();
    r.listening.retain(|l| l.sock != id);
}

/// Whether a descriptor is a socket, for a caller deciding whether the bracket
/// below is needed at all. The `fd_ops` table is the socket crate's, and this is
/// the one question anyone else asks about it.
pub fn sockrestart_is_socket(fd: &ffi::fd) -> bool {
    is_socket(fd)
}

/// This thread is about to wait on at least one socket.
pub fn sockrestart_begin_listen_wait_bare() {
    let entered = DEPTH.with(|d| {
        let n = d.get();
        d.set(n + 1);
        n == 0
    });
    if entered {
        let me = my_waiter();
        registry().lock().unwrap().waiting.push(me);
    }
}

/// That wait is over.
///
/// A call with nothing to end is ignored. The C decremented unconditionally, so
/// one unbalanced end left the count at -1 and the *next* wait registered
/// nothing — a thread that then slept through a resume.
pub fn sockrestart_end_listen_wait_bare() {
    let left = DEPTH.with(|d| {
        let n = d.get();
        if n == 0 {
            return false;
        }
        d.set(n - 1);
        n == 1
    });
    if left {
        let me = my_waiter();
        let mut r = registry().lock().unwrap();
        r.waiting.retain(|w| !Arc::ptr_eq(w, &me));
    }
}

pub fn sockrestart_begin_listen_wait(sock: &ffi::fd) {
    if is_socket(sock) {
        *lock_accepting(&my_waiter()) = Some(ffi::FdId::of(sock));
        sockrestart_begin_listen_wait_bare();
    }
}

pub fn sockrestart_end_listen_wait(sock: &ffi::fd) {
    if is_socket(sock) {
        sockrestart_end_listen_wait_bare();
        *lock_accepting(&my_waiter()) = None;
    }
}

fn lock_accepting(w: &Waiter) -> std::sync::MutexGuard<'_, Option<ffi::FdId>> {
    w.accepting.lock().unwrap_or_else(|p| p.into_inner())
}

/// Wake every thread blocked in a host `accept` on `sock`.
///
/// For `shutdown(SHUT_RD)` on a listener, which on Linux ends such a wait
/// with `EINVAL` -- measured by `sock_probe`. The host's `shutdown` does not
/// wake an `accept` blocked on a Darwin listening socket, so a guest thread
/// stayed there for good: `sock_race` hung on its own teardown on 2026-09-30.
/// The punt is what makes the woken thread go round its loop, where it finds
/// the socket shut down, rather than take the `EINTR` as an answer.
///
/// **A narrow window is left**, and it is the one a guest signal has as well:
/// a thread that has looked at the flag and not yet entered `accept` takes the
/// `SIGUSR1` in between and then blocks. Closing it needs the host wait to
/// be bounded, which this crate's accept is not.
pub fn sockrestart_wake_accepting(sock: &ffi::fd) {
    let id = ffi::FdId::of(sock);
    let r = registry().lock().unwrap();
    for w in &r.waiting {
        if *lock_accepting(w) != Some(id) {
            continue;
        }
        w.punt.store(true, Ordering::SeqCst);
        if let Some(task) = w.task {
            // SAFETY: registered, so the thread is inside its wait and its
            // task is live; see the `Send` impl on `Waiter`.
            unsafe { task_interrupt_host_call(task.as_ptr()) };
        }
    }
}

/// Whether a resume happened during the wait this thread just left, in which
/// case its `EINTR` is not an answer and the wait should be made again.
///
/// Every caller asks this *after* ending the wait, which is why the handle
/// outlives the registration.
pub fn sockrestart_should_restart_listen_wait() -> bool {
    WAITER.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|w| w.punt.swap(false, Ordering::SeqCst))
    })
}
