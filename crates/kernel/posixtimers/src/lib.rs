//! A thread group's POSIX timers: the table `timer_create` hands out ids from,
//! and what each of them notifies when it fires.
//!
//! Small, bounded, and with a bad history. Three separate defects have come out
//! of this table being a fixed array in `struct tgroup` reached by a guest
//! index:
//!
//! - `timer_settime` bounded its id with `> TIMERS_MAX` where the array has
//!   that many elements, so `timer_settime(16, …)` read and wrote a whole
//!   `struct posix_timer` past the end of it;
//! - `timer_delete` had no bound at all, and `tools/index-bounds.py` is what
//!   found it;
//! - a forked child shared its parent's array, so the child's `timer_delete`
//!   destroyed a timer the parent still owned.
//!
//! Two more were found while moving it here, and neither is expressible against
//! this shape:
//!
//! - **A deadlock.** `timer_delete` held the thread group's lock across
//!   `timer_free`, which *waits* for a callback in flight — and the callback
//!   takes `pids_lock`, which is held elsewhere by a thread waiting for that
//!   same group lock. Three parties, one cycle, and invisible to
//!   `tools/lock-order.py` because the middle edge runs through a Rust
//!   callback. Here the slot is taken out under the lock and the lock is
//!   released *before* the wait, and there is one place that can be got wrong.
//! - **A use of a slot being reused.** The service thread reads a firing
//!   timer's notification without the group lock. Once the delete releases that
//!   lock, `timer_create` can claim the same index and overwrite the fields the
//!   callback is reading. What a timer notifies is its own allocation here,
//!   **owned by the timer** — so it lives exactly as long as the timer does,
//!   and the ordering that used to be written out in `Retired::destroy` as
//!   "`timer_free` first, then `Box::from_raw`" is the drop of the last
//!   reference. Since 2026-09-16; see `crates/util/timer`'s module comment for
//!   what the payload was before.

use std::ffi::c_int;
use std::sync::{Arc, Mutex, MutexGuard};

use util_identity::TaskRef;
use util_timer::{Spec, Timespec};

/// Linux has no fixed limit; this table does, and `timer_create` answers
/// `ENOMEM` past it. Sixteen is what the C had.
pub const MAX: usize = 16;

use guest_errno::c_int_::{EINVAL, ENOMEM};

/// What a firing timer asks the caller to deliver. Delivery needs a task,
/// which this crate knows nothing about; this is everything it needs to know.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Notification {
    pub signal: c_int,
    /// The guest's timer id, which is this table's index.
    pub timer_id: c_int,
    /// The thread to signal -- the process is addressed through its leader.
    /// A reference and not a number: a `SIGEV_THREAD_ID` timer outlives the
    /// thread it names, and the number is handed to another task once it is
    /// gone. Linux's `it_pid` is a `struct pid` for the same reason.
    pub target: TaskRef,
    /// How many expirations were missed. Always zero: the timer service
    /// delivers every expiry rather than coalescing, so there is nothing to
    /// have missed. Reported because `siginfo_t.si_overrun` has a field for it.
    pub overrun: c_int,
    pub sig_value: u64,
}

pub type Notify = fn(notification: &Notification);

/// One timer's notification, owned by the host timer.
///
/// Not a field of the slot: the service thread reads it without this table's
/// lock, and a delete releases that lock before waiting for the expiry —
/// because holding it across the wait is the deadlock described above. So the
/// slot can be claimed by a new `timer_create` the instant the delete releases
/// it, and the expiry must not then be reading the new timer's fields.
///
/// It was `Box::into_raw`'d into a `usize` in the slot until 2026-09-16, with
/// `Retired::destroy` doing `timer_free` and then `Box::from_raw` in that order
/// — a hand-written "this is freed after the timer, never before". The timer
/// owns it now, so that order is `timer_free`'s and there is nothing for a
/// caller to get wrong.
struct Armed {
    /// `None` for `SIGEV_NONE`, which creates a timer that notifies nothing.
    notify: Option<Notify>,
    notification: Notification,
}

impl util_timer::Expire for Armed {
    fn expired(&self) {
        if let Some(notify) = self.notify {
            notify(&self.notification);
        }
    }
}

struct Slot {
    handle: u64,
    clockid: c_int,
}

/// A slot taken out of the table, whose host timer has yet to be destroyed.
///
/// Returned by value so that the destruction happens with the table's lock
/// released: that is the whole discipline, and a type that has to be consumed
/// is how it stays kept.
struct Retired(Slot);

impl Retired {
    /// Waits for an expiry in flight, which is also what drops the
    /// notification: the timer owns it.
    fn destroy(self) {
        util_timer::timer_free(self.0.handle);
    }
}

#[derive(Default)]
pub struct Timers {
    slots: Mutex<Vec<Option<Slot>>>,
}

impl std::fmt::Debug for Timers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Timers").finish_non_exhaustive()
    }
}

impl Timers {
    pub fn new() -> Timers {
        Timers {
            slots: Mutex::new((0..MAX).map(|_| None).collect()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Option<Slot>>> {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Claim the lowest free id and arm nothing.
    ///
    /// `notify` is `None` for `SIGEV_NONE`. Returns the guest's timer id, or a
    /// negative guest errno.
    pub fn create(
        &self,
        clockid: c_int,
        notify: Option<Notify>,
        signal: c_int,
        sig_value: u64,
        target: TaskRef,
    ) -> c_int {
        let mut slots = self.lock();
        let Some(id) = slots.iter().position(|slot| slot.is_none()) else {
            return ENOMEM;
        };
        let armed = Arc::new(Armed {
            notify,
            notification: Notification {
                signal,
                timer_id: id as c_int,
                target,
                overrun: 0,
                sig_value,
            },
        });
        // `armed.clone()` rather than `Arc::clone(&armed)`: the argument
        // coerces to `Arc<dyn Expire>`, and the associated-function form makes
        // inference resolve `Arc::clone` at the target type instead. The
        // handle failing is what drops it, with nothing to write.
        let handle = util_timer::timer_new(clockid, armed.clone());
        if handle == 0 {
            return ENOMEM;
        }
        slots[id] = Some(Slot { handle, clockid });
        id as c_int
    }

    fn with<T>(&self, id: c_int, f: impl FnOnce(&Slot) -> T) -> Option<T> {
        let slots = self.lock();
        let slot = slots.get(usize::try_from(id).ok()?)?.as_ref()?;
        Some(f(slot))
    }

    /// Arm, re-arm or disarm. `absolute` is `TIMER_ABSTIME`.
    pub fn set(&self, id: c_int, absolute: bool, spec: Spec, old: &mut Spec) -> c_int {
        self.with(id, |slot| {
            let mut spec = spec;
            // Not `&& !is_zero`: a zero with `TIMER_ABSTIME` is a deadline at
            // the epoch, not a disarm -- measured, a real kernel's
            // `timer_gettime` still answers armed after it. `timerfd` is the
            // other way round, and that was measured too.
            if absolute {
                // Against the same clock the timer runs on, which is why the
                // slot remembers it: the service takes a relative value.
                spec.value = until(spec.value, util_timer::now(slot.clockid));
            }
            util_timer::timer_set(slot.handle, spec, Some(old))
        })
        .unwrap_or(EINVAL)
    }

    pub fn get(&self, id: c_int, out: &mut Spec) -> c_int {
        self.with(id, |slot| util_timer::timer_get(slot.handle, out))
            .unwrap_or(EINVAL)
    }

    /// Always zero; see [`Notification::overrun`]. Answers `EINVAL` for an id
    /// that is not a timer, which is the part a caller can observe.
    pub fn overrun(&self, id: c_int) -> c_int {
        self.with(id, |_| 0).unwrap_or(EINVAL)
    }

    fn take(&self, id: c_int) -> Option<Retired> {
        let mut slots = self.lock();
        let index = usize::try_from(id).ok()?;
        Some(Retired(slots.get_mut(index)?.take()?))
    }

    pub fn delete(&self, id: c_int) -> c_int {
        match self.take(id) {
            // Outside the lock. This is the deadlock the C had.
            Some(retired) => {
                retired.destroy();
                0
            }
            None => EINVAL,
        }
    }

    /// Every timer, destroyed.
    ///
    /// A timer cannot survive `execve` for the same reason a signal handler
    /// cannot: the program that asked for it is gone, and its notification
    /// would arrive at a program that never asked.
    pub fn clear(&self) {
        // Collected first, destroyed after the lock is released, for the same
        // reason `delete` does.
        let retired: Vec<Retired> = self
            .lock()
            .iter_mut()
            .filter_map(|slot| slot.take().map(Retired))
            .collect();
        for one in retired {
            one.destroy();
        }
    }

    pub fn live(&self) -> usize {
        self.lock().iter().filter(|slot| slot.is_some()).count()
    }
}

impl Drop for Timers {
    fn drop(&mut self) {
        self.clear();
    }
}

fn is_zero(t: Timespec) -> bool {
    t.sec == 0 && t.nsec == 0
}

/// How long from `now` until the absolute deadline `at`, as the delay the
/// timer service arms -- and **never zero**, which is how the service is told
/// to disarm.
///
/// A deadline that has passed is due now. It was the plain difference until
/// 2026-09-29, so a deadline of exactly now came out as zero and disarmed the
/// timer it was arming; one already past came out negative and fired, which is
/// right, and a nanosecond is the same answer for both.
fn until(at: Timespec, now: Timespec) -> Timespec {
    let left = subtract(at, now);
    if left.sec < 0 || is_zero(left) {
        Timespec { sec: 0, nsec: 1 }
    } else {
        left
    }
}

fn subtract(a: Timespec, b: Timespec) -> Timespec {
    let mut sec = a.sec - b.sec;
    let mut nsec = a.nsec - b.nsec;
    if nsec < 0 {
        nsec += 1_000_000_000;
        sec -= 1;
    }
    Timespec { sec, nsec }
}

// ---------------------------------------------------------------------------

// The five per-timer operations -- create, set, get, overrun, delete -- have
// no C ABI: their one caller is `crates/kernel/timecalls`, which is Rust and
// calls the methods. What stays below is the table's lifetime, for the crates
// that build and tear down a thread group through bindgen.

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
