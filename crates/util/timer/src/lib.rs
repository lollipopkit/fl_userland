//! Timers: one service thread with a deadline queue, where there was one OS
//! thread per armed timer.
//!
//! `timerfd`, POSIX timers and `setitimer` all sit on this. What it replaces
//! did three things worth naming:
//!
//! - **A `pthread_create` per arming.** A program with a timerfd per connection
//!   got an OS thread per connection, each one asleep in `nanosleep` and woken
//!   by `pthread_kill(SIGUSR1)` whenever its deadline moved. There is one
//!   thread here regardless of how many timers exist.
//! - **`malloc` and partial initialisation.** `timer_new` set the clock, the
//!   callback, `active` and the lock, and left `start`, `end` and `interval` as
//!   whatever was on the heap. A fresh timerfd's `gettime` therefore reported a
//!   garbage interval whenever the allocator did not happen to hand back zeros.
//! - **A free that did not wait.** `timer_free` marked the timer dead, signalled
//!   the thread and returned — while the callback might be running. For a
//!   timerfd that callback touches the descriptor and wakes its pollers, so a
//!   close racing an expiry used the descriptor after it was freed. Here
//!   [`free`] waits for a callback in flight, which is what makes closing safe
//!   rather than usually safe.
//!
//! # What a caller must still know
//!
//! [`Expire::expired`] runs on the service thread, not on the guest thread that
//! armed it, and it runs with **no lock of this module held** — so it may take
//! whatever it likes, and it may call back in here. Two things follow: an
//! implementation that blocks for ever stops every other timer, and it must not
//! assume the guest thread is anywhere in particular.
//!
//! # The target was `(fn(usize), usize)` until 2026-09-16
//!
//! C's `void (*cb)(void *), void *user_data`, carried across whole. Three
//! callers each recovered a *different* type from that one integer — a
//! `*mut TimerFd`, a `*const Armed`, a `*mut task` — and nothing tied a
//! callback to the payload it read: `timerfd_callback` beside a task pointer
//! type-checked. Two of the three tested the payload for null and the third did
//! not, which is the same fact seen from the other end, an untyped `usize`
//! leaving that decision to each caller.
//!
//! An `Arc<dyn Expire>` is that pair as one value the compiler holds together,
//! and it **owns** the target rather than borrowing it. Ownership is what makes
//! the third caller expressible at all: `setitimer`'s payload is the task that
//! armed the timer, and a `&task` was unsound while that task ran until
//! 2026-10-16 — its own thread wrote `task->cpu` on every instruction, which
//! `docs/changelog/2026-09-05-a-shared-reference-to-a-struct-another-thread-writes.md`
//! is about — and a borrow cannot outlive a reaped task anyway. Owning a small
//! object that *holds the task's address as a key* sidesteps both, and the object has somewhere to be freed — here, when the
//! timer is — which is what an earlier attempt at this could not find.
//!
//! The cost is one atomic pair per expiry, against a `fn` pointer and a word.
//! An expiry already takes this module's mutex and then does a signal send or a
//! descriptor wakeup, so it is not on a path where that is measurable.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};

/// `struct timespec`, as the C passes it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

impl Timespec {
    fn is_zero(self) -> bool {
        self.sec == 0 && self.nsec == 0
    }
    fn is_positive(self) -> bool {
        self.sec > 0 || (self.sec == 0 && self.nsec > 0)
    }
    fn add(self, other: Timespec) -> Timespec {
        let mut sec = self.sec.saturating_add(other.sec);
        let mut nsec = self.nsec + other.nsec;
        if nsec >= 1_000_000_000 {
            nsec -= 1_000_000_000;
            sec = sec.saturating_add(1);
        }
        Timespec { sec, nsec }
    }
    fn sub(self, other: Timespec) -> Timespec {
        let mut sec = self.sec - other.sec;
        let mut nsec = self.nsec - other.nsec;
        if nsec < 0 {
            nsec += 1_000_000_000;
            sec -= 1;
        }
        Timespec { sec, nsec }
    }
    fn as_duration(self) -> std::time::Duration {
        if !self.is_positive() {
            return std::time::Duration::ZERO;
        }
        std::time::Duration::new(self.sec as u64, self.nsec as u32)
    }
}

/// `struct timer_spec`: when to fire, and how often after that.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Spec {
    pub value: Timespec,
    pub interval: Timespec,
}

/// What a timer does when it expires.
///
/// `Send + Sync` because the target is made on a guest thread and used on the
/// service thread. That was true of the `usize` this replaces as well — every
/// integer is `Send` — so the assertion was being made at three call sites by
/// the type system declining to ask. Here it is asked once.
pub trait Expire: Send + Sync {
    /// Runs on the service thread with no lock of this module held.
    fn expired(&self);
}

type DueTimer = (u64, Arc<dyn Expire>);

/// The clock, now. `pub` because crates/kernel/posixtimers turns an absolute
/// deadline into a relative one and has to do it against the same clock.
pub fn now(clockid: i32) -> Timespec {
    let (sec, nsec) = util_timeabi::host_clock(clockid as libc::clockid_t).unwrap_or((0, 0));
    Timespec { sec, nsec }
}

struct Timer {
    clockid: i32,
    target: Arc<dyn Expire>,
    active: bool,
    /// Absolute, on `clockid`.
    end: Timespec,
    interval: Timespec,
}

#[derive(Default)]
struct Service {
    timers: BTreeMap<u64, Timer>,
    next_id: u64,
    /// The timer whose callback is executing, if any. [`free`] waits on it.
    running: Option<u64>,
    started: bool,
}

static SERVICE: Mutex<Option<Service>> = Mutex::new(None);
/// Signalled when a deadline changes, and when a callback finishes.
static WAKE: Condvar = Condvar::new();

fn with<R>(f: impl FnOnce(&mut Service) -> R) -> R {
    let mut g = SERVICE.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Service::default))
}

/// How long until the earliest deadline, or `None` if nothing is armed.
fn earliest(svc: &Service) -> Option<std::time::Duration> {
    svc.timers
        .values()
        .filter(|t| t.active)
        .map(|t| t.end.sub(now(t.clockid)).as_duration())
        .min()
}

fn service_thread() {
    loop {
        let mut g = SERVICE.lock().unwrap_or_else(|e| e.into_inner());
        let svc = g.get_or_insert_with(Service::default);

        // Everything due right now, taken as (id, target) so the targets run
        // with nothing of ours held.
        //
        // The `Arc` is cloned rather than borrowed, and that is what makes the
        // unlocked call below safe **in the type system** rather than by the
        // `running` protocol alone: `free` may remove this timer from the map
        // the moment the guard drops, and the clone is what keeps the target
        // alive across that. `free` still waits, because a timerfd must not
        // fire after its descriptor is closed -- but that is now an ordering
        // rule rather than the thing standing between this call and a
        // use-after-free.
        let mut due: Vec<DueTimer> = Vec::new();
        for (&id, t) in svc.timers.iter_mut() {
            if t.active && !t.end.sub(now(t.clockid)).is_positive() {
                due.push((id, Arc::clone(&t.target)));
                if t.interval.is_positive() {
                    // Advance from the deadline, not from now: a periodic timer
                    // that is delivered late must not drift.
                    t.end = t.end.add(t.interval);
                } else {
                    t.active = false;
                }
            }
        }

        if due.is_empty() {
            // **Under the same acquisition as the check above.** This dropped
            // the guard here and took the lock again before waiting, and that
            // gap is a lost wakeup: another thread can `timer_set` and
            // `WAKE.notify_all()` while nobody is waiting, and with nothing
            // armed when `earliest` ran the fallback below is a *minute*. A
            // 60ms timerfd fired 60 seconds late, about one guest run in
            // twenty-five, and `timerfd_abi` reported it as "not for ever:
            // 60005ms" -- the 5 being the time the read really needed.
            //
            // The drop was there to end `svc`'s borrow of `g`. It does not need
            // to be: `earliest` answers an owned `Option<Duration>`, so the
            // borrow ends at that statement and the guard can be moved straight
            // into the wait.
            let wait = earliest(svc);
            match wait {
                // A minute is a re-check, not a deadline: nothing is armed, and
                // waiting for ever would need every arming to signal.
                None => {
                    let _ = WAKE.wait_timeout(g, std::time::Duration::from_secs(60));
                }
                Some(d) => {
                    let _ = WAKE.wait_timeout(g, d.max(std::time::Duration::from_micros(50)));
                }
            }
            continue;
        }

        for (id, target) in due {
            g.get_or_insert_with(Service::default).running = Some(id);
            drop(g);
            // The target runs with nothing of ours held, so it may take
            // whatever locks it likes and may call back in here.
            target.expired();
            // **Dropped before the lock is retaken**, because this clone can be
            // the last reference: `free` removes the map's entry, and for
            // `crates/kernel/posixtimers` the retiring slot keeps none of its
            // own. A target's destructor is not this module's to run
            // underneath this module's mutex -- `crates/kernel/timerfd`'s ends
            // in `cond_destroy`, which aborts on `EBUSY`. One line, and the
            // question does not arise.
            drop(target);
            g = SERVICE.lock().unwrap_or_else(|e| e.into_inner());
            let svc = g.get_or_insert_with(Service::default);
            svc.running = None;
            // A free may be waiting on exactly this.
            WAKE.notify_all();
        }
        drop(g);
    }
}

fn ensure_started(svc: &mut Service) {
    if !svc.started {
        svc.started = true;
        std::thread::Builder::new()
            .name("iul-timers".into())
            .spawn(service_thread)
            .expect("timer service thread");
    }
}

// ---------------------------------------------------------------------------
// The timer service API
// ---------------------------------------------------------------------------

/// Create a timer. The handle is an id, not a pointer, so a stale one is a
/// lookup that fails rather than a dangling dereference.
pub fn timer_new(clockid: i32, target: Arc<dyn Expire>) -> u64 {
    with(|svc| {
        ensure_started(svc);
        svc.next_id += 1;
        let id = svc.next_id;
        svc.timers.insert(
            id,
            Timer {
                clockid,
                target,
                active: false,
                // Zero, not whatever was on the heap. A fresh timer has no
                // deadline and no interval, and `gettime` reports both.
                end: Timespec::default(),
                interval: Timespec::default(),
            },
        );
        id
    })
}

/// Destroy a timer, waiting for an expiry in flight, and drop its target.
///
/// The wait is what stops a timerfd firing after its descriptor is closed: the
/// target touches the descriptor state and wakes its pollers, so returning
/// while one is running would let the caller tear that down underneath it.
///
/// It is no longer what keeps the *target* alive — the service thread holds its
/// own `Arc` for the length of the call — so a caller that gets this wrong now
/// has a timerfd that fires once too often rather than a use-after-free.
pub fn timer_free(id: u64) {
    let mut g = SERVICE.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let svc = g.get_or_insert_with(Service::default);
        if svc.running != Some(id) {
            svc.timers.remove(&id);
            WAKE.notify_all();
            return;
        }
        g = WAKE.wait(g).unwrap_or_else(|e| e.into_inner());
    }
}

/// Arm, re-arm or disarm. `oldspec` gets what was there when requested.
pub fn timer_set(id: u64, spec: Spec, oldspec: Option<&mut Spec>) -> i32 {
    let old = with(|svc| {
        let t = svc.timers.get_mut(&id)?;
        let n = now(t.clockid);
        // What was there. An inactive timer has *no* time remaining rather than
        // a negative one -- this reported `end - now` unconditionally, and a
        // fresh timer's `end` is the epoch, so disarming one that was never
        // armed reported about minus eleven days.
        let was = Spec {
            value: if t.active {
                t.end.sub(n)
            } else {
                Timespec::default()
            },
            interval: t.interval,
        };
        t.end = n.add(spec.value);
        t.interval = spec.interval;
        t.active = !spec.value.is_zero();
        Some(was)
    });
    let Some(was) = old else { return -22 };
    if let Some(oldspec) = oldspec {
        *oldspec = was;
    }
    WAKE.notify_all();
    0
}

/// What is left to run, without disturbing it.
pub fn timer_get(id: u64, out: &mut Spec) -> i32 {
    let spec = with(|svc| {
        svc.timers.get(&id).map(|t| Spec {
            value: if t.active {
                t.end.sub(now(t.clockid))
            } else {
                Timespec::default()
            },
            interval: t.interval,
        })
    });
    match spec {
        Some(s) => {
            *out = s;
            0
        }
        None => -22,
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
