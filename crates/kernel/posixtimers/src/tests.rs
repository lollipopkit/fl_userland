use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Darwin's `CLOCK_MONOTONIC`, which is 6 where Linux's is 1.
const CLOCK_MONOTONIC: c_int = 6;

/// The two tests that count firings share one counter and one timer
/// service, and cargo runs tests in parallel — so they take this first.
/// Without it, the delete test saw the *other* test's timer and read as a
/// deleted timer firing.
static FIRING_TESTS: Mutex<()> = Mutex::new(());
static FIRED: AtomicUsize = AtomicUsize::new(0);
static LAST: Mutex<Notification> = Mutex::new(Notification {
    signal: 0,
    timer_id: 0,
    target: TaskRef {
        pid: 0,
        generation: 0,
    },
    overrun: 0,
    sig_value: 0,
});

/// A target for the timers that notify nothing.
const NOBODY: TaskRef = TaskRef {
    pid: 1,
    generation: 1,
};
/// The one the firing test checks comes back as it went in.
const SOMEONE: TaskRef = TaskRef {
    pid: 77,
    generation: 3,
};

fn record(notification: &Notification) {
    FIRED.fetch_add(1, Ordering::SeqCst);
    *LAST.lock().unwrap_or_else(|e| e.into_inner()) = *notification;
}

fn in_ms(ms: i64) -> Spec {
    Spec {
        value: Timespec {
            sec: ms / 1000,
            nsec: (ms % 1000) * 1_000_000,
        },
        interval: Timespec::default(),
    }
}

#[test]
fn ids_are_handed_out_lowest_first_and_reused_after_a_delete() {
    let timers = Timers::new();
    let first = timers.create(CLOCK_MONOTONIC, None, 14, 0, NOBODY);
    let second = timers.create(CLOCK_MONOTONIC, None, 14, 0, NOBODY);
    assert_eq!((first, second), (0, 1));
    assert_eq!(timers.delete(first), 0);
    assert_eq!(timers.create(CLOCK_MONOTONIC, None, 14, 0, NOBODY), 0);
    assert_eq!(timers.live(), 2);
}

#[test]
fn the_table_is_bounded_and_says_so() {
    let timers = Timers::new();
    for expected in 0..MAX {
        assert_eq!(
            timers.create(CLOCK_MONOTONIC, None, 14, 0, NOBODY),
            expected as c_int
        );
    }
    assert_eq!(timers.create(CLOCK_MONOTONIC, None, 14, 0, NOBODY), ENOMEM);
    assert_eq!(timers.live(), MAX);
}

/// The three bound defects this table has had, as one test: an id past the
/// end, a negative one, and one inside the table that is not a timer.
#[test]
fn an_id_that_is_not_a_timer_is_einval_everywhere() {
    let timers = Timers::new();
    let live = timers.create(CLOCK_MONOTONIC, None, 14, 0, NOBODY);
    let mut spec = Spec::default();
    for id in [MAX as c_int, MAX as c_int + 1, -1, 1000, live + 1] {
        assert_eq!(
            timers.set(id, false, in_ms(10), &mut spec),
            EINVAL,
            "set {id}"
        );
        assert_eq!(timers.get(id, &mut spec), EINVAL, "get {id}");
        assert_eq!(timers.overrun(id), EINVAL, "overrun {id}");
        assert_eq!(timers.delete(id), EINVAL, "delete {id}");
    }
    // And the one that is a timer still works.
    assert_eq!(timers.set(live, false, in_ms(10), &mut spec), 0);
}

#[test]
fn a_timer_fires_and_reports_what_it_was_created_with() {
    let _serial = FIRING_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    FIRED.store(0, Ordering::SeqCst);
    let timers = Timers::new();
    let id = timers.create(CLOCK_MONOTONIC, Some(record), 14, 0xabcd, SOMEONE);
    let mut old = Spec::default();
    assert_eq!(timers.set(id, false, in_ms(20), &mut old), 0);
    for _ in 0..200 {
        if FIRED.load(Ordering::SeqCst) > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(FIRED.load(Ordering::SeqCst) > 0, "the timer never fired");
    let last = *LAST.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        last,
        Notification {
            signal: 14,
            timer_id: id,
            target: SOMEONE,
            overrun: 0,
            sig_value: 0xabcd,
        }
    );
    timers.delete(id);
}

#[test]
fn a_deleted_timer_never_fires_again() {
    let _serial = FIRING_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    FIRED.store(0, Ordering::SeqCst);
    let timers = Timers::new();
    let id = timers.create(CLOCK_MONOTONIC, Some(record), 14, 0, NOBODY);
    let mut old = Spec::default();
    assert_eq!(timers.set(id, false, in_ms(60), &mut old), 0);
    assert_eq!(timers.delete(id), 0);
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(FIRED.load(Ordering::SeqCst), 0);
}

#[test]
fn clearing_destroys_every_timer() {
    let timers = Timers::new();
    for _ in 0..4 {
        timers.create(CLOCK_MONOTONIC, None, 14, 0, NOBODY);
    }
    assert_eq!(timers.live(), 4);
    timers.clear();
    assert_eq!(timers.live(), 0);
    // And the ids are free again.
    assert_eq!(timers.create(CLOCK_MONOTONIC, None, 14, 0, NOBODY), 0);
}

/// A disarmed timer has *no* time remaining rather than a negative one,
/// and asking about one that was never armed must not report the epoch.
#[test]
fn a_timer_that_was_never_armed_reports_nothing_remaining() {
    let timers = Timers::new();
    let id = timers.create(CLOCK_MONOTONIC, None, 14, 0, NOBODY);
    let mut spec = Spec::default();
    assert_eq!(timers.get(id, &mut spec), 0);
    assert_eq!(spec, Spec::default());
}

/// An absolute deadline of exactly now arms the timer; it came out as a zero
/// delay, which is how a timer is disarmed.
#[test]
fn a_deadline_of_now_or_before_is_due_not_disarmed() {
    let now = Timespec { sec: 100, nsec: 5 };
    let soon = Timespec { sec: 0, nsec: 1 };
    assert_eq!(super::until(now, now), soon, "exactly now");
    assert_eq!(super::until(Timespec { sec: 90, nsec: 0 }, now), soon, "ten seconds ago");
    assert_eq!(
        super::until(Timespec { sec: 101, nsec: 5 }, now),
        Timespec { sec: 1, nsec: 0 },
        "a second from now is a second"
    );
}
