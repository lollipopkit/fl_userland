use super::*;
use std::sync::atomic::{AtomicI64, Ordering};

/// Each test counts into its own cell, which is the timer's target.
///
/// A shared counter would be wrong twice over: the tests run concurrently on
/// one service, so they would see each other's timers -- and the target is how
/// every real caller finds its own object, so a test that ignores it does not
/// exercise the thing that matters.
///
/// It used to be an `AtomicI64` reached through a `usize` payload, with a
/// `Box::leak` to outlive the timer pointing at it. The timer owns its target
/// now, so there is nothing to leak and nothing to cast: `Arc::strong_count`
/// below is a check the old shape could not express at all.
#[derive(Default)]
struct Counter(AtomicI64);

impl Expire for Counter {
    fn expired(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Counter {
    fn get(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn counter() -> Arc<Counter> {
    Arc::new(Counter::default())
}

const MONOTONIC: i32 = libc::CLOCK_MONOTONIC as i32;

fn ms(n: i64) -> Timespec {
    Timespec {
        sec: n / 1000,
        nsec: (n % 1000) * 1_000_000,
    }
}

/// The defect the guest test caught: `timer_set`'s old value for a timer
/// that was never armed. `end - now` on a zeroed `end` is minus the current
/// time, which came out as about minus eleven days.
#[test]
fn a_fresh_timer_reports_nothing_rather_than_a_negative() {
    let id = timer_new(MONOTONIC, counter());
    let mut got = Spec::default();
    assert_eq!(timer_get(id, &mut got), 0);
    assert_eq!(
        got,
        Spec::default(),
        "a fresh timer has no deadline and no interval"
    );

    let mut old = Spec::default();
    assert_eq!(timer_set(id, Spec::default(), Some(&mut old)), 0);
    assert_eq!(old, Spec::default(), "disarming one that was never armed");
    timer_free(id);
}

/// And the other half: `start`, `end` and `interval` were never
/// initialised, so this read the heap.
#[test]
fn a_fresh_timer_has_no_interval() {
    for _ in 0..64 {
        let id = timer_new(MONOTONIC, counter());
        let mut got = Spec::default();
        timer_get(id, &mut got);
        assert_eq!(got.interval, Timespec::default());
        timer_free(id);
    }
}

#[test]
fn arming_reports_what_was_there() {
    let id = timer_new(MONOTONIC, counter());
    timer_set(
        id,
        Spec {
            value: ms(5000),
            interval: ms(700),
        },
        None,
    );
    let mut old = Spec::default();
    timer_set(id, Spec::default(), Some(&mut old));
    assert_eq!(old.interval, ms(700));
    assert!(old.value.sec >= 4 && old.value.sec <= 5, "{:?}", old.value);
    // And now it is disarmed, so the next old value is nothing.
    let mut old2 = Spec::default();
    timer_set(id, Spec::default(), Some(&mut old2));
    assert_eq!(old2, Spec::default());
    timer_free(id);
}

#[test]
fn a_one_shot_fires_once() {
    let fired = counter();
    let id = timer_new(MONOTONIC, fired.clone());
    timer_set(
        id,
        Spec {
            value: ms(30),
            interval: Timespec::default(),
        },
        None,
    );
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(fired.get(), 1);
    // And it disarmed itself.
    let mut got = Spec::default();
    timer_get(id, &mut got);
    assert_eq!(got.value, Timespec::default());
    timer_free(id);
}

#[test]
fn a_periodic_timer_keeps_firing() {
    let fired = counter();
    let id = timer_new(MONOTONIC, fired.clone());
    timer_set(
        id,
        Spec {
            value: ms(20),
            interval: ms(20),
        },
        None,
    );
    std::thread::sleep(std::time::Duration::from_millis(300));
    timer_free(id);
    let n = fired.get();
    assert!(n >= 3, "a 20 ms periodic timer fired {n} times in 300 ms");
}

/// One thread, however many timers. The C created one per arming.
#[test]
fn many_timers_share_one_thread() {
    let fired = counter();
    let ids: Vec<u64> = (0..200)
        .map(|_| timer_new(MONOTONIC, fired.clone()))
        .collect();
    for id in &ids {
        timer_set(
            *id,
            Spec {
                value: ms(20),
                interval: Timespec::default(),
            },
            None,
        );
    }
    std::thread::sleep(std::time::Duration::from_millis(400));
    let n = fired.get();
    assert_eq!(n, 200, "every one of 200 timers fired exactly once");
    for id in ids {
        timer_free(id);
    }
}

/// A freed timer never fires again. The C's free returned while a callback
/// could still be running, and for a timerfd that callback touches the
/// descriptor the caller is about to release.
#[test]
fn freeing_stops_it() {
    let fired = counter();
    let id = timer_new(MONOTONIC, fired.clone());
    timer_set(
        id,
        Spec {
            value: ms(10),
            interval: ms(10),
        },
        None,
    );
    std::thread::sleep(std::time::Duration::from_millis(120));
    timer_free(id);
    let after_free = fired.get();
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(
        fired.get(),
        after_free,
        "it fired after being freed"
    );
}

/// A handle is an id, so using a stale one fails a lookup instead of
/// dereferencing freed memory.
#[test]
fn a_stale_handle_is_refused() {
    let id = timer_new(MONOTONIC, counter());
    timer_free(id);
    let mut got = Spec::default();
    assert_eq!(timer_get(id, &mut got), -22);
    assert_eq!(timer_set(id, Spec::default(), None), -22);
    timer_free(id); // and freeing twice is not a crash
}

/// A timer armed while the service thread is between "nothing is armed" and
/// its wait must still fire on time.
///
/// This is a **lost wakeup**, and the 60 seconds is where it shows. The service
/// loop computed how long to sleep, released the lock, took it again and then
/// waited — and in that gap another thread could arm a timer and
/// `WAKE.notify_all()` with nobody waiting. With nothing armed when the
/// deadline was computed, the fallback is a 60-second re-check, so a 60ms timer
/// fired 60 seconds late.
///
/// Found by `tests/guest/src/bin/timerfd_abi.rs` on 2026-09-09, failing
/// `not for ever: 60005ms` about **one run in twenty-five** — which is what
/// 60005 is: 60 seconds of fallback plus the 5ms the read actually needed.
///
/// The loop is what makes it a test rather than an observation: each iteration
/// waits for the timer to fire, which leaves the service with nothing armed, so
/// the next arming lands in exactly the window. Each iteration is bounded, so a
/// failure is a failure rather than a hang.
#[test]
fn a_timer_armed_while_the_service_is_idle_still_fires_on_time() {
    use std::time::{Duration, Instant};

    let fired = counter();
    let id = timer_new(0 /* CLOCK_REALTIME */, fired.clone());
    let ms = |n: i64| Spec {
        value: Timespec {
            sec: 0,
            nsec: n * 1_000_000,
        },
        interval: Timespec::default(),
    };

    for i in 0..400 {
        let before = fired.get();
        assert_eq!(timer_set(id, ms(1), None), 0);
        let started = Instant::now();
        while fired.get() == before {
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "iteration {i}: a 1ms timer had not fired after {}ms -- the \
                 service is asleep on its 60-second fallback",
                started.elapsed().as_millis()
            );
            std::thread::yield_now();
        }
    }
    timer_free(id);
}
