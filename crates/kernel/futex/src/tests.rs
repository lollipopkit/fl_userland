use super::*;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use kernel_sighand as _;
use kernel_sigqueue as _;

/// An address space for a test: an identity, and the host address its pages
/// answer.
///
/// **0 means "not a shared page"**, and that is the rule the whole keying rests
/// on: a private mapping is copy-on-write, so its host address changes the
/// first time the word is written, and a futex word is written by definition.
/// `crates/kernel/futexcalls` answers 0 unless the page carries `P_SHARED`.
///
/// This was a `GuestOps` installed once by whichever test ran first, reading a
/// static, and before that three `#[unsafe(no_mangle)]` stubs for the whole
/// test binary.
struct TestSpace {
    id: usize,
    shared_host: u64,
}

impl Space for TestSpace {
    fn id(&self) -> usize {
        self.id
    }
    fn read_word(&self, _addr: u64) -> Option<u32> {
        None
    }
    fn cmpxchg_word(&self, _addr: u64, _old: u32, _new: u32) -> Option<Result<(), u32>> {
        None
    }
    fn backing(&self, _addr: u64) -> Backing {
        match self.shared_host {
            0 => Backing::Private,
            host => Backing::Shared(host),
        }
    }
}

/// The identity a futex is looked up by, which is two rules and not one.
#[test]
fn a_shared_futex_is_one_futex_from_either_address_space() {
    let space_a = &TestSpace { id: 1, shared_host: 0 };
    let space_b = &TestSpace { id: 2, shared_host: 0 };

    // A private futex is the address space *and* the guest address, so two
    // processes waiting on the same guest address are two futexes -- which is
    // what a fork of a private mapping produces and what must not be merged.
    assert_ne!(
        key_of(space_a, Word { addr: 0x1000, private: true }).unwrap(),
        key_of(space_b, Word { addr: 0x1000, private: true }).unwrap()
    );
    assert_ne!(
        key_of(space_a, Word { addr: 0x1000, private: true }).unwrap(),
        key_of(space_a, Word { addr: 0x2000, private: true }).unwrap()
    );

    // A shared futex on a shared page is the page. Different address spaces
    // and even different guest addresses -- the same page can be mapped
    // anywhere -- are one futex.
    let shared_a = &TestSpace { id: 1, shared_host: 0xdead_0000 };
    let shared_b = &TestSpace { id: 2, shared_host: 0xdead_0000 };
    assert_eq!(
        key_of(shared_a, Word { addr: 0x1000, private: false }).unwrap(),
        key_of(shared_b, Word { addr: 0x9000, private: false }).unwrap()
    );
    // And never confused with a private one at the same number.
    assert_ne!(
        key_of(shared_a, Word { addr: 0x1000, private: false }).unwrap(),
        key_of(shared_a, Word { addr: 0x1000, private: true }).unwrap()
    );

    // A page that is not shared falls back to the address space, whatever the
    // flag said. This is Linux's rule -- get_futex_key uses the mm key unless
    // the mapping is VM_MAYSHARE -- and here it is also a correctness
    // requirement: keying a copy-on-write page on its host address made every
    // wake miss, because the waker's write moved the page.
    assert_eq!(
        key_of(space_a, Word { addr: 0x1000, private: false }).unwrap(),
        key_of(space_a, Word { addr: 0x1000, private: true }).unwrap()
    );
    assert_ne!(
        key_of(space_a, Word { addr: 0x1000, private: false }).unwrap(),
        key_of(space_b, Word { addr: 0x1000, private: false }).unwrap()
    );
}

/// A stand-in address space: one word, which is all a futex is.
///
/// `AtomicU32` because the real one is read atomically for the reason the C's
/// `futex_load` comment records — a futex word is the one word in a program
/// other threads are certainly CAS-ing.
#[derive(Default)]
struct TestWord {
    value: AtomicU32,
    mapped: std::sync::atomic::AtomicBool,
}

impl TestWord {
    fn at(v: u32) -> Arc<TestWord> {
        let w = Arc::new(TestWord::default());
        w.value.store(v, Ordering::SeqCst);
        w.mapped.store(true, Ordering::SeqCst);
        w
    }

    fn reader(self: &Arc<TestWord>) -> impl Fn() -> Option<u32> + use<> {
        let w = Arc::clone(self);
        move || {
            w.mapped
                .load(Ordering::SeqCst)
                .then(|| w.value.load(Ordering::SeqCst))
        }
    }
}

fn key(addr: u64) -> Key {
    Key { space: 1, addr }
}

fn table_() -> Arc<Table> {
    Arc::new(Table::new())
}

// --- the value check ----------------------------------------------------

#[test]
fn a_word_that_has_already_changed_is_eagain() {
    let t = table_();
    let w = TestWord::at(7);
    assert_eq!(t.wait(key(0x1000), 6, !0, None, &w.reader()), EAGAIN);
    assert_eq!(t.waiters_on(key(0x1000)), 0, "and nothing is queued");
}

#[test]
fn an_unmapped_word_is_efault() {
    let t = table_();
    let w = TestWord::at(7);
    w.mapped.store(false, Ordering::SeqCst);
    assert_eq!(t.wait(key(0x1000), 7, !0, None, &w.reader()), EFAULT);
}

#[test]
fn an_empty_bitset_is_einval() {
    let t = table_();
    let w = TestWord::at(7);
    assert_eq!(t.wait(key(0x1000), 7, 0, None, &w.reader()), EINVAL);
    assert_eq!(wake(&TestSpace { id: 1, shared_host: 0 }, Word { addr: 0, private: true }, 1, 0), Err(EINVAL));
}

// --- waking -------------------------------------------------------------

#[test]
fn waking_nobody_is_zero() {
    let t = table_();
    assert_eq!(t.wake(key(0x1000), 1, !0).unwrap(), 0);
}

#[test]
fn a_waiter_is_woken() {
    let t = table_();
    let w = TestWord::at(7);
    let waiter = {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        std::thread::spawn(move || t.wait(key(0x1000), 7, !0, None, &w.reader()))
    };

    // Wait for it to be parked, so the wake is not racing the enqueue.
    while t.waiters_on(key(0x1000)) == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(t.wake(key(0x1000), 1, !0).unwrap(), 1);
    assert_eq!(waiter.join().unwrap(), 0);
}

/// The thing a broadcast cannot do on its own.
#[test]
fn waking_one_of_three_wakes_exactly_one() {
    let t = table_();
    let w = TestWord::at(7);
    let mut waiters = Vec::new();
    for _ in 0..3 {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        waiters.push(std::thread::spawn(move || {
            t.wait(key(0x1000), 7, !0, Some(Instant::now() + Duration::from_secs(10)), &w.reader())
        }));
    }
    while t.waiters_on(key(0x1000)) < 3 {
        std::thread::sleep(Duration::from_millis(1));
    }

    assert_eq!(t.wake(key(0x1000), 1, !0).unwrap(), 1);
    // The other two are still parked, having rechecked and gone back to sleep.
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(t.waiters_on(key(0x1000)), 2);

    assert_eq!(t.wake(key(0x1000), 99, !0).unwrap(), 2, "and the rest go together");
    for h in waiters {
        assert_eq!(h.join().unwrap(), 0);
    }
}

#[test]
fn a_waiter_on_another_address_is_not_woken() {
    let t = table_();
    let w = TestWord::at(7);
    let waiter = {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        std::thread::spawn(move || {
            t.wait(key(0x1000), 7, !0, Some(Instant::now() + Duration::from_millis(200)), &w.reader())
        })
    };
    while t.waiters_on(key(0x1000)) == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(t.wake(key(0x2000), 99, !0).unwrap(), 0);
    assert_eq!(waiter.join().unwrap(), ETIMEDOUT, "it waited out its timeout");
}

/// One address space's futex is not another's, even at the same address.
#[test]
fn a_waiter_in_another_address_space_is_not_woken() {
    let t = table_();
    let w = TestWord::at(7);
    let waiter = {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        std::thread::spawn(move || {
            t.wait(
                Key { space: 1, addr: 0x1000 },
                7,
                !0,
                Some(Instant::now() + Duration::from_millis(200)),
                &w.reader(),
            )
        })
    };
    while t.waiters_on(key(0x1000)) == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(t.wake(Key { space: 2, addr: 0x1000 }, 99, !0).unwrap(), 0);
    assert_eq!(waiter.join().unwrap(), ETIMEDOUT);
}

#[test]
fn the_longest_waiting_goes_first() {
    let t = table_();
    let w = TestWord::at(7);
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    for i in 0..3u32 {
        let (tc, wc, oc) = (Arc::clone(&t), Arc::clone(&w), Arc::clone(&order));
        handles.push(std::thread::spawn(move || {
            let r = tc.wait(key(0x1000), 7, !0, Some(Instant::now() + Duration::from_secs(10)), &wc.reader());
            oc.lock().unwrap().push(i);
            r
        }));
        // Parked before the next one starts, so the queue order is the loop's.
        while t.waiters_on(key(0x1000)) < (i + 1) as usize {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    for expected in 0..3u32 {
        assert_eq!(t.wake(key(0x1000), 1, !0).unwrap(), 1);
        // Let it record itself before the next wake.
        while order.lock().unwrap().len() < (expected + 1) as usize {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            *order.lock().unwrap().last().unwrap(),
            expected,
            "waiters go in the order they arrived"
        );
    }
    for h in handles {
        assert_eq!(h.join().unwrap(), 0);
    }
}

// --- bitsets ------------------------------------------------------------

#[test]
fn a_wake_only_reaches_an_overlapping_bitset() {
    let t = table_();
    let w = TestWord::at(7);
    let waiter = {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        std::thread::spawn(move || {
            t.wait(key(0x1000), 7, 0b0010, Some(Instant::now() + Duration::from_secs(10)), &w.reader())
        })
    };
    while t.waiters_on(key(0x1000)) == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }

    assert_eq!(t.wake(key(0x1000), 99, 0b1101).unwrap(), 0, "no bit in common");
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(t.waiters_on(key(0x1000)), 1);

    assert_eq!(t.wake(key(0x1000), 99, 0b0011).unwrap(), 1, "one bit is enough");
    assert_eq!(waiter.join().unwrap(), 0);
}

#[test]
fn a_plain_wake_reaches_a_bitset_waiter() {
    let t = table_();
    let w = TestWord::at(7);
    let waiter = {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        std::thread::spawn(move || {
            t.wait(key(0x1000), 7, 0b0100, Some(Instant::now() + Duration::from_secs(10)), &w.reader())
        })
    };
    while t.waiters_on(key(0x1000)) == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }
    // FUTEX_WAKE is FUTEX_WAKE_BITSET with FUTEX_BITSET_MATCH_ANY.
    assert_eq!(t.wake(key(0x1000), 1, !0).unwrap(), 1);
    assert_eq!(waiter.join().unwrap(), 0);
}

// --- timeouts -----------------------------------------------------------

#[test]
fn a_timeout_is_etimedout() {
    let t = table_();
    let w = TestWord::at(7);
    let started = Instant::now();
    assert_eq!(
        t.wait(key(0x1000), 7, !0, Some(Instant::now() + Duration::from_millis(50)), &w.reader()),
        ETIMEDOUT
    );
    assert!(started.elapsed() >= Duration::from_millis(40));
    assert_eq!(t.waiters_on(key(0x1000)), 0, "and it left the queue");
}

/// A deadline, not a duration: wakeups meant for other waiters are normal here,
/// and re-arming the timeout on each one would make the call wait for ever
/// under load.
#[test]
fn other_peoples_wakeups_do_not_extend_the_deadline() {
    let t = table_();
    let w = TestWord::at(7);

    // A second waiter on another address, woken repeatedly, so the broadcast
    // reaches the one under test without being for it.
    let noise = {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        std::thread::spawn(move || {
            for _ in 0..6 {
                std::thread::sleep(Duration::from_millis(25));
                t.wake(key(0x2000), 99, !0).unwrap();
                let _ = &w;
            }
        })
    };

    let started = Instant::now();
    assert_eq!(
        t.wait(key(0x1000), 7, !0, Some(Instant::now() + Duration::from_millis(100)), &w.reader()),
        ETIMEDOUT
    );
    let waited = started.elapsed();
    noise.join().unwrap();
    assert!(
        waited < Duration::from_millis(200),
        "waited {waited:?}, which is the timeout re-armed rather than a deadline"
    );
}

// --- requeue ------------------------------------------------------------

#[test]
fn a_requeue_moves_waiters_without_waking_them() {
    let t = table_();
    let w = TestWord::at(7);
    let mut handles = Vec::new();
    for _ in 0..3 {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        handles.push(std::thread::spawn(move || {
            t.wait(key(0x1000), 7, !0, Some(Instant::now() + Duration::from_secs(10)), &w.reader())
        }));
    }
    while t.waiters_on(key(0x1000)) < 3 {
        std::thread::sleep(Duration::from_millis(1));
    }

    // Wake one, move the other two.
    assert_eq!(t.requeue(key(0x1000), key(0x2000), 1, 99, None).unwrap(), 3);
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(t.waiters_on(key(0x1000)), 0);
    assert_eq!(t.waiters_on(key(0x2000)), 2, "still parked, at the new address");

    // And they answer to the new address.
    assert_eq!(t.wake(key(0x2000), 99, !0).unwrap(), 2);
    for h in handles {
        assert_eq!(h.join().unwrap(), 0);
    }
}

#[test]
fn a_requeue_bound_moves_only_that_many() {
    let t = table_();
    let w = TestWord::at(7);
    let mut handles = Vec::new();
    for _ in 0..3 {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        handles.push(std::thread::spawn(move || {
            t.wait(key(0x1000), 7, !0, Some(Instant::now() + Duration::from_secs(10)), &w.reader())
        }));
    }
    while t.waiters_on(key(0x1000)) < 3 {
        std::thread::sleep(Duration::from_millis(1));
    }

    assert_eq!(t.requeue(key(0x1000), key(0x2000), 0, 1, None).unwrap(), 1, "none woken, one moved");
    assert_eq!(t.waiters_on(key(0x1000)), 2);
    assert_eq!(t.waiters_on(key(0x2000)), 1);

    assert_eq!(t.wake(key(0x1000), 99, !0).unwrap(), 2);
    assert_eq!(t.wake(key(0x2000), 99, !0).unwrap(), 1);
    for h in handles {
        assert_eq!(h.join().unwrap(), 0);
    }
}

#[test]
fn requeueing_to_the_same_address_is_a_no_op_that_still_wakes() {
    let t = table_();
    let w = TestWord::at(7);
    let waiter = {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        std::thread::spawn(move || {
            t.wait(key(0x1000), 7, !0, Some(Instant::now() + Duration::from_secs(10)), &w.reader())
        })
    };
    while t.waiters_on(key(0x1000)) == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(t.requeue(key(0x1000), key(0x1000), 1, 99, None).unwrap(), 1);
    assert_eq!(waiter.join().unwrap(), 0);
}

// --- the shape the whole thing exists for -------------------------------

/// The wake must not be able to land between the comparison and the enqueue.
///
/// A waker that changed the word and woke in that window would find nobody, and
/// this thread would then sleep on a value that had already moved. The window
/// is closed by holding the queue lock across both, and this drives a waker at
/// the only instant it could exist: from inside the read.
///
/// It has to be another thread, because taking the queue lock is exactly what a
/// waker does and this call is holding it. The first version of this test
/// called `wake` directly from the reader and **deadlocked** — which is the
/// invariant holding, but is not an assertion.
#[test]
fn a_wake_cannot_slip_between_the_check_and_the_enqueue() {
    let t = table_();
    let w = TestWord::at(7);
    // 0 while the waker is still going, otherwise one more than what it woke.
    let woke = Arc::new(AtomicU32::new(0));

    let racing_read = {
        let (t, w, woke) = (Arc::clone(&t), Arc::clone(&w), Arc::clone(&woke));
        move || {
            let seen = w.value.load(Ordering::SeqCst);
            // What a waker does, in the order it does it.
            w.value.store(seen + 1, Ordering::SeqCst);
            let (t, woke) = (Arc::clone(&t), Arc::clone(&woke));
            std::thread::spawn(move || {
                let n = t.wake(key(0x1000), 99, !0).unwrap();
                woke.store(n + 1, Ordering::SeqCst);
            });
            // Long enough for it to get as far as it can, which is the lock
            // this call is holding.
            std::thread::sleep(Duration::from_millis(20));
            seen
        }
    };

    let started = Instant::now();
    let r = t.wait(
        key(0x1000),
        7,
        !0,
        Some(Instant::now() + Duration::from_secs(5)),
        &move || Some(racing_read()),
    );
    assert_eq!(r, 0, "woken, not timed out");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "and promptly: a lost wakeup shows up as the full timeout"
    );

    while woke.load(Ordering::SeqCst) == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        woke.load(Ordering::SeqCst),
        2,
        "the waker found one waiter, so it ran after the enqueue and not before"
    );
}

// --- a wake that races the deadline -------------------------------------

/// A waiter a waker took is woken, even if its timeout expired first.
///
/// `wake` removes the waiter from the queue and counts it in the number it
/// returns to its own guest thread. If the waiter then answers `ETIMEDOUT`, the
/// two disagree about whether anything happened and the wake is gone: one
/// thread has been told it handed off and the other has been told to give up.
/// For a guest lock or condition variable that is a thread parked for ever.
///
/// **Forced, not raced.** The first version of this test slept in the waker and
/// hoped; the waker always got there after the waiter had already given up and
/// left the queue, so `woken` was 0, the interesting assertion never applied,
/// and it passed against the bug. `wake_after_holding` takes the queue lock
/// *first* and holds it past the deadline: `pthread_cond_timedwait` expires,
/// then blocks re-acquiring the mutex until the take has run. The waiter comes
/// back with `TimedOut` and is no longer in the queue, which is exactly the
/// case.
#[test]
fn a_wake_that_lands_on_an_expired_deadline_is_still_a_wake() {
    let t = table_();
    let w = TestWord::at(7);

    let waker = {
        let t = Arc::clone(&t);
        std::thread::spawn(move || {
            // Long enough that the waiter is parked and has released the
            // queue, and well short of its 100ms deadline -- the two must not
            // coincide, or the waiter re-acquires first and the waker finds
            // nobody, which is what the first attempt did.
            std::thread::sleep(Duration::from_millis(20));
            // Takes the lock and holds it from 20ms to 220ms, so the waiter's
            // deadline falls inside the window.
            t.wake_after_holding(key(0x1000), 1, Duration::from_millis(200))
        })
    };

    let res = t.wait(
        key(0x1000),
        7,
        !0,
        Some(Instant::now() + Duration::from_millis(100)),
        &w.reader(),
    );
    let woken = waker.join().unwrap();

    assert_eq!(woken, 1, "the waker has to find it, or this proves nothing");
    assert_eq!(
        res, 0,
        "taken from the queue, so it was woken -- ETIMEDOUT here loses the wake"
    );
    assert_eq!(t.waiters_on(key(0x1000)), 0, "and nothing is left queued");
}

// --- futex_waitv ----------------------------------------------------------

fn entry(addr: u64) -> Entry {
    Entry { key: key(addr), bitset: !0 }
}

fn wait_until_parked(t: &Table, k: Key, n: usize) {
    while t.waiters_on(k) < n {
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// The index a vector wait answers is the entry that was woken, which a
/// waker removing the waiter could not have told it.
#[test]
fn a_vector_wait_answers_the_index_that_was_woken() {
    for which in [0x1000u64, 0x2000, 0x3000] {
        let t = table_();
        let waiter = {
            let t = Arc::clone(&t);
            std::thread::spawn(move || {
                let es = [entry(0x1000), entry(0x2000), entry(0x3000)];
                t.wait_any(&es, &|| Ok(()), Some(Instant::now() + Duration::from_secs(10)))
            })
        };
        wait_until_parked(&t, key(which), 1);
        assert_eq!(t.wake(key(which), 1, !0), Ok(1));
        let want = ((which >> 12) - 1) as usize;
        assert_eq!(waiter.join().unwrap(), Ok(want));
        // One waiter on three words is one waiter: a wake on another of its
        // words afterwards finds nobody.
        assert_eq!(t.wake(key(0x1000), 9, !0), Ok(0));
        assert_eq!(t.wake(key(0x2000), 9, !0), Ok(0));
    }
}

/// A vector waiter is woken once, by whichever of its words is woken first;
/// a second wake on another of its words must not count it again.
#[test]
fn a_vector_waiter_counts_once() {
    let t = table_();
    let waiter = {
        let t = Arc::clone(&t);
        std::thread::spawn(move || {
            t.wait_any(&[entry(0x1000), entry(0x2000)], &|| Ok(()), Some(Instant::now() + Duration::from_secs(10)))
        })
    };
    wait_until_parked(&t, key(0x1000), 1);
    let first = t.wake(key(0x2000), 1, !0);
    let second = t.wake(key(0x1000), 1, !0);
    assert_eq!((first, second), (Ok(1), Ok(0)));
    assert_eq!(waiter.join().unwrap(), Ok(1));
}

#[test]
fn a_vector_wait_that_fails_its_check_parks_nothing() {
    let t = table_();
    assert_eq!(t.wait_any(&[entry(0x1000), entry(0x2000)], &|| Err(EAGAIN), None), Err(EAGAIN));
    assert_eq!(t.waiters_on(key(0x1000)), 0);
    assert_eq!(t.waiters_on(key(0x2000)), 0);
}

// --- requeue with the comparison under the lock ---------------------------

#[test]
fn a_requeue_whose_check_fails_moves_and_wakes_nothing() {
    let t = table_();
    let w = TestWord::at(7);
    let waiter = {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        std::thread::spawn(move || t.wait(key(0x1000), 7, !0, Some(Instant::now() + Duration::from_millis(300)), &w.reader()))
    };
    wait_until_parked(&t, key(0x1000), 1);
    assert_eq!(t.requeue(key(0x1000), key(0x2000), 1, 9, Some(&|| Err(EAGAIN))), Err(EAGAIN));
    assert_eq!(t.waiters_on(key(0x1000)), 1, "still where it was");
    assert_eq!(waiter.join().unwrap(), ETIMEDOUT);
}

// --- PI -------------------------------------------------------------------

/// A PI word for the tests: an atomic, mapped.
struct Pi(AtomicU32);

impl PiWord for Pi {
    fn read(&self) -> Option<u32> {
        Some(self.0.load(Ordering::SeqCst))
    }
    fn cmpxchg(&self, old: u32, new: u32) -> Option<Result<(), u32>> {
        Some(self.0.compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst).map(|_| ()))
    }
}

fn pi(v: u32) -> Arc<Pi> {
    Arc::new(Pi(AtomicU32::new(v)))
}

fn everyone_alive(_: u32) -> bool {
    true
}

#[test]
fn lock_pi_on_a_free_word_takes_it_and_unlock_releases_it() {
    let t = table_();
    let w = pi(0);
    assert_eq!(t.lock_pi(key(0x1000), 42, &*w, &everyone_alive, None, false), 0);
    assert_eq!(w.0.load(Ordering::SeqCst), 42);
    assert_eq!(t.lock_pi(key(0x1000), 42, &*w, &everyone_alive, None, false), EDEADLK);
    assert_eq!(t.lock_pi(key(0x1000), 42, &*w, &everyone_alive, None, true), EDEADLK);
    assert_eq!(t.unlock_pi(key(0x1000), 7, &*w), EPERM, "not the owner");
    assert_eq!(t.unlock_pi(key(0x1000), 42, &*w), 0);
    assert_eq!(w.0.load(Ordering::SeqCst), 0);
    assert_eq!(t.unlock_pi(key(0x1000), 42, &*w), EPERM, "not held");
}

#[test]
fn trylock_pi_on_a_held_word_is_eagain_or_esrch() {
    let t = table_();
    let w = pi(9);
    assert_eq!(t.lock_pi(key(0x1000), 42, &*w, &everyone_alive, None, true), EAGAIN);
    assert_eq!(t.lock_pi(key(0x1000), 42, &*w, &|_| false, None, true), ESRCH);
    // Linux sets the bit before it looks at the owner, a trylock included.
    assert_eq!(w.0.load(Ordering::SeqCst), 9 | FUTEX_WAITERS);
    // A blocking lock behind a dead owner nobody waits behind says so.
    assert_eq!(t.lock_pi(key(0x1000), 42, &*w, &|_| false, None, false), ESRCH);
    assert_eq!(w.0.load(Ordering::SeqCst), 9 | FUTEX_WAITERS);
}

/// The handoff: an unlock with a waiter writes the waiter's tid and
/// `FUTEX_WAITERS`, and the waiter returns owning it.
#[test]
fn unlock_pi_hands_the_lock_to_the_oldest_waiter() {
    let t = table_();
    let w = pi(0);
    assert_eq!(t.lock_pi(key(0x1000), 1, &*w, &everyone_alive, None, false), 0);
    let waiters: Vec<_> = (2..=3)
        .map(|tid| {
            let (tt, ww) = (Arc::clone(&t), Arc::clone(&w));
            let h = std::thread::spawn(move || {
                let r = tt.lock_pi(key(0x1000), tid, &*ww, &everyone_alive, Some(Instant::now() + Duration::from_secs(10)), false);
                // Owning it now: hand it on.
                let owned = ww.0.load(Ordering::SeqCst) & FUTEX_TID_MASK == tid;
                assert_eq!(tt.unlock_pi(key(0x1000), tid, &*ww), 0);
                (r, owned)
            });
            wait_until_parked(&t, key(0x1000), (tid - 1) as usize);
            h
        })
        .collect();
    assert_eq!(w.0.load(Ordering::SeqCst), 1 | FUTEX_WAITERS);
    assert_eq!(t.unlock_pi(key(0x1000), 1, &*w), 0);
    for h in waiters {
        assert_eq!(h.join().unwrap(), (0, true));
    }
    assert_eq!(w.0.load(Ordering::SeqCst), 0);
}

#[test]
fn a_pi_lock_times_out_behind_a_live_owner() {
    let t = table_();
    let w = pi(5);
    let started = Instant::now();
    let r = t.lock_pi(key(0x1000), 42, &*w, &everyone_alive, Some(Instant::now() + Duration::from_millis(30)), false);
    assert_eq!(r, ETIMEDOUT);
    assert!(started.elapsed() >= Duration::from_millis(25));
    assert_eq!(t.waiters_on(key(0x1000)), 0);
}

/// An owner that exits holding the lock hands it to the waiter parked behind
/// it, which takes it over -- keeping `FUTEX_OWNER_DIED` if a robust-list walk
/// set it.
#[test]
fn an_owner_that_exits_hands_the_lock_to_its_waiter() {
    let t = table_();
    let w = pi(77);
    let waiter = {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        std::thread::spawn(move || t.lock_pi(key(0x1000), 42, &*w, &everyone_alive, Some(Instant::now() + Duration::from_secs(10)), false))
    };
    wait_until_parked(&t, key(0x1000), 1);
    t.owner_exited(76);
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(t.waiters_on(key(0x1000)), 1, "another thread's exit is not this owner's");
    t.owner_exited(77);
    assert_eq!(waiter.join().unwrap(), 0);
    assert_eq!(w.0.load(Ordering::SeqCst), 42 | FUTEX_WAITERS);

    // The robust shape: the walk cleared the tid and set OWNER_DIED first.
    let w = pi(78);
    let waiter = {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        std::thread::spawn(move || t.lock_pi(key(0x2000), 43, &*w, &everyone_alive, Some(Instant::now() + Duration::from_secs(10)), false))
    };
    wait_until_parked(&t, key(0x2000), 1);
    w.0.store(FUTEX_WAITERS | FUTEX_OWNER_DIED, Ordering::SeqCst);
    t.owner_exited(78);
    assert_eq!(waiter.join().unwrap(), 0);
    assert_eq!(w.0.load(Ordering::SeqCst), 43 | FUTEX_OWNER_DIED);
}

/// A plain wake that reaches a PI waiter is `EINVAL`, which is Linux's
/// refusal to mix the two kinds on one word.
#[test]
fn a_plain_wake_on_a_pi_word_is_einval() {
    let t = table_();
    let w = pi(5);
    let waiter = {
        let (t, w) = (Arc::clone(&t), Arc::clone(&w));
        std::thread::spawn(move || t.lock_pi(key(0x1000), 42, &*w, &everyone_alive, Some(Instant::now() + Duration::from_millis(200)), false))
    };
    wait_until_parked(&t, key(0x1000), 1);
    assert_eq!(t.wake(key(0x1000), 1, !0), Err(EINVAL));
    assert_eq!(t.requeue(key(0x1000), key(0x2000), 0, 1, None), Err(EINVAL));
    assert_eq!(waiter.join().unwrap(), ETIMEDOUT);
}

/// The condition variable glibc builds on PI: `FUTEX_WAIT_REQUEUE_PI` on the
/// condition, `FUTEX_CMP_REQUEUE_PI` onto the mutex. A free mutex is taken
/// for the top waiter; behind a held one the waiters are moved and handed it
/// one at a time by the unlocks.
#[test]
fn requeue_pi_takes_a_free_mutex_or_queues_behind_a_held_one() {
    let t = table_();
    let cond = TestWord::at(0);
    let m = pi(0);
    let spawn = |tid: u32| {
        let (t, cond, m) = (Arc::clone(&t), Arc::clone(&cond), Arc::clone(&m));
        std::thread::spawn(move || {
            let r = t.wait_requeue_pi(
                key(0x1000),
                0,
                key(0x2000),
                tid,
                &cond.reader(),
                &*m,
                &everyone_alive,
                Some(Instant::now() + Duration::from_secs(10)),
            );
            let owned = m.0.load(Ordering::SeqCst) & FUTEX_TID_MASK == tid;
            assert_eq!(t.unlock_pi(key(0x2000), tid, &*m), 0);
            (r, owned)
        })
    };
    let a = spawn(10);
    wait_until_parked(&t, key(0x1000), 1);
    let b = spawn(11);
    wait_until_parked(&t, key(0x1000), 2);
    // A plain wake cannot reach them.
    assert_eq!(t.wake(key(0x1000), 1, !0), Err(EINVAL));
    // Wrong target.
    assert_eq!(t.cmp_requeue_pi(key(0x1000), key(0x3000), 1, &|| Ok(()), &*m, &everyone_alive), Err(EINVAL));
    // The mutex is held by 1: both are moved behind it.
    m.0.store(1, Ordering::SeqCst);
    assert_eq!(t.cmp_requeue_pi(key(0x1000), key(0x2000), 9, &|| Ok(()), &*m, &everyone_alive), Ok(2));
    assert_eq!(m.0.load(Ordering::SeqCst), 1 | FUTEX_WAITERS);
    assert_eq!(t.waiters_on(key(0x2000)), 2);
    assert_eq!(t.unlock_pi(key(0x2000), 1, &*m), 0);
    assert_eq!(a.join().unwrap(), (0, true));
    assert_eq!(b.join().unwrap(), (0, true));
    assert_eq!(m.0.load(Ordering::SeqCst), 0);

    // And a free mutex is taken for the top waiter at once.
    let c = spawn(12);
    wait_until_parked(&t, key(0x1000), 1);
    assert_eq!(t.cmp_requeue_pi(key(0x1000), key(0x2000), 0, &|| Ok(()), &*m, &everyone_alive), Ok(1));
    assert_eq!(c.join().unwrap(), (0, true));
}

/// Mutual exclusion under contention: every thread increments a plain counter
/// inside the PI lock, and no increment is lost.
#[test]
fn pi_locking_is_mutual_exclusion_under_contention() {
    let t = table_();
    let w = pi(0);
    let counter = Arc::new(AtomicU32::new(0));
    let threads: Vec<_> = (1..=8u32)
        .map(|tid| {
            let (t, w, counter) = (Arc::clone(&t), Arc::clone(&w), Arc::clone(&counter));
            std::thread::spawn(move || {
                for _ in 0..500 {
                    // The userspace fast path, then the kernel.
                    if w.0.compare_exchange(0, tid, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                        assert_eq!(t.lock_pi(key(0x1000), tid, &*w, &everyone_alive, None, false), 0);
                    }
                    assert_eq!(w.0.load(Ordering::SeqCst) & FUTEX_TID_MASK, tid, "owned by this thread");
                    let v = counter.load(Ordering::Relaxed);
                    std::hint::spin_loop();
                    counter.store(v + 1, Ordering::Relaxed);
                    if w.0.compare_exchange(tid, 0, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                        assert_eq!(t.unlock_pi(key(0x1000), tid, &*w), 0);
                    }
                }
            })
        })
        .collect();
    for h in threads {
        h.join().unwrap();
    }
    assert_eq!(counter.load(Ordering::SeqCst), 8 * 500);
    assert_eq!(w.0.load(Ordering::SeqCst), 0);
    assert_eq!(t.waiters_on(key(0x1000)), 0);
}
