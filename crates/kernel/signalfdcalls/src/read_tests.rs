use super::read::read;
use guest_errno::c_int_::{EAGAIN, EINTR, EINVAL};
use kernel_sighand::{Queue, SigHand};
use kernel_sigqueue::{SigInfo, Signals};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

/// A test's queue, as [`read`] takes one.
fn qu<'a>(sh: &'a SigHand, q: &'a mut Signals) -> Queue<'a> {
    // SAFETY: the test owns `q` for the call, and `sh` is the lock it uses.
    unsafe { Queue::new(sh, q, Box::leak(Box::default())) }
}

const RECORD: usize = 128;

fn sighand() -> Arc<SigHand> {
    SigHand::new()
}

/// The signal number a record reports, out of the encoded bytes.
///
/// `signalfd_siginfo`'s first field is `ssi_signo`, a `u32`.
fn record_signo(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn queued(sig: i32) -> SigInfo {
    SigInfo {
        sig,
        ..Default::default()
    }
}

/// An address another thread also uses, always under sighand's lock.
struct QueuePtr(usize);

#[test]
fn a_buffer_shorter_than_one_record_is_einval() {
    let sh = sighand();
    let mut q = Signals::default();
    let mask = AtomicU64::new(!0);
    let mut out = [0u8; RECORD - 1];
    assert_eq!(
        read(qu(&sh, &mut q), &mask, true, &mut out),
        EINVAL as isize
    );
}

#[test]
fn a_queued_signal_is_one_record() {
    let sh = sighand();
    let mut q = Signals::default();
    q.set_blocked(kernel_sigqueue::mask_of(10));
    q.arrive(10, queued(10), true);

    let mask = AtomicU64::new(kernel_sigqueue::mask_of(10));
    let mut out = [0u8; RECORD * 4];
    assert_eq!(
        read(qu(&sh, &mut q), &mask, false, &mut out),
        RECORD as isize
    );
    assert_eq!(record_signo(&out), 10);
}

#[test]
fn as_many_records_as_fit_come_out_at_once() {
    let sh = sighand();
    let mut q = Signals::default();
    q.set_blocked(!0);
    // Not 10, 11, 12: 11 is SIGSEGV, which the queue hands out ahead of
    // every other signal -- Linux's `next_signal`, which signalfd reads
    // through too -- and this test is about how many come out, not which.
    for sig in [10, 12, 13] {
        q.arrive(sig, queued(sig), true);
    }

    let mask = AtomicU64::new(!0);
    // Room for two of the three.
    let mut out = [0u8; RECORD * 2];
    assert_eq!(
        read(qu(&sh, &mut q), &mask, false, &mut out),
        (RECORD * 2) as isize
    );
    assert_eq!(record_signo(&out[..RECORD]), 10);
    assert_eq!(record_signo(&out[RECORD..]), 12);

    // And the third is still there.
    let mut out = [0u8; RECORD];
    assert_eq!(
        read(qu(&sh, &mut q), &mask, false, &mut out),
        RECORD as isize
    );
    assert_eq!(record_signo(&out), 13);
}

#[test]
fn a_signal_outside_the_mask_is_not_reported() {
    let sh = sighand();
    let mut q = Signals::default();
    q.set_blocked(!0);
    q.arrive(11, queued(11), true);

    let mask = AtomicU64::new(kernel_sigqueue::mask_of(10));
    let mut out = [0u8; RECORD];
    assert_eq!(
        read(qu(&sh, &mut q), &mask, true, &mut out),
        EAGAIN as isize
    );
    assert!(
        q.pending() & kernel_sigqueue::mask_of(11) != 0,
        "still queued"
    );
}

#[test]
fn an_empty_queue_on_a_nonblocking_descriptor_is_eagain() {
    let sh = sighand();
    let mut q = Signals::default();
    let mask = AtomicU64::new(!0);
    let mut out = [0u8; RECORD];
    let started = Instant::now();
    assert_eq!(
        read(qu(&sh, &mut q), &mask, true, &mut out),
        EAGAIN as isize
    );
    assert!(started.elapsed() < Duration::from_secs(1), "did not wait");
}

#[test]
fn a_blocking_read_waits_for_a_signal() {
    let sh = sighand();
    let mut q = Signals::default();
    q.set_blocked(kernel_sigqueue::mask_of(10));
    let mask = AtomicU64::new(kernel_sigqueue::mask_of(10));

    let ptr = QueuePtr(&mut q as *mut Signals as usize);
    let sender = {
        let sh = Arc::clone(&sh);
        std::thread::spawn(move || {
            let ptr = ptr;
            std::thread::sleep(Duration::from_millis(30));
            {
                let mut guard = unsafe { sh.lock_queue(ptr.0 as *mut Signals, Box::leak(Box::default())) };
                guard.queue_mut().arrive(10, queued(10), true);
            }
            sh.notify();
        })
    };

    let mut out = [0u8; RECORD];
    assert_eq!(
        read(qu(&sh, &mut q), &mask, false, &mut out),
        RECORD as isize
    );
    sender.join().unwrap();
    assert_eq!(record_signo(&out), 10);
}

/// The mask is reloaded on every pass, because `signalfd4` can retarget a
/// descriptor another thread is parked on.
#[test]
fn a_retarget_during_the_wait_is_seen() {
    let sh = sighand();
    let mut q = Signals::default();
    q.set_blocked(!0);
    // Nothing at first.
    let mask = Arc::new(AtomicU64::new(kernel_sigqueue::mask_of(10)));

    let ptr = QueuePtr(&mut q as *mut Signals as usize);
    let sender = {
        let sh = Arc::clone(&sh);
        let mask = Arc::clone(&mask);
        std::thread::spawn(move || {
            let ptr = ptr;
            std::thread::sleep(Duration::from_millis(30));
            {
                let mut guard = unsafe { sh.lock_queue(ptr.0 as *mut Signals, Box::leak(Box::default())) };
                // A signal the descriptor does *not* watch yet...
                guard.queue_mut().arrive(11, queued(11), true);
                // ...and then it does.
                mask.store(
                    kernel_sigqueue::mask_of(11),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
            sh.notify();
        })
    };

    let mut out = [0u8; RECORD];
    assert_eq!(
        read(qu(&sh, &mut q), &mask, false, &mut out),
        RECORD as isize
    );
    sender.join().unwrap();
    assert_eq!(record_signo(&out), 11);
}

/// The dequeue happens before the interruption is judged, which is Linux's
/// order: a read that had an answer must not report that it did not.
///
/// The lock's test primitive never reports an interruption — there are no
/// guest signals in a unit test — so this drives the same path with a notify
/// and a signal that arrives together.
#[test]
fn a_wakeup_with_a_matching_signal_returns_the_signal() {
    let sh = sighand();
    let mut q = Signals::default();
    q.set_blocked(!0);
    let mask = AtomicU64::new(kernel_sigqueue::mask_of(10));

    let ptr = QueuePtr(&mut q as *mut Signals as usize);
    let sender = {
        let sh = Arc::clone(&sh);
        std::thread::spawn(move || {
            let ptr = ptr;
            std::thread::sleep(Duration::from_millis(20));
            {
                let mut guard = unsafe { sh.lock_queue(ptr.0 as *mut Signals, Box::leak(Box::default())) };
                // One the descriptor wants and one it does not, at once.
                guard.queue_mut().arrive(10, queued(10), true);
                guard.queue_mut().arrive(15, queued(15), true);
            }
            sh.notify();
        })
    };

    let mut out = [0u8; RECORD];
    assert_eq!(
        read(qu(&sh, &mut q), &mask, false, &mut out),
        RECORD as isize
    );
    sender.join().unwrap();
    assert_eq!(record_signo(&out), 10);
    assert!(
        q.pending() & kernel_sigqueue::mask_of(15) != 0,
        "the other one is untouched"
    );
    let _ = EINTR;
}

/// `waiting` is restored, not zeroed: `sigtimedwait` uses the same field and a
/// handler can nest the two.
#[test]
fn the_waiting_mask_is_put_back() {
    let sh = sighand();
    let mut q = Signals::default();
    let outer = kernel_sigqueue::mask_of(20);
    q.set_waiting(outer);
    q.set_blocked(kernel_sigqueue::mask_of(10));
    q.arrive(10, queued(10), true);

    let mask = AtomicU64::new(kernel_sigqueue::mask_of(10));
    let mut out = [0u8; RECORD];
    assert_eq!(
        read(qu(&sh, &mut q), &mask, false, &mut out),
        RECORD as isize
    );
    assert_eq!(q.waiting(), outer, "the outer wait's set is back");
}
