//! The queue of filesystem changes an embedder is told about.
//!
//! fakefs's write paths call `fakefs_record_change(path, op)`; a host consumer
//! is woken and drains what has accumulated. This crate is the queue: what is
//! in it, what happens when it is full, and what each record says. The waking
//! stays in C, because it is a dispatch source and a Clang block — a contract
//! with the host, like the console driver the terminal left behind.
//!
//! Four things it changes from the ring it replaces.
//!
//! **The timestamp was not nanoseconds.** The field is `timestamp_ns` and it
//! held `mach_absolute_time()`, which on Apple Silicon is a 24 MHz counter: the
//! timebase is 125/3, so a 100 ms interval was reported as 2 520 562. Every
//! device this fork targets is Apple Silicon, so every embedder computing an
//! age from that field was 41.67× low. The header said `/* raw ticks */`, which
//! documents the discrepancy rather than removing it. It is real nanoseconds
//! now, from the same clock: `CLOCK_UPTIME_RAW` on Darwin is
//! `mach_absolute_time` converted, and `CLOCK_MONOTONIC` elsewhere.
//!
//! **It was Apple-only.** The ring, the drop counter and the truncation rule
//! were all inside `#if defined(__APPLE__)`, and every other platform got three
//! functions that did nothing — so a Linux build silently dropped every event
//! and `fakefs_change_dropped_count()` reported none had been dropped. Only the
//! dispatch source needs to be Apple-only, and it still is.
//!
//! **It cost a megabyte, always.** The ring was 1024 records of 1048 bytes,
//! statically allocated, whether or not anything ever consumed one. A record
//! holds the path it needs; the 1024-byte array exists in the struct the
//! consumer is handed, not in the queue.
//!
//! **Installing a consumer raced with itself.** `g_change_consumer_source` was
//! a plain pointer, written by the installer and read by every producer with no
//! synchronisation, and two concurrent installs both saw NULL and both built a
//! queue. Whether anyone is listening is one `AtomicBool` here, and C's
//! installer claims it with a compare-exchange.
//!
//! What is kept, because both were arrived at the hard way: a path that does not
//! fit the record is **dropped and counted** rather than truncated, since the
//! prefix of `/a/b/verylong/file` is `/a/b/verylong`, which usually names a
//! directory that exists and is not the thing that changed; and the check
//! happens before the queue is touched, so an event that cannot be recorded does
//! not evict one that can.

//! # `as i64` on a host `libc` field is not redundant
//!
//! `clippy::unnecessary_cast` reports the `time_t` and `suseconds_t` casts
//! here because those are already `i64` on this target. They are `i32` on a
//! 32-bit host, which this tree compiles on — `differential.sh` runs the
//! guest tests in a Linux container and the host tools build wherever they
//! are. The lint sees one target.
#![allow(clippy::unnecessary_cast)]

use std::collections::VecDeque;
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// How many events are held before the oldest is dropped.
///
/// The same 1024 the ring had. It is a bound on how far behind a consumer may
/// fall, not a buffer that is allocated up front.
pub const CAPACITY: usize = 1024;

/// The path field in the record a consumer is handed, including its NUL.
pub const PATH_MAX: usize = 1024;

/// `struct fakefs_change_event` in `fs/fake.h`. The layout is the contract with
/// the embedder, so it is asserted below rather than described.
mod consumer;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub linux_path: [c_char; PATH_MAX],
    pub op: c_int,
    pub timestamp_ns: i64,
    pub fs_context: u64,
}

const _: () = {
    assert!(std::mem::size_of::<Event>() == 1048);
    assert!(std::mem::align_of::<Event>() == 8);
};

/// What is actually held while the event waits: the path as it was given, with
/// no padding to 1024. A queue of these is about 90 KB for a full 1024 events
/// of average-length paths, against the megabyte the fixed ring cost whether or
/// not anything was ever recorded.
struct Pending {
    path: Box<[u8]>,
    op: c_int,
    timestamp_ns: i64,
    fs_context: u64,
}

struct Queue {
    events: VecDeque<Pending>,
}

fn queue() -> &'static Mutex<Queue> {
    static Q: OnceLock<Mutex<Queue>> = OnceLock::new();
    Q.get_or_init(|| {
        Mutex::new(Queue {
            events: VecDeque::new(),
        })
    })
}

/// Whether a consumer is installed. Producers read it before doing any work,
/// which is the whole cost of this feature when nobody has asked for it.
static LISTENING: AtomicBool = AtomicBool::new(false);
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Monotonic nanoseconds, from the clock that does not run while the device is
/// asleep — which is what `mach_absolute_time` counts, so the meaning of the
/// field is unchanged and only its unit is fixed.
///
/// **Deliberately not [`util_timeabi::monotonic_ns`].** Five other crates had
/// a private `now_ns` and became that one on 2026-09-15; this is the sixth and
/// stays, because it asks a *different clock*. `CLOCK_UPTIME_RAW` excludes
/// time the device spent asleep and `CLOCK_MONOTONIC` on Darwin does not, and
/// an embedder reads this field to order change events across a suspend. The
/// note is here so that the next sweep for duplicate `now_ns` finds a reason
/// rather than a sixth copy.
fn now_ns() -> i64 {
    const CLOCK: libc::clockid_t = libc::CLOCK_UPTIME_RAW;

    let Ok((sec, nsec)) = util_timeabi::host_clock(CLOCK) else {
        return 0;
    };
    sec.saturating_mul(1_000_000_000).saturating_add(nsec)
}

/// Claim the consumer slot. `true` if this caller got it and should build the
/// wakeup machinery; `false` if one is already installed.
///
/// Release ordering, and `is_listening` acquires: a producer that sees the flag
/// set therefore sees everything the installer wrote before setting it, which
/// is what the plain pointer this replaces did not give.
pub(crate) fn claim_listener() -> bool {
    LISTENING
        .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)
        .is_ok()
}

pub(crate) fn is_listening() -> bool {
    LISTENING.load(Ordering::Acquire)
}

/// Record a change. `path` is the guest path, without a NUL.
pub fn record(path: &[u8], op: c_int, fs_context: u64) {
    // A path that does not fit the record a consumer is handed is not a
    // shorter answer, it is a different one. Counted, and counted *before* the
    // queue is touched so it does not evict an event that could have been
    // delivered. A path with a NUL in it is the same case: what the consumer
    // would read is a prefix.
    if path.len() >= PATH_MAX || path.contains(&0) {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let pending = Pending {
        path: path.to_vec().into_boxed_slice(),
        op,
        timestamp_ns: now_ns(),
        fs_context,
    };

    let Ok(mut q) = queue().lock() else { return };
    if q.events.len() >= CAPACITY {
        q.events.pop_front();
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
    q.events.push_back(pending);
}

/// Move up to `out.len()` events into `out`, oldest first. Returns how many.
pub fn drain(out: &mut [Event]) -> usize {
    let Ok(mut q) = queue().lock() else { return 0 };
    let n = out.len().min(q.events.len());
    for slot in out.iter_mut().take(n) {
        let e = q.events.pop_front().expect("n is at most the length");
        // Zeroed in full rather than only up to the NUL: the record goes to
        // another process's address space and the tail of a reused buffer is
        // not this kernel's to disclose.
        slot.linux_path = [0; PATH_MAX];
        for (dst, src) in slot.linux_path.iter_mut().zip(e.path.iter()) {
            *dst = *src as c_char;
        }
        slot.op = e.op;
        slot.timestamp_ns = e.timestamp_ns;
        slot.fs_context = e.fs_context;
    }
    n
}

/// How many events have been dropped since boot, for either reason.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// How many are waiting. For `/proc/iul/objects` and for tests; a queue that
/// only ever grows is the failure this makes visible.
pub fn depth() -> usize {
    queue().lock().map(|q| q.events.len()).unwrap_or(0)
}

// ---- the C boundary ----------------------------------------------------
//
// Two symbols an embedder names: `fakefs_record_change`, which every fakefs
// write path calls, and `fakefs_install_change_consumer`, in `consumer`. The
// six `fakechange_*` wrappers that stood here existed for `fs/fake.c` and went
// with it on 2026-09-04; `/proc/iul/objects` reads the depth and the drop
// count as Rust.

/// `path` is a NUL-terminated guest path. A null pointer records nothing.
///
/// # Safety
/// `path` is NUL-terminated or null.
/// The producer entry point every fakefs write path calls.
///
/// `fs/fake.c`'s until 2026-09-03, where it was written twice — once inside
/// `#if defined(__APPLE__)` and once outside — because only the Apple half has
/// a `dispatch_source` to wake. It read `current->group->fs_context` in both,
/// which is what kept `fs/fake.c` reading `current` after everything else in it
/// had stopped.
///
/// The context is read through `crates/kernel/taskview`, and waking the
/// consumer is [`consumer::wake_consumer`] -- which was a C hook until
/// 2026-09-04, on the grounds that GCD blocks are Clang's. There is one copy
/// of the rule now: a record is taken only when somebody is listening, and
/// nothing claims the listener slot on a platform with no consumer, so the
/// producer stops at its first line there exactly as it did.
///
/// # Safety
/// `path` is NUL-terminated or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fakefs_record_change(path: *const c_char, op: c_int) {
    if path.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    record_change(unsafe { std::ffi::CStr::from_ptr(path) }, op);
}

/// [`fakefs_record_change`] for a Rust caller, which has a `&CStr` and no
/// pointer to vouch for. Every caller in this workspace is one.
pub fn record_change(path: &std::ffi::CStr, op: c_int) {
    if !is_listening() {
        return;
    }
    record(path.to_bytes(), op, taskview::current_fs_context());
    consumer::wake_consumer();
}

/// How many change records have been dropped because nobody drained them.
///
/// `fs/fake.h` publishes this and `/proc/iul/objects` reports it. It was a
/// one-line C forwarder in `fs/fake.c` until 2026-09-03.
#[unsafe(no_mangle)]
pub extern "C" fn fakefs_change_dropped_count() -> u64 {
    dropped()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The queue is process-wide, so the tests take turns and each starts by
    /// emptying it. A test that assumed an empty queue and did not empty it
    /// would pass alone and fail beside another, which is the shape that makes
    /// a suite flaky rather than failing.
    fn reset() -> std::sync::MutexGuard<'static, ()> {
        static SERIAL: Mutex<()> = Mutex::new(());
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut buf = vec![blank(); CAPACITY];
        while drain(&mut buf) > 0 {}
        g
    }

    fn blank() -> Event {
        Event {
            linux_path: [0; PATH_MAX],
            op: 0,
            timestamp_ns: 0,
            fs_context: 0,
        }
    }

    fn path_of(e: &Event) -> Vec<u8> {
        let bytes: Vec<u8> = e.linux_path.iter().map(|c| *c as u8).collect();
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        bytes[..end].to_vec()
    }

    #[test]
    fn records_come_back_in_order() {
        let _g = reset();
        record(b"/a", 1, 7);
        record(b"/b", 2, 7);
        record(b"/c", 3, 7);
        let mut out = vec![blank(); 8];
        assert_eq!(drain(&mut out), 3);
        assert_eq!(path_of(&out[0]), b"/a");
        assert_eq!(path_of(&out[1]), b"/b");
        assert_eq!(path_of(&out[2]), b"/c");
        assert_eq!(out[1].op, 2);
        assert_eq!(out[2].fs_context, 7);
        assert_eq!(drain(&mut out), 0, "and the queue is then empty");
    }

    #[test]
    fn a_partial_drain_leaves_the_rest() {
        let _g = reset();
        for i in 0..5u8 {
            record(&[b'/', b'a' + i], 0, 0);
        }
        let mut out = vec![blank(); 2];
        assert_eq!(drain(&mut out), 2);
        assert_eq!(path_of(&out[0]), b"/a");
        assert_eq!(depth(), 3);
        assert_eq!(drain(&mut out), 2);
        assert_eq!(path_of(&out[0]), b"/c");
        assert_eq!(drain(&mut out), 1);
        assert_eq!(path_of(&out[0]), b"/e");
    }

    #[test]
    fn a_full_queue_drops_the_oldest() {
        let _g = reset();
        let before = dropped();
        for i in 0..(CAPACITY + 10) {
            record(format!("/f{i}").as_bytes(), 0, 0);
        }
        assert_eq!(depth(), CAPACITY);
        assert_eq!(dropped(), before + 10);
        let mut out = vec![blank(); 1];
        assert_eq!(drain(&mut out), 1);
        // The first ten are gone; the eleventh is at the front.
        assert_eq!(path_of(&out[0]), b"/f10");
    }

    #[test]
    fn a_path_that_does_not_fit_is_dropped_not_truncated() {
        let _g = reset();
        let before = dropped();
        let long = vec![b'x'; PATH_MAX];
        record(&long, 0, 0);
        assert_eq!(depth(), 0, "nothing was queued");
        assert_eq!(dropped(), before + 1);

        // One byte shorter fits: the field holds PATH_MAX bytes including the
        // NUL, so PATH_MAX - 1 is the longest path there is room for.
        let ok = vec![b'x'; PATH_MAX - 1];
        record(&ok, 0, 0);
        let mut out = vec![blank(); 1];
        assert_eq!(drain(&mut out), 1);
        assert_eq!(path_of(&out[0]).len(), PATH_MAX - 1);
        assert_eq!(out[0].linux_path[PATH_MAX - 1], 0, "and it is terminated");
    }

    #[test]
    fn an_oversized_path_does_not_evict_a_queued_one() {
        // The reason the length check comes first. An event that cannot be
        // delivered must not cost one that can.
        let _g = reset();
        for i in 0..CAPACITY {
            record(format!("/{i}").as_bytes(), 0, 0);
        }
        record(&vec![b'x'; PATH_MAX + 1], 0, 0);
        assert_eq!(depth(), CAPACITY);
        let mut out = vec![blank(); 1];
        drain(&mut out);
        assert_eq!(path_of(&out[0]), b"/0", "the oldest is still there");
    }

    #[test]
    fn a_path_with_an_embedded_nul_is_dropped() {
        // What the consumer would read is a prefix, which is the truncation
        // case by another route.
        let _g = reset();
        let before = dropped();
        record(b"/a\0b", 0, 0);
        assert_eq!(depth(), 0);
        assert_eq!(dropped(), before + 1);
    }

    #[test]
    fn the_tail_of_a_reused_buffer_is_not_disclosed() {
        let _g = reset();
        let mut out = vec![blank(); 1];
        out[0].linux_path[..8].copy_from_slice(&[b'S' as c_char; 8]);
        record(b"/x", 0, 0);
        assert_eq!(drain(&mut out), 1);
        assert_eq!(path_of(&out[0]), b"/x");
        assert!(
            out[0].linux_path[2..].iter().all(|c| *c == 0),
            "everything past the path is zero, not what was there before"
        );
    }

    #[test]
    fn the_timestamp_is_nanoseconds() {
        // The defect this crate was written for. `mach_absolute_time` on Apple
        // Silicon ticks at 24 MHz, so a 50 ms sleep moved the old field by
        // about 1.2 million and this one by about 50 million.
        let _g = reset();
        record(b"/a", 0, 0);
        std::thread::sleep(std::time::Duration::from_millis(50));
        record(b"/b", 0, 0);
        let mut out = vec![blank(); 2];
        assert_eq!(drain(&mut out), 2);
        let delta = out[1].timestamp_ns - out[0].timestamp_ns;
        assert!(
            (40_000_000..500_000_000).contains(&delta),
            "50ms apart, measured as {delta}ns"
        );
    }

    #[test]
    fn drain_into_nothing_is_zero() {
        let _g = reset();
        record(b"/a", 0, 0);
        let mut none: [Event; 0] = [];
        assert_eq!(drain(&mut none), 0);
        assert_eq!(depth(), 1, "and the event is still waiting");
    }

    #[test]
    fn producers_do_not_lose_events_to_each_other() {
        let _g = reset();
        let before = dropped();
        std::thread::scope(|s| {
            for t in 0..4 {
                s.spawn(move || {
                    for i in 0..64 {
                        record(format!("/t{t}/{i}").as_bytes(), t, 0);
                    }
                });
            }
        });
        assert_eq!(dropped(), before, "256 events fit in {CAPACITY}");
        assert_eq!(depth(), 256);
        let mut out = vec![blank(); 256];
        assert_eq!(drain(&mut out), 256);
        // Each thread's own events are in the order it recorded them, whatever
        // order the threads interleaved in.
        for t in 0..4 {
            let mine: Vec<Vec<u8>> = out.iter().filter(|e| e.op == t).map(path_of).collect();
            assert_eq!(mine.len(), 64);
            for (i, p) in mine.iter().enumerate() {
                assert_eq!(p, format!("/t{t}/{i}").as_bytes());
            }
        }
    }

    #[test]
    fn the_listener_slot_is_claimed_once() {
        // Two installers raced for this and both won, which built two consumer
        // queues and leaked the first.
        assert!(claim_listener() || is_listening());
        assert!(!claim_listener(), "the second caller does not get it");
        assert!(is_listening());
    }
}
