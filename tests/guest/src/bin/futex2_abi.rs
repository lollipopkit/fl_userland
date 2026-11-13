//! futex2 (`futex_wait`, `futex_wake`, `futex_waitv`, `futex_requeue`) and the
//! PI `futex(2)` operations, as behaviour rather than argument rules -- those
//! are `futex2_probe`'s.
//!
//! What is checked here is what a program builds on them: that a wait parks
//! until the matching wake and only that, that `futex_waitv` answers the index
//! it was woken on, that the two interfaces are one queue, that a PI mutex is
//! mutual exclusion with the owner's tid in the word and a handoff on unlock,
//! that the owner dying hands the lock on, and that a signal interrupts a wait
//! (or restarts it under `SA_RESTART`). The stress groups run threads against
//! each other many times; a lost wakeup there is a hang, which the alarm turns
//! into a failure.
//!
//! Every check passes on a real 7.x kernel too; `differential.sh` compares it.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const NR_FUTEX_WAITV: libc::c_long = 449;
const NR_FUTEX_WAKE: libc::c_long = 454;
const NR_FUTEX_WAIT: libc::c_long = 455;
const NR_FUTEX_REQUEUE: libc::c_long = 456;

const U32: u32 = 2;
const PRIV: u32 = 128;
const ANY: u64 = 0xffff_ffff;

const LOCK_PI: i32 = 6;
const UNLOCK_PI: i32 = 7;
const TRYLOCK_PI: i32 = 8;
const WAIT_REQUEUE_PI: i32 = 11;
const CMP_REQUEUE_PI: i32 = 12;
const LOCK_PI2: i32 = 13;
const PRIVATE_FLAG: i32 = 128;

const WAITERS: u32 = 0x8000_0000;
const TID_MASK: u32 = 0x3fff_ffff;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// The syscall's answer as `Ok(value)` or `Err(errno)`.
fn res(r: libc::c_long) -> Result<i64, i32> {
    if r < 0 { Err(errno()) } else { Ok(r) }
}

fn gettid() -> u32 {
    unsafe { libc::syscall(libc::SYS_gettid) as u32 }
}

fn now(clock: libc::clockid_t) -> libc::timespec {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts
}

fn plus(mut t: libc::timespec, d: Duration) -> libc::timespec {
    t.tv_sec += d.as_secs() as i64;
    t.tv_nsec += d.subsec_nanos() as libc::c_long;
    if t.tv_nsec >= 1_000_000_000 {
        t.tv_nsec -= 1_000_000_000;
        t.tv_sec += 1;
    }
    t
}

fn deadline(d: Duration) -> libc::timespec {
    plus(now(libc::CLOCK_MONOTONIC), d)
}

fn fwait(w: &AtomicU32, val: u32, mask: u64, t: Option<&libc::timespec>, clock: i32) -> Result<i64, i32> {
    let tp = t.map_or(std::ptr::null(), |t| t as *const libc::timespec);
    res(unsafe { libc::syscall(NR_FUTEX_WAIT, w.as_ptr(), val as u64, mask, U32 | PRIV, tp, clock) })
}

fn fwake(w: &AtomicU32, mask: u64, nr: i32) -> Result<i64, i32> {
    res(unsafe { libc::syscall(NR_FUTEX_WAKE, w.as_ptr(), mask, nr, U32 | PRIV) })
}

#[repr(C)]
struct Waitv {
    val: u64,
    uaddr: u64,
    flags: u32,
    reserved: u32,
}

fn entry(w: &AtomicU32, val: u32) -> Waitv {
    Waitv { val: val as u64, uaddr: w.as_ptr() as u64, flags: U32 | PRIV, reserved: 0 }
}

fn waitv(v: &[Waitv], t: Option<&libc::timespec>) -> Result<i64, i32> {
    let tp = t.map_or(std::ptr::null(), |t| t as *const libc::timespec);
    res(unsafe { libc::syscall(NR_FUTEX_WAITV, v.as_ptr(), v.len() as u32, 0u32, tp, libc::CLOCK_MONOTONIC) })
}

fn legacy(w: &AtomicU32, op: i32, val: u32, t: *const libc::timespec, w2: *const u32, val3: u32) -> Result<i64, i32> {
    res(unsafe { libc::syscall(libc::SYS_futex, w.as_ptr(), op, val, t, w2, val3) })
}

/// Wake `w` until somebody is woken, for a waiter that may not be parked yet.
fn wake_one_eventually(w: &AtomicU32) -> bool {
    for _ in 0..2000 {
        if fwake(w, ANY, 1) == Ok(1) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    false
}

fn leak<T>(v: T) -> &'static T {
    Box::leak(Box::new(v))
}

fn main() {
    // A lost wakeup is a hang; the alarm makes it a failure with a name.
    unsafe { libc::alarm(120) };
    let mut h = Harness::new();
    basic(&mut h);
    exit_wake_shared(&mut h);
    exec_releases_robust(&mut h);
    vector(&mut h);
    requeue(&mut h);
    interrupt(&mut h);
    pi(&mut h);
    pi_owner_death(&mut h);
    requeue_pi(&mut h);
    requeue_pi_none_behind_held(&mut h);
    stress_mutex(&mut h);
    stress_waitv(&mut h);
    stress_pi(&mut h);
    hash(&mut h);
    std::process::exit(h.finish());
}

fn basic(h: &mut Harness) {
    h.group("wait-wake");
    let w = leak(AtomicU32::new(0));
    check!(h, fwait(w, 1, ANY, None, 0) == Err(libc::EAGAIN), "a value that does not match is EAGAIN");
    let t0 = Instant::now();
    let d = deadline(Duration::from_millis(50));
    let r = fwait(w, 0, ANY, Some(&d), libc::CLOCK_MONOTONIC);
    let took = t0.elapsed();
    check!(h, r == Err(libc::ETIMEDOUT), "an absolute monotonic deadline expires: {r:?}");
    check!(h, took >= Duration::from_millis(45) && took < Duration::from_millis(1000), "and when it says: {took:?}");
    let d = plus(now(libc::CLOCK_REALTIME), Duration::from_millis(50));
    let t0 = Instant::now();
    let r = fwait(w, 0, ANY, Some(&d), libc::CLOCK_REALTIME);
    check!(h, r == Err(libc::ETIMEDOUT) && t0.elapsed() >= Duration::from_millis(45), "so does a realtime one: {r:?}");

    // futex_wait woken by futex_wake, and by FUTEX_WAKE: one queue.
    for legacy_waker in [false, true] {
        let w = leak(AtomicU32::new(0));
        let waker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            for _ in 0..2000 {
                let n = if legacy_waker {
                    legacy(w, libc::FUTEX_WAKE | PRIVATE_FLAG, 1, std::ptr::null(), std::ptr::null(), 0)
                } else {
                    fwake(w, ANY, 1)
                };
                if n == Ok(1) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            false
        });
        let d = deadline(Duration::from_secs(10));
        let r = fwait(w, 0, ANY, Some(&d), libc::CLOCK_MONOTONIC);
        let woke = waker.join().unwrap();
        check!(h, r == Ok(0) && woke, "futex_wait is woken by {}: {r:?}", if legacy_waker { "FUTEX_WAKE" } else { "futex_wake" });
    }
    // And a FUTEX_WAIT woken by futex_wake.
    let w = leak(AtomicU32::new(0));
    let waiter = std::thread::spawn(move || {
        let t = libc::timespec { tv_sec: 10, tv_nsec: 0 };
        legacy(w, libc::FUTEX_WAIT | PRIVATE_FLAG, 0, &t, std::ptr::null(), 0)
    });
    check!(h, wake_one_eventually(w), "futex_wake finds a FUTEX_WAIT waiter");
    check!(h, waiter.join().unwrap() == Ok(0), "and it returns 0");

    // The mask: a disjoint wake leaves it parked, an overlapping one wakes it.
    let w = leak(AtomicU32::new(0));
    let waiter = std::thread::spawn(move || {
        let d = deadline(Duration::from_secs(10));
        fwait(w, 0, 0b0100, Some(&d), libc::CLOCK_MONOTONIC)
    });
    std::thread::sleep(Duration::from_millis(50));
    let disjoint = fwake(w, 0b1011, 5);
    std::thread::sleep(Duration::from_millis(20));
    let overlapping = fwake(w, 0b0110, 5);
    check!(h, disjoint == Ok(0), "a disjoint mask wakes nobody: {disjoint:?}");
    check!(h, overlapping == Ok(1), "an overlapping one wakes it: {overlapping:?}");
    check!(h, waiter.join().unwrap() == Ok(0), "and the waiter returns 0");

    // A shared futex on a MAP_SHARED page, across fork.
    h.group("shared");
    let page = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0)
    };
    let sw = unsafe { &*(page as *const AtomicU32) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::usleep(100_000) };
        sw.store(1, Ordering::SeqCst);
        let r = unsafe { libc::syscall(NR_FUTEX_WAKE, sw.as_ptr(), ANY, 1, U32) };
        unsafe { libc::_exit(r as i32) };
    }
    let d = deadline(Duration::from_secs(5));
    let r = res(unsafe { libc::syscall(NR_FUTEX_WAIT, sw.as_ptr(), 0u64, ANY, U32, &d as *const libc::timespec, libc::CLOCK_MONOTONIC) });
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    check!(h, r == Ok(0) || (r == Err(libc::EAGAIN) && sw.load(Ordering::SeqCst) == 1), "a shared futex_wait is woken from the child: {r:?}");
    check!(h, libc::WIFEXITED(status) && libc::WEXITSTATUS(status) <= 1, "and the child's futex_wake answered {}", libc::WEXITSTATUS(status));
}

/// A thread's `clear_child_tid` on a `MAP_SHARED` page wakes a waiter in
/// another process: the exit wake is keyed shared, as Linux's `mm_release`
/// keys it. The thread is one of two in its process -- Linux clears and wakes
/// only while the address space has another user.
fn exit_wake_shared(h: &mut Harness) {
    h.group("exit-wake-shared");
    let page = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0)
    };
    let word = unsafe { &*(page as *const AtomicU32) };
    word.store(u32::MAX, Ordering::SeqCst);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let addr = word as *const AtomicU32 as usize;
        std::thread::spawn(move || {
            let w = unsafe { &*(addr as *const AtomicU32) };
            unsafe { libc::syscall(libc::SYS_set_tid_address, addr) };
            w.store(gettid(), Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(150));
            unsafe { libc::syscall(libc::SYS_exit, 0) };
        });
        std::thread::sleep(Duration::from_secs(2));
        unsafe { libc::_exit(0) };
    }
    while word.load(Ordering::SeqCst) == u32::MAX {
        std::thread::yield_now();
    }
    let tid = word.load(Ordering::SeqCst);
    let t = libc::timespec { tv_sec: 1, tv_nsec: 0 };
    let t0 = Instant::now();
    let r = res(unsafe { libc::syscall(libc::SYS_futex, word.as_ptr(), libc::FUTEX_WAIT, tid, &t as *const libc::timespec, 0, 0) });
    let took = t0.elapsed();
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    check!(h, word.load(Ordering::SeqCst) == 0, "the exiting thread cleared its tid word");
    check!(h, r == Ok(0) && took < Duration::from_millis(900), "and woke the other process's shared FUTEX_WAIT: {r:?} after {took:?}");
}

/// `execve` releases the robust list: a robust futex held across an exec is
/// disowned then, as Linux's `exec_mm_release` does, and not left for the new
/// image's exit to walk through memory that is no longer there.
fn exec_releases_robust(h: &mut Harness) {
    h.group("exec-release");
    #[repr(C)]
    struct Head {
        list: u64,
        offset: i64,
        pending: u64,
    }
    let page = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0)
    } as *mut u64;
    // An entry at page[0] whose futex is the word at page[1].
    let word = unsafe { &*(page.add(1) as *const AtomicU32) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let head = Box::leak(Box::new(Head { list: 0, offset: 8, pending: 0 }));
        unsafe {
            *page = head as *const Head as u64;
            head.list = page as u64;
            word.store(gettid(), Ordering::SeqCst);
            libc::syscall(libc::SYS_set_robust_list, head as *const Head, 24usize);
            let argv = [c"/bin/true".as_ptr(), std::ptr::null()];
            libc::execv(c"/bin/true".as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let v = word.load(Ordering::SeqCst);
    check!(h, libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "the child exec'd /bin/true");
    check!(h, v & 0x4000_0000 != 0 && v & TID_MASK == 0, "and the robust futex it held was disowned: {v:#x}");
}

fn vector(h: &mut Harness) {
    h.group("waitv");
    for idx in 0..4usize {
        let ws: Vec<&'static AtomicU32> = (0..4).map(|_| leak(AtomicU32::new(0))).collect();
        let target = ws[idx];
        let waker = std::thread::spawn(move || wake_one_eventually(target));
        let v: Vec<Waitv> = ws.iter().map(|w| entry(w, 0)).collect();
        let d = deadline(Duration::from_secs(10));
        let r = waitv(&v, Some(&d));
        check!(h, waker.join().unwrap(), "the waker found the vector waiter on word {idx}");
        check!(h, r == Ok(idx as i64), "futex_waitv answers the index woken, {idx}: {r:?}");
        // Woken once: nobody is left on the other words.
        let others: i64 = ws.iter().map(|w| fwake(w, ANY, 9).unwrap_or(-1)).sum();
        check!(h, others == 0, "and nothing is left parked on its other words: {others}");
    }
    let (a, b) = (leak(AtomicU32::new(0)), leak(AtomicU32::new(5)));
    check!(h, waitv(&[entry(a, 0), entry(b, 0)], None) == Err(libc::EAGAIN), "one mismatch is EAGAIN for the vector");
    check!(h, fwake(a, ANY, 9) == Ok(0), "and nothing was parked on the word that matched");
    let d = deadline(Duration::from_millis(30));
    let t0 = Instant::now();
    let r = waitv(&[entry(a, 0), entry(b, 5)], Some(&d));
    check!(h, r == Err(libc::ETIMEDOUT) && t0.elapsed() >= Duration::from_millis(25), "a vector wait times out: {r:?}");
}

fn requeue(h: &mut Harness) {
    h.group("requeue");
    let (a, b) = (leak(AtomicU32::new(0)), leak(AtomicU32::new(0)));
    let parked = Arc::new(AtomicUsize::new(0));
    let waiters: Vec<_> = (0..3)
        .map(|_| {
            let parked = Arc::clone(&parked);
            std::thread::spawn(move || {
                parked.fetch_add(1, Ordering::SeqCst);
                let d = deadline(Duration::from_secs(10));
                fwait(a, 0, ANY, Some(&d), libc::CLOCK_MONOTONIC)
            })
        })
        .collect();
    while parked.load(Ordering::SeqCst) < 3 {
        std::thread::yield_now();
    }
    std::thread::sleep(Duration::from_millis(100));
    let v = [entry(a, 0), entry(b, 0)];
    let bad = [entry(a, 1), entry(b, 0)];
    let refused = res(unsafe { libc::syscall(NR_FUTEX_REQUEUE, bad.as_ptr(), 0u32, 1, 9) });
    check!(h, refused == Err(libc::EAGAIN), "a requeue whose first value moved is EAGAIN: {refused:?}");
    let n = res(unsafe { libc::syscall(NR_FUTEX_REQUEUE, v.as_ptr(), 0u32, 1, 9) });
    check!(h, n == Ok(3), "wake 1, requeue the other 2: {n:?}");
    std::thread::sleep(Duration::from_millis(20));
    check!(h, fwake(a, ANY, 9) == Ok(0), "nobody is left on the first word");
    check!(h, fwake(b, ANY, 9) == Ok(2), "the two moved are on the second");
    let answers: Vec<_> = waiters.into_iter().map(|t| t.join().unwrap()).collect();
    check!(h, answers.iter().all(|r| *r == Ok(0)), "every waiter returns 0: {answers:?}");
}

static SIGNALLED: AtomicUsize = AtomicUsize::new(0);
extern "C" fn on_signal(_: i32) {
    SIGNALLED.fetch_add(1, Ordering::SeqCst);
}

fn install(restart: bool) {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = on_signal as *const () as usize;
    sa.sa_flags = if restart { libc::SA_RESTART } else { 0 };
    unsafe { libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) };
}

fn interrupt(h: &mut Harness) {
    h.group("signals");
    for (restart, vector) in [(false, false), (true, false), (false, true), (true, true)] {
        install(restart);
        let w = leak(AtomicU32::new(0));
        let tid = Arc::new(AtomicI64::new(0));
        let t2 = Arc::clone(&tid);
        let waiter = std::thread::spawn(move || {
            t2.store(gettid() as i64, Ordering::SeqCst);
            let d = deadline(Duration::from_millis(400));
            let t0 = Instant::now();
            let r = if vector { waitv(&[entry(w, 0)], Some(&d)) } else { fwait(w, 0, ANY, Some(&d), libc::CLOCK_MONOTONIC) };
            (r, t0.elapsed())
        });
        while tid.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(80));
        unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), tid.load(Ordering::SeqCst), libc::SIGUSR1) };
        let (r, took) = waiter.join().unwrap();
        let what = if vector { "futex_waitv" } else { "futex_wait" };
        if restart {
            check!(h, r == Err(libc::ETIMEDOUT) && took >= Duration::from_millis(350), "{what} restarts under SA_RESTART and waits out its deadline: {r:?} after {took:?}");
        } else {
            check!(h, r == Err(libc::EINTR) && took < Duration::from_millis(350), "{what} is interrupted by a handler: {r:?} after {took:?}");
        }
    }

    // LOCK_PI is restarted whatever the handler asked: Linux answers it
    // `ERESTARTNOINTR`, so a PI mutex lock never returns EINTR.
    for restart in [false, true] {
        install(restart);
        SIGNALLED.store(0, Ordering::SeqCst);
        let w = leak(AtomicU32::new(0));
        let (ltx, lrx) = std::sync::mpsc::channel();
        let owner = std::thread::spawn(move || {
            ltx.send(legacy(w, LOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0)).unwrap();
            std::thread::sleep(Duration::from_millis(300));
            legacy(w, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0)
        });
        lrx.recv().unwrap().unwrap();
        let tid = Arc::new(AtomicI64::new(0));
        let t2 = Arc::clone(&tid);
        let waiter = std::thread::spawn(move || {
            t2.store(gettid() as i64, Ordering::SeqCst);
            let r = legacy(w, LOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
            let _ = legacy(w, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
            r
        });
        while tid.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(80));
        unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), tid.load(Ordering::SeqCst), libc::SIGUSR1) };
        let r = waiter.join().unwrap();
        check!(h, SIGNALLED.load(Ordering::SeqCst) == 1, "the handler ran during LOCK_PI (SA_RESTART={restart})");
        check!(h, r == Ok(0), "and LOCK_PI was restarted rather than EINTR (SA_RESTART={restart}): {r:?}");
        check!(h, owner.join().unwrap() == Ok(0), "the owner unlocked");
    }
    unsafe { libc::signal(libc::SIGUSR1, libc::SIG_DFL) };
}

fn pi(h: &mut Harness) {
    h.group("pi");
    let me = gettid();
    let w = leak(AtomicU32::new(0));
    check!(h, legacy(w, LOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0) == Ok(0), "LOCK_PI on a free word");
    check!(h, w.load(Ordering::SeqCst) == me, "writes the caller's tid: {:#x}", w.load(Ordering::SeqCst));
    check!(h, legacy(w, LOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0) == Err(libc::EDEADLK), "a second LOCK_PI by the owner is EDEADLK");
    check!(h, legacy(w, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0) == Ok(0), "UNLOCK_PI by the owner");
    check!(h, w.load(Ordering::SeqCst) == 0, "releases it to 0");

    // Handoff: the owner is another thread; the waiter parks and is handed it.
    let w = leak(AtomicU32::new(0));
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let (ltx, lrx) = std::sync::mpsc::channel();
    let owner = std::thread::spawn(move || {
        ltx.send((legacy(w, LOCK_PI2 | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0), gettid())).unwrap();
        rx.recv().unwrap();
        legacy(w, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0)
    });
    let (locked, owner_tid) = lrx.recv().unwrap();
    check!(h, locked == Ok(0), "LOCK_PI2 in the owner thread");
    check!(h, legacy(w, TRYLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0) == Err(libc::EAGAIN), "TRYLOCK_PI behind a live owner is EAGAIN");
    check!(h, legacy(w, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0) == Err(libc::EPERM), "UNLOCK_PI by a non-owner is EPERM");
    let d = deadline(Duration::from_millis(30));
    let t0 = Instant::now();
    let r = legacy(w, LOCK_PI2 | PRIVATE_FLAG, 0, &d, std::ptr::null(), 0);
    check!(h, r == Err(libc::ETIMEDOUT) && t0.elapsed() >= Duration::from_millis(25), "LOCK_PI2 times out behind it: {r:?}");
    check!(h, w.load(Ordering::SeqCst) == owner_tid | WAITERS, "and left FUTEX_WAITERS set: {:#x}", w.load(Ordering::SeqCst));
    let go = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        tx.send(()).unwrap();
    });
    let r = legacy(w, LOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
    check!(h, r == Ok(0), "a blocked LOCK_PI is handed the lock: {r:?}");
    check!(h, w.load(Ordering::SeqCst) == me | WAITERS, "with its tid and FUTEX_WAITERS: {:#x}", w.load(Ordering::SeqCst));
    check!(h, owner.join().unwrap() == Ok(0), "the owner's UNLOCK_PI succeeded");
    go.join().unwrap();
    check!(h, legacy(w, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0) == Ok(0), "and the new owner unlocks");
    check!(h, w.load(Ordering::SeqCst) == 0, "to 0, with nobody waiting");

    // A plain FUTEX_WAKE that reaches a PI waiter is EINVAL.
    let w = leak(AtomicU32::new(0));
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let (ltx, lrx) = std::sync::mpsc::channel();
    let owner = std::thread::spawn(move || {
        ltx.send(legacy(w, LOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0)).unwrap();
        rx.recv().unwrap();
        legacy(w, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0)
    });
    lrx.recv().unwrap().unwrap();
    let waiter = std::thread::spawn(move || {
        let d = plus(now(libc::CLOCK_REALTIME), Duration::from_millis(300));
        legacy(w, LOCK_PI | PRIVATE_FLAG, 0, &d, std::ptr::null(), 0)
    });
    std::thread::sleep(Duration::from_millis(100));
    let r = legacy(w, libc::FUTEX_WAKE | PRIVATE_FLAG, 1, std::ptr::null(), std::ptr::null(), 0);
    check!(h, r == Err(libc::EINVAL), "FUTEX_WAKE on a word with a PI waiter is EINVAL: {r:?}");
    check!(h, waiter.join().unwrap() == Err(libc::ETIMEDOUT), "and the PI waiter times out on LOCK_PI's realtime deadline");
    tx.send(()).unwrap();
    check!(h, owner.join().unwrap() == Ok(0), "the owner unlocks");
}

fn pi_owner_death(h: &mut Harness) {
    h.group("pi-owner-death");
    // The owner exits through the raw syscall, holding the lock and with no
    // robust list: the waiter behind it is given the lock.
    let w = leak(AtomicU32::new(0));
    let (ltx, lrx) = std::sync::mpsc::channel();
    let (gtx, grx) = std::sync::mpsc::channel::<()>();
    let owner = std::thread::spawn(move || {
        ltx.send(legacy(w, LOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0)).unwrap();
        grx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        // Not pthread_exit: nothing of libc may unlock it on the way out.
        unsafe { libc::syscall(libc::SYS_exit, 0) };
    });
    lrx.recv().unwrap().unwrap();
    let owner_tid = w.load(Ordering::SeqCst) & TID_MASK;
    gtx.send(()).unwrap();
    let d = plus(now(libc::CLOCK_REALTIME), Duration::from_secs(10));
    let r = legacy(w, LOCK_PI | PRIVATE_FLAG, 0, &d, std::ptr::null(), 0);
    let v = w.load(Ordering::SeqCst);
    check!(h, r == Ok(0), "a waiter behind an owner that exits gets the lock: {r:?}");
    check!(h, v & TID_MASK == gettid(), "the word names it now: {v:#x} (owner was {owner_tid:#x})");
    drop(owner);
    let _ = legacy(w, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
    // And a new LOCK_PI behind the dead tid, with nobody parked, is ESRCH.
    let w = leak(AtomicU32::new(owner_tid));
    let r = legacy(w, LOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
    check!(h, r == Err(libc::ESRCH), "LOCK_PI behind a tid that has exited is ESRCH: {r:?}");
}

fn requeue_pi(h: &mut Harness) {
    h.group("requeue-pi");
    // A glibc-shaped PI condition variable: waiters on `cond`, handed `mutex`.
    for held in [false, true] {
        let (cond, mutex) = (leak(AtomicU32::new(0)), leak(AtomicU32::new(0)));
        let parked = Arc::new(AtomicUsize::new(0));
        let waiters: Vec<_> = (0..3)
            .map(|_| {
                let parked = Arc::clone(&parked);
                std::thread::spawn(move || {
                    parked.fetch_add(1, Ordering::SeqCst);
                    let r = legacy(cond, WAIT_REQUEUE_PI | PRIVATE_FLAG, 0, std::ptr::null(), mutex.as_ptr(), 0);
                    let owned = mutex.load(Ordering::SeqCst) & TID_MASK == gettid();
                    let u = legacy(mutex, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
                    (r, owned, u)
                })
            })
            .collect();
        while parked.load(Ordering::SeqCst) < 3 {
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(150));
        if held {
            let _ = legacy(mutex, LOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
        }
        // nr_wake must be 1; nr_requeue is the rest.
        let n = legacy(cond, CMP_REQUEUE_PI | PRIVATE_FLAG, 1, 2 as *const libc::timespec, mutex.as_ptr(), 0);
        // Three either way: free, the top one is given the mutex and two are
        // moved; held, the top one is moved within the one it would have been
        // woken under, and so are the other two.
        check!(h, n == Ok(3), "CMP_REQUEUE_PI counts woken plus requeued, mutex held={held}: {n:?}");
        if held {
            check!(h, mutex.load(Ordering::SeqCst) == gettid() | WAITERS, "behind a held mutex the bit is set");
            let _ = legacy(mutex, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
        }
        let left = legacy(cond, CMP_REQUEUE_PI | PRIVATE_FLAG, 1, 9 as *const libc::timespec, mutex.as_ptr(), 0);
        check!(h, left == Ok(0), "nobody is left on the condition: {left:?}");
        let answers: Vec<_> = waiters.into_iter().map(|t| t.join().unwrap()).collect();
        check!(h, answers.iter().all(|a| *a == (Ok(0), true, Ok(0))), "every waiter returns 0 owning the mutex, and unlocks it: {answers:?}");
        check!(h, mutex.load(Ordering::SeqCst) == 0, "the mutex ends free: {:#x}", mutex.load(Ordering::SeqCst));
    }
}

/// `nr_requeue` 0 behind a held mutex still moves the top waiter, so the
/// mutex has to say it has waiters, or its owner's unlock never reaches the
/// kernel and the waiter is never handed it.
fn requeue_pi_none_behind_held(h: &mut Harness) {
    h.group("requeue-pi");
    let (cond, mutex) = (leak(AtomicU32::new(0)), leak(AtomicU32::new(0)));
    let _ = legacy(mutex, LOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
    let waiter = std::thread::spawn(move || {
        let r = legacy(cond, WAIT_REQUEUE_PI | PRIVATE_FLAG, 0, std::ptr::null(), mutex.as_ptr(), 0);
        let owned = mutex.load(Ordering::SeqCst) & TID_MASK == gettid();
        let _ = legacy(mutex, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
        (r, owned)
    });
    std::thread::sleep(Duration::from_millis(150));
    let n = legacy(cond, CMP_REQUEUE_PI | PRIVATE_FLAG, 1, std::ptr::null(), mutex.as_ptr(), 0);
    check!(h, n == Ok(1), "nr_requeue 0 behind a held mutex moves the top waiter: {n:?}");
    let v = mutex.load(Ordering::SeqCst);
    check!(h, v == gettid() | WAITERS, "and sets FUTEX_WAITERS on the mutex: {v:#x}");
    // The userspace unlock fast path, which must fail and go to the kernel.
    if mutex.compare_exchange(gettid(), 0, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        let _ = legacy(mutex, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
    }
    check!(h, waiter.join().unwrap() == (Ok(0), true), "and the waiter is handed it on unlock");
}

/// A mutex built on futex_wait/futex_wake (Drepper's), hammered by threads;
/// every increment inside it has to survive.
fn stress_mutex(h: &mut Harness) {
    h.group("stress-mutex");
    let lock = leak(AtomicU32::new(0));
    let counter = leak(AtomicU32::new(0));
    const THREADS: u32 = 6;
    const ITERS: u32 = 3000;
    let ts: Vec<_> = (0..THREADS)
        .map(|_| {
            std::thread::spawn(move || {
                for _ in 0..ITERS {
                    // lock
                    let mut c = lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).unwrap_or_else(|v| v);
                    if c != 0 {
                        if c != 2 {
                            c = lock.swap(2, Ordering::Acquire);
                        }
                        while c != 0 {
                            let _ = fwait(lock, 2, ANY, None, 0);
                            c = lock.swap(2, Ordering::Acquire);
                        }
                    }
                    let v = counter.load(Ordering::Relaxed);
                    counter.store(v + 1, Ordering::Relaxed);
                    // unlock
                    if lock.fetch_sub(1, Ordering::Release) != 1 {
                        lock.store(0, Ordering::Release);
                        let _ = fwake(lock, ANY, 1);
                    }
                }
            })
        })
        .collect();
    for t in ts {
        t.join().unwrap();
    }
    let total = counter.load(Ordering::SeqCst);
    check!(h, total == THREADS * ITERS, "no increment lost under a futex_wait mutex: {total}");
}

/// Waiters on vectors of words, wakers on single words. Every wake that
/// reports a waiter has to correspond to a waiter that returned that index.
fn stress_waitv(h: &mut Harness) {
    h.group("stress-waitv");
    const WORDS: usize = 4;
    const ROUNDS: usize = 300;
    let words: &'static [AtomicU32; WORDS] = leak([const { AtomicU32::new(0) }; WORDS]);
    let woken_by_waker = leak(AtomicUsize::new(0));
    let returned = leak(AtomicUsize::new(0));
    let stop = leak(AtomicBool::new(false));
    let waiters: Vec<_> = (0..3)
        .map(|_| {
            std::thread::spawn(move || {
                let mut wrong = 0;
                for _ in 0..ROUNDS {
                    let v: Vec<Waitv> = words.iter().map(|w| entry(w, 0)).collect();
                    let d = deadline(Duration::from_millis(200));
                    match waitv(&v, Some(&d)) {
                        Ok(i) if (i as usize) < WORDS => {
                            returned.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(_) => wrong += 1,
                        Err(libc::ETIMEDOUT) | Err(libc::EAGAIN) | Err(libc::EINTR) => {}
                        Err(_) => wrong += 1,
                    }
                }
                wrong
            })
        })
        .collect();
    let wakers: Vec<_> = (0..2)
        .map(|k| {
            std::thread::spawn(move || {
                let mut i = k;
                while !stop.load(Ordering::SeqCst) {
                    if let Ok(n) = fwake(&words[i % WORDS], ANY, 1) {
                        woken_by_waker.fetch_add(n as usize, Ordering::SeqCst);
                    }
                    i += 1;
                    std::thread::yield_now();
                }
            })
        })
        .collect();
    let wrong: usize = waiters.into_iter().map(|t| t.join().unwrap()).sum();
    stop.store(true, Ordering::SeqCst);
    for w in wakers {
        w.join().unwrap();
    }
    let (a, b) = (woken_by_waker.load(Ordering::SeqCst), returned.load(Ordering::SeqCst));
    check!(h, wrong == 0, "no vector wait answered an impossible index or errno: {wrong}");
    // At least, not exactly: Linux parks a vector waiter as one queue entry
    // per word and unqueues the others only once it runs, so a second wake in
    // between counts it again -- measured at three counts per return on a 7.2
    // kernel. What cannot happen is a waiter returning woken that no wake
    // counted.
    check!(h, a >= b, "every waiter that returned woken was counted by a wake: {a} woken, {b} returned");
    check!(h, b > 0, "and some were: {b}");
}

/// A PI mutex with the userspace fast path, hammered by threads.
fn stress_pi(h: &mut Harness) {
    h.group("stress-pi");
    let w = leak(AtomicU32::new(0));
    let counter = leak(AtomicU32::new(0));
    let bad = leak(AtomicU32::new(0));
    const THREADS: u32 = 6;
    const ITERS: u32 = 1500;
    let ts: Vec<_> = (0..THREADS)
        .map(|_| {
            std::thread::spawn(move || {
                let me = gettid();
                for _ in 0..ITERS {
                    if w.compare_exchange(0, me, Ordering::Acquire, Ordering::Relaxed).is_err() {
                        let r = legacy(w, LOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
                        if r != Ok(0) {
                            bad.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                    }
                    if w.load(Ordering::SeqCst) & TID_MASK != me {
                        bad.fetch_add(1, Ordering::SeqCst);
                    }
                    let v = counter.load(Ordering::Relaxed);
                    counter.store(v + 1, Ordering::Relaxed);
                    if w.compare_exchange(me, 0, Ordering::Release, Ordering::Relaxed).is_err() {
                        let r = legacy(w, UNLOCK_PI | PRIVATE_FLAG, 0, std::ptr::null(), std::ptr::null(), 0);
                        if r != Ok(0) {
                            bad.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            })
        })
        .collect();
    for t in ts {
        t.join().unwrap();
    }
    check!(h, bad.load(Ordering::SeqCst) == 0, "every LOCK_PI/UNLOCK_PI succeeded and the owner was always the holder: {} bad", bad.load(Ordering::SeqCst));
    check!(h, counter.load(Ordering::SeqCst) == THREADS * ITERS, "no increment lost under a PI mutex: {}", counter.load(Ordering::SeqCst));
    check!(h, w.load(Ordering::SeqCst) == 0, "and it ends free: {:#x}", w.load(Ordering::SeqCst));
}

fn hash(h: &mut Harness) {
    h.group("futex-hash");
    // In a child, so the answer does not depend on what ran above.
    let page = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0)
    } as *mut i64;
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let pr = |a: u64, b: u64| unsafe { libc::prctl(78, a, b, 0u64, 0u64) as i64 };
        unsafe {
            *page = pr(2, 0);
            std::thread::spawn(|| ()).join().unwrap();
            *page.add(1) = pr(2, 0);
            *page.add(2) = pr(1, 64);
            *page.add(3) = pr(2, 0);
            *page.add(4) = pr(1, 0);
            *page.add(5) = pr(1, 64);
            *page.add(6) = pr(2, 0);
            libc::_exit(0);
        }
    }
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    let got: Vec<i64> = (0..7).map(|i| unsafe { *page.add(i) }).collect();
    check!(h, got[0] == 0, "no private hash before the first thread: {}", got[0]);
    check!(h, got[1] >= 16 && (got[1] as u64).is_power_of_two(), "a default of at least 16 after it: {}", got[1]);
    check!(h, got[2] == 0 && got[3] == 64, "SET_SLOTS 64 is what GET_SLOTS answers: {} {}", got[2], got[3]);
    check!(h, got[4] == 0 && got[5] == -1 && got[6] == 0, "SET_SLOTS 0 is the global hash, for good: {} {} {}", got[4], got[5], got[6]);
}
