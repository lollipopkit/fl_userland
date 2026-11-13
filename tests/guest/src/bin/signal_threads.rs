//! Which thread a process-directed signal is delivered to.
//!
//! `kill(getpid(), sig)` addresses the *process*, not a thread. The kernel
//! picks any thread that does not have the signal blocked. A kernel that
//! always picks the group leader loses the signal whenever the leader is the
//! one thread that blocked it -- the signal goes pending on a thread that will
//! never take it, and nothing reports anything.
//!
//! That is the normal shape of a program with a dedicated signal thread: block
//! the signal everywhere, and let one thread take it. It only works if the
//! kernel delivers to a thread that can accept it.
//!
//! `tgkill` is the opposite and is checked here too: it names one thread and
//! must deliver to that one even if it is blocked there.
//!
//! Nothing here waits without a bound. The failure this is about is a signal
//! that never arrives, so every wait is a deadline and a miss is a failed
//! check rather than a hung test.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use std::time::{Duration, Instant};

static HANDLED_BY: AtomicI64 = AtomicI64::new(0);
static HANDLED_SIG: AtomicI32 = AtomicI32::new(0);

/// **The tid first, and the signal number last**, because every wait in this
/// file is on the signal number and then reads the tid.
///
/// This is a narrowing, not a diagnosis. On 2026-09-04 the check
/// `process-directed-goes-to-a-thread-that-can-take-it` failed once, in a full
/// suite run, with `handled_by=0 worker=2 main=1` — the handler had run and
/// stored the right signal number, and the tid beside it was zero. **The cause
/// was not established.** The store order is one way that reading can happen,
/// since a `gettid()` syscall used to sit between the two stores, but it is a
/// window of microseconds inside a 2 ms poll and it did not reproduce: 160 runs
/// against the old order — 80 debug and 80 release, four at a time — all
/// passed. Written down rather than guessed at.
///
/// What the reorder and the wait below do is make that reading impossible
/// whatever caused it, so a next occurrence means something else.
extern "C" fn handler(sig: i32) {
    HANDLED_BY.store(gettid(), Ordering::SeqCst);
    HANDLED_SIG.store(sig, Ordering::SeqCst);
}

fn gettid() -> i64 {
    unsafe { libc::syscall(libc::SYS_gettid) }
}

fn install(sig: i32) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn block(sig: i32, how: i32) {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, sig);
        libc::pthread_sigmask(how, &set, std::ptr::null_mut());
    }
}

/// Spins until `f` or the deadline. Returns whether it happened.
fn within(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    f()
}

fn main() {
    let mut h = Harness::new();
    let main_tid = gettid();
    check!(h, main_tid > 0, "gettid works: {main_tid}");

    install(libc::SIGUSR1);
    install(libc::SIGUSR2);

    h.group("process-directed-goes-to-a-thread-that-can-take-it");
    // Blocked here, in the group leader, and nowhere else.
    block(libc::SIGUSR1, libc::SIG_BLOCK);

    let ready = std::sync::Arc::new(AtomicI64::new(0));
    let stop = std::sync::Arc::new(AtomicI32::new(0));
    let worker = {
        let ready = ready.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            // Inherited the leader's mask, so it has to be undone here.
            block(libc::SIGUSR1, libc::SIG_UNBLOCK);
            // And SIGUSR2 blocked here as well as in the leader, for the group
            // below: that one is about a signal *no* thread can take, and a
            // worker that could take it would handle it and leave nothing
            // pending -- on either kernel, so the two would agree and the
            // check would be measuring nothing.
            block(libc::SIGUSR2, libc::SIG_BLOCK);
            ready.store(gettid(), Ordering::SeqCst);
            while stop.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };

    let worker_tid = if within(Duration::from_secs(2), || ready.load(Ordering::SeqCst) != 0) {
        ready.load(Ordering::SeqCst)
    } else {
        0
    };
    check!(h, worker_tid != 0 && worker_tid != main_tid,
        "a second thread with the signal unblocked: tid={worker_tid} main={main_tid}");

    HANDLED_BY.store(0, Ordering::SeqCst);
    HANDLED_SIG.store(0, Ordering::SeqCst);
    let pid = unsafe { libc::getpid() };
    let r = unsafe { libc::kill(pid, libc::SIGUSR1) };
    check!(h, r == 0, "kill(getpid(), SIGUSR1): r={r}");

    // Both, not just the signal number: a handler that has run has written the
    // tid first, so waiting for the pair is waiting for the handler to have
    // finished rather than to have started.
    let arrived = within(Duration::from_secs(2), || {
        HANDLED_SIG.load(Ordering::SeqCst) != 0 && HANDLED_BY.load(Ordering::SeqCst) != 0
    });
    check!(h, arrived,
        "a process-directed signal reaches a thread that has not blocked it");
    check!(h, HANDLED_SIG.load(Ordering::SeqCst) == libc::SIGUSR1,
        "and it is the one that was sent: {}", HANDLED_SIG.load(Ordering::SeqCst));
    check!(h, HANDLED_BY.load(Ordering::SeqCst) == worker_tid,
        "on that thread: handled_by={} worker={worker_tid} main={main_tid}",
        HANDLED_BY.load(Ordering::SeqCst));

    h.group("sigpending-is-process-wide");
    // SIGUSR2 blocked everywhere, then sent to the process. It has nowhere to
    // go, so it stays pending -- and sigpending() reports the union of what is
    // pending for the thread and for the process, so the leader must see it
    // even though it was not the thread it was queued on.
    block(libc::SIGUSR2, libc::SIG_BLOCK);
    let r = unsafe { libc::kill(pid, libc::SIGUSR2) };
    check!(h, r == 0, "kill(getpid(), SIGUSR2) with it blocked: r={r}");
    let seen = within(Duration::from_secs(2), || {
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut set) };
        unsafe { libc::sigpending(&mut set) };
        unsafe { libc::sigismember(&set, libc::SIGUSR2) == 1 }
    });
    check!(h, seen, "sigpending reports it");
    // And taking it with sigwait clears it.
    let mut wait_set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut wait_set) };
    unsafe { libc::sigaddset(&mut wait_set, libc::SIGUSR2) };
    let mut got = 0i32;
    let sw = unsafe { libc::sigwait(&wait_set, &mut got) };
    check!(h, sw == 0 && got == libc::SIGUSR2, "sigwait takes it: sw={sw} got={got}");
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    unsafe { libc::sigpending(&mut set) };
    check!(h, unsafe { libc::sigismember(&set, libc::SIGUSR2) } == 0,
        "and it is no longer pending");
    block(libc::SIGUSR2, libc::SIG_UNBLOCK);

    h.group("tgkill-names-one-thread");
    // The leader still has SIGUSR1 blocked, so a signal aimed at it must go
    // pending there rather than being handed to the thread that can take it.
    HANDLED_BY.store(0, Ordering::SeqCst);
    HANDLED_SIG.store(0, Ordering::SeqCst);
    let tgid = pid;
    let r = unsafe { libc::syscall(libc::SYS_tgkill, tgid, main_tid, libc::SIGUSR1) };
    check!(h, r == 0, "tgkill at the leader: r={r}");
    std::thread::sleep(Duration::from_millis(100));
    check!(h, HANDLED_SIG.load(Ordering::SeqCst) == 0,
        "does not run on the other thread: handled_by={}", HANDLED_BY.load(Ordering::SeqCst));
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    unsafe { libc::sigpending(&mut set) };
    check!(h, unsafe { libc::sigismember(&set, libc::SIGUSR1) } == 1,
        "it is pending on the leader instead");
    // Unblocking runs it here, which is the proof it was queued here.
    block(libc::SIGUSR1, libc::SIG_UNBLOCK);
    let ran = within(Duration::from_secs(2), || {
        HANDLED_SIG.load(Ordering::SeqCst) != 0 && HANDLED_BY.load(Ordering::SeqCst) != 0
    });
    check!(h, ran, "and unblocking delivers it");
    check!(h, HANDLED_BY.load(Ordering::SeqCst) == main_tid,
        "to the leader: handled_by={} main={main_tid}", HANDLED_BY.load(Ordering::SeqCst));

    h.group("kill-arguments");
    // Signal 0 delivers nothing and reports whether the process exists. It
    // still goes through the thread-choosing path, which has to cope with a
    // number that is not a signal.
    let r = unsafe { libc::kill(pid, 0) };
    check!(h, r == 0, "kill(getpid(), 0) is an existence check: r={r}");
    let r = unsafe { libc::kill(pid, 65) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EINVAL, "a signal number past the end: r={r} errno={e}");

    h.group("tgkill-arguments");
    let r = unsafe { libc::syscall(libc::SYS_tgkill, tgid, main_tid, 0) };
    check!(h, r == 0, "signal 0 is an existence check: r={r}");
    let r = unsafe { libc::syscall(libc::SYS_tgkill, tgid, 0, libc::SIGUSR1) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EINVAL, "tid 0 is EINVAL: r={r} errno={e}");
    let r = unsafe { libc::syscall(libc::SYS_tgkill, 0, main_tid, libc::SIGUSR1) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EINVAL, "tgid 0 is EINVAL: r={r} errno={e}");
    // A tid that exists in a different thread group is ESRCH, which is what
    // makes tgkill safe against tid reuse where tkill is not.
    let r = unsafe { libc::syscall(libc::SYS_tgkill, tgid + 100000, main_tid, libc::SIGUSR1) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::ESRCH, "a mismatched tgid is ESRCH: r={r} errno={e}");
    let r = unsafe { libc::syscall(libc::SYS_tkill, main_tid, 0) };
    check!(h, r == 0, "tkill with signal 0: r={r}");
    let r = unsafe { libc::syscall(libc::SYS_tkill, 0, libc::SIGUSR1) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EINVAL, "tkill tid 0 is EINVAL: r={r} errno={e}");

    stop.store(1, Ordering::SeqCst);
    worker.join().ok();
    std::process::exit(h.finish());
}
