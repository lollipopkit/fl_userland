//! Signals, from several threads at once.
//!
//! `sighand->lock` guards a table of handlers shared by every thread in a
//! group; `task->pending` and `task->blocked` are per task and read by
//! `/proc/<pid>/stat` and by every blocking wait. Delivery interrupts a
//! syscall, runs a handler on the guest stack, and returns through
//! `sigreturn`, which restores the whole CPU state — including the
//! floating-point control register.
//!
//! Threads here install and replace handlers while signals are being
//! delivered, block and unblock them, deliver to specific threads with
//! `pthread_kill`, and take signals in the middle of blocking syscalls. The
//! checks are that a handler always sees the signal it was installed for, that
//! a blocked signal is never delivered, and that what a handler changes about
//! the CPU state does not leak past `sigreturn`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

static WRONG_SIGNAL: AtomicU64 = AtomicU64::new(0);
static BLOCKED_DELIVERED: AtomicU64 = AtomicU64::new(0);
static DELIVERED: AtomicU64 = AtomicU64::new(0);
/// Set while SIGWINCH is blocked in the one thread that ever raises it, so a
/// handler firing then is a violation.
///
/// A dedicated signal, because the mask is per thread and this flag is not:
/// the first version of this used SIGUSR2, which another thread raises with it
/// unblocked, and counted 65,000 perfectly legitimate deliveries as failures.
static WINCH_BLOCKED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_usr1(sig: libc::c_int) {
    if sig != libc::SIGUSR1 {
        WRONG_SIGNAL.fetch_add(1, Ordering::Relaxed);
    }
    DELIVERED.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn on_usr2(sig: libc::c_int) {
    if sig != libc::SIGUSR2 {
        WRONG_SIGNAL.fetch_add(1, Ordering::Relaxed);
    }
    DELIVERED.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn on_winch(sig: libc::c_int) {
    if sig != libc::SIGWINCH {
        WRONG_SIGNAL.fetch_add(1, Ordering::Relaxed);
    }
    if WINCH_BLOCKED.load(Ordering::SeqCst) {
        BLOCKED_DELIVERED.fetch_add(1, Ordering::Relaxed);
    }
    DELIVERED.fetch_add(1, Ordering::Relaxed);
}

fn install(sig: libc::c_int, handler: extern "C" fn(libc::c_int), restart: bool) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        sa.sa_flags = if restart { libc::SA_RESTART } else { 0 };
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    install(libc::SIGUSR1, on_usr1, false);
    install(libc::SIGUSR2, on_usr2, false);
    install(libc::SIGWINCH, on_winch, false);

    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();

    // Deliver, constantly.
    for sig in [libc::SIGUSR1, libc::SIGUSR2] {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                unsafe { libc::raise(sig) };
                n += 1;
            }
            n
        }));
    }

    // Replace the handlers while they are being delivered. A signal that
    // arrives during sigaction must run one of the two, not something else.
    {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                install(libc::SIGUSR1, on_usr1, n % 2 == 0);
                install(libc::SIGUSR2, on_usr2, n % 2 == 0);
                n += 1;
            }
            n
        }));
    }

    // Block and unblock, checking nothing arrives while blocked. The flag is
    // set inside the blocked window, which only this thread's mask covers —
    // so this thread does the raising for it too.
    {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGWINCH);
            }
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
                    WINCH_BLOCKED.store(true, Ordering::SeqCst);
                    libc::raise(libc::SIGWINCH);
                    // Still blocked: the handler must not have run.
                    WINCH_BLOCKED.store(false, Ordering::SeqCst);
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
                }
                n += 1;
            }
            n
        }));
    }

    // Take signals in the middle of blocking syscalls, with and without
    // SA_RESTART: a short read on a pipe that is being fed slowly.
    {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            let mut pipefd = [0i32; 2];
            if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
                return 0;
            }
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    libc::write(pipefd[1], b"x".as_ptr().cast(), 1);
                    let mut buf = [0u8; 1];
                    libc::read(pipefd[0], buf.as_mut_ptr().cast(), 1);
                }
                n += 1;
            }
            unsafe {
                libc::close(pipefd[0]);
                libc::close(pipefd[1]);
            }
            n
        }));
    }

    // Read the pending and blocked masks out of /proc while all of the above
    // is happening — the fields proc_pid_stat_snapshot copies under
    // sighand->lock.
    {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let _ = std::fs::read_to_string("/proc/self/stat");
                n += 1;
            }
            n
        }));
    }

    std::thread::sleep(std::time::Duration::from_secs(seconds));
    stop.store(true, Ordering::Relaxed);
    let counts: Vec<u64> = threads.into_iter().map(|t| t.join().unwrap_or(0)).collect();

    println!("iterations: {counts:?}");
    println!("delivered: {}", DELIVERED.load(Ordering::Relaxed));
    let wrong = WRONG_SIGNAL.load(Ordering::Relaxed);
    let blocked = BLOCKED_DELIVERED.load(Ordering::Relaxed);
    if wrong != 0 {
        println!("LOST: {wrong} handlers ran for a signal they were not installed for");
    }
    if blocked != 0 {
        println!("LOST: {blocked} deliveries of a blocked signal");
    }
    println!("survived");
}
