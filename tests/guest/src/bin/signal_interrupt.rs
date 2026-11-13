//! A signal has to reach a thread that is blocked in a syscall.
//!
//! This is the direct probe for a defect found sideways: `realfs` retried every
//! host `EINTR`, which swallowed the wake the emulator uses to deliver a guest
//! signal into a blocking call. A guest blocked reading a pipe did not notice a
//! signal until the read finished on its own, and `kill -TERM` on a process
//! waiting for input did nothing until the input arrived. It was caught by a
//! test that signalled a *process group* and counted the dead; nothing asked
//! the question directly.
//!
//! The three answers, and they are different:
//!
//! - a caught signal with no `SA_RESTART` interrupts the call: `EINTR`.
//! - a caught signal **with** `SA_RESTART` runs the handler and the call
//!   carries on, so the caller never sees the interruption at all.
//! - an *ignored* signal does not interrupt anything. It is never queued, so
//!   there is nothing for the blocked thread to notice.
//!
//! The signal is sent with `tgkill` to the blocked thread by name. A
//! process-directed `kill` would be delivered to whichever thread could take
//! it, which here is as likely to be the one doing the sending.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicI32, Ordering};

use std::time::Duration;

static RAN: AtomicI32 = AtomicI32::new(0);

extern "C" fn handler(_: i32) {
    RAN.fetch_add(1, Ordering::SeqCst);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn install(sig: i32, restart: bool) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = if restart { libc::SA_RESTART } else { 0 };
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn ignore(sig: i32) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

/// What to do after the signal, and how long to wait first.
#[derive(Clone, Copy)]
enum Then {
    /// Nothing. The call under test is expected to come back on its own.
    Nothing,
    /// Write a byte, so a call that was restarted can finish.
    Write(i32),
}

/// Signals `tid` after 80ms, then does `then`, then — after a further second —
/// **rescues** whatever is blocked.
///
/// The rescue is what keeps a regression a failed check instead of a hung
/// suite. Backing the fix out and running this without one produced no output
/// at all: the read never returned, which is the bug exactly, and a test that
/// hangs is a test nobody can run. With it, a broken kernel returns the rescued
/// byte a second late and the check fails on what it returned.
fn poker(tid: i32, sig: i32, then: Then, rescue: Rescue) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(80));
        let tgid = unsafe { libc::getpid() };
        unsafe { libc::syscall(libc::SYS_tgkill, tgid, tid, sig) };
        if let Then::Write(w) = then {
            std::thread::sleep(Duration::from_millis(80));
            unsafe { libc::write(w, b"x".as_ptr().cast(), 1) };
        }
        std::thread::sleep(Duration::from_millis(1200));
        match rescue {
            Rescue::Write(w) => {
                unsafe { libc::write(w, b"!".as_ptr().cast(), 1) };
            }
            Rescue::Drain(r) => {
                let mut sink = vec![0u8; 65536];
                unsafe { libc::fcntl(r, libc::F_SETFL, libc::O_NONBLOCK) };
                while unsafe { libc::read(r, sink.as_mut_ptr().cast(), sink.len()) } > 0 {}
                unsafe { libc::fcntl(r, libc::F_SETFL, 0) };
            }
        }
    })
}

/// How to unblock the call under test if the kernel never does.
///
/// There was a `None` arm meaning "no rescue needed". Nothing ever built one,
/// so it was a case this file claimed to cover and did not; every call under
/// test here needs unblocking, which is what makes it a test of interruption.
#[derive(Clone, Copy)]
enum Rescue {
    Write(i32),
    Drain(i32),
}

fn main() {
    let mut h = Harness::new();
    let tid = gettid();

    h.group("a-caught-signal-interrupts-a-blocking-read");
    let mut p = [0i32; 2];
    check!(h, unsafe { libc::pipe(p.as_mut_ptr()) } == 0, "a pipe");
    install(libc::SIGUSR1, false);
    RAN.store(0, Ordering::SeqCst);
    let t = poker(tid, libc::SIGUSR1, Then::Nothing, Rescue::Write(p[1]));
    let mut buf = [0u8; 1];
    let n = unsafe { libc::read(p[0], buf.as_mut_ptr().cast(), 1) };
    let e = errno();
    t.join().ok();
    check!(h, n == -1 && e == libc::EINTR, "read is interrupted: n={n} errno={e}");
    check!(h, RAN.load(Ordering::SeqCst) == 1, "and the handler ran: {}",
        RAN.load(Ordering::SeqCst));

    h.group("SA_RESTART-carries-on-instead");
    // The handler runs and the read does not come back until it has something.
    install(libc::SIGUSR1, true);
    RAN.store(0, Ordering::SeqCst);
    let t = poker(tid, libc::SIGUSR1, Then::Write(p[1]), Rescue::Write(p[1]));
    let n = unsafe { libc::read(p[0], buf.as_mut_ptr().cast(), 1) };
    let e = errno();
    t.join().ok();
    check!(h, RAN.load(Ordering::SeqCst) == 1, "the handler ran: {}",
        RAN.load(Ordering::SeqCst));
    check!(h, n == 1, "and the read finished rather than failing: n={n} errno={e}");

    h.group("an-ignored-signal-interrupts-nothing");
    // Never queued, so there is nothing for a blocked thread to notice.
    ignore(libc::SIGUSR2);
    RAN.store(0, Ordering::SeqCst);
    let t = poker(tid, libc::SIGUSR2, Then::Write(p[1]), Rescue::Write(p[1]));
    let n = unsafe { libc::read(p[0], buf.as_mut_ptr().cast(), 1) };
    let e = errno();
    t.join().ok();
    check!(h, n == 1, "the read finished: n={n} errno={e}");
    check!(h, RAN.load(Ordering::SeqCst) == 0, "and nothing ran: {}",
        RAN.load(Ordering::SeqCst));

    h.group("a-blocked-signal-interrupts-nothing-either");
    // Pending, but the thread has said it does not want it yet.
    install(libc::SIGUSR1, false);
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    unsafe { libc::sigaddset(&mut set, libc::SIGUSR1) };
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    RAN.store(0, Ordering::SeqCst);
    let t = poker(tid, libc::SIGUSR1, Then::Write(p[1]), Rescue::Write(p[1]));
    let n = unsafe { libc::read(p[0], buf.as_mut_ptr().cast(), 1) };
    let e = errno();
    t.join().ok();
    check!(h, n == 1, "the read finished: n={n} errno={e}");
    check!(h, RAN.load(Ordering::SeqCst) == 0, "and the handler has not run yet: {}",
        RAN.load(Ordering::SeqCst));
    // Unblocking delivers it, which proves it really was pending all along.
    unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
    check!(h, RAN.load(Ordering::SeqCst) == 1, "and unblocking delivers it: {}",
        RAN.load(Ordering::SeqCst));

    h.group("a-write-that-blocks-is-interrupted-too");
    // Fill the pipe, then write into it with a signal on the way.
    unsafe { libc::fcntl(p[1], libc::F_SETFL, libc::O_NONBLOCK) };
    let filler = vec![0u8; 65536];
    while unsafe { libc::write(p[1], filler.as_ptr().cast(), filler.len()) } > 0 {}
    unsafe { libc::fcntl(p[1], libc::F_SETFL, 0) };
    install(libc::SIGUSR1, false);
    RAN.store(0, Ordering::SeqCst);
    let t = poker(tid, libc::SIGUSR1, Then::Nothing, Rescue::Drain(p[0]));
    let n = unsafe { libc::write(p[1], b"y".as_ptr().cast(), 1) };
    let e = errno();
    t.join().ok();
    check!(h, n == -1 && e == libc::EINTR, "the write is interrupted: n={n} errno={e}");
    check!(h, RAN.load(Ordering::SeqCst) == 1, "and the handler ran: {}",
        RAN.load(Ordering::SeqCst));

    h.group("splice-into-a-full-pipe-is-interruptible");
    // Filled again here rather than left over from the group above, whose
    // rescue drains it. A precondition that depends on what the previous group
    // left is not a precondition: without this the splice had room, moved 4096
    // bytes, and the check failed on both sides for a reason that had nothing
    // to do with the kernel.
    unsafe { libc::fcntl(p[1], libc::F_SETFL, libc::O_NONBLOCK) };
    while unsafe { libc::write(p[1], filler.as_ptr().cast(), filler.len()) } > 0 {}
    unsafe { libc::fcntl(p[1], libc::F_SETFL, 0) };
    // Nothing can move, so a signal has to come back as EINTR rather than as a
    // count -- there is no partial transfer to report.
    let src = "/tmp/signal_interrupt_src";
    std::fs::write(src, vec![7u8; 8192]).expect("a source file");
    let inf = unsafe { libc::open(guest_tests::cpath(src).as_ptr(), libc::O_RDONLY) };
    check!(h, inf >= 0, "a source: fd={inf}");
    RAN.store(0, Ordering::SeqCst);
    let t = poker(tid, libc::SIGUSR1, Then::Nothing, Rescue::Drain(p[0]));
    let n = unsafe {
        libc::syscall(libc::SYS_splice, inf, std::ptr::null_mut::<libc::off64_t>(),
                      p[1], std::ptr::null_mut::<libc::off64_t>(), 4096usize, 0u32)
    };
    let e = errno();
    t.join().ok();
    check!(h, n == -1 && e == libc::EINTR, "splice is interrupted: n={n} errno={e}");
    check!(h, RAN.load(Ordering::SeqCst) == 1, "and the handler ran: {}",
        RAN.load(Ordering::SeqCst));
    unsafe { libc::close(inf) };
    let _ = std::fs::remove_file(src);

    unsafe { libc::close(p[0]) };
    unsafe { libc::close(p[1]) };
    std::process::exit(h.finish());
}
