//! What makes a signal pending, and what takes it off again.
//!
//! Three mechanisms read the same per-task state and they have to agree:
//! `sigpending` reports it, `sigwaitinfo` consumes one entry, and a `signalfd`
//! turns "there is one" into a pollable event. The kernel keeps a bitmask of
//! signal numbers beside a queue of `struct siginfo`, and every check here is
//! ultimately about those two staying in step.
//!
//! The interesting cases are all about *blocked* signals, because that is the
//! only state in which a signal is pending long enough to be observed:
//!
//!   * A signal whose disposition says ignore is still kept when it is
//!     blocked — the disposition can change before it is unblocked, and
//!     `sigwait`/`signalfd` are entitled to it either way. SIGCHLD's default
//!     action is to ignore, which makes this the single most common case
//!     rather than a corner.
//!   * Consuming a signal has to clear the bitmask as well as the queue. A
//!     standard signal whose bit is already set is not queued again, so a
//!     dequeue that leaves the bit behind silently stops that signal for the
//!     rest of the process's life — which the second `sigwaitinfo` here is
//!     what catches.
//!   * A blocked signal still has to *wake* a thread that is watching for it
//!     through a signalfd, or a poll loop sleeps through the event.

use guest_tests::{Harness, check, check_fails};

const SFD_CLOEXEC: i32 = 0o2000000;
const SFD_NONBLOCK: i32 = 0o4000;

/// The 128-byte record a signalfd read yields.
#[repr(C)]
#[derive(Clone, Copy)]
struct SignalfdSiginfo {
    signo: u32,
    err: i32,
    code: i32,
    pid: u32,
    uid: u32,
    fd: i32,
    tid: u32,
    band: u32,
    overrun: u32,
    trapno: u32,
    status: i32,
    int_: i32,
    ptr: u64,
    utime: u64,
    stime: u64,
    addr: u64,
    addr_lsb: u16,
    pad: [u8; 46],
}

impl SignalfdSiginfo {
    fn zeroed() -> SignalfdSiginfo {
        // SAFETY: every field is an integer, and the record is what the
        // kernel is about to overwrite anyway.
        unsafe { std::mem::zeroed() }
    }
}

fn sigset(sigs: &[i32]) -> libc::sigset_t {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    for &s in sigs {
        unsafe { libc::sigaddset(&mut set, s) };
    }
    set
}

fn block(sigs: &[i32]) {
    let set = sigset(sigs);
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
}

fn unblock(sigs: &[i32]) {
    let set = sigset(sigs);
    unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
}

fn is_pending(sig: i32) -> bool {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigpending(&mut set);
        libc::sigismember(&set, sig) == 1
    }
}

/// sigwaitinfo with a timeout, so a lost signal fails the test instead of
/// hanging it. Returns the signal number, or -1 on timeout.
fn wait_sig(sigs: &[i32], ms: i64) -> i32 {
    let set = sigset(sigs);
    let ts = libc::timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::sigtimedwait(&set, &mut info, &ts) };
    if r < 0 { -1 } else { r }
}

fn signalfd(fd: i32, sigs: &[i32], flags: i32) -> i32 {
    let set = sigset(sigs);
    // musl's signalfd() wrapper hides the size argument; go straight to the
    // syscall so the argument checks below are reachable at all.
    unsafe { libc::syscall(libc::SYS_signalfd4, fd, &set, 8usize, flags) as i32 }
}

fn read_record(fd: i32) -> Option<SignalfdSiginfo> {
    let mut rec = SignalfdSiginfo::zeroed();
    let n = unsafe {
        libc::read(
            fd,
            (&raw mut rec).cast(),
            size_of::<SignalfdSiginfo>(),
        )
    };
    if n == size_of::<SignalfdSiginfo>() as isize {
        Some(rec)
    } else {
        None
    }
}

/// What poll(2) said: the return value, and the revents it filled in.
///
/// Both, because -1 has to be told apart from 0 and from a revents. The first
/// version of this returned revents-or-the-return-value, and `-1 & POLLIN` is
/// nonzero -- so a poll that failed with EINTR read as readable and the check
/// that was written to catch exactly that passed.
fn poll_once(fd: i32, ms: i32) -> (i32, i32) {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let r = unsafe { libc::poll(&mut p, 1, ms) };
    (r, p.revents as i32)
}

fn poll_readable(fd: i32, ms: i32) -> bool {
    let (r, revents) = poll_once(fd, ms);
    r > 0 && revents & libc::POLLIN as i32 != 0
}

/// A signal whose disposition is "ignore" is still kept while it is blocked.
fn t_blocked_ignored_stays_pending(h: &mut Harness) {
    h.group("blocked-ignored");

    // SIGCHLD, left at SIG_DFL, whose default action is to ignore.
    block(&[libc::SIGCHLD]);
    unsafe { libc::raise(libc::SIGCHLD) };
    check!(h, is_pending(libc::SIGCHLD), "a blocked SIGCHLD is pending");
    check!(
        h,
        wait_sig(&[libc::SIGCHLD], 500) == libc::SIGCHLD,
        "sigwaitinfo returns the blocked SIGCHLD"
    );
    unblock(&[libc::SIGCHLD]);

    // The same for a signal explicitly set to SIG_IGN: the handler can be
    // replaced before it is unblocked, so the kernel may not decide now.
    unsafe { libc::signal(libc::SIGUSR2, libc::SIG_IGN) };
    block(&[libc::SIGUSR2]);
    unsafe { libc::raise(libc::SIGUSR2) };
    check!(
        h,
        is_pending(libc::SIGUSR2),
        "a blocked SIG_IGN signal is pending"
    );
    check!(
        h,
        wait_sig(&[libc::SIGUSR2], 500) == libc::SIGUSR2,
        "sigwaitinfo returns the blocked SIG_IGN signal"
    );
    unblock(&[libc::SIGUSR2]);
    unsafe { libc::signal(libc::SIGUSR2, libc::SIG_DFL) };

    // Unblocked, an ignored signal is dropped and never becomes pending.
    unsafe { libc::raise(libc::SIGCHLD) };
    check!(
        h,
        !is_pending(libc::SIGCHLD),
        "an unblocked SIGCHLD is not left pending"
    );
}

/// Consuming a signal clears the bitmask, not only the queue entry.
fn t_dequeue_clears_pending(h: &mut Harness) {
    h.group("sigwait-consumes");

    block(&[libc::SIGUSR1]);
    unsafe { libc::raise(libc::SIGUSR1) };
    check!(
        h,
        wait_sig(&[libc::SIGUSR1], 500) == libc::SIGUSR1,
        "first sigwaitinfo takes the signal"
    );
    check!(
        h,
        !is_pending(libc::SIGUSR1),
        "sigpending is empty once the signal has been taken"
    );

    // The one that matters. A standard signal whose pending bit is still set
    // is not queued a second time, so if the first dequeue left the bit behind
    // this raise is dropped and the wait times out.
    unsafe { libc::raise(libc::SIGUSR1) };
    check!(
        h,
        is_pending(libc::SIGUSR1),
        "a second raise makes it pending again"
    );
    check!(
        h,
        wait_sig(&[libc::SIGUSR1], 500) == libc::SIGUSR1,
        "second sigwaitinfo takes the second signal"
    );
    check!(
        h,
        !is_pending(libc::SIGUSR1),
        "and clears it again"
    );

    // A third time, because two could be a coincidence and this is cheap.
    unsafe { libc::raise(libc::SIGUSR1) };
    check!(
        h,
        wait_sig(&[libc::SIGUSR1], 500) == libc::SIGUSR1,
        "third sigwaitinfo takes the third signal"
    );
    unblock(&[libc::SIGUSR1]);
}

/// sigtimedwait's own contract, around the edges.
fn t_sigtimedwait_edges(h: &mut Harness) {
    h.group("sigtimedwait");

    block(&[libc::SIGUSR1]);
    check!(
        h,
        wait_sig(&[libc::SIGUSR1], 50) == -1,
        "nothing pending: the wait times out"
    );
    check!(
        h,
        guest_tests::sys::errno() == libc::EAGAIN,
        "and the errno is EAGAIN, not ETIMEDOUT"
    );

    // A signal that arrived before the call is returned without waiting: it
    // will not be announced a second time.
    unsafe { libc::raise(libc::SIGUSR1) };
    let started = std::time::Instant::now();
    check!(
        h,
        wait_sig(&[libc::SIGUSR1], 5000) == libc::SIGUSR1,
        "an already-pending signal is returned"
    );
    check!(
        h,
        started.elapsed() < std::time::Duration::from_secs(2),
        "and returned promptly, not after the timeout"
    );
    // The timeout is a deadline, not something re-armed on every wakeup.
    //
    // The noise is a real-time signal because standard ones coalesce: once
    // SIGCHLD is pending, deliver_signal_unlocked drops the next one before it
    // wakes anybody, so a first attempt at this produced exactly one wakeup
    // and passed against a wait that restarted its timeout every time. RT
    // signals queue, so each one is a wakeup.
    //
    // It has to be a signal this thread is watching through a signalfd, since
    // that is what makes a *blocked* signal wake anything at all. None of them
    // is in the set being waited for, so every wakeup they cause is spurious,
    // which is the point.
    let rt = libc::SIGRTMIN();
    let sfd = signalfd(-1, &[rt], 0);
    block(&[rt]);
    let noise = std::thread::spawn({
        let me = Tid(unsafe { libc::pthread_self() } as usize);
        move || {
            for _ in 0..48 {
                std::thread::sleep(std::time::Duration::from_millis(25));
                unsafe { libc::pthread_kill(me.0 as libc::pthread_t, rt) };
            }
        }
    });
    let started = std::time::Instant::now();
    check!(
        h,
        wait_sig(&[libc::SIGUSR1], 300) == -1,
        "a wait for something that never arrives still times out"
    );
    let waited = started.elapsed();
    check!(
        h,
        waited < std::time::Duration::from_millis(600),
        "and at its deadline rather than restarting: waited {waited:?}"
    );
    let _ = noise.join();
    unsafe { libc::close(sfd) };
    // Drain what the noise thread left queued.
    while wait_sig(&[rt], 0) == rt {}
    unblock(&[rt]);

    unblock(&[libc::SIGUSR1]);
}

/// The argument checks, which are all a program can rely on when it gets them
/// wrong.
fn t_signalfd_arguments(h: &mut Harness) {
    h.group("signalfd-args");

    let set = sigset(&[libc::SIGUSR1]);
    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_signalfd4, -1, &set, 8usize, 1 << 20) },
        libc::EINVAL,
        "an unknown flag"
    );
    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_signalfd4, -1, &set, 4usize, 0) },
        libc::EINVAL,
        "a sigset size that is not 8"
    );
    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_signalfd4, -1, std::ptr::null::<u8>(), 8usize, 0) },
        libc::EFAULT,
        "a null mask"
    );
    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_signalfd4, 4096, &set, 8usize, 0) },
        libc::EBADF,
        "retargeting a descriptor that does not exist"
    );

    // Retargeting something that is not a signalfd.
    let pipe = unsafe {
        let mut p = [0i32; 2];
        libc::pipe(p.as_mut_ptr());
        p
    };
    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_signalfd4, pipe[0], &set, 8usize, 0) },
        libc::EINVAL,
        "retargeting a pipe"
    );
    unsafe {
        libc::close(pipe[0]);
        libc::close(pipe[1]);
    }

    // A read too small for one record is EINVAL, not a short read.
    let sfd = signalfd(-1, &[libc::SIGUSR1], 0);
    if sfd < 0 {
        check!(h, false, "creating a signalfd: errno {}", guest_tests::sys::errno());
        return;
    }
    let mut small = [0u8; 64];
    check_fails!(
        h,
        unsafe { libc::read(sfd, small.as_mut_ptr().cast(), small.len()) },
        libc::EINVAL,
        "a read of less than one record"
    );

    // SFD_CLOEXEC has to reach the descriptor flags.
    let c = signalfd(-1, &[libc::SIGUSR1], SFD_CLOEXEC);
    check!(
        h,
        c >= 0 && unsafe { libc::fcntl(c, libc::F_GETFD) } & libc::FD_CLOEXEC != 0,
        "SFD_CLOEXEC sets FD_CLOEXEC"
    );
    check!(
        h,
        unsafe { libc::fcntl(sfd, libc::F_GETFD) } & libc::FD_CLOEXEC == 0,
        "and without it the descriptor is not close-on-exec"
    );
    unsafe {
        libc::close(c);
        libc::close(sfd);
    }
}

/// Reading signals off the descriptor.
fn t_signalfd_read(h: &mut Harness) {
    h.group("signalfd-read");

    block(&[libc::SIGUSR1, libc::SIGUSR2]);
    let sfd = signalfd(-1, &[libc::SIGUSR1], SFD_NONBLOCK);
    if sfd < 0 {
        check!(h, false, "creating a signalfd: errno {}", guest_tests::sys::errno());
        return;
    }

    // Nothing pending.
    check_fails!(
        h,
        unsafe {
            let mut rec = SignalfdSiginfo::zeroed();
            libc::read(fd_of(sfd), (&raw mut rec).cast(), size_of::<SignalfdSiginfo>())
        },
        libc::EAGAIN,
        "a non-blocking read with nothing pending"
    );
    check!(h, !poll_readable(sfd, 0), "and poll says not readable");

    // One signal in the mask.
    unsafe { libc::raise(libc::SIGUSR1) };
    check!(
        h,
        poll_readable(sfd, 500),
        "poll says readable once the signal is pending"
    );
    match read_record(sfd) {
        Some(rec) => {
            check!(
                h,
                rec.signo == libc::SIGUSR1 as u32,
                "ssi_signo is SIGUSR1, got {}",
                rec.signo
            );
        }
        None => check!(h, false, "reading a record: errno {}", guest_tests::sys::errno()),
    }
    check!(
        h,
        !is_pending(libc::SIGUSR1),
        "the read consumed it: sigpending is empty"
    );
    check!(h, !poll_readable(sfd, 0), "and poll says not readable again");

    // A signal outside the mask is not this descriptor's business, and is left
    // pending for whoever does want it.
    unsafe { libc::raise(libc::SIGUSR2) };
    check!(
        h,
        !poll_readable(sfd, 50),
        "a signal outside the mask does not make it readable"
    );
    check!(
        h,
        is_pending(libc::SIGUSR2),
        "and is left pending"
    );

    // Retargeting picks it up without losing it.
    check!(
        h,
        signalfd(sfd, &[libc::SIGUSR2], 0) == sfd,
        "retargeting returns the same descriptor"
    );
    check!(
        h,
        poll_readable(sfd, 500),
        "and the already-pending signal is now readable"
    );
    check!(
        h,
        read_record(sfd).map(|r| r.signo) == Some(libc::SIGUSR2 as u32),
        "which reads back as SIGUSR2"
    );

    unsafe { libc::close(sfd) };
    unblock(&[libc::SIGUSR1, libc::SIGUSR2]);
}

// libc::read wants a plain i32; this exists only to keep the check_fails!
// invocation above readable.
fn fd_of(fd: i32) -> i32 {
    fd
}

/// The canonical use: a child exit arriving as a pollable event.
///
/// SIGCHLD's default action is to ignore, so this only works if a blocked
/// signal is kept regardless of disposition. It is also the case a real event
/// loop is written against.
fn t_signalfd_sigchld(h: &mut Harness) {
    h.group("signalfd-sigchld");

    block(&[libc::SIGCHLD]);
    let sfd = signalfd(-1, &[libc::SIGCHLD], 0);
    if sfd < 0 {
        check!(h, false, "creating a signalfd: errno {}", guest_tests::sys::errno());
        return;
    }

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::_exit(7) };
    }
    check!(h, pid > 0, "forking a child");

    let started = std::time::Instant::now();
    let (r, revents) = poll_once(sfd, 5000);
    let waited = started.elapsed();
    let readable = r > 0 && revents & libc::POLLIN as i32 != 0;
    check!(
        h,
        readable,
        "the child's exit makes the signalfd readable: poll returned {r} \
         revents {revents:#x} errno {}",
        guest_tests::sys::errno()
    );
    // Named separately, because the way this fails is specific: the host
    // wakeup that carries the event is a SIGUSR1 to this thread, and poll
    // reporting the interruption instead of re-polling turns an event into a
    // syscall failure the guest never asked for.
    check!(
        h,
        r >= 0,
        "poll did not fail: returned {r} errno {}",
        guest_tests::sys::errno()
    );
    // And promptly. A blocked signal wakes nobody by default, which is the
    // whole point of blocking it -- but a signalfd exists to watch blocked
    // signals, so the thread has to be woken for one anyway. Without that,
    // poll only notices when its one-second re-check slice expires, and an
    // event loop that waits for a child exit pays a second per child.
    check!(
        h,
        waited < std::time::Duration::from_millis(400),
        "and promptly: poll took {waited:?}"
    );
    // Guarded: reading a blocking descriptor that poll says is empty would
    // hang the run instead of reporting the failure above.
    match if readable { read_record(sfd) } else { None } {
        Some(rec) => {
            check!(
                h,
                rec.signo == libc::SIGCHLD as u32,
                "ssi_signo is SIGCHLD, got {}",
                rec.signo
            );
            check!(
                h,
                rec.pid == pid as u32,
                "ssi_pid is the child, want {pid} got {}",
                rec.pid
            );
            check!(
                h,
                rec.status == 7,
                "ssi_status is the exit code, want 7 got {}",
                rec.status
            );
            check!(
                h,
                rec.code == libc::CLD_EXITED,
                "ssi_code is CLD_EXITED, got {}",
                rec.code
            );
        }
        None => check!(h, false, "reading a record: errno {}", guest_tests::sys::errno()),
    }

    let mut status = 0;
    check!(
        h,
        unsafe { libc::waitpid(pid, &mut status, 0) } == pid,
        "the child is still reapable after the signalfd read"
    );

    unsafe { libc::close(sfd) };
    unblock(&[libc::SIGCHLD]);
}

/// pthread_t is a pointer on musl and so not Send; this carries it to a helper
/// thread as a plain integer. The thread it names outlives every helper here.
struct Tid(usize);
unsafe impl Send for Tid {}

extern "C" fn watchdog_handler(_: libc::c_int) {}

/// A blocking read has to be woken by a signal that is blocked — the whole
/// point of the descriptor, and the case a "blocked signals wake nobody" rule
/// would sleep through.
fn t_signalfd_blocking_read(h: &mut Harness) {
    h.group("signalfd-wakeup");

    block(&[libc::SIGUSR1]);
    let sfd = signalfd(-1, &[libc::SIGUSR1], 0);
    if sfd < 0 {
        check!(h, false, "creating a signalfd: errno {}", guest_tests::sys::errno());
        return;
    }

    let me = Tid(unsafe { libc::pthread_self() } as usize);
    // SIGURG is the watchdog's; its default action is to ignore, so it needs a
    // handler to interrupt a read at all.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = watchdog_handler as *const () as usize;
        libc::sigaction(libc::SIGURG, &sa, std::ptr::null_mut());
    }
    let waker = std::thread::spawn({
        let me = Tid(me.0);
        move || {
        std::thread::sleep(std::time::Duration::from_millis(150));
        // pthread_kill, not raise: this has to land on the parked thread.
        unsafe { libc::pthread_kill(me.0 as libc::pthread_t, libc::SIGUSR1) };
    }});

    // A watchdog, so a read that is never woken fails instead of hanging: an
    // unblocked signal with a handler interrupts it and the read comes back
    // EINTR.
    let watchdog = std::thread::spawn({
        let me = Tid(me.0);
        move || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            unsafe { libc::pthread_kill(me.0 as libc::pthread_t, libc::SIGURG) };
        }
    });

    let started = std::time::Instant::now();
    let rec = read_record(sfd);
    let waited = started.elapsed();
    let _ = watchdog.join();
    check!(
        h,
        rec.map(|r| r.signo) == Some(libc::SIGUSR1 as u32),
        "the blocking read returns the signal"
    );
    // Generous, but well under the second-long slice a poll loop falls back
    // to when nothing wakes it: this is about the wakeup existing at all.
    check!(
        h,
        waited < std::time::Duration::from_millis(900),
        "and was woken rather than polling: waited {waited:?}"
    );
    let _ = waker.join();

    unsafe { libc::close(sfd) };
    unblock(&[libc::SIGUSR1]);
}

/// Neither mechanism may consume SIGKILL.
///
/// Taking a signal off the queue is what consumes it, so a task that could
/// name SIGKILL in a `sigwait` set or a signalfd mask would swallow its own
/// kill and become unkillable. Checked from a child, because the only way to
/// find out is to send one.
fn t_sigkill_is_not_waitable(h: &mut Harness) {
    h.group("unkillable");

    for (what, mode) in [("sigwaitinfo", "sigwait"), ("a signalfd read", "signalfd")] {
        let exe = std::env::args().next().unwrap_or_default();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let c = std::ffi::CString::new(exe).unwrap();
            let m = std::ffi::CString::new(mode).unwrap();
            unsafe {
                libc::execl(c.as_ptr(), c.as_ptr(), m.as_ptr(), std::ptr::null::<libc::c_char>());
                libc::_exit(71);
            }
        }
        if pid < 0 {
            check!(h, false, "forking for {what}");
            continue;
        }
        // Long enough for the child to reach the wait.
        std::thread::sleep(std::time::Duration::from_millis(300));
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut status = 0;
        let got = unsafe { libc::waitpid(pid, &mut status, 0) };
        check!(
            h,
            got == pid && libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL,
            "SIGKILL kills a task parked in {what}: waitpid={got} status={status:#x}"
        );
    }
}

/// The child half of t_sigkill_is_not_waitable: park, naming SIGKILL, and wait
/// to be killed. Exiting on its own is the failure.
fn unkillable_child(mode: &str) -> ! {
    unsafe {
        let all = sigset(&[libc::SIGKILL, libc::SIGUSR1]);
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
        if mode == "signalfd" {
            let sfd = signalfd(-1, &[libc::SIGKILL, libc::SIGUSR1], 0);
            if sfd >= 0 {
                let mut rec = SignalfdSiginfo::zeroed();
                libc::read(sfd, (&raw mut rec).cast(), size_of::<SignalfdSiginfo>());
            }
        } else {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let ts = libc::timespec { tv_sec: 30, tv_nsec: 0 };
            libc::sigtimedwait(&all, &mut info, &ts);
        }
        // Reached only if the wait returned, which means it took the SIGKILL.
        libc::_exit(9);
    }
}

fn main() {
    if let Some(mode) = std::env::args().nth(1) {
        unkillable_child(&mode);
    }
    let mut h = Harness::new();
    t_blocked_ignored_stays_pending(&mut h);
    t_dequeue_clears_pending(&mut h);
    t_sigtimedwait_edges(&mut h);
    t_signalfd_arguments(&mut h);
    t_signalfd_read(&mut h);
    t_signalfd_sigchld(&mut h);
    t_signalfd_blocking_read(&mut h);
    t_sigkill_is_not_waitable(&mut h);
    std::process::exit(h.finish());
}
