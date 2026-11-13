//! Pipes, eventfd and timerfd.
//!
//! The async plumbing every runtime is built from: libuv's async handle is an
//! eventfd, its timers a timerfd, Go's netpoll breaker a pipe, and every
//! shell pipeline is the first of those. None of the three had any coverage.
//!
//! A pipe here is a host pipe behind an adhoc descriptor, so the questions are
//! whether the guest's flags reach the host descriptor and whether the errnos
//! come back translated. eventfd and timerfd are implemented in the emulator,
//! so theirs are about the semantics.

use std::sync::atomic::{AtomicU32, Ordering};

use guest_tests::{Harness, check, check_fails, sys};

const EFD_SEMAPHORE: i32 = 1;
const EFD_CLOEXEC: i32 = 0o2000000;
const EFD_NONBLOCK: i32 = 0o4000;

const TFD_CLOEXEC: i32 = 0o2000000;
const TFD_NONBLOCK: i32 = 0o4000;

static SIGPIPES: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_sigpipe(_: libc::c_int) {
    SIGPIPES.fetch_add(1, Ordering::Relaxed);
}

fn pipe2(flags: i32) -> Option<(i32, i32)> {
    let mut p = [0i32; 2];
    let r = unsafe { libc::syscall(libc::SYS_pipe2, p.as_mut_ptr(), flags) };
    (r == 0).then_some((p[0], p[1]))
}

fn eventfd(init: u32, flags: i32) -> i32 {
    unsafe { libc::syscall(libc::SYS_eventfd2, init, flags) as i32 }
}

fn efd_write(fd: i32, v: u64) -> isize {
    unsafe { libc::write(fd, (&raw const v).cast(), 8) }
}

fn efd_read(fd: i32) -> Option<u64> {
    let mut v: u64 = 0;
    (unsafe { libc::read(fd, (&raw mut v).cast(), 8) } == 8).then_some(v)
}

fn readable(fd: i32, ms: i32) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let n = unsafe { libc::poll(&mut p, 1, ms) };
    n > 0 && p.revents & libc::POLLIN != 0
}

fn t_pipe_flags(h: &mut Harness) {
    h.group("pipe-flags");

    let Some((r, w)) = pipe2(0) else {
        check!(h, false, "pipe2(0)");
        return;
    };
    check!(
        h,
        unsafe { libc::fcntl(r, libc::F_GETFD) } & libc::FD_CLOEXEC == 0,
        "without O_CLOEXEC the descriptors are not close-on-exec"
    );
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check!(
        h,
        unsafe { libc::fstat(r, &mut st) } == 0 && st.st_mode & libc::S_IFMT == libc::S_IFIFO,
        "fstat says S_IFIFO, got mode {:#o}",
        st.st_mode
    );
    check_fails!(
        h,
        unsafe { libc::lseek(r, 0, libc::SEEK_SET) },
        libc::ESPIPE,
        "seeking a pipe"
    );
    sys::close(r);
    sys::close(w);

    let Some((r, w)) = pipe2(libc::O_CLOEXEC) else {
        check!(h, false, "pipe2(O_CLOEXEC)");
        return;
    };
    check!(
        h,
        unsafe { libc::fcntl(r, libc::F_GETFD) } & libc::FD_CLOEXEC != 0
            && unsafe { libc::fcntl(w, libc::F_GETFD) } & libc::FD_CLOEXEC != 0,
        "O_CLOEXEC sets FD_CLOEXEC on both ends"
    );
    sys::close(r);
    sys::close(w);

    // O_NONBLOCK has to reach the *host* descriptor: the read below goes
    // straight to it, so a flag recorded only on the guest side would block
    // for ever rather than answering EAGAIN.
    let Some((r, w)) = pipe2(libc::O_NONBLOCK) else {
        check!(h, false, "pipe2(O_NONBLOCK)");
        return;
    };
    let mut buf = [0u8; 8];
    check_fails!(
        h,
        sys::read(r, &mut buf) as i64,
        libc::EAGAIN,
        "a non-blocking read of an empty pipe"
    );
    check!(
        h,
        unsafe { libc::fcntl(r, libc::F_GETFL) } & libc::O_NONBLOCK != 0,
        "and F_GETFL reports it"
    );
    // Fill it, which must eventually answer EAGAIN rather than block.
    let big = vec![0u8; 4096];
    let mut wrote = 0i64;
    let mut filled = false;
    for _ in 0..256 {
        let n = sys::write(w, &big);
        if n < 0 {
            filled = sys::errno() == libc::EAGAIN;
            break;
        }
        wrote += n as i64;
    }
    check!(
        h,
        filled,
        "a full non-blocking pipe answers EAGAIN after {wrote} bytes"
    );
    sys::close(r);
    sys::close(w);

    check_fails!(
        h,
        {
            let mut p = [0i32; 2];
            unsafe { libc::syscall(libc::SYS_pipe2, p.as_mut_ptr(), 1 << 20) }
        },
        libc::EINVAL,
        "an unsupported pipe2 flag"
    );
}

fn t_pipe_ends(h: &mut Harness) {
    h.group("pipe-ends");
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigpipe as *const () as usize;
        libc::sigaction(libc::SIGPIPE, &sa, std::ptr::null_mut());
    }

    // Closing the write end is EOF for the reader.
    let Some((r, w)) = pipe2(0) else {
        check!(h, false, "pipe2");
        return;
    };
    sys::write(w, b"abc");
    sys::close(w);
    let mut buf = [0u8; 16];
    check!(h, sys::read(r, &mut buf) == 3, "the buffered bytes are still there");
    check!(h, sys::read(r, &mut buf) == 0, "and then end of file");
    check!(h, sys::read(r, &mut buf) == 0, "which repeats");
    sys::close(r);

    // Closing the read end makes a write EPIPE, and raises SIGPIPE.
    let Some((r, w)) = pipe2(0) else {
        check!(h, false, "second pipe2");
        return;
    };
    sys::close(r);
    let before = SIGPIPES.load(Ordering::Relaxed);
    check_fails!(
        h,
        sys::write(w, b"x") as i64,
        libc::EPIPE,
        "writing to a pipe whose read end is closed"
    );
    check!(
        h,
        SIGPIPES.load(Ordering::Relaxed) == before + 1,
        "and SIGPIPE is raised once, got {}",
        SIGPIPES.load(Ordering::Relaxed) - before
    );
    sys::close(w);
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}

fn t_eventfd(h: &mut Harness) {
    h.group("eventfd");

    let fd = eventfd(0, 0);
    if fd < 0 {
        check!(h, false, "eventfd2(0, 0): errno {}", sys::errno());
        return;
    }
    check!(h, efd_write(fd, 1) == 8, "writing 1");
    check!(h, efd_read(fd) == Some(1), "reads back 1");

    // The counter accumulates, and a read takes all of it.
    efd_write(fd, 1);
    efd_write(fd, 2);
    efd_write(fd, 3);
    check!(h, efd_read(fd) == Some(6), "three writes accumulate into one read");

    // Short buffers are EINVAL on both sides, and so is the reserved value.
    let mut small = [0u8; 4];
    check_fails!(
        h,
        unsafe { libc::read(fd, small.as_mut_ptr().cast(), 4) },
        libc::EINVAL,
        "a read of fewer than eight bytes"
    );
    check_fails!(
        h,
        unsafe { libc::write(fd, small.as_ptr().cast(), 4) },
        libc::EINVAL,
        "a write of fewer than eight bytes"
    );
    check_fails!(
        h,
        efd_write(fd, u64::MAX) as i64,
        libc::EINVAL,
        "writing the reserved 0xffffffffffffffff"
    );
    sys::close(fd);

    // Non-blocking: a read of zero is EAGAIN rather than a wait.
    let fd = eventfd(0, EFD_NONBLOCK);
    let mut v = [0u8; 8];
    check_fails!(
        h,
        unsafe { libc::read(fd, v.as_mut_ptr().cast(), 8) },
        libc::EAGAIN,
        "a non-blocking read of a zero counter"
    );
    check!(h, !readable(fd, 0), "and poll says it is not readable");
    efd_write(fd, 5);
    check!(h, readable(fd, 100), "and readable once it is non-zero");
    sys::close(fd);

    // Semaphore mode hands out one at a time.
    let fd = eventfd(3, EFD_SEMAPHORE | EFD_NONBLOCK);
    if fd < 0 {
        check!(h, false, "eventfd2 with EFD_SEMAPHORE: errno {}", sys::errno());
    } else {
        check!(h, efd_read(fd) == Some(1), "semaphore mode reads 1");
        check!(h, efd_read(fd) == Some(1), "and 1 again");
        check!(h, efd_read(fd) == Some(1), "and a third time");
        let mut v = [0u8; 8];
        check_fails!(
            h,
            unsafe { libc::read(fd, v.as_mut_ptr().cast(), 8) },
            libc::EAGAIN,
            "and is empty after the initial count is used up"
        );
        sys::close(fd);
    }

    // The initial value is the counter, not a size hint.
    let fd = eventfd(7, EFD_NONBLOCK);
    check!(h, efd_read(fd) == Some(7), "the initial value is the counter");
    sys::close(fd);

    let fd = eventfd(0, EFD_CLOEXEC);
    check!(
        h,
        fd >= 0 && unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC != 0,
        "EFD_CLOEXEC sets FD_CLOEXEC"
    );
    sys::close(fd);

    check_fails!(
        h,
        eventfd(0, 1 << 20) as i64,
        libc::EINVAL,
        "an unknown eventfd flag"
    );
}

fn t_timerfd(h: &mut Harness) {
    h.group("timerfd");

    let fd = unsafe {
        libc::syscall(libc::SYS_timerfd_create, libc::CLOCK_MONOTONIC, TFD_NONBLOCK) as i32
    };
    if fd < 0 {
        check!(h, false, "timerfd_create: errno {}", sys::errno());
        return;
    }

    // Not armed: nothing to read, nothing to poll.
    let mut v = [0u8; 8];
    check_fails!(
        h,
        unsafe { libc::read(fd, v.as_mut_ptr().cast(), 8) },
        libc::EAGAIN,
        "an unarmed timer has no expirations"
    );
    check!(h, !readable(fd, 0), "and is not readable");

    // A one-shot 60ms timer.
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec { tv_sec: 0, tv_nsec: 60_000_000 },
    };
    let r = unsafe {
        libc::syscall(libc::SYS_timerfd_settime, fd, 0, &spec, std::ptr::null_mut::<libc::itimerspec>())
    };
    check!(h, r == 0, "arming a one-shot timer: {r} errno {}", sys::errno());

    // gettime reports what is left, and it is less than what was set.
    let mut cur: libc::itimerspec = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::syscall(libc::SYS_timerfd_gettime, fd, &mut cur) };
    check!(
        h,
        r == 0 && cur.it_value.tv_nsec > 0 && cur.it_value.tv_nsec <= 60_000_000,
        "gettime reports time remaining: r={r} value={}ns",
        cur.it_value.tv_nsec
    );

    let started = std::time::Instant::now();
    check!(h, readable(fd, 2000), "it becomes readable");
    let waited = started.elapsed();
    check!(
        h,
        waited >= std::time::Duration::from_millis(30),
        "not before it was due: {waited:?}"
    );
    check!(
        h,
        efd_read(fd) == Some(1),
        "and reports one expiration"
    );
    check_fails!(
        h,
        unsafe { libc::read(fd, v.as_mut_ptr().cast(), 8) },
        libc::EAGAIN,
        "which is consumed by the read"
    );

    // A periodic timer accumulates expirations.
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 20_000_000 },
        it_value: libc::timespec { tv_sec: 0, tv_nsec: 20_000_000 },
    };
    let r = unsafe {
        libc::syscall(libc::SYS_timerfd_settime, fd, 0, &spec, std::ptr::null_mut::<libc::itimerspec>())
    };
    check!(h, r == 0, "arming a periodic timer");
    std::thread::sleep(std::time::Duration::from_millis(130));
    match efd_read(fd) {
        Some(n) => check!(
            h,
            n >= 2,
            "a periodic timer accumulates expirations, got {n} after 130ms of a 20ms period"
        ),
        None => check!(h, false, "reading a periodic timer: errno {}", sys::errno()),
    }

    // Disarming stops it.
    let off: libc::itimerspec = unsafe { std::mem::zeroed() };
    unsafe {
        libc::syscall(libc::SYS_timerfd_settime, fd, 0, &off, std::ptr::null_mut::<libc::itimerspec>())
    };
    // Drain whatever had already fired, then confirm nothing more arrives.
    let _ = efd_read(fd);
    std::thread::sleep(std::time::Duration::from_millis(80));
    check_fails!(
        h,
        unsafe { libc::read(fd, v.as_mut_ptr().cast(), 8) },
        libc::EAGAIN,
        "a disarmed timer stops firing"
    );
    sys::close(fd);

    let c = unsafe {
        libc::syscall(libc::SYS_timerfd_create, libc::CLOCK_MONOTONIC, TFD_CLOEXEC) as i32
    };
    check!(
        h,
        c >= 0 && unsafe { libc::fcntl(c, libc::F_GETFD) } & libc::FD_CLOEXEC != 0,
        "TFD_CLOEXEC sets FD_CLOEXEC"
    );
    sys::close(c);

    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_timerfd_create, 99, 0) },
        libc::EINVAL,
        "an unknown clock"
    );
}

fn main() {
    let mut h = Harness::new();
    t_pipe_flags(&mut h);
    t_pipe_ends(&mut h);
    t_eventfd(&mut h);
    t_timerfd(&mut h);
    std::process::exit(h.finish());
}
