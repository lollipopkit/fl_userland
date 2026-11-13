//! What `select`, `pselect6`, `poll` and `ppoll` answer, case by case.
//!
//! # Why this exists
//!
//! `crates/kernel/pollcalls` is four syscalls over two guest representations of
//! "which descriptors and which events", and both of them are sized from a
//! number the guest chose. That is the shape this tree keeps finding defects
//! in: `select(1000000000, ...)` asked for 125 MB of stack three times over and
//! `ppoll(fds, 100000000, ...)` for 800 MB, and both were fixed by bounding the
//! count with `RLIMIT_NOFILE` — a bound that is *this kernel's choice* and has
//! never been compared against what Linux actually answers.
//!
//! Beyond the counts there is a second surface nothing asks about: what goes in
//! `revents`. A negative descriptor is skipped, a closed one is `POLLNVAL`,
//! `POLLERR` and `POLLHUP` arrive whether or not they were requested, and a
//! zero `events` mask still reports them. An event loop branches on every one.
//!
//! # What is checked
//!
//! Nothing is asserted. Each case prints one line, and the finding is the
//! difference against an arm64 Linux container through
//! `tests/integration/probe_diff.sh`.
//!
//! # Every wait is bounded
//!
//! A case that blocks reports nothing and reads as "one side died early", so
//! every timeout here is finite and the cases that expect nothing use zero.

use std::ffi::c_int;

const POLLIN: i16 = 0x001;
const POLLPRI: i16 = 0x002;
const POLLOUT: i16 = 0x004;
const POLLERR: i16 = 0x008;
const POLLHUP: i16 = 0x010;
const POLLNVAL: i16 = 0x020;
const POLLRDHUP: i16 = 0x2000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Timeval {
    sec: i64,
    usec: i64,
}

/// `pselect6`'s sixth argument: a pointer to a mask and its size.
#[repr(C)]
struct SigsetArg {
    mask: u64,
    size: u64,
}

fn errname(e: i32) -> String {
    let n = match e {
        1 => "EPERM", 4 => "EINTR", 9 => "EBADF", 12 => "ENOMEM", 14 => "EFAULT",
        22 => "EINVAL", 24 => "EMFILE",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 { format!("-{}", errname(-v as i32)) } else { v.to_string() }
}

fn revents(v: i16) -> String {
    let mut out = Vec::new();
    for (bit, name) in [
        (POLLIN, "IN"),
        (POLLPRI, "PRI"),
        (POLLOUT, "OUT"),
        (POLLERR, "ERR"),
        (POLLHUP, "HUP"),
        (POLLNVAL, "NVAL"),
        (POLLRDHUP, "RDHUP"),
    ] {
        if v & bit != 0 {
            out.push(name);
        }
    }
    let known = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDHUP;
    if v & !known != 0 {
        return format!("{}+{:#x}", out.join("|"), v & !known);
    }
    if out.is_empty() { "none".into() } else { out.join("|") }
}

unsafe fn sys(n: i64, a: i64, b: i64, c: i64, d: i64, e: i64, f: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            in("x4") e,
            in("x5") f,
            options(nostack)
        );
    }
    ret
}

const NR_PPOLL: i64 = 73;
const NR_PSELECT6: i64 = 72;

fn ppoll(fds: &mut [PollFd], timeout: Option<&Timespec>) -> i64 {
    unsafe {
        sys(
            NR_PPOLL,
            fds.as_mut_ptr() as i64,
            fds.len() as i64,
            timeout.map_or(0, |t| t as *const Timespec as i64),
            0,
            8,
            0,
        )
    }
}

/// `ppoll` with a count the array does not have, which is the whole point of
/// several cases below.
fn ppoll_raw(addr: i64, n: i64, timeout: Option<&Timespec>) -> i64 {
    unsafe {
        sys(NR_PPOLL, addr, n, timeout.map_or(0, |t| t as *const Timespec as i64), 0, 8, 0)
    }
}

fn pselect(nfds: i64, r: i64, w: i64, e: i64, t: Option<&Timespec>, sig: i64) -> i64 {
    unsafe {
        sys(NR_PSELECT6, nfds, r, w, e, t.map_or(0, |t| t as *const Timespec as i64), sig)
    }
}

fn pipe() -> (c_int, c_int) {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    (fds[0], fds[1])
}

fn main() {
    poll_counts();
    poll_revents();
    poll_timeouts();
    select_counts();
    select_sets();
    select_timeouts();
    waking();
}

/// **Does a `poll` already in progress wake when the descriptor becomes
/// ready?**
///
/// Every case above makes the descriptor ready first and then asks, which is a
/// different question: a wait already parked is woken by a *readiness
/// transition*, and a kind of descriptor whose transition path forgets to
/// announce itself answers the first question correctly and never wakes a
/// program that is waiting.
///
/// `epoll_probe` asks the same of `epoll_wait` and found nothing; the two
/// primitives wake through different machinery here — a `poll` set is a
/// transient waiter on each description and an epoll is a durable watcher — so
/// one answering does not answer for the other. `signalfd` was the kind that
/// failed, and it failed only for epoll.
///
/// Each case registers, has a child make it ready 200 ms later, and waits two
/// seconds. The number is not the measurement: what is reported is which of
/// the two happened.
fn waking() {
    println!("## a poll already in progress");

    let (rd, wr) = pipe();
    println!("  pipe, written by a child -> {}", woken(rd, move || {
        unsafe { libc::write(wr, b"x".as_ptr().cast(), 1) };
    }));
    unsafe {
        libc::close(rd);
        libc::close(wr);
    }

    let efd = unsafe { libc::eventfd(0, 0) };
    println!("  eventfd, written by a child -> {}", woken(efd, move || {
        let one: u64 = 1;
        unsafe { libc::write(efd, (&raw const one).cast(), 8) };
    }));
    unsafe { libc::close(efd) };

    let sfd = {
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGURG);
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            libc::signalfd(-1, &set, 0)
        }
    };
    let me = unsafe { libc::getpid() };
    println!("  signalfd, signalled by a child -> {}", woken(sfd, move || {
        unsafe { libc::kill(me, libc::SIGURG) };
    }));
    unsafe { libc::close(sfd) };

    let tfd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec { tv_sec: 0, tv_nsec: 200_000_000 },
    };
    unsafe { libc::timerfd_settime(tfd, 0, &spec, std::ptr::null_mut()) };
    println!("  timerfd, on expiry -> {}", woken(tfd, || {}));
    unsafe { libc::close(tfd) };

    let mut sv = [0i32; 2];
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    let (a, b) = (sv[0], sv[1]);
    println!("  unix socket, written by a child -> {}", woken(a, move || {
        unsafe { libc::send(b, b"x".as_ptr().cast(), 1, 0) };
    }));
    unsafe {
        libc::close(a);
        libc::close(b);
    }

    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::usleep(200_000);
            libc::_exit(0);
        }
    }
    let pfd = unsafe { libc::syscall(434, child, 0) } as c_int;
    println!("  pidfd, on the process exiting -> {}", woken(pfd, || {}));
    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, 0) };
    unsafe { libc::close(pfd) };

    let ino = unsafe { libc::inotify_init1(0) };
    let dir = c"/tmp/poll_probe_watch";
    unsafe {
        libc::mkdir(dir.as_ptr(), 0o755);
        libc::inotify_add_watch(ino, dir.as_ptr(), libc::IN_CREATE);
    }
    println!("  inotify, on a file appearing -> {}", woken(ino, || {
        unsafe {
            let fd = libc::open(c"/tmp/poll_probe_watch/new".as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644);
            libc::close(fd);
        }
    }));
    unsafe {
        libc::close(ino);
        libc::unlink(c"/tmp/poll_probe_watch/new".as_ptr());
        libc::rmdir(dir.as_ptr());
    }
}

/// Polls `fd` for two seconds with a child making it ready after 200 ms.
fn woken(fd: c_int, ready: impl FnOnce()) -> String {
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::usleep(200_000) };
        ready();
        unsafe { libc::_exit(0) };
    }
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let n = unsafe { libc::poll(&mut p, 1, 2000) };
    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, 0) };
    match n {
        0 => "timed out".into(),
        n if n > 0 => format!("woke with revents {:#x}", p.revents),
        _ => r(-1),
    }
}

/// How many descriptors `ppoll` will take, and what it does with a count the
/// caller could not possibly have an array for.
fn poll_counts() {
    println!("## ppoll counts");
    let zero = Timespec::default();

    // Zero descriptors is a sleep, and a null array with a zero count is legal.
    println!("  nfds 0, null array -> {}", r(ppoll_raw(0, 0, Some(&zero))));

    // A count past `RLIMIT_NOFILE`. Linux's bound is `RLIMIT_NOFILE`, and above
    // it the answer is EINVAL; this kernel bounds it too, and whether the two
    // agree is what has never been asked.
    let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    // The limit's *value* is the environment's -- a container and this
    // emulator start with different ones -- so the cases are named by their
    // relationship to it rather than by the number, which is the rule.
    for (n, what) in [
        (lim.rlim_cur as i64, "at RLIMIT_NOFILE"),
        (lim.rlim_cur as i64 + 1, "one past RLIMIT_NOFILE"),
        (1 << 20, "a megabyte of entries"),
        (100_000_000, "a hundred million"),
    ] {
        println!("  nfds {what}, null array -> {}", r(ppoll_raw(0, n, Some(&zero))));
    }
    // A negative count.
    println!("  nfds -1 -> {}", r(ppoll_raw(0, -1, Some(&zero))));

    // A non-null array that is too short for the count: Linux reads what the
    // count says, so this must be an address that is not mapped rather than a
    // short array, or the probe reads its own stack.
    println!("  a count past the address space -> {}", r(unsafe {
        sys(NR_PPOLL, 0x7fff_ffff_ffff_ff00u64 as i64, 4, &zero as *const _ as i64, 0, 8, 0)
    }));

    // The signal mask argument: a size that is not 8 is EINVAL, and a null mask
    // ignores the size.
    let mut one = [PollFd { fd: -1, events: 0, revents: 0 }];
    for size in [0i64, 4, 8, 16] {
        let mask = 0u64;
        let e = unsafe {
            sys(
                NR_PPOLL,
                one.as_mut_ptr() as i64,
                1,
                &zero as *const _ as i64,
                &mask as *const u64 as i64,
                size,
                0,
            )
        };
        println!("  a sigmask of {size} bytes -> {}", r(e));
    }
    println!("  a null sigmask with a size of 99 -> {}", r(unsafe {
        sys(NR_PPOLL, one.as_mut_ptr() as i64, 1, &zero as *const _ as i64, 0, 99, 0)
    }));
}

/// What comes back in `revents`, which is what an event loop branches on.
fn poll_revents() {
    println!("## ppoll revents");
    let zero = Timespec::default();
    let (rd, wr) = pipe();

    // A negative descriptor is skipped entirely -- not an error, and its
    // `revents` is cleared. That is how a caller disables one entry of a set it
    // keeps between calls.
    let mut fds = [
        PollFd { fd: -1, events: POLLIN, revents: 0x7fff },
        PollFd { fd: rd, events: POLLIN, revents: 0x7fff },
    ];
    let n = ppoll(&mut fds, Some(&zero));
    println!("  a negative fd -> {} ready, revents {}", r(n), revents(fds[0].revents));

    // A closed descriptor is POLLNVAL, and counts as ready.
    let mut fds = [PollFd { fd: 9999, events: POLLIN, revents: 0 }];
    let n = ppoll(&mut fds, Some(&zero));
    println!("  a closed fd -> {} ready, revents {}", r(n), revents(fds[0].revents));

    // A zero events mask still reports errors.
    let mut fds = [PollFd { fd: 9999, events: 0, revents: 0 }];
    let n = ppoll(&mut fds, Some(&zero));
    println!("  a closed fd with events 0 -> {} ready, revents {}", r(n), revents(fds[0].revents));

    // An events mask with bits that are output-only. Linux ignores POLLERR,
    // POLLHUP and POLLNVAL in `events` and reports them regardless.
    let mut fds = [PollFd { fd: rd, events: POLLERR | POLLHUP | POLLNVAL, revents: 0 }];
    let n = ppoll(&mut fds, Some(&zero));
    println!("  output-only bits in events -> {} ready, revents {}", r(n), revents(fds[0].revents));

    // A readable pipe, and the same after the writer goes away.
    unsafe { libc::write(wr, c"x".as_ptr().cast(), 1) };
    let mut fds = [PollFd { fd: rd, events: POLLIN, revents: 0 }];
    let n = ppoll(&mut fds, Some(&zero));
    println!("  a readable pipe -> {} ready, revents {}", r(n), revents(fds[0].revents));

    let mut fds = [PollFd { fd: wr, events: POLLOUT, revents: 0 }];
    let n = ppoll(&mut fds, Some(&zero));
    println!("  a writable pipe -> {} ready, revents {}", r(n), revents(fds[0].revents));

    unsafe { libc::close(wr) };
    let mut fds = [PollFd { fd: rd, events: POLLIN, revents: 0 }];
    let n = ppoll(&mut fds, Some(&zero));
    println!("  the writer closed -> {} ready, revents {}", r(n), revents(fds[0].revents));
    let mut buf = [0u8; 8];
    unsafe { libc::read(rd, buf.as_mut_ptr().cast(), 8) };
    let mut fds = [PollFd { fd: rd, events: POLLIN, revents: 0 }];
    let n = ppoll(&mut fds, Some(&zero));
    println!("  ...and drained -> {} ready, revents {}", r(n), revents(fds[0].revents));
    unsafe { libc::close(rd) };

    // The other direction: the reader goes away.
    let (rd, wr) = pipe();
    unsafe { libc::close(rd) };
    let mut fds = [PollFd { fd: wr, events: POLLOUT, revents: 0 }];
    let n = ppoll(&mut fds, Some(&zero));
    println!("  the reader closed -> {} ready, revents {}", r(n), revents(fds[0].revents));
    unsafe { libc::close(wr) };

    // The same descriptor twice: both entries are filled in.
    let (rd, wr) = pipe();
    unsafe { libc::write(wr, c"y".as_ptr().cast(), 1) };
    let mut fds = [
        PollFd { fd: rd, events: POLLIN, revents: 0 },
        PollFd { fd: rd, events: POLLIN, revents: 0 },
    ];
    let n = ppoll(&mut fds, Some(&zero));
    println!(
        "  one fd listed twice -> {} ready, {} and {}",
        r(n),
        revents(fds[0].revents),
        revents(fds[1].revents)
    );
    unsafe {
        libc::close(rd);
        libc::close(wr);
    }
}

/// `ppoll`'s timeout, which is a `timespec` and has a validity rule.
fn poll_timeouts() {
    println!("## ppoll timeouts");
    // A descriptor that is **already ready**, so a timeout the kernel accepts
    // returns 1 at once and one it refuses returns EINVAL. Waiting on nothing
    // would make a large timeout block, and a probe that blocks reports
    // nothing at all -- which is what the first version of this did with
    // `tv_sec = LLONG_MAX`, a value Linux accepts and saturates.
    let (rd, wr) = pipe();
    unsafe { libc::write(wr, c"t".as_ptr().cast(), 1) };
    let mut fds = [PollFd { fd: rd, events: POLLIN, revents: 0 }];
    for (sec, nsec, what) in [
        (0i64, 0i64, "zero"),
        (0, 1_000_000, "one millisecond"),
        (0, 1_000_000_000, "a nsec of exactly one second"),
        (0, 1_000_000_001, "a nsec above one second"),
        (0, -1, "a negative nsec"),
        (-1, 0, "a negative sec"),
        (i64::MAX, 0, "a sec of LLONG_MAX"),
        (i64::MAX, 999_999_999, "a sum that saturates"),
    ] {
        let t = Timespec { sec, nsec };
        println!("  {what} -> {}", r(ppoll(&mut fds, Some(&t))));
    }
    unsafe {
        libc::close(rd);
        libc::close(wr);
    }
    let mut fds = [PollFd { fd: -1, events: 0, revents: 0 }];
    println!("  a timeout past the address space -> {}", r(unsafe {
        sys(NR_PPOLL, fds.as_mut_ptr() as i64, 1, 0x7fff_ffff_ffff_ff00u64 as i64, 0, 8, 0)
    }));
}

/// `pselect6`'s first argument, which is a descriptor *number* and not a count.
fn select_counts() {
    println!("## pselect6 counts");
    let zero = Timespec::default();
    println!("  nfds 0, all sets null -> {}", r(pselect(0, 0, 0, 0, Some(&zero), 0)));
    println!("  nfds -1 -> {}", r(pselect(-1, 0, 0, 0, Some(&zero), 0)));

    let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    for (n, what) in [
        (lim.rlim_cur as i64, "at RLIMIT_NOFILE"),
        (lim.rlim_cur as i64 + 1, "one past RLIMIT_NOFILE"),
        (1 << 20, "a megabyte of bits"),
        (1_000_000_000, "a billion"),
    ] {
        println!("  nfds {what}, null sets -> {}", r(pselect(n, 0, 0, 0, Some(&zero), 0)));
    }

    // A set that is too short for `nfds`: the kernel reads `nfds` bits, so this
    // has to be an unmapped address rather than a short array.
    println!("  a read set past the address space -> {}", r(pselect(
        64,
        0x7fff_ffff_ffff_ff00u64 as i64,
        0,
        0,
        Some(&zero),
        0,
    )));

    // The sixth argument is a `{ mask, size }` pair, and the size must be 8.
    let mask = 0u64;
    for size in [0u64, 4, 8, 16] {
        let arg = SigsetArg { mask: &mask as *const u64 as u64, size };
        println!("  a sigmask of {size} bytes -> {}", r(pselect(
            0, 0, 0, 0, Some(&zero), &arg as *const SigsetArg as i64,
        )));
    }
    let arg = SigsetArg { mask: 0, size: 99 };
    println!("  a null mask with a size of 99 -> {}", r(pselect(
        0, 0, 0, 0, Some(&zero), &arg as *const SigsetArg as i64,
    )));
}

/// Which bits come back in the three sets.
fn select_sets() {
    println!("## pselect6 sets");
    let zero = Timespec::default();
    let (rd, wr) = pipe();
    unsafe { libc::write(wr, c"z".as_ptr().cast(), 1) };

    // The sets are bitmaps of `nfds` bits. Sixteen words is 1024 descriptors,
    // which is more than the limit any of these cases uses.
    let mut rset = [0u64; 16];
    let mut wset = [0u64; 16];
    let set = |s: &mut [u64; 16], fd: c_int| s[fd as usize / 64] |= 1 << (fd as usize % 64);
    let isset = |s: &[u64; 16], fd: c_int| s[fd as usize / 64] & (1 << (fd as usize % 64)) != 0;

    set(&mut rset, rd);
    set(&mut wset, wr);
    let n = pselect(
        (wr.max(rd) + 1) as i64,
        rset.as_mut_ptr() as i64,
        wset.as_mut_ptr() as i64,
        0,
        Some(&zero),
        0,
    );
    println!(
        "  a readable and a writable pipe -> {}, read {} write {}",
        r(n),
        isset(&rset, rd),
        isset(&wset, wr)
    );

    // A descriptor above `nfds` is not looked at, even if its bit is set.
    let mut rset = [0u64; 16];
    set(&mut rset, rd);
    let n = pselect(rd as i64, rset.as_mut_ptr() as i64, 0, 0, Some(&zero), 0);
    println!("  a bit at nfds itself -> {}, still set {}", r(n), isset(&rset, rd));

    // A closed descriptor inside `nfds` is EBADF for the whole call, which is
    // the difference from `poll`: there is no per-entry answer.
    let mut rset = [0u64; 16];
    set(&mut rset, 900);
    let n = pselect(901, rset.as_mut_ptr() as i64, 0, 0, Some(&zero), 0);
    println!("  a closed descriptor in the set -> {}", r(n));

    unsafe {
        libc::close(rd);
        libc::close(wr);
    }
}

/// `pselect6`'s timeout, and whether it is written back.
fn select_timeouts() {
    println!("## pselect6 timeouts");
    // As above: something already readable, so an accepted timeout returns at
    // once rather than blocking.
    let (rd, wr) = pipe();
    unsafe { libc::write(wr, c"t".as_ptr().cast(), 1) };
    for (sec, nsec, what) in [
        (0i64, 0i64, "zero"),
        (0, 1_000_000, "one millisecond"),
        (0, 1_000_000_000, "a nsec of exactly one second"),
        (0, -1, "a negative nsec"),
        (-1, 0, "a negative sec"),
        (i64::MAX, 0, "a sec of LLONG_MAX"),
    ] {
        let mut rset = [0u64; 16];
        rset[rd as usize / 64] |= 1 << (rd as usize % 64);
        let t = Timespec { sec, nsec };
        println!("  {what} -> {}", r(pselect(
            (rd + 1) as i64, rset.as_mut_ptr() as i64, 0, 0, Some(&t), 0,
        )));
    }
    unsafe {
        libc::close(rd);
        libc::close(wr);
    }
    // `pselect6` does not write the remaining time back, unlike `select`. The
    // caller's struct must be untouched.
    let t = Timespec { sec: 0, nsec: 5_000_000 };
    let before = (t.sec, t.nsec);
    pselect(0, 0, 0, 0, Some(&t), 0);
    println!("  the timeout is left alone: {}", before == (t.sec, t.nsec));
    // A null timeout with nothing to wait for would block for ever, so there is
    // deliberately no case for one.
    let _ = Timeval::default();
}
