//! What `epoll` answers, case by case.
//!
//! # Why this exists
//!
//! `epoll` is the largest state machine in the descriptor layer and nothing
//! compares it against a real kernel. `crates/kernel/epollcalls` owns the three
//! syscalls and `crates/kernel/epoll` the registrations, the generational
//! tokens and the ready queue; between them they decide edge against level
//! triggering, whether a one-shot rearms, what a closed peer reports, and which
//! of half a dozen errnos a bad `epoll_ctl` gets.
//!
//! Every one of those is a value a program branches on. A wrong errno makes a
//! library retry something it should give up on; a missing `EPOLLHUP` makes an
//! event loop spin; a one-shot that rearms itself delivers an event twice to
//! code written on the promise that it will not.
//!
//! # What is checked
//!
//! Nothing is asserted. Each case prints one line and the finding is the
//! difference against an arm64 Linux container, through
//! `tests/integration/probe_diff.sh`.
//!
//! # Every wait has a timeout
//!
//! A probe that blocks reports nothing at all, and the two sides would differ
//! by one of them hanging. Every `epoll_wait` here has a bounded timeout, and
//! the cases that expect nothing use a short one on purpose.

use std::ffi::c_int;

const EPOLLIN: u32 = 0x001;
const EPOLLPRI: u32 = 0x002;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLEXCLUSIVE: u32 = 1 << 28;
const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;

const EPOLL_CTL_ADD: c_int = 1;
const EPOLL_CTL_DEL: c_int = 2;
const EPOLL_CTL_MOD: c_int = 3;

const EPOLL_CLOEXEC: c_int = 0o2000000;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct Event {
    events: u32,
    data: u64,
}

fn errname(e: i32) -> String {
    let n = match e {
        1 => "EPERM", 2 => "ENOENT", 9 => "EBADF", 11 => "EAGAIN", 12 => "ENOMEM",
        13 => "EACCES", 14 => "EFAULT", 17 => "EEXIST", 22 => "EINVAL",
        24 => "EMFILE", 40 => "ELOOP", 4 => "EINTR", 25 => "ENOTTY",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 { format!("-{}", errname(-v as i32)) } else { v.to_string() }
}

/// The event bits, printed by name so a difference says which one moved.
fn bits(e: u32) -> String {
    let mut out = Vec::new();
    for (bit, name) in [
        (EPOLLIN, "IN"),
        (EPOLLPRI, "PRI"),
        (EPOLLOUT, "OUT"),
        (EPOLLERR, "ERR"),
        (EPOLLHUP, "HUP"),
        (EPOLLRDHUP, "RDHUP"),
    ] {
        if e & bit != 0 {
            out.push(name);
        }
    }
    let rest = e & !(EPOLLIN | EPOLLPRI | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP);
    if rest != 0 {
        return format!("{}+{rest:#x}", out.join("|"));
    }
    if out.is_empty() { "none".into() } else { out.join("|") }
}

unsafe fn sys(n: i64, a: i64, b: i64, c: i64, d: i64, e: i64) -> i64 {
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
            options(nostack)
        );
    }
    ret
}

const NR_EPOLL_CREATE1: i64 = 20;
const NR_EPOLL_CTL: i64 = 21;
const NR_EPOLL_PWAIT: i64 = 22;

fn create(flags: c_int) -> i64 {
    unsafe { sys(NR_EPOLL_CREATE1, flags as i64, 0, 0, 0, 0) }
}

fn ctl(ep: i64, op: c_int, fd: i64, events: u32, data: u64) -> i64 {
    let mut ev = Event { events, data };
    unsafe { sys(NR_EPOLL_CTL, ep, op as i64, fd, &raw mut ev as i64, 0) }
}

fn ctl_null(ep: i64, op: c_int, fd: i64) -> i64 {
    unsafe { sys(NR_EPOLL_CTL, ep, op as i64, fd, 0, 0) }
}

/// `epoll_pwait` with no signal mask, which is what `epoll_wait` is on aarch64.
fn wait(ep: i64, out: &mut [Event], timeout: c_int) -> i64 {
    unsafe {
        sys(
            NR_EPOLL_PWAIT,
            ep,
            out.as_mut_ptr() as i64,
            out.len() as i64,
            timeout as i64,
            0,
        )
    }
}

/// A pipe, as `(read end, write end)`.
fn pipe() -> (i64, i64) {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    (fds[0] as i64, fds[1] as i64)
}

fn close(fd: i64) {
    unsafe { libc::close(fd as i32) };
}

fn main() {
    creation();
    ctl_errnos();
    level_triggered();
    edge_triggered();
    oneshot();
    hangup();
    wait_arguments();
    nesting();
    closing();
    waking();
}

/// **Does a wait already in progress wake when the descriptor becomes ready?**
///
/// Every case above makes the descriptor ready *first* and then asks. That is a
/// different question, and it is the one an event loop asks: an epoll set is
/// woken by a description telling its watchers, so a kind of descriptor whose
/// readiness path forgets to tell them answers correctly to every test that
/// looks after the fact and never wakes a program that is waiting.
///
/// `signalfd` was exactly that, and it cost a day: 46 probe cases agreed with
/// Linux and PostgreSQL 18 still hung, because `SetLatch` is
/// `kill(pid, SIGURG)` read through a signalfd in an epoll set. This asks the
/// question of every kind of descriptor there is, so the next one cannot hide.
///
/// Each case registers, arranges for readiness 200 ms later from another
/// process, and waits two seconds. The number is not the measurement -- what is
/// reported is which of the two happened.
fn waking() {
    println!("## a wait already in progress");

    // A pipe: a child writes.
    let (rd, wr) = pipe();
    println!("  pipe, written by a child -> {}", woken(rd, move || {
        unsafe { libc::write(wr as c_int, b"x".as_ptr().cast(), 1) };
    }));
    close(rd);
    close(wr);

    // An eventfd, likewise.
    let efd = unsafe { libc::eventfd(0, 0) } as i64;
    println!("  eventfd, written by a child -> {}", woken(efd, move || {
        let one: u64 = 1;
        unsafe { libc::write(efd as c_int, (&raw const one).cast(), 8) };
    }));
    close(efd);

    // A signalfd: the child signals the *parent*, so what makes it readable is
    // a signal arriving at the waiting process rather than a write.
    let sfd = {
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGURG);
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            libc::signalfd(-1, &set, 0) as i64
        }
    };
    let me = unsafe { libc::getpid() };
    println!("  signalfd, signalled by a child -> {}", woken(sfd, move || {
        unsafe { libc::kill(me, libc::SIGURG) };
    }));
    close(sfd);

    // A timerfd, which nobody writes: the expiry is the emulator's own timer
    // thread, so this is the one case where the wakeup comes from neither the
    // waiting process nor another guest process.
    let tfd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) } as i64;
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec { tv_sec: 0, tv_nsec: 200_000_000 },
    };
    unsafe { libc::timerfd_settime(tfd as c_int, 0, &spec, std::ptr::null_mut()) };
    println!("  timerfd, on expiry -> {}", woken(tfd, || {}));
    close(tfd);

    // A unix socket pair: a child sends.
    let mut sv = [0i32; 2];
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    let (a, b) = (sv[0] as i64, sv[1] as i64);
    println!("  unix socket, written by a child -> {}", woken(a, move || {
        unsafe { libc::send(b as c_int, b"x".as_ptr().cast(), 1, 0) };
    }));
    close(a);
    close(b);

    // A pidfd: the process it names exits.
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::usleep(200_000);
            libc::_exit(0);
        }
    }
    let pfd = unsafe { libc::syscall(434, child, 0) };
    println!("  pidfd, on the process exiting -> {}", woken(pfd, || {}));
    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, 0) };
    close(pfd);

    // An inotify watch: a child creates a file in the directory.
    let ino = unsafe { libc::inotify_init1(0) } as i64;
    let dir = c"/tmp/epoll_probe_watch";
    unsafe {
        libc::mkdir(dir.as_ptr(), 0o755);
        libc::inotify_add_watch(ino as c_int, dir.as_ptr(), libc::IN_CREATE);
    }
    println!("  inotify, on a file appearing -> {}", woken(ino, || {
        let f = c"/tmp/epoll_probe_watch/new";
        unsafe {
            let fd = libc::open(f.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644);
            libc::close(fd);
        }
    }));
    close(ino);
    unsafe {
        libc::unlink(c"/tmp/epoll_probe_watch/new".as_ptr());
        libc::rmdir(dir.as_ptr());
    }
}

/// Registers `fd` in a fresh epoll set, runs `ready` in a forked child after
/// 200 ms, and waits two seconds. Answers what happened.
///
/// The work is done in a **child** on purpose: readiness arranged by the
/// waiting process itself would be there before the wait began, which is the
/// question the rest of this file already asks.
fn woken(fd: i64, ready: impl FnOnce()) -> String {
    let ep = create(0);
    if ctl(ep, libc::EPOLL_CTL_ADD, fd, EPOLLIN, 0) < 0 {
        close(ep);
        return "could not register".into();
    }
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::usleep(200_000) };
        ready();
        unsafe { libc::_exit(0) };
    }
    let mut out = [Event { events: 0, data: 0 }; 4];
    let n = wait(ep, &mut out, 2000);
    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, 0) };
    close(ep);
    match n {
        0 => "timed out".into(),
        n if n > 0 => format!("woke with {}", bits(out[0].events)),
        e => r(e),
    }
}

/// `epoll_create1`'s one flag.
fn creation() {
    println!("## epoll_create1");
    let ep = create(0);
    println!("  flags 0 -> {}", if ep >= 0 { "a descriptor".to_string() } else { r(ep) });
    close(ep);
    let ep = create(EPOLL_CLOEXEC);
    println!("  EPOLL_CLOEXEC -> {}", if ep >= 0 { "a descriptor".to_string() } else { r(ep) });
    close(ep);
    // Any other bit is EINVAL. `epoll_create1(1)` in particular is what a
    // caller writing `epoll_create1(true)` produces.
    for flag in [1i64, 2, 0o2000001, -1] {
        let e = unsafe { sys(NR_EPOLL_CREATE1, flag, 0, 0, 0, 0) };
        println!("  flags {flag:#x} -> {}", if e >= 0 { close(e); "a descriptor".to_string() } else { r(e) });
    }
}

/// The six errnos `epoll_ctl` can answer, and which argument produces each.
fn ctl_errnos() {
    println!("## epoll_ctl errnos");
    let ep = create(0);
    let (rd, wr) = pipe();

    println!("  ADD a pipe -> {}", r(ctl(ep, EPOLL_CTL_ADD, rd, EPOLLIN, 1)));
    println!("  ADD it twice -> {}", r(ctl(ep, EPOLL_CTL_ADD, rd, EPOLLIN, 1)));
    println!("  MOD it -> {}", r(ctl(ep, EPOLL_CTL_MOD, rd, EPOLLOUT, 2)));
    println!("  MOD one never added -> {}", r(ctl(ep, EPOLL_CTL_MOD, wr, EPOLLIN, 3)));
    println!("  DEL one never added -> {}", r(ctl_null(ep, EPOLL_CTL_DEL, wr)));
    println!("  DEL it -> {}", r(ctl_null(ep, EPOLL_CTL_DEL, rd)));
    println!("  DEL it twice -> {}", r(ctl_null(ep, EPOLL_CTL_DEL, rd)));

    println!("  a closed descriptor -> {}", r(ctl(ep, EPOLL_CTL_ADD, 9999, EPOLLIN, 0)));
    println!("  a closed epoll -> {}", r(ctl(9999, EPOLL_CTL_ADD, rd, EPOLLIN, 0)));
    println!("  an unallocated op -> {}", r(ctl(ep, 99, rd, EPOLLIN, 0)));
    // The epoll itself is not a thing it may watch.
    println!("  ADD the epoll to itself -> {}", r(ctl(ep, EPOLL_CTL_ADD, ep, EPOLLIN, 0)));
    // A regular file has no readiness to report and Linux refuses it.
    let f = unsafe { libc::open(c"/etc/passwd".as_ptr(), libc::O_RDONLY) } as i64;
    println!("  ADD a regular file -> {}", r(ctl(ep, EPOLL_CTL_ADD, f, EPOLLIN, 0)));
    // ...and so does a directory.
    let d = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) } as i64;
    println!("  ADD a directory -> {}", r(ctl(ep, EPOLL_CTL_ADD, d, EPOLLIN, 0)));
    close(f);
    close(d);

    // A null event pointer: needed by ADD and MOD, ignored by DEL since 2.6.9.
    println!("  ADD with a null event -> {}", r(ctl_null(ep, EPOLL_CTL_ADD, rd)));
    let added = ctl(ep, EPOLL_CTL_ADD, rd, EPOLLIN, 7);
    println!("  ADD again for the DEL below -> {}", r(added));
    println!("  MOD with a null event -> {}", r(ctl_null(ep, EPOLL_CTL_MOD, rd)));
    println!("  DEL with a null event -> {}", r(ctl_null(ep, EPOLL_CTL_DEL, rd)));

    // EPOLLEXCLUSIVE may not be combined with MOD, and may not be set on an
    // epoll being watched.
    println!(
        "  ADD with EPOLLEXCLUSIVE -> {}",
        r(ctl(ep, EPOLL_CTL_ADD, rd, EPOLLIN | EPOLLEXCLUSIVE, 8))
    );
    println!(
        "  MOD to EPOLLEXCLUSIVE -> {}",
        r(ctl(ep, EPOLL_CTL_MOD, rd, EPOLLIN | EPOLLEXCLUSIVE, 9))
    );
    // The rest of EPOLLEXCLUSIVE's rules, which are about what it may be
    // combined with. Measured rather than read: the set Linux allows is
    // `EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP|EPOLLWAKEUP|EPOLLET|EPOLLEXCLUSIVE`,
    // and the interesting part is which of the others it refuses.
    let (rd2, wr2) = pipe();
    for (extra, name) in [
        (EPOLLONESHOT, "EPOLLONESHOT"),
        (EPOLLET, "EPOLLET"),
        (EPOLLPRI, "EPOLLPRI"),
        (EPOLLRDHUP, "EPOLLRDHUP"),
        (EPOLLHUP, "EPOLLHUP"),
    ] {
        let e = ctl(ep, EPOLL_CTL_ADD, rd2, EPOLLIN | EPOLLEXCLUSIVE | extra, 10);
        println!("  ADD EPOLLEXCLUSIVE|{name} -> {}", r(e));
        if e == 0 {
            ctl_null(ep, EPOLL_CTL_DEL, rd2);
        }
    }
    let inner = create(0);
    println!(
        "  ADD an epoll with EPOLLEXCLUSIVE -> {}",
        r(ctl(ep, EPOLL_CTL_ADD, inner, EPOLLIN | EPOLLEXCLUSIVE, 11))
    );
    close(inner);
    close(rd2);
    close(wr2);

    close(rd);
    close(wr);
    close(ep);
}

/// Level triggering: readiness is reported for as long as it lasts.
fn level_triggered() {
    println!("## level triggering");
    let ep = create(0);
    let (rd, wr) = pipe();
    ctl(ep, EPOLL_CTL_ADD, rd, EPOLLIN, 0x11);

    let mut out = [Event::default(); 4];
    println!("  empty pipe, 0 ms -> {}", r(wait(ep, &mut out, 0)));

    unsafe { libc::write(wr as i32, c"abcd".as_ptr().cast(), 4) };
    let n = wait(ep, &mut out, 100);
    let (ev, data) = (out[0].events, out[0].data);
    println!("  after a write -> {} events, {} data {data:#x}", r(n), bits(ev));

    // Still ready, because nothing was read: that is what level means.
    let n = wait(ep, &mut out, 0);
    println!("  again without reading -> {} events, {}", r(n), bits(out[0].events));

    let mut buf = [0u8; 2];
    unsafe { libc::read(rd as i32, buf.as_mut_ptr().cast(), 2) };
    let n = wait(ep, &mut out, 0);
    println!("  after a partial read -> {} events, {}", r(n), bits(out[0].events));

    unsafe { libc::read(rd as i32, buf.as_mut_ptr().cast(), 2) };
    println!("  after draining -> {}", r(wait(ep, &mut out, 0)));

    // The write end, which is writable until the pipe fills.
    ctl(ep, EPOLL_CTL_ADD, wr, EPOLLOUT, 0x22);
    let n = wait(ep, &mut out, 0);
    println!("  the write end -> {} events, {}", r(n), bits(out[0].events));

    close(rd);
    close(wr);
    close(ep);
}

/// Edge triggering: readiness is reported when it *changes*.
fn edge_triggered() {
    println!("## edge triggering");
    let ep = create(0);
    let (rd, wr) = pipe();
    ctl(ep, EPOLL_CTL_ADD, rd, EPOLLIN | EPOLLET, 0x33);

    let mut out = [Event::default(); 4];
    unsafe { libc::write(wr as i32, c"abcd".as_ptr().cast(), 4) };
    println!("  after a write -> {}", r(wait(ep, &mut out, 100)));
    // The whole point: no second report without a new write.
    println!("  again without reading -> {}", r(wait(ep, &mut out, 0)));

    let mut buf = [0u8; 2];
    unsafe { libc::read(rd as i32, buf.as_mut_ptr().cast(), 2) };
    println!("  after a partial read -> {}", r(wait(ep, &mut out, 0)));

    unsafe { libc::write(wr as i32, c"ef".as_ptr().cast(), 2) };
    println!("  after a second write -> {}", r(wait(ep, &mut out, 100)));

    // A MOD rearms an edge-triggered registration even with nothing new,
    // because it re-reports current readiness.
    ctl(ep, EPOLL_CTL_MOD, rd, EPOLLIN | EPOLLET, 0x34);
    println!("  after a MOD with data still buffered -> {}", r(wait(ep, &mut out, 100)));

    close(rd);
    close(wr);
    close(ep);
}

/// `EPOLLONESHOT`: one report, then the registration is disarmed until a MOD.
fn oneshot() {
    println!("## EPOLLONESHOT");
    let ep = create(0);
    let (rd, wr) = pipe();
    ctl(ep, EPOLL_CTL_ADD, rd, EPOLLIN | EPOLLONESHOT, 0x44);

    let mut out = [Event::default(); 4];
    unsafe { libc::write(wr as i32, c"ab".as_ptr().cast(), 2) };
    let n = wait(ep, &mut out, 100);
    println!("  first wait -> {} events, {}", r(n), bits(out[0].events));
    // Disarmed, even though the data is still there.
    println!("  second wait -> {}", r(wait(ep, &mut out, 0)));
    // A MOD rearms it.
    println!("  MOD to rearm -> {}", r(ctl(ep, EPOLL_CTL_MOD, rd, EPOLLIN | EPOLLONESHOT, 0x45)));
    let n = wait(ep, &mut out, 100);
    let data = out[0].data;
    println!("  after rearming -> {} events, data {data:#x}", r(n));

    close(rd);
    close(wr);
    close(ep);
}

/// What a closed peer reports. An event loop that does not see these spins.
fn hangup() {
    println!("## hangup");
    // The reader watches, the writer goes away.
    let ep = create(0);
    let (rd, wr) = pipe();
    ctl(ep, EPOLL_CTL_ADD, rd, EPOLLIN, 0x55);
    close(wr);
    let mut out = [Event::default(); 4];
    let n = wait(ep, &mut out, 100);
    println!("  the write end closed -> {} events, {}", r(n), bits(out[0].events));
    close(rd);
    close(ep);

    // The writer watches, the reader goes away. `EPOLLERR` is reported whether
    // or not it was asked for, which is the rule a caller most often misses.
    let ep = create(0);
    let (rd, wr) = pipe();
    ctl(ep, EPOLL_CTL_ADD, wr, EPOLLOUT, 0x66);
    close(rd);
    let n = wait(ep, &mut out, 100);
    println!("  the read end closed -> {} events, {}", r(n), bits(out[0].events));
    close(wr);
    close(ep);

    // Asking for nothing at all still reports ERR and HUP.
    let ep = create(0);
    let (rd, wr) = pipe();
    ctl(ep, EPOLL_CTL_ADD, wr, 0, 0x77);
    close(rd);
    let n = wait(ep, &mut out, 100);
    println!("  watching for no events at all -> {} events, {}", r(n), bits(out[0].events));
    close(wr);
    close(ep);
}

/// `epoll_wait`'s own arguments.
fn wait_arguments() {
    println!("## epoll_pwait arguments");
    let ep = create(0);
    let mut out = [Event::default(); 4];
    println!("  maxevents 0 -> {}", r(wait(ep, &mut out[..0], 0)));
    println!("  maxevents negative -> {}", r(unsafe {
        sys(NR_EPOLL_PWAIT, ep, out.as_mut_ptr() as i64, -1, 0, 0)
    }));
    // Where the cap actually is. Linux refuses anything above
    // `INT_MAX / sizeof(struct epoll_event)`, and the size of that struct is
    // **architecture-dependent**: 12 bytes on x86-64, where it is packed, and
    // 16 everywhere else. Measured rather than written down, which is why there
    // are four cases around the boundary rather than one.
    //
    // Printed as *whether it is EINVAL* rather than as the errno, because a
    // value at the cap makes the span `maxevents * 16` about two gigabytes and
    // whether that leaves the address space depends on where the stack happens
    // to be -- which differs between a container and this emulator and is not
    // a rule either of them has. The question here is only where the cap is.
    for n in [134_217_727i64, 134_217_728, 178_956_970, 1 << 30, i32::MAX as i64] {
        let e = unsafe { sys(NR_EPOLL_PWAIT, ep, out.as_mut_ptr() as i64, n, 0, 0) };
        println!("  maxevents {n} is EINVAL: {}", e == -22);
    }
    // The span check itself, with an address that is out of range whatever the
    // stack is doing.
    println!("  an event array past the address space -> {}", r(unsafe {
        sys(NR_EPOLL_PWAIT, ep, 0x7fff_ffff_ffff_ff00u64 as i64, 4, 0, 0)
    }));
    println!("  a null event array -> {}", r(unsafe {
        sys(NR_EPOLL_PWAIT, ep, 0, 4, 0, 0)
    }));
    println!("  a descriptor that is not an epoll -> {}", r(unsafe {
        sys(NR_EPOLL_PWAIT, 1, out.as_mut_ptr() as i64, 4, 0, 0)
    }));
    println!("  a closed descriptor -> {}", r(unsafe {
        sys(NR_EPOLL_PWAIT, 9999, out.as_mut_ptr() as i64, 4, 0, 0)
    }));
    // There is deliberately no case for a timeout below -1. Linux's
    // `ep_timeout_to_timespec` treats *any* negative value as "wait for ever",
    // so `-2` blocks — which is a probe that reports nothing and a diff that
    // says one side died early. The first version of this file had it and hung
    // both sides.
    close(ep);
}

/// An epoll watching another epoll, which is allowed and bounded.
fn nesting() {
    println!("## nesting");
    let outer = create(0);
    let inner = create(0);
    let (rd, wr) = pipe();

    println!("  ADD an epoll to an epoll -> {}", r(ctl(outer, EPOLL_CTL_ADD, inner, EPOLLIN, 0x88)));
    println!("  ADD a pipe to the inner one -> {}", r(ctl(inner, EPOLL_CTL_ADD, rd, EPOLLIN, 0x99)));

    let mut out = [Event::default(); 4];
    println!("  nothing ready -> {}", r(wait(outer, &mut out, 0)));
    unsafe { libc::write(wr as i32, c"x".as_ptr().cast(), 1) };
    let n = wait(outer, &mut out, 100);
    println!("  the inner one has an event -> {} events, {}", r(n), bits(out[0].events));

    // A cycle is refused, whichever way round it is closed.
    println!("  closing the cycle -> {}", r(ctl(inner, EPOLL_CTL_ADD, outer, EPOLLIN, 0)));

    close(rd);
    close(wr);
    close(inner);
    close(outer);
}

/// What happens to a registration when the watched descriptor is closed.
///
/// Linux removes it when the last reference to the *description* goes, not the
/// descriptor — so a `dup` keeps it alive, which is the behaviour that surprises
/// people and the one an event loop leaks on.
fn closing() {
    println!("## closing a watched descriptor");
    let ep = create(0);
    let (rd, wr) = pipe();
    ctl(ep, EPOLL_CTL_ADD, rd, EPOLLIN, 0xaa);
    unsafe { libc::write(wr as i32, c"x".as_ptr().cast(), 1) };

    let dup = unsafe { libc::dup(rd as i32) } as i64;
    close(rd);
    let mut out = [Event::default(); 4];
    // The description is still open through `dup`, so the registration stands.
    let n = wait(ep, &mut out, 100);
    println!("  after closing one of two descriptors -> {} events, {}", r(n), bits(out[0].events));
    // And a DEL naming the closed number cannot find it.
    println!("  DEL the closed number -> {}", r(ctl_null(ep, EPOLL_CTL_DEL, rd)));
    println!("  DEL the surviving number -> {}", r(ctl_null(ep, EPOLL_CTL_DEL, dup)));

    close(dup);
    close(wr);
    close(ep);
}
