//! POSIX message queues: what needs a second thread, a second process or a
//! clock to check.
//!
//! The answer table -- every errno and the order of them -- is
//! `mqueue_probe`'s. What is asserted here is behaviour:
//!
//! - **Order.** Highest priority first, arrival order within one.
//! - **Waiting.** A blocked receive is woken by a send, a blocked send by a
//!   receive; an absolute `CLOCK_REALTIME` deadline ends either with
//!   `ETIMEDOUT`; a signal ends it with `EINTR`, or restarts it under
//!   `SA_RESTART`. `poll` and `epoll` are woken the same way.
//! - **Notification.** `SIGEV_SIGNAL` carries `SI_MESGQ`, the *sender's* pid
//!   and the registration's value; it fires once, only on a message reaching
//!   an empty queue nobody is waiting on, and is the owner's alone. Any close
//!   of a descriptor by the owner removes it. `SIGEV_THREAD` through musl
//!   runs the function on a thread, by way of a netlink socket.
//! - **Lifetime.** A queue outlives its descriptors until unlinked, and an
//!   unlinked one lives for whoever still holds it. A fork child and an
//!   unrelated opener see the same queue.
//! - **Stress.** Producers and consumers in threads and in a second process:
//!   nothing lost, nothing duplicated, each producer's messages in order.
//!
//! Runs on a real arm64 kernel too: `differential.sh` compares it live.

use guest_tests::{Harness, check};
use std::ffi::CString;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const NR_MQ_OPEN: i64 = 180;
const NR_MQ_UNLINK: i64 = 181;
const NR_MQ_TIMEDSEND: i64 = 182;
const NR_MQ_TIMEDRECEIVE: i64 = 183;
const NR_MQ_NOTIFY: i64 = 184;
const NR_MQ_GETSETATTR: i64 = 185;

const O_RDONLY: i64 = 0;
const O_WRONLY: i64 = 1;
const O_RDWR: i64 = 2;
const O_CREAT: i64 = 0o100;
const O_EXCL: i64 = 0o200;
const O_NONBLOCK: i64 = 0o4000;

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
const SI_MESGQ: i32 = -3;

const EINTR: i64 = -4;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EEXIST: i64 = -17;
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;
const EBUSY: i64 = -16;
const EMSGSIZE: i64 = -90;
const ETIMEDOUT: i64 = -110;

unsafe fn sys(n: i64, a: i64, b: i64, c: i64, d: i64, e: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b, in("x2") c, in("x3") d, in("x4") e,
            options(nostack)
        );
    }
    ret
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Attr {
    flags: i64,
    maxmsg: i64,
    msgsize: i64,
    curmsgs: i64,
    reserved: [i64; 4],
}

fn attr(maxmsg: i64, msgsize: i64) -> Attr {
    Attr { maxmsg, msgsize, ..Attr::default() }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Sigevent {
    value: u64,
    signo: i32,
    notify: i32,
    function: usize,
    attributes: usize,
    rest: [u8; 32],
}

fn sigev(notify: i32, signo: i32, value: u64) -> Sigevent {
    Sigevent { value, signo, notify, function: 0, attributes: 0, rest: [0; 32] }
}

/// A name of this run's own, so two runs -- or a run and a leftover -- never
/// share a queue.
fn name(tag: &str) -> CString {
    CString::new(format!("mqabi_{}_{tag}", unsafe { libc::getpid() })).unwrap()
}

fn open(n: &CString, oflag: i64, mode: i64, a: Option<&Attr>) -> i64 {
    let ap = a.map_or(0, |a| a as *const Attr as i64);
    unsafe { sys(NR_MQ_OPEN, n.as_ptr() as i64, oflag, mode, ap, 0) }
}

fn unlink(n: &CString) -> i64 {
    unsafe { sys(NR_MQ_UNLINK, n.as_ptr() as i64, 0, 0, 0, 0) }
}

fn send(fd: i64, msg: &[u8], prio: i64, ts: Option<&[i64; 2]>) -> i64 {
    let tp = ts.map_or(0, |t| t.as_ptr() as i64);
    unsafe { sys(NR_MQ_TIMEDSEND, fd, msg.as_ptr() as i64, msg.len() as i64, prio, tp) }
}

fn recv(fd: i64, buf: &mut [u8], prio: &mut u32, ts: Option<&[i64; 2]>) -> i64 {
    let tp = ts.map_or(0, |t| t.as_ptr() as i64);
    unsafe { sys(NR_MQ_TIMEDRECEIVE, fd, buf.as_mut_ptr() as i64, buf.len() as i64, prio as *mut u32 as i64, tp) }
}

fn notify(fd: i64, ev: Option<&Sigevent>) -> i64 {
    let p = ev.map_or(0, |e| e as *const Sigevent as i64);
    unsafe { sys(NR_MQ_NOTIFY, fd, p, 0, 0, 0) }
}

fn curmsgs(fd: i64) -> i64 {
    let mut a = Attr::default();
    let v = unsafe { sys(NR_MQ_GETSETATTR, fd, 0, &mut a as *mut Attr as i64, 0, 0) };
    if v < 0 { v } else { a.curmsgs }
}

fn set_nonblock(fd: i64, on: bool) -> i64 {
    let mut a = Attr::default();
    a.flags = if on { O_NONBLOCK } else { 0 };
    unsafe { sys(NR_MQ_GETSETATTR, fd, &a as *const Attr as i64, 0, 0, 0) }
}

fn close(fd: i64) {
    unsafe { libc::close(fd as i32) };
}

fn now() -> [i64; 2] {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    [ts.tv_sec, ts.tv_nsec]
}

fn in_ms(ms: i64) -> [i64; 2] {
    let mut t = now();
    t[1] += ms * 1_000_000;
    t[0] += t[1] / 1_000_000_000;
    t[1] %= 1_000_000_000;
    t
}

fn gettid() -> i64 {
    unsafe { sys(178, 0, 0, 0, 0, 0) }
}

fn tgkill(pid: i64, tid: i64, sig: i32) {
    unsafe { sys(131, pid, tid, sig as i64, 0, 0) };
}

static HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_signal(_: i32) {
    HITS.fetch_add(1, Ordering::SeqCst);
}

fn handle(sig: i32, flags: i32) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as extern "C" fn(i32) as usize;
        sa.sa_flags = flags;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn block(sig: i32) {
    let mask: u64 = 1 << (sig - 1);
    unsafe { sys(135, 0, &mask as *const u64 as i64, 0, 8, 0) };
}

/// The siginfo of one pending `sig`, waiting at most `ms`: `(code, pid, uid,
/// value)`, or the errno.
fn take_signal(sig: i32, ms: i64) -> Result<(i32, i32, u32, u64), i64> {
    let mask: u64 = 1 << (sig - 1);
    let ts = [ms / 1000, (ms % 1000) * 1_000_000];
    let mut info = [0u8; 128];
    let v = unsafe { sys(137, &mask as *const u64 as i64, info.as_mut_ptr() as i64, ts.as_ptr() as i64, 8, 0) };
    if v < 0 {
        return Err(v);
    }
    let w = |at: usize| i32::from_le_bytes(info[at..at + 4].try_into().unwrap());
    Ok((w(8), w(16), w(20) as u32, u64::from_le_bytes(info[24..32].try_into().unwrap())))
}

fn status(fd: i64) -> String {
    let mut buf = [0u8; 128];
    let n = unsafe { libc::pread(fd as i32, buf.as_mut_ptr().cast(), buf.len(), 0) };
    String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned()
}

fn registered(fd: i64) -> bool {
    !status(fd).contains("NOTIFY_PID:0 ")
}

fn wait_child(pid: i32) -> i32 {
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 128 }
}

/// `CAP_SYS_RESOURCE` in the effective set: a container's root lacks it.
fn has_sys_resource() -> bool {
    let header = [0x2008_0522u32, 0];
    let mut data = [0u32; 6];
    unsafe { libc::syscall(libc::SYS_capget, header.as_ptr(), data.as_mut_ptr()) };
    data[0] & (1 << 24) != 0
}

fn main() {
    let mut h = Harness::new();
    block(libc::SIGUSR2);
    ordering(&mut h);
    limits(&mut h);
    waiting(&mut h);
    signals(&mut h);
    readiness(&mut h);
    notification(&mut h);
    owner_close(&mut h);
    thread_notification(&mut h);
    lifetime(&mut h);
    stress(&mut h);
    std::process::exit(h.finish());
}

fn ordering(h: &mut Harness) {
    h.group("ordering");
    let n = name("order");
    let q = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(10, 8)));
    check!(h, q >= 0, "create: {q}");
    let sent = [(b'a', 1), (b'b', 5), (b'c', 5), (b'd', 3), (b'e', 0), (b'f', 5), (b'g', 0), (b'h', 32767)];
    for (m, p) in sent {
        check!(h, send(q, &[m], p, None) == 0, "send {} at {p}", m as char);
    }
    check!(h, curmsgs(q) == 8, "eight queued: {}", curmsgs(q));
    let mut got = String::new();
    let mut buf = [0u8; 8];
    let mut prio = 0;
    for _ in 0..8 {
        if recv(q, &mut buf, &mut prio, None) == 1 {
            got.push(buf[0] as char);
        }
    }
    check!(h, got == "hbcfdaeg", "priority first, FIFO within one: {got}");
    set_nonblock(q, true);
    check!(h, recv(q, &mut buf, &mut prio, None) == EAGAIN, "then empty");
    close(q);
    unlink(&n);
}

fn limits(h: &mut Harness) {
    h.group("limits");
    let n = name("limits");
    let q = open(&n, O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0o600, Some(&attr(2, 16)));
    check!(h, open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, None) == EEXIST, "O_EXCL on an existing name");
    check!(h, open(&name("missing"), O_RDWR, 0, None) == ENOENT, "a missing name");
    check!(h, send(q, &[0; 17], 0, None) == EMSGSIZE, "a message over msgsize");
    check!(h, send(q, b"x", 32768, None) == EINVAL, "priority MQ_PRIO_MAX");
    let mut buf = [0u8; 16];
    let mut prio = 0;
    check!(h, recv(q, &mut buf[..15], &mut prio, None) == EMSGSIZE, "a buffer under msgsize");
    check!(h, send(q, b"1", 0, None) == 0 && send(q, b"2", 0, None) == 0, "fill");
    check!(h, send(q, b"3", 0, None) == EAGAIN, "full and non-blocking");
    let ro = open(&n, O_RDONLY, 0, None);
    let wo = open(&n, O_WRONLY, 0, None);
    check!(h, send(ro, b"x", 0, None) == EBADF, "send on O_RDONLY");
    check!(h, recv(wo, &mut buf, &mut prio, None) == EBADF, "receive on O_WRONLY");
    check!(h, send(1, b"x", 0, None) == EBADF, "send on stdout");
    close(ro);
    close(wo);
    let bad = [now()[0] + 10, 1_000_000_000];
    check!(h, recv(q, &mut buf, &mut prio, Some(&bad)) == EINVAL, "an invalid deadline, a message queued");
    close(q);
    unlink(&n);

    // Past msg_max: `CAP_SYS_RESOURCE` only, which a container's root lacks.
    let big = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(11, 16)));
    if has_sys_resource() {
        check!(h, big >= 0, "maxmsg 11 with CAP_SYS_RESOURCE: {big}");
    } else {
        check!(h, big == EINVAL, "maxmsg 11 without CAP_SYS_RESOURCE: {big}");
    }
    close(big);
    unlink(&n);
}

fn waiting(h: &mut Harness) {
    h.group("waiting");
    let n = name("wait");
    let q = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(1, 16)));
    let mut buf = [0u8; 16];
    let mut prio = 0;

    let t0 = Instant::now();
    let r = recv(q, &mut buf, &mut prio, Some(&in_ms(80)));
    let waited = t0.elapsed();
    check!(h, r == ETIMEDOUT, "an empty queue times out: {r}");
    check!(h, waited >= Duration::from_millis(70), "after the deadline: {waited:?}");
    check!(h, recv(q, &mut buf, &mut prio, Some(&[1, 0])) == ETIMEDOUT, "a deadline in the past");

    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(40));
        send(q, b"late", 7, None)
    });
    let r = recv(q, &mut buf, &mut prio, Some(&in_ms(5000)));
    check!(h, r == 4 && &buf[..4] == b"late" && prio == 7, "a blocked receive takes a send: {r} prio {prio}");
    check!(h, t.join().unwrap() == 0, "  and the send succeeded");

    send(q, b"full", 0, None);
    let t0 = Instant::now();
    let r = send(q, b"x", 0, Some(&in_ms(80)));
    check!(h, r == ETIMEDOUT && t0.elapsed() >= Duration::from_millis(70), "a full queue times out a send: {r}");
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(40));
        let mut b = [0u8; 16];
        let mut p = 0;
        recv(q, &mut b, &mut p, None)
    });
    let r = send(q, b"next", 2, Some(&in_ms(5000)));
    check!(h, r == 0, "a blocked send goes in when a receive makes room: {r}");
    check!(h, t.join().unwrap() == 4, "  the receive took the old one");
    check!(h, curmsgs(q) == 1, "  and the new one is queued");
    let r = recv(q, &mut buf, &mut prio, None);
    check!(h, r == 4 && &buf[..4] == b"next", "  in full");
    close(q);
    unlink(&n);
}

fn signals(h: &mut Harness) {
    h.group("signals");
    let n = name("signals");
    let q = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(1, 16)));
    let mut buf = [0u8; 16];
    let mut prio = 0;
    let (pid, tid) = (unsafe { libc::getpid() } as i64, gettid());

    handle(libc::SIGUSR1, 0);
    HITS.store(0, Ordering::SeqCst);
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(40));
        tgkill(pid, tid, libc::SIGUSR1);
    });
    let r = recv(q, &mut buf, &mut prio, None);
    t.join().unwrap();
    check!(h, r == EINTR && HITS.load(Ordering::SeqCst) == 1, "a handler interrupts a receive: {r}");

    send(q, b"full", 0, None);
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(40));
        tgkill(pid, tid, libc::SIGUSR1);
    });
    let r = send(q, b"x", 0, Some(&in_ms(5000)));
    t.join().unwrap();
    check!(h, r == EINTR, "and a send: {r}");
    recv(q, &mut buf, &mut prio, None);

    // SA_RESTART: the call carries on, and its deadline is the one it had.
    handle(libc::SIGUSR1, libc::SA_RESTART);
    HITS.store(0, Ordering::SeqCst);
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        tgkill(pid, tid, libc::SIGUSR1);
        std::thread::sleep(Duration::from_millis(60));
        send(q, b"after", 0, None)
    });
    let r = recv(q, &mut buf, &mut prio, Some(&in_ms(5000)));
    t.join().unwrap();
    check!(h, r == 5 && HITS.load(Ordering::SeqCst) == 1, "SA_RESTART: the receive restarts and takes the send: {r}");
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        tgkill(pid, tid, libc::SIGUSR1);
    });
    let t0 = Instant::now();
    let r = recv(q, &mut buf, &mut prio, Some(&in_ms(150)));
    let waited = t0.elapsed();
    t.join().unwrap();
    check!(h, r == ETIMEDOUT, "SA_RESTART with a deadline: ETIMEDOUT: {r}");
    check!(h, waited >= Duration::from_millis(140) && waited < Duration::from_millis(1000), "  at the deadline, not after it again: {waited:?}");
    handle(libc::SIGUSR1, 0);
    close(q);
    unlink(&n);
}

fn readiness(h: &mut Harness) {
    h.group("readiness");
    let n = name("ready");
    let q = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(1, 16)));
    let mut buf = [0u8; 16];
    let mut prio = 0;
    let mut p = libc::pollfd { fd: q as i32, events: libc::POLLIN, revents: 0 };
    check!(h, unsafe { libc::poll(&mut p, 1, 0) } == 0, "empty: not readable");

    // A poll asleep is woken by the send.
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(40));
        send(q, b"x", 0, None)
    });
    let r = unsafe { libc::poll(&mut p, 1, 5000) };
    t.join().unwrap();
    check!(h, r == 1 && p.revents & libc::POLLIN != 0, "a send wakes a poll: {r} {:#x}", p.revents);

    // epoll, waiting for room on the full queue.
    let ep = unsafe { libc::epoll_create1(0) };
    let mut ev = libc::epoll_event { events: libc::EPOLLOUT as u32, u64: 7 };
    check!(h, unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, q as i32, &mut ev) } == 0, "epoll_ctl");
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 2];
    check!(h, unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), 2, 0) } == 0, "full: not writable");
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(40));
        let mut b = [0u8; 16];
        let mut p = 0;
        recv(q, &mut b, &mut p, None)
    });
    let r = unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), 2, 5000) };
    t.join().unwrap();
    check!(h, r == 1 && out[0].u64 == 7 && out[0].events & libc::EPOLLOUT as u32 != 0, "a receive wakes epoll for EPOLLOUT: {r}");
    let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: 8 };
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_MOD, q as i32, &mut ev) };
    let child = unsafe { libc::fork() };
    if child == 0 {
        std::thread::sleep(Duration::from_millis(40));
        let c = open(&n, O_WRONLY, 0, None);
        unsafe { libc::_exit(if send(c, b"y", 0, None) == 0 { 0 } else { 1 }) };
    }
    let r = unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), 2, 5000) };
    check!(h, r == 1 && out[0].u64 == 8, "a send from another process wakes epoll for EPOLLIN: {r}");
    check!(h, wait_child(child) == 0, "  the child sent");
    check!(h, recv(q, &mut buf, &mut prio, None) == 1, "  and it is there");
    close(ep as i64);
    close(q);
    unlink(&n);
}

fn notification(h: &mut Harness) {
    h.group("notification");
    let n = name("notify");
    let q = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(4, 16)));
    let mut buf = [0u8; 16];
    let mut prio = 0;
    let me = unsafe { libc::getpid() };
    let uid = unsafe { libc::getuid() };

    check!(h, notify(q, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 0xfeed))) == 0, "register SIGUSR2");
    check!(h, notify(q, Some(&sigev(SIGEV_NONE, 0, 0))) == EBUSY, "a second registration is EBUSY");
    send(q, b"a", 0, None);
    let got = take_signal(libc::SIGUSR2, 1000);
    check!(h, got == Ok((SI_MESGQ, me, uid, 0xfeed)), "SI_MESGQ, the sender, the value: {got:?}");
    check!(h, !registered(q), "  and the registration is used up");
    send(q, b"b", 0, None);
    check!(h, take_signal(libc::SIGUSR2, 0) == Err(EAGAIN), "  so the next send says nothing");
    recv(q, &mut buf, &mut prio, None);
    recv(q, &mut buf, &mut prio, None);

    // Only the transition from empty, and only with nobody waiting.
    send(q, b"c", 0, None);
    notify(q, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 1)));
    send(q, b"d", 0, None);
    check!(h, take_signal(libc::SIGUSR2, 0) == Err(EAGAIN), "a send to a non-empty queue does not notify");
    recv(q, &mut buf, &mut prio, None);
    recv(q, &mut buf, &mut prio, None);
    let t = std::thread::spawn(move || {
        let mut b = [0u8; 16];
        let mut p = 0;
        recv(q, &mut b, &mut p, Some(&in_ms(5000)))
    });
    std::thread::sleep(Duration::from_millis(60));
    send(q, b"e", 0, None);
    check!(h, t.join().unwrap() == 1, "a blocked receiver takes the message");
    check!(h, take_signal(libc::SIGUSR2, 0) == Err(EAGAIN), "  and nothing is notified");
    check!(h, registered(q), "  and the registration stays");

    // Another process: cannot take it, cannot remove it, and its send is the
    // pid the signal names.
    let child = unsafe { libc::fork() };
    if child == 0 {
        let busy = notify(q, Some(&sigev(SIGEV_NONE, 0, 0))) == EBUSY;
        let null = notify(q, None) == 0;
        let sent = send(q, b"f", 0, None) == 0;
        unsafe { libc::_exit(if busy && null && sent { 0 } else { 1 }) };
    }
    check!(h, wait_child(child) == 0, "a child: EBUSY, a harmless NULL, a send");
    let got = take_signal(libc::SIGUSR2, 1000);
    check!(h, got.map(|g| (g.0, g.1, g.3)) == Ok((SI_MESGQ, child, 1)), "the signal names the child: {got:?}");
    recv(q, &mut buf, &mut prio, None);

    check!(h, notify(q, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 2))) == 0, "register again");
    check!(h, notify(q, None) == 0 && !registered(q), "NULL from the owner removes it");
    close(q);
    unlink(&n);
}

/// Any close by the owner -- a duplicate's, a second open's, the exit's --
/// drops the registration.
fn owner_close(h: &mut Harness) {
    h.group("owner close");
    let n = name("flush");
    let q = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(4, 16)));
    let d = unsafe { libc::dup(q as i32) } as i64;
    notify(q, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 3)));
    close(d);
    check!(h, !registered(q), "a dup closed");

    let q2 = open(&n, O_RDONLY, 0, None);
    notify(q2, Some(&sigev(SIGEV_NONE, 0, 0)));
    close(q2);
    check!(h, !registered(q), "another descriptor closed");

    let child = unsafe { libc::fork() };
    if child == 0 {
        notify(q, Some(&sigev(SIGEV_NONE, 0, 0)));
        unsafe { libc::_exit(0) };
    }
    wait_child(child);
    check!(h, !registered(q), "the owner exited");
    check!(h, notify(q, Some(&sigev(SIGEV_NONE, 0, 0))) == 0, "  and the next registration is accepted");

    // Somebody else closing is nothing to the owner.
    let child = unsafe { libc::fork() };
    if child == 0 {
        close(q);
        unsafe { libc::_exit(0) };
    }
    wait_child(child);
    check!(h, registered(q), "a child closing its copy leaves it");
    close(q);
    unlink(&n);
}

static THREAD_RAN: AtomicU64 = AtomicU64::new(0);

// musl's, which the `libc` crate does not declare: the library half of
// `SIGEV_THREAD` is what is being tested.
unsafe extern "C" {
    fn mq_notify(mqdes: i32, sevp: *const Sigevent) -> i32;
}

extern "C" fn on_message(value: usize) {
    THREAD_RAN.store(value as u64, Ordering::SeqCst);
}

/// `SIGEV_THREAD` through musl, which opens a netlink socket, registers it
/// with the kernel and reads the cookie back on a thread of its own.
fn thread_notification(h: &mut Harness) {
    h.group("SIGEV_THREAD");
    let n = name("thread");
    let q = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(4, 16)));
    let mut ev = sigev(SIGEV_THREAD, 0, 0x5eed);
    ev.function = on_message as extern "C" fn(usize) as usize;
    let r = unsafe { mq_notify(q as i32, &ev) };
    check!(h, r == 0, "musl's mq_notify(SIGEV_THREAD): {r} errno {}", guest_tests::sys::errno());
    check!(h, status(q).contains("NOTIFY:2 "), "registered as SIGEV_THREAD: {}", status(q).trim());
    send(q, b"t", 0, None);
    let t0 = Instant::now();
    while THREAD_RAN.load(Ordering::SeqCst) == 0 && t0.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(5));
    }
    check!(h, THREAD_RAN.load(Ordering::SeqCst) == 0x5eed, "the function ran with the value: {:#x}", THREAD_RAN.load(Ordering::SeqCst));
    close(q);
    unlink(&n);
}

fn lifetime(h: &mut Harness) {
    h.group("lifetime");
    let n = name("life");
    let q = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(4, 16)));
    send(q, b"kept", 1, None);
    close(q);
    let q = open(&n, O_RDWR, 0, None);
    check!(h, curmsgs(q) == 1, "a closed queue keeps its messages");

    let child = unsafe { libc::fork() };
    if child == 0 {
        let c = open(&n, O_RDWR, 0, None);
        let mut b = [0u8; 16];
        let mut p = 0;
        let got = recv(c, &mut b, &mut p, None) == 4 && &b[..4] == b"kept";
        let sent = send(c, b"child", 2, None) == 0;
        unsafe { libc::_exit(if got && sent { 0 } else { 1 }) };
    }
    check!(h, wait_child(child) == 0, "a child opens it by name, receives and sends");
    check!(h, curmsgs(q) == 1, "  and the parent sees the child's message");

    check!(h, unlink(&n) == 0, "unlink while open");
    check!(h, open(&n, O_RDWR, 0, None) == ENOENT, "  the name is gone");
    let q2 = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(4, 16)));
    check!(h, q2 >= 0 && curmsgs(q2) == 0, "  a new queue by that name is a different one");
    let mut buf = [0u8; 16];
    let mut prio = 0;
    let r = recv(q, &mut buf, &mut prio, None);
    check!(h, r == 5 && &buf[..5] == b"child", "  the unlinked one still answers: {r}");
    let link = std::fs::read_link(format!("/proc/self/fd/{q}")).map(|p| p.display().to_string()).unwrap_or_default();
    check!(h, link == format!("/{} (deleted)", n.to_str().unwrap()), "  and reads as deleted: {link}");
    close(q);
    close(q2);
    unlink(&n);

    // `futimens` sets the queue's times. The descriptor's path is `/<name>`,
    // and a file of that name at the root is somebody else's.
    let q = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, None);
    let decoy = format!("/{}", n.to_str().unwrap());
    let made = std::fs::write(&decoy, b"decoy").is_ok();
    let times = [libc::timespec { tv_sec: 1000, tv_nsec: 0 }, libc::timespec { tv_sec: 2000, tv_nsec: 0 }];
    let r = unsafe { libc::futimens(q as i32, times.as_ptr()) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(q as i32, &mut st) };
    check!(h, r == 0 && st.st_mtime == 2000 && st.st_atime == 1000, "futimens sets the queue's times: {r} {} {}", st.st_atime, st.st_mtime);
    let decoy_mtime = std::fs::metadata(&decoy).ok().and_then(|m| m.modified().ok());
    let untouched = decoy_mtime.is_some_and(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() > 2000);
    check!(h, made && untouched, "  and not the file at /{}", n.to_str().unwrap());
    let _ = std::fs::remove_file(&decoy);
    close(q);
    unlink(&n);
}

/// Four producer threads and a producer process into a queue of three, one
/// consumer checking each producer's order, then four consumers checking
/// that nothing was lost or doubled.
fn stress(h: &mut Harness) {
    h.group("stress");
    const PER: u32 = 300;
    let n = name("stress");
    let q = open(&n, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(3, 8)));

    let produce = move |who: u32| {
        for i in 0..PER {
            let m = ((who as u64) << 32 | i as u64).to_le_bytes();
            if send(q, &m, who as i64, Some(&in_ms(10_000))) != 0 {
                return false;
            }
        }
        true
    };

    // One consumer: each producer's messages arrive in its order.
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::_exit(if produce(4) { 0 } else { 1 }) };
    }
    let producers: Vec<_> = (0..4).map(|w| std::thread::spawn(move || produce(w))).collect();
    let mut next = [0u32; 5];
    let mut in_order = true;
    let mut buf = [0u8; 8];
    let mut prio = 0;
    for _ in 0..5 * PER {
        if recv(q, &mut buf, &mut prio, Some(&in_ms(10_000))) != 8 {
            in_order = false;
            break;
        }
        let v = u64::from_le_bytes(buf);
        let (who, i) = ((v >> 32) as usize, v as u32);
        in_order &= who < 5 && i == next[who] && prio as usize == who;
        if who < 5 {
            next[who] += 1;
        }
    }
    let ok = producers.into_iter().all(|t| t.join().unwrap());
    check!(h, ok && wait_child(child) == 0, "every producer finished");
    check!(h, in_order && next == [PER; 5], "each producer's messages in its order: {next:?}");

    // Four consumers: the union is everything, once.
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::_exit(if produce(4) { 0 } else { 1 }) };
    }
    let producers: Vec<_> = (0..4).map(|w| std::thread::spawn(move || produce(w))).collect();
    let consumers: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(move || {
                let mut got = Vec::new();
                let mut b = [0u8; 8];
                let mut p = 0;
                while recv(q, &mut b, &mut p, Some(&in_ms(1000))) == 8 {
                    got.push(u64::from_le_bytes(b));
                }
                got
            })
        })
        .collect();
    let ok = producers.into_iter().all(|t| t.join().unwrap());
    let mut all: Vec<u64> = consumers.into_iter().flat_map(|t| t.join().unwrap()).collect();
    check!(h, ok && wait_child(child) == 0, "every producer finished");
    all.sort_unstable();
    let want: Vec<u64> = (0..5u64).flat_map(|w| (0..PER as u64).map(move |i| w << 32 | i)).collect();
    check!(h, all == want, "nothing lost and nothing doubled: {} of {}", all.len(), want.len());
    check!(h, curmsgs(q) == 0, "  and the queue is empty");
    close(q);
    unlink(&n);
}
