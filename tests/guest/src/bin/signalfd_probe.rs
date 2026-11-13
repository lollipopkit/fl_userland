//! What a `signalfd` answers, and what is in the 128 bytes it hands back.
//!
//! # Why this exists
//!
//! `struct signalfd_siginfo` is a **fixed-size wire format**, which is the
//! shape this tree keeps finding defects in: `struct cmsghdr_` was the i386
//! layout so passing a descriptor over a unix socket passed nothing, and the
//! signal frame's `siginfo_` union ended at 48 so two thirds of it was never
//! written. Nothing reads this one back field by field.
//!
//! The rules around it are just as unasked. `signalfd4`'s first argument is
//! either -1 (make one) or an existing signalfd (change its mask) and anything
//! else is an error; the mask silently drops `SIGKILL` and `SIGSTOP`; a read
//! shorter than one record is refused; and the descriptor answers for the
//! **reading** thread rather than the creating one, which is Linux's rule and
//! is why one inherited across `fork` answers for the child.
//!
//! # What is checked
//!
//! Nothing is asserted. Each case prints one line, and the finding is the
//! difference against an arm64 Linux container through
//! `tests/integration/probe_diff.sh`.
//!
//! # Signals 32, 33 and 34 are not usable here
//!
//! musl reserves them and its `sigaddset` and `sigaction` refuse them outright,
//! so a probe that picks `SIGRTMIN` by its architectural number never blocks the
//! signal it then sends itself. The first version of this file did and died.
//!
//! Number 34 is also where the two sides *legitimately* differ, and it cost an
//! hour to establish that: on Linux this binary starts with 34 set to `SIG_IGN`
//! and here it starts `SIG_DFL`, so `kill(self, 34)` kills it here and does not
//! there. It is not a lost disposition — setting `SIG_IGN` explicitly sticks,
//! survives `fork`, and is honoured, and `exec_reset_probe` already checks that
//! an ignored signal stays ignored across `execve`. It is what the process
//! *inherits*: a container's first process inherits its parent's ignored set,
//! and a guest's first process here has nothing to inherit from.
//!
//! # Every signal used here is blocked first
//!
//! A signalfd only sees what the thread has blocked; an unblocked one takes its
//! default action, and for `SIGUSR1` that is death. The mask is set once at the
//! top and every case relies on it.

use std::ffi::c_int;

const SFD_NONBLOCK: c_int = 0o4000;
const SFD_CLOEXEC: c_int = 0o2000000;

const SIGUSR1: c_int = 10;
const SIGUSR2: c_int = 12;
const SIGCHLD: c_int = 17;
/// A real-time signal, chosen at 36 rather than 34: **musl reserves 32, 33 and
/// 34** for its own use and its `sigaddset` refuses them outright, so a probe
/// that picks `SIGRT` by its architectural number never blocks the signal it
/// then sends itself. The first version of this file did, and died of it.
const SIGRT: c_int = 36;

/// `struct signalfd_siginfo`, 128 bytes. Every field, so a layout that has
/// moved shows up as the *name* that moved rather than as a count.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
struct SignalfdSiginfo {
    signo: u32,
    errno: i32,
    code: i32,
    pid: u32,
    uid: u32,
    fd: i32,
    tid: u32,
    band: u32,
    overrun: u32,
    trapno: u32,
    status: i32,
    int: i32,
    ptr: u64,
    utime: u64,
    stime: u64,
    addr: u64,
    addr_lsb: u16,
    _pad2: u16,
    syscall: i32,
    call_addr: u64,
    arch: u32,
    _pad: [u8; 28],
}

fn errname(e: i32) -> String {
    let n = match e {
        1 => "EPERM", 4 => "EINTR", 9 => "EBADF", 11 => "EAGAIN", 14 => "EFAULT",
        22 => "EINVAL", 25 => "ENOTTY", 29 => "ESPIPE",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 { format!("-{}", errname(-v as i32)) } else { v.to_string() }
}

unsafe fn sys(n: i64, a: i64, b: i64, c: i64, d: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            options(nostack)
        );
    }
    ret
}

const NR_SIGNALFD4: i64 = 74;
const NR_READ: i64 = 63;
const NR_TKILL: i64 = 130;
const NR_RT_SIGQUEUEINFO: i64 = 138;

fn signalfd(fd: i64, mask: u64, size: i64, flags: c_int) -> i64 {
    unsafe { sys(NR_SIGNALFD4, fd, &mask as *const u64 as i64, size, flags as i64) }
}

fn read_raw(fd: i64, buf: *mut u8, len: usize) -> i64 {
    unsafe { sys(NR_READ, fd, buf as i64, len as i64, 0) }
}

fn bit(sig: c_int) -> u64 {
    1u64 << (sig - 1)
}

fn main() {
    // Every signal this uses, blocked for the whole run.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        for s in [SIGUSR1, SIGUSR2, SIGCHLD, SIGRT] {
            libc::sigaddset(&mut set, s);
        }
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }

    creation();
    mask_rules();
    read_rules();
    record_fields();
    queueing();
    in_an_event_loop();
}

/// A signalfd in a `poll` set and in an `epoll` set, woken by a signal that
/// arrives while the thread is already waiting.
///
/// This is the whole reason the descriptor exists -- a program that wanted to
/// read signals synchronously could use `sigtimedwait` -- and it is the case
/// nothing had measured. `poll` worked here and `epoll` did not: a thread
/// blocked in `poll` is woken by the signal itself and re-polls its set, while
/// an epoll set is woken by a *description* telling its watchers, and nothing
/// told them. Linux's `signalfd_notify` is that telling, and it is called from
/// `__send_signal`.
///
/// Every case has a bound, so a kernel that never wakes reports a timeout
/// rather than taking the sweep with it. The waits are two seconds and the
/// signal arrives after 300 ms, so the *number* is not a measurement -- what is
/// reported is which of the two happened.
fn in_an_event_loop() {
    println!("## in an event loop");
    let fd = signalfd(-1, bit(SIGUSR1), 8, SFD_NONBLOCK) as i32;

    // poll(), with the signal sent by another process.
    println!("  poll, signalled by a child -> {}", waited(fd, false));
    drain(fd);
    // epoll_wait, the same.
    println!("  epoll, signalled by a child -> {}", waited(fd, true));
    drain(fd);
    // And a signal that arrives *before* the wait: level-triggered readiness,
    // which is a different path -- the set is built with the signal already
    // pending.
    unsafe { libc::kill(libc::getpid(), SIGUSR1) };
    println!("  epoll, already pending -> {}", waited(fd, true));
    drain(fd);
    close(fd as i64);
}

/// Waits up to two seconds for `fd` to become readable, with a child sending
/// `SIGUSR1` after 300 ms unless one is already pending. Answers what happened.
fn waited(fd: i32, use_epoll: bool) -> String {
    let already = {
        let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut pending);
            libc::sigpending(&mut pending);
            libc::sigismember(&pending, SIGUSR1) == 1
        }
    };
    let me = unsafe { libc::getpid() };
    let child = if already {
        -1
    } else {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                libc::usleep(300_000);
                libc::kill(me, SIGUSR1);
                libc::_exit(0);
            }
        }
        pid
    };

    let woke = if use_epoll {
        let ep = unsafe { libc::epoll_create1(0) };
        let mut reg = libc::epoll_event { events: libc::EPOLLIN as u32, u64: fd as u64 };
        unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut reg) };
        let mut ev: libc::epoll_event = unsafe { std::mem::zeroed() };
        let n = unsafe { libc::epoll_wait(ep, &mut ev, 1, 2000) };
        unsafe { libc::close(ep) };
        n
    } else {
        let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        unsafe { libc::poll(&mut p, 1, 2000) }
    };
    if child > 0 {
        let mut status = 0;
        unsafe { libc::waitpid(child, &mut status, 0) };
    }
    match woke {
        1 => "readable".into(),
        0 => "timed out".into(),
        _ => format!("-{}", errname(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))),
    }
}

/// Take whatever is in the descriptor, so one case does not leak into the next.
fn drain(fd: i32) {
    let mut buf = [0u8; 128];
    while unsafe { libc::read(fd as c_int, buf.as_mut_ptr().cast(), 128) } > 0 {}
    drain_pending(SIGUSR1);
}

/// `signalfd4`'s first argument and its flags.
fn creation() {
    println!("## signalfd4 creation");
    let fd = signalfd(-1, bit(SIGUSR1), 8, 0);
    println!("  a new one -> {}", if fd >= 0 { "a descriptor" } else { "an error" });

    // Updating an existing one: the first argument is the signalfd itself.
    println!("  updating it -> {}", r(signalfd(fd, bit(SIGUSR2), 8, 0)));
    // A descriptor that is not a signalfd.
    let (rd, wr) = pipe();
    println!("  updating a pipe -> {}", r(signalfd(rd, bit(SIGUSR1), 8, 0)));
    println!("  updating a closed number -> {}", r(signalfd(9999, bit(SIGUSR1), 8, 0)));

    // The flags.
    for (f, name) in [
        (0, "0"),
        (SFD_CLOEXEC, "SFD_CLOEXEC"),
        (SFD_NONBLOCK, "SFD_NONBLOCK"),
        (SFD_CLOEXEC | SFD_NONBLOCK, "both"),
        (1, "an unallocated flag"),
        (0o10000, "another unallocated flag"),
    ] {
        let e = signalfd(-1, bit(SIGUSR1), 8, f);
        println!("  flags {name} -> {}", if e >= 0 { close(e); "a descriptor".to_string() } else { r(e) });
    }

    // The mask size. Linux takes `sizeof(sigset_t)`, which is 8 on aarch64.
    for size in [0i64, 4, 8, 16, 128] {
        let e = signalfd(-1, bit(SIGUSR1), size, 0);
        println!("  a mask of {size} bytes -> {}", if e >= 0 { close(e); "a descriptor".to_string() } else { r(e) });
    }
    // A null mask.
    println!("  a null mask -> {}", r(unsafe { sys(NR_SIGNALFD4, -1, 0, 8, 0) }));

    close(fd);
    close(rd);
    close(wr);
}

/// What the mask may contain.
fn mask_rules() {
    println!("## the mask");
    // SIGKILL and SIGSTOP cannot be caught, and Linux silently drops them
    // rather than refusing the call.
    let fd = signalfd(-1, bit(9) | bit(19) | bit(SIGUSR1), 8, SFD_NONBLOCK);
    println!("  SIGKILL and SIGSTOP in the mask -> {}", if fd >= 0 { "accepted" } else { "an error" });
    // An empty mask is legal and simply never reports anything.
    let empty = signalfd(-1, 0, 8, SFD_NONBLOCK);
    println!("  an empty mask -> {}", if empty >= 0 { "accepted" } else { "an error" });
    let mut buf = [0u8; 128];
    println!("  ...and reads -> {}", r(read_raw(empty, buf.as_mut_ptr(), 128)));
    // A mask with every bit set, including the ones no signal uses.
    let all = signalfd(-1, u64::MAX, 8, SFD_NONBLOCK);
    println!("  every bit set -> {}", if all >= 0 { "accepted" } else { "an error" });
    close(fd);
    close(empty);
    close(all);
}

/// The read side: how much may be asked for, and what an empty queue does.
fn read_rules() {
    println!("## reading");
    let fd = signalfd(-1, bit(SIGUSR1), 8, SFD_NONBLOCK);
    let mut buf = [0u8; 512];

    // Nothing pending, non-blocking.
    println!("  an empty queue -> {}", r(read_raw(fd, buf.as_mut_ptr(), 128)));

    // A buffer shorter than one record.
    raise(SIGUSR1);
    println!("  a 127-byte buffer -> {}", r(read_raw(fd, buf.as_mut_ptr(), 127)));
    println!("  a zero-length read -> {}", r(read_raw(fd, buf.as_mut_ptr(), 0)));
    // ...and the signal is still there afterwards.
    println!("  then a 128-byte read -> {}", r(read_raw(fd, buf.as_mut_ptr(), 128)));

    // Room for three records with one signal queued: a short count, not a wait.
    raise(SIGUSR1);
    println!("  room for three, one queued -> {}", r(read_raw(fd, buf.as_mut_ptr(), 384)));

    // A read into an address that is not mapped.
    raise(SIGUSR1);
    println!("  a buffer past the address space -> {}", r(unsafe {
        sys(NR_READ, fd, 0x7fff_ffff_ffff_ff00u64 as i64, 128, 0)
    }));
    // Drain, so the next section starts clean.
    read_raw(fd, buf.as_mut_ptr(), 128);

    // A signal outside the mask is not delivered here.
    raise(SIGUSR2);
    println!("  a signal outside the mask -> {}", r(read_raw(fd, buf.as_mut_ptr(), 128)));
    // ...and is still pending for anything else that asks.
    let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigpending(&mut pending) };
    println!(
        "  ...and is still pending: {}",
        unsafe { libc::sigismember(&pending, SIGUSR2) } == 1
    );
    drain_pending(SIGUSR2);

    close(fd);
}

/// The 128 bytes themselves, field by field.
fn record_fields() {
    println!("## the record");
    let fd = signalfd(-1, bit(SIGUSR1) | bit(SIGCHLD) | bit(SIGRT), 8, SFD_NONBLOCK);
    let me = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() } as u32;

    // A `tkill` to this thread. `si_code` is SI_TKILL (-6), which is what every
    // `raise()` in a musl program produces.
    let tid = unsafe { libc::syscall(178) } as i64; // gettid
    unsafe { sys(NR_TKILL, tid, SIGUSR1 as i64, 0, 0) };
    let s = one(fd);
    println!("  tkill: signo {} errno {} code {}", s.signo, s.errno, s.code);
    println!("  tkill: pid is ours {} uid is ours {}", s.pid == me, s.uid == uid);
    println!("  tkill: fd {} tid {} band {} overrun {}", s.fd, s.tid, s.band, s.overrun);
    println!("  tkill: status {} int {} ptr {}", s.status, s.int, s.ptr);
    println!("  tkill: utime {} stime {} addr {}", s.utime, s.stime, s.addr);
    println!("  tkill: addr_lsb {} syscall {} arch {}", s.addr_lsb, s.syscall, s.arch);

    // `rt_sigqueueinfo` with a value, which is where `ssi_int` and `ssi_ptr`
    // come from -- the two fields a real-time signal carries and the reason the
    // record has them at all.
    let mut info = [0u8; 128];
    info[0..4].copy_from_slice(&(SIGRT as u32).to_le_bytes()); // si_signo
    info[8..12].copy_from_slice(&(-1i32).to_le_bytes()); // si_code = SI_QUEUE
    info[12..16].copy_from_slice(&me.to_le_bytes()); // si_pid
    info[16..20].copy_from_slice(&uid.to_le_bytes()); // si_uid
    info[20..24].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // si_value
    let e = unsafe {
        sys(NR_RT_SIGQUEUEINFO, me as i64, SIGRT as i64, info.as_mut_ptr() as i64, 0)
    };
    println!("  rt_sigqueueinfo -> {}", r(e));
    if e == 0 {
        let s = one(fd);
        println!("  queued: signo {} code {} int {:#x}", s.signo, s.code, s.int);
        println!("  queued: pid is ours {} uid is ours {}", s.pid == me, s.uid == uid);
    } else {
        println!("  queued: signo - code - int -");
        println!("  queued: pid is ours - uid is ours -");
    }

    close(fd);
}

/// More than one signal at a time.
fn queueing() {
    println!("## queueing");
    let fd = signalfd(-1, bit(SIGUSR1) | bit(SIGUSR2), 8, SFD_NONBLOCK);
    raise(SIGUSR1);
    raise(SIGUSR2);
    let mut buf = [0u8; 512];
    let n = read_raw(fd, buf.as_mut_ptr(), 512);
    println!("  two different signals, room for four -> {}", r(n));
    if n >= 256 {
        let a = unsafe { *(buf.as_ptr() as *const SignalfdSiginfo) };
        let b = unsafe { *(buf.as_ptr().add(128) as *const SignalfdSiginfo) };
        println!("  ...in order: {} then {}", a.signo, b.signo);
    } else {
        println!("  ...in order: - then -");
    }

    // A standard signal raised twice coalesces into one record; a real-time one
    // does not. That is the queue's whole distinction.
    raise(SIGUSR1);
    raise(SIGUSR1);
    let n = read_raw(fd, buf.as_mut_ptr(), 512);
    println!("  the same standard signal twice -> {} bytes", r(n));

    close(fd);
    let fd = signalfd(-1, bit(SIGRT), 8, SFD_NONBLOCK);
    let me = unsafe { libc::getpid() };
    for _ in 0..2 {
        unsafe { libc::syscall(129, me, SIGRT) }; // kill
    }
    let n = read_raw(fd, buf.as_mut_ptr(), 512);
    println!("  the same real-time signal twice -> {} bytes", r(n));
    close(fd);
}

// --------------------------------------------------------------- helpers

fn one(fd: i64) -> SignalfdSiginfo {
    let mut buf = [0u8; 128];
    let n = read_raw(fd, buf.as_mut_ptr(), 128);
    if n != 128 {
        return SignalfdSiginfo::default();
    }
    unsafe { *(buf.as_ptr() as *const SignalfdSiginfo) }
}

fn raise(sig: c_int) {
    unsafe { libc::syscall(129, libc::getpid(), sig) };
}

/// Take a pending signal off the queue with `sigtimedwait`, so it does not
/// leak into a later case.
fn drain_pending(sig: c_int) {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, sig);
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        libc::sigtimedwait(&set, std::ptr::null_mut(), &ts);
    }
}

fn pipe() -> (i64, i64) {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    (fds[0] as i64, fds[1] as i64)
}

fn close(fd: i64) {
    unsafe { libc::close(fd as i32) };
}
