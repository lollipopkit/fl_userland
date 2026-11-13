//! epoll and poll, against what Linux does.
//!
//! Neither had any coverage, and they are the interface every runtime this
//! emulator is meant to run is built on: Node and bun through libuv, Go
//! through netpoll, anything using a reactor.
//!
//! The errnos matter as much as the events. libuv asserts that `epoll_pwait`
//! fails only with EINTR, and treats EPERM from `epoll_ctl(ADD)` on a regular
//! file as "this is a file, poll it differently" — so an implementation that
//! returns the wrong one does not degrade, it takes a different code path or
//! aborts.

use guest_tests::{Harness, check, check_fails, sys};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const EPOLL_CLOEXEC: i32 = 0o2000000;
const EPOLL_POLL_WAKE_DELAY: Duration = Duration::from_millis(80);
const EPOLL_POLL_WAKE_LIMIT: Duration = Duration::from_millis(800);
const VIRTUAL_WAKE_DELAY: Duration = Duration::from_millis(80);
const VIRTUAL_WAKE_RESCUE: Duration = Duration::from_millis(800);
const KERNEL_SIGSET_SIZE: usize = 8;

static PWATCH_SIGNAL_RAN: AtomicUsize = AtomicUsize::new(0);

extern "C" fn signal_handler(_: i32) {
    PWATCH_SIGNAL_RAN.fetch_add(1, Ordering::SeqCst);
}

fn epoll_create1(flags: i32) -> i32 {
    unsafe { libc::syscall(libc::SYS_epoll_create1, flags) as i32 }
}

fn ctl(ep: i32, op: i32, fd: i32, ev: &mut libc::epoll_event) -> i32 {
    unsafe { libc::epoll_ctl(ep, op, fd, ev) }
}

fn ctl_raw(ep: i32, op: i32, fd: i32, ev: *mut libc::epoll_event) -> i64 {
    unsafe { libc::syscall(libc::SYS_epoll_ctl, ep, op, fd, ev) }
}

fn event(events: u32, data: u64) -> libc::epoll_event {
    libc::epoll_event { events, u64: data }
}

#[derive(Debug)]
struct WaitResult {
    raw: i32,
    events: Vec<(u32, u64)>,
}

fn wait_up_to<const N: usize>(ep: i32, ms: i32) -> WaitResult {
    let mut buf: [libc::epoll_event; N] = unsafe { std::mem::zeroed() };
    let raw = unsafe { libc::epoll_wait(ep, buf.as_mut_ptr(), N as i32, ms) };
    let events = if raw > 0 {
        buf[..raw as usize]
            .iter()
            .map(|e| (e.events, e.u64))
            .collect()
    } else {
        Vec::new()
    };
    WaitResult { raw, events }
}

/// Wait, and give back both the raw return and what came out.
fn wait(ep: i32, ms: i32) -> WaitResult {
    wait_up_to::<8>(ep, ms)
}

fn pipe() -> Option<(i32, i32)> {
    let mut p = [0i32; 2];
    (unsafe { libc::pipe(p.as_mut_ptr()) } == 0).then_some((p[0], p[1]))
}

fn eventfd(initval: u32, flags: i32) -> i32 {
    unsafe { libc::syscall(libc::SYS_eventfd2, initval, flags) as i32 }
}

fn timerfd() -> i32 {
    unsafe { libc::syscall(libc::SYS_timerfd_create, libc::CLOCK_MONOTONIC, 0) as i32 }
}

fn timerfd_arm(fd: i32, delay: Duration) -> i64 {
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: delay.as_secs() as _,
            tv_nsec: delay.subsec_nanos() as _,
        },
    };
    unsafe {
        libc::syscall(
            libc::SYS_timerfd_settime,
            fd,
            0,
            &raw const spec,
            std::ptr::null_mut::<libc::itimerspec>(),
        )
    }
}

fn wait_one(ep: i32, ms: i32) -> WaitResult {
    wait_up_to::<1>(ep, ms)
}

fn epoll_pwait_raw(
    ep: i32,
    events: *mut libc::epoll_event,
    max_events: i32,
    timeout: i32,
    mask: *const u64,
    mask_size: usize,
) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_epoll_pwait,
            ep,
            events,
            max_events,
            timeout,
            mask,
            mask_size,
        )
    }
}

fn t_create(h: &mut Harness) {
    h.group("epoll-create");
    let ep = epoll_create1(0);
    check!(h, ep >= 0, "epoll_create1(0): {ep}");
    check!(
        h,
        unsafe { libc::fcntl(ep, libc::F_GETFD) } & libc::FD_CLOEXEC == 0,
        "without EPOLL_CLOEXEC the descriptor is not close-on-exec"
    );
    let c = epoll_create1(EPOLL_CLOEXEC);
    check!(
        h,
        c >= 0 && unsafe { libc::fcntl(c, libc::F_GETFD) } & libc::FD_CLOEXEC != 0,
        "EPOLL_CLOEXEC sets FD_CLOEXEC"
    );
    check_fails!(
        h,
        epoll_create1(1 << 20) as i64,
        libc::EINVAL,
        "an unknown flag"
    );
    unsafe {
        libc::close(ep);
        libc::close(c);
    }
}

fn t_ctl_errnos(h: &mut Harness) {
    h.group("epoll-ctl-errnos");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let mut ev = event(libc::EPOLLIN as u32, 1);

    check_fails!(
        h,
        ctl(4096, libc::EPOLL_CTL_ADD, r, &mut ev) as i64,
        libc::EBADF,
        "an epoll descriptor that does not exist"
    );
    check_fails!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, 4096, &mut ev) as i64,
        libc::EBADF,
        "a target descriptor that does not exist"
    );
    check_fails!(
        h,
        ctl(r, libc::EPOLL_CTL_ADD, w, &mut ev) as i64,
        libc::EINVAL,
        "an epoll argument that is not an epoll descriptor"
    );
    check_fails!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, ep, &mut ev) as i64,
        libc::EINVAL,
        "adding the set to itself"
    );
    check_fails!(
        h,
        ctl(ep, 99, r, &mut ev) as i64,
        libc::EINVAL,
        "an operation that is not ADD, MOD or DEL"
    );

    // MOD and DEL of something that was never added.
    check_fails!(
        h,
        ctl(ep, libc::EPOLL_CTL_MOD, r, &mut ev) as i64,
        libc::ENOENT,
        "MOD of a descriptor that is not in the set"
    );
    check_fails!(
        h,
        ctl(ep, libc::EPOLL_CTL_DEL, r, &mut ev) as i64,
        libc::ENOENT,
        "DEL of a descriptor that is not in the set"
    );

    check!(h, ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev) == 0, "ADD");
    check_fails!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev) as i64,
        libc::EEXIST,
        "ADD of a descriptor already in the set"
    );
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_MOD, r, &mut ev) == 0,
        "MOD once it is there"
    );
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_DEL, r, &mut ev) == 0,
        "DEL once it is there"
    );

    // A null event pointer: required for ADD and MOD, ignored for DEL —
    // Linux has ignored it for DEL since 2.6.9 and programs rely on that.
    check_fails!(
        h,
        ctl_raw(ep, libc::EPOLL_CTL_ADD, r, std::ptr::null_mut()),
        libc::EFAULT,
        "ADD with a null event"
    );
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev) == 0,
        "ADD again"
    );
    check!(
        h,
        ctl_raw(ep, libc::EPOLL_CTL_DEL, r, std::ptr::null_mut()) == 0,
        "DEL with a null event is allowed"
    );

    unsafe {
        libc::close(r);
        libc::close(w);
        libc::close(ep);
    }
}

/// A regular file is always ready, so Linux refuses to put one in an epoll
/// set. libuv and bun read the EPERM as "this is a file" and take a different
/// path; accepting it sends them down the polling one.
fn t_regular_file_is_refused(h: &mut Harness) {
    h.group("epoll-regular-file");
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    let path = format!("{dir}/epoll-probe");
    if std::fs::write(&path, b"x").is_err() {
        check!(h, false, "writing {path}");
        return;
    }
    let fd = sys::open(&path, libc::O_RDONLY, 0);
    let ep = epoll_create1(0);
    let mut ev = event(libc::EPOLLIN as u32, 7);
    check_fails!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) as i64,
        libc::EPERM,
        "adding a regular file"
    );
    // And a directory.
    let dfd = sys::open(&dir, libc::O_RDONLY | libc::O_DIRECTORY, 0);
    if dfd >= 0 {
        check_fails!(
            h,
            ctl(ep, libc::EPOLL_CTL_ADD, dfd, &mut ev) as i64,
            libc::EPERM,
            "adding a directory"
        );
        sys::close(dfd);
    }
    sys::close(fd);
    sys::close(ep);
    unsafe { libc::unlink(guest_tests::cpath(&path).as_ptr()) };
}

fn t_wait_arguments(h: &mut Harness) {
    h.group("epoll-wait-args");
    let ep = epoll_create1(0);
    let mut buf: [libc::epoll_event; 4] = unsafe { std::mem::zeroed() };
    check_fails!(
        h,
        unsafe { libc::epoll_wait(ep, buf.as_mut_ptr(), 0, 0) } as i64,
        libc::EINVAL,
        "maxevents of zero"
    );
    check_fails!(
        h,
        unsafe { libc::epoll_wait(ep, buf.as_mut_ptr(), -1, 0) } as i64,
        libc::EINVAL,
        "a negative maxevents"
    );
    check!(
        h,
        unsafe { libc::epoll_wait(ep, buf.as_mut_ptr(), 4, 0) } == 0,
        "an empty set with a zero timeout returns 0"
    );
    let r = unsafe { libc::epoll_wait(4096, buf.as_mut_ptr(), 4, 0) };
    check!(
        h,
        r == -1 && sys::errno() == libc::EBADF,
        "a bad epoll descriptor: got {r} errno {}",
        sys::errno()
    );
    sys::close(ep);
}

/// epoll_pwait applies a guest-kernel-width signal mask only for the wait. A
/// blocked SIGUSR1 is made pending before the call; the temporary empty mask
/// must let it interrupt the wait, and the original blocked mask must be back
/// before the call returns to userspace.
fn t_pwait_mask(h: &mut Harness) {
    h.group("epoll-pwait-mask");
    install_signal_handler(libc::SIGUSR1);
    PWATCH_SIGNAL_RAN.store(0, Ordering::SeqCst);

    let signal_bit = 1u64 << (libc::SIGUSR1 - 1);
    let empty = 0u64;
    let mut old = 0u64;
    let block = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            &raw const signal_bit,
            &raw mut old,
            KERNEL_SIGSET_SIZE,
        )
    };
    check!(
        h,
        block == 0,
        "block SIGUSR1 before epoll_pwait: {block} errno {}",
        sys::errno()
    );
    let raised = unsafe { libc::raise(libc::SIGUSR1) };
    check!(h, raised == 0, "queue blocked SIGUSR1: {raised}");
    check!(
        h,
        PWATCH_SIGNAL_RAN.load(Ordering::SeqCst) == 0,
        "the blocked signal has not run before epoll_pwait"
    );

    let ep = epoll_create1(0);
    let mut ready: libc::epoll_event = unsafe { std::mem::zeroed() };
    sys::clear_errno();
    let result = epoll_pwait_raw(
        ep,
        &raw mut ready,
        1,
        1000,
        &raw const empty,
        KERNEL_SIGSET_SIZE,
    );
    let errno = sys::errno();
    check!(
        h,
        result == -1 && errno == libc::EINTR,
        "the temporary empty mask exposes pending SIGUSR1: {result} errno {errno}"
    );
    check!(
        h,
        PWATCH_SIGNAL_RAN.load(Ordering::SeqCst) == 1,
        "SIGUSR1 handler ran exactly once"
    );

    let mut current = 0u64;
    let read_mask = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            std::ptr::null::<u64>(),
            &raw mut current,
            KERNEL_SIGSET_SIZE,
        )
    };
    check!(
        h,
        read_mask == 0 && current & signal_bit != 0,
        "epoll_pwait restored the caller's blocked mask: r={read_mask} mask={current:#x}"
    );

    for bad_size in [0usize, 4, 16, 128] {
        check_fails!(
            h,
            epoll_pwait_raw(ep, &raw mut ready, 1, 0, &raw const empty, bad_size),
            libc::EINVAL,
            "epoll_pwait rejects sigsetsize {bad_size}"
        );
    }
    // Linux ignores sigsetsize when no mask was supplied.
    let no_mask = epoll_pwait_raw(ep, &raw mut ready, 1, 0, std::ptr::null(), 128);
    check!(
        h,
        no_mask == 0,
        "a null epoll_pwait mask ignores sigsetsize and times out with return 0: {no_mask} errno {}",
        sys::errno()
    );

    let restore = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            &raw const old,
            std::ptr::null_mut::<u64>(),
            KERNEL_SIGSET_SIZE,
        )
    };
    check!(h, restore == 0, "restore the original mask: {restore}");
    sys::close(ep);
}

fn t_levels(h: &mut Harness) {
    h.group("epoll-level");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let mut ev = event(libc::EPOLLIN as u32, 0xabc);
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev) == 0,
        "ADD the read end"
    );

    let empty = wait(ep, 0);
    check!(
        h,
        empty.raw == 0,
        "an empty pipe times out with return 0: {empty:?}, errno {}",
        sys::errno()
    );
    sys::write(w, b"hi");
    let got = wait(ep, 500);
    check!(
        h,
        got.raw == 1,
        "one event once there is data, got {got:?}, errno {}",
        sys::errno()
    );
    if let Some(&(events, data)) = got.events.first() {
        check!(
            h,
            events & libc::EPOLLIN as u32 != 0,
            "EPOLLIN, got {events:#x}"
        );
        check!(
            h,
            data == 0xabc,
            "the data the registration carried, got {data:#x}"
        );
    }
    // Level-triggered: still ready without reading.
    let repeated = wait(ep, 0);
    check!(
        h,
        repeated.raw == 1,
        "level-triggered readiness reports again without reading: {repeated:?}"
    );
    let mut buf = [0u8; 8];
    sys::read(r, &mut buf);
    let drained = wait(ep, 0);
    check!(
        h,
        drained.raw == 0,
        "drained readiness times out with return 0: {drained:?}, errno {}",
        sys::errno()
    );

    // The write end hanging up.
    sys::close(w);
    let got = wait(ep, 500);
    check!(
        h,
        got.raw == 1 && got.events[0].0 & libc::EPOLLHUP as u32 != 0,
        "closing the write end reports EPOLLHUP, got {got:?}"
    );

    sys::close(r);
    sys::close(ep);
}

fn t_always_reported_errors_and_hangups(h: &mut Harness) {
    h.group("epoll-always-hup");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let mut none = event(0, 0xa1);
    check!(h, ctl(ep, libc::EPOLL_CTL_ADD, r, &mut none) == 0,
        "ADD a pipe with events=0");
    sys::close(w);
    let got = wait(ep, 500);
    check!(h, got.raw == 1 && got.events[0].0 == libc::EPOLLHUP as u32,
        "an empty pipe reports exactly unrequested EPOLLHUP: {got:?}");
    sys::close(r);
    sys::close(ep);

    h.group("epoll-hup-filtering");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let mut requested = event((libc::EPOLLIN | libc::EPOLLOUT) as u32, 0xa3);
    check!(h, ctl(ep, libc::EPOLL_CTL_ADD, r, &mut requested) == 0,
        "ADD pipe read end with IN|OUT");
    sys::close(w);
    let got = wait(ep, 500);
    check!(h, got.raw == 1 && got.events[0].0 == libc::EPOLLHUP as u32,
        "an empty read end does not invent requested IN or OUT at EOF: {got:?}");
    sys::close(r);
    sys::close(ep);

    h.group("epoll-always-err");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let mut none = event(0, 0xa2);
    check!(h, ctl(ep, libc::EPOLL_CTL_ADD, w, &mut none) == 0,
        "ADD a pipe write end with events=0");
    sys::close(r);
    let got = wait(ep, 500);
    check!(h, got.raw == 1 && got.events[0].0 == libc::EPOLLERR as u32,
        "a broken pipe reports exactly unrequested EPOLLERR: {got:?}");
    sys::close(w);
    sys::close(ep);

    h.group("epoll-err-filtering");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let mut requested = event(libc::EPOLLOUT as u32, 0xa4);
    check!(h, ctl(ep, libc::EPOLL_CTL_ADD, w, &mut requested) == 0,
        "ADD pipe write end with OUT");
    sys::close(r);
    let got = wait(ep, 500);
    check!(h, got.raw == 1
        && got.events[0].0 == (libc::EPOLLOUT | libc::EPOLLERR) as u32,
        "a broken write end reports requested OUT plus ERR, without HUP: {got:?}");
    sys::close(w);
    sys::close(ep);
}

fn t_writable(h: &mut Harness) {
    h.group("epoll-out");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let mut ev = event(libc::EPOLLOUT as u32, 5);
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, w, &mut ev) == 0,
        "ADD the write end"
    );
    let got = wait(ep, 500);
    check!(
        h,
        got.raw == 1 && got.events[0].0 & libc::EPOLLOUT as u32 != 0,
        "an empty pipe's write end is writable, got {got:?}"
    );
    sys::close(r);
    sys::close(w);
    sys::close(ep);
}

/// EPOLLONESHOT disarms the registration after it fires; it stays in the set
/// and comes back with EPOLL_CTL_MOD.
fn t_oneshot(h: &mut Harness) {
    h.group("epoll-oneshot");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let mut ev = event((libc::EPOLLIN | libc::EPOLLONESHOT) as u32, 9);
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev) == 0,
        "ADD oneshot"
    );
    sys::write(w, b"a");
    let first = wait(ep, 500);
    check!(h, first.raw == 1, "it fires once: {first:?}");
    let disarmed = wait(ep, 50);
    check!(
        h,
        disarmed.raw == 0,
        "and times out with return 0 while disarmed: {disarmed:?}, errno {}",
        sys::errno()
    );
    // Still a member: MOD works rather than answering ENOENT.
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_MOD, r, &mut ev) == 0,
        "MOD re-arms it (so it is still a member)"
    );
    let rearmed = wait(ep, 500);
    check!(h, rearmed.raw == 1, "and it fires again: {rearmed:?}");

    sys::close(r);
    sys::close(w);
    sys::close(ep);
}

/// Edge-triggered reports the transition, not the state.
fn t_edge(h: &mut Harness) {
    h.group("epoll-edge");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let mut ev = event((libc::EPOLLIN | libc::EPOLLET) as u32, 3);
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev) == 0,
        "ADD edge-triggered"
    );
    sys::write(w, b"a");
    let first = wait(ep, 500);
    check!(h, first.raw == 1, "the arrival is an edge: {first:?}");
    let no_second = wait(ep, 50);
    check!(
        h,
        no_second.raw == 0,
        "the same data times out with return 0 rather than becoming a second edge: {no_second:?}, errno {}",
        sys::errno()
    );
    sys::write(w, b"b");
    let second = wait(ep, 500);
    check!(h, second.raw == 1, "more data is another edge: {second:?}");

    sys::close(r);
    sys::close(w);
    sys::close(ep);
}

/// The interest-list key contains both the descriptor number and its open file
/// description. Two dup aliases can therefore carry different registrations,
/// while closing entries follows the lifetime of the shared description.
fn t_dup_registrations(h: &mut Harness) {
    h.group("epoll-dup-registrations");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let alias = unsafe { libc::dup(r) };
    check!(h, alias >= 0, "dup the read end: {alias}");
    if alias < 0 {
        sys::close(r);
        sys::close(w);
        sys::close(ep);
        return;
    }

    let mut original = event(libc::EPOLLIN as u32, 0xa1);
    let mut duplicate = event(libc::EPOLLIN as u32, 0xb1);
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, r, &mut original) == 0,
        "ADD the original number"
    );
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, alias, &mut duplicate) == 0,
        "ADD its dup alias independently"
    );

    duplicate.u64 = 0xb2;
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_MOD, alias, &mut duplicate) == 0,
        "MOD only the alias"
    );
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_DEL, r, &mut original) == 0,
        "DEL only the original number"
    );
    check!(
        h,
        sys::write(w, b"x") == 1,
        "make the shared description ready"
    );
    let got = wait(ep, 500);
    check!(
        h,
        got.raw == 1 && got.events[0].1 == 0xb2,
        "only the modified alias registration remains: {got:?}"
    );
    let mut byte = [0u8; 1];
    check!(
        h,
        sys::read(alias, &mut byte) == 1,
        "drain it through the alias"
    );

    original.u64 = 0xa2;
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, r, &mut original) == 0,
        "ADD the original number again"
    );
    sys::close(r);
    check!(
        h,
        sys::write(w, b"y") == 1,
        "ready it after closing one alias"
    );
    let got = wait(ep, 500);
    let mut data: Vec<_> = got.events.iter().map(|e| e.1).collect();
    data.sort_unstable();
    check!(
        h,
        got.raw == 2 && data == [0xa2, 0xb2],
        "closing one number keeps both registrations while another alias refers to the description: {got:?}"
    );

    // The byte is deliberately left unread. If closing the last descriptor did
    // not remove the registrations, their level-triggered readiness would still
    // make the next wait return them.
    sys::close(alias);
    let removed = wait(ep, 50);
    check!(
        h,
        removed.raw == 0,
        "closing the last alias removes every registration and returns timeout 0: {removed:?}, errno {}",
        sys::errno()
    );

    sys::close(w);
    sys::close(ep);
}

fn ready_pair_with_maxevents_one(h: &mut Harness, flags: u32, data: [u64; 2], kind: &str) {
    let ep = epoll_create1(0);
    let Some((r1, w1)) = pipe() else {
        check!(h, false, "first {kind} pipe");
        return;
    };
    let Some((r2, w2)) = pipe() else {
        check!(h, false, "second {kind} pipe");
        sys::close(r1);
        sys::close(w1);
        sys::close(ep);
        return;
    };
    let mut first = event(libc::EPOLLIN as u32 | flags, data[0]);
    let mut second = event(libc::EPOLLIN as u32 | flags, data[1]);
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, r1, &mut first) == 0,
        "ADD the first {kind} registration"
    );
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, r2, &mut second) == 0,
        "ADD the second {kind} registration"
    );
    check!(
        h,
        sys::write(w1, b"a") == 1,
        "ready the first {kind} registration"
    );
    check!(
        h,
        sys::write(w2, b"b") == 1,
        "ready the second {kind} registration"
    );

    let first_delivery = wait_one(ep, 500);
    let second_delivery = wait_one(ep, 500);
    let mut delivered: Vec<_> = first_delivery
        .events
        .iter()
        .chain(&second_delivery.events)
        .map(|e| e.1)
        .collect();
    delivered.sort_unstable();
    check!(
        h,
        first_delivery.raw == 1 && second_delivery.raw == 1 && delivered == data,
        "maxevents=1 preserves the undelivered {kind} registration for the next call: {first_delivery:?}, {second_delivery:?}"
    );
    let exhausted = wait_one(ep, 50);
    check!(
        h,
        exhausted.raw == 0,
        "both {kind} registrations are consumed or disarmed, and the next call returns timeout 0: {exhausted:?}, errno {}",
        sys::errno()
    );

    sys::close(r1);
    sys::close(w1);
    sys::close(r2);
    sys::close(w2);
    sys::close(ep);
}

/// Filling one epoll_wait result array must not consume readiness that was not
/// returned to the caller. ET and ONESHOT both change state on delivery, so
/// each gets a pair of ready registrations and a one-event output array.
fn t_maxevents_preserves_ready(h: &mut Harness) {
    h.group("epoll-maxevents-edge");
    ready_pair_with_maxevents_one(h, libc::EPOLLET as u32, [0xe1, 0xe2], "edge-triggered");

    h.group("epoll-maxevents-oneshot");
    ready_pair_with_maxevents_one(h, libc::EPOLLONESHOT as u32, [0x101, 0x102], "oneshot");
}

fn install_signal_handler_with_flags(signal: i32, flags: i32) {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = signal_handler as *const () as usize;
        action.sa_flags = flags;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(signal, &action, std::ptr::null_mut());
    }
}

fn install_signal_handler(signal: i32) {
    install_signal_handler_with_flags(signal, 0);
}

fn t_epoll_wait_is_never_sa_restart(h: &mut Harness) {
    h.group("epoll-wait-sa-restart");
    PWATCH_SIGNAL_RAN.store(0, Ordering::SeqCst);
    install_signal_handler_with_flags(libc::SIGUSR1, libc::SA_RESTART);
    let ep = epoll_create1(0);
    check!(h, ep >= 0, "create an empty epoll set");
    if ep >= 0 {
        let target = unsafe { libc::pthread_self() } as usize;
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            unsafe { libc::pthread_kill(target as libc::pthread_t, libc::SIGUSR1) }
        });
        let started = Instant::now();
        let got = wait_one(ep, 1000);
        let elapsed = started.elapsed();
        let send_result = sender.join().unwrap_or(-1);
        let errno = sys::errno();
        check!(h, send_result == 0, "send the caught signal: {send_result}");
        check!(
            h,
            got.raw == -1 && errno == libc::EINTR,
            "SA_RESTART does not restart epoll_wait: {got:?}, errno {errno}, elapsed={elapsed:?}"
        );
        check!(
            h,
            elapsed < Duration::from_millis(700),
            "the signal ends the original wait promptly: {elapsed:?}"
        );
        sys::close(ep);
    }
}

fn rescue_waiter(waiter: usize, done: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(VIRTUAL_WAKE_RESCUE);
        if !done.load(Ordering::SeqCst) {
            unsafe { libc::pthread_kill(waiter as libc::pthread_t, libc::SIGURG) };
        }
    })
}

/// eventfd and timerfd have no host descriptor whose readiness can wake the
/// host queue. Each transition must therefore notify epoll's own ready list.
/// A SIGURG watchdog turns a lost notification into EINTR rather than a hung
/// suite; success must arrive before that rescue and name the virtual member.
fn t_virtual_member_wakeups(h: &mut Harness) {
    install_signal_handler(libc::SIGURG);

    h.group("epoll-delayed-eventfd");
    let ep = epoll_create1(0);
    let efd = eventfd(0, 0);
    check!(h, ep >= 0 && efd >= 0, "create epoll={ep} eventfd={efd}");
    if ep >= 0 && efd >= 0 {
        let mut ev = event(libc::EPOLLIN as u32, 0xe7);
        check!(
            h,
            ctl(ep, libc::EPOLL_CTL_ADD, efd, &mut ev) == 0,
            "ADD eventfd"
        );
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let worker = std::thread::spawn(move || {
            worker_barrier.wait();
            std::thread::sleep(VIRTUAL_WAKE_DELAY);
            let value = 1u64;
            unsafe { libc::write(efd, (&raw const value).cast(), 8) }
        });
        let done = Arc::new(AtomicBool::new(false));
        let watchdog = rescue_waiter(unsafe { libc::pthread_self() } as usize, Arc::clone(&done));
        barrier.wait();
        let started = Instant::now();
        let got = wait_one(ep, -1);
        let elapsed = started.elapsed();
        done.store(true, Ordering::SeqCst);
        let write_result = worker.join().unwrap_or(-1);
        let _ = watchdog.join();
        check!(
            h,
            write_result == 8,
            "the delayed eventfd write succeeds: {write_result}"
        );
        check!(
            h,
            got.raw == 1 && got.events.first().map(|e| e.1) == Some(0xe7),
            "a delayed eventfd wakes epoll before the rescue: {got:?}, errno {}, elapsed={elapsed:?}",
            sys::errno()
        );
        check!(
            h,
            elapsed < VIRTUAL_WAKE_RESCUE,
            "eventfd notification, not the rescue, ended the wait: {elapsed:?}"
        );
    }
    if efd >= 0 {
        sys::close(efd);
    }
    if ep >= 0 {
        sys::close(ep);
    }

    h.group("epoll-delayed-timerfd");
    let ep = epoll_create1(0);
    let tfd = timerfd();
    check!(h, ep >= 0 && tfd >= 0, "create epoll={ep} timerfd={tfd}");
    if ep >= 0 && tfd >= 0 {
        let mut ev = event(libc::EPOLLIN as u32, 0x71);
        check!(
            h,
            ctl(ep, libc::EPOLL_CTL_ADD, tfd, &mut ev) == 0,
            "ADD timerfd as the only member"
        );
        check!(
            h,
            timerfd_arm(tfd, VIRTUAL_WAKE_DELAY) == 0,
            "arm a delayed timerfd: errno {}",
            sys::errno()
        );
        let done = Arc::new(AtomicBool::new(false));
        let watchdog = rescue_waiter(unsafe { libc::pthread_self() } as usize, Arc::clone(&done));
        let started = Instant::now();
        let got = wait_one(ep, -1);
        let elapsed = started.elapsed();
        done.store(true, Ordering::SeqCst);
        let _ = watchdog.join();
        check!(
            h,
            got.raw == 1 && got.events.first().map(|e| e.1) == Some(0x71),
            "a delayed timerfd expiry wakes epoll before the rescue: {got:?}, errno {}, elapsed={elapsed:?}",
            sys::errno()
        );
        check!(
            h,
            elapsed >= VIRTUAL_WAKE_DELAY / 2 && elapsed < VIRTUAL_WAKE_RESCUE,
            "timerfd expiry, not an immediate return or rescue, ended the wait: {elapsed:?}"
        );
    }
    if tfd >= 0 {
        sys::close(tfd);
    }
    if ep >= 0 {
        sys::close(ep);
    }
}

/// poll() must be notified when an epoll member becomes ready after poll has
/// begun. The rescue pipe makes this bounded without comparing against a tight
/// elapsed-time threshold: if the epoll wake is lost, the later rescue wakes
/// poll and is visible in revents.
fn t_poll_epoll_wakeup(h: &mut Harness) {
    h.group("poll-epoll-wakeup");
    let ep = epoll_create1(0);
    let Some((member_r, member_w)) = pipe() else {
        check!(h, false, "member pipe");
        return;
    };
    let Some((rescue_r, rescue_w)) = pipe() else {
        check!(h, false, "rescue pipe");
        sys::close(member_r);
        sys::close(member_w);
        sys::close(ep);
        return;
    };
    let mut ev = event(libc::EPOLLIN as u32, 0xc1);
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, member_r, &mut ev) == 0,
        "ADD the member"
    );

    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = Arc::clone(&barrier);
    let worker = std::thread::spawn(move || {
        worker_barrier.wait();
        std::thread::sleep(EPOLL_POLL_WAKE_DELAY);
        sys::write(member_w, b"m");
        std::thread::sleep(EPOLL_POLL_WAKE_LIMIT - EPOLL_POLL_WAKE_DELAY);
        sys::write(rescue_w, b"r");
    });
    let mut fds = [
        libc::pollfd {
            fd: ep,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: rescue_r,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    barrier.wait();
    let started = Instant::now();
    let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 2000) };
    let elapsed = started.elapsed();
    check!(
        h,
        n == 1 && fds[0].revents & libc::POLLIN != 0 && fds[1].revents == 0,
        "the member wakes poll through the epoll fd before the rescue: n={n}, epoll={:#x}, rescue={:#x}, elapsed={elapsed:?}",
        fds[0].revents,
        fds[1].revents
    );
    let ready = wait_one(ep, 0);
    check!(
        h,
        ready.raw == 1 && ready.events.first().map(|e| e.1) == Some(0xc1),
        "the epoll event itself remains available: {ready:?}"
    );

    worker.join().ok();
    sys::close(member_r);
    sys::close(member_w);
    sys::close(rescue_r);
    sys::close(rescue_w);
    sys::close(ep);
}

/// ADD is one operation under the interest-list lock. Two callers released by
/// the same barrier may race, but they cannot both observe an absent entry.
fn t_concurrent_add(h: &mut Harness) {
    h.group("epoll-concurrent-add");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for data in [0xd1, 0xd2] {
        let worker_barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let mut ev = event(libc::EPOLLIN as u32, data);
            worker_barrier.wait();
            sys::clear_errno();
            let result = ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev);
            let errno = (result < 0).then(sys::errno);
            (result, errno, data)
        }));
    }
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap_or((-2, None, 0)))
        .collect();
    check!(
        h,
        results.iter().filter(|result| result.0 == 0).count() == 1,
        "exactly one concurrent ADD succeeds: {results:?}"
    );
    check!(
        h,
        results
            .iter()
            .filter(|result| result.0 == -1 && result.1 == Some(libc::EEXIST))
            .count()
            == 1,
        "exactly one concurrent ADD gets EEXIST: {results:?}"
    );

    check!(
        h,
        sys::write(w, b"x") == 1,
        "ready the winning registration"
    );
    let winning_data = results
        .iter()
        .find(|result| result.0 == 0)
        .map(|result| result.2);
    let ready = wait_one(ep, 500);
    check!(
        h,
        ready.raw == 1 && ready.events.first().map(|e| e.1) == winning_data,
        "the set contains the successful caller's one registration: {ready:?}"
    );

    sys::close(r);
    sys::close(w);
    sys::close(ep);

    h.group("epoll-concurrent-distinct-members");
    let ep = epoll_create1(0);
    let mut pipes = Vec::new();
    for _ in 0..4 {
        let Some(member) = pipe() else {
            check!(h, false, "create four member pipes");
            for (r, w) in pipes {
                sys::close(r);
                sys::close(w);
            }
            sys::close(ep);
            return;
        };
        pipes.push(member);
    }
    let phases = Arc::new(Barrier::new(pipes.len() + 1));
    let mut workers = Vec::new();
    for (index, &(member_r, _)) in pipes.iter().enumerate() {
        let worker_phases = Arc::clone(&phases);
        workers.push(std::thread::spawn(move || {
            let mut ev = event(libc::EPOLLIN as u32, 0xa0 + index as u64);
            worker_phases.wait();
            let add = ctl(ep, libc::EPOLL_CTL_ADD, member_r, &mut ev);
            worker_phases.wait();

            worker_phases.wait();
            ev.u64 = 0xb0 + index as u64;
            let modify = ctl(ep, libc::EPOLL_CTL_MOD, member_r, &mut ev);
            worker_phases.wait();

            worker_phases.wait();
            let delete = ctl(ep, libc::EPOLL_CTL_DEL, member_r, &mut ev);
            worker_phases.wait();
            (add, modify, delete)
        }));
    }

    phases.wait();
    phases.wait();
    phases.wait();
    phases.wait();
    for &(_, member_w) in &pipes {
        check!(
            h,
            sys::write(member_w, b"x") == 1,
            "ready a concurrently modified member"
        );
    }
    let ready = wait(ep, 500);
    let mut data: Vec<_> = ready.events.iter().map(|event| event.1).collect();
    data.sort_unstable();
    check!(
        h,
        ready.raw == pipes.len() as i32 && data == [0xb0, 0xb1, 0xb2, 0xb3],
        "concurrent MOD changes each distinct member independently: {ready:?}"
    );
    for &(member_r, _) in &pipes {
        let mut byte = [0u8; 1];
        check!(
            h,
            sys::read(member_r, &mut byte) == 1,
            "drain a concurrently modified member"
        );
    }

    phases.wait();
    phases.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap_or((-2, -2, -2)))
        .collect();
    check!(
        h,
        results.iter().all(|result| *result == (0, 0, 0)),
        "ADD, MOD and DEL all succeed on distinct members: {results:?}"
    );
    for &(_, member_w) in &pipes {
        check!(
            h,
            sys::write(member_w, b"y") == 1,
            "ready a concurrently deleted member"
        );
    }
    let deleted = wait(ep, 50);
    check!(
        h,
        deleted.raw == 0,
        "concurrent DEL removes every distinct member and returns timeout 0: {deleted:?}, errno {}",
        sys::errno()
    );

    for (member_r, member_w) in pipes {
        sys::close(member_r);
        sys::close(member_w);
    }
    sys::close(ep);
}

/// Both close orders have independent lifetimes: an epoll set does not own its
/// member, and a member registration does not keep a closed descriptor number
/// occupied. The member-first case reuses the exact number so a stale entry
/// cannot accidentally pass by referring only to the integer fd.
fn t_close_lifetimes(h: &mut Harness) {
    h.group("epoll-close-set-first");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    let mut ev = event(libc::EPOLLIN as u32, 1);
    check!(h, ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev) == 0, "ADD");
    sys::close(ep);
    check!(
        h,
        sys::write(w, b"x") == 1,
        "the member remains writable after closing epoll first"
    );
    let mut byte = [0u8; 1];
    check!(
        h,
        sys::read(r, &mut byte) == 1 && byte[0] == b'x',
        "the member remains readable after closing epoll first"
    );
    sys::close(r);
    sys::close(w);

    h.group("epoll-close-member-first-reuse");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "first pipe");
        sys::close(ep);
        return;
    };
    let reused = r;
    let mut old = event(libc::EPOLLIN as u32, 0xc1);
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, r, &mut old) == 0,
        "ADD the old member"
    );
    sys::close(r);
    sys::close(w);

    let Some((new_r, new_w)) = pipe() else {
        check!(h, false, "replacement pipe");
        sys::close(ep);
        return;
    };
    check!(
        h,
        new_r == reused,
        "the replacement deterministically reuses closed member number {reused}, got {new_r}"
    );
    if new_r != reused {
        sys::close(new_r);
        sys::close(new_w);
        sys::close(ep);
        return;
    }
    let replacement_w = new_w;

    let before_add = wait(ep, 0);
    check!(
        h,
        before_add.raw == 0,
        "fd reuse alone does not revive the old registration: {before_add:?}, errno {}",
        sys::errno()
    );
    let mut fresh = event(libc::EPOLLIN as u32, 0xc2);
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, reused, &mut fresh) == 0,
        "the reused number is a distinct registration"
    );
    check!(
        h,
        sys::write(replacement_w, b"y") == 1,
        "ready the replacement description"
    );
    let got = wait_one(ep, 500);
    check!(
        h,
        got.raw == 1 && got.events.first().map(|e| e.1) == Some(0xc2),
        "only the replacement registration is reported: {got:?}"
    );

    sys::close(reused);
    sys::close(replacement_w);
    sys::close(ep);
}

fn t_poll(h: &mut Harness) {
    h.group("poll");
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };

    // A negative descriptor is skipped and reports zero revents.
    let mut fds = [
        libc::pollfd {
            fd: -1,
            events: libc::POLLIN,
            revents: 0x55,
        },
        libc::pollfd {
            fd: r,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, 0) };
    check!(h, n == 0, "nothing ready, got {n}");
    check!(
        h,
        fds[0].revents == 0,
        "a negative descriptor gets zero revents, got {:#x}",
        fds[0].revents
    );

    // A descriptor that does not exist is POLLNVAL, and counts towards the
    // return value.
    let mut bad = [libc::pollfd {
        fd: 4096,
        events: libc::POLLIN,
        revents: 0,
    }];
    let n = unsafe { libc::poll(bad.as_mut_ptr(), 1, 0) };
    check!(
        h,
        n == 1 && bad[0].revents & libc::POLLNVAL != 0,
        "a bad descriptor is POLLNVAL: n={n} revents={:#x}",
        bad[0].revents
    );

    // And it does not wait: POLLNVAL is an answer, not a state to wait for.
    // A generous timeout rather than -1, so a regression is a failure and not
    // a hang.
    let mut bad2 = [libc::pollfd {
        fd: 4096,
        events: libc::POLLIN,
        revents: 0,
    }];
    let started = std::time::Instant::now();
    let n = unsafe { libc::poll(bad2.as_mut_ptr(), 1, 5000) };
    check!(
        h,
        n == 1 && started.elapsed() < std::time::Duration::from_millis(500),
        "a bad descriptor answers straight away: n={n} after {:?}",
        started.elapsed()
    );
    // Mixed with a live one that is not ready: still immediate.
    let mut mixed = [
        libc::pollfd {
            fd: 4096,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: r,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let started = std::time::Instant::now();
    let n = unsafe { libc::poll(mixed.as_mut_ptr(), 2, 5000) };
    check!(
        h,
        n == 1 && started.elapsed() < std::time::Duration::from_millis(500),
        "one bad among live ones does not wait either: n={n} after {:?}",
        started.elapsed()
    );

    sys::write(w, b"x");
    let mut one = [libc::pollfd {
        fd: r,
        events: libc::POLLIN,
        revents: 0,
    }];
    let n = unsafe { libc::poll(one.as_mut_ptr(), 1, 500) };
    check!(
        h,
        n == 1 && one[0].revents & libc::POLLIN != 0,
        "readable: n={n} revents={:#x}",
        one[0].revents
    );

    // Zero descriptors with a timeout is a sleep, and returns 0.
    let started = std::time::Instant::now();
    let n = unsafe { libc::poll(std::ptr::null_mut(), 0, 60) };
    check!(h, n == 0, "poll of nothing returns 0, got {n}");
    check!(
        h,
        started.elapsed() >= std::time::Duration::from_millis(40),
        "and waits for its timeout: {:?}",
        started.elapsed()
    );

    sys::close(w);
    let mut hup = [libc::pollfd {
        fd: r,
        events: libc::POLLIN,
        revents: 0,
    }];
    let n = unsafe { libc::poll(hup.as_mut_ptr(), 1, 500) };
    check!(
        h,
        n == 1 && hup[0].revents & (libc::POLLHUP | libc::POLLIN) != 0,
        "a hung-up pipe: n={n} revents={:#x}",
        hup[0].revents
    );
    sys::close(r);
}

/// Counts a caller can name that it could not possibly have descriptors for.
///
/// `poll` and `select` sized stack arrays straight from the guest's count.
/// `ppoll(fds, 100000000, ...)` asked for 800 MB of stack and took the
/// emulator down -- every other guest process with it -- and `select` asked
/// for 125 MB three times over. Linux bounds both by the descriptor limit,
/// because a poll naming more descriptors than a process may open is a poll
/// that cannot be answered.
fn t_absurd_counts(h: &mut Harness) {
    h.group("absurd-counts");
    static NOW: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut one = libc::pollfd {
        fd: 0,
        events: libc::POLLIN,
        revents: 0,
    };

    // The count that used to crash it.
    let r = unsafe {
        libc::syscall(
            libc::SYS_ppoll,
            &raw mut one,
            100_000_000usize,
            &raw const NOW,
            std::ptr::null::<libc::sigset_t>(),
            0usize,
        )
    };
    check!(
        h,
        r < 0 && sys::errno() == libc::EINVAL,
        "ppoll with a count past the descriptor limit is EINVAL: {r} errno {}",
        sys::errno()
    );

    // And the emulator is still here to answer an ordinary one.
    let mut pfd = libc::pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    let r = unsafe { libc::poll(&raw mut pfd, 1, 0) };
    check!(h, r >= 0, "an ordinary poll still works afterwards: {r}");

    // select with a negative count. pselect6's last argument is a pointer to
    // {sigset, size}, not a sigset -- passing null there is EFAULT before the
    // count is ever looked at, which is what the first version of this check
    // measured.
    #[repr(C)]
    struct SigmaskArg {
        mask: *const libc::sigset_t,
        size: usize,
    }
    let no_mask = SigmaskArg {
        mask: std::ptr::null(),
        size: 8,
    };
    // A zero timeout, not a null one: null means wait for ever, and with an
    // empty set nothing will ever be ready.
    let now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r = unsafe {
        libc::syscall(
            libc::SYS_pselect6,
            -1i64,
            std::ptr::null_mut::<libc::fd_set>(),
            std::ptr::null_mut::<libc::fd_set>(),
            std::ptr::null_mut::<libc::fd_set>(),
            &raw const now,
            &raw const no_mask,
        )
    };
    check!(
        h,
        r < 0 && sys::errno() == libc::EINVAL,
        "select with a negative count is EINVAL: {r} errno {}",
        sys::errno()
    );

    // A large count is clamped rather than refused, as on Linux -- what
    // matters is that it answers at all.
    let mut set: libc::fd_set = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::syscall(
            libc::SYS_pselect6,
            1_000_000_000i64,
            &raw mut set,
            std::ptr::null_mut::<libc::fd_set>(),
            std::ptr::null_mut::<libc::fd_set>(),
            &raw const now,
            &raw const no_mask,
        )
    };
    check!(
        h,
        r >= 0 || sys::errno() == libc::EFAULT || sys::errno() == libc::EINVAL,
        "select with a huge count answers rather than dying: {r} errno {}",
        sys::errno()
    );
    let r = unsafe { libc::poll(&raw mut pfd, 1, 0) };
    check!(h, r >= 0, "and the emulator is still here: {r}");
}

/// A descriptor that was already readable when it was registered.
///
/// This is the case the whole design rests on for a kernel whose epoll reports
/// from a *ready list* rather than by scanning every member: a registration
/// added after the data arrived has to be reported without anything further
/// happening. Nothing wakes it, nothing transitions -- the state is simply
/// already true.
///
/// It is also the common case. A server accepts a connection, reads the
/// request headers, and registers the socket; the rest of the body is already
/// buffered by then.
fn t_already_ready(h: &mut Harness) {
    h.group("epoll-already-ready");
    let ep = epoll_create1(0);
    let Some((r, w)) = pipe() else {
        check!(h, false, "pipe");
        return;
    };
    // Ready first, registered second.
    sys::write(w, b"already here");
    let mut ev = event(libc::EPOLLIN as u32, 11);
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, r, &mut ev) == 0,
        "ADD after the data arrived"
    );
    let got = wait(ep, 500);
    check!(h, got.raw == 1, "it is reported at once: {got:?}");
    check!(
        h,
        got.events.first().map(|e| e.1) == Some(11),
        "with its own data: {got:?}"
    );
    // And again, because it is level-triggered and nothing has read it.
    let again = wait(ep, 500);
    check!(
        h,
        again.raw == 1,
        "and again while it stays ready: {again:?}"
    );

    // The same for edge-triggered: EPOLL_CTL_ADD of a ready descriptor is
    // itself the edge, so the first wait reports it and the second does not.
    let ep2 = epoll_create1(0);
    let mut ev = event((libc::EPOLLIN | libc::EPOLLET) as u32, 12);
    check!(
        h,
        ctl(ep2, libc::EPOLL_CTL_ADD, r, &mut ev) == 0,
        "ADD edge-triggered, ready"
    );
    let first = wait(ep2, 500);
    check!(h, first.raw == 1, "the registration is the edge: {first:?}");
    let no_second = wait(ep2, 50);
    check!(
        h,
        no_second.raw == 0,
        "and the next wait returns timeout 0: {no_second:?}, errno {}",
        sys::errno()
    );
    sys::close(ep2);

    // A member added to a set that is otherwise all sockets, which is the
    // shape a ready list gets wrong if it keeps the two kinds together: the
    // host queue cannot speak for an eventfd.
    let efd = unsafe { libc::syscall(libc::SYS_eventfd2, 0u32, 0) } as i32;
    check!(h, efd >= 0, "an eventfd: {efd}");
    let mut ev = event(libc::EPOLLIN as u32, 13);
    check!(
        h,
        ctl(ep, libc::EPOLL_CTL_ADD, efd, &mut ev) == 0,
        "ADD the eventfd"
    );
    let v: u64 = 5;
    unsafe { libc::write(efd, (&raw const v).cast(), 8) };
    let got = wait(ep, 500);
    check!(
        h,
        got.raw == 2,
        "both the pipe and the eventfd are reported: {got:?}"
    );
    check!(
        h,
        got.events.iter().any(|e| e.1 == 13),
        "the eventfd among them: {got:?}"
    );
    sys::close(efd);

    sys::close(r);
    sys::close(w);
    sys::close(ep);
}

fn main() {
    let mut h = Harness::new();
    t_absurd_counts(&mut h);
    t_create(&mut h);
    t_ctl_errnos(&mut h);
    t_regular_file_is_refused(&mut h);
    t_wait_arguments(&mut h);
    t_pwait_mask(&mut h);
    t_epoll_wait_is_never_sa_restart(&mut h);
    t_levels(&mut h);
    t_always_reported_errors_and_hangups(&mut h);
    t_writable(&mut h);
    t_oneshot(&mut h);
    t_edge(&mut h);
    t_already_ready(&mut h);
    t_dup_registrations(&mut h);
    t_maxevents_preserves_ready(&mut h);
    t_virtual_member_wakeups(&mut h);
    t_poll_epoll_wakeup(&mut h);
    t_concurrent_add(&mut h);
    t_close_lifetimes(&mut h);
    t_poll(&mut h);
    std::process::exit(h.finish());
}
