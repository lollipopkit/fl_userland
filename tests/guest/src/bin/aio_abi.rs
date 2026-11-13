//! Linux native AIO: `io_setup`, `io_submit`, `io_getevents`,
//! `io_pgetevents`, `io_cancel` and `io_destroy`, held to what a real arm64
//! kernel does (`aio_probe` asked it first).
//!
//! What is easy to get wrong:
//!
//! - **The ring is the ABI.** libaio and fio reap from the `struct aio_ring`
//!   at the context id without a syscall, so its header, its `head`/`tail`
//!   and its events have to be the real ones -- and a poll that completes
//!   while nobody is in a syscall has to land there by itself.
//! - **Refused or completed.** A bad descriptor or opcode fails `io_submit`;
//!   a fault on the buffer or an empty non-blocking pipe is a completion with
//!   a negative `res`. Partial success returns the count before the refusal.
//! - **Lifetime.** `io_destroy` unmaps the ring and wakes waiters with
//!   `EINVAL`; a forked child cannot use its parent's contexts; an exiting
//!   process gives its share of `aio-max-nr` back.
//!
//! Nothing here depends on the CPU count, on a raised `aio-max-nr`, or on the
//! exact bits a driver's wakeup adds to a poll result.

use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use guest_tests::{Harness, check};

const NR_IO_SETUP: i64 = 0;
const NR_IO_DESTROY: i64 = 1;
const NR_IO_SUBMIT: i64 = 2;
const NR_IO_CANCEL: i64 = 3;
const NR_IO_GETEVENTS: i64 = 4;
const NR_IO_PGETEVENTS: i64 = 292;

const PREAD: u16 = 0;
const PWRITE: u16 = 1;
const FSYNC: u16 = 2;
const POLL: u16 = 5;
const NOOP: u16 = 6;
const PREADV: u16 = 7;
const PWRITEV: u16 = 8;
const FLAG_RESFD: u32 = 1;

const EINVAL: i64 = -22;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EAGAIN: i64 = -11;
const EINTR: i64 = -4;
const EINPROGRESS: i64 = -115;

unsafe fn sys(n: i64, a: i64, b: i64, c: i64, d: i64, e: i64, f: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b, in("x2") c, in("x3") d, in("x4") e, in("x5") f,
            options(nostack)
        );
    }
    ret
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Iocb {
    data: u64,
    key: u32,
    rw_flags: i32,
    opcode: u16,
    reqprio: i16,
    fildes: u32,
    buf: u64,
    nbytes: u64,
    offset: i64,
    reserved2: u64,
    flags: u32,
    resfd: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq)]
struct Event {
    data: u64,
    obj: u64,
    res: i64,
    res2: i64,
}

fn setup(nr: u32) -> (i64, u64) {
    let mut ctx = 0u64;
    let r = unsafe { sys(NR_IO_SETUP, nr as i64, &raw mut ctx as i64, 0, 0, 0, 0) };
    (r, ctx)
}

fn destroy(ctx: u64) -> i64 {
    unsafe { sys(NR_IO_DESTROY, ctx as i64, 0, 0, 0, 0, 0) }
}

fn submit(ctx: u64, cbs: &[*const Iocb]) -> i64 {
    unsafe { sys(NR_IO_SUBMIT, ctx as i64, cbs.len() as i64, cbs.as_ptr() as i64, 0, 0, 0) }
}

fn submit1(ctx: u64, cb: &Iocb) -> i64 {
    submit(ctx, &[cb as *const Iocb])
}

fn getevents(ctx: u64, min: i64, ev: &mut [Event], ts: Option<[i64; 2]>) -> i64 {
    let t = ts.as_ref().map_or(0, |t| t.as_ptr() as i64);
    unsafe { sys(NR_IO_GETEVENTS, ctx as i64, min, ev.len() as i64, ev.as_mut_ptr() as i64, t, 0) }
}

fn cancel(ctx: u64, cb: &Iocb) -> i64 {
    unsafe { sys(NR_IO_CANCEL, ctx as i64, cb as *const Iocb as i64, 0, 0, 0, 0) }
}

fn rw(op: u16, fd: i32, buf: u64, n: u64, off: i64, data: u64) -> Iocb {
    Iocb { data, opcode: op, fildes: fd as u32, buf, nbytes: n, offset: off, ..Default::default() }
}

fn poll_cb(fd: i32, events: i16, data: u64) -> Iocb {
    Iocb { data, opcode: POLL, fildes: fd as u32, buf: events as u16 as u64, ..Default::default() }
}

fn ring_word(ctx: u64, i: usize) -> &'static AtomicU32 {
    unsafe { &*(ctx as *const AtomicU32).add(i) }
}

fn pipe() -> [i32; 2] {
    let mut p = [-1i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    p
}

fn read_counter(fd: i32) -> u64 {
    let mut v = 0u64;
    let n = unsafe { libc::read(fd, (&raw mut v).cast(), 8) };
    if n == 8 { v } else { 0 }
}

fn wr(fd: i32, b: &[u8]) -> isize {
    unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) }
}

/// The ring's `/proc/self/maps` line, if a ring is mapped at `addr`. Only a
/// ring's: reading the file allocates, and the allocator may well put its
/// buffer where a ring just was.
fn maps_has(addr: u64) -> Option<String> {
    let want = format!("{addr:08x}-");
    std::fs::read_to_string("/proc/self/maps")
        .ok()?
        .lines()
        .find(|l| l.starts_with(&want) && l.contains("[aio]"))
        .map(str::to_owned)
}

fn max_nr() -> u32 {
    std::fs::read_to_string("/proc/sys/fs/aio-max-nr").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(65536)
}

static SIGNALS: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(_: i32) {
    SIGNALS.fetch_add(1, Ordering::SeqCst);
}

fn handle(sig: i32) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as extern "C" fn(i32) as usize;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn alarm_ms(ms: i64) {
    let it = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: ms / 1000, tv_usec: (ms % 1000) * 1000 },
    };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    let path = format!("{dir}/aio_abi.{}", std::process::id());
    let cpath = std::ffi::CString::new(path.clone()).unwrap();
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o600) };
    let mut h = Harness::new();
    check!(h, fd >= 0, "open the scratch file: {fd}");

    setup_cases(&mut h);
    transfer_cases(&mut h, fd);
    resfd_cases(&mut h, fd);
    wait_cases(&mut h, fd);
    signal_cases(&mut h);
    poll_cases(&mut h, fd);
    cancel_cases(&mut h, fd);
    destroy_cases(&mut h, fd);
    lifetime_cases(&mut h, fd);
    stress(&mut h, fd);

    unsafe { libc::close(fd) };
    let _ = std::fs::remove_file(&path);
    std::process::exit(h.finish());
}

fn setup_cases(h: &mut Harness) {
    h.group("io_setup");
    let (r, ctx) = setup(8);
    check!(h, r == 0 && ctx != 0 && ctx % 4096 == 0, "io_setup(8): {r}, ctx {ctx:#x}");
    let w = |i| ring_word(ctx, i).load(Ordering::SeqCst);
    check!(h, w(0) == 0, "the first context's ring id is 0: {}", w(0));
    check!(h, w(1) >= 16, "ring.nr holds at least twice what was asked: {}", w(1));
    check!(h, (w(2), w(3)) == (0, 0), "head and tail start at 0: {} {}", w(2), w(3));
    check!(h, w(4) == 0xa10a10a1, "ring.magic: {:#x}", w(4));
    check!(h, (w(5), w(6), w(7)) == (1, 0, 32), "features and header length: {} {} {}", w(5), w(6), w(7));
    let line = maps_has(ctx).unwrap_or_default();
    check!(h, line.contains(" rw-s ") && line.ends_with("/[aio] (deleted)"), "the ring's maps line: {line:?}");
    let (r2, c2) = setup(1);
    check!(h, r2 == 0 && ring_word(c2, 0).load(Ordering::SeqCst) == 1, "a second context gets id 1");
    check!(h, destroy(c2) == 0, "and destroys");
    check!(h, destroy(ctx) == 0, "io_destroy(8)");

    let mut nz = 1u64;
    let r = unsafe { sys(NR_IO_SETUP, 1, &raw mut nz as i64, 0, 0, 0, 0) };
    check!(h, r == EINVAL && nz == 1, "*ctxp != 0 is EINVAL and leaves it: {r}");
    check!(h, setup(0).0 == EINVAL, "nr_events 0 is EINVAL");
    check!(h, unsafe { sys(NR_IO_SETUP, 1, 0, 0, 0, 0, 0) } == EFAULT, "ctxp NULL is EFAULT");
    check!(h, setup(max_nr() + 1).0 == EAGAIN, "above aio-max-nr is EAGAIN");
    check!(h, setup(0x8000_0000).0 == EAGAIN, "0x80000000 doubles to 0: EAGAIN");
    check!(h, setup(0xffff_ffff).0 == EINVAL, "0xffffffff trips the overflow guard: EINVAL");
    let before: i64 = std::fs::read_to_string("/proc/sys/fs/aio-nr").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(-1);
    let (_, c) = setup(100);
    let after: i64 = std::fs::read_to_string("/proc/sys/fs/aio-nr").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(-1);
    check!(h, before >= 0 && after - before == 100, "aio-nr counts what was asked: {before} -> {after}");
    destroy(c);
}

fn transfer_cases(h: &mut Harness, fd: i32) {
    h.group("transfers");
    let (_, ctx) = setup(64);
    let mut cb = rw(PWRITE, fd, b"hello aio!".as_ptr() as u64, 10, 0, 0xabc);
    cb.key = 0x5555;
    check!(h, submit1(ctx, &cb) == 1, "PWRITE is accepted");
    check!(h, cb.key == 0, "and its aio_key is set to KIOCB_KEY: {:#x}", cb.key);
    let tail = ring_word(ctx, 3).load(Ordering::SeqCst);
    check!(h, tail == 1, "the event is in the ring before io_getevents: tail {tail}");
    let mut ev = [Event::default(); 4];
    let n = getevents(ctx, 1, &mut ev, Some([1, 0]));
    check!(h, n == 1, "one event: {n}");
    check!(h, ev[0] == Event { data: 0xabc, obj: &raw const cb as u64, res: 10, res2: 0 }, "PWRITE's event: {:?}", ev[0]);
    check!(h, ring_word(ctx, 2).load(Ordering::SeqCst) == 1, "head moved past it");

    let mut buf = [0u8; 16];
    let cb = rw(PREAD, fd, buf.as_mut_ptr() as u64, 16, 6, 1);
    submit1(ctx, &cb);
    let n = getevents(ctx, 1, &mut ev, Some([1, 0]));
    check!(h, n == 1 && ev[0].res == 4 && &buf[..4] == b"aio!", "PREAD of a short tail: {} {:?}", ev[0].res, &buf[..4]);

    let (a, b) = (b"12", b"345");
    let iov = [libc::iovec { iov_base: a.as_ptr() as *mut _, iov_len: 2 }, libc::iovec { iov_base: b.as_ptr() as *mut _, iov_len: 3 }];
    submit1(ctx, &rw(PWRITEV, fd, iov.as_ptr() as u64, 2, 100, 2));
    let (mut x, mut y) = ([0u8; 1], [0u8; 4]);
    let iov = [libc::iovec { iov_base: x.as_mut_ptr().cast(), iov_len: 1 }, libc::iovec { iov_base: y.as_mut_ptr().cast(), iov_len: 4 }];
    submit1(ctx, &rw(PREADV, fd, iov.as_ptr() as u64, 2, 100, 3));
    let n = getevents(ctx, 2, &mut ev, Some([1, 0]));
    check!(h, n == 2 && ev[0].res == 5 && ev[1].res == 5, "PWRITEV then PREADV: {n} {} {}", ev[0].res, ev[1].res);
    check!(h, &x == b"1" && &y == b"2345", "the vectors scattered: {x:?} {y:?}");

    check!(h, submit1(ctx, &rw(FSYNC, fd, 0, 0, 0, 4)) == 1, "FSYNC is accepted");
    let n = getevents(ctx, 1, &mut ev, Some([1, 0]));
    check!(h, n == 1 && ev[0].res == 0 && ev[0].data == 4, "and completes with 0: {:?}", ev[0]);
    check!(h, submit1(ctx, &rw(FSYNC, fd, 0, 1, 0, 0)) == EINVAL, "FSYNC with nbytes is EINVAL");
    let p = pipe();
    check!(h, submit1(ctx, &rw(FSYNC, p[1], 0, 0, 0, 0)) == EINVAL, "FSYNC on a pipe is EINVAL");

    check!(h, submit1(ctx, &rw(NOOP, fd, 0, 0, 0, 0)) == EINVAL, "IOCB_CMD_NOOP is EINVAL");
    check!(h, submit1(ctx, &rw(9, fd, 0, 0, 0, 0)) == EINVAL, "an unknown opcode is EINVAL");
    check!(h, submit1(ctx, &rw(9, -1, 0, 0, 0, 0)) == EBADF, "an unknown opcode on a bad fd is EBADF");
    check!(h, submit1(ctx, &Iocb { reserved2: 1, ..rw(PREAD, fd, buf.as_mut_ptr() as u64, 1, 0, 0) }) == EINVAL, "aio_reserved2 is EINVAL");
    check!(h, submit1(ctx, &rw(PREAD, fd, buf.as_mut_ptr() as u64, 1, -1, 0)) == EINVAL, "a negative offset is EINVAL");
    check!(h, submit1(ctx, &rw(PREAD, 9999, buf.as_mut_ptr() as u64, 1, 0, 0)) == EBADF, "a bad fd is EBADF");
    check!(h, submit1(ctx, &rw(PWRITE, p[0], buf.as_ptr() as u64, 1, 0, 0)) == EBADF, "writing a read end is EBADF");
    check!(h, unsafe { sys(NR_IO_SUBMIT, ctx as i64, -1, 0, 0, 0, 0) } == EINVAL, "nr -1 is EINVAL");
    check!(h, submit(0x10000, &[&rw(PREAD, fd, 0, 0, 0, 0)]) == EINVAL, "an unmapped ctx is EINVAL");
    let plain = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) } as u64;
    check!(h, submit(plain, &[&rw(PREAD, fd, 0, 0, 0, 0)]) == EINVAL, "a page holding id 0 that is not a ring is EINVAL");

    let cb = rw(PREAD, fd, 0x1000, 4, 0, 5);
    check!(h, submit1(ctx, &cb) == 1, "a read into an unmapped page is accepted");
    let n = getevents(ctx, 1, &mut ev, Some([1, 0]));
    check!(h, n == 1 && ev[0].res == EFAULT, "and completes with EFAULT: {:?}", ev[0]);
    unsafe { libc::fcntl(p[0], libc::F_SETFL, libc::O_NONBLOCK) };
    submit1(ctx, &rw(PREAD, p[0], buf.as_mut_ptr() as u64, 4, 0, 6));
    let n = getevents(ctx, 1, &mut ev, Some([1, 0]));
    check!(h, n == 1 && ev[0].res == EAGAIN, "an empty O_NONBLOCK pipe completes with EAGAIN: {:?}", ev[0]);
    wr(p[1], b"pipe");
    submit1(ctx, &rw(PREAD, p[0], buf.as_mut_ptr() as u64, 8, 12345, 7));
    let n = getevents(ctx, 1, &mut ev, Some([1, 0]));
    check!(h, n == 1 && ev[0].res == 4 && &buf[..4] == b"pipe", "a pipe ignores the offset: {:?}", ev[0]);

    h.group("partial submission");
    let good = rw(PWRITE, fd, b"g".as_ptr() as u64, 1, 200, 8);
    let bad = rw(PWRITE, -1, b"g".as_ptr() as u64, 1, 200, 9);
    check!(h, submit(ctx, &[&good, &bad, &good]) == 1, "good, bad, good answers 1");
    check!(h, submit(ctx, &[&bad, &good]) == EBADF, "a refusal first is the errno");
    check!(h, submit(ctx, &[&good, std::ptr::null()]) == 1, "good, NULL answers 1");
    let n = getevents(ctx, 0, &mut ev, Some([0, 0]));
    check!(h, n == 2, "exactly the accepted ones completed: {n}");
    unsafe {
        libc::close(p[0]);
        libc::close(p[1]);
    }
    destroy(ctx);

    h.group("ring capacity");
    let (_, ctx) = setup(1);
    let nr = ring_word(ctx, 1).load(Ordering::SeqCst) as usize;
    let mut accepted = 0;
    let last = loop {
        let r = submit1(ctx, &good);
        if r != 1 || accepted > nr {
            break r;
        }
        accepted += 1;
    };
    check!(h, last == EAGAIN && accepted >= 1 && accepted < nr, "unreaped events fill the ring: {accepted} of {nr}, then {last}");
    let mut evs = vec![Event::default(); nr];
    check!(h, getevents(ctx, 0, &mut evs, Some([0, 0])) == accepted as i64, "all of them reap");
    check!(h, submit1(ctx, &good) == 1, "and there is room again");
    destroy(ctx);
}

fn resfd_cases(h: &mut Harness, fd: i32) {
    h.group("IOCB_FLAG_RESFD");
    let (_, ctx) = setup(16);
    let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
    let cb = Iocb { flags: FLAG_RESFD, resfd: efd as u32, ..rw(PWRITE, fd, b"r".as_ptr() as u64, 1, 300, 1) };
    check!(h, submit(ctx, &[&cb, &cb, &cb]) == 3, "three with RESFD");
    check!(h, read_counter(efd) == 3, "the eventfd counts one per completion");
    let p = pipe();
    check!(h, submit1(ctx, &Iocb { resfd: p[0] as u32, ..cb }) == EINVAL, "RESFD that is not an eventfd is EINVAL");
    check!(h, submit1(ctx, &Iocb { resfd: u32::MAX, ..cb }) == EBADF, "RESFD -1 is EBADF");
    check!(h, read_counter(efd) == 0, "and the refusals signalled nothing");
    unsafe {
        libc::close(p[0]);
        libc::close(p[1]);
        libc::close(efd);
    }
    destroy(ctx);
}

fn wait_cases(h: &mut Harness, fd: i32) {
    h.group("io_getevents");
    let (_, ctx) = setup(16);
    let mut ev = [Event::default(); 4];
    check!(h, getevents(ctx, 2, &mut ev[..1], Some([0, 0])) == EINVAL, "min_nr > nr is EINVAL");
    check!(h, getevents(ctx, -1, &mut ev, Some([0, 0])) == EINVAL, "min_nr < 0 is EINVAL");
    check!(h, getevents(ctx, 1, &mut ev, Some([0, 0])) == 0, "nothing ready, zero timeout: 0");
    let t = Instant::now();
    check!(h, getevents(ctx, 1, &mut ev, Some([0, 40_000_000])) == 0, "nothing ready in 40ms: 0");
    check!(h, t.elapsed() >= Duration::from_millis(40), "and it waited: {:?}", t.elapsed());
    let r = unsafe { sys(NR_IO_GETEVENTS, ctx as i64, 0, 1, ev.as_mut_ptr() as i64, 0x10, 0) };
    check!(h, r == EFAULT, "an unreadable timeout is EFAULT: {r}");

    let w = rw(PWRITE, fd, b"w".as_ptr() as u64, 1, 400, 1);
    submit1(ctx, &w);
    let t = Instant::now();
    let n = getevents(ctx, 2, &mut ev, Some([0, 40_000_000]));
    check!(h, n == 1 && t.elapsed() >= Duration::from_millis(40), "min_nr 2 with one ready: 1 after the timeout ({n})");
    submit1(ctx, &w);
    let c = ctx;
    let late = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(40));
        submit1(c, &w)
    });
    let t = Instant::now();
    let n = getevents(ctx, 2, &mut ev, None);
    late.join().unwrap();
    check!(h, n == 2 && t.elapsed() >= Duration::from_millis(30), "min_nr 2 waits for the second: {n}");

    submit(ctx, &[&w, &w, &w]);
    let r = unsafe { sys(NR_IO_GETEVENTS, ctx as i64, 1, 3, 0x10, [0i64, 0].as_ptr() as i64, 0) };
    check!(h, r == EFAULT, "an unwritable events array is EFAULT: {r}");
    check!(h, getevents(ctx, 0, &mut ev[..2], Some([0, 0])) == 2, "and consumed nothing: 2 of 3");
    check!(h, getevents(ctx, 0, &mut ev, Some([0, 0])) == 1, "then the last one");

    h.group("reaping from the ring");
    submit(ctx, &[&w, &w]);
    let tail = ring_word(ctx, 3).load(Ordering::SeqCst);
    ring_word(ctx, 2).store(tail, Ordering::SeqCst);
    check!(h, getevents(ctx, 0, &mut ev, Some([0, 0])) == 0, "the guest moved head itself: nothing left");
    destroy(ctx);
}

fn signal_cases(h: &mut Harness) {
    h.group("signals");
    let (_, ctx) = setup(4);
    let mut ev = [Event::default(); 1];
    handle(libc::SIGALRM);
    SIGNALS.store(0, Ordering::SeqCst);
    alarm_ms(40);
    let t = Instant::now();
    let r = getevents(ctx, 1, &mut ev, None);
    check!(h, r == EINTR && SIGNALS.load(Ordering::SeqCst) == 1, "a handled signal ends an indefinite wait: {r}");
    check!(h, t.elapsed() < Duration::from_secs(5), "promptly");
    alarm_ms(40);
    let r = getevents(ctx, 1, &mut ev, Some([-1, 0]));
    check!(h, r == EINTR, "a negative tv_sec is no timeout: only the signal ends it ({r})");

    h.group("io_pgetevents");
    let pg = |ts: &[i64; 2], usig: i64, ev: &mut [Event; 1]| unsafe {
        sys(NR_IO_PGETEVENTS, ctx as i64, 1, 1, ev.as_mut_ptr() as i64, ts.as_ptr() as i64, usig)
    };
    let mut mask: u64 = 1 << (libc::SIGALRM - 1);
    let usig = [&raw mut mask as i64, 8];
    SIGNALS.store(0, Ordering::SeqCst);
    alarm_ms(30);
    let t = Instant::now();
    let r = pg(&[0, 120_000_000], usig.as_ptr() as i64, &mut ev);
    check!(h, r == 0 && t.elapsed() >= Duration::from_millis(120), "the temporary mask holds SIGALRM off: {r}");
    check!(h, SIGNALS.load(Ordering::SeqCst) == 1, "and it is delivered once the mask is restored");
    let bad = [&raw mut mask as i64, 4];
    check!(h, pg(&[0, 0], bad.as_ptr() as i64, &mut ev) == EINVAL, "sigsetsize 4 is EINVAL");
    check!(h, pg(&[0, 0], 0x10, &mut ev) == EFAULT, "an unreadable __aio_sigset is EFAULT");
    let none = [0i64, 4];
    check!(h, pg(&[0, 0], none.as_ptr() as i64, &mut ev) == 0, "a NULL mask ignores the size");
    destroy(ctx);
}

fn poll_cases(h: &mut Harness, fd: i32) {
    h.group("IOCB_CMD_POLL");
    let (_, ctx) = setup(16);
    let mut ev = [Event::default(); 4];
    let p = pipe();
    let cb = poll_cb(p[0], libc::POLLIN, 0x50);
    check!(h, submit1(ctx, &cb) == 1, "POLLIN on an empty pipe is accepted");
    check!(h, getevents(ctx, 0, &mut ev, Some([0, 0])) == 0, "and is pending");
    let w = p[1];
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        wr(w, b"x");
    });
    let n = getevents(ctx, 1, &mut ev, Some([2, 0]));
    t.join().unwrap();
    check!(h, n == 1 && ev[0].obj == &raw const cb as u64 && ev[0].data == 0x50, "a write completes it: {n} {:?}", ev[0]);
    check!(h, ev[0].res & libc::POLLIN as i64 != 0 && ev[0].res & libc::POLLOUT as i64 == 0, "with POLLIN: {:#x}", ev[0].res);
    wr(p[1], b"y");
    check!(h, getevents(ctx, 0, &mut ev, Some([0, 0])) == 0, "it is one-shot");
    let mut b = [0u8; 8];
    unsafe { libc::read(p[0], b.as_mut_ptr().cast(), 8) };

    // With nobody in a syscall: the ring moves and the eventfd counts.
    let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
    let cb = Iocb { flags: FLAG_RESFD, resfd: efd as u32, ..poll_cb(p[0], libc::POLLIN, 0x51) };
    submit1(ctx, &cb);
    let tail0 = ring_word(ctx, 3).load(Ordering::SeqCst);
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        wr(w, b"z");
    });
    let start = Instant::now();
    while ring_word(ctx, 3).load(Ordering::SeqCst) == tail0 && start.elapsed() < Duration::from_secs(3) {
        std::thread::yield_now();
    }
    t.join().unwrap();
    check!(h, ring_word(ctx, 3).load(Ordering::SeqCst) != tail0, "the ring's tail moves without a syscall");
    let start = Instant::now();
    let mut count = 0;
    while count == 0 && start.elapsed() < Duration::from_secs(3) {
        count = read_counter(efd);
    }
    check!(h, count == 1, "and the RESFD eventfd counts it: {count}");
    check!(h, getevents(ctx, 0, &mut ev, Some([0, 0])) == 1 && ev[0].data == 0x51, "the event is there");
    unsafe { libc::read(p[0], b.as_mut_ptr().cast(), 8) };
    unsafe { libc::close(efd) };

    check!(h, submit1(ctx, &poll_cb(fd, libc::POLLIN | libc::POLLOUT, 1)) == 1, "a regular file");
    let n = getevents(ctx, 0, &mut ev, Some([0, 0]));
    check!(h, n == 1 && ev[0].res == (libc::POLLIN | libc::POLLOUT) as i64, "is ready at once with POLLIN|POLLOUT: {:#x}", ev[0].res);
    check!(h, submit1(ctx, &poll_cb(p[0], 0, 2)) == 1, "events 0 on an empty pipe");
    unsafe { libc::close(p[1]) };
    let n = getevents(ctx, 1, &mut ev, Some([2, 0]));
    check!(h, n == 1 && ev[0].res == libc::POLLHUP as i64, "the writer closing completes it with POLLHUP: {:#x}", ev[0].res);

    let mut s = [-1i32; 2];
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, s.as_mut_ptr()) };
    check!(h, submit1(ctx, &poll_cb(s[0], libc::POLLIN, 3)) == 1, "POLLIN on a socket");
    let peer = s[1];
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        wr(peer, b"s");
    });
    let n = getevents(ctx, 1, &mut ev, Some([2, 0]));
    t.join().unwrap();
    check!(h, n == 1 && ev[0].res & libc::POLLIN as i64 != 0, "completes when the peer writes: {n} {:#x}", ev[0].res);
    unsafe {
        libc::close(s[0]);
        libc::close(s[1]);
        libc::close(p[0]);
    }
    let p = pipe();
    check!(h, submit1(ctx, &Iocb { buf: 0x10000, ..poll_cb(p[0], 0, 0) }) == EINVAL, "events above 16 bits are EINVAL");
    check!(h, submit1(ctx, &Iocb { nbytes: 1, ..poll_cb(p[0], 1, 0) }) == EINVAL, "nbytes is EINVAL");
    reap_all(ctx);
    unsafe {
        libc::close(p[0]);
        libc::close(p[1]);
    }
    destroy(ctx);
}

fn reap_all(ctx: u64) {
    let mut ev = [Event::default(); 64];
    getevents(ctx, 0, &mut ev, Some([0, 0]));
}

fn cancel_cases(h: &mut Harness, fd: i32) {
    h.group("io_cancel");
    let (_, ctx) = setup(16);
    let mut ev = [Event::default(); 4];
    let p = pipe();
    let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
    let cb = Iocb { flags: FLAG_RESFD, resfd: efd as u32, ..poll_cb(p[0], libc::POLLIN, 0x70) };
    submit1(ctx, &cb);
    check!(h, cancel(ctx, &cb) == EINPROGRESS, "a pending poll is EINPROGRESS");
    let n = getevents(ctx, 1, &mut ev, Some([1, 0]));
    check!(h, n == 1 && ev[0] == Event { data: 0x70, obj: &raw const cb as u64, res: 0, res2: 0 }, "its event arrives with res 0: {:?}", ev[0]);
    check!(h, read_counter(efd) == 1, "and signals its RESFD");
    check!(h, cancel(ctx, &cb) == EINVAL, "cancelling it again is EINVAL");
    let copy = poll_cb(p[0], libc::POLLIN, 0);
    submit1(ctx, &copy);
    let twin = copy;
    check!(h, cancel(ctx, &twin) == EINVAL, "an identical iocb elsewhere is not it");
    check!(h, cancel(ctx, &copy) == EINPROGRESS, "the iocb itself is");
    reap_all(ctx);
    let w = rw(PWRITE, fd, b"c".as_ptr() as u64, 1, 500, 0);
    submit1(ctx, &w);
    check!(h, cancel(ctx, &w) == EINVAL, "a completed write is EINVAL");
    let keyed = Iocb { key: 1, ..w };
    check!(h, cancel(ctx, &keyed) == EINVAL, "a key that is not KIOCB_KEY is EINVAL");
    check!(h, unsafe { sys(NR_IO_CANCEL, 0, 0, 0, 0, 0, 0) } == EFAULT, "a NULL iocb is EFAULT before the context is looked at");
    reap_all(ctx);
    unsafe {
        libc::close(p[0]);
        libc::close(p[1]);
        libc::close(efd);
    }
    destroy(ctx);
}

fn destroy_cases(h: &mut Harness, fd: i32) {
    h.group("io_destroy");
    let (_, ctx) = setup(4);
    let w = rw(PWRITE, fd, b"d".as_ptr() as u64, 1, 600, 0);
    submit1(ctx, &w);
    let p = pipe();
    submit1(ctx, &poll_cb(p[0], libc::POLLIN, 0));
    check!(h, destroy(ctx) == 0, "with an unreaped event and a pending poll: 0");
    check!(h, maps_has(ctx).is_none(), "the ring is unmapped");
    check!(h, destroy(ctx) == EINVAL, "a second io_destroy is EINVAL");
    check!(h, submit1(ctx, &w) == EINVAL, "io_submit after it is EINVAL");
    unsafe {
        libc::close(p[0]);
        libc::close(p[1]);
    }

    let (_, ctx) = setup(4);
    let c = ctx;
    let waiter = std::thread::spawn(move || {
        let mut ev = [Event::default(); 1];
        let t = Instant::now();
        (getevents(c, 1, &mut ev, Some([5, 0])), t.elapsed())
    });
    std::thread::sleep(Duration::from_millis(50));
    check!(h, destroy(ctx) == 0, "io_destroy with a waiter");
    let (r, took) = waiter.join().unwrap();
    check!(h, r == EINVAL && took < Duration::from_secs(4), "the waiter is answered EINVAL at once: {r} after {took:?}");

    let (_, ctx) = setup(4);
    unsafe { libc::munmap(ctx as *mut _, 4096) };
    check!(h, submit1(ctx, &w) == EINVAL, "an unmapped ring's context cannot be found");
    let (_, ctx) = setup(4);
    let id = ring_word(ctx, 0).load(Ordering::SeqCst);
    ring_word(ctx, 0).store(id + 77, Ordering::SeqCst);
    check!(h, submit1(ctx, &w) == EINVAL, "nor one whose id was scribbled on");
    ring_word(ctx, 0).store(id, Ordering::SeqCst);
    check!(h, submit1(ctx, &w) == 1, "until it is put back");
    let to = ctx + 0x200000;
    let moved = unsafe { libc::mremap(ctx as *mut _, 4096, 4096, libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED, to as *mut libc::c_void) } as u64;
    check!(h, moved == to, "mremap moves the ring");
    check!(h, submit1(ctx, &w) == EINVAL && submit1(to, &w) == 1, "and the context moves with it");
    check!(h, destroy(to) == 0 && maps_has(to).is_none(), "io_destroy at the new address unmaps it");
}

fn lifetime_cases(h: &mut Harness, fd: i32) {
    h.group("threads, fork and exit");
    let (_, ctx) = setup(8);
    let w = rw(PWRITE, fd, b"t".as_ptr() as u64, 1, 700, 0);
    let c = ctx;
    check!(h, std::thread::spawn(move || submit1(c, &w)).join().unwrap() == 1, "a thread shares the context");
    let mut ev = [Event::default(); 1];
    check!(h, getevents(ctx, 1, &mut ev, Some([1, 0])) == 1, "and another reaps it");
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let ok = submit1(ctx, &w) == EINVAL && destroy(ctx) == EINVAL && maps_has(ctx).is_none();
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    check!(h, libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "a forked child has no ring and no context: {status:#x}");
    check!(h, submit1(ctx, &w) == 1, "the parent's still works");
    destroy(ctx);

    let half = max_nr() / 2 + 1;
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, _) = setup(half);
        unsafe { libc::_exit(if r == 0 { 0 } else { 1 }) };
    }
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let (r, c) = setup(half);
    check!(h, r == 0, "a child's context is released when it exits: {r}");
    if r == 0 {
        destroy(c);
    }
}

/// Several threads submitting and several reaping one context, every event
/// accounted for exactly once; and polls completed by writer threads.
fn stress(h: &mut Harness, fd: i32) {
    h.group("stress");
    const THREADS: u64 = 4;
    const EACH: u64 = 1500;
    let (_, ctx) = setup(256);
    let seen = Arc::new((0..THREADS * EACH).map(|_| AtomicU64::new(0)).collect::<Vec<_>>());
    let reaped = Arc::new(AtomicU64::new(0));
    let bad = Arc::new(AtomicU64::new(0));
    let mut reapers = Vec::new();
    for _ in 0..2 {
        let (seen, reaped, bad) = (Arc::clone(&seen), Arc::clone(&reaped), Arc::clone(&bad));
        reapers.push(std::thread::spawn(move || {
            let mut ev = [Event::default(); 32];
            while reaped.load(Ordering::SeqCst) < THREADS * EACH {
                let n = getevents(ctx, 1, &mut ev, Some([0, 50_000_000]));
                if n < 0 {
                    bad.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                for e in &ev[..n as usize] {
                    if e.res != 1 || e.data >= THREADS * EACH {
                        bad.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                    seen[e.data as usize].fetch_add(1, Ordering::SeqCst);
                }
                reaped.fetch_add(n as u64, Ordering::SeqCst);
            }
        }));
    }
    let mut submitters = Vec::new();
    for t in 0..THREADS {
        let bad = Arc::clone(&bad);
        submitters.push(std::thread::spawn(move || {
            let byte = [b'0' + t as u8];
            let mut i = 0;
            while i < EACH {
                let id = t * EACH + i;
                let cb = rw(PWRITE, fd, byte.as_ptr() as u64, 1, (1000 + id) as i64, id);
                match submit1(ctx, &cb) {
                    1 => i += 1,
                    EAGAIN => std::thread::yield_now(),
                    _ => {
                        bad.fetch_add(1, Ordering::SeqCst);
                        return;
                    }
                }
            }
        }));
    }
    for s in submitters {
        s.join().unwrap();
    }
    for r in reapers {
        r.join().unwrap();
    }
    let once = seen.iter().all(|s| s.load(Ordering::SeqCst) == 1);
    check!(h, bad.load(Ordering::SeqCst) == 0, "no bad submission or event: {}", bad.load(Ordering::SeqCst));
    check!(h, once && reaped.load(Ordering::SeqCst) == THREADS * EACH, "every event reaped exactly once: {}", reaped.load(Ordering::SeqCst));
    destroy(ctx);

    // Polls on many pipes, completed by writers on other threads.
    let (_, ctx) = setup(64);
    const PIPES: usize = 16;
    let pipes: Vec<[i32; 2]> = (0..PIPES).map(|_| pipe()).collect();
    let mut done = 0usize;
    let rounds = 20;
    let mut ok = true;
    for _ in 0..rounds {
        let cbs: Vec<Iocb> = pipes.iter().enumerate().map(|(i, p)| poll_cb(p[0], libc::POLLIN, i as u64)).collect();
        let ptrs: Vec<*const Iocb> = cbs.iter().map(|c| c as *const Iocb).collect();
        ok &= submit(ctx, &ptrs) == PIPES as i64;
        let writers: Vec<_> = pipes.iter().map(|p| {
            let w = p[1];
            std::thread::spawn(move || {
                wr(w, b"!");
            })
        }).collect();
        let mut got = 0;
        let mut ev = [Event::default(); PIPES];
        let start = Instant::now();
        while got < PIPES && start.elapsed() < Duration::from_secs(5) {
            let n = getevents(ctx, 1, &mut ev[got..], Some([1, 0]));
            if n < 0 {
                ok = false;
                break;
            }
            got += n as usize;
        }
        for w in writers {
            w.join().unwrap();
        }
        done += got;
        let mut b = [0u8; 4];
        for p in &pipes {
            unsafe { libc::read(p[0], b.as_mut_ptr().cast(), 4) };
        }
    }
    check!(h, ok && done == PIPES * rounds, "polls completed by other threads: {done} of {}", PIPES * rounds);
    for p in pipes {
        unsafe {
            libc::close(p[0]);
            libc::close(p[1]);
        }
    }
    destroy(ctx);
}
