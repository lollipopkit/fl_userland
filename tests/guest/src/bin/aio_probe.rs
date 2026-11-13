//! What Linux native AIO (`io_setup`, `io_submit`, `io_getevents`,
//! `io_pgetevents`, `io_cancel`, `io_destroy`) does with its arguments.
//!
//! One line per case, nothing asserted: `probe_diff.sh` compares the lines
//! against a real kernel. Nothing here waits without a timeout except the
//! cases a timer or a second thread ends after a few milliseconds.
//!
//! # What is printed raw and what is not
//!
//! The ring's `nr` depends on the CPU count (`ioctx_alloc` doubles
//! `max(nr_events, 4 * num_possible_cpus())`), and `/proc/sys/fs/aio-max-nr`
//! is a sysctl a host may have raised: both are printed as a comparison with
//! the formula or used to size the case, never as the number. The one raw `nr`
//! (`io_setup(1000)`) is above the CPU term on any machine with fewer than 250
//! processors.
//!
//! With `--after-exec` it is the image `execve` started, and answers whether
//! the contexts the previous image made were released.
//!
//! # Where this kernel answers differently, and why
//!
//! - `RWF_NOWAIT read`: the container's overlayfs has no `FMODE_NOWAIT`, so
//!   Linux refuses with `EOPNOTSUPP`; that is the mount's answer, the same
//!   one `io_probe`'s `preadv2(RWF_NOWAIT)` line records.
//! - `IOCB_FLAG_IOPRIO realtime`: `CAP_SYS_NICE`, which the container's root
//!   lacks and this kernel's root has.
//! - `res, after a ... write woke it`: Linux completes a poll from the
//!   driver's wakeup and reports the wakeup's key unfiltered (a pipe write's
//!   `POLLIN|POLLRDNORM`, a socket's `POLLIN|POLLPRI|POLLRDNORM|POLLRDBAND`).
//!   This kernel's drivers do not notify with Linux's keys, so the result is
//!   the descriptor's readiness masked by what was asked -- what Linux answers
//!   at submission and for a wakeup without a key. See `crates/kernel/aio`.

use std::io::Write;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::{Duration, Instant};

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

fn errname(e: i32) -> String {
    let n = match e {
        1 => "EPERM", 4 => "EINTR", 9 => "EBADF", 11 => "EAGAIN", 12 => "ENOMEM",
        14 => "EFAULT", 21 => "EISDIR", 22 => "EINVAL", 29 => "ESPIPE", 38 => "ENOSYS",
        95 => "EOPNOTSUPP", 115 => "EINPROGRESS", 125 => "ECANCELED",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 && v > -4096 { format!("-{}", errname(-v as i32)) } else { v.to_string() }
}

fn say(what: &str, v: i64) {
    println!("  {what:<62} {}", r(v));
    let _ = std::io::stdout().flush();
}

fn show(what: &str, v: impl std::fmt::Display) {
    println!("  {what:<62} {v}");
    let _ = std::io::stdout().flush();
}

const NR_IO_SETUP: i64 = 0;
const NR_IO_DESTROY: i64 = 1;
const NR_IO_SUBMIT: i64 = 2;
const NR_IO_CANCEL: i64 = 3;
const NR_IO_GETEVENTS: i64 = 4;
const NR_IO_PGETEVENTS: i64 = 292;

const PREAD: u16 = 0;
const PWRITE: u16 = 1;
const FSYNC: u16 = 2;
const FDSYNC: u16 = 3;
const POLL: u16 = 5;
const NOOP: u16 = 6;
const PREADV: u16 = 7;
const PWRITEV: u16 = 8;

const FLAG_RESFD: u32 = 1;
const FLAG_IOPRIO: u32 = 2;

const MAGIC: u32 = 0xa10a10a1;

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
#[derive(Clone, Copy, Default, Debug)]
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

fn submit(ctx: u64, iocbs: &[*const Iocb]) -> i64 {
    unsafe { sys(NR_IO_SUBMIT, ctx as i64, iocbs.len() as i64, iocbs.as_ptr() as i64, 0, 0, 0) }
}

fn submit1(ctx: u64, cb: &Iocb) -> i64 {
    submit(ctx, &[cb as *const Iocb])
}

fn getevents(ctx: u64, min: i64, nr: i64, ev: *mut Event, ts: Option<&[i64; 2]>) -> i64 {
    let t = ts.map_or(0, |t| t.as_ptr() as i64);
    unsafe { sys(NR_IO_GETEVENTS, ctx as i64, min, nr, ev as i64, t, 0) }
}

fn getevents_raw(ctx: u64, min: i64, nr: i64, ev: i64, ts: i64) -> i64 {
    unsafe { sys(NR_IO_GETEVENTS, ctx as i64, min, nr, ev, ts, 0) }
}

/// One event, waiting at most a second for it.
/// Submit one and, if it was accepted, print its result.
fn run(ctx: u64, what: &str, cb: &Iocb) {
    let r = submit1(ctx, cb);
    say(what, r);
    if r == 1 {
        say("  res", reap1(ctx).1.res);
    }
}

fn reap1(ctx: u64) -> (i64, Event) {
    let mut ev = Event::default();
    let n = getevents(ctx, 1, 1, &mut ev, Some(&[1, 0]));
    (n, ev)
}

const ZERO: [i64; 2] = [0, 0];

fn cancel(ctx: u64, cb: i64, result: i64) -> i64 {
    unsafe { sys(NR_IO_CANCEL, ctx as i64, cb, result, 0, 0, 0) }
}

fn rw(op: u16, fd: i32, buf: u64, n: u64, off: i64) -> Iocb {
    Iocb { data: 0x1234_5678_9abc_def0, opcode: op, fildes: fd as u32, buf, nbytes: n, offset: off, ..Default::default() }
}

fn poll_cb(fd: i32, events: u64) -> Iocb {
    Iocb { data: 0x9011, opcode: POLL, fildes: fd as u32, buf: events, ..Default::default() }
}

fn ring(ctx: u64) -> [u32; 8] {
    let p = ctx as *const u32;
    let mut h = [0u32; 8];
    for (i, w) in h.iter_mut().enumerate() {
        *w = unsafe { std::ptr::read_volatile(p.add(i)) };
    }
    h
}

fn ring_word(ctx: u64, i: usize) -> &'static AtomicU32 {
    unsafe { &*(ctx as *const AtomicU32).add(i) }
}

fn pipe(flags: i32) -> [i32; 2] {
    let mut p = [-1i32; 2];
    unsafe { libc::pipe2(p.as_mut_ptr(), flags) };
    p
}

fn eventfd(init: u32, flags: i32) -> i32 {
    unsafe { libc::eventfd(init, flags) }
}

fn read_eventfd(fd: i32) -> i64 {
    let mut v = 0u64;
    let n = unsafe { libc::read(fd, (&raw mut v).cast(), 8) };
    if n == 8 { v as i64 } else { -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64) }
}

fn wr(fd: i32, b: &[u8]) -> isize {
    unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) }
}

fn close(fd: i32) {
    unsafe { libc::close(fd) };
}

fn later(ms: u64, f: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(ms));
        f();
    })
}

/// The `/proc/self/maps` line whose range starts at `addr`, without the
/// device and inode columns, which are the host's.
fn maps_line(addr: u64) -> String {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let want = format!("{addr:08x}-");
    for line in maps.lines() {
        // Only a ring: reading this file allocates, and the allocator may put
        // its buffer where a ring just was.
        if line.starts_with(&want) && line.contains("[aio]") {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (lo, hi) = f[0].split_once('-').unwrap();
            let pages = (u64::from_str_radix(hi, 16).unwrap() - u64::from_str_radix(lo, 16).unwrap()) / 4096;
            let name = if f.len() > 5 { f[5..].join(" ") } else { String::new() };
            return format!("{} off={} pages={} name={:?}", f[1], f[2], pages, name);
        }
    }
    "absent".into()
}

fn maps_count(word: &str) -> usize {
    std::fs::read_to_string("/proc/self/maps").unwrap_or_default().lines().filter(|l| l.contains(word)).count()
}

fn sysctl(name: &str) -> Option<i64> {
    std::fs::read_to_string(format!("/proc/sys/fs/{name}")).ok()?.trim().parse().ok()
}

fn max_nr() -> u32 {
    sysctl("aio-max-nr").map_or(65536, |v| v as u32)
}

fn cpus() -> u64 {
    unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) as u64 }
}

/// The `nr` a ring for `nr_events` should report, from `aio_setup_ring`.
fn ring_nr(nr_events: u64) -> u64 {
    let n = nr_events.max(4 * cpus()) * 2;
    let bytes = 32 + 32 * n;
    let pages = bytes.div_ceil(4096);
    (pages * 4096 - 32) / 32
}

fn page(prot: i32) -> u64 {
    unsafe { libc::mmap(std::ptr::null_mut(), 4096, prot, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) as u64 }
}

static SIGNALS: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(_: i32) {
    SIGNALS.fetch_add(1, Ordering::SeqCst);
}

fn handle(sig: i32, restart: bool) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as extern "C" fn(i32) as usize;
        sa.sa_flags = if restart { libc::SA_RESTART } else { 0 };
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn alarm_ms(ms: i64) {
    let it = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: 0, tv_usec: ms * 1000 },
    };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--after-exec") {
        after_exec();
        return;
    }
    println!("## aio");
    let tmp = format!("/tmp/aio_probe.{}", std::process::id());
    let _ = std::fs::remove_file(&tmp);
    fresh_mm_cases();
    setup_cases();
    let file = std::ffi::CString::new(tmp.clone()).unwrap();
    let fd = unsafe { libc::open(file.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o600) };
    submit_cases(fd, &file);
    getevents_cases(fd);
    signal_cases();
    poll_cases(fd);
    cancel_cases(fd);
    destroy_cases(fd);
    lifetime_cases(fd);
    close(fd);
    let _ = std::fs::remove_file(&tmp);
}

/// In a child, so the context table starts empty.
fn fresh_mm_cases() {
    println!("## a fresh address space");
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r0, c0) = setup(1);
        let (r1, c1) = setup(1);
        let (r2, c2) = setup(1);
        say("three io_setup", r0 | r1 | r2);
        show("their ring ids", format!("{} {} {}", ring(c0)[0], ring(c1)[0], ring(c2)[0]));
        say("destroy the second", destroy(c1));
        show("the second ring is unmapped", maps_line(c1));
        let (r3, c3) = setup(1);
        say("a fourth", r3);
        show("its ring id", ring(c3)[0]);
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
}

fn setup_cases() {
    println!("## io_setup");
    let before = sysctl("aio-nr");
    let (r, ctx) = setup(1);
    say("io_setup(1)", r);
    show("ctx is page aligned", ctx & 0xfff == 0);
    let h = ring(ctx);
    show("ring.nr matches 2*max(nr, 4*cpus), page-rounded", h[1] as u64 == ring_nr(1));
    show("ring.head", h[2]);
    show("ring.tail", h[3]);
    show("ring.magic is 0xa10a10a1", h[4] == MAGIC);
    show("ring.compat_features", h[5]);
    show("ring.incompat_features", h[6]);
    show("ring.header_length", h[7]);
    let ring_pages = (32 + 32 * h[1] as u64).div_ceil(4096);
    show("maps line of the ring", maps_line(ctx).replace(&format!("pages={ring_pages} "), "pages=<ring.nr's> "));
    show("aio-nr is readable", before.is_some());
    show("aio-nr grew by nr_events", sysctl("aio-nr").zip(before).map(|(a, b)| a - b).unwrap_or(-1));
    let (r2, c2) = setup(1000);
    say("io_setup(1000)", r2);
    show("  its ring.nr", ring(c2)[1]);
    show("  its maps line", maps_line(c2));
    say("  io_destroy", destroy(c2));
    say("io_destroy(1)", destroy(ctx));
    show("aio-nr is back", sysctl("aio-nr") == before);

    let mut nz = 0x1000u64;
    say("*ctxp != 0", unsafe { sys(NR_IO_SETUP, 1, &raw mut nz as i64, 0, 0, 0, 0) });
    show("  *ctxp untouched", format!("{nz:#x}"));
    let mut z = 0u64;
    say("nr_events 0", unsafe { sys(NR_IO_SETUP, 0, &raw mut z as i64, 0, 0, 0, 0) });
    say("ctxp NULL", unsafe { sys(NR_IO_SETUP, 1, 0, 0, 0, 0, 0) });
    say("ctxp unmapped", unsafe { sys(NR_IO_SETUP, 1, 0x10, 0, 0, 0, 0) });
    let ro = page(libc::PROT_READ);
    let rings = maps_count("[aio]");
    say("ctxp read-only", unsafe { sys(NR_IO_SETUP, 1, ro as i64, 0, 0, 0, 0) });
    show("  no ring left behind", maps_count("[aio]") == rings);
    let max = max_nr();
    say("nr = aio-max-nr + 1", setup(max + 1).0);
    say("nr = 4194305 (overflow guard)", setup(4194305).0);
    say("nr = 0x80000000 (doubles to 0)", setup(0x8000_0000).0);
    say("nr = 0xffffffff", setup(0xffff_ffff).0);
    let half = max / 2 + 1;
    let (ra, ca) = setup(half);
    say("nr = aio-max-nr/2 + 1", ra);
    let (rb, cb) = setup(half);
    say("  and again: over the system-wide budget", rb);
    if rb == 0 {
        destroy(cb);
    }
    say("  destroy the first", destroy(ca));
    let (rc, cc) = setup(half);
    say("  then the budget is back", rc);
    destroy(cc);
}

fn submit_cases(fd: i32, file: &std::ffi::CStr) {
    println!("## io_submit");
    let (_, ctx) = setup(128);
    let cb = rw(PWRITE, fd, b"hello aio".as_ptr() as u64, 9, 0);
    say("nr -1", unsafe { sys(NR_IO_SUBMIT, ctx as i64, -1, 0, 0, 0, 0) });
    say("ctx 0", submit(0, &[&cb]));
    say("ctx unmapped", submit(0x10000, &[&cb]));
    let plain = Box::leak(Box::new([0u64; 512])).as_ptr() as u64;
    say("ctx a page with id 0 at it", submit(plain, &[&cb]));
    say("ctx misaligned (ring + 4)", submit(ctx + 4, &[&cb]));
    say("nr 0", submit(ctx, &[]));
    say("iocbpp NULL", unsafe { sys(NR_IO_SUBMIT, ctx as i64, 1, 0, 0, 0, 0) });
    say("iocbpp[0] NULL", submit(ctx, &[std::ptr::null()]));
    say("iocbpp[0] unmapped", submit(ctx, &[0x10 as *const Iocb]));

    let mut cb = rw(PWRITE, fd, b"hello aio".as_ptr() as u64, 9, 0);
    cb.key = 0xdead;
    say("PWRITE 9 at 0", submit1(ctx, &cb));
    show("  aio_key afterwards", format!("{:#x}", cb.key));
    let h = ring(ctx);
    show("  ring tail - head before getevents", h[3].wrapping_sub(h[2]));
    let (n, ev) = reap1(ctx);
    say("  getevents", n);
    show("  data", format!("{:#x}", ev.data));
    show("  obj is the iocb", ev.obj == &raw const cb as u64);
    say("  res", ev.res);
    say("  res2", ev.res2);
    let h = ring(ctx);
    show("  ring head == tail after", h[2] == h[3]);

    let mut buf = [0u8; 32];
    let cb = rw(PREAD, fd, buf.as_mut_ptr() as u64, 9, 0);
    say("PREAD 9 at 0", submit1(ctx, &cb));
    let (_, ev) = reap1(ctx);
    say("  res", ev.res);
    show("  bytes", String::from_utf8_lossy(&buf[..9]));
    let cb = rw(PREAD, fd, buf.as_mut_ptr() as u64, 100, 4);
    submit1(ctx, &cb);
    say("PREAD 100 at 4: res", reap1(ctx).1.res);
    let cb = rw(PREAD, fd, buf.as_mut_ptr() as u64, 10, 1000);
    submit1(ctx, &cb);
    say("PREAD past EOF: res", reap1(ctx).1.res);
    let cb = rw(PREAD, fd, buf.as_mut_ptr() as u64, 0, 0);
    submit1(ctx, &cb);
    say("PREAD 0 bytes: res", reap1(ctx).1.res);

    let a = b"abc";
    let b = b"defg";
    let iov = [libc::iovec { iov_base: a.as_ptr() as *mut _, iov_len: 3 }, libc::iovec { iov_base: b.as_ptr() as *mut _, iov_len: 4 }];
    let cb = rw(PWRITEV, fd, iov.as_ptr() as u64, 2, 20);
    run(ctx, "PWRITEV 2 vectors at 20", &cb);
    let mut x = [0u8; 3];
    let mut y = [0u8; 8];
    let iov = [libc::iovec { iov_base: x.as_mut_ptr().cast(), iov_len: 3 }, libc::iovec { iov_base: y.as_mut_ptr().cast(), iov_len: 8 }];
    let cb = rw(PREADV, fd, iov.as_ptr() as u64, 2, 20);
    run(ctx, "PREADV 2 vectors at 20", &cb);
    show("  bytes", format!("{}|{}", String::from_utf8_lossy(&x), String::from_utf8_lossy(&y[..4])));
    let cb = rw(PREADV, fd, iov.as_ptr() as u64, 1025, 0);
    say("PREADV 1025 vectors", submit1(ctx, &cb));
    let cb = rw(PREADV, fd, 0x10, 1, 0);
    say("PREADV vector array unmapped", submit1(ctx, &cb));
    let cb = rw(PREADV, fd, iov.as_ptr() as u64, 0, 0);
    submit1(ctx, &cb);
    say("PREADV 0 vectors: res", reap1(ctx).1.res);
    let bad = [libc::iovec { iov_base: 0x10 as *mut _, iov_len: 3 }];
    let cb = rw(PREADV, fd, bad.as_ptr() as u64, 1, 0);
    run(ctx, "PREADV into an unmapped vector", &cb);

    for (name, op) in [("FSYNC", FSYNC), ("FDSYNC", FDSYNC)] {
        let cb = rw(op, fd, 0, 0, 0);
        say(name, submit1(ctx, &cb));
        let (_, ev) = reap1(ctx);
        say("  res", ev.res);
        say("  res2", ev.res2);
    }
    say("FSYNC with buf", submit1(ctx, &rw(FSYNC, fd, 8, 0, 0)));
    say("FSYNC with nbytes", submit1(ctx, &rw(FSYNC, fd, 0, 8, 0)));
    say("FSYNC with offset", submit1(ctx, &rw(FSYNC, fd, 0, 0, 8)));
    let mut cb = rw(FSYNC, fd, 0, 0, 0);
    cb.rw_flags = 2;
    say("FSYNC with rw_flags", submit1(ctx, &cb));
    let p = pipe(libc::O_NONBLOCK);
    say("FSYNC a pipe", submit1(ctx, &rw(FSYNC, p[1], 0, 0, 0)));
    let e = eventfd(0, 0);
    say("FSYNC an eventfd", submit1(ctx, &rw(FSYNC, e, 0, 0, 0)));

    say("NOOP", submit1(ctx, &rw(NOOP, fd, 0, 0, 0)));
    say("opcode 4", submit1(ctx, &rw(4, fd, 0, 0, 0)));
    say("opcode 9", submit1(ctx, &rw(9, fd, 0, 0, 0)));
    say("opcode 0xffff", submit1(ctx, &rw(0xffff, fd, 0, 0, 0)));
    say("opcode 9, fd -1", submit1(ctx, &rw(9, -1, 0, 0, 0)));
    let mut cb = rw(PREAD, fd, buf.as_mut_ptr() as u64, 1, 0);
    cb.reserved2 = 1;
    say("aio_reserved2 set", submit1(ctx, &cb));
    cb.reserved2 = 0;
    cb.fildes = u32::MAX;
    cb.reserved2 = 1;
    say("aio_reserved2 set, fd -1", submit1(ctx, &cb));
    say("nbytes 1<<63", submit1(ctx, &rw(PREAD, fd, buf.as_mut_ptr() as u64, 1 << 63, 0)));
    say("nbytes 1<<63, fd -1", submit1(ctx, &rw(PREAD, -1, buf.as_mut_ptr() as u64, 1 << 63, 0)));
    say("fd -1", submit1(ctx, &rw(PREAD, -1, buf.as_mut_ptr() as u64, 1, 0)));
    say("fd 9999", submit1(ctx, &rw(PREAD, 9999, buf.as_mut_ptr() as u64, 1, 0)));
    let wo = unsafe { libc::open(file.as_ptr(), libc::O_WRONLY) };
    let ro = unsafe { libc::open(file.as_ptr(), libc::O_RDONLY) };
    let op = unsafe { libc::open(file.as_ptr(), libc::O_PATH) };
    say("PREAD an O_WRONLY fd", submit1(ctx, &rw(PREAD, wo, buf.as_mut_ptr() as u64, 1, 0)));
    say("PWRITE an O_RDONLY fd", submit1(ctx, &rw(PWRITE, ro, buf.as_ptr() as u64, 1, 0)));
    say("PREADV an O_WRONLY fd", submit1(ctx, &rw(PREADV, wo, iov.as_ptr() as u64, 1, 0)));
    say("PREAD an O_PATH fd", submit1(ctx, &rw(PREAD, op, buf.as_mut_ptr() as u64, 1, 0)));
    say("FSYNC an O_PATH fd", submit1(ctx, &rw(FSYNC, op, 0, 0, 0)));
    run(ctx, "FSYNC an O_RDONLY fd", &rw(FSYNC, ro, 0, 0, 0));
    close(wo);
    close(ro);
    close(op);
    say("PREAD offset -1", submit1(ctx, &rw(PREAD, fd, buf.as_mut_ptr() as u64, 1, -1)));
    say("PWRITE offset -1", submit1(ctx, &rw(PWRITE, fd, buf.as_ptr() as u64, 1, -1)));
    run(ctx, "PREAD offset i64::MAX", &rw(PREAD, fd, buf.as_mut_ptr() as u64, 1, i64::MAX));
    run(ctx, "PREAD offset i64::MAX - 1, 4 bytes", &rw(PREAD, fd, buf.as_mut_ptr() as u64, 4, i64::MAX - 1));
    run(ctx, "PREAD into an unmapped low page", &rw(PREAD, fd, 0x1000, 4, 0));
    say("PREAD into a kernel address", submit1(ctx, &rw(PREAD, fd, 1 << 60, 4, 0)));
    run(ctx, "PWRITE from an unmapped low page", &rw(PWRITE, fd, 0x1000, 4, 0));
    let dir = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    say("PREAD a directory", submit1(ctx, &rw(PREAD, dir, buf.as_mut_ptr() as u64, 4, 0)));
    say("  getevents {0,0}", getevents(ctx, 0, 8, [Event::default(); 8].as_mut_ptr(), Some(&ZERO)));
    say("PWRITE a directory", submit1(ctx, &rw(PWRITE, dir, buf.as_ptr() as u64, 4, 0)));
    close(dir);

    let e = eventfd(5, libc::EFD_NONBLOCK);
    let mut v = 0u64;
    run(ctx, "PREAD an eventfd holding 5", &rw(PREAD, e, &raw mut v as u64, 8, 0));
    show("  value", v);
    let seven = 7u64;
    run(ctx, "PWRITE 7 to the eventfd", &rw(PWRITE, e, &raw const seven as u64, 8, 0));
    say("  counter", read_eventfd(e));
    run(ctx, "PREAD 4 bytes of an eventfd", &rw(PREAD, e, &raw mut v as u64, 4, 0));
    close(e);

    let p = pipe(libc::O_NONBLOCK);
    wr(p[1], b"xyz");
    run(ctx, "PREAD a pipe holding 3, offset 100", &rw(PREAD, p[0], buf.as_mut_ptr() as u64, 10, 100));
    run(ctx, "PREAD an empty O_NONBLOCK pipe", &rw(PREAD, p[0], buf.as_mut_ptr() as u64, 10, 0));
    run(ctx, "PWRITE a pipe, offset 5", &rw(PWRITE, p[1], b"hi".as_ptr() as u64, 2, 5));
    say("PREAD a pipe, offset -1", submit1(ctx, &rw(PREAD, p[0], buf.as_mut_ptr() as u64, 10, -1)));
    close(p[0]);
    run(ctx, "PWRITE a pipe with no reader", &rw(PWRITE, p[1], b"hi".as_ptr() as u64, 2, 0));
    close(p[1]);

    println!("## rw_flags, reqprio, aio_flags");
    for (name, flags, op) in [
        ("RWF_HIPRI read", 1, PREAD),
        ("RWF_DSYNC write", 2, PWRITE),
        ("RWF_SYNC write", 4, PWRITE),
        ("RWF_DSYNC read", 2, PREAD),
        ("RWF_NOWAIT read", 8, PREAD),
        ("RWF_APPEND read", 0x10, PREAD),
        ("RWF_NOAPPEND write", 0x20, PWRITE),
        ("RWF_ATOMIC write", 0x40, PWRITE),
        ("RWF_DONTCACHE read", 0x80, PREAD),
        ("RWF_NOSIGNAL write", 0x100, PWRITE),
        ("RWF_NOSIGNAL read", 0x100, PREAD),
        ("RWF_ATOMIC read", 0x40, PREAD),
        ("rw_flags 0x200", 0x200, PREAD),
        ("rw_flags 0x10000", 0x10000, PREAD),
        ("rw_flags -1", -1, PREAD),
    ] {
        let mut cb = rw(op, fd, buf.as_mut_ptr() as u64, 2, 0);
        cb.rw_flags = flags;
        let r = submit1(ctx, &cb);
        if r == 1 {
            say(name, reap1(ctx).1.res);
        } else {
            say(name, r);
        }
    }
    let size = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
    let mut cb = rw(PWRITE, fd, b"APP".as_ptr() as u64, 3, 0);
    cb.rw_flags = 0x10;
    run(ctx, "RWF_APPEND write at offset 0", &cb);
    say("  the file grew by", unsafe { libc::lseek(fd, 0, libc::SEEK_END) } - size);
    let mut cb = rw(PREAD, fd, buf.as_mut_ptr() as u64, 1, 0);
    cb.reqprio = 7;
    say("aio_reqprio 7 without IOCB_FLAG_IOPRIO", submit1(ctx, &cb));
    reap1(ctx);
    cb.reqprio = -1;
    say("aio_reqprio -1 without IOCB_FLAG_IOPRIO", submit1(ctx, &cb));
    reap1(ctx);
    cb.flags = FLAG_IOPRIO;
    cb.reqprio = (2 << 13) | 4;
    say("IOCB_FLAG_IOPRIO best-effort 4", submit1(ctx, &cb));
    reap1(ctx);
    cb.reqprio = 7 << 13;
    say("IOCB_FLAG_IOPRIO class 7", submit1(ctx, &cb));
    cb.reqprio = (2 << 13) | 9;
    say("IOCB_FLAG_IOPRIO best-effort level 9", submit1(ctx, &cb));
    cb.reqprio = 1 << 13;
    say("IOCB_FLAG_IOPRIO realtime", submit1(ctx, &cb));
    if reap_now(ctx) != 0 {
        show("  (completed)", "");
    }
    cb.reqprio = 0;
    say("IOCB_FLAG_IOPRIO none", submit1(ctx, &cb));
    reap_now(ctx);
    cb.flags = 4;
    say("aio_flags 4", submit1(ctx, &cb));
    reap_now(ctx);
    cb.flags = 0x8000_0000;
    say("aio_flags 1<<31", submit1(ctx, &cb));
    reap_now(ctx);

    let ro = page(libc::PROT_READ | libc::PROT_WRITE) as *mut Iocb;
    unsafe { *ro = rw(PREAD, fd, buf.as_mut_ptr() as u64, 1, 0) };
    unsafe { libc::mprotect(ro.cast(), 4096, libc::PROT_READ) };
    say("an iocb in read-only memory", submit(ctx, &[ro]));
    let mut bad_fd_ro = unsafe { *ro };
    bad_fd_ro.fildes = u32::MAX;
    unsafe { libc::mprotect(ro.cast(), 4096, libc::PROT_READ | libc::PROT_WRITE) };
    unsafe { *ro = bad_fd_ro };
    unsafe { libc::mprotect(ro.cast(), 4096, libc::PROT_READ) };
    say("  and with fd -1", submit(ctx, &[ro]));
    unsafe { libc::mprotect(ro.cast(), 4096, libc::PROT_READ | libc::PROT_WRITE) };
    unsafe { (*ro).fildes = fd as u32; (*ro).opcode = 9 };
    unsafe { libc::mprotect(ro.cast(), 4096, libc::PROT_READ) };
    say("  and with opcode 9", submit(ctx, &[ro]));

    println!("## IOCB_FLAG_RESFD");
    let e = eventfd(0, libc::EFD_NONBLOCK);
    let mut cb = rw(PWRITE, fd, b"r".as_ptr() as u64, 1, 40);
    cb.flags = FLAG_RESFD;
    cb.resfd = e as u32;
    say("PWRITE with RESFD", submit1(ctx, &cb));
    say("  eventfd counter", read_eventfd(e));
    submit(ctx, &[&cb, &cb, &cb]);
    say("  three more, counter", read_eventfd(e));
    say("  getevents", getevents(ctx, 4, 8, [Event::default(); 8].as_mut_ptr(), Some(&[1, 0])));
    let es = eventfd(0, libc::EFD_NONBLOCK | libc::EFD_SEMAPHORE);
    cb.resfd = es as u32;
    submit(ctx, &[&cb, &cb]);
    say("  a semaphore eventfd, first read", read_eventfd(es));
    say("  second read", read_eventfd(es));
    reap_now(ctx);
    let p = pipe(0);
    cb.resfd = p[0] as u32;
    say("RESFD a pipe", submit1(ctx, &cb));
    cb.resfd = u32::MAX;
    say("RESFD -1", submit1(ctx, &cb));
    cb.fildes = u32::MAX;
    cb.resfd = p[0] as u32;
    say("RESFD a pipe, fd -1", submit1(ctx, &cb));
    cb.fildes = fd as u32;
    cb.resfd = e as u32;
    cb.opcode = 9;
    say("RESFD, opcode 9", submit1(ctx, &cb));
    say("  counter", read_eventfd(e));
    cb.flags = 0;
    cb.opcode = PWRITE;
    cb.resfd = 9999;
    say("resfd 9999 without the flag", submit1(ctx, &cb));
    reap_now(ctx);
    close(p[0]);
    close(p[1]);
    close(e);
    close(es);

    println!("## partial submission");
    let good = rw(PWRITE, fd, b"g".as_ptr() as u64, 1, 50);
    let bad = rw(PWRITE, -1, b"g".as_ptr() as u64, 1, 50);
    say("good, bad fd, good", submit(ctx, &[&good, &bad, &good]));
    say("  events", reap_now(ctx));
    say("bad fd first", submit(ctx, &[&bad, &good]));
    say("good, NULL", submit(ctx, &[&good, std::ptr::null()]));
    say("  events", reap_now(ctx));
    say("good, reserved2", submit(ctx, &[&good, &Iocb { reserved2: 1, ..good }]));
    reap_now(ctx);
    destroy(ctx);

    println!("## ring capacity");
    let (_, ctx) = setup(1);
    let nr = ring(ctx)[1] as i64;
    let mut accepted = 0i64;
    let last;
    loop {
        let r = submit1(ctx, &good);
        if r != 1 {
            last = r;
            break;
        }
        accepted += 1;
        if accepted > 100_000 {
            last = 0;
            break;
        }
    }
    say("io_setup(1), submit until refused: the refusal", last);
    show("  accepted >= 1", accepted >= 1);
    show("  accepted < ring.nr", accepted < nr);
    let mut evs = vec![Event::default(); nr as usize];
    let got = getevents(ctx, 0, nr, evs.as_mut_ptr(), Some(&ZERO));
    show("  getevents takes all of them", got == accepted);
    say("  then a submit is accepted again", submit1(ctx, &good));
    reap_now(ctx);
    let many: Vec<*const Iocb> = (0..nr + 50).map(|_| &good as *const Iocb).collect();
    let r = submit(ctx, &many);
    show("  nr above ring.nr: accepted < ring.nr", r > 0 && r < nr);
    getevents(ctx, 0, nr, evs.as_mut_ptr(), Some(&ZERO));
    destroy(ctx);
}

/// Take whatever is completed without waiting.
fn reap_now(ctx: u64) -> i64 {
    let mut evs = [Event::default(); 64];
    getevents(ctx, 0, 64, evs.as_mut_ptr(), Some(&ZERO))
}

fn getevents_cases(fd: i32) {
    println!("## io_getevents");
    let (_, ctx) = setup(16);
    let mut ev = [Event::default(); 4];
    let e = ev.as_mut_ptr();
    say("min_nr > nr", getevents(ctx, 2, 1, e, Some(&ZERO)));
    say("min_nr -1", getevents(ctx, -1, 1, e, Some(&ZERO)));
    say("nr -1", getevents(ctx, 0, -1, e, Some(&ZERO)));
    say("min 0, nr 0", getevents(ctx, 0, 0, e, Some(&ZERO)));
    say("min 0, nr 0, no timeout", getevents(ctx, 0, 0, e, None));
    say("ctx 0", getevents(0, 0, 1, e, Some(&ZERO)));
    say("ctx unmapped, timeout unmapped", getevents_raw(0x10000, 0, 1, e as i64, 0x10));
    say("timeout unmapped", getevents_raw(ctx, 0, 1, e as i64, 0x10));
    say("min_nr > nr, timeout unmapped", getevents_raw(ctx, 2, 1, e as i64, 0x10));
    say("{0,0} with nothing", getevents(ctx, 1, 1, e, Some(&ZERO)));
    let t = Instant::now();
    let n = getevents(ctx, 1, 1, e, Some(&[0, 30_000_000]));
    say("30ms with nothing", n);
    show("  waited at least 30ms", t.elapsed() >= Duration::from_millis(30));
    handle(libc::SIGALRM, false);
    alarm_ms(100);
    let t = Instant::now();
    say("{-1, 0} with nothing, SIGALRM at 100ms", getevents(ctx, 1, 1, e, Some(&[-1, 0])));
    show("  waited for the signal", t.elapsed() >= Duration::from_millis(90));
    alarm_ms(100);
    let t = Instant::now();
    say("{0, -1} with nothing, SIGALRM at 100ms", getevents(ctx, 1, 1, e, Some(&[0, -1])));
    show("  waited for the signal", t.elapsed() >= Duration::from_millis(90));
    alarm_ms(1500);
    let t = Instant::now();
    say("{0, 1e9} with nothing, SIGALRM at 1.5s", getevents(ctx, 1, 1, e, Some(&[0, 1_000_000_000])));
    show("  waited a second", t.elapsed() >= Duration::from_millis(990));
    alarm_ms(0);
    let w = rw(PWRITE, fd, b"w".as_ptr() as u64, 1, 60);
    submit(ctx, &[&w, &w, &w]);
    say("3 pending, events unmapped", getevents_raw(ctx, 1, 3, 0x10, ZERO.as_ptr() as i64));
    let ro = page(libc::PROT_READ);
    say("3 pending, events read-only", getevents_raw(ctx, 1, 3, ro as i64, ZERO.as_ptr() as i64));
    say("  nr 2", getevents(ctx, 1, 2, e, Some(&ZERO)));
    say("  then the rest", getevents(ctx, 1, 4, e, Some(&ZERO)));
    submit1(ctx, &w);
    let t = Instant::now();
    say("1 pending, min_nr 2, 30ms", getevents(ctx, 2, 4, e, Some(&[0, 30_000_000])));
    show("  waited for the timeout", t.elapsed() >= Duration::from_millis(30));
    submit1(ctx, &w);
    let t = Instant::now();
    say("1 pending, min_nr 2, no timeout, a second completes at 30ms", {
        let c = ctx;
        let w2 = w;
        let h = later(30, move || {
            submit1(c, &w2);
        });
        let n = getevents(ctx, 2, 4, e, None);
        h.join().unwrap();
        n
    });
    show("  waited for it", t.elapsed() >= Duration::from_millis(25));
    submit1(ctx, &w);
    say("1 pending, min 0, nr 4, no timeout", getevents(ctx, 0, 4, e, None));

    println!("## userspace reaping");
    submit(ctx, &[&w, &w]);
    let h = ring(ctx);
    show("tail - head with 2 completed", h[3].wrapping_sub(h[2]));
    ring_word(ctx, 2).store(h[3], Ordering::SeqCst);
    say("head moved to tail by hand: getevents", getevents(ctx, 0, 4, e, Some(&ZERO)));
    submit1(ctx, &w);
    let h = ring(ctx);
    let nr = h[1];
    ring_word(ctx, 2).store((h[3] + nr - 2) % nr, Ordering::SeqCst);
    say("head moved back two by hand: getevents", getevents(ctx, 0, 4, e, Some(&ZERO)));
    ring_word(ctx, 2).store(nr + 5, Ordering::SeqCst);
    say("head beyond nr: getevents", getevents(ctx, 0, 4, e, Some(&ZERO)));
    show("  head afterwards", ring(ctx)[2]);
    ring_word(ctx, 3).store(9999, Ordering::SeqCst);
    say("tail scribbled: getevents", getevents(ctx, 0, 4, e, Some(&ZERO)));
    submit1(ctx, &w);
    show("  tail after one more completion", ring(ctx)[3]);
    destroy(ctx);
}

fn signal_cases() {
    println!("## signals");
    let (_, ctx) = setup(4);
    let mut ev = [Event::default(); 4];
    let e = ev.as_mut_ptr();
    handle(libc::SIGALRM, false);
    SIGNALS.store(0, Ordering::SeqCst);
    alarm_ms(30);
    say("blocked, SIGALRM at 30ms, no SA_RESTART", getevents(ctx, 1, 1, e, None));
    show("  handler ran", SIGNALS.load(Ordering::SeqCst));
    handle(libc::SIGALRM, true);
    alarm_ms(30);
    say("blocked, SIGALRM at 30ms, SA_RESTART", getevents(ctx, 1, 1, e, Some(&[2, 0])));
    show("  handler ran", SIGNALS.load(Ordering::SeqCst));
    unsafe { libc::signal(libc::SIGALRM, libc::SIG_IGN) };
    alarm_ms(30);
    let t = Instant::now();
    say("SIGALRM ignored, 100ms timeout", getevents(ctx, 1, 1, e, Some(&[0, 100_000_000])));
    show("  waited the whole timeout", t.elapsed() >= Duration::from_millis(100));
    handle(libc::SIGALRM, false);

    println!("## io_pgetevents");
    let pg = |min: i64, ts: i64, usig: i64| unsafe { sys(NR_IO_PGETEVENTS, ctx as i64, min, 1, e as i64, ts, usig) };
    say("usig NULL, {0,0}", pg(1, ZERO.as_ptr() as i64, 0));
    let mut set: u64 = 0;
    let u = [&raw mut set as i64, 4];
    say("sigsetsize 4", pg(1, ZERO.as_ptr() as i64, u.as_ptr() as i64));
    let u = [&raw mut set as i64, 16];
    say("sigsetsize 16", pg(1, ZERO.as_ptr() as i64, u.as_ptr() as i64));
    say("usig unmapped", pg(1, ZERO.as_ptr() as i64, 0x10));
    let u = [0i64, 8];
    say("sigmask NULL, size 8", pg(1, ZERO.as_ptr() as i64, u.as_ptr() as i64));
    let u = [0i64, 4];
    say("sigmask NULL, size 4", pg(1, ZERO.as_ptr() as i64, u.as_ptr() as i64));
    let u = [0x10i64, 8];
    say("sigmask unmapped", pg(1, ZERO.as_ptr() as i64, u.as_ptr() as i64));
    say("bad ctx, usig unmapped", unsafe { sys(NR_IO_PGETEVENTS, 0, 1, 1, e as i64, ZERO.as_ptr() as i64, 0x10) });
    say("bad ctx, sigsetsize 4", {
        let u = [&raw mut set as i64, 4];
        unsafe { sys(NR_IO_PGETEVENTS, 0, 1, 1, e as i64, ZERO.as_ptr() as i64, u.as_ptr() as i64) }
    });

    set = 1 << (libc::SIGALRM - 1);
    let u = [&raw mut set as i64, 8];
    SIGNALS.store(0, Ordering::SeqCst);
    alarm_ms(30);
    let t = Instant::now();
    say("SIGALRM masked by usig, at 30ms, 100ms timeout", pg(1, [0i64, 100_000_000].as_ptr() as i64, u.as_ptr() as i64));
    show("  waited the whole timeout", t.elapsed() >= Duration::from_millis(100));
    show("  handler ran after", SIGNALS.load(Ordering::SeqCst));

    unsafe {
        let mut s: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut s);
        libc::sigaddset(&mut s, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_BLOCK, &s, std::ptr::null_mut());
    }
    handle(libc::SIGUSR1, false);
    SIGNALS.store(0, Ordering::SeqCst);
    unsafe { libc::raise(libc::SIGUSR1) };
    set = 0;
    let u = [&raw mut set as i64, 8];
    say("SIGUSR1 pending and blocked, usig unblocks it", pg(1, [1i64, 0].as_ptr() as i64, u.as_ptr() as i64));
    show("  handler ran", SIGNALS.load(Ordering::SeqCst));
    let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut old) };
    show("  SIGUSR1 blocked again after", unsafe { libc::sigismember(&old, libc::SIGUSR1) });
    unsafe { libc::raise(libc::SIGUSR1) };
    say("SIGUSR1 pending, usig NULL", pg(1, ZERO.as_ptr() as i64, 0));
    let u = [&raw mut set as i64, 8];
    let full = pipe(0);
    wr(full[1], b"x");
    let mut byte = [0u8; 1];
    let w = rw(PREAD, full[0], byte.as_mut_ptr() as u64, 1, 0);
    say("SIGUSR1 pending: PREAD a pipe holding a byte", submit1(ctx, &w));
    say("SIGUSR1 pending, an event ready, usig unblocks", pg(1, ZERO.as_ptr() as i64, u.as_ptr() as i64));
    show("  handler ran", SIGNALS.load(Ordering::SeqCst));
    close(full[0]);
    close(full[1]);
    unsafe {
        let mut s: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut s);
        libc::sigaddset(&mut s, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_UNBLOCK, &s, std::ptr::null_mut());
    }
    destroy(ctx);
}

fn poll_cases(fd: i32) {
    println!("## IOCB_CMD_POLL");
    let (_, ctx) = setup(16);
    let mut ev = [Event::default(); 4];
    let e = ev.as_mut_ptr();
    let p = pipe(0);
    let cb = poll_cb(p[0], libc::POLLIN as u64);
    say("POLLIN on an empty pipe", submit1(ctx, &cb));
    say("  getevents {0,0}", getevents(ctx, 0, 4, e, Some(&ZERO)));
    let h = ring(ctx);
    show("  ring empty", h[2] == h[3]);
    let w = p[1];
    let t = later(30, move || {
        wr(w, b"x");
    });
    say("  a write at 30ms; getevents", getevents(ctx, 1, 4, e, Some(&[2, 0])));
    t.join().unwrap();
    show("  data", format!("{:#x}", ev[0].data));
    show("  obj is the iocb", ev[0].obj == &raw const cb as u64);
    say("  res, after a pipe write woke it", ev[0].res);
    say("  res2", ev[0].res2);
    let mut b = [0u8; 4];
    unsafe { libc::read(p[0], b.as_mut_ptr().cast(), 4) };

    let cb = poll_cb(p[0], libc::POLLIN as u64);
    let efd = eventfd(0, libc::EFD_NONBLOCK);
    let cb = Iocb { flags: FLAG_RESFD, resfd: efd as u32, ..cb };
    submit1(ctx, &cb);
    let w = p[1];
    let t = later(20, move || {
        wr(w, b"y");
    });
    let start = Instant::now();
    let mut moved = false;
    while start.elapsed() < Duration::from_secs(2) {
        let h = ring(ctx);
        if h[2] != h[3] {
            moved = true;
            break;
        }
        std::thread::yield_now();
    }
    t.join().unwrap();
    show("POLLIN + RESFD: the ring tail moves with no syscall", moved);
    say("  eventfd counter", read_eventfd(efd));
    say("  getevents", getevents(ctx, 1, 4, e, Some(&ZERO)));
    say("  res, after a pipe write woke it", ev[0].res);
    wr(p[1], b"z");
    say("  a second write produces nothing more", getevents(ctx, 0, 4, e, Some(&ZERO)));
    unsafe { libc::read(p[0], b.as_mut_ptr().cast(), 4) };
    close(efd);

    say("POLLIN|POLLOUT on a regular file", submit1(ctx, &poll_cb(fd, (libc::POLLIN | libc::POLLOUT) as u64)));
    let n = getevents(ctx, 0, 4, e, Some(&ZERO));
    say("  completed at once", n);
    say("  res", ev[0].res);
    say("POLLOUT on a pipe's write end", submit1(ctx, &poll_cb(p[1], libc::POLLOUT as u64)));
    getevents(ctx, 0, 4, e, Some(&ZERO));
    say("  res", ev[0].res);
    say("POLLIN|POLLRDNORM on a pipe holding data", {
        wr(p[1], b"d");
        submit1(ctx, &poll_cb(p[0], (libc::POLLIN | libc::POLLRDNORM) as u64))
    });
    getevents(ctx, 0, 4, e, Some(&ZERO));
    say("  res", ev[0].res);
    unsafe { libc::read(p[0], b.as_mut_ptr().cast(), 4) };
    say("events 0 on an empty pipe", submit1(ctx, &poll_cb(p[0], 0)));
    say("  getevents {0,0}", getevents(ctx, 0, 4, e, Some(&ZERO)));
    close(p[1]);
    say("  the writer closes; getevents", getevents(ctx, 1, 4, e, Some(&[1, 0])));
    say("  res", ev[0].res);
    say("POLLIN on a pipe with no writer", submit1(ctx, &poll_cb(p[0], libc::POLLIN as u64)));
    getevents(ctx, 0, 4, e, Some(&ZERO));
    say("  res", ev[0].res);
    close(p[0]);

    let mut s = [-1i32; 2];
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, s.as_mut_ptr()) };
    say("POLLIN on a socketpair end", submit1(ctx, &poll_cb(s[0], libc::POLLIN as u64)));
    let w = s[1];
    let t = later(30, move || {
        wr(w, b"s");
    });
    say("  the peer writes at 30ms; getevents", getevents(ctx, 1, 4, e, Some(&[2, 0])));
    t.join().unwrap();
    say("  res, after a socket write woke it", ev[0].res);
    close(s[0]);
    close(s[1]);

    let efd = eventfd(0, 0);
    say("POLLIN on an eventfd", submit1(ctx, &poll_cb(efd, libc::POLLIN as u64)));
    let t = later(30, move || {
        let one = 1u64;
        unsafe { libc::write(efd, (&raw const one).cast(), 8) };
    });
    say("  written at 30ms; getevents", getevents(ctx, 1, 4, e, Some(&[2, 0])));
    t.join().unwrap();
    say("  res", ev[0].res);
    close(efd);

    let p = pipe(0);
    say("events 0x10000", submit1(ctx, &poll_cb(p[0], 0x10000)));
    let all = poll_cb(p[0], 0xffff);
    say("events 0xffff on an empty pipe", submit1(ctx, &all));
    say("  getevents {0,0}", getevents(ctx, 0, 4, e, Some(&ZERO)));
    say("  cancel", cancel(ctx, &raw const all as i64, 0));
    getevents(ctx, 1, 4, e, Some(&[1, 0]));
    say("  res", ev[0].res);
    say("nbytes 1", submit1(ctx, &Iocb { nbytes: 1, ..poll_cb(p[0], 1) }));
    say("offset 1", submit1(ctx, &Iocb { offset: 1, ..poll_cb(p[0], 1) }));
    say("rw_flags 1", submit1(ctx, &Iocb { rw_flags: 1, ..poll_cb(p[0], 1) }));
    let prio = Iocb { reqprio: 3, ..poll_cb(p[0], 1) };
    say("reqprio 3", submit1(ctx, &prio));
    cancel(ctx, &raw const prio as i64, 0);
    getevents(ctx, 1, 4, e, Some(&[1, 0]));
    say("fd -1", submit1(ctx, &poll_cb(-1, 1)));
    destroy(ctx);

    let (_, ctx) = setup(16);
    let pending = poll_cb(p[0], libc::POLLIN as u64);
    say("POLLIN pending, then the fd is closed", submit1(ctx, &pending));
    let w = p[1];
    close(p[0]);
    wr(w, b"q");
    say("  a write after the close; getevents 1s", getevents(ctx, 1, 4, e, Some(&[1, 0])));
    say("  res, after a pipe write woke it", ev[0].res);
    close(w);
    destroy(ctx);
}

fn cancel_cases(fd: i32) {
    println!("## io_cancel");
    let (_, ctx) = setup(16);
    let mut ev = [Event::default(); 4];
    let e = ev.as_mut_ptr();
    let mut out = Event { res: 77, ..Default::default() };
    let p = pipe(0);
    let cb = poll_cb(p[0], libc::POLLIN as u64);
    submit1(ctx, &cb);
    say("a pending POLL", cancel(ctx, &raw const cb as i64, &raw mut out as i64));
    show("  result untouched", out.res);
    say("  getevents", getevents(ctx, 1, 4, e, Some(&[1, 0])));
    show("  obj is the iocb", ev[0].obj == &raw const cb as u64);
    say("  res", ev[0].res);
    say("  res2", ev[0].res2);
    say("  cancel it again", cancel(ctx, &raw const cb as i64, 0));
    let w = rw(PWRITE, fd, b"c".as_ptr() as u64, 1, 70);
    submit1(ctx, &w);
    say("a completed PWRITE", cancel(ctx, &raw const w as i64, &raw mut out as i64));
    reap_now(ctx);
    let never = Iocb::default();
    say("an iocb never submitted, key 0", cancel(ctx, &raw const never as i64, 0));
    let keyed = Iocb { key: 1, ..never };
    say("key 1", cancel(ctx, &raw const keyed as i64, 0));
    say("iocb NULL", cancel(ctx, 0, 0));
    say("iocb NULL, ctx 0", cancel(0, 0, 0));
    say("key 1, ctx 0", cancel(0, &raw const keyed as i64, 0));
    say("key 0, ctx 0", cancel(0, &raw const never as i64, 0));
    let cb = poll_cb(p[0], libc::POLLIN as u64);
    submit1(ctx, &cb);
    say("a pending POLL, result NULL", cancel(ctx, &raw const cb as i64, 0));
    reap1(ctx);
    let cb = poll_cb(p[0], libc::POLLIN as u64);
    submit1(ctx, &cb);
    say("a pending POLL, result unmapped", cancel(ctx, &raw const cb as i64, 0x10));
    reap1(ctx);
    let cb = poll_cb(p[0], libc::POLLIN as u64);
    submit1(ctx, &cb);
    let copy = cb;
    say("a pending POLL, through a copy of its iocb", cancel(ctx, &raw const copy as i64, 0));
    say("  then through the iocb", cancel(ctx, &raw const cb as i64, 0));
    reap1(ctx);
    let efd = eventfd(0, libc::EFD_NONBLOCK);
    let cb = Iocb { flags: FLAG_RESFD, resfd: efd as u32, ..poll_cb(p[0], libc::POLLIN as u64) };
    submit1(ctx, &cb);
    cancel(ctx, &raw const cb as i64, 0);
    reap1(ctx);
    say("a cancelled POLL with RESFD: counter", read_eventfd(efd));
    close(efd);
    let one = poll_cb(p[0], libc::POLLIN as u64);
    let two = poll_cb(p[0], libc::POLLIN as u64);
    submit(ctx, &[&one, &two]);
    say("two pending POLLs on one pipe, cancel the first", cancel(ctx, &raw const one as i64, 0));
    say("  getevents", getevents(ctx, 1, 4, e, Some(&[1, 0])));
    show("  the event is the first", ev[0].obj == &raw const one as u64);
    wr(p[1], b"x");
    say("  a write, getevents", getevents(ctx, 1, 4, e, Some(&[1, 0])));
    show("  the event is the second", ev[0].obj == &raw const two as u64);
    say("  res, after a pipe write woke it", ev[0].res);
    close(p[0]);
    close(p[1]);
    destroy(ctx);
}

fn destroy_cases(fd: i32) {
    println!("## io_destroy");
    let (_, ctx) = setup(4);
    let mut ev = [Event::default(); 4];
    let e = ev.as_mut_ptr();
    let w = rw(PWRITE, fd, b"d".as_ptr() as u64, 1, 80);
    submit1(ctx, &w);
    say("io_destroy with an unreaped event", destroy(ctx));
    show("  the ring is unmapped", maps_line(ctx));
    say("  io_destroy again", destroy(ctx));
    say("  io_submit", submit1(ctx, &w));
    say("  io_getevents", getevents(ctx, 0, 1, e, Some(&ZERO)));
    say("  io_cancel", cancel(ctx, &raw const w as i64, 0));
    say("io_destroy(0)", destroy(0));
    say("io_destroy(unmapped)", destroy(0x10000));
    say("io_destroy(a plain page)", destroy(page(libc::PROT_READ | libc::PROT_WRITE)));

    let (_, ctx) = setup(4);
    let p = pipe(0);
    let cb = poll_cb(p[0], libc::POLLIN as u64);
    submit1(ctx, &cb);
    say("io_destroy with a pending POLL", destroy(ctx));
    wr(p[1], b"x");
    close(p[0]);
    close(p[1]);

    let (_, ctx) = setup(4);
    let c = ctx;
    let t = std::thread::spawn(move || {
        let mut ev = [Event::default(); 1];
        let start = Instant::now();
        let n = getevents(c, 1, 1, ev.as_mut_ptr(), Some(&[3, 0]));
        (n, start.elapsed())
    });
    std::thread::sleep(Duration::from_millis(50));
    say("io_destroy while another thread waits", destroy(ctx));
    let (n, took) = t.join().unwrap();
    say("  the waiter answers", n);
    show("  and returned before its timeout", took < Duration::from_secs(2));

    let (_, ctx) = setup(4);
    let pages = 1;
    say("munmap the ring", unsafe { libc::munmap(ctx as *mut _, pages * 4096) } as i64);
    say("  io_submit", submit1(ctx, &w));
    say("  io_getevents", getevents(ctx, 0, 1, e, Some(&ZERO)));
    say("  io_destroy", destroy(ctx));

    let (_, ctx) = setup(4);
    let id = ring(ctx)[0];
    ring_word(ctx, 0).store(id + 1000, Ordering::SeqCst);
    say("ring.id scribbled: io_submit", submit1(ctx, &w));
    say("  io_destroy", destroy(ctx));
    ring_word(ctx, 0).store(id, Ordering::SeqCst);
    say("  restored: io_submit", submit1(ctx, &w));
    say("  io_destroy", destroy(ctx));

    let (_, ctx) = setup(4);
    say("mprotect the ring read-only", unsafe { libc::mprotect(ctx as *mut _, 4096, libc::PROT_READ) } as i64);
    say("  io_submit", submit1(ctx, &w));
    say("  io_getevents", getevents(ctx, 1, 1, e, Some(&[1, 0])));
    show("  maps line", maps_line(ctx));
    say("  io_destroy", destroy(ctx));
    let (_, ctx) = setup(4);
    let moved = unsafe { libc::mremap(ctx as *mut _, 4096, 4096, libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED, (ctx + 0x100000) as *mut libc::c_void) as u64 };
    show("mremap the ring: moved", moved == ctx + 0x100000);
    say("  io_submit at the old address", submit1(ctx, &w));
    say("  io_submit at the new address", submit1(ctx + 0x100000, &w));
    say("  io_destroy at the new address", destroy(ctx + 0x100000));
    show("  the moved ring", maps_line(ctx + 0x100000));
    destroy(ctx);
}

fn lifetime_cases(fd: i32) {
    println!("## threads, fork and exec");
    let (_, ctx) = setup(8);
    let w = rw(PWRITE, fd, b"t".as_ptr() as u64, 1, 90);
    let c = ctx;
    let r = std::thread::spawn(move || submit1(c, &w)).join().unwrap();
    say("another thread submits to the context", r);
    say("  this thread reaps", reap1(ctx).0);

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let mut ev = [Event::default(); 1];
        say("child: io_submit on the parent's ctx", submit1(ctx, &w));
        say("child: io_getevents", getevents(ctx, 0, 1, ev.as_mut_ptr(), Some(&ZERO)));
        say("child: io_destroy", destroy(ctx));
        show("child: the ring", maps_line(ctx));
        let (r, c) = setup(1);
        say("child: io_setup", r);
        show("child: its ring id", ring(c)[0]);
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    say("parent: io_submit after the child", submit1(ctx, &w));
    say("parent: reap", reap1(ctx).0);
    destroy(ctx);

    let half = max_nr() / 2 + 1;
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, _) = setup(half);
        if r != 0 {
            println!("  child: io_setup(half) {}", self::r(r));
        }
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    let (r, c) = setup(half);
    say("a child made half the budget and exited: io_setup(half)", r);
    if r == 0 {
        destroy(c);
    }

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, _) = setup(half);
        if r != 0 {
            println!("  child: io_setup(half) {}", self::r(r));
        }
        let exe = c"/proc/self/exe";
        let argv = [c"aio_probe".as_ptr(), c"--after-exec".as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        unsafe { libc::execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        unsafe { libc::_exit(1) };
    }
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
}

fn after_exec() {
    let (r, c) = setup(max_nr() / 2 + 1);
    say("after execve: io_setup(half)", r);
    show("after execve: rings mapped besides the new one", maps_count("[aio]") - usize::from(r == 0));
    if r == 0 {
        destroy(c);
    }
}
