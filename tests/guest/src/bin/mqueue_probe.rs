//! What the POSIX message queue syscalls (`mq_open`, `mq_unlink`,
//! `mq_timedsend`, `mq_timedreceive`, `mq_notify`, `mq_getsetattr`) and the
//! descriptor they hand out answer.
//!
//! One line per case, nothing asserted: `probe_diff.sh` compares the lines
//! against a real kernel. Raw `svc` throughout, because musl's wrappers strip a
//! leading `/` from the name and the probe is about what the kernel does with
//! it.
//!
//! # What is printed and what is not
//!
//! Descriptor numbers, pids and inode numbers are not comparable, so a case
//! prints `ok` for a descriptor and `self` for a pid that is the caller's.
//! The limit cases run in a child that has dropped to uid 65534: a root in a
//! container has no `CAP_SYS_RESOURCE`, the emulator's root has every
//! capability, and the unprivileged answer is the one both can give.

use std::ffi::CStr;
use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};

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
        1 => "EPERM", 2 => "ENOENT", 4 => "EINTR", 9 => "EBADF", 11 => "EAGAIN",
        12 => "ENOMEM", 13 => "EACCES", 14 => "EFAULT", 16 => "EBUSY", 17 => "EEXIST",
        19 => "ENODEV", 20 => "ENOTDIR", 21 => "EISDIR", 22 => "EINVAL", 24 => "EMFILE",
        25 => "ENOTTY", 28 => "ENOSPC", 29 => "ESPIPE", 36 => "ENAMETOOLONG", 38 => "ENOSYS",
        75 => "EOVERFLOW", 88 => "ENOTSOCK", 90 => "EMSGSIZE", 95 => "EOPNOTSUPP",
        110 => "ETIMEDOUT", 111 => "ECONNREFUSED",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 && v > -4096 { format!("-{}", errname(-v as i32)) } else { v.to_string() }
}

/// A descriptor prints as `ok`: the number is not the point.
/// A libc call's answer as the raw syscall's: `-1` becomes `-errno`.
fn lc(v: i64) -> i64 {
    if v == -1 { -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64) } else { v }
}

fn rfd(v: i64) -> String {
    if v >= 0 { "ok".into() } else { r(v) }
}

fn say(what: &str, v: i64) {
    show(what, r(v));
}

fn sayfd(what: &str, v: i64) {
    show(what, rfd(v));
}

fn show(what: &str, v: String) {
    println!("  {what:<62} {v}");
    let _ = std::io::stdout().flush();
}

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
const O_CLOEXEC: i64 = 0o2000000;

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
const SIGEV_THREAD_ID: i32 = 4;

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
    rest: [u8; 48],
}

fn sigev(notify: i32, signo: i32, value: u64) -> Sigevent {
    Sigevent { value, signo, notify, rest: [0; 48] }
}

fn open(name: &CStr, oflag: i64, mode: i64, a: Option<&Attr>) -> i64 {
    let ap = a.map_or(0, |a| a as *const Attr as i64);
    unsafe { sys(NR_MQ_OPEN, name.as_ptr() as i64, oflag, mode, ap, 0, 0) }
}

fn unlink(name: &CStr) -> i64 {
    unsafe { sys(NR_MQ_UNLINK, name.as_ptr() as i64, 0, 0, 0, 0, 0) }
}

fn send(fd: i64, msg: &[u8], prio: i64, ts: Option<&[i64; 2]>) -> i64 {
    let tp = ts.map_or(0, |t| t.as_ptr() as i64);
    unsafe { sys(NR_MQ_TIMEDSEND, fd, msg.as_ptr() as i64, msg.len() as i64, prio, tp, 0) }
}

fn recv(fd: i64, buf: &mut [u8], prio: Option<&mut u32>, ts: Option<&[i64; 2]>) -> i64 {
    let pp = prio.map_or(0, |p| p as *mut u32 as i64);
    let tp = ts.map_or(0, |t| t.as_ptr() as i64);
    unsafe { sys(NR_MQ_TIMEDRECEIVE, fd, buf.as_mut_ptr() as i64, buf.len() as i64, pp, tp, 0) }
}

fn notify(fd: i64, ev: Option<&Sigevent>) -> i64 {
    let p = ev.map_or(0, |e| e as *const Sigevent as i64);
    unsafe { sys(NR_MQ_NOTIFY, fd, p, 0, 0, 0, 0) }
}

fn getattr(fd: i64) -> Result<Attr, i64> {
    let mut a = Attr::default();
    let v = unsafe { sys(NR_MQ_GETSETATTR, fd, 0, &mut a as *mut Attr as i64, 0, 0, 0) };
    if v < 0 { Err(v) } else { Ok(a) }
}

fn attr_text(fd: i64) -> String {
    match getattr(fd) {
        Ok(a) => format!(
            "flags={:#o} maxmsg={} msgsize={} curmsgs={}",
            a.flags, a.maxmsg, a.msgsize, a.curmsgs
        ),
        Err(e) => r(e),
    }
}

fn close(fd: i64) {
    unsafe { libc::close(fd as i32) };
}

fn now() -> [i64; 2] {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    [ts.tv_sec, ts.tv_nsec]
}

fn plus_ms(mut t: [i64; 2], ms: i64) -> [i64; 2] {
    t[1] += ms * 1_000_000;
    while t[1] >= 1_000_000_000 {
        t[1] -= 1_000_000_000;
        t[0] += 1;
    }
    while t[1] < 0 {
        t[1] += 1_000_000_000;
        t[0] -= 1;
    }
    t
}

fn gettid() -> i64 {
    unsafe { sys(178, 0, 0, 0, 0, 0, 0) }
}

fn getpid() -> i64 {
    unsafe { libc::getpid() as i64 }
}

/// The status line `read` gives, with the notifying pid named rather than
/// printed.
fn status(fd: i64) -> String {
    let mut buf = [0u8; 200];
    unsafe { libc::lseek(fd as i32, 0, libc::SEEK_SET) };
    let n = unsafe { libc::read(fd as i32, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return r(-(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64));
    }
    let text = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
    let me = format!("NOTIFY_PID:{:<6}", getpid());
    format!("{:?}", text.replace(&me, "NOTIFY_PID:self  "))
}

/// A region whose last `room` bytes before an inaccessible page are readable:
/// where a struct the kernel copies whole is placed to see how much it copies.
fn at_page_end(room: usize) -> *mut u8 {
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            8192,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        ) as *mut u8;
        libc::mprotect(p.add(4096).cast(), 4096, libc::PROT_NONE);
        p.add(4096 - room)
    }
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
    unsafe { sys(135, 0, &mask as *const u64 as i64, 0, 8, 0, 0) };
}

/// `rt_sigtimedwait` for one signal, with a timeout in milliseconds. The
/// siginfo's interesting fields as text, or the errno.
fn take_signal(sig: i32, ms: i64) -> String {
    let mask: u64 = 1 << (sig - 1);
    let ts = [ms / 1000, (ms % 1000) * 1_000_000];
    let mut info = [0u8; 128];
    let v = unsafe {
        sys(137, &mask as *const u64 as i64, info.as_mut_ptr() as i64, ts.as_ptr() as i64, 8, 0, 0)
    };
    if v < 0 {
        return r(v);
    }
    let w = |at: usize| i32::from_le_bytes(info[at..at + 4].try_into().unwrap());
    let value = u64::from_le_bytes(info[24..32].try_into().unwrap());
    let pid = w(16) as i64;
    let pid = if pid == getpid() { "self".to_string() } else { format!("other({})", pid > 0) };
    format!(
        "signo={} errno={} code={} pid={} uid={} value={:#x}",
        w(0), w(4), w(8), pid, w(20), value
    )
}

fn main() {
    println!("## POSIX message queues");
    // A run that died half way must not leave queues the next one trips over.
    for n in [c"mqp_a", c"mqp_b", c"mqp_c", c"mqp_d", c"mqp_e", c"mqp_x"] {
        unlink(n);
    }
    unsafe { libc::umask(0o022) };
    names();
    access_modes();
    attrs();
    descriptor();
    send_receive();
    timeouts();
    blocking();
    notifications();
    getsetattr();
    lifetime();
    unprivileged();
    filesystem();
}

fn names() {
    println!("## names");
    let q = open(c"mqp_a", O_CREAT | O_RDWR, 0o600, None);
    sayfd("create mqp_a", q);
    close(q);
    sayfd("reopen mqp_a", { let f = open(c"mqp_a", O_RDWR, 0, None); close(f); f });
    say("O_CREAT|O_EXCL on an existing name", open(c"mqp_a", O_CREAT | O_EXCL | O_RDWR, 0o600, None));
    sayfd("O_CREAT on an existing name", { let f = open(c"mqp_a", O_CREAT | O_RDWR, 0o600, None); close(f); f });
    say("open a missing name", open(c"mqp_missing", O_RDWR, 0, None));
    say("leading slash, O_CREAT", open(c"/mqp_slash", O_CREAT | O_RDWR, 0o600, None));
    say("leading slash, existing", open(c"/mqp_a", O_RDWR, 0, None));
    say("embedded slash", open(c"mq/p", O_CREAT | O_RDWR, 0o600, None));
    say("empty name", open(c"", O_CREAT | O_RDWR, 0o600, None));
    say("\".\"", open(c".", O_CREAT | O_RDWR, 0o600, None));
    say("\"..\"", open(c"..", O_CREAT | O_RDWR, 0o600, None));
    say("\"...\"", { let f = open(c"...", O_CREAT | O_RDWR, 0o600, None); close(f); unlink(c"..."); if f >= 0 { 0 } else { f } });
    let long255 = std::ffi::CString::new("n".repeat(255)).unwrap();
    let long256 = std::ffi::CString::new("n".repeat(256)).unwrap();
    let long4096 = std::ffi::CString::new("n".repeat(4096)).unwrap();
    let f = open(&long255, O_CREAT | O_RDWR, 0o600, None);
    sayfd("a 255-byte name", f);
    close(f);
    say("unlink the 255-byte name", unlink(&long255));
    say("a 256-byte name", open(&long256, O_CREAT | O_RDWR, 0o600, None));
    say("a 4096-byte name", open(&long4096, O_CREAT | O_RDWR, 0o600, None));
    say("a null name", unsafe { sys(NR_MQ_OPEN, 0, O_CREAT | O_RDWR, 0o600, 0, 0, 0) });
    say("an unmapped name", unsafe { sys(NR_MQ_OPEN, 16, O_CREAT | O_RDWR, 0o600, 0, 0, 0) });
    say("unlink a missing name", unlink(c"mqp_missing"));
    say("unlink with a leading slash", unlink(c"/mqp_a"));
    say("unlink \"\"", unlink(c""));
    say("unlink \".\"", unlink(c"."));
    say("unlink \"..\"", unlink(c".."));
    say("unlink a 256-byte name", unlink(&long256));
    say("unlink null", unsafe { sys(NR_MQ_UNLINK, 0, 0, 0, 0, 0, 0) });
    say("unlink mqp_a", unlink(c"mqp_a"));
    say("unlink mqp_a again", unlink(c"mqp_a"));
}

fn access_modes() {
    println!("## access modes");
    let q = open(c"mqp_b", O_CREAT | O_RDWR, 0o600, Some(&attr(4, 16)));
    sayfd("create", q);
    let ro = open(c"mqp_b", O_RDONLY, 0, None);
    let wo = open(c"mqp_b", O_WRONLY, 0, None);
    sayfd("O_RDONLY", ro);
    sayfd("O_WRONLY", wo);
    say("existing, O_ACCMODE 3", open(c"mqp_b", 3, 0, None));
    say("existing, O_CREAT | 3", open(c"mqp_b", O_CREAT | 3, 0o600, None));
    say("send on O_RDONLY", send(ro, b"x", 0, None));
    say("send on O_WRONLY", send(wo, b"x", 0, None));
    let mut buf = [0u8; 16];
    say("receive on O_WRONLY", recv(wo, &mut buf, None, None));
    say("receive on O_RDONLY", recv(ro, &mut buf, None, None));
    say("notify on O_WRONLY, SIGEV_NONE", notify(wo, Some(&sigev(SIGEV_NONE, 0, 0))));
    say("  and NULL from the same process", notify(wo, None));
    show("F_GETFL O_RDONLY", format!("{:#o}", unsafe { libc::fcntl(ro as i32, libc::F_GETFL) }));
    show("F_GETFL O_WRONLY", format!("{:#o}", unsafe { libc::fcntl(wo as i32, libc::F_GETFL) }));
    show("F_GETFL O_RDWR", format!("{:#o}", unsafe { libc::fcntl(q as i32, libc::F_GETFL) }));
    close(ro);
    close(wo);
    close(q);
    unlink(c"mqp_b");

    // Created with access mode 3: Linux checks the mode only for an existing
    // queue, so the create goes through and the description can do neither.
    let q3 = open(c"mqp_b", O_CREAT | 3, 0o600, Some(&attr(4, 16)));
    sayfd("create with O_ACCMODE 3", q3);
    if q3 >= 0 {
        show("  F_GETFL", format!("{:#o}", unsafe { libc::fcntl(q3 as i32, libc::F_GETFL) }));
        say("  send", send(q3, b"x", 0, None));
        say("  receive", recv(q3, &mut buf, None, None));
        show("  getsetattr", attr_text(q3));
        say("  notify SIGEV_NONE", notify(q3, Some(&sigev(SIGEV_NONE, 0, 0))));
        say("  read", lc(unsafe { libc::read(q3 as i32, buf.as_mut_ptr().cast(), 16) as i64 }));
        say("  pread", lc(unsafe { libc::pread(q3 as i32, buf.as_mut_ptr().cast(), 16, 0) as i64 }));
        say("  write", lc(unsafe { libc::write(q3 as i32, buf.as_ptr().cast(), 1) as i64 }));
        say("  lseek", lc(unsafe { libc::lseek(q3 as i32, 0, libc::SEEK_END) }));
        say("  ftruncate", lc(unsafe { libc::ftruncate(q3 as i32, 0) as i64 }));
        show("  poll", poll_text(q3));
        close(q3);
    }
    unlink(c"mqp_b");

    let f = open(c"mqp_b", O_CREAT | O_RDWR | O_CLOEXEC, 0o600, None);
    show("O_CLOEXEC: F_GETFD", format!("{}", unsafe { libc::fcntl(f as i32, libc::F_GETFD) }));
    show("O_CLOEXEC: F_GETFL", format!("{:#o}", unsafe { libc::fcntl(f as i32, libc::F_GETFL) }));
    say("F_SETFD 0", lc(unsafe { libc::fcntl(f as i32, libc::F_SETFD, 0) } as i64));
    show("  F_GETFD after", format!("{}", unsafe { libc::fcntl(f as i32, libc::F_GETFD) }));
    close(f);
    let f = open(c"mqp_b", O_RDWR, 0, None);
    show("no O_CLOEXEC: F_GETFD", format!("{}", unsafe { libc::fcntl(f as i32, libc::F_GETFD) }));
    close(f);
    let f = open(c"mqp_b", O_RDWR | O_NONBLOCK, 0, None);
    show("O_NONBLOCK: F_GETFL", format!("{:#o}", unsafe { libc::fcntl(f as i32, libc::F_GETFL) }));
    show("O_NONBLOCK: getsetattr", attr_text(f));
    close(f);
    let f = open(c"mqp_b", O_RDWR | 0o1000 | 0o2000 | 0o400, 0, None);
    sayfd("O_TRUNC | O_APPEND | O_NOCTTY", f);
    if f >= 0 {
        show("  F_GETFL", format!("{:#o}", unsafe { libc::fcntl(f as i32, libc::F_GETFL) }));
    }
    close(f);
    unlink(c"mqp_b");
}

fn attrs() {
    println!("## attributes");
    let cases: [(&str, i64, i64); 10] = [
        ("maxmsg 0", 0, 16),
        ("msgsize 0", 4, 0),
        ("maxmsg -1", -1, 16),
        ("msgsize -1", 4, -1),
        ("maxmsg 1 msgsize 1", 1, 1),
        ("maxmsg 10 msgsize 8192", 10, 8192),
        ("maxmsg 1<<40", 1 << 40, 1),
        ("msgsize 1<<40", 1, 1 << 40),
        ("maxmsg 5 msgsize 100", 5, 100),
        ("maxmsg i64::MIN", i64::MIN, 1),
    ];
    for (what, m, s) in cases {
        let f = open(c"mqp_c", O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(m, s)));
        if f >= 0 {
            show(what, format!("ok, {}", attr_text(f)));
            close(f);
            unlink(c"mqp_c");
        } else {
            say(what, f);
        }
    }
    let mut a = attr(3, 7);
    a.flags = O_NONBLOCK;
    a.curmsgs = 99;
    a.reserved = [1, 2, 3, 4];
    let f = open(c"mqp_c", O_CREAT | O_RDWR, 0o600, Some(&a));
    show("flags, curmsgs and reserved set in the attr", if f >= 0 { attr_text(f) } else { r(f) });
    close(f);
    let f = open(c"mqp_c", O_CREAT | O_RDWR, 0o600, Some(&attr(0, 0)));
    show("bad attr on an existing queue", if f >= 0 { attr_text(f) } else { r(f) });
    close(f);
    let f = open(c"mqp_c", O_RDWR, 0o600, Some(&attr(-5, -5)));
    show("bad attr without O_CREAT, existing", if f >= 0 { attr_text(f) } else { r(f) });
    close(f);
    unlink(c"mqp_c");
    say("bad attr without O_CREAT, missing", open(c"mqp_c", O_RDWR, 0o600, Some(&attr(0, 0))));
    let f = open(c"mqp_c", O_CREAT | O_RDWR, 0o600, None);
    show("NULL attr: the defaults", attr_text(f));
    close(f);
    unlink(c"mqp_c");
    say("attr unmapped, missing", unsafe {
        sys(NR_MQ_OPEN, c"mqp_c".as_ptr() as i64, O_CREAT | O_RDWR, 0o600, 16, 0, 0)
    });
    say("attr unmapped, without O_CREAT", unsafe {
        sys(NR_MQ_OPEN, c"mqp_c".as_ptr() as i64, O_RDWR, 0o600, 16, 0, 0)
    });
    // 32 readable bytes: maxmsg and msgsize are in them, the reserved words
    // are not. Whether this fails says how much of the struct is copied.
    let p = at_page_end(32);
    unsafe { std::ptr::copy_nonoverlapping(&attr(2, 2) as *const Attr as *const u8, p, 32) };
    say("attr with only 32 bytes readable", unsafe {
        sys(NR_MQ_OPEN, c"mqp_c".as_ptr() as i64, O_CREAT | O_RDWR, 0o600, p as i64, 0, 0)
    });
    unlink(c"mqp_c");
    let p = at_page_end(64);
    unsafe { std::ptr::copy_nonoverlapping(&attr(2, 2) as *const Attr as *const u8, p, 64) };
    let f = unsafe { sys(NR_MQ_OPEN, c"mqp_c".as_ptr() as i64, O_CREAT | O_RDWR, 0o600, p as i64, 0, 0) };
    sayfd("attr with exactly 64 bytes readable", f);
    close(f);
    unlink(c"mqp_c");
}

fn stat_text(fd: i64) -> String {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd as i32, &mut st) } != 0 {
        return r(-(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64));
    }
    format!(
        "mode={:#o} size={} nlink={} uid={} gid={} blksize={} blocks={} rdev={}",
        st.st_mode, st.st_size, st.st_nlink, st.st_uid, st.st_gid, st.st_blksize, st.st_blocks,
        st.st_rdev
    )
}

fn link_text(fd: i64) -> String {
    let path = std::ffi::CString::new(format!("/proc/self/fd/{fd}")).unwrap();
    let mut buf = [0u8; 300];
    let n = unsafe { libc::readlink(path.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return r(-(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64));
    }
    format!("{:?}", String::from_utf8_lossy(&buf[..n as usize]))
}

fn poll_text(fd: i64) -> String {
    let mut p = libc::pollfd { fd: fd as i32, events: libc::POLLIN | libc::POLLOUT | libc::POLLPRI, revents: 0 };
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    format!("{n} revents={:#x}", p.revents)
}

fn descriptor() {
    println!("## the descriptor");
    let q = open(c"mqp_d", O_CREAT | O_RDWR, 0o777, Some(&attr(2, 8)));
    show("fstat, mode 0777 under umask 022", stat_text(q));
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    let v = unsafe { libc::fstatfs(q as i32, &mut sfs) };
    show("fstatfs", if v == 0 { format!("type={:#x} bsize={} namelen={}", sfs.f_type, sfs.f_bsize, sfs.f_namelen) } else { "failed".into() });
    show("/proc/self/fd link", link_text(q));
    show("status, empty", status(q));
    let mut buf = [0u8; 100];
    unsafe { libc::lseek(q as i32, 0, libc::SEEK_SET) };
    say("read 10 bytes", unsafe { libc::read(q as i32, buf.as_mut_ptr().cast(), 10) as i64 });
    show("  which are", format!("{:?}", String::from_utf8_lossy(&buf[..10])));
    say("read the rest", unsafe { libc::read(q as i32, buf.as_mut_ptr().cast(), 100) as i64 });
    say("read at the end", unsafe { libc::read(q as i32, buf.as_mut_ptr().cast(), 100) as i64 });
    say("lseek SEEK_CUR 0", unsafe { libc::lseek(q as i32, 0, libc::SEEK_CUR) });
    say("lseek SEEK_END 0", unsafe { libc::lseek(q as i32, 0, libc::SEEK_END) });
    say("pread at 0", {
        let n = unsafe { libc::pread(q as i32, buf.as_mut_ptr().cast(), 100, 0) as i64 };
        if n < 0 { -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64) } else { n }
    });
    say("write", {
        let n = unsafe { libc::write(q as i32, b"hello".as_ptr().cast(), 5) as i64 };
        if n < 0 { -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64) } else { n }
    });
    say("ioctl FIONREAD", {
        let mut n = 0i32;
        let v = unsafe { libc::ioctl(q as i32, libc::FIONREAD, &mut n) as i64 };
        if v < 0 { -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64) } else { v }
    });
    say("mmap", {
        let p = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ, libc::MAP_SHARED, q as i32, 0) };
        if p == libc::MAP_FAILED { -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64) } else { 0 }
    });
    say("fchmod 0640", {
        let v = unsafe { libc::fchmod(q as i32, 0o640) as i64 };
        if v < 0 { -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64) } else { v }
    });
    show("  fstat after", stat_text(q));
    say("ftruncate 1000", lc(unsafe { libc::ftruncate(q as i32, 1000) as i64 }));
    show("  fstat after", stat_text(q));
    say("  lseek SEEK_END", lc(unsafe { libc::lseek(q as i32, 0, libc::SEEK_END) }));
    say("  pread at 0", lc(unsafe { libc::pread(q as i32, buf.as_mut_ptr().cast(), 100, 0) as i64 }));
    say("ftruncate -1", lc(unsafe { libc::ftruncate(q as i32, -1) as i64 }));
    say("ftruncate", {
        let v = unsafe { libc::ftruncate(q as i32, 0) as i64 };
        if v < 0 { -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64) } else { v }
    });
    say("pread at -1", lc(unsafe { libc::pread(q as i32, buf.as_mut_ptr().cast(), 100, -1) as i64 }));
    say("pread at 79", lc(unsafe { libc::pread(q as i32, buf.as_mut_ptr().cast(), 100, 79) as i64 }));
    say("pread at 1000", lc(unsafe { libc::pread(q as i32, buf.as_mut_ptr().cast(), 100, 1000) as i64 }));
    say("lseek SEEK_SET -1", lc(unsafe { libc::lseek(q as i32, -1, libc::SEEK_SET) }));
    say("lseek SEEK_SET 1<<40", lc(unsafe { libc::lseek(q as i32, 1 << 40, libc::SEEK_SET) }));
    say("  read there", lc(unsafe { libc::read(q as i32, buf.as_mut_ptr().cast(), 100) as i64 }));
    say("lseek SEEK_DATA 0", lc(unsafe { libc::lseek(q as i32, 0, libc::SEEK_DATA) }));
    let mut tv = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }, libc::timespec { tv_sec: 5, tv_nsec: 0 }];
    say("futimens", lc(unsafe { libc::futimens(q as i32, tv.as_mut_ptr()) } as i64));
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(q as i32, &mut st) };
    show("  mtime", format!("{}", st.st_mtime));
    say("fchown 1,1", lc(unsafe { libc::fchown(q as i32, 1, 1) } as i64));
    show("  fstat after", stat_text(q));
    unsafe { libc::fchown(q as i32, 0, 0) };
    say("fsync", {
        let v = unsafe { libc::fsync(q as i32) as i64 };
        if v < 0 { -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64) } else { v }
    });
    show("poll, empty", poll_text(q));
    send(q, b"12345", 3, None);
    show("poll, one of two", poll_text(q));
    show("status, 5 bytes queued", status(q));
    send(q, b"abc", 1, None);
    show("poll, full", poll_text(q));
    show("status, 8 bytes queued", status(q));
    show("fstat, 8 bytes queued", stat_text(q));
    let mut n = -7i32;
    unsafe { libc::lseek(q as i32, 3, libc::SEEK_SET) };
    let v = lc(unsafe { libc::ioctl(q as i32, libc::FIONREAD, &mut n) } as i64);
    show("FIONREAD at offset 3", format!("{} n={}", r(v), n));
    let ro = open(c"mqp_d", O_RDONLY, 0, None);
    let wo = open(c"mqp_d", O_WRONLY, 0, None);
    show("poll O_RDONLY, full", poll_text(ro));
    show("poll O_WRONLY, full", poll_text(wo));
    say("read on O_WRONLY", {
        let n = unsafe { libc::read(wo as i32, buf.as_mut_ptr().cast(), 100) as i64 };
        if n < 0 { -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64) } else { n }
    });
    say("pread on O_WRONLY", lc(unsafe { libc::pread(wo as i32, buf.as_mut_ptr().cast(), 100, 0) as i64 }));
    say("lseek on O_WRONLY", lc(unsafe { libc::lseek(wo as i32, 0, libc::SEEK_END) }));
    say("ftruncate on O_RDONLY", lc(unsafe { libc::ftruncate(ro as i32, 0) as i64 }));
    say("write on O_RDONLY", {
        let n = unsafe { libc::write(ro as i32, b"x".as_ptr().cast(), 1) as i64 };
        if n < 0 { -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64) } else { n }
    });
    close(ro);
    close(wo);
    let d = unsafe { libc::dup(q as i32) } as i64;
    unsafe { libc::fcntl(d as i32, libc::F_SETFL, libc::O_NONBLOCK) };
    show("F_SETFL O_NONBLOCK on a dup: getsetattr on the original", attr_text(q));
    unsafe { libc::fcntl(d as i32, libc::F_SETFL, 0) };
    close(d);
    say("unlink while open", unlink(c"mqp_d"));
    show("/proc/self/fd link after unlink", link_text(q));
    show("fstat after unlink", stat_text(q));
    close(q);
    // The remaining modes.
    for mode in [0o7777i64, 0o4755, 0o1700, 0o000] {
        let f = open(c"mqp_d", O_CREAT | O_RDWR, mode, None);
        show(&format!("fstat, mode {mode:#o}"), stat_text(f));
        close(f);
        unlink(c"mqp_d");
    }
    unsafe { libc::umask(0) };
    let f = open(c"mqp_d", O_CREAT | O_RDWR, 0o777, None);
    show("fstat, mode 0777 under umask 0", stat_text(f));
    close(f);
    unlink(c"mqp_d");
    unsafe { libc::umask(0o022) };
}

fn send_receive() {
    println!("## send and receive");
    let q = open(c"mqp_e", O_CREAT | O_RDWR, 0o600, Some(&attr(8, 16)));
    let mut buf = [0u8; 64];
    let mut prio = 0u32;
    say("prio 32768", send(q, b"x", 32768, None));
    say("prio u32::MAX", send(q, b"x", 0xffff_ffff, None));
    say("prio 1<<32 (the high half of the register)", send(q, b"x", 1 << 32, None));
    say("prio 32767", send(q, b"top", 32767, None));
    say("17 bytes into 16", send(q, &[0u8; 17], 0, None));
    say("16 bytes", send(q, &[7u8; 16], 0, None));
    say("0 bytes", send(q, b"", 0, None));
    say("0 bytes from an unmapped pointer", unsafe { sys(NR_MQ_TIMEDSEND, q, 16, 0, 0, 0, 0) });
    say("1 byte from an unmapped pointer", unsafe { sys(NR_MQ_TIMEDSEND, q, 16, 1, 0, 0, 0) });
    say("length u64::MAX", unsafe { sys(NR_MQ_TIMEDSEND, q, buf.as_ptr() as i64, -1, 0, 0, 0) });
    show("curmsgs", attr_text(q));
    say("receive into 15", recv(q, &mut buf[..15], None, None));
    say("receive into u64::MAX", unsafe { sys(NR_MQ_TIMEDRECEIVE, q, buf.as_mut_ptr() as i64, -1, 0, 0, 0) });
    show("  curmsgs", attr_text(q));
    // Drain in order.
    let mut order = Vec::new();
    loop {
        let mut nb = Attr::default();
        nb.flags = O_NONBLOCK;
        unsafe { sys(NR_MQ_GETSETATTR, q, &nb as *const Attr as i64, 0, 0, 0, 0) };
        let n = recv(q, &mut buf[..16], Some(&mut prio), None);
        if n < 0 {
            order.push(r(n));
            break;
        }
        order.push(format!("{}:{}", prio, n));
    }
    show("drained", order.join(" "));
    // Priority order, FIFO within one.
    let mut nb = Attr::default();
    unsafe { sys(NR_MQ_GETSETATTR, q, &nb as *const Attr as i64, 0, 0, 0, 0) };
    for (m, p) in [(b"a", 1i64), (b"b", 5), (b"c", 5), (b"d", 3), (b"e", 0), (b"f", 5), (b"g", 0)] {
        send(q, m, p, None);
    }
    let mut got = String::new();
    for _ in 0..7 {
        let n = recv(q, &mut buf[..16], Some(&mut prio), None);
        if n > 0 {
            got.push_str(&format!("{}{} ", buf[0] as char, prio));
        } else {
            got.push_str(&r(n));
        }
    }
    show("order", got);
    nb.flags = O_NONBLOCK;
    unsafe { sys(NR_MQ_GETSETATTR, q, &nb as *const Attr as i64, 0, 0, 0, 0) };
    say("receive from empty, O_NONBLOCK", recv(q, &mut buf[..16], None, None));
    for _ in 0..8 {
        send(q, b"f", 0, None);
    }
    say("send to full, O_NONBLOCK", send(q, b"f", 0, None));
    say("receive into an unmapped buffer", unsafe { sys(NR_MQ_TIMEDRECEIVE, q, 16, 16, 0, 0, 0) });
    show("  curmsgs after", attr_text(q));
    say("receive with an unmapped prio", unsafe { sys(NR_MQ_TIMEDRECEIVE, q, buf.as_mut_ptr() as i64, 16, 16, 0, 0) });
    show("  curmsgs after", attr_text(q));
    say("send on fd -1", send(-1, b"x", 0, None));
    say("send on fd 1000", send(1000, b"x", 0, None));
    say("send on stdout", send(1, b"x", 0, None));
    say("receive on stdout", recv(1, &mut buf[..16], None, None));
    say("prio 32768 on fd -1", send(-1, b"x", 32768, None));
    say("17 bytes on fd -1", send(-1, &[0u8; 17], 0, None));
    close(q);
    unlink(c"mqp_e");
}

fn timeouts() {
    println!("## timeouts");
    let q = open(c"mqp_e", O_CREAT | O_RDWR, 0o600, Some(&attr(1, 16)));
    let mut buf = [0u8; 16];
    let past = [1i64, 0];
    let bad_nsec = [now()[0] + 10, 1_000_000_000];
    let neg_nsec = [now()[0] + 10, -1];
    let neg_sec = [-1i64, 0];
    say("receive, empty, deadline in the past", recv(q, &mut buf, None, Some(&past)));
    say("receive, empty, deadline at 0", recv(q, &mut buf, None, Some(&[0, 0])));
    let t0 = std::time::Instant::now();
    say("receive, empty, deadline now+60ms", recv(q, &mut buf, None, Some(&plus_ms(now(), 60))));
    show("  waited at least 50ms", format!("{}", t0.elapsed().as_millis() >= 50));
    say("receive, empty, nsec 1e9", recv(q, &mut buf, None, Some(&bad_nsec)));
    say("receive, empty, nsec -1", recv(q, &mut buf, None, Some(&neg_nsec)));
    say("receive, empty, sec -1", recv(q, &mut buf, None, Some(&neg_sec)));
    say("receive, unmapped timeout", unsafe { sys(NR_MQ_TIMEDRECEIVE, q, buf.as_mut_ptr() as i64, 16, 0, 16, 0) });
    say("send, nsec 1e9, room", send(q, b"x", 0, Some(&bad_nsec)));
    say("send, unmapped timeout, room", unsafe { sys(NR_MQ_TIMEDSEND, q, buf.as_ptr() as i64, 1, 0, 16, 0) });
    say("send, deadline in the past, room", send(q, b"x", 0, Some(&past)));
    say("send, full, deadline in the past", send(q, b"y", 0, Some(&past)));
    let t0 = std::time::Instant::now();
    say("send, full, deadline now+60ms", send(q, b"y", 0, Some(&plus_ms(now(), 60))));
    show("  waited at least 50ms", format!("{}", t0.elapsed().as_millis() >= 50));
    say("send, full, sec -1", send(q, b"y", 0, Some(&neg_sec)));
    say("receive, one queued, nsec 1e9", recv(q, &mut buf, None, Some(&bad_nsec)));
    say("receive, one queued, deadline in the past", recv(q, &mut buf, None, Some(&past)));
    say("send, nsec 1e9, fd -1", send(-1, b"x", 0, Some(&bad_nsec)));
    say("send, nsec 1e9, prio 32768", send(q, b"x", 32768, Some(&bad_nsec)));
    let mut nb = Attr::default();
    nb.flags = O_NONBLOCK;
    unsafe { sys(NR_MQ_GETSETATTR, q, &nb as *const Attr as i64, 0, 0, 0, 0) };
    say("receive, empty, O_NONBLOCK, nsec 1e9", recv(q, &mut buf, None, Some(&bad_nsec)));
    say("receive, empty, O_NONBLOCK, deadline in the past", recv(q, &mut buf, None, Some(&past)));
    close(q);
    unlink(c"mqp_e");
}

fn blocking() {
    println!("## blocking");
    handle(libc::SIGUSR1, 0);
    let q = open(c"mqp_e", O_CREAT | O_RDWR, 0o600, Some(&attr(1, 16)));
    let mut buf = [0u8; 16];
    let mut prio = 0u32;

    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        send(q, b"late", 9, None)
    });
    let n = recv(q, &mut buf, Some(&mut prio), Some(&plus_ms(now(), 3000)));
    show("a receiver woken by a send", format!("{} prio={} {:?}", r(n), prio, String::from_utf8_lossy(&buf[..n.max(0) as usize])));
    say("  the send", t.join().unwrap());

    send(q, b"full", 0, None);
    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        let mut b = [0u8; 16];
        recv(q, &mut b, None, None)
    });
    say("a sender woken by a receive", send(q, b"next", 2, Some(&plus_ms(now(), 3000))));
    say("  the receive", t.join().unwrap());
    show("  curmsgs", attr_text(q));
    recv(q, &mut buf, Some(&mut prio), None);
    show("  and what is queued", format!("{:?} prio={}", String::from_utf8_lossy(&buf[..4]), prio));

    let tid = gettid();
    let pid = getpid();
    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        unsafe { sys(131, pid, tid, libc::SIGUSR1 as i64, 0, 0, 0) };
    });
    HITS.store(0, Ordering::SeqCst);
    say("receive, a handler without SA_RESTART", recv(q, &mut buf, None, Some(&plus_ms(now(), 3000))));
    show("  handler ran", format!("{}", HITS.load(Ordering::SeqCst)));
    t.join().unwrap();

    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        unsafe { sys(131, pid, tid, libc::SIGUSR1 as i64, 0, 0, 0) };
    });
    HITS.store(0, Ordering::SeqCst);
    say("receive, no deadline, a handler without SA_RESTART", recv(q, &mut buf, None, None));
    t.join().unwrap();

    handle(libc::SIGUSR1, libc::SA_RESTART);
    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        unsafe { sys(131, pid, tid, libc::SIGUSR1 as i64, 0, 0, 0) };
    });
    HITS.store(0, Ordering::SeqCst);
    let t0 = std::time::Instant::now();
    say("receive, deadline now+200ms, an SA_RESTART handler", recv(q, &mut buf, None, Some(&plus_ms(now(), 200))));
    show("  handler ran", format!("{}", HITS.load(Ordering::SeqCst)));
    show("  waited at least 150ms", format!("{}", t0.elapsed().as_millis() >= 150));
    t.join().unwrap();

    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        unsafe { sys(131, pid, tid, libc::SIGUSR1 as i64, 0, 0, 0) };
        std::thread::sleep(std::time::Duration::from_millis(30));
        send(q, b"after", 0, None)
    });
    HITS.store(0, Ordering::SeqCst);
    say("receive, no deadline, SA_RESTART, then a send", recv(q, &mut buf, None, None));
    show("  handler ran", format!("{}", HITS.load(Ordering::SeqCst)));
    say("  the send", t.join().unwrap());

    send(q, b"full", 0, None);
    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        unsafe { sys(131, pid, tid, libc::SIGUSR1 as i64, 0, 0, 0) };
    });
    HITS.store(0, Ordering::SeqCst);
    let t0 = std::time::Instant::now();
    say("send to full, deadline now+200ms, SA_RESTART", send(q, b"x", 0, Some(&plus_ms(now(), 200))));
    show("  waited at least 150ms", format!("{}", t0.elapsed().as_millis() >= 150));
    t.join().unwrap();
    handle(libc::SIGUSR1, 0);
    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        unsafe { sys(131, pid, tid, libc::SIGUSR1 as i64, 0, 0, 0) };
    });
    say("send to full, no deadline, no SA_RESTART", send(q, b"x", 0, None));
    t.join().unwrap();
    close(q);
    unlink(c"mqp_e");
}

fn notifications() {
    println!("## mq_notify");
    let q = open(c"mqp_e", O_CREAT | O_RDWR, 0o600, Some(&attr(4, 16)));
    let mut buf = [0u8; 16];
    block(libc::SIGUSR2);
    say("NULL with nothing registered", notify(q, None));
    say("SIGEV_NONE", notify(q, Some(&sigev(SIGEV_NONE, 0, 0))));
    show("  status", status(q));
    say("  again", notify(q, Some(&sigev(SIGEV_NONE, 0, 0))));
    say("  SIGEV_SIGNAL while registered", notify(q, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 0))));
    send(q, b"n", 0, None);
    show("  after a send", status(q));
    recv(q, &mut buf, None, None);
    say("SIGEV_SIGNAL SIGUSR2", notify(q, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 0x1234_5678_9abc))));
    show("  status", status(q));
    send(q, b"n", 7, None);
    show("  the signal", take_signal(libc::SIGUSR2, 500));
    show("  status after", status(q));
    send(q, b"n", 0, None);
    recv(q, &mut buf, None, None);
    recv(q, &mut buf, None, None);
    show("  a second send: no signal", take_signal(libc::SIGUSR2, 0));

    // Registered on a queue that is not empty: only the empty-to-not-empty
    // transition notifies.
    send(q, b"n", 0, None);
    notify(q, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 1)));
    send(q, b"n", 0, None);
    show("registered on a non-empty queue, then a send", take_signal(libc::SIGUSR2, 0));
    show("  status", status(q));
    recv(q, &mut buf, None, None);
    recv(q, &mut buf, None, None);
    send(q, b"n", 0, None);
    show("  emptied, then a send", take_signal(libc::SIGUSR2, 200));
    recv(q, &mut buf, None, None);

    // A blocked receiver takes the message and the registration stays.
    notify(q, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 2)));
    let t = std::thread::spawn(move || {
        let mut b = [0u8; 16];
        recv(q, &mut b, None, Some(&plus_ms(now(), 3000)))
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    send(q, b"direct", 0, None);
    say("a blocked receiver", t.join().unwrap());
    show("  no signal", take_signal(libc::SIGUSR2, 0));
    show("  still registered", status(q));
    say("NULL from the owner", notify(q, None));
    show("  status", status(q));

    say("SIGEV_SIGNAL signo 0", notify(q, Some(&sigev(SIGEV_SIGNAL, 0, 0))));
    show("  status", status(q));
    send(q, b"n", 0, None);
    show("  status after a send", status(q));
    recv(q, &mut buf, None, None);
    say("SIGEV_SIGNAL signo 64", notify(q, Some(&sigev(SIGEV_SIGNAL, 64, 0))));
    notify(q, None);
    say("SIGEV_SIGNAL signo 65", notify(q, Some(&sigev(SIGEV_SIGNAL, 65, 0))));
    say("SIGEV_SIGNAL signo -1", notify(q, Some(&sigev(SIGEV_SIGNAL, -1, 0))));
    say("SIGEV_NONE signo 65", notify(q, Some(&sigev(SIGEV_NONE, 65, 0))));
    notify(q, None);
    say("sigev_notify 3", notify(q, Some(&sigev(3, 0, 0))));
    say("SIGEV_THREAD_ID", notify(q, Some(&sigev(SIGEV_THREAD_ID, libc::SIGUSR2, 0))));
    say("sigev_notify -1", notify(q, Some(&sigev(-1, 0, 0))));
    say("unmapped sigevent", unsafe { sys(NR_MQ_NOTIFY, q, 16, 0, 0, 0, 0) });
    let p = at_page_end(16);
    unsafe { std::ptr::copy_nonoverlapping(&sigev(SIGEV_NONE, 0, 0) as *const Sigevent as *const u8, p, 16) };
    say("sigevent with only 16 bytes readable", unsafe { sys(NR_MQ_NOTIFY, q, p as i64, 0, 0, 0, 0) });
    notify(q, None);
    say("NULL on fd -1", notify(-1, None));
    say("NULL on stdout", notify(1, None));
    say("SIGEV_NONE on stdout", notify(1, Some(&sigev(SIGEV_NONE, 0, 0))));
    say("sigev_notify 3 on fd -1", notify(-1, Some(&sigev(3, 0, 0))));
    say("signo 65 on fd -1", notify(-1, Some(&sigev(SIGEV_SIGNAL, 65, 0))));

    // SIGEV_THREAD at the syscall level: a netlink socket in sigev_signo and a
    // 32-byte cookie at sigev_value.
    let cookie = [0x5au8; 32];
    let ck = cookie.as_ptr() as u64;
    say("SIGEV_THREAD, signo -1", notify(q, Some(&sigev(SIGEV_THREAD, -1, ck))));
    say("SIGEV_THREAD, signo the queue", notify(q, Some(&sigev(SIGEV_THREAD, q as i32, ck))));
    say("SIGEV_THREAD, signo stdout", notify(q, Some(&sigev(SIGEV_THREAD, 1, ck))));
    let mut sv = [0i32; 2];
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) };
    say("SIGEV_THREAD, a unix socket", notify(q, Some(&sigev(SIGEV_THREAD, sv[0], ck))));
    say("SIGEV_THREAD, a unix socket, fd -1", notify(-1, Some(&sigev(SIGEV_THREAD, sv[0], ck))));
    say("SIGEV_THREAD, bad signo, fd -1", notify(-1, Some(&sigev(SIGEV_THREAD, -1, ck))));
    let nl = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
    sayfd("a netlink socket", nl as i64);
    say("SIGEV_THREAD, netlink, unmapped cookie", notify(q, Some(&sigev(SIGEV_THREAD, nl, 16))));
    say("SIGEV_THREAD, netlink, fd -1", notify(-1, Some(&sigev(SIGEV_THREAD, nl, ck))));
    say("SIGEV_THREAD, netlink", notify(q, Some(&sigev(SIGEV_THREAD, nl, ck))));
    show("  status", status(q));
    send(q, b"t", 0, None);
    let mut got = [0u8; 64];
    let n = unsafe { libc::recv(nl, got.as_mut_ptr().cast(), 64, libc::MSG_DONTWAIT) } as i64;
    show("  the netlink datagram", if n < 0 { "none".into() } else { format!("{} bytes, last {}, cookie kept {}", n, got[(n as usize).max(1) - 1], got[..31] == cookie[..31]) });
    show("  status after", status(q));
    recv(q, &mut buf, None, None);
    say("SIGEV_THREAD, netlink, again", notify(q, Some(&sigev(SIGEV_THREAD, nl, ck))));
    say("  NULL", notify(q, None));
    let n = unsafe { libc::recv(nl, got.as_mut_ptr().cast(), 64, libc::MSG_DONTWAIT) } as i64;
    show("  the netlink datagram", if n < 0 { "none".into() } else { format!("{} bytes, last {}", n, got[(n as usize).max(1) - 1]) });
    close(nl as i64);
    close(sv[0] as i64);
    close(sv[1] as i64);

    // Another process cannot take the registration or remove it.
    notify(q, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 3)));
    let child = unsafe { libc::fork() };
    if child == 0 {
        say("  child: SIGEV_NONE", notify(q, Some(&sigev(SIGEV_NONE, 0, 0))));
        say("  child: NULL", notify(q, None));
        send(q, b"c", 0, None);
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
    let s = take_signal(libc::SIGUSR2, 500);
    show("a send from a child: the signal", s);
    recv(q, &mut buf, None, None);

    // The owner closing its descriptor drops the registration.
    let q2 = open(c"mqp_e", O_RDWR, 0, None);
    notify(q2, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 4)));
    show("registered through a second descriptor", status(q));
    close(q2);
    show("  that descriptor closed", status(q));
    send(q, b"n", 0, None);
    show("  then a send", take_signal(libc::SIGUSR2, 0));
    recv(q, &mut buf, None, None);

    // A registration through a dup, the dup closed: the description lives on.
    let d = unsafe { libc::dup(q as i32) } as i64;
    notify(d, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 5)));
    close(d);
    show("registered through a dup, the dup closed", status(q));
    notify(q, None);

    // The owner exits without closing.
    let child = unsafe { libc::fork() };
    if child == 0 {
        notify(q, Some(&sigev(SIGEV_SIGNAL, libc::SIGUSR2, 6)));
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
    show("registered by a child that exited", status(q).replace(&format!("{child}"), "child"));
    say("  SIGEV_NONE from the parent", notify(q, Some(&sigev(SIGEV_NONE, 0, 0))));
    notify(q, None);
    close(q);
    unlink(c"mqp_e");
}

fn getsetattr() {
    println!("## mq_getsetattr");
    let q = open(c"mqp_e", O_CREAT | O_RDWR, 0o600, Some(&attr(4, 16)));
    send(q, b"x", 0, None);
    let mut old = Attr::default();
    let mut new = attr(99, 99);
    new.flags = O_NONBLOCK;
    new.curmsgs = 42;
    let v = unsafe { sys(NR_MQ_GETSETATTR, q, &new as *const Attr as i64, &mut old as *mut Attr as i64, 0, 0, 0) };
    show("set O_NONBLOCK", format!("{} old flags={:#o} maxmsg={} msgsize={} curmsgs={}", r(v), old.flags, old.maxmsg, old.msgsize, old.curmsgs));
    show("  after", attr_text(q));
    show("  F_GETFL", format!("{:#o}", unsafe { libc::fcntl(q as i32, libc::F_GETFL) }));
    new.flags = 1;
    say("flags 1", unsafe { sys(NR_MQ_GETSETATTR, q, &new as *const Attr as i64, 0, 0, 0, 0) });
    new.flags = O_NONBLOCK | 0o2;
    say("flags O_NONBLOCK|2", unsafe { sys(NR_MQ_GETSETATTR, q, &new as *const Attr as i64, 0, 0, 0, 0) });
    new.flags = 1 << 40;
    say("flags 1<<40", unsafe { sys(NR_MQ_GETSETATTR, q, &new as *const Attr as i64, 0, 0, 0, 0) });
    new.flags = 1;
    say("flags 1 on fd -1", unsafe { sys(NR_MQ_GETSETATTR, -1, &new as *const Attr as i64, 0, 0, 0, 0) });
    say("both NULL", unsafe { sys(NR_MQ_GETSETATTR, q, 0, 0, 0, 0, 0) });
    say("both NULL, fd -1", unsafe { sys(NR_MQ_GETSETATTR, -1, 0, 0, 0, 0, 0) });
    say("both NULL, stdout", unsafe { sys(NR_MQ_GETSETATTR, 1, 0, 0, 0, 0, 0) });
    say("new unmapped", unsafe { sys(NR_MQ_GETSETATTR, q, 16, 0, 0, 0, 0) });
    say("new unmapped, fd -1", unsafe { sys(NR_MQ_GETSETATTR, -1, 16, 0, 0, 0, 0) });
    new.flags = 0;
    say("clear O_NONBLOCK, old unmapped", unsafe { sys(NR_MQ_GETSETATTR, q, &new as *const Attr as i64, 16, 0, 0, 0) });
    show("  after", attr_text(q));
    let p = at_page_end(32);
    say("old with only 32 bytes writable", unsafe { sys(NR_MQ_GETSETATTR, q, 0, p as i64, 0, 0, 0) });
    let p = at_page_end(32);
    unsafe { std::ptr::write_bytes(p, 0, 32) };
    say("new with only 32 bytes readable", unsafe { sys(NR_MQ_GETSETATTR, q, p as i64, 0, 0, 0, 0) });
    close(q);
    unlink(c"mqp_e");
}

fn lifetime() {
    println!("## lifetime");
    let q = open(c"mqp_e", O_CREAT | O_RDWR, 0o600, Some(&attr(4, 16)));
    send(q, b"kept", 4, None);
    close(q);
    let q = open(c"mqp_e", O_RDWR, 0, None);
    show("closed with a message, reopened", attr_text(q));
    let child = unsafe { libc::fork() };
    if child == 0 {
        let c = open(c"mqp_e", O_RDWR, 0, None);
        let mut b = [0u8; 16];
        let mut p = 0u32;
        let n = recv(c, &mut b, Some(&mut p), None);
        show("  child: opened by name, received", format!("{} prio={} {:?}", r(n), p, String::from_utf8_lossy(&b[..n.max(0) as usize])));
        send(c, b"from child", 1, None);
        send(q, b"inherited", 2, None);
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
    show("  after the child", attr_text(q));
    say("unlink while open", unlink(c"mqp_e"));
    say("  open by name", open(c"mqp_e", O_RDWR, 0, None));
    show("  the open descriptor", attr_text(q));
    let q2 = open(c"mqp_e", O_CREAT | O_RDWR, 0o600, Some(&attr(4, 16)));
    show("  a new queue by the same name", attr_text(q2));
    let mut buf = [0u8; 16];
    let n = recv(q, &mut buf, None, None);
    show("  the old one still answers", format!("{} {:?}", r(n), String::from_utf8_lossy(&buf[..n.max(0) as usize])));
    close(q);
    close(q2);
    unlink(c"mqp_e");
}

fn unprivileged() {
    println!("## unprivileged");
    let a = open(c"mqp_a", O_CREAT | O_RDWR, 0o600, Some(&attr(1, 1)));
    let b = open(c"mqp_b", O_CREAT | O_RDWR, 0o644, Some(&attr(1, 1)));
    let c = open(c"mqp_c", O_CREAT | O_RDWR, 0o666, Some(&attr(1, 1)));
    close(a);
    close(b);
    close(c);
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::setgroups(0, std::ptr::null());
            libc::setgid(65534);
            libc::setuid(65534);
        }
        say("0600 root's, O_RDONLY", open(c"mqp_a", O_RDONLY, 0, None));
        sayfd("0644 root's, O_RDONLY", { let f = open(c"mqp_b", O_RDONLY, 0, None); close(f); f });
        say("0644 root's, O_WRONLY", open(c"mqp_b", O_WRONLY, 0, None));
        say("0644 root's, O_RDWR", open(c"mqp_b", O_RDWR, 0, None));
        say("0644 root's, O_CREAT|O_EXCL", open(c"mqp_b", O_CREAT | O_EXCL | O_RDWR, 0o600, None));
        let fb = open(c"mqp_b", O_RDONLY, 0, None);
        let fc = open(c"mqp_c", O_RDONLY, 0, None);
        let set = [libc::timespec { tv_sec: 5, tv_nsec: 0 }, libc::timespec { tv_sec: 5, tv_nsec: 0 }];
        say("futimens NULL, 0644 root's", lc(unsafe { libc::futimens(fb as i32, std::ptr::null()) } as i64));
        say("futimens NULL, 0666 root's", lc(unsafe { libc::futimens(fc as i32, std::ptr::null()) } as i64));
        say("futimens explicit, 0666 root's", lc(unsafe { libc::futimens(fc as i32, set.as_ptr()) } as i64));
        say("fchmod 0666 root's", lc(unsafe { libc::fchmod(fc as i32, 0o600) } as i64));
        close(fb);
        close(fc);
        say("unlink 0666 root's", unlink(c"mqp_c"));
        let f = open(c"mqp_x", O_CREAT | O_RDWR, 0o600, None);
        show("create as 65534", stat_text(f));
        close(f);
        say("unlink its own", unlink(c"mqp_x"));
        for (what, m, s) in [
            ("maxmsg 10 msgsize 8192", 10i64, 8192i64),
            ("maxmsg 11", 11, 16),
            ("msgsize 8193", 4, 8193),
            ("maxmsg 65537", 65537, 1),
            ("msgsize 16MiB+1", 1, (16 << 20) + 1),
        ] {
            let f = open(c"mqp_x", O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr(m, s)));
            sayfd(what, f);
            close(f);
            unlink(c"mqp_x");
        }

        // RLIMIT_MSGQUEUE: 819200 bytes, each default queue charged its
        // messages plus the bookkeeping.
        let mut names = Vec::new();
        let mut made = 0;
        let mut last = 0;
        for i in 0..20 {
            let n = std::ffi::CString::new(format!("mqp_r{i}")).unwrap();
            let f = open(&n, O_CREAT | O_RDWR, 0o600, None);
            if f < 0 {
                last = f;
                break;
            }
            close(f);
            names.push(n);
            made += 1;
        }
        show("default queues before RLIMIT_MSGQUEUE", format!("{} then {}", made, r(last)));
        if made == 9 {
            // 9 * 82880 = 745920 charged, 73280 left.
            for s in [7233i64, 7232] {
                let f = open(c"mqp_x", O_CREAT | O_RDWR, 0o600, Some(&attr(10, s)));
                sayfd(&format!("  a tenth, maxmsg 10 msgsize {s}"), f);
                close(f);
                unlink(c"mqp_x");
            }
        }
        // Unlinked and closed is uncharged.
        let n0 = names.pop().unwrap();
        unlink(&n0);
        sayfd("  one unlinked, then a create", { let f = open(c"mqp_x", O_CREAT | O_RDWR, 0o600, None); close(f); f });
        unlink(c"mqp_x");
        // Unlinked but still open is still charged.
        let n1 = names.pop().unwrap();
        let held = open(&n1, O_RDWR, 0, None);
        unlink(&n1);
        say("  one unlinked but open, then a create", { let f = open(c"mqp_x", O_CREAT | O_RDWR, 0o600, None); close(f); unlink(c"mqp_x"); f.min(0) });
        sayfd("  ...and one more", { let f = open(c"mqp_y", O_CREAT | O_RDWR, 0o600, None); close(f); unlink(c"mqp_y"); f });
        close(held);
        for n in &names {
            unlink(n);
        }
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 819200 };
        unsafe { libc::setrlimit(libc::RLIMIT_MSGQUEUE, &lim) };
        say("RLIMIT_MSGQUEUE 0, create", open(c"mqp_x", O_CREAT | O_RDWR, 0o600, Some(&attr(1, 1))));
        sayfd("RLIMIT_MSGQUEUE 0, open an existing one", { let f = open(c"mqp_b", O_RDONLY, 0, None); close(f); f });
        let lim = libc::rlimit { rlim_cur: 819200, rlim_max: 819200 };
        unsafe { libc::setrlimit(libc::RLIMIT_MSGQUEUE, &lim) };

        // queues_max: 256, the three root queues above included.
        let mut made = 0;
        let mut last = 0;
        for i in 0..300 {
            let n = std::ffi::CString::new(format!("mqp_m{i}")).unwrap();
            let f = open(&n, O_CREAT | O_RDWR, 0o600, Some(&attr(1, 1)));
            if f < 0 {
                last = f;
                break;
            }
            close(f);
            made += 1;
        }
        show("tiny queues before queues_max, three others live", format!("{} then {}", made, r(last)));
        for i in 0..made {
            unlink(&std::ffi::CString::new(format!("mqp_m{i}")).unwrap());
        }
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
    unlink(c"mqp_a");
    unlink(c"mqp_b");
    unlink(c"mqp_c");
}

fn filesystem() {
    println!("## filesystem");
    for p in [
        c"/proc/sys/fs/mqueue/msg_max",
        c"/proc/sys/fs/mqueue/msgsize_max",
        c"/proc/sys/fs/mqueue/queues_max",
        c"/proc/sys/fs/mqueue/msg_default",
        c"/proc/sys/fs/mqueue/msgsize_default",
    ] {
        let f = unsafe { libc::open(p.as_ptr(), libc::O_RDONLY) };
        if f < 0 {
            say(&p.to_string_lossy(), -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64));
            continue;
        }
        let mut b = [0u8; 32];
        let n = unsafe { libc::read(f, b.as_mut_ptr().cast(), 32) };
        unsafe { libc::close(f) };
        show(&p.to_string_lossy(), format!("{:?}", String::from_utf8_lossy(&b[..n.max(0) as usize])));
    }
    let has = std::fs::read_to_string("/proc/filesystems").map(|s| s.lines().any(|l| l.ends_with("\tmqueue"))).unwrap_or(false);
    show("/proc/filesystems lists mqueue", format!("{has}"));
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let v = unsafe { libc::stat(c"/dev/mqueue".as_ptr(), &mut st) };
    // Docker mounts one there and a bare kernel does not: printed for the
    // record, and the line beside it is the one a guest can rely on.
    show("/dev/mqueue (a container mounts one)", if v == 0 { format!("mode={:#o}", st.st_mode) } else { "absent".into() });
}
