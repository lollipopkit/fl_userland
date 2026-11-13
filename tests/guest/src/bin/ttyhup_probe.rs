//! What a terminal hangup does, and to whom.
//!
//! **A report, not a check**: one line per case, run here and in a privileged
//! arm64 container (`vhangup` needs `CAP_SYS_TTY_CONFIG`) and diffed by
//! `tests/integration/probe_diff.sh`.
//!
//! Four ways a terminal goes away: `vhangup`, the pty master closing, every
//! slave descriptor closing, and the session leader exiting. For each, what
//! the descriptors open at that moment answer, whether the terminal can be
//! opened again and works, whether the session still has it, and which
//! processes get `SIGHUP` and `SIGCONT` -- the session leader and a member of
//! the session in the foreground process group are counted separately.
//!
//! Every section runs in a forked child that makes its own session, so the
//! probe's own is never touched.

use std::io::Write;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<56} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EBADF => "EBADF",
        libc::EAGAIN => "EAGAIN",
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ENOSYS => "ENOSYS",
        libc::EINTR => "EINTR",
        libc::EACCES => "EACCES",
        libc::EIO => "EIO",
        libc::ENXIO => "ENXIO",
        libc::ENOTTY => "ENOTTY",
        libc::EBUSY => "EBUSY",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn r(v: i64) -> String {
    if v < 0 { named(errno()) } else { v.to_string() }
}

fn ok(v: i64) -> String {
    if v < 0 { named(errno()) } else { "ok".into() }
}

static HUPS: AtomicI32 = AtomicI32::new(0);
static CONTS: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_hup(_: i32) {
    HUPS.fetch_add(1, Ordering::SeqCst);
}
extern "C" fn on_cont(_: i32) {
    CONTS.fetch_add(1, Ordering::SeqCst);
}

fn count_signals() {
    for (sig, f) in [(libc::SIGHUP, on_hup as extern "C" fn(i32)), (libc::SIGCONT, on_cont)] {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = f as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
    HUPS.store(0, Ordering::SeqCst);
    CONTS.store(0, Ordering::SeqCst);
}

fn signals() -> String {
    format!("HUP {} CONT {}", HUPS.load(Ordering::SeqCst), CONTS.load(Ordering::SeqCst))
}

fn settle() {
    std::thread::sleep(Duration::from_millis(150));
}

/// A pty pair, the slave opened `O_NOCTTY`, and the slave's name.
fn pty() -> (i32, i32, std::ffi::CString) {
    let m = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    unsafe {
        libc::grantpt(m);
        libc::unlockpt(m);
    }
    let name = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(m)) }.to_owned();
    let s = open(&name, libc::O_RDWR | libc::O_NOCTTY);
    (m, s, name)
}

fn open(path: &std::ffi::CStr, flags: i32) -> i32 {
    unsafe { libc::open(path.as_ptr(), flags) }
}

fn opened(fd: i32) -> String {
    if fd < 0 { named(errno()) } else { "ok".into() }
}

fn nonblock(fd: i32) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
}

fn read(fd: i32) -> String {
    let mut b = [0u8; 64];
    r(unsafe { libc::read(fd, b.as_mut_ptr().cast(), b.len()) } as i64)
}

fn write(fd: i32, bytes: &[u8]) -> String {
    r(unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) } as i64)
}

fn revents(fd: i32) -> String {
    let mut p = libc::pollfd { fd, events: libc::POLLIN | libc::POLLOUT | libc::POLLPRI, revents: 0 };
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    if n < 0 {
        return named(errno());
    }
    let mut names = Vec::new();
    for (bit, name) in [
        (libc::POLLIN, "IN"),
        (libc::POLLPRI, "PRI"),
        (libc::POLLOUT, "OUT"),
        (libc::POLLERR, "ERR"),
        (libc::POLLHUP, "HUP"),
        (libc::POLLNVAL, "NVAL"),
    ] {
        if p.revents & bit != 0 {
            names.push(name);
        }
    }
    if names.is_empty() { "none".into() } else { names.join("|") }
}

fn ioctl_int(fd: i32, req: libc::c_ulong) -> String {
    let mut v = 0i32;
    r(unsafe { libc::ioctl(fd, req as _, &mut v) } as i64)
}

fn tcgets(fd: i32) -> String {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    ok(unsafe { libc::ioctl(fd, libc::TCGETS as _, &mut t) } as i64)
}

fn sid_of(fd: i32) -> String {
    let mut v = 0i32;
    if unsafe { libc::ioctl(fd, libc::TIOCGSID as _, &mut v) } < 0 {
        return named(errno());
    }
    if v == unsafe { libc::getsid(0) } { "the caller's session".into() } else { "another session".into() }
}

fn dev_tty() -> String {
    let fd = open(c"/dev/tty", libc::O_RDWR | libc::O_NOCTTY);
    let s = opened(fd);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
    s
}

/// A member of the caller's session in a process group of its own, made the
/// terminal's foreground group. It waits for a byte on `go`, then writes what
/// it saw to `report`, one line per case, and exits.
struct Member {
    pid: i32,
    go: i32,
    report: i32,
}

impl Member {
    /// `master` is closed in the member, so that closing it in the caller
    /// is the last close.
    fn start(tty: i32, master: i32, after: fn(i32) -> Vec<(String, String)>) -> Member {
        let mut go = [0i32; 2];
        let mut report = [0i32; 2];
        let mut ready = [0i32; 2];
        unsafe {
            libc::pipe(go.as_mut_ptr());
            libc::pipe(report.as_mut_ptr());
            libc::pipe(ready.as_mut_ptr());
        }
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            count_signals();
            unsafe {
                libc::close(master);
                libc::setpgid(0, 0);
                libc::write(ready[1], b"r".as_ptr().cast(), 1);
            }
            let mut b = [0u8; 1];
            while unsafe { libc::read(go[0], b.as_mut_ptr().cast(), 1) } < 0 && errno() == libc::EINTR {}
            settle();
            let mut out = vec![("signals".to_string(), signals())];
            out.extend(after(tty));
            let mut text = String::new();
            for (k, v) in out {
                text += &format!("{k}\t{v}\n");
            }
            unsafe {
                libc::write(report[1], text.as_ptr().cast(), text.len());
                libc::_exit(0);
            }
        }
        unsafe {
            libc::setpgid(pid, pid);
            let mut b = [0u8; 1];
            libc::close(ready[1]);
            libc::read(ready[0], b.as_mut_ptr().cast(), 1);
            libc::close(ready[0]);
            libc::close(go[0]);
            libc::close(report[1]);
            libc::tcsetpgrp(tty, pid);
        }
        Member { pid, go: go[1], report: report[0] }
    }

    /// Release it and print its report under `who`.
    fn finish(self, who: &str) {
        unsafe { libc::write(self.go, b"g".as_ptr().cast(), 1) };
        let mut text = Vec::new();
        let mut b = [0u8; 512];
        loop {
            let n = unsafe { libc::read(self.report, b.as_mut_ptr().cast(), b.len()) };
            if n > 0 {
                text.extend_from_slice(&b[..n as usize]);
            } else if !(n < 0 && errno() == libc::EINTR) {
                break;
            }
        }
        let mut st = 0;
        unsafe { libc::waitpid(self.pid, &mut st, 0) };
        let text = String::from_utf8_lossy(&text);
        if text.is_empty() {
            line(&format!("  {who}"), "no report");
        }
        for l in text.lines() {
            let (k, v) = l.split_once('\t').unwrap_or((l, ""));
            line(&format!("  {who}: {k}"), v);
        }
    }
}

fn member_view(tty: i32) -> Vec<(String, String)> {
    nonblock(tty);
    vec![
        ("read its descriptor".into(), read(tty)),
        ("write its descriptor".into(), write(tty, b"m")),
        ("open /dev/tty".into(), dev_tty()),
    ]
}

fn in_child(f: fn()) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

fn vhangup_section() {
    println!("\n########## vhangup ##########");
    count_signals();
    unsafe { libc::setsid() };
    let (m, s, name) = pty();
    line("TIOCSCTTY", ok(unsafe { libc::ioctl(s, libc::TIOCSCTTY as _, 0) } as i64));
    let t = open(c"/dev/tty", libc::O_RDWR);
    line("open /dev/tty before", opened(t));
    let member = Member::start(s, m, member_view);
    line("vhangup()", ok(unsafe { libc::syscall(58) }));
    settle();
    line("  the leader's signals", signals());
    nonblock(s);
    nonblock(t);
    line("  poll the old slave descriptor", revents(s));
    line("  read it", read(s));
    line("  write it", write(s, b"x"));
    line("  TCGETS on it", tcgets(s));
    line("  TIOCGPGRP on it", ioctl_int(s, libc::TIOCGPGRP as _));
    line("  TIOCSPGRP on it", {
        let pg = unsafe { libc::getpgrp() };
        ok(unsafe { libc::ioctl(s, libc::TIOCSPGRP as _, &pg) } as i64)
    });
    line("  read the /dev/tty descriptor", read(t));
    line("  write the /dev/tty descriptor", write(t, b"x"));
    nonblock(m);
    line("  poll the master", revents(m));
    line("  read the master", read(m));
    line("  write the master", write(m, b"ab\n"));
    member.finish("the foreground member");
    line("  open /dev/tty after", dev_tty());
    let s2 = open(&name, libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK);
    line("  reopen the slave", opened(s2));
    line("  read the new descriptor", read(s2));
    line("  write the new descriptor", write(s2, b"y"));
    line("  read the master", read(m));
    line("  TIOCGSID on the new descriptor", sid_of(s2));
    line("  poll the old descriptor again", revents(s));
    line("  read the old descriptor again", read(s));
    line("  TIOCSCTTY on the new descriptor", ok(unsafe { libc::ioctl(s2, libc::TIOCSCTTY as _, 0) } as i64));
    line("  TIOCGSID on it", sid_of(s2));
    line("  open /dev/tty then", dev_tty());
}

fn vhangup_unprivileged_section() {
    println!("\n########## vhangup without CAP_SYS_TTY_CONFIG ##########");
    unsafe { libc::setsid() };
    let (_m, s, _) = pty();
    unsafe { libc::ioctl(s, libc::TIOCSCTTY as _, 0) };
    unsafe { libc::setresuid(65534, 65534, 65534) };
    line("vhangup() as uid 65534", ok(unsafe { libc::syscall(58) }));
    nonblock(s);
    line("  write the slave", write(s, b"x"));
}

fn master_close_section() {
    println!("\n########## the master closes ##########");
    count_signals();
    unsafe { libc::setsid() };
    let (m, s, name) = pty();
    unsafe { libc::ioctl(s, libc::TIOCSCTTY as _, 0) };
    let member = Member::start(s, m, member_view);
    line("close the master", ok(unsafe { libc::close(m) } as i64));
    settle();
    line("  the leader's signals", signals());
    nonblock(s);
    line("  poll the slave", revents(s));
    line("  read it", read(s));
    line("  write it", write(s, b"x"));
    line("  TCGETS on it", tcgets(s));
    line("  TIOCGSID on it", sid_of(s));
    member.finish("the foreground member");
    line("  open /dev/tty", dev_tty());
    line("  reopen the slave", opened(open(&name, libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK)));
}

fn slave_close_section() {
    println!("\n########## every slave descriptor closes ##########");
    // Linux moves bytes between the two ends from a work queue, so each step
    // settles before the next one looks.
    let (m, s, name) = pty();
    nonblock(m);
    line("write the slave", write(s, b"a"));
    settle();
    line("close the slave", ok(unsafe { libc::close(s) } as i64));
    settle();
    line("  poll the master", revents(m));
    line("  read the master", read(m));
    line("  read the master again", read(m));
    line("  poll the master once it is drained", revents(m));
    line("  write the master", write(m, b"b"));
    settle();
    let s2 = open(&name, libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK);
    line("  reopen the slave", opened(s2));
    settle();
    line("  poll the master", revents(m));
    line("  read the new descriptor", read(s2));
    line("  write the new descriptor", write(s2, b"c"));
    settle();
    line("  read the master", read(m));
    line("  poll the master after reading", revents(m));
    line("  close it again", ok(unsafe { libc::close(s2) } as i64));
    settle();
    line("  read the master", read(m));
}

fn leader_exit() {
    println!("\n########## the session leader exits ##########");
    count_signals();
    let (m, s, name) = pty();
    unsafe { libc::close(s) };
    nonblock(m);
    // go: grandparent -> member. report: member -> grandparent.
    let mut go = [0i32; 2];
    let mut report = [0i32; 2];
    let mut ready = [0i32; 2];
    unsafe {
        libc::pipe(go.as_mut_ptr());
        libc::pipe(report.as_mut_ptr());
        libc::pipe(ready.as_mut_ptr());
    }
    let leader = unsafe { libc::fork() };
    if leader == 0 {
        unsafe {
            libc::close(m);
            libc::setsid();
        }
        let s = open(&name, libc::O_RDWR);
        let member = unsafe { libc::fork() };
        if member == 0 {
            count_signals();
            unsafe { libc::setpgid(0, 0) };
            unsafe { libc::write(ready[1], b"r".as_ptr().cast(), 1) };
            let mut b = [0u8; 1];
            while unsafe { libc::read(go[0], b.as_mut_ptr().cast(), 1) } < 0 && errno() == libc::EINTR {}
            settle();
            let mut text = format!("signals\t{}\n", signals());
            for (k, v) in member_view(s) {
                text += &format!("{k}\t{v}\n");
            }
            text += &format!("TIOCGSID on its descriptor\t{}\n", sid_of(s));
            unsafe {
                libc::write(report[1], text.as_ptr().cast(), text.len());
                libc::_exit(0);
            }
        }
        unsafe {
            libc::setpgid(member, member);
            let mut b = [0u8; 1];
            libc::read(ready[0], b.as_mut_ptr().cast(), 1);
            libc::tcsetpgrp(s, member);
            libc::_exit(0);
        }
    }
    unsafe {
        libc::close(go[0]);
        libc::close(report[1]);
        libc::close(ready[0]);
        libc::close(ready[1]);
    }
    let mut st = 0;
    unsafe { libc::waitpid(leader, &mut st, 0) };
    settle();
    line("the leader has exited", libc::WIFEXITED(st));
    line("  poll the master", revents(m));
    unsafe { libc::write(go[1], b"g".as_ptr().cast(), 1) };
    let mut text = Vec::new();
    let mut b = [0u8; 512];
    loop {
        let n = unsafe { libc::read(report[0], b.as_mut_ptr().cast(), b.len()) };
        if n > 0 {
            text.extend_from_slice(&b[..n as usize]);
        } else if !(n < 0 && errno() == libc::EINTR) {
            break;
        }
    }
    for l in String::from_utf8_lossy(&text).lines() {
        let (k, v) = l.split_once('\t').unwrap_or((l, ""));
        line(&format!("  the foreground member: {k}"), v);
    }
    line("  read the master", read(m));
    line("  the prober's signals", signals());
}

fn main() {
    in_child(vhangup_section);
    in_child(vhangup_unprivileged_section);
    in_child(master_close_section);
    in_child(slave_close_section);
    in_child(leader_exit);
}
