//! What a pidfd can do on a 7.x kernel beyond `pidfd_open` and a signal:
//! `PIDFD_NONBLOCK`, `PIDFD_THREAD`, `pidfd_getfd`, the `PIDFD_GET_INFO` and
//! namespace ioctls, the `PIDFD_SELF_*` sentinels, the 6.9 signal-scope flags,
//! `poll` and `waitid(P_PIDFD)`, and `clone3`'s `set_tid` and `cgroup`.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container and diffed by `tests/integration/probe_diff.sh`. The container
//! runs it with seccomp off and `CAP_CHECKPOINT_RESTORE` added (see
//! `docker_opts` there): the guest is root in its own kernel, and `set_tid` is
//! what that capability gates.

use std::io::Write;
use std::sync::mpsc;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<60} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EPERM => "EPERM",
        libc::ESRCH => "ESRCH",
        libc::EBADF => "EBADF",
        libc::ECHILD => "ECHILD",
        libc::EAGAIN => "EAGAIN",
        libc::EFAULT => "EFAULT",
        libc::EEXIST => "EEXIST",
        libc::EINVAL => "EINVAL",
        libc::ENOTTY => "ENOTTY",
        libc::ENOSYS => "ENOSYS",
        libc::E2BIG => "E2BIG",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EACCES => "EACCES",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn r(v: i64) -> String {
    if v < 0 { named(errno()) } else { v.to_string() }
}

/// A descriptor is a number nobody compares; "a descriptor" is the answer.
fn fdr(v: i64) -> String {
    if v < 0 { named(errno()) } else { "a descriptor".into() }
}

const PIDFD_NONBLOCK: u32 = libc::O_NONBLOCK as u32;
const PIDFD_THREAD: u32 = libc::O_EXCL as u32;
const PIDFD_SELF_THREAD: i32 = -10000;
const PIDFD_SELF_THREAD_GROUP: i32 = -10001;
const PIDFD_SIGNAL_THREAD: u32 = 1;
const PIDFD_SIGNAL_THREAD_GROUP: u32 = 2;
const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 4;

const INFO_CGROUPID: u64 = 4;
const INFO_EXIT: u64 = 8;
const INFO_COREDUMP: u64 = 16;
const INFO_SUPPORTED_MASK: u64 = 32;

const P_PIDFD: i32 = 3;
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_INTO_CGROUP: u64 = 1 << 33;

fn pidfd_open(pid: i32, flags: u32) -> i64 {
    unsafe { libc::syscall(434, pid, flags) }
}

fn getfd(pidfd: i32, fd: i32, flags: u32) -> i64 {
    unsafe { libc::syscall(438, pidfd, fd, flags) }
}

fn send(fd: i32, sig: i32, flags: u32) -> i64 {
    unsafe { libc::syscall(424, fd, sig, std::ptr::null::<u8>(), flags) }
}

fn close(fd: i64) {
    if fd >= 0 {
        unsafe { libc::close(fd as i32) };
    }
}

/// `_IOWR(0xFF, nr, size)`.
const fn iowr(nr: u64, size: u64) -> u64 {
    (3 << 30) | (size << 16) | (0xFF << 8) | nr
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PidfdInfo {
    mask: u64,
    cgroupid: u64,
    pid: u32,
    tgid: u32,
    ppid: u32,
    ruid: u32,
    rgid: u32,
    euid: u32,
    egid: u32,
    suid: u32,
    sgid: u32,
    fsuid: u32,
    fsgid: u32,
    exit_code: i32,
    coredump_mask: u32,
    coredump_signal: u32,
    coredump_code: u32,
    coredump_pad: u32,
    supported_mask: u64,
    /// Room past the 88 bytes 7.2 knows, for the size cases.
    tail: [u64; 4],
}

fn info(fd: i32, mask: u64, size: u64) -> (i64, PidfdInfo) {
    let mut i = PidfdInfo { mask, ..Default::default() };
    let v = unsafe { libc::ioctl(fd, iowr(11, size) as _, &mut i) } as i64;
    (v, i)
}

/// The mask with `CGROUPID` taken out and reported on its own line: whether
/// the process is in a cgroup is the container's fact, not the kernel's.
fn mask_line(what: &str, v: i64, i: &PidfdInfo) {
    if v < 0 {
        line(what, named(errno()));
    } else {
        line(what, format!("mask {:#x}", i.mask & !INFO_CGROUPID));
    }
    line(&format!("  {what}: cgroupid reported"), v >= 0 && i.mask & INFO_CGROUPID != 0);
}

fn poll_revents(fd: i32) -> String {
    let mut p = libc::pollfd { fd, events: libc::POLLIN | libc::POLLOUT, revents: 0 };
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    if n < 0 { named(errno()) } else { format!("n={n} revents={:#x}", p.revents) }
}

fn waitid_pidfd(fd: i32, options: i32) -> String {
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let v = unsafe {
        libc::syscall(libc::SYS_waitid, P_PIDFD, fd, &mut si, options, std::ptr::null::<u8>())
    };
    if v < 0 {
        return named(errno());
    }
    let p = (&raw const si).cast::<i32>();
    // si_signo, si_errno, si_code, pad, si_pid, si_uid, si_status.
    let (code, pid, status) = unsafe { (p.add(2).read(), p.add(4).read(), p.add(6).read()) };
    format!("{v}, si_pid {}, si_code {code}, si_status {status}", if pid == 0 { "0" } else { "set" })
}

fn fork_waiting() -> (i32, i32) {
    // A child that waits for a byte on a pipe, then exits 7.
    let mut p = [0; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let c = unsafe { libc::fork() };
    if c == 0 {
        unsafe {
            libc::close(p[1]);
            let mut b = 0u8;
            libc::read(p[0], (&raw mut b).cast(), 1);
            libc::_exit(7);
        }
    }
    unsafe { libc::close(p[0]) };
    (c, p[1])
}

fn release(w: i32) {
    unsafe {
        libc::write(w, b"x".as_ptr().cast(), 1);
        libc::close(w);
    }
}

/// Wait until `pid` is a zombie without reaping it.
fn wait_exited(pid: i32) {
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe { libc::waitid(libc::P_PID, pid as u32, &mut si, libc::WEXITED | libc::WNOWAIT) };
}

fn reap(pid: i32) {
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// `clone3`, with a child that exits 0 at once; the child's pid, or an errno.
fn clone3(a: &CloneArgs, size: usize) -> i64 {
    let v = unsafe { libc::syscall(435, a as *const CloneArgs, size) };
    if v == 0 {
        unsafe { libc::_exit(0) };
    }
    if v > 0 {
        reap(v as i32);
    }
    v
}

fn main() {
    let me = std::process::id() as i32;

    println!("########## pidfd_open's flags ##########");
    for (name, flags) in [
        ("PIDFD_NONBLOCK", PIDFD_NONBLOCK),
        ("PIDFD_THREAD", PIDFD_THREAD),
        ("PIDFD_NONBLOCK|PIDFD_THREAD", PIDFD_NONBLOCK | PIDFD_THREAD),
    ] {
        let fd = pidfd_open(me, flags);
        line(&format!("pidfd_open(self, {name})"), fdr(fd));
        if fd >= 0 {
            let fl = unsafe { libc::fcntl(fd as i32, libc::F_GETFL) };
            line("  O_NONBLOCK in F_GETFL", fl & libc::O_NONBLOCK != 0);
            line("  O_EXCL in F_GETFL", fl & libc::O_EXCL != 0);
            line("  FD_CLOEXEC", unsafe { libc::fcntl(fd as i32, libc::F_GETFD) } & libc::FD_CLOEXEC);
        }
        close(fd);
    }

    // A thread that sits until told to go, so its tid is live.
    let (tid_tx, tid_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let t = std::thread::spawn(move || {
        tid_tx.send(unsafe { libc::gettid() }).unwrap();
        let _ = go_rx.recv();
    });
    let tid = tid_rx.recv().unwrap();
    line("pidfd_open(a thread, 0)", fdr(pidfd_open(tid, 0)));
    let tfd = pidfd_open(tid, PIDFD_THREAD);
    line("pidfd_open(a thread, PIDFD_THREAD)", fdr(tfd));
    line("  poll while the thread runs", poll_revents(tfd as i32));
    line("  pidfd_send_signal(thread pidfd, 0)", r(send(tfd as i32, 0, 0)));
    line(
        "  ... with PIDFD_SIGNAL_THREAD_GROUP",
        r(send(tfd as i32, 0, PIDFD_SIGNAL_THREAD_GROUP)),
    );
    {
        let (v, i) = info(tfd as i32, 0, 64);
        line("  PIDFD_GET_INFO", r(v));
        line("  pid is the thread", i.pid == tid as u32);
        line("  tgid is the process", i.tgid == me as u32);
    }
    let pfd = pidfd_open(me, 0);
    go_tx.send(()).unwrap();
    t.join().unwrap();
    // The thread's exit is reported asynchronously on both sides; give it a
    // moment rather than racing it.
    for _ in 0..200 {
        let mut p = libc::pollfd { fd: tfd as i32, events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut p, 1, 10) } > 0 {
            break;
        }
    }
    line("  poll after the thread exited", poll_revents(tfd as i32));
    line("  process pidfd after the thread exited", poll_revents(pfd as i32));
    line("  signal 0 to the exited thread", r(send(tfd as i32, 0, 0)));
    close(tfd);
    close(pfd);

    println!("\n########## the descriptor itself ##########");
    let fd = pidfd_open(me, 0) as i32;
    {
        let mut buf = [0u8; 128];
        let path = format!("/proc/self/fd/{fd}\0");
        let n = unsafe { libc::readlink(path.as_ptr().cast(), buf.as_mut_ptr().cast(), 128) };
        let s = if n < 0 {
            named(errno())
        } else {
            String::from_utf8_lossy(&buf[..n as usize])
                .chars()
                .map(|c| if c.is_ascii_digit() { 'N' } else { c })
                .collect()
        };
        line("readlink /proc/self/fd/<pidfd>, digits as N", s);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let v = unsafe { libc::fstat(fd, &mut st) };
        line("fstat", r(v as i64));
        line("  st_mode", format!("{:o}", st.st_mode));
        let mut b = [0u8; 8];
        line("read", r(unsafe { libc::read(fd, b.as_mut_ptr().cast(), 8) } as i64));
        line("write", r(unsafe { libc::write(fd, b.as_ptr().cast(), 8) } as i64));
        let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap_or_default();
        let pid_line = fdinfo.lines().find(|l| l.starts_with("Pid:")).map(str::to_owned);
        line("fdinfo has Pid: <self>", pid_line.as_deref() == Some(&format!("Pid:\t{me}")[..]));
        let nspid = fdinfo.lines().find(|l| l.starts_with("NSpid:")).map(str::to_owned);
        line("fdinfo has NSpid: <self>", nspid.as_deref() == Some(&format!("NSpid:\t{me}")[..]));
    }

    println!("\n########## pidfd_getfd ##########");
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    {
        let g = getfd(fd, null, 0);
        line("pidfd_getfd(self, /dev/null, 0)", fdr(g));
        if g >= 0 {
            let (mut a, mut b): (libc::stat, libc::stat) = unsafe { std::mem::zeroed() };
            unsafe { libc::fstat(null, &mut a) };
            unsafe { libc::fstat(g as i32, &mut b) };
            line("  the same file", a.st_ino == b.st_ino && a.st_dev == b.st_dev);
            line("  FD_CLOEXEC", unsafe { libc::fcntl(g as i32, libc::F_GETFD) } & libc::FD_CLOEXEC);
            // Shared description: an offset moved on one is moved on the other.
            line("  shares the description (F_GETFL agrees)",
                unsafe { libc::fcntl(g as i32, libc::F_GETFL) == libc::fcntl(null, libc::F_GETFL) });
        }
        close(g);
    }
    line("pidfd_getfd(self, /dev/null, 1)", r(getfd(fd, null, 1)));
    line("pidfd_getfd(self, 9999, 0)", r(getfd(fd, 9999, 0)));
    line("pidfd_getfd(self, -1, 0)", r(getfd(fd, -1, 0)));
    line("pidfd_getfd(/dev/null, 0, 0)", r(getfd(null, 0, 0)));
    line("pidfd_getfd(-1, 0, 0)", r(getfd(-1, 0, 0)));
    line("pidfd_getfd(9999, 0, 0)", r(getfd(9999, 0, 0)));
    {
        let g = getfd(PIDFD_SELF_THREAD, null, 0);
        line("pidfd_getfd(PIDFD_SELF_THREAD, /dev/null, 0)", fdr(g));
        close(g);
        let g = getfd(PIDFD_SELF_THREAD_GROUP, null, 0);
        line("pidfd_getfd(PIDFD_SELF_THREAD_GROUP, /dev/null, 0)", fdr(g));
        close(g);
        line("pidfd_getfd(-10002, /dev/null, 0)", r(getfd(-10002, null, 0)));
    }
    {
        // From a child: its descriptor 50 is a pipe it made.
        let mut p = [0; 2];
        unsafe { libc::pipe(p.as_mut_ptr()) };
        let c = unsafe { libc::fork() };
        if c == 0 {
            unsafe {
                libc::close(p[1]);
                let q = libc::open(c"/dev/zero".as_ptr(), libc::O_RDONLY);
                libc::dup2(q, 50);
                let mut b = 0u8;
                libc::read(p[0], (&raw mut b).cast(), 1);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(p[0]) };
        // Let the child reach its dup2.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let cfd = pidfd_open(c, 0) as i32;
        let g = getfd(cfd, 50, 0);
        line("pidfd_getfd(child, 50)", fdr(g));
        if g >= 0 {
            let mut b = [1u8; 4];
            let n = unsafe { libc::read(g as i32, b.as_mut_ptr().cast(), 4) };
            line("  reads the child's /dev/zero", n == 4 && b == [0; 4]);
        }
        close(g);
        line("pidfd_getfd(child, 51), not open there", r(getfd(cfd, 51, 0)));
        release(p[1]);
        wait_exited(c);
        line("pidfd_getfd(child, 50) once it has exited", r(getfd(cfd, 50, 0)));
        reap(c);
        line("pidfd_getfd(child, 50) once it is reaped", r(getfd(cfd, 50, 0)));
        unsafe { libc::close(cfd) };
    }

    println!("\n########## pidfd_send_signal: scopes and sentinels ##########");
    line("PIDFD_SELF_THREAD, signal 0", r(send(PIDFD_SELF_THREAD, 0, 0)));
    line("PIDFD_SELF_THREAD_GROUP, signal 0", r(send(PIDFD_SELF_THREAD_GROUP, 0, 0)));
    line("PIDFD_SIGNAL_THREAD, signal 0", r(send(fd, 0, PIDFD_SIGNAL_THREAD)));
    line("PIDFD_SIGNAL_THREAD_GROUP, signal 0", r(send(fd, 0, PIDFD_SIGNAL_THREAD_GROUP)));
    line("PIDFD_SIGNAL_PROCESS_GROUP, signal 0", r(send(fd, 0, PIDFD_SIGNAL_PROCESS_GROUP)));
    line("THREAD|THREAD_GROUP", r(send(fd, 0, 3)));
    line("flags 8", r(send(fd, 0, 8)));
    {
        // SIGUSR1 to the thread group, blocked and then collected: it must
        // arrive whichever scope named it.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }
        for (name, f) in [
            ("PIDFD_SIGNAL_THREAD", PIDFD_SIGNAL_THREAD),
            ("PIDFD_SIGNAL_THREAD_GROUP", PIDFD_SIGNAL_THREAD_GROUP),
            ("PIDFD_SIGNAL_PROCESS_GROUP", PIDFD_SIGNAL_PROCESS_GROUP),
        ] {
            let v = send(fd, libc::SIGUSR1, f);
            let ts = libc::timespec { tv_sec: 1, tv_nsec: 0 };
            let got = unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &ts) };
            line(&format!("SIGUSR1 with {name}"), format!("{}, received {}", r(v), got == libc::SIGUSR1));
        }
    }

    println!("\n########## PIDFD_GET_INFO ##########");
    {
        let (v, i) = info(fd, 0, 64);
        mask_line("GET_INFO(self, mask 0, 64 bytes)", v, &i);
        line("  pid", i.pid == me as u32);
        line("  tgid", i.tgid == me as u32);
        line("  ppid", i.ppid == unsafe { libc::getppid() } as u32);
        line("  ruid euid suid fsuid", format!("{} {} {} {}", i.ruid, i.euid, i.suid, i.fsuid));
        line("  rgid egid sgid fsgid", format!("{} {} {} {}", i.rgid, i.egid, i.sgid, i.fsgid));
        let (v, i) = info(fd, INFO_EXIT | INFO_COREDUMP, 64);
        mask_line("GET_INFO(self, EXIT|COREDUMP)", v, &i);
        let (v, i) = info(fd, INFO_SUPPORTED_MASK, 88);
        mask_line("GET_INFO(self, SUPPORTED_MASK, 88 bytes)", v, &i);
        line("  supported_mask", format!("{:#x}", i.supported_mask));
        let (v, i) = info(fd, INFO_SUPPORTED_MASK, 72);
        mask_line("GET_INFO(self, SUPPORTED_MASK, 72 bytes)", v, &i);
        line("  supported_mask untouched", i.supported_mask == 0);
        let mut i = PidfdInfo { tail: [!0; 4], ..Default::default() };
        let v = unsafe { libc::ioctl(fd, iowr(11, 120) as _, &mut i) } as i64;
        mask_line("GET_INFO(self, 0, 120 bytes)", v, &i);
        line("  tail past 88 bytes, filled with ones first", format!("{:x?}", i.tail));
        let (v, _) = info(fd, 0, 56);
        line("GET_INFO, 56 bytes", r(v));
        let (v, _) = info(fd, 0, 0);
        line("GET_INFO, 0 bytes", r(v));
        let v = unsafe { libc::ioctl(fd, iowr(11, 64) as _, 1usize) } as i64;
        line("GET_INFO at an unreadable address", r(v));
        let v = unsafe { libc::ioctl(fd, iowr(12, 64) as _, &mut PidfdInfo::default()) } as i64;
        line("ioctl nr 12", r(v));
        let v = unsafe { libc::ioctl(null, iowr(11, 64) as _, &mut PidfdInfo::default()) } as i64;
        line("GET_INFO on /dev/null", r(v));
        let (v, i) = info(PIDFD_SELF_THREAD_GROUP, 0, 64);
        line("GET_INFO on PIDFD_SELF_THREAD_GROUP", format!("{}, pid {}", r(v), i.pid == me as u32));
    }
    {
        let (c, w) = fork_waiting();
        let cfd = pidfd_open(c, 0) as i32;
        let (v, i) = info(cfd, INFO_EXIT, 64);
        mask_line("GET_INFO(live child, EXIT)", v, &i);
        line("  ppid is this process", i.ppid == me as u32);
        line("  exit_code", i.exit_code);
        release(w);
        wait_exited(c);
        let (v, i) = info(cfd, INFO_EXIT, 64);
        mask_line("GET_INFO(exited child, EXIT)", v, &i);
        line("  exit_code", format!("{:#x}", i.exit_code));
        let (v, i) = info(cfd, 0, 64);
        mask_line("GET_INFO(exited child, 0)", v, &i);
        reap(c);
        let (v, i) = info(cfd, INFO_EXIT, 64);
        mask_line("GET_INFO(reaped child, EXIT)", v, &i);
        line("  exit_code", format!("{:#x}", i.exit_code));
        line("  pid still reported", i.pid == c as u32);
        let (v, i) = info(cfd, 0, 64);
        mask_line("GET_INFO(reaped child, 0)", v, &i);
        unsafe { libc::close(cfd) };
        // Killed by a signal, so exit_code is a signal status.
        let (c, _w) = fork_waiting();
        let cfd = pidfd_open(c, 0) as i32;
        unsafe { libc::kill(c, libc::SIGKILL) };
        reap(c);
        let (v, i) = info(cfd, INFO_EXIT, 64);
        mask_line("GET_INFO(child killed by SIGKILL, EXIT)", v, &i);
        line("  exit_code", format!("{:#x}", i.exit_code));
        unsafe { libc::close(cfd) };
    }

    println!("\n########## the namespace ioctls ##########");
    for (nr, name) in [
        (1, "CGROUP"), (2, "IPC"), (3, "MNT"), (4, "NET"), (5, "PID"),
        (6, "PID_FOR_CHILDREN"), (7, "TIME"), (8, "TIME_FOR_CHILDREN"), (9, "USER"), (10, "UTS"),
    ] {
        let v = unsafe { libc::ioctl(fd, ((0xFF << 8) | nr) as _) } as i64;
        line(&format!("PIDFD_GET_{name}_NAMESPACE"), fdr(v));
        close(v);
    }

    println!("\n########## poll ##########");
    line("poll(self)", poll_revents(fd));
    {
        let (c, w) = fork_waiting();
        let cfd = pidfd_open(c, 0) as i32;
        line("poll(live child)", poll_revents(cfd));
        release(w);
        wait_exited(c);
        line("poll(exited child)", poll_revents(cfd));
        reap(c);
        line("poll(reaped child)", poll_revents(cfd));
        unsafe { libc::close(cfd) };
    }

    println!("\n########## waitid(P_PIDFD) ##########");
    {
        let (c, w) = fork_waiting();
        let cfd = pidfd_open(c, 0) as i32;
        let nfd = pidfd_open(c, PIDFD_NONBLOCK) as i32;
        line("live child, WEXITED|WNOHANG", waitid_pidfd(cfd, libc::WEXITED | libc::WNOHANG));
        line("live child, PIDFD_NONBLOCK, WEXITED", waitid_pidfd(nfd, libc::WEXITED));
        line("live child, PIDFD_NONBLOCK, WEXITED|WNOHANG", waitid_pidfd(nfd, libc::WEXITED | libc::WNOHANG));
        release(w);
        wait_exited(c);
        line("exited child, WEXITED|WNOWAIT", waitid_pidfd(cfd, libc::WEXITED | libc::WNOWAIT));
        line("exited child, PIDFD_NONBLOCK, WEXITED", waitid_pidfd(nfd, libc::WEXITED));
        line("reaped child, WEXITED", waitid_pidfd(cfd, libc::WEXITED));
        unsafe { libc::close(cfd) };
        unsafe { libc::close(nfd) };
    }
    line("self, WEXITED|WNOHANG", waitid_pidfd(fd, libc::WEXITED | libc::WNOHANG));
    line("/dev/null, WEXITED", waitid_pidfd(null, libc::WEXITED));
    line("-1, WEXITED", waitid_pidfd(-1, libc::WEXITED));
    line("9999, WEXITED", waitid_pidfd(9999, libc::WEXITED));
    line("PIDFD_SELF_THREAD_GROUP, WEXITED|WNOHANG", waitid_pidfd(PIDFD_SELF_THREAD_GROUP, libc::WEXITED | libc::WNOHANG));

    println!("\n########## clone3: CLONE_PIDFD ##########");
    {
        let mut pfd: i32 = -1;
        let a = CloneArgs {
            flags: CLONE_PIDFD,
            pidfd: (&raw mut pfd) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..Default::default()
        };
        let v = unsafe { libc::syscall(435, &a as *const CloneArgs, 88usize) };
        if v == 0 {
            unsafe { libc::_exit(3) };
        }
        line("clone3(CLONE_PIDFD)", if v > 0 { "a child".to_string() } else { named(errno()) });
        line("  pidfd written", pfd >= 0);
        line("  FD_CLOEXEC", unsafe { libc::fcntl(pfd, libc::F_GETFD) } & libc::FD_CLOEXEC);
        if v > 0 {
            wait_exited(v as i32);
            line("  poll after the child exits", poll_revents(pfd));
            line("  waitid through it", waitid_pidfd(pfd, libc::WEXITED));
        }
        unsafe { libc::close(pfd) };
        let a = CloneArgs {
            flags: CLONE_PIDFD,
            pidfd: 1,
            exit_signal: libc::SIGCHLD as u64,
            ..Default::default()
        };
        line("clone3(CLONE_PIDFD) with an unwritable pidfd", r(clone3(&a, 88)));
    }

    println!("\n########## clone3: set_tid ##########");
    {
        // A pid nothing holds, which neither kernel will have handed out to a
        // process this young: the top of the guest's range.
        let want: i32 = 32000;
        let tids = [want];
        let a = CloneArgs {
            exit_signal: libc::SIGCHLD as u64,
            set_tid: tids.as_ptr() as u64,
            set_tid_size: 1,
            ..Default::default()
        };
        let v = clone3(&a, 88);
        line("set_tid = [32000]", if v < 0 { named(errno()) } else { format!("child pid is 32000: {}", v == want as i64) });
        let tids = [me];
        let a = CloneArgs { set_tid: tids.as_ptr() as u64, ..a };
        line("set_tid = [own pid]", r(clone3(&a, 88)));
        let tids = [0];
        let a = CloneArgs { set_tid: tids.as_ptr() as u64, ..a };
        line("set_tid = [0]", r(clone3(&a, 88)));
        let tids = [-1];
        let a = CloneArgs { set_tid: tids.as_ptr() as u64, ..a };
        line("set_tid = [-1]", r(clone3(&a, 88)));
        let tids = [0x7fff_ffff];
        let a = CloneArgs { set_tid: tids.as_ptr() as u64, ..a };
        line("set_tid = [INT_MAX]", r(clone3(&a, 88)));
        // One entry per pid-namespace level, and how deep a container's is
        // depends on the machine (OrbStack's took three), so the comparable
        // bound is MAX_PID_NS_LEVEL's.
        let tids = [want; 33];
        let a = CloneArgs { set_tid: tids.as_ptr() as u64, set_tid_size: 33, ..a };
        line("set_tid_size = 33", r(clone3(&a, 88)));
        let a = CloneArgs { set_tid: 0, set_tid_size: 1, ..a };
        line("set_tid = NULL, set_tid_size = 1", r(clone3(&a, 88)));
        let a = CloneArgs { set_tid: tids.as_ptr() as u64, set_tid_size: 0, ..a };
        line("set_tid set, set_tid_size = 0", r(clone3(&a, 88)));
        let a = CloneArgs { set_tid: 1, set_tid_size: 1, ..a };
        line("set_tid unreadable", r(clone3(&a, 88)));
        let tids = [want];
        let a = CloneArgs { set_tid: tids.as_ptr() as u64, set_tid_size: 1, ..a };
        // The struct ends before `set_tid`, so it is not read at all.
        line("set_tid with a 64-byte struct", fdr(clone3(&a, 64)).replace("a descriptor", "a child"));
    }

    println!("\n########## clone3: CLONE_INTO_CGROUP ##########");
    {
        let base = CloneArgs { flags: CLONE_INTO_CGROUP, exit_signal: libc::SIGCHLD as u64, ..Default::default() };
        line("cgroup = /dev/null", r(clone3(&CloneArgs { cgroup: null as u64, ..base }, 88)));
        line("cgroup = 9999", r(clone3(&CloneArgs { cgroup: 9999, ..base }, 88)));
        line("cgroup > INT_MAX", r(clone3(&CloneArgs { cgroup: 1 << 31, ..base }, 88)));
        line("cgroup with an 80-byte struct", r(clone3(&CloneArgs { cgroup: null as u64, ..base }, 80)));
        let root = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        line("cgroup = the root directory", r(clone3(&CloneArgs { cgroup: root as u64, ..base }, 88)));
        unsafe { libc::close(root) };
    }

    unsafe { libc::close(null) };
    unsafe { libc::close(fd) };
}
