//! What `fcntl(2)` answers, command by command, on a regular file, a pipe and
//! a socket.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! `fcntl_abi` checks the commands this kernel implements do what they say;
//! this asks about the ones it does not, and about the corners of the ones it
//! does: which `F_SETFL` bits take and which are silently dropped, what
//! `F_GETFL` reports that the caller never set, the `F_DUPFD` bounds, the
//! owner and signal commands a `SIGIO` user needs, leases, directory
//! notification, and what a command nobody knows is told.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<58} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::EBADF => "EBADF",
        libc::EAGAIN => "EAGAIN",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::EMFILE => "EMFILE",
        libc::ENOTDIR => "ENOTDIR",
        libc::ESRCH => "ESRCH",
        libc::EBUSY => "EBUSY",
        libc::ENOMEM => "ENOMEM",
        libc::ENOTTY => "ENOTTY",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn fcntl(fd: i32, cmd: i32, arg: i64) -> String {
    let r = unsafe { libc::syscall(libc::SYS_fcntl, fd, cmd, arg) };
    if r < 0 { named(errno()) } else { r.to_string() }
}

/// An `ioctl` whose argument is a pointer to an `int`.
///
/// The `FIO*` family: the same requests as `F_SETFL`/`F_SETOWN`, from the two
/// socket APIs that defined them. What is here rather than in `fcntl_abi` is
/// that this asks a *real kernel* the same question, which is the only way to
/// find out that the argument is a pointer and not a value.
fn ioctl_word(fd: i32, cmd: u64, value: i32) -> String {
    let v = value;
    let r = unsafe { libc::ioctl(fd, cmd as _, &v as *const i32) };
    if r < 0 { named(errno()) } else { r.to_string() }
}

/// `F_GETFL`'s answer, as the bits that mean something.
fn flags(fd: i32) -> String {
    let r = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if r < 0 {
        return named(errno());
    }
    let mut out = Vec::new();
    match r & libc::O_ACCMODE {
        libc::O_RDONLY => out.push("O_RDONLY"),
        libc::O_WRONLY => out.push("O_WRONLY"),
        libc::O_RDWR => out.push("O_RDWR"),
        _ => out.push("O_ACCMODE=3"),
    }
    for (bit, name) in [
        (libc::O_APPEND, "O_APPEND"),
        (libc::O_NONBLOCK, "O_NONBLOCK"),
        (libc::O_DIRECT, "O_DIRECT"),
        (libc::O_NOATIME, "O_NOATIME"),
        (libc::O_ASYNC, "O_ASYNC"),
        (libc::O_DSYNC, "O_DSYNC"),
        (libc::O_SYNC, "O_SYNC"),
        (libc::O_LARGEFILE, "O_LARGEFILE"),
        (libc::O_CLOEXEC, "O_CLOEXEC"),
        (libc::O_CREAT, "O_CREAT"),
        (libc::O_TRUNC, "O_TRUNC"),
        (libc::O_EXCL, "O_EXCL"),
        (libc::O_NOCTTY, "O_NOCTTY"),
        (libc::O_DIRECTORY, "O_DIRECTORY"),
        (libc::O_NOFOLLOW, "O_NOFOLLOW"),
        (libc::O_PATH, "O_PATH"),
    ] {
        if r & bit != 0 {
            out.push(name);
        }
    }
    out.join("|")
}

const F_SETOWN_EX: i32 = 15;
const F_GETOWN_EX: i32 = 16;
const F_SETSIG: i32 = 10;
const F_GETSIG: i32 = 11;
const F_SETLEASE: i32 = 1024;
const F_GETLEASE: i32 = 1025;
const F_NOTIFY: i32 = 1026;
const F_DUPFD_CLOEXEC: i32 = 1030;
const F_SETPIPE_SZ: i32 = 1031;
const F_GETPIPE_SZ: i32 = 1032;
const F_GET_RW_HINT: i32 = 1035;
const F_SET_RW_HINT: i32 = 1036;
const F_GET_FILE_RW_HINT: i32 = 1037;
const F_SET_FILE_RW_HINT: i32 = 1038;
const F_DUPFD_QUERY: i32 = 1027;
const F_CREATED_QUERY: i32 = 1028;

/// Runs `f` in a forked child as uid 1000 and waits for it. The child prints
/// its own lines -- stdout is flushed first so nothing is printed twice -- and
/// exits without running anything else. For the rules that depend on *not*
/// being root: both sides run this probe as root, and a rule that says "the
/// owner or a privileged caller" cannot be seen from there.
fn as_user_1000(f: impl FnOnce()) {
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::setgid(1000);
            libc::setuid(1000);
        }
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

fn main() {
    let path = c"/tmp/fcntl_probe.file";
    unsafe { libc::unlink(path.as_ptr()) };
    let file = unsafe { libc::open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR | libc::O_APPEND, 0o644) };
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let mut dp = [0i32; 2];
    unsafe { libc::pipe2(dp.as_mut_ptr(), libc::O_DIRECT) };
    let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    let dir = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    let ro = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    let opath = unsafe { libc::open(path.as_ptr(), libc::O_PATH) };
    line("setup", (file >= 0 && p[0] >= 0 && dp[0] >= 0 && sock >= 0 && dir >= 0 && ro >= 0 && opath >= 0).to_string());

    println!("## F_GETFL reports what was opened, and more");
    line("a file opened O_RDWR|O_APPEND", flags(file));
    line("a file opened O_RDONLY", flags(ro));
    line("an O_PATH descriptor", flags(opath));
    line("a pipe's read end", flags(p[0]));
    line("a pipe's write end", flags(p[1]));
    line("a pipe made with O_DIRECT, read end", flags(dp[0]));
    line("a pipe made with O_DIRECT, write end", flags(dp[1]));
    line("a socket", flags(sock));
    line("a directory", flags(dir));
    {
        // Which of the flags an open is given does the description keep?
        let path2 = c"/tmp/fcntl_probe.file2";
        unsafe { libc::unlink(path2.as_ptr()) };
        let every = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC | libc::O_NOCTTY
            | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_SYNC | libc::O_NOATIME | libc::O_NONBLOCK;
        let f2 = unsafe { libc::open(path2.as_ptr(), every, 0o644) };
        line("a file opened with every flag at once", flags(f2));
        line("  F_CREATED_QUERY on it", fcntl(f2, F_CREATED_QUERY, 0));
        let f3 = unsafe { libc::open(path2.as_ptr(), libc::O_RDONLY | libc::O_CREAT, 0o644) };
        line("  F_CREATED_QUERY on a second O_CREAT open of it", fcntl(f3, F_CREATED_QUERY, 0));
        let dsync = unsafe { libc::open(path2.as_ptr(), libc::O_RDONLY | libc::O_DSYNC) };
        line("a file opened O_DSYNC", flags(dsync));
        let pd = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        line("O_PATH|O_DIRECTORY|O_CLOEXEC on a directory", flags(pd));
        let pf = unsafe { libc::open(path2.as_ptr(), libc::O_PATH | libc::O_DIRECTORY) };
        line("O_PATH|O_DIRECTORY on a regular file", if pf < 0 { named(errno()) } else { flags(pf) });
        unsafe {
            libc::close(f2);
            libc::close(f3);
            libc::close(dsync);
            libc::close(pd);
            if pf >= 0 { libc::close(pf); }
            libc::unlink(path2.as_ptr());
        }
    }

    println!("## F_SETFL: which bits take");
    line("F_SETFL(O_NONBLOCK) on the file", fcntl(file, libc::F_SETFL, libc::O_NONBLOCK as i64));
    line("  flags after", flags(file));
    line("F_SETFL(0) clears O_APPEND too", fcntl(file, libc::F_SETFL, 0));
    line("  flags after", flags(file));
    line("F_SETFL(O_APPEND)", fcntl(file, libc::F_SETFL, libc::O_APPEND as i64));
    line("  flags after", flags(file));
    line("F_SETFL(O_RDONLY) cannot change the access mode", fcntl(file, libc::F_SETFL, 0));
    line("  flags after", flags(file));
    line("F_SETFL(O_CLOEXEC|O_CREAT|O_TRUNC), which are not status flags", fcntl(file, libc::F_SETFL, (libc::O_CLOEXEC | libc::O_CREAT | libc::O_TRUNC) as i64));
    line("  flags after", flags(file));
    line("F_SETFL(O_NOATIME) as the owner", fcntl(file, libc::F_SETFL, libc::O_NOATIME as i64));
    line("  flags after", flags(file));
    unsafe { libc::fcntl(file, libc::F_SETFL, 0) };
    as_user_1000(|| {
        line("F_SETFL(O_NOATIME) as somebody else", fcntl(file, libc::F_SETFL, libc::O_NOATIME as i64));
        line("  flags after", flags(file));
        line("F_SETFL(O_NONBLOCK) as somebody else, which needs nothing", fcntl(file, libc::F_SETFL, libc::O_NONBLOCK as i64));
    });
    line("F_SETFL(O_DIRECT) on a regular file", fcntl(file, libc::F_SETFL, libc::O_DIRECT as i64));
    line("  flags after", flags(file));
    line("F_SETFL(O_DIRECT) on a pipe, which is packet mode", fcntl(p[1], libc::F_SETFL, libc::O_DIRECT as i64));
    line("  flags after", flags(p[1]));
    line("  and the record boundary it makes", {
        // Two writes, one read: packet mode gives the first record alone.
        unsafe {
            libc::write(p[1], b"aaaa".as_ptr().cast(), 4);
            libc::write(p[1], b"bb".as_ptr().cast(), 2);
        }
        let mut buf = [0u8; 16];
        let n = unsafe { libc::read(p[0], buf.as_mut_ptr().cast(), 16) };
        let m = unsafe { libc::read(p[0], buf.as_mut_ptr().cast(), 16) };
        format!("{n} then {m}")
    });
    line("F_SETFL(0) on the pipe turns packet mode off again", fcntl(p[1], libc::F_SETFL, 0));
    line("  and two writes read as one", {
        unsafe {
            libc::write(p[1], b"aaaa".as_ptr().cast(), 4);
            libc::write(p[1], b"bb".as_ptr().cast(), 2);
        }
        let mut buf = [0u8; 16];
        unsafe { libc::read(p[0], buf.as_mut_ptr().cast(), 16) }.to_string()
    });
    line("F_SETFL(O_DIRECT) on a socket", fcntl(sock, libc::F_SETFL, libc::O_DIRECT as i64));
    line("  flags after", flags(sock));
    line("F_SETFL(O_ASYNC) on a socket", fcntl(sock, libc::F_SETFL, libc::O_ASYNC as i64));
    line("  flags after", flags(sock));
    line("F_SETFL(O_ASYNC) on a pipe", fcntl(p[0], libc::F_SETFL, libc::O_ASYNC as i64));
    line("  flags after", flags(p[0]));
    line("F_SETFL(O_ASYNC) on a regular file, which has no fasync", fcntl(file, libc::F_SETFL, libc::O_ASYNC as i64));
    line("  flags after", flags(file));
    unsafe { libc::fcntl(p[0], libc::F_SETFL, 0) };
    line("F_SETFL(O_SYNC), which cannot be set this way", fcntl(file, libc::F_SETFL, libc::O_SYNC as i64));
    line("  flags after", flags(file));
    line("F_SETFL(0x40000000), a bit that means nothing", fcntl(file, libc::F_SETFL, 0x4000_0000));
    line("  flags after", flags(file));
    line("F_SETFL(O_NONBLOCK) on an O_PATH descriptor", fcntl(opath, libc::F_SETFL, libc::O_NONBLOCK as i64));
    line("  flags after", flags(opath));
    unsafe { libc::fcntl(file, libc::F_SETFL, libc::O_APPEND) };

    println!("## F_GETFD and F_SETFD");
    line("F_GETFD on a fresh descriptor", fcntl(file, libc::F_GETFD, 0));
    line("F_SETFD(FD_CLOEXEC)", fcntl(file, libc::F_SETFD, libc::FD_CLOEXEC as i64));
    line("  F_GETFD after", fcntl(file, libc::F_GETFD, 0));
    line("F_SETFD(0xff), every bit", fcntl(file, libc::F_SETFD, 0xff));
    line("  F_GETFD after, only the one bit is kept", fcntl(file, libc::F_GETFD, 0));
    line("F_SETFD(0)", fcntl(file, libc::F_SETFD, 0));
    line("  F_GETFD after", fcntl(file, libc::F_GETFD, 0));
    line("F_SETFD(-1)", fcntl(file, libc::F_SETFD, -1));
    line("  F_GETFD after", fcntl(file, libc::F_GETFD, 0));
    unsafe { libc::fcntl(file, libc::F_SETFD, 0) };

    println!("## F_DUPFD");
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    line("F_DUPFD(0) answers a new descriptor", {
        let r = unsafe { libc::fcntl(file, libc::F_DUPFD, 0) };
        if r < 0 { named(errno()) } else { let s = (r != file && r >= 0).to_string(); unsafe { libc::close(r) }; s }
    });
    line("F_DUPFD(100) lands at or above 100", {
        let r = unsafe { libc::fcntl(file, libc::F_DUPFD, 100) };
        if r < 0 { named(errno()) } else { let s = (r >= 100).to_string(); unsafe { libc::close(r) }; s }
    });
    line("F_DUPFD(RLIMIT_NOFILE)", fcntl(file, libc::F_DUPFD, lim.rlim_cur as i64));
    line("F_DUPFD(RLIMIT_NOFILE - 1)", {
        let r = unsafe { libc::fcntl(file, libc::F_DUPFD, lim.rlim_cur as i32 - 1) };
        if r < 0 { named(errno()) } else { let s = (r == lim.rlim_cur as i32 - 1).to_string(); unsafe { libc::close(r) }; s }
    });
    line("F_DUPFD(-1)", fcntl(file, libc::F_DUPFD, -1));
    line("F_DUPFD(1 << 40), which is F_DUPFD(0) in 32 bits", {
        let r = unsafe { libc::fcntl(file, libc::F_DUPFD, 1u64 << 40) };
        if r < 0 { named(errno()) } else { let s = (r >= 0).to_string(); unsafe { libc::close(r) }; s }
    });
    line("F_DUPFD((1 << 32) | 200) lands at or above 200", {
        let r = unsafe { libc::fcntl(file, libc::F_DUPFD, (1u64 << 32) | 200) };
        if r < 0 { named(errno()) } else { let s = (r >= 200).to_string(); unsafe { libc::close(r) }; s }
    });
    line("F_DUPFD_CLOEXEC sets the flag on the copy", {
        let r = unsafe { libc::fcntl(file, F_DUPFD_CLOEXEC, 0) };
        if r < 0 { named(errno()) } else { let s = fcntl(r, libc::F_GETFD, 0); unsafe { libc::close(r) }; s }
    });
    line("F_DUPFD_QUERY(same fd)", fcntl(file, F_DUPFD_QUERY, file as i64));
    line("F_DUPFD_QUERY(a dup of it)", {
        let d = unsafe { libc::dup(file) };
        let s = fcntl(file, F_DUPFD_QUERY, d as i64);
        unsafe { libc::close(d) };
        s
    });
    line("F_DUPFD_QUERY(other fd)", fcntl(file, F_DUPFD_QUERY, ro as i64));
    line("F_DUPFD_QUERY(999)", fcntl(file, F_DUPFD_QUERY, 999));
    // `do_fcntl` opens with `int argi = (int)arg;` and hands *that* to every
    // command that wants a number, so `(1 << 32) | fd` is `fd`. The two
    // F_DUPFD cases above ask the same of the descriptor-number argument; this
    // asks it of the one command whose argument is a descriptor to compare
    // against, where a kernel that kept all 64 bits would answer EBADF.
    line("F_DUPFD_QUERY((1 << 32) | same fd)", fcntl(file, F_DUPFD_QUERY, (1i64 << 32) | file as i64));
    line("F_CREATED_QUERY on the file this opened with O_CREAT", fcntl(file, F_CREATED_QUERY, 0));
    line("F_CREATED_QUERY on the read-only open of it", fcntl(ro, F_CREATED_QUERY, 0));
    line("F_CREATED_QUERY on a pipe", fcntl(p[0], F_CREATED_QUERY, 0));

    println!("## owners and signals, for SIGIO");
    line("F_GETOWN on the socket, nobody yet", fcntl(sock, libc::F_GETOWN, 0));
    line("F_SETOWN(getpid) on the socket", fcntl(sock, libc::F_SETOWN, unsafe { libc::getpid() } as i64));
    line("  F_GETOWN after, is it us", {
        let r = unsafe { libc::fcntl(sock, libc::F_GETOWN) };
        (r == unsafe { libc::getpid() }).to_string()
    });
    line("F_SETOWN(-getpgrp), a process group", fcntl(sock, libc::F_SETOWN, -(unsafe { libc::getpgrp() } as i64)));
    line("  F_GETOWN after, is it minus our group", {
        let r = unsafe { libc::fcntl(sock, libc::F_GETOWN) };
        (r == -unsafe { libc::getpgrp() }).to_string()
    });
    line("F_SETOWN(0) clears it", fcntl(sock, libc::F_SETOWN, 0));
    line("  F_GETOWN after", fcntl(sock, libc::F_GETOWN, 0));
    line("F_SETOWN(999999), no such process", fcntl(sock, libc::F_SETOWN, 999_999));
    line("F_SETOWN on a regular file", fcntl(file, libc::F_SETOWN, unsafe { libc::getpid() } as i64));
    line("F_SETOWN on a pipe", fcntl(p[0], libc::F_SETOWN, unsafe { libc::getpid() } as i64));
    line("F_GETOWN_EX into NULL", fcntl(sock, F_GETOWN_EX, 0));
    line("F_GETOWN_EX", {
        let mut ex = [0i32; 2];
        let r = unsafe { libc::syscall(libc::SYS_fcntl, sock, F_GETOWN_EX, ex.as_mut_ptr()) };
        if r < 0 { named(errno()) } else { format!("type {} pid-is-us {}", ex[0], ex[1] == unsafe { libc::getpid() }) }
    });
    line("F_SETOWN_EX(F_OWNER_TID, gettid)", {
        let ex = [0i32, unsafe { libc::gettid() }];
        fcntl(sock, F_SETOWN_EX, ex.as_ptr() as i64)
    });
    line("F_SETOWN_EX(type 7)", {
        let ex = [7i32, unsafe { libc::getpid() }];
        fcntl(sock, F_SETOWN_EX, ex.as_ptr() as i64)
    });
    line("F_GETSIG, the default", fcntl(sock, F_GETSIG, 0));
    line("F_SETSIG(SIGUSR1)", fcntl(sock, F_SETSIG, libc::SIGUSR1 as i64));
    line("  F_GETSIG after", fcntl(sock, F_GETSIG, 0));
    line("F_SETSIG(0), back to SIGIO", fcntl(sock, F_SETSIG, 0));
    line("F_SETSIG(65)", fcntl(sock, F_SETSIG, 65));
    line("F_SETSIG(-1)", fcntl(sock, F_SETSIG, -1));
    // `argi` again: `valid_signal(argi)` is asked of the truncated number, so
    // this is F_SETSIG(SIGUSR1) and not a nonsense signal.
    line("F_SETSIG((1 << 32) | SIGUSR1)", fcntl(sock, F_SETSIG, (1i64 << 32) | libc::SIGUSR1 as i64));
    line("  F_GETSIG after", fcntl(sock, F_GETSIG, 0));
    line("F_SETSIG(0), back to SIGIO", fcntl(sock, F_SETSIG, 0));

    println!("## leases and notification");
    line("F_GETLEASE on the file", fcntl(file, F_GETLEASE, 0));
    line("F_SETLEASE(F_RDLCK) on a file open for writing", fcntl(file, F_SETLEASE, libc::F_RDLCK as i64));
    line("F_SETLEASE(F_RDLCK) on a file open read-only", fcntl(ro, F_SETLEASE, libc::F_RDLCK as i64));
    line("  F_GETLEASE after", fcntl(ro, F_GETLEASE, 0));
    line("F_SETLEASE(F_UNLCK)", fcntl(ro, F_SETLEASE, libc::F_UNLCK as i64));
    line("F_SETLEASE(F_WRLCK) while it is open elsewhere", fcntl(file, F_SETLEASE, libc::F_WRLCK as i64));
    line("F_SETLEASE(7)", fcntl(file, F_SETLEASE, 7));
    line("F_SETLEASE on a pipe", fcntl(p[0], F_SETLEASE, libc::F_RDLCK as i64));
    line("F_SETLEASE(F_UNLCK) on a pipe", fcntl(p[0], F_SETLEASE, libc::F_UNLCK as i64));
    line("F_GETLEASE on a pipe", fcntl(p[0], F_GETLEASE, 0));
    as_user_1000(|| {
        line("F_SETLEASE(F_RDLCK) as somebody else", fcntl(ro, F_SETLEASE, libc::F_RDLCK as i64));
    });
    line("F_NOTIFY(DN_MODIFY) on a directory", fcntl(dir, F_NOTIFY, 2));
    line("F_NOTIFY(DN_MODIFY) on a file", fcntl(file, F_NOTIFY, 2));
    line("F_NOTIFY(0) on a directory", fcntl(dir, F_NOTIFY, 0));
    line("F_NOTIFY(0x100) on a directory", fcntl(dir, F_NOTIFY, 0x100));

    println!("## pipes and hints");
    line("F_GETPIPE_SZ on the pipe", fcntl(p[0], F_GETPIPE_SZ, 0));
    line("F_GETPIPE_SZ on a file", fcntl(file, F_GETPIPE_SZ, 0));
    line("F_SETPIPE_SZ(0)", fcntl(p[0], F_SETPIPE_SZ, 0));
    line("  F_GETPIPE_SZ after", fcntl(p[0], F_GETPIPE_SZ, 0));
    line("F_SETPIPE_SZ(1)", fcntl(p[0], F_SETPIPE_SZ, 1));
    line("  F_GETPIPE_SZ after", fcntl(p[0], F_GETPIPE_SZ, 0));
    line("F_SETPIPE_SZ(1 << 20)", fcntl(p[0], F_SETPIPE_SZ, 1 << 20));
    line("F_SETPIPE_SZ((1 << 32) | 4096), which is 4096 in 32 bits", fcntl(p[0], F_SETPIPE_SZ, (1 << 32) | 4096));
    as_user_1000(|| {
        // pipe_max_size is 1 MB for a caller without CAP_SYS_RESOURCE, and the
        // limit is compared against the rounded size.
        line("F_SETPIPE_SZ(1 << 31) unprivileged", fcntl(p[0], F_SETPIPE_SZ, 1 << 31));
        line("F_SETPIPE_SZ((1 << 20) + 1) unprivileged", fcntl(p[0], F_SETPIPE_SZ, (1 << 20) + 1));
        line("F_SETPIPE_SZ(1 << 20) unprivileged", fcntl(p[0], F_SETPIPE_SZ, 1 << 20));
        line("F_SETPIPE_SZ(-1) unprivileged", fcntl(p[0], F_SETPIPE_SZ, -1));
    });
    line("F_SETPIPE_SZ(-1)", fcntl(p[0], F_SETPIPE_SZ, -1));
    line("F_SETPIPE_SZ on a file", fcntl(file, F_SETPIPE_SZ, 65536));
    line("F_GET_RW_HINT into NULL", fcntl(file, F_GET_RW_HINT, 0));
    let rw_hint = |fd: i32| -> String {
        let mut hint: u64 = 99;
        let r = unsafe { libc::syscall(libc::SYS_fcntl, fd, F_GET_RW_HINT, &mut hint as *mut u64) };
        if r < 0 { named(errno()) } else { hint.to_string() }
    };
    line("F_GET_RW_HINT", rw_hint(file));
    line("F_SET_RW_HINT(2)", {
        let hint: u64 = 2;
        fcntl(file, F_SET_RW_HINT, &hint as *const u64 as i64)
    });
    line("  F_GET_RW_HINT after", rw_hint(file));
    line("  F_GET_RW_HINT through another descriptor of the file", rw_hint(ro));
    line("F_SET_RW_HINT(99)", {
        let hint: u64 = 99;
        fcntl(file, F_SET_RW_HINT, &hint as *const u64 as i64)
    });
    line("F_SET_RW_HINT(5), the largest", {
        let hint: u64 = 5;
        fcntl(file, F_SET_RW_HINT, &hint as *const u64 as i64)
    });
    line("F_SET_RW_HINT into NULL", fcntl(file, F_SET_RW_HINT, 0));
    line("F_GET_RW_HINT on a pipe", rw_hint(p[0]));
    line("F_GET_FILE_RW_HINT", {
        let mut hint: u64 = 99;
        let r = unsafe { libc::syscall(libc::SYS_fcntl, file, F_GET_FILE_RW_HINT, &mut hint as *mut u64) };
        if r < 0 { named(errno()) } else { hint.to_string() }
    });
    line("F_SET_FILE_RW_HINT(2)", {
        let hint: u64 = 2;
        fcntl(file, F_SET_FILE_RW_HINT, &hint as *const u64 as i64)
    });

    // Nothing tested these until 2026-09-16, and the way that was established
    // is the point: inverting `FIONBIO`'s argument -- so that 1 clears
    // O_NONBLOCK and 0 sets it -- left `guest_tests.sh`, `smoke.sh` and every
    // probe green. `fcntl_probe` covered the `F_SETFL` spelling and nothing
    // covered the `ioctl` one, which is a different function in this kernel.
    println!("## the FIO* ioctls, which are F_SETFL and F_SETOWN written another way");
    const FIONBIO: u64 = 0x5421;
    const FIOASYNC: u64 = 0x5452;
    const FIOCLEX: u64 = 0x5451;
    const FIONCLEX: u64 = 0x5450;
    const FIOSETOWN: u64 = 0x8901;
    const FIOGETOWN: u64 = 0x8903;

    line("FIONBIO(1) on a pipe", ioctl_word(p[0], FIONBIO, 1));
    line("  flags after", flags(p[0]));
    line("FIONBIO(0) on a pipe", ioctl_word(p[0], FIONBIO, 0));
    line("  flags after", flags(p[0]));
    line("FIONBIO(1) on a regular file", ioctl_word(file, FIONBIO, 1));
    line("  flags after", flags(file));
    line("FIONBIO(0) on a regular file", ioctl_word(file, FIONBIO, 0));
    line("  flags after", flags(file));

    line("FIOASYNC(1) on a socket", ioctl_word(sock, FIOASYNC, 1));
    line("  flags after", flags(sock));
    line("FIOASYNC(0) on a socket", ioctl_word(sock, FIOASYNC, 0));
    line("  flags after", flags(sock));
    // The rule `set_async` exists for: Linux compares against `f_flags` first
    // and returns 0 when nothing changes, so clearing it on a file that never
    // had it succeeds even though the file has no `fasync`.
    line("FIOASYNC(0) on a regular file, which has no fasync", ioctl_word(file, FIOASYNC, 0));
    line("FIOASYNC(1) on a regular file", ioctl_word(file, FIOASYNC, 1));
    line("  flags after", flags(file));

    line("FIOCLEX on a pipe", {
        let r = unsafe { libc::ioctl(p[0], FIOCLEX as _) };
        if r < 0 { named(errno()) } else { r.to_string() }
    });
    line("  F_GETFD after", fcntl(p[0], libc::F_GETFD, 0));
    line("FIONCLEX on a pipe", {
        let r = unsafe { libc::ioctl(p[0], FIONCLEX as _) };
        if r < 0 { named(errno()) } else { r.to_string() }
    });
    line("  F_GETFD after", fcntl(p[0], libc::F_GETFD, 0));

    line("FIOSETOWN(pid) on a socket", ioctl_word(sock, FIOSETOWN, unsafe { libc::getpid() }));
    line("  F_GETOWN after", fcntl(sock, libc::F_GETOWN, 0));
    line("FIOGETOWN on a socket", {
        let mut got: i32 = 0;
        let r = unsafe { libc::ioctl(sock, FIOGETOWN as _, &mut got as *mut i32) };
        if r < 0 { named(errno()) } else { format!("{r}, owner {}", i32::from(got == unsafe { libc::getpid() })) }
    });
    line("FIONBIO on a descriptor nobody has", ioctl_word(999, FIONBIO, 1));
    line("FIONBIO on an O_PATH descriptor", ioctl_word(opath, FIONBIO, 1));

    println!("## a command nobody knows, and a descriptor nobody has");
    line("fcntl(file, 99)", fcntl(file, 99, 0));
    line("fcntl(file, -1)", fcntl(file, -1, 0));
    line("fcntl(999, F_GETFD)", fcntl(999, libc::F_GETFD, 0));
    line("fcntl(999, 99), the descriptor is judged first", fcntl(999, 99, 0));
    line("fcntl(-1, F_GETFD)", fcntl(-1, libc::F_GETFD, 0));

    unsafe {
        libc::close(file);
        libc::close(ro);
        libc::close(opath);
        libc::close(dir);
        libc::close(sock);
        libc::close(p[0]);
        libc::close(p[1]);
        libc::close(dp[0]);
        libc::close(dp[1]);
        libc::unlink(path.as_ptr());
    }
}
