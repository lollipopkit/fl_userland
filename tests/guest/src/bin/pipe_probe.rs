//! What a pipe does.
//!
//! **A report, not a check** — the seventh in the shape `mmap_probe`
//! established. One line per case, never fails, diffed against an arm64
//! container by `tests/integration/probe_diff.sh`.
//!
//! A pipe here is a **host pipe**: `fs/pipe.c` is 81 lines that call `pipe(2)`
//! and hand each end to `realfs_fdops`. So every answer below is macOS's unless
//! something in between changed it, and the ones that differ are the
//! specification for a pipe this kernel would own itself. That is not a
//! hypothetical: `tee(2)` copies bytes out of a pipe *without consuming them*
//! and cannot be written against a host pipe at all, so it is `ENOSYS` today.
//!
//! Nothing here blocks. Both ends are `O_NONBLOCK` wherever a case could fill
//! or empty the pipe, because a probe that parks is a probe that reports
//! nothing — and because "what happens when it is full" is most of the
//! question.

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn name(e: i32) -> String {
    let s = match e {
        libc::EINVAL => "EINVAL",
        libc::EAGAIN => "EAGAIN",
        libc::EPIPE => "EPIPE",
        libc::EBADF => "EBADF",
        libc::ESPIPE => "ESPIPE",
        libc::EFAULT => "EFAULT",
        libc::EPERM => "EPERM",
        libc::ENOSYS => "ENOSYS",
        libc::EBUSY => "EBUSY",
        libc::ENOTTY => "ENOTTY",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EISDIR => "EISDIR",
        _ => return format!("errno {e}"),
    };
    s.into()
}

/// Run `f` in a forked child as uid 1000, so that a case whose answer depends
/// on a capability is asked without one. The parent waits, so the output stays
/// in order.
fn as_user_1000(f: impl FnOnce()) {
    use std::io::Write;
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

fn report(what: &str, r: i64) {
    if r < 0 {
        println!("{what:<52} -> {}", name(errno()));
    } else {
        println!("{what:<52} -> {r}");
    }
}

fn value(what: &str, v: i64) {
    println!("{what:<52} -> {v}");
}

/// A pipe with both ends non-blocking.
fn pipe() -> (i32, i32) {
    let mut fds = [0i32; 2];
    assert!(unsafe { libc::pipe(fds.as_mut_ptr()) } == 0, "pipe failed");
    for f in fds {
        unsafe { libc::fcntl(f, libc::F_SETFL, libc::O_NONBLOCK) };
    }
    (fds[0], fds[1])
}

fn close2(a: i32, b: i32) {
    unsafe {
        libc::close(a);
        libc::close(b);
    }
}

fn write_n(fd: i32, n: usize) -> i64 {
    let buf = vec![0x5au8; n];
    unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, n) as i64 }
}

fn read_n(fd: i32, n: usize) -> i64 {
    let mut buf = vec![0u8; n];
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, n) as i64 }
}

const F_GETPIPE_SZ: i32 = 1032;
const F_SETPIPE_SZ: i32 = 1031;
/// **arm64 overrides asm-generic here.** `asm-generic/fcntl.h` has
/// `O_DIRECT = 00040000`, and `arch/arm64/include/uapi/asm/fcntl.h` replaces it
/// with `0200000` — on arm64, `0o40000` is `O_DIRECTORY`. The first run of this
/// probe used the generic value, so both sides refused `pipe2(O_DIRECTORY)` and
/// agreed perfectly about a question neither had been asked.
const O_DIRECT: i32 = 0o200000;

fn main() {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

    println!("## pipe2 flags");
    for (n, f) in [
        ("0", 0i32),
        ("O_CLOEXEC", libc::O_CLOEXEC),
        ("O_NONBLOCK", libc::O_NONBLOCK),
        ("O_DIRECT (packet mode)", O_DIRECT),
        ("O_CLOEXEC|O_NONBLOCK", libc::O_CLOEXEC | libc::O_NONBLOCK),
        ("O_APPEND", libc::O_APPEND),
        ("O_RDWR", libc::O_RDWR),
        ("an undefined bit (0x8000000)", 0x800_0000),
    ] {
        let mut fds = [0i32; 2];
        let r = unsafe { libc::syscall(libc::SYS_pipe2, fds.as_mut_ptr(), f) };
        report(&format!("pipe2(flags={n})"), r);
        if r == 0 {
            close2(fds[0], fds[1]);
        }
    }
    {
        // What the flags actually did, rather than whether they were accepted.
        let mut fds = [0i32; 2];
        unsafe { libc::syscall(libc::SYS_pipe2, fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        value("  FD_CLOEXEC is set on the read end", unsafe {
            (libc::fcntl(fds[0], libc::F_GETFD) & libc::FD_CLOEXEC != 0) as i64
        });
        value("  O_NONBLOCK is set on the write end", unsafe {
            (libc::fcntl(fds[1], libc::F_GETFL) & libc::O_NONBLOCK != 0) as i64
        });
        value("  the read end's access mode", unsafe {
            (libc::fcntl(fds[0], libc::F_GETFL) & libc::O_ACCMODE) as i64
        });
        value("  the write end's access mode", unsafe {
            (libc::fcntl(fds[1], libc::F_GETFL) & libc::O_ACCMODE) as i64
        });
        close2(fds[0], fds[1]);
    }

    println!("## how much a pipe holds");
    {
        let (r, w) = pipe();
        report("F_GETPIPE_SZ", unsafe {
            libc::fcntl(w, F_GETPIPE_SZ) as i64
        });
        // Filling it says the same thing without asking, which is the check on
        // the answer above: a kernel may report a capacity it does not have.
        let mut total = 0i64;
        loop {
            let n = write_n(w, 4096);
            if n <= 0 {
                break;
            }
            total += n;
            if total > 8 * 1024 * 1024 {
                break; // something is wrong; do not loop for ever
            }
        }
        value("bytes written before it was full", total);
        report("the write that found it full", write_n(w, 1));
        value("and then reading it all back gives", {
            let mut got = 0i64;
            loop {
                let n = read_n(r, 4096);
                if n <= 0 {
                    break;
                }
                got += n;
            }
            got
        });
        report("the read that found it empty", read_n(r, 1));
        close2(r, w);
    }

    println!("## F_SETPIPE_SZ");
    for (n, sz) in [
        ("4096", 4096i64),
        ("1", 1),
        ("0", 0),
        ("65536", 65536),
        ("100000 (not a power of two)", 100_000),
        ("-1", -1),
    ] {
        let (r, w) = pipe();
        let set = unsafe { libc::fcntl(w, F_SETPIPE_SZ, sz) as i64 };
        report(&format!("F_SETPIPE_SZ({n})"), set);
        if set >= 0 {
            value("  F_GETPIPE_SZ then says", unsafe {
                libc::fcntl(w, F_GETPIPE_SZ) as i64
            });
        }
        close2(r, w);
    }
    // 0x7fffffff rounds up to 2 GiB, which is above `pipe_max_size` — so this
    // has to be asked **unprivileged**, and not because a container's root has
    // no CAP_SYS_RESOURCE and this kernel's root does. Asked as root the call
    // *succeeds* and answers 2^31, which does not fit the `int` that `fcntl`
    // returns: both sides hand back INT_MIN and both then print whatever
    // `errno` was left at, which is a line that can differ for no reason.
    // Unprivileged, both answer EPERM, and the check is a check.
    as_user_1000(|| {
        let (r, w) = pipe();
        report("F_SETPIPE_SZ(0x7fffffff) unprivileged", unsafe {
            libc::fcntl(w, F_SETPIPE_SZ, 0x7fff_ffffi64) as i64
        });
        close2(r, w);
    });

    {
        // Shrinking below what is already in the pipe.
        let (r, w) = pipe();
        write_n(w, 8192);
        report("F_SETPIPE_SZ(4096) with 8192 bytes queued", unsafe {
            libc::fcntl(w, F_SETPIPE_SZ, 4096) as i64
        });
        close2(r, w);
    }

    println!("## when one end is gone");
    {
        let (r, w) = pipe();
        unsafe { libc::close(r) };
        report("write with no readers", write_n(w, 4));
        unsafe { libc::close(w) };
    }
    {
        let (r, w) = pipe();
        unsafe { libc::write(w, b"abc".as_ptr() as *const libc::c_void, 3) };
        unsafe { libc::close(w) };
        report("read of what is left after the writer closed", read_n(r, 8));
        report("the read after that", read_n(r, 8));
        report("and the one after that", read_n(r, 8));
        unsafe { libc::close(r) };
    }
    {
        // SIGPIPE, rather than the errno. Ignored at the top of main, so this
        // asks whether it was *raised* -- sigpending sees it either way.
        let (r, w) = pipe();
        unsafe { libc::close(r) };
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut set) };
        unsafe { libc::sigaddset(&mut set, libc::SIGPIPE) };
        unsafe { libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
        write_n(w, 4);
        let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigpending(&mut pending) };
        value("a write with no readers left SIGPIPE pending", unsafe {
            libc::sigismember(&pending, libc::SIGPIPE) as i64
        });
        unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
        unsafe { libc::close(w) };
    }

    println!("## reading and writing the wrong end");
    {
        let (r, w) = pipe();
        report("write to the read end", write_n(r, 4));
        report("read from the write end", read_n(w, 4));
        close2(r, w);
    }

    println!("## a pipe is not a file");
    {
        let (r, w) = pipe();
        report("lseek(0, SEEK_SET)", unsafe { libc::lseek(r, 0, libc::SEEK_SET) as i64 });
        report("lseek(0, SEEK_CUR)", unsafe { libc::lseek(r, 0, libc::SEEK_CUR) as i64 });
        report("ftruncate(0)", unsafe { libc::ftruncate(w, 0) as i64 });
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        report("fstat", unsafe { libc::fstat(r, &mut st) as i64 });
        value("  S_ISFIFO", ((st.st_mode & libc::S_IFMT) == libc::S_IFIFO) as i64);
        value("  st_size", st.st_size as i64);
        value("  st_nlink", st.st_nlink as i64);
        value("  the permission bits", (st.st_mode & 0o7777) as i64);
        close2(r, w);
    }

    println!("## FIONREAD");
    {
        let (r, w) = pipe();
        let mut n = 0i32;
        report("ioctl(FIONREAD) on an empty pipe", unsafe {
            libc::ioctl(r, libc::FIONREAD, &mut n) as i64
        });
        value("  it says", n as i64);
        write_n(w, 100);
        unsafe { libc::ioctl(r, libc::FIONREAD, &mut n) };
        value("after writing 100 bytes it says", n as i64);
        let mut m = 0i32;
        report("ioctl(FIONREAD) on the write end", unsafe {
            libc::ioctl(w, libc::FIONREAD, &mut m) as i64
        });
        report("ioctl(an unknown request)", unsafe {
            libc::ioctl(r, 0x1234_5678, &mut n) as i64
        });
        close2(r, w);
    }

    println!("## poll");
    {
        let (r, w) = pipe();
        let mut pfd = [
            libc::pollfd { fd: r, events: (libc::POLLIN | libc::POLLOUT) as i16, revents: 0 },
            libc::pollfd { fd: w, events: (libc::POLLIN | libc::POLLOUT) as i16, revents: 0 },
        ];
        unsafe { libc::poll(pfd.as_mut_ptr(), 2, 0) };
        value("an empty pipe: the read end's revents", pfd[0].revents as i64);
        value("  the write end's revents", pfd[1].revents as i64);
        write_n(w, 4);
        pfd[0].revents = 0;
        pfd[1].revents = 0;
        unsafe { libc::poll(pfd.as_mut_ptr(), 2, 0) };
        value("with 4 bytes in it: the read end", pfd[0].revents as i64);
        value("  the write end", pfd[1].revents as i64);
        unsafe { libc::close(w) };
        pfd[0].revents = 0;
        unsafe { libc::poll(pfd.as_mut_ptr(), 1, 0) };
        value("after the writer closed: the read end", pfd[0].revents as i64);
        unsafe { libc::close(r) };
    }
    {
        // A full pipe's write end must not say POLLOUT.
        let (r, w) = pipe();
        while write_n(w, 4096) > 0 {}
        let mut pfd = [libc::pollfd { fd: w, events: libc::POLLOUT as i16, revents: 0 }];
        unsafe { libc::poll(pfd.as_mut_ptr(), 1, 0) };
        value("a full pipe: the write end's revents", pfd[0].revents as i64);
        unsafe { libc::close(r) };
        pfd[0].revents = 0;
        unsafe { libc::poll(pfd.as_mut_ptr(), 1, 0) };
        value("...and once the reader is gone", pfd[0].revents as i64);
        unsafe { libc::close(w) };
    }

    println!("## a write larger than the pipe holds");
    {
        let (r, w) = pipe();
        // Non-blocking and larger than the capacity: Linux writes what fits.
        let n = write_n(w, 1 << 20);
        if n < 0 {
            report("write(1 MiB) to an empty non-blocking pipe", n);
        } else {
            println!("{:<52} -> wrote a partial amount", "write(1 MiB) to an empty non-blocking pipe");
        }
        // Drain, then a PIPE_BUF-sized write into a pipe with a little room:
        // Linux makes writes up to PIPE_BUF atomic, so this one must not go
        // partially in.
        while read_n(r, 65536) > 0 {}
        let cap_probe = write_n(w, 4096);
        value("a 4096-byte write into an empty pipe", cap_probe);
        close2(r, w);
    }
    {
        // Fill to within 100 bytes of full, then ask for PIPE_BUF.
        let (r, w) = pipe();
        let mut cap = 0i64;
        while write_n(w, 4096) > 0 {
            cap += 4096;
        }
        if cap >= 4096 {
            read_n(r, 100);
            let n = write_n(w, 4096);
            // Atomic means all or nothing: either 4096 or EAGAIN, never 100.
            if n < 0 {
                report("PIPE_BUF write with 100 bytes of room", n);
            } else {
                value("PIPE_BUF write with 100 bytes of room wrote", n);
            }
            // A write *above* PIPE_BUF has no such promise.
            read_n(r, 100);
            let n = write_n(w, 8192);
            if n < 0 {
                report("an 8192-byte write with 100 bytes of room", n);
            } else {
                value("an 8192-byte write with 100 bytes of room wrote", n);
            }
        }
        close2(r, w);
    }

    println!("## O_DIRECT, if it exists");
    {
        let mut fds = [0i32; 2];
        let made = unsafe { libc::syscall(libc::SYS_pipe2, fds.as_mut_ptr(), O_DIRECT | libc::O_NONBLOCK) };
        if made == 0 {
            let (r, w) = (fds[0], fds[1]);
            // Three packets in; each read returns exactly one, and a short
            // read discards the rest of its packet.
            write_n(w, 10);
            write_n(w, 20);
            write_n(w, 30);
            value("packet mode: the first read of 100", read_n(r, 100));
            value("  the second read of 5 (discards the rest)", read_n(r, 5));
            value("  the third read of 100", read_n(r, 100));
            value("  the fourth read", read_n(r, 100));
            close2(r, w);
        } else {
            println!("{:<52} -> not supported", "packet mode");
        }
    }

    println!("## the descriptors themselves");
    {
        let (r, w) = pipe();
        let dup = unsafe { libc::dup(w) };
        unsafe { libc::close(w) };
        report("write through a dup of the write end", write_n(dup, 4));
        report("read it back", read_n(r, 8));
        unsafe { libc::close(dup) };
        report("read after every writer is closed", read_n(r, 8));
        unsafe { libc::close(r) };
    }
}
