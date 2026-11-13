//! What `fcntl` record locks answer, at their edges.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! POSIX record locks are a small interface with a long list of rules that
//! programs depend on without saying so: which errno a conflict is, what
//! `F_GETLK` reports and in what coordinates, that a negative length runs
//! backwards and a zero one to the end of the file, that adjacent locks of one
//! owner merge and a partial unlock splits, that a deadlock is refused rather
//! than waited on, and the rule everyone learns the hard way -- closing *any*
//! descriptor on the file drops every lock the process holds on it, which is
//! why open-file-description locks exist. SQLite, dpkg, git and every mail
//! spool are written against these.
//!
//! # Every conflicting party is a forked child
//!
//! A lock never conflicts with its own owner, so a conflict needs a second
//! process. Each case forks one, the child does its part and prints its own
//! lines, and the parent waits before going on -- so the output is in one
//! order on both kernels. Standard output is flushed before every fork so a
//! buffered line is not printed twice.
//!
//! # Every case has its own file
//!
//! Locks belong to the file, so a case that left one behind would decide the
//! next one's answer.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<58} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> &'static str {
    match e {
        0 => "ok",
        libc::EAGAIN => "EAGAIN",
        libc::EACCES => "EACCES",
        libc::EBADF => "EBADF",
        libc::EINVAL => "EINVAL",
        libc::EDEADLK => "EDEADLK",
        libc::EINTR => "EINTR",
        libc::EOVERFLOW => "EOVERFLOW",
        libc::ENOLCK => "ENOLCK",
        _ => "other",
    }
}

/// `fcntl`'s answer as a word.
fn outcome(r: i32) -> String {
    if r < 0 { named(errno()).to_string() } else { "ok".to_string() }
}

fn flock(ty: i32, whence: i32, start: i64, len: i64) -> libc::flock {
    libc::flock {
        l_type: ty as i16,
        l_whence: whence as i16,
        l_start: start,
        l_len: len,
        l_pid: 0,
    }
}

fn setlk(fd: i32, cmd: i32, ty: i32, start: i64, len: i64) -> String {
    let l = flock(ty, libc::SEEK_SET, start, len);
    outcome(unsafe { libc::fcntl(fd, cmd, &l) })
}

/// What `F_GETLK` (or the OFD form) reports for a query: "free", or the
/// conflicting lock's type, whence, start, length and whose it is -- "parent",
/// "self", "-1" for an OFD lock, or "other".
fn getlk(fd: i32, cmd: i32, ty: i32, start: i64, len: i64, parent: i32) -> String {
    let mut q = flock(ty, libc::SEEK_SET, start, len);
    let r = unsafe { libc::fcntl(fd, cmd, &mut q) };
    if r < 0 {
        return named(errno()).to_string();
    }
    if q.l_type == libc::F_UNLCK as i16 {
        return "free".to_string();
    }
    let ty = match q.l_type as i32 {
        libc::F_RDLCK => "read",
        libc::F_WRLCK => "write",
        _ => "?",
    };
    let who = if q.l_pid == parent {
        "parent".to_string()
    } else if q.l_pid == unsafe { libc::getpid() } {
        "self".to_string()
    } else if q.l_pid == -1 {
        "-1".to_string()
    } else {
        "other".to_string()
    };
    format!("{ty} lock, whence {}, start {}, len {}, held by {who}", q.l_whence, q.l_start, q.l_len)
}

const F_OFD_GETLK: i32 = 36;
const F_OFD_SETLK: i32 = 37;
const F_OFD_SETLKW: i32 = 38;

/// A fresh file of a hundred bytes for one case, opened read-write.
fn fresh(dir: &str, name: &str) -> i32 {
    let path = format!("{dir}/{name}\0");
    let fd = unsafe {
        libc::open(path.as_ptr().cast(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644)
    };
    let bytes = [b'x'; 100];
    unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    fd
}

/// Run `body` in a child that inherits every descriptor, and wait for it.
/// The child prints its own lines.
fn in_child(body: impl FnOnce()) {
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        body();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

fn main() {
    // Not `/tmp/lock_probe`: that is where the guest suite puts this binary,
    // and a directory that cannot be made turns every line below into
    // `EBADF` -- which the first run of this probe reported for all of them,
    // on one side only. The setup line is what says so now.
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/lock_probe.d".to_string());
    let made = unsafe { libc::mkdir(format!("{dir}\0").as_ptr().cast(), 0o755) };
    line(
        "setup: the scratch directory",
        if made == 0 || errno() == libc::EEXIST { "ok" } else { named(errno()) },
    );
    let me = unsafe { libc::getpid() };

    println!("## a conflict, seen from another process");
    {
        let fd = fresh(&dir, "conflict");
        line("parent: F_SETLK write [10,20)", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 10, 10));
        in_child(|| {
            line("child: F_SETLK write [10,20)", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 10, 10));
            line("child: F_SETLK read [15,25)", setlk(fd, libc::F_SETLK, libc::F_RDLCK, 15, 10));
            line("child: F_SETLK write [20,30), disjoint", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 20, 10));
            line("child: F_GETLK write [10,20)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 10, 10, me));
            line("child: F_GETLK read [0,100)", getlk(fd, libc::F_GETLK, libc::F_RDLCK, 0, 100, me));
            line("child: F_GETLK write [0,100)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 0, 100, me));
        });
        // Its own lock is never a conflict to itself.
        line("parent: F_GETLK write [10,20) on its own lock", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 10, 10, me));
        unsafe { libc::close(fd) };
    }

    println!("## read locks share, write locks do not");
    {
        let fd = fresh(&dir, "shared");
        line("parent: F_SETLK read [0,10)", setlk(fd, libc::F_SETLK, libc::F_RDLCK, 0, 10));
        in_child(|| {
            line("child: F_SETLK read [0,10)", setlk(fd, libc::F_SETLK, libc::F_RDLCK, 0, 10));
            line("child: F_SETLK write [0,10)", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 0, 10));
            line("child: F_GETLK write [0,10)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 0, 10, me));
        });
        unsafe { libc::close(fd) };
    }

    println!("## lengths: negative runs backwards, zero runs to the end");
    {
        let fd = fresh(&dir, "lengths");
        line("parent: F_SETLK write start 50 len -10", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 50, -10));
        line("parent: F_SETLK write start 90 len 0", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 90, 0));
        in_child(|| {
            line("child: F_GETLK [40,50)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 40, 10, me));
            line("child: F_GETLK [50,60)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 50, 10, me));
            line("child: F_GETLK [39,40)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 39, 1, me));
            line("child: F_GETLK [95,96)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 95, 1, me));
            line("child: F_GETLK [1000,1001), past the end", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 1000, 1, me));
            line("child: F_GETLK start 0 len 0, everything", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 0, 0, me));
        });
        unsafe { libc::close(fd) };
    }

    println!("## the origin: SEEK_CUR and SEEK_END");
    {
        let fd = fresh(&dir, "origin");
        unsafe { libc::lseek(fd, 30, libc::SEEK_SET) };
        let cur = flock(libc::F_WRLCK, libc::SEEK_CUR, 5, 5);
        line("parent: F_SETLK write SEEK_CUR+5 len 5 at offset 30", outcome(unsafe { libc::fcntl(fd, libc::F_SETLK, &cur) }));
        let end = flock(libc::F_WRLCK, libc::SEEK_END, -10, 5);
        line("parent: F_SETLK write SEEK_END-10 len 5", outcome(unsafe { libc::fcntl(fd, libc::F_SETLK, &end) }));
        in_child(|| {
            line("child: F_GETLK [35,40)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 35, 5, me));
            line("child: F_GETLK [90,95)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 90, 5, me));
            // What coordinates a query in SEEK_END terms is answered in.
            let mut q = flock(libc::F_WRLCK, libc::SEEK_END, -10, 5);
            let r = unsafe { libc::fcntl(fd, libc::F_GETLK, &mut q) };
            line(
                "child: F_GETLK asked in SEEK_END terms answers in",
                if r < 0 { named(errno()).to_string() } else { format!("whence {}, start {}, len {}", q.l_whence, q.l_start, q.l_len) },
            );
        });
        unsafe { libc::close(fd) };
    }

    println!("## a partial unlock splits, adjacent locks merge");
    {
        let fd = fresh(&dir, "split");
        line("parent: F_SETLK write [0,100)", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 0, 100));
        line("parent: F_SETLK unlock [40,60)", setlk(fd, libc::F_SETLK, libc::F_UNLCK, 40, 20));
        in_child(|| {
            line("child: F_GETLK [0,100) after the split", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 0, 100, me));
            line("child: F_GETLK [40,60)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 40, 20, me));
            line("child: F_GETLK [60,100)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 60, 40, me));
        });
        unsafe { libc::close(fd) };

        let fd = fresh(&dir, "merge");
        line("parent: F_SETLK write [0,10)", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 0, 10));
        line("parent: F_SETLK write [10,20)", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 10, 10));
        line("parent: F_SETLK read [20,30), a different type", setlk(fd, libc::F_SETLK, libc::F_RDLCK, 20, 10));
        in_child(|| {
            line("child: F_GETLK [0,30) after two adjacent writes", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 0, 30, me));
            line("child: F_GETLK [20,30)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 20, 10, me));
        });
        // Downgrading part of a write lock to a read lock.
        line("parent: F_SETLK read [5,15) over its write lock", setlk(fd, libc::F_SETLK, libc::F_RDLCK, 5, 10));
        in_child(|| {
            line("child: F_GETLK [5,15) after the downgrade", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 5, 10, me));
            line("child: F_SETLK read [5,15)", setlk(fd, libc::F_SETLK, libc::F_RDLCK, 5, 10));
        });
        unsafe { libc::close(fd) };
    }

    println!("## arguments");
    {
        let fd = fresh(&dir, "args");
        line("F_SETLK with l_type 99", setlk(fd, libc::F_SETLK, 99, 0, 10));
        let bad = flock(libc::F_WRLCK, 99, 0, 10);
        line("F_SETLK with l_whence 99", outcome(unsafe { libc::fcntl(fd, libc::F_SETLK, &bad) }));
        line("F_SETLK with a negative start", setlk(fd, libc::F_SETLK, libc::F_WRLCK, -5, 10));
        line("F_SETLK start 0 len -1, before the start", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 0, -1));
        line("F_SETLK start 5 len -5, exactly to the start", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 5, -5));
        line("F_SETLK start i64::MAX len 10", setlk(fd, libc::F_SETLK, libc::F_WRLCK, i64::MAX, 10));
        line("F_SETLK start i64::MAX len 0", setlk(fd, libc::F_SETLK, libc::F_WRLCK, i64::MAX, 0));
        line("F_SETLK unlock a region never locked", setlk(fd, libc::F_SETLK, libc::F_UNLCK, 70, 10));
        line("F_GETLK with l_type F_UNLCK", getlk(fd, libc::F_GETLK, libc::F_UNLCK, 0, 10, me));
        line("F_GETLK with l_type 99", getlk(fd, libc::F_GETLK, 99, 0, 10, me));
        unsafe { libc::close(fd) };

        let path = format!("{dir}/modes\0");
        unsafe { libc::close(libc::open(path.as_ptr().cast(), libc::O_RDWR | libc::O_CREAT, 0o644)) };
        let ro = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDONLY) };
        let wo = unsafe { libc::open(path.as_ptr().cast(), libc::O_WRONLY) };
        line("write lock on a read-only descriptor", setlk(ro, libc::F_SETLK, libc::F_WRLCK, 0, 10));
        line("read lock on a read-only descriptor", setlk(ro, libc::F_SETLK, libc::F_RDLCK, 0, 10));
        line("read lock on a write-only descriptor", setlk(wo, libc::F_SETLK, libc::F_RDLCK, 20, 10));
        line("write lock on a write-only descriptor", setlk(wo, libc::F_SETLK, libc::F_WRLCK, 20, 10));
        unsafe {
            libc::close(ro);
            libc::close(wo);
        }
    }

    println!("## closing any descriptor drops the process's locks, an OFD lock survives");
    {
        let path = format!("{dir}/close\0");
        let fd = fresh(&dir, "close");
        let second = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR) };
        line("parent: F_SETLK write [0,10) through the first", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 0, 10));
        unsafe { libc::close(second) };
        in_child(|| {
            line("child: F_GETLK [0,10) after the second closed", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 0, 10, me));
        });
        unsafe { libc::close(fd) };

        let fd = fresh(&dir, "ofdclose");
        let second = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR) };
        line("parent: F_OFD_SETLK write [0,10) through the first", setlk(fd, F_OFD_SETLK, libc::F_WRLCK, 0, 10));
        unsafe { libc::close(second) };
        in_child(|| {
            line("child: F_GETLK [0,10) after the second closed", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 0, 10, me));
            line("child: F_OFD_GETLK [0,10)", getlk(fd, F_OFD_GETLK, libc::F_WRLCK, 0, 10, me));
            // The inherited descriptor is the same description, so the
            // child holds this lock too.
            line("child: F_OFD_SETLK write [0,10) on the inherited description", setlk(fd, F_OFD_SETLK, libc::F_WRLCK, 0, 10));
        });
        let other = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR) };
        line("parent: F_OFD_GETLK through a second open", getlk(other, F_OFD_GETLK, libc::F_WRLCK, 0, 10, me));
        line("parent: F_OFD_SETLK write through a second open", setlk(other, F_OFD_SETLK, libc::F_WRLCK, 0, 10));
        line("parent: F_SETLK write through a second open", setlk(other, libc::F_SETLK, libc::F_WRLCK, 0, 10));
        unsafe {
            libc::close(other);
            libc::close(fd);
        }
    }

    println!("## a lock is the process's, not the child's");
    {
        let fd = fresh(&dir, "fork");
        line("parent: F_SETLK write [0,10)", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 0, 10));
        in_child(|| {
            line("child: F_GETLK [0,10) on the inherited descriptor", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 0, 10, me));
            line("child: F_SETLK write [0,10)", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 0, 10));
            line("child: F_SETLK unlock [0,10), the parent's lock", setlk(fd, libc::F_SETLK, libc::F_UNLCK, 0, 10));
        });
        in_child(|| {
            line("second child: F_GETLK [0,10) after the first's unlock", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 0, 10, me));
        });
        unsafe { libc::close(fd) };
    }

    println!("## flock and fcntl do not see each other");
    {
        let fd = fresh(&dir, "flock");
        line("parent: flock(LOCK_EX)", outcome(unsafe { libc::flock(fd, libc::LOCK_EX) }));
        in_child(|| {
            line("child: F_SETLK write [0,10) under the parent's flock", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 0, 10));
            line("child: F_GETLK write [0,10)", getlk(fd, libc::F_GETLK, libc::F_WRLCK, 0, 10, me));
            line("child: flock(LOCK_EX|LOCK_NB)", outcome(unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) }));
        });
        unsafe { libc::close(fd) };
    }

    println!("## a deadlock is refused, a wait ends when the lock goes");
    {
        let fd = fresh(&dir, "deadlock");
        let mut to_child = [0i32; 2];
        let mut to_parent = [0i32; 2];
        unsafe {
            libc::pipe(to_child.as_mut_ptr());
            libc::pipe(to_parent.as_mut_ptr());
        }
        // Parent holds A = [0,10); child holds B = [50,60). Parent waits for B,
        // child then waits for A: a cycle, which Linux refuses with EDEADLK for
        // the request that would close it. Both waits are bounded by an alarm
        // in case neither side notices.
        extern "C" fn nothing(_: i32) {}
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = nothing as *const () as usize;
        unsafe {
            libc::sigemptyset(&mut act.sa_mask);
            libc::sigaction(libc::SIGALRM, &act, std::ptr::null_mut());
        }
        line("parent: F_SETLK write A [0,10)", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 0, 10));
        let _ = std::io::stdout().flush();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let mut byte = 0u8;
            unsafe { libc::sigaction(libc::SIGALRM, &act, std::ptr::null_mut()) };
            line("child: F_SETLK write B [50,60)", setlk(fd, libc::F_SETLK, libc::F_WRLCK, 50, 10));
            // Tell the parent B is held, wait until the parent is waiting.
            unsafe {
                libc::write(to_parent[1], b"b".as_ptr().cast(), 1);
                libc::read(to_child[0], (&mut byte as *mut u8).cast(), 1);
                libc::usleep(200_000);
                libc::alarm(3);
            }
            line("child: F_SETLKW write A, closing the cycle", setlk(fd, libc::F_SETLKW, libc::F_WRLCK, 0, 10));
            unsafe { libc::alarm(0) };
            line("child: F_SETLK unlock B", setlk(fd, libc::F_SETLK, libc::F_UNLCK, 50, 10));
            let _ = std::io::stdout().flush();
            unsafe { libc::_exit(0) };
        }
        let mut byte = 0u8;
        unsafe {
            libc::read(to_parent[0], (&mut byte as *mut u8).cast(), 1);
            libc::write(to_child[1], b"g".as_ptr().cast(), 1);
            libc::alarm(5);
        }
        line("parent: F_SETLKW write B, waits for the child", setlk(fd, libc::F_SETLKW, libc::F_WRLCK, 50, 10));
        unsafe { libc::alarm(0) };
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        unsafe {
            libc::close(fd);
            for p in [to_child, to_parent] {
                libc::close(p[0]);
                libc::close(p[1]);
            }
        }
    }

    println!("## OFD locks report no pid and wait like the others");
    {
        let fd = fresh(&dir, "ofd");
        let path = format!("{dir}/ofd\0");
        line("parent: F_OFD_SETLK write [0,10)", setlk(fd, F_OFD_SETLK, libc::F_WRLCK, 0, 10));
        let other = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR) };
        line("parent: F_OFD_GETLK through a second open", getlk(other, F_OFD_GETLK, libc::F_WRLCK, 0, 10, me));
        line("parent: F_GETLK through a second open", getlk(other, libc::F_GETLK, libc::F_WRLCK, 0, 10, me));
        line("parent: F_OFD_SETLK with a non-zero l_pid", {
            let mut l = flock(libc::F_WRLCK, libc::SEEK_SET, 20, 10);
            l.l_pid = 7;
            outcome(unsafe { libc::fcntl(fd, F_OFD_SETLK, &l) })
        });
        line("parent: F_OFD_SETLKW write [0,10) on the holder itself", setlk(fd, F_OFD_SETLKW, libc::F_WRLCK, 0, 10));
        unsafe {
            libc::close(other);
            libc::close(fd);
        }
    }
}
