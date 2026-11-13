//! What a child inherits from `fork(2)`, and what it does not.
//!
//! `tools/fork-inherit.py` asked the structural question (the compiler asks it
//! since 2026-09-30: a forked task is a struct literal) — whether a field the
//! copy does not name is silently the parent's — and it found two defects an
//! hour apart on 2026-08-23. Neither can ask the behavioural one: *should* this
//! be inherited. That is Linux's business, and this asks Linux.
//!
//! A probe, so it asserts nothing: every case prints one line and
//! `probe_diff.sh` runs it here and in an arm64 Linux container and reports
//! where the two disagree.
//!
//! # Every case reports from the child
//!
//! The parent sets something up, forks, and the **child** prints. So a line is
//! about what crossed the boundary, and a case that crashed the child prints
//! nothing at all — which the tool reports as one side dying early rather than
//! as a difference in whatever came after.
//!
//! # Two things deliberately not asked
//!
//! - **The alternate signal stack.** Rust's runtime installs one before `main`
//!   for stack-overflow detection, so a Rust child reports one whatever it
//!   inherited. See `exec_reset_probe.rs`, where the same thing made the first
//!   version of that probe wrong.
//! - **CPU times.** A child's `getrusage` starts fresh, but every way of saying
//!   so is a comparison against a number that differs by two orders of
//!   magnitude between an emulator and a real kernel.

use std::ffi::CString;

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no NUL")
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Runs `body` in a child and waits for it. The child prints; the parent does
/// not, so the output is one line per case wherever the case is decided.
fn in_child(body: impl FnOnce()) {
    // SAFETY: the child only reads its own state and prints, then _exits.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        body();
        // Flushed by the exit below; _exit would drop the buffered line.
        std::process::exit(0);
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<48} -> {value}");
}

extern "C" fn handler(_: libc::c_int) {}

fn main() {
    println!("## signals");
    {
        // A blocked mask, a handler and an ignore, all set before the fork.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR2);
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());

            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = handler as *const () as usize;
            libc::sigaction(libc::SIGUSR1, &act, std::ptr::null_mut());
            act.sa_sigaction = libc::SIG_IGN;
            libc::sigaction(libc::SIGTERM, &act, std::ptr::null_mut());
        }
        in_child(|| {
            let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) };
            line("the blocked mask", unsafe {
                libc::sigismember(&mask, libc::SIGUSR2)
            });
            let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
            unsafe { libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut act) };
            line(
                "a handler",
                if act.sa_sigaction == libc::SIG_DFL {
                    "SIG_DFL"
                } else if act.sa_sigaction == libc::SIG_IGN {
                    "SIG_IGN"
                } else {
                    "a handler"
                },
            );
            unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut act) };
            line(
                "an ignored signal",
                if act.sa_sigaction == libc::SIG_IGN {
                    "SIG_IGN"
                } else {
                    "not SIG_IGN"
                },
            );
        });
    }

    println!("## what a child starts without");
    {
        // A pending signal is the parent's alone: raise one that is blocked, so
        // it stays pending across the fork rather than being delivered.
        unsafe { libc::raise(libc::SIGUSR2) };
        in_child(|| {
            let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe { libc::sigpending(&mut pending) };
            line("a pending signal", unsafe {
                libc::sigismember(&pending, libc::SIGUSR2)
            });
        });
        // Taken back out of the parent so the cases below start clean.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR2);
            let mut sig = 0;
            let ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            libc::sigtimedwait(&set, std::ptr::null_mut(), &ts);
            let _ = &mut sig;
        }
    }

    {
        // An interval timer belongs to the process that armed it.
        let it = libc::itimerval {
            it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
            it_value: libc::timeval { tv_sec: 100, tv_usec: 0 },
        };
        unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };
        in_child(|| {
            let mut got: libc::itimerval = unsafe { std::mem::zeroed() };
            unsafe { libc::getitimer(libc::ITIMER_REAL, &mut got) };
            line("an armed ITIMER_REAL", got.it_value.tv_sec != 0);
        });
        let off: libc::itimerval = unsafe { std::mem::zeroed() };
        unsafe { libc::setitimer(libc::ITIMER_REAL, &off, std::ptr::null_mut()) };
    }

    {
        // The parent-death signal, which prctl(2) says is cleared for a child.
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGUSR1) };
        in_child(|| {
            let mut sig = -1i32;
            let r = unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut sig) };
            line("the parent-death signal", if r < 0 { -1 } else { sig });
        });
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) };
    }

    println!("## what a child keeps");
    {
        unsafe {
            libc::prctl(libc::PR_SET_KEEPCAPS, 1);
            libc::prctl(libc::PR_SET_DUMPABLE, 0);
        }
        in_child(|| {
            line("keepcaps", unsafe { libc::prctl(libc::PR_GET_KEEPCAPS, 0, 0, 0, 0) });
            line("dumpable", unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) });
        });
        unsafe {
            libc::prctl(libc::PR_SET_KEEPCAPS, 0);
            libc::prctl(libc::PR_SET_DUMPABLE, 1);
        }
    }

    {
        // no_new_privs is a one-way latch, so it is set inside a child of its
        // own -- setting it here would change every case after this one.
        in_child(|| {
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            in_child(|| {
                // The four unused arguments explicitly zero: Linux refuses
                // PR_GET_NO_NEW_PRIVS with anything else in them, and `prctl`
                // is variadic -- so passing none leaves whatever the caller's
                // registers held and both kernels answer -1. The first version
                // of this case did that and "agreed" for a reason that had
                // nothing to do with fork.
                line("no_new_privs", unsafe {
                    libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
                });
            });
        });
    }

    println!("## record locks");
    {
        // A lock belongs to the process that took it, so the child does not
        // hold it -- and F_GETLK from the child finds the parent's.
        let path = "/tmp/fork_probe_lock";
        let fd = unsafe {
            libc::open(
                cstr(path).as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
                0o600,
            )
        };
        let lock = libc::flock {
            l_type: libc::F_WRLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 4,
            l_pid: 0,
        };
        let took = unsafe { libc::fcntl(fd, libc::F_SETLK, &lock) };
        line("the parent takes a write lock", took);
        in_child(|| {
            let mut q = libc::flock {
                l_type: libc::F_WRLCK as i16,
                l_whence: libc::SEEK_SET as i16,
                l_start: 0,
                l_len: 4,
                l_pid: 0,
            };
            let r = unsafe { libc::fcntl(fd, libc::F_GETLK, &mut q) };
            line(
                "and the child sees it as somebody else's",
                if r < 0 {
                    format!("errno {}", errno())
                } else if q.l_type == libc::F_UNLCK as i16 {
                    "no conflict".to_string()
                } else {
                    "a conflicting lock".to_string()
                },
            );
        });
        unsafe { libc::close(fd) };
        let _ = std::fs::remove_file(path);
    }

    println!("## a parent that is not its process's leader");
    {
        // The parent of a child forked by a thread is the process: getppid
        // and /proc/<pid>/status's PPid name its tgid, not the thread.
        let me = unsafe { libc::getpid() };
        let t = std::thread::spawn(move || {
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let c = unsafe { libc::fork() };
            if c == 0 {
                let ppid = unsafe { libc::getppid() };
                let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
                let field = status.lines().find_map(|l| l.strip_prefix("PPid:")).map(str::trim).unwrap_or("?").to_string();
                println!("{:<48} -> {}", "getppid() is the forking process", ppid == me);
                println!("{:<48} -> {}", "PPid is the forking process", field == me.to_string());
                let _ = std::io::Write::flush(&mut std::io::stdout());
                unsafe { libc::_exit(0) };
            }
            unsafe { libc::waitpid(c, std::ptr::null_mut(), 0) };
        });
        let _ = t.join();
    }
}
