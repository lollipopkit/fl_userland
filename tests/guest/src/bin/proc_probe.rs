//! What the process syscalls answer at their edges.
//!
//! **A report, not a check** — the fourth in the shape `mmap_probe`
//! established. One line per case, never fails, run here and in an arm64
//! container and diffed.
//!
//! Two things this probe has to be careful about, because they would measure
//! the container rather than the kernel:
//!
//! - **Its own pid.** In a container this program may be pid 1, and pid 1 is
//!   special to `kill`, to reparenting and to `setsid`. Every case that cares
//!   runs in a **child**, so both sides see the same shape.
//! - **Privilege.** A container runs as root by default and so does this
//!   kernel's guest, so the `setuid` cases below are root's answers on both
//!   sides. What a non-root process is told is `auxv_abi`'s job.

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn name(e: i32) -> String {
    let s = match e {
        0 => "-",
        libc::EINVAL => "EINVAL",
        libc::ECHILD => "ECHILD",
        libc::ESRCH => "ESRCH",
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::EAGAIN => "EAGAIN",
        libc::ENOSYS => "ENOSYS",
        libc::EFAULT => "EFAULT",
        libc::ERANGE => "ERANGE",
        libc::EINTR => "EINTR",
        _ => return format!("errno {e}"),
    };
    s.into()
}

fn report(what: &str, r: i64) {
    if r < 0 {
        println!("{what:<52} -> {}", name(errno()));
    } else {
        println!("{what:<52} -> ok");
    }
}

fn value(what: &str, v: i64) {
    println!("{what:<52} -> {v}");
}

/// A child that exits with `code` after `ms` milliseconds.
fn spawn_exiting(code: i32, ms: u64) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        if ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
        unsafe { libc::_exit(code) };
    }
    pid
}

fn main() {
    println!("## wait4 options");
    // A child that has already gone, so the options are what is being judged
    // rather than the timing.
    let pid = spawn_exiting(3, 0);
    std::thread::sleep(std::time::Duration::from_millis(50));
    let mut status = 0i32;
    // Bits no option defines. Linux: `if (options & ~(WNOHANG|WUNTRACED|
    // WCONTINUED|__WNOTHREAD|__WCLONE|__WALL)) return -EINVAL;`
    for (n, o) in [
        ("WNOHANG", libc::WNOHANG),
        ("0x1000", 0x1000),
        ("0x80000000u", -0x8000_0000i32),
        ("all known", libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED),
    ] {
        report(&format!("wait4(-1, {n})"), unsafe {
            libc::wait4(-1, &mut status, o, std::ptr::null_mut()) as i64
        });
    }
    // Reap it for real, whatever the above did.
    unsafe { libc::waitpid(pid, &mut status, 0) };

    println!("## wait4 with no children");
    report("wait4(-1) with nothing to wait for", unsafe {
        libc::wait4(-1, &mut status, 0, std::ptr::null_mut()) as i64
    });
    report("waitpid(a pid that is not ours)", unsafe {
        libc::waitpid(1, &mut status, libc::WNOHANG) as i64
    });
    report("waitpid(a pid that does not exist)", unsafe {
        libc::waitpid(30000, &mut status, libc::WNOHANG) as i64
    });
    report("waitpid(0) with no process group children", unsafe {
        libc::waitpid(0, &mut status, libc::WNOHANG) as i64
    });

    println!("## the exit status word");
    let pid = spawn_exiting(42, 0);
    unsafe { libc::waitpid(pid, &mut status, 0) };
    value("a child that exited 42: WIFEXITED", libc::WIFEXITED(status) as i64);
    value("  WEXITSTATUS", libc::WEXITSTATUS(status) as i64);
    value("  the raw word", status as i64);
    // An exit code above 255: only the low byte survives.
    let pid = spawn_exiting(0x123, 0);
    unsafe { libc::waitpid(pid, &mut status, 0) };
    value("a child that exited 0x123: WEXITSTATUS", libc::WEXITSTATUS(status) as i64);
    // Killed by a signal.
    let pid = spawn_exiting(0, 5000);
    std::thread::sleep(std::time::Duration::from_millis(30));
    unsafe { libc::kill(pid, libc::SIGKILL) };
    unsafe { libc::waitpid(pid, &mut status, 0) };
    value("a child killed by SIGKILL: WIFSIGNALED", libc::WIFSIGNALED(status) as i64);
    value("  WTERMSIG", libc::WTERMSIG(status) as i64);
    value("  the raw word", status as i64);

    println!("## waitid");
    let pid = spawn_exiting(7, 0);
    std::thread::sleep(std::time::Duration::from_millis(50));
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // P_ALL is 0, P_PID 1, P_PGID 2, P_PIDFD 3.
    report("waitid(P_PID, WEXITED|WNOWAIT)", unsafe {
        libc::waitid(libc::P_PID, pid as u32, &mut info, libc::WEXITED | libc::WNOWAIT) as i64
    });
    value("  si_code is CLD_EXITED", (info.si_code == libc::CLD_EXITED) as i64);
    // WNOWAIT left it, so the same call answers again.
    report("waitid(the same child again)", unsafe {
        libc::waitid(libc::P_PID, pid as u32, &mut info, libc::WEXITED) as i64
    });
    report("waitid(idtype=99)", unsafe {
        libc::waitid(99, 0, &mut info, libc::WEXITED) as i64
    });
    // No WEXITED, WSTOPPED or WCONTINUED: nothing to report on.
    report("waitid(options with none of the three)", unsafe {
        libc::waitid(libc::P_ALL, 0, &mut info, 0) as i64
    });
    report("waitid(options=0x1000)", unsafe {
        libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | 0x1000) as i64
    });

    println!("## kill");
    report("kill(self, 0)", unsafe {
        libc::kill(libc::getpid(), 0) as i64
    });
    report("kill(self, 99)", unsafe {
        libc::kill(libc::getpid(), 99) as i64
    });
    report("kill(self, -1)", unsafe {
        libc::kill(libc::getpid(), -1) as i64
    });
    report("kill(a pid that does not exist, 0)", unsafe {
        libc::kill(30000, 0) as i64
    });
    report("kill(0, 0) -- this process group", unsafe {
        libc::kill(0, 0) as i64
    });
    report("kill(-30000, 0) -- a group that does not exist", unsafe {
        libc::kill(-30000, 0) as i64
    });
    report("tgkill(self, self, 0)", unsafe {
        libc::syscall(libc::SYS_tgkill, libc::getpid(), libc::getpid(), 0)
    });
    report("tgkill(self, 30000, 0)", unsafe {
        libc::syscall(libc::SYS_tgkill, libc::getpid(), 30000, 0)
    });
    report("tgkill(tgid=0)", unsafe {
        libc::syscall(libc::SYS_tgkill, 0, libc::getpid(), 0)
    });

    println!("## process groups and sessions");
    // In a child, so that neither side is asking about pid 1.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let me = unsafe { libc::getpid() };
        report("setpgid(0, 0)", unsafe { libc::setpgid(0, 0) as i64 });
        value("  getpgid(0) is our own pid", (unsafe { libc::getpgid(0) } == me) as i64);
        report("setpgid(0, a group that does not exist)", unsafe {
            libc::setpgid(0, 30000) as i64
        });
        report("setpgid(a pid that is not ours, 0)", unsafe {
            libc::setpgid(1, 0) as i64
        });
        report("setpgid(0, -1)", unsafe { libc::setpgid(0, -1) as i64 });
        report("getpgid(30000)", unsafe { libc::getpgid(30000) as i64 });
        report("getsid(30000)", unsafe { libc::getsid(30000) as i64 });
        // setsid fails for a process that is already a group leader, which
        // the setpgid(0, 0) above made this one.
        report("setsid(as a group leader)", unsafe { libc::setsid() as i64 });
        unsafe { libc::_exit(0) };
    }
    let mut st = 0i32;
    unsafe { libc::waitpid(pid, &mut st, 0) };

    println!("## ids");
    report("setuid(0) as root", unsafe { libc::setuid(0) as i64 });
    report("setresuid(-1, -1, -1)", unsafe {
        libc::setresuid(u32::MAX, u32::MAX, u32::MAX) as i64
    });
    report("setgroups(0, NULL)", unsafe {
        libc::setgroups(0, std::ptr::null()) as i64
    });
    let mut groups = [0u32; 1];
    report("getgroups(-1, buf)", unsafe {
        libc::getgroups(-1, groups.as_mut_ptr()) as i64
    });
    report("getgroups(0, NULL) -- the count question", unsafe {
        libc::getgroups(0, std::ptr::null_mut()) as i64
    });

    println!("## prctl");
    // PR_SET_NAME is 15, PR_GET_NAME 16.
    let n = c"probe";
    report("prctl(PR_SET_NAME)", unsafe {
        libc::syscall(libc::SYS_prctl, 15, n.as_ptr(), 0, 0, 0)
    });
    let mut got = [0u8; 16];
    report("prctl(PR_GET_NAME)", unsafe {
        libc::syscall(libc::SYS_prctl, 16, got.as_mut_ptr(), 0, 0, 0)
    });
    value(
        "  the name came back",
        (got.starts_with(b"probe\0")) as i64,
    );
    report("prctl(option=9999)", unsafe {
        libc::syscall(libc::SYS_prctl, 9999, 0, 0, 0, 0)
    });
    // PR_SET_PDEATHSIG is 1.
    report("prctl(PR_SET_PDEATHSIG, 99)", unsafe {
        libc::syscall(libc::SYS_prctl, 1, 99, 0, 0, 0)
    });
    report("prctl(PR_SET_PDEATHSIG, 0)", unsafe {
        libc::syscall(libc::SYS_prctl, 1, 0, 0, 0, 0)
    });
}
