//! What `wait4` and `waitid` answer, and what they fill in.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Two things make this worth asking about. `waitid` fills a `siginfo_t`, and a
//! **wire format the kernel writes** is the shape that has produced the most
//! defects in this tree — the signal frame's `siginfo_` union ended at 48 bytes
//! so two thirds of it was never written. And `wait4`'s status is a 32-bit word
//! with six encodings, two of which no process can produce, which is why the
//! decoding has its own crate and its own tests.
//!
//! # Every case gets its own child
//!
//! A `wait` consumes one, and a case that reaped somebody else's would answer
//! about the wrong process. Each fork here is waited for by the case that made
//! it, and the two that stop a child continue it before leaving.
//!
//! # No case blocks without a way out
//!
//! A probe that hangs takes the whole sweep with it. Every blocking wait here is
//! for a child that has already been told to exit, and the polling ones give up
//! after a bounded number of tries and say so.

use std::sync::atomic::{AtomicBool, Ordering};

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<50} -> {value}");
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> &'static str {
    match e {
        libc::ECHILD => "ECHILD",
        libc::EINVAL => "EINVAL",
        libc::EFAULT => "EFAULT",
        libc::EAGAIN => "EAGAIN",
        libc::EINTR => "EINTR",
        libc::ESRCH => "ESRCH",
        0 => "ok",
        _ => "other",
    }
}

/// A child that does `body` and then `_exit`s with `code`.
fn child(code: i32, body: impl FnOnce()) -> i32 {
    // SAFETY: the child only does what `body` says and then leaves.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        body();
        unsafe { libc::_exit(code) };
    }
    pid
}

/// What `waitid` wrote, read out of the raw bytes rather than through an
/// accessor: which offset a value came from is half the question.
struct Info {
    signo: i32,
    code: i32,
    pid: i32,
    uid: u32,
    status: i32,
}

fn read_info(raw: &[u8; 128]) -> Info {
    let word = |at: usize| i32::from_ne_bytes(raw[at..at + 4].try_into().unwrap());
    Info {
        signo: word(0),
        code: word(8),
        pid: word(16),
        uid: word(20) as u32,
        status: word(24),
    }
}

fn waitid(idtype: u32, id: u32, options: i32, raw: &mut [u8; 128]) -> i32 {
    raw.fill(0);
    unsafe {
        libc::syscall(
            libc::SYS_waitid,
            idtype,
            id,
            raw.as_mut_ptr(),
            options,
            std::ptr::null_mut::<libc::c_void>(),
        ) as i32
    }
}

const P_ALL: u32 = 0;
const P_PID: u32 = 1;
const P_PGID: u32 = 2;

/// `SIGCHLD` has to be caught for `WCONTINUED` to be reportable on some
/// kernels; a handler that records is enough, and it must not be `SIG_IGN`,
/// which auto-reaps.
static GOT_CHLD: AtomicBool = AtomicBool::new(false);

extern "C" fn chld(_: libc::c_int) {
    GOT_CHLD.store(true, Ordering::SeqCst);
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = chld as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut());
    }

    println!("## a child that exits");
    {
        let pid = child(42, || {});
        let mut status = 0;
        let got = unsafe { libc::waitpid(pid, &mut status, 0) };
        line("waitpid returns the pid", got == pid);
        line("the raw status word", format!("{status:#x}"));
        line("  WIFEXITED", libc::WIFEXITED(status));
        line("  WEXITSTATUS", libc::WEXITSTATUS(status));
        line("  WIFSIGNALED", libc::WIFSIGNALED(status));
        line("  WIFSTOPPED", libc::WIFSTOPPED(status));
        line("  WCOREDUMP", libc::WCOREDUMP(status));
    }

    println!("## and what waitid says about the same thing");
    {
        let pid = child(42, || {});
        let mut raw = [0u8; 128];
        let r = waitid(P_PID, pid as u32, libc::WEXITED, &mut raw);
        line("waitid", if r == 0 { "ok".into() } else { named(errno()).to_string() });
        let i = read_info(&raw);
        line("  si_signo", i.signo);
        line("  si_code", i.code);
        line("  si_pid is the child", i.pid == pid);
        line("  si_uid is ours", i.uid == unsafe { libc::getuid() });
        line("  si_status", i.status);
    }

    println!("## a child killed by a signal");
    {
        let pid = child(0, || unsafe {
            // Wait to be killed rather than exiting on its own.
            libc::pause();
        });
        // Give it a moment to reach pause; the kill works either way, and what
        // is reported is the same.
        unsafe { libc::usleep(20_000) };
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut status = 0;
        let got = unsafe { libc::waitpid(pid, &mut status, 0) };
        line("waitpid returns the pid", got == pid);
        line("the raw status word", format!("{status:#x}"));
        line("  WIFSIGNALED", libc::WIFSIGNALED(status));
        line("  WTERMSIG", libc::WTERMSIG(status));
        line("  WIFEXITED", libc::WIFEXITED(status));
        line("  WCOREDUMP", libc::WCOREDUMP(status));
    }

    println!("## and waitid for a killed child");
    {
        let pid = child(0, || unsafe {
            libc::pause();
        });
        unsafe { libc::usleep(20_000) };
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let mut raw = [0u8; 128];
        let r = waitid(P_PID, pid as u32, libc::WEXITED, &mut raw);
        line("waitid", if r == 0 { "ok".into() } else { named(errno()).to_string() });
        let i = read_info(&raw);
        line("  si_code", i.code);
        line("  si_status is the signal", i.status);
    }

    println!("## a stopped child");
    {
        let pid = child(7, || unsafe {
            libc::pause();
        });
        unsafe { libc::usleep(20_000) };
        unsafe { libc::kill(pid, libc::SIGSTOP) };
        let mut status = 0;
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        line("waitpid(WUNTRACED) returns the pid", got == pid);
        line("the raw status word", format!("{status:#x}"));
        line("  WIFSTOPPED", libc::WIFSTOPPED(status));
        line("  WSTOPSIG", libc::WSTOPSIG(status));
        line("  WIFEXITED", libc::WIFEXITED(status));

        // Continued, and reported.
        unsafe { libc::kill(pid, libc::SIGCONT) };
        let mut status = 0;
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WCONTINUED) };
        line("waitpid(WCONTINUED) returns the pid", got == pid);
        line("the raw status word", format!("{status:#x}"));
        line("  WIFCONTINUED", libc::WIFCONTINUED(status));

        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        line("and then it is reaped", libc::WIFSIGNALED(status));
    }

    println!("## waitid for a stopped one");
    {
        let pid = child(7, || unsafe {
            libc::pause();
        });
        unsafe { libc::usleep(20_000) };
        unsafe { libc::kill(pid, libc::SIGSTOP) };
        let mut raw = [0u8; 128];
        let r = waitid(P_PID, pid as u32, libc::WSTOPPED, &mut raw);
        line("waitid(WSTOPPED)", if r == 0 { "ok".into() } else { named(errno()).to_string() });
        let i = read_info(&raw);
        line("  si_code", i.code);
        line("  si_status is the stopping signal", i.status);

        unsafe { libc::kill(pid, libc::SIGCONT) };
        let r = waitid(P_PID, pid as u32, libc::WCONTINUED, &mut raw);
        line("waitid(WCONTINUED)", if r == 0 { "ok".into() } else { named(errno()).to_string() });
        let i = read_info(&raw);
        line("  si_code", i.code);
        line("  si_status", i.status);

        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        line("and then it is reaped", libc::WIFSIGNALED(status));
    }

    println!("## WNOWAIT leaves the child where it was");
    {
        let pid = child(9, || {});
        let mut raw = [0u8; 128];
        let r = waitid(P_PID, pid as u32, libc::WEXITED | libc::WNOWAIT, &mut raw);
        line("waitid(WNOWAIT)", if r == 0 { "ok".into() } else { named(errno()).to_string() });
        line("  si_status", read_info(&raw).status);
        // Still reapable, which is what WNOWAIT means.
        let mut status = 0;
        let got = unsafe { libc::waitpid(pid, &mut status, 0) };
        line("and it can still be reaped", got == pid);
        line("  with the same status", libc::WEXITSTATUS(status));
    }

    println!("## WNOHANG");
    {
        let pid = child(3, || unsafe {
            libc::pause();
        });
        let mut status = 0;
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        line("a child that has not exited", got);
        unsafe { libc::kill(pid, libc::SIGKILL) };
        // Bounded: a hundred tries of a millisecond each, and then say so.
        let mut tries = 0;
        let got = loop {
            let g = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if g != 0 || tries >= 100 {
                break g;
            }
            tries += 1;
            unsafe { libc::usleep(1000) };
        };
        line("and one that has", got == pid);
    }

    println!("## what they refuse");
    {
        let mut status = 0;
        let r = unsafe { libc::waitpid(0x7fff_fffe, &mut status, 0) };
        line("waitpid on a pid nothing has", if r < 0 { named(errno()) } else { "ok" });

        // No children at all: this process has reaped every one it made.
        let r = unsafe { libc::waitpid(-1, &mut status, 0) };
        line("waitpid(-1) with no children", if r < 0 { named(errno()) } else { "ok" });

        let mut raw = [0u8; 128];
        let r = waitid(99, 0, libc::WEXITED, &mut raw);
        line("waitid with an idtype nobody has", if r < 0 { named(errno()) } else { "ok" });

        // Neither WEXITED nor WSTOPPED nor WCONTINUED: nothing to wait for.
        let r = waitid(P_ALL, 0, 0, &mut raw);
        line("waitid with no state asked for", if r < 0 { named(errno()) } else { "ok" });

        // WNOWAIT alone is the same question.
        let r = waitid(P_ALL, 0, libc::WNOWAIT, &mut raw);
        line("waitid with only WNOWAIT", if r < 0 { named(errno()) } else { "ok" });

        let r = unsafe {
            libc::syscall(
                libc::SYS_waitid,
                P_PID,
                1u32,
                0x7fff_0000_0000u64,
                libc::WEXITED,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        line("waitid into an unmapped siginfo", if r < 0 { named(errno()) } else { "ok" });

        // Linux fills the siginfo *before* returning the error:
        // `SYSCALL_DEFINE5(waitid)` takes `kernel_waitid`'s answer, writes six
        // zeroed fields through `infop`, and only then returns it. Two things
        // follow, and the second is what the case above measures -- an
        // unwritable buffer is EFAULT whatever the wait itself would have said.
        let mut poisoned = [0xa5u8; 128];
        let r = unsafe {
            libc::syscall(
                libc::SYS_waitid,
                P_ALL,
                0u32,
                poisoned.as_mut_ptr(),
                libc::WEXITED,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        let info = read_info(&poisoned);
        line("waitid with no children", if r < 0 { named(errno()) } else { "ok" });
        line("  si_signo it leaves behind", info.signo);
        line("  si_pid it leaves behind", info.pid);
    }

    println!("## P_PGID and P_ALL");
    {
        let pid = child(11, || {});
        let mut raw = [0u8; 128];
        // The child is in this process's group, which is what P_PGID 0 means.
        let r = waitid(P_PGID, 0, libc::WEXITED, &mut raw);
        line("waitid(P_PGID, 0)", if r == 0 { "ok".into() } else { named(errno()).to_string() });
        line("  si_pid is the child", read_info(&raw).pid == pid);

        let pid = child(13, || {});
        let r = waitid(P_ALL, 0, libc::WEXITED, &mut raw);
        line("waitid(P_ALL)", if r == 0 { "ok".into() } else { named(errno()).to_string() });
        line("  si_pid is the child", read_info(&raw).pid == pid);
        line("  si_status", read_info(&raw).status);
    }

    println!("## the rusage wait4 fills");
    {
        let pid = child(0, || {
            // Something to account for, so the times are not trivially zero on
            // a kernel that fills them.
            let mut n = 0u64;
            for i in 0..500_000u64 {
                n = n.wrapping_add(i);
            }
            std::hint::black_box(n);
        });
        let mut status = 0;
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        let got = unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
        line("wait4 returns the pid", got == pid);
        // The *shape* rather than the numbers: how much CPU a child used
        // differs by orders of magnitude between an emulator and a real
        // kernel, and that is not the question.
        line("ru_utime is not negative", ru.ru_utime.tv_sec >= 0);
        line("ru_maxrss is not negative", ru.ru_maxrss >= 0);
        line("ru_nvcsw is not negative", ru.ru_nvcsw >= 0);
    }

    // Nothing is left behind: every child above was waited for.
    let mut status = 0;
    let leftover = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    line("no child is left unreaped", leftover);
    let _ = GOT_CHLD.load(Ordering::SeqCst);
}
