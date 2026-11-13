//! `SECCOMP_RET_TRACE` and `PTRACE_O_TRACESECCOMP`: a filter hands a syscall
//! to the tracer, which may let it run, change it, or skip it.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container and diffed by `tests/integration/probe_diff.sh`. Each case is a
//! child that calls `PTRACE_TRACEME`, installs a filter that answers
//! `RET_TRACE | 42` for `getppid` and `RET_ERRNO | EPERM` for `getuid`, stops,
//! and then makes the call; it reports what the call answered through its
//! exit status.

use std::ffi::c_void;

const TRACEME: i32 = 0;
const CONT: i32 = 7;
const SETOPTIONS: i32 = 0x4200;
const GETEVENTMSG: i32 = 0x4201;
const GETREGSET: i32 = 0x4204;
const SETREGSET: i32 = 0x4205;
const NT_PRSTATUS: u64 = 1;
/// arm64's syscall number in flight, which is what a tracer changes: x8 is
/// only the register the guest put it in.
const NT_ARM_SYSTEM_CALL: u64 = 0x404;
const SYSCALL: i32 = 24;
const O_TRACESYSGOOD: u64 = 1;
const O_TRACESECCOMP: u64 = 0x80;

const NR_GETPPID: u32 = 173;
const NR_GETUID: u32 = 174;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
}

fn ptrace(req: i32, pid: i32, addr: u64, data: u64) -> i64 {
    unsafe { libc::ptrace(req, pid, addr as *mut c_void, data as *mut c_void) as i64 }
}

fn wait_bounded(pid: i32) -> (i32, i32) {
    for _ in 0..2000 {
        let mut st = 0;
        let r = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
        if r != 0 {
            return (r, st);
        }
        unsafe { libc::usleep(1000) };
    }
    (0, 0)
}

fn status(st: i32) -> String {
    if libc::WIFEXITED(st) {
        format!("exited {}", libc::WEXITSTATUS(st))
    } else if libc::WIFSIGNALED(st) {
        format!("killed by {}", libc::WTERMSIG(st))
    } else if libc::WIFSTOPPED(st) {
        match st >> 16 {
            0 => format!("stopped {}", libc::WSTOPSIG(st)),
            ev => format!("stopped {} event {ev}", libc::WSTOPSIG(st)),
        }
    } else {
        format!("{st:#x}")
    }
}

/// The filter: `getppid` -> TRACE|42, `getuid` -> ERRNO|EPERM, else ALLOW.
fn install() {
    #[repr(C)]
    struct Insn {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    let i = |code, jt, jf, k| Insn { code, jt, jf, k };
    let prog = [
        i(0x20, 0, 0, 0),                    // ld [nr]
        i(0x15, 0, 1, NR_GETPPID),           // jeq getppid
        i(0x06, 0, 0, 0x7ff0_0000 | 42),     // ret TRACE|42
        i(0x15, 0, 1, NR_GETUID),            // jeq getuid
        i(0x06, 0, 0, 0x0005_0000 | 1),      // ret ERRNO|EPERM
        i(0x06, 0, 0, 0x7fff_0000),          // ret ALLOW
    ];
    #[repr(C)]
    struct Fprog {
        len: u16,
        filter: *const Insn,
    }
    let fp = Fprog { len: prog.len() as u16, filter: prog.as_ptr() };
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        libc::syscall(libc::SYS_seccomp, 1, 0, &fp);
    }
}

/// A traced child with the filter, stopped; after the continue it makes
/// `getppid` and exits with what it answered, as `0` for a parent's pid,
/// `200 + errno` for an error, and 100 for anything else.
fn child() -> Option<i32> {
    let parent = unsafe { libc::getpid() };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::ptrace(TRACEME, 0, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
            install();
            libc::raise(libc::SIGSTOP);
            let r = libc::syscall(libc::SYS_getppid);
            let code = if r == parent as i64 {
                0
            } else if r < 0 {
                200 + *libc::__errno_location()
            } else {
                100
            };
            libc::_exit(code);
        }
    }
    let (r, st) = wait_bounded(pid);
    (r == pid && libc::WIFSTOPPED(st)).then_some(pid)
}

fn regs(pid: i32) -> [u64; 34] {
    let mut r = [0u64; 34];
    let mut iov = libc::iovec { iov_base: r.as_mut_ptr().cast(), iov_len: 272 };
    ptrace(GETREGSET, pid, NT_PRSTATUS, &raw mut iov as u64);
    r
}

fn set_regs(pid: i32, mut r: [u64; 34]) {
    let mut iov = libc::iovec { iov_base: r.as_mut_ptr().cast(), iov_len: 272 };
    ptrace(SETREGSET, pid, NT_PRSTATUS, &raw mut iov as u64);
}

fn get_nr(pid: i32) -> String {
    let mut nr = 0i32;
    let mut iov = libc::iovec { iov_base: (&raw mut nr).cast(), iov_len: 4 };
    if ptrace(GETREGSET, pid, NT_ARM_SYSTEM_CALL, &raw mut iov as u64) < 0 {
        return format!("errno {}", std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    format!("{nr}, {} bytes", iov.iov_len)
}

fn set_nr(pid: i32, mut nr: i32) {
    let mut iov = libc::iovec { iov_base: (&raw mut nr).cast(), iov_len: 4 };
    ptrace(SETREGSET, pid, NT_ARM_SYSTEM_CALL, &raw mut iov as u64);
}

/// A seccomp stop of a fresh child, continued to.
fn at_seccomp_stop() -> Option<i32> {
    let pid = child()?;
    ptrace(SETOPTIONS, pid, 0, O_TRACESECCOMP);
    ptrace(CONT, pid, 0, 0);
    wait_bounded(pid);
    Some(pid)
}

/// A fresh child stopped at the entry of its `getppid`.
fn at_getppid_entry() -> Option<i32> {
    let pid = child()?;
    ptrace(SETOPTIONS, pid, 0, O_TRACESYSGOOD);
    for _ in 0..20 {
        ptrace(SYSCALL, pid, 0, 0);
        let (r, st) = wait_bounded(pid);
        if r != pid || !libc::WIFSTOPPED(st) {
            return None;
        }
        if regs(pid)[8] == NR_GETPPID as u64 {
            return Some(pid);
        }
        // Past its exit stop.
        ptrace(SYSCALL, pid, 0, 0);
        wait_bounded(pid);
    }
    None
}

fn finish(pid: i32) -> String {
    ptrace(CONT, pid, 0, 0);
    let (r, st) = wait_bounded(pid);
    if r == pid {
        status(st)
    } else {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        "nothing".into()
    }
}

fn main() {
    if let Some(pid) = child() {
        line("RET_TRACE without TRACESECCOMP: the call", finish(pid));
    }

    if let Some(pid) = child() {
        ptrace(SETOPTIONS, pid, 0, O_TRACESECCOMP);
        ptrace(CONT, pid, 0, 0);
        let (_, st) = wait_bounded(pid);
        line("RET_TRACE with TRACESECCOMP: the stop", status(st));
        let mut msg = 0u64;
        ptrace(GETEVENTMSG, pid, 0, &raw mut msg as u64);
        line("  GETEVENTMSG", msg);
        let r = regs(pid);
        line("  x8 at the stop is the syscall", r[8] == NR_GETPPID as u64);
        line("  CONT: the call", finish(pid));
    }

    if let Some(pid) = at_seccomp_stop() {
        line("NT_ARM_SYSTEM_CALL at the stop", get_nr(pid));
        let mut r = regs(pid);
        r[8] = u64::MAX;
        r[0] = (-(libc::EACCES as i64)) as u64;
        set_regs(pid, r);
        line("x8 = -1, x0 = -EACCES at the stop: the call", finish(pid));
    }

    if let Some(pid) = at_seccomp_stop() {
        let mut r = regs(pid);
        r[0] = (-(libc::EACCES as i64)) as u64;
        set_regs(pid, r);
        set_nr(pid, -1);
        line("SYSTEM_CALL = -1, x0 = -EACCES: the call", finish(pid));
    }

    if let Some(pid) = at_seccomp_stop() {
        set_nr(pid, NR_GETUID as i32);
        line("SYSTEM_CALL = getuid at the stop: the filter again", finish(pid));
    }

    if let Some(pid) = at_seccomp_stop() {
        let mut r = regs(pid);
        r[8] = NR_GETUID as u64;
        set_regs(pid, r);
        line("x8 = getuid at the stop: the call", finish(pid));
    }

    // At a syscall-entry stop, the same two ways to change the call.
    if let Some(pid) = at_getppid_entry() {
        line("NT_ARM_SYSTEM_CALL at the entry stop", get_nr(pid));
        let mut r = regs(pid);
        r[8] = NR_GETUID as u64;
        set_regs(pid, r);
        line("x8 = getuid at the entry stop: the call", finish(pid));
    }
    if let Some(pid) = at_getppid_entry() {
        set_nr(pid, NR_GETUID as i32);
        line("SYSTEM_CALL = getuid at the entry stop: the call", finish(pid));
    }
    if let Some(pid) = at_getppid_entry() {
        let mut r = regs(pid);
        r[0] = (-(libc::EACCES as i64)) as u64;
        set_regs(pid, r);
        set_nr(pid, -1);
        line("SYSTEM_CALL = -1 at the entry stop: the call", finish(pid));
    }
}
