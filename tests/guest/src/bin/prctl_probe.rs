//! What `prctl(2)` answers, option by option.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! `prctl` is one syscall with seventy-odd options, and a program asks it about
//! itself: its name, whether it may be dumped, whether it keeps capabilities,
//! its timer slack, its tagged-address mode. This kernel answered twelve and
//! `EINVAL` for the rest until 2026-09-04, which is what Linux answers for an
//! option it does not have — so the question for each of the others is whether
//! Linux *has* it, and what a program written against it is told here.
//!
//! # Nothing here changes what the process can do
//!
//! Every setter is either read back and restored, harmless, called with an
//! argument both kernels refuse, or done in a **forked child** whose state dies
//! with it: MDWE, a forced speculation disable, a dropped capability and a
//! locked securebit are all one-way. `PR_SET_SECCOMP` is called with a mode
//! that does not exist, because the strict mode would kill the process at its
//! next syscall. `PR_SET_NO_NEW_PRIVS` is sticky and is set last.
//!
//! # The exec case
//!
//! Whether MDWE and the THP setting survive an `execve` is measured by a child
//! that sets one and then execs *this binary* with an argument; the new image
//! prints the one line and exits. That is the only way to ask, and it is why
//! `main` looks at `argv[1]` first.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
    // A forked child shares the pipe and would otherwise print the parent's
    // buffered lines a second time.
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> &'static str {
    match e {
        0 => "ok",
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::EFAULT => "EFAULT",
        libc::ENOSYS => "ENOSYS",
        libc::EACCES => "EACCES",
        libc::ERANGE => "ERANGE",
        libc::ENXIO => "ENXIO",
        libc::ENODEV => "ENODEV",
        libc::EEXIST => "EEXIST",
        libc::ENOMEM => "ENOMEM",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        _ => "other",
    }
}

/// `prctl` with five arguments; the answer as "ok" (the result if non-zero)
/// or an errno name. Through `syscall`, so a `long` comes back whole.
fn prctl(option: i32, a2: u64, a3: u64, a4: u64, a5: u64) -> String {
    let r = unsafe { libc::syscall(libc::SYS_prctl, option as i64, a2, a3, a4, a5) };
    if r < 0 {
        named(errno()).to_string()
    } else if r == 0 {
        "ok".to_string()
    } else {
        format!("{r}")
    }
}

/// A getter that answers through a pointer.
fn prctl_get(option: i32, a3: u64, a4: u64, a5: u64) -> String {
    let mut out: u64 = 0xdead_beef;
    let r = unsafe { libc::syscall(libc::SYS_prctl, option as i64, &mut out as *mut u64 as u64, a3, a4, a5) };
    if r < 0 {
        named(errno()).to_string()
    } else {
        format!("r={r}, {}", out & 0xffff_ffff)
    }
}

/// Run `f` in a forked child and wait for it. What it prints is the child's,
/// and what it sets dies with it.
fn in_child(f: impl FnOnce()) {
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

/// Replace this process with itself, told to print one line and exit.
fn exec_self(arg: &str, what: &str) {
    let exe = std::env::current_exe().unwrap();
    let err = std::os::unix::process::CommandExt::exec(std::process::Command::new(exe).arg(arg));
    line(what, format!("exec failed: {err}"));
}

fn mmap(prot: i32) -> Result<*mut u8, i32> {
    let p = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, prot, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    };
    if p == libc::MAP_FAILED { Err(errno()) } else { Ok(p.cast()) }
}

fn mmap_line(what: &str, prot: i32) -> Option<*mut u8> {
    match mmap(prot) {
        Ok(p) => {
            line(what, "ok");
            Some(p)
        }
        Err(e) => {
            line(what, named(e));
            None
        }
    }
}

fn mprotect_line(what: &str, p: Option<*mut u8>, prot: i32) {
    let Some(p) = p else {
        line(what, "no mapping to protect");
        return;
    };
    let r = unsafe { libc::mprotect(p.cast(), 4096, prot) };
    line(what, if r == 0 { "ok" } else { named(errno()) });
}

// Option numbers, from <linux/prctl.h>. Written here rather than taken from
// libc, which lacks the newer ones on this target.
const PR_SET_PDEATHSIG: i32 = 1;
const PR_GET_PDEATHSIG: i32 = 2;
const PR_GET_DUMPABLE: i32 = 3;
const PR_SET_DUMPABLE: i32 = 4;
const PR_GET_UNALIGN: i32 = 5;
const PR_SET_UNALIGN: i32 = 6;
const PR_GET_KEEPCAPS: i32 = 7;
const PR_SET_KEEPCAPS: i32 = 8;
const PR_GET_FPEMU: i32 = 9;
const PR_GET_TIMING: i32 = 13;
const PR_SET_TIMING: i32 = 14;
const PR_SET_NAME: i32 = 15;
const PR_GET_NAME: i32 = 16;
const PR_GET_ENDIAN: i32 = 19;
const PR_GET_SECCOMP: i32 = 21;
const PR_SET_SECCOMP: i32 = 22;
const PR_CAPBSET_READ: i32 = 23;
const PR_CAPBSET_DROP: i32 = 24;
const PR_GET_TSC: i32 = 25;
const PR_SET_TSC: i32 = 26;
const PR_GET_SECUREBITS: i32 = 27;
const PR_SET_SECUREBITS: i32 = 28;
const PR_SET_TIMERSLACK: i32 = 29;
const PR_GET_TIMERSLACK: i32 = 30;
const PR_TASK_PERF_EVENTS_DISABLE: i32 = 31;
const PR_TASK_PERF_EVENTS_ENABLE: i32 = 32;
const PR_MCE_KILL: i32 = 33;
const PR_MCE_KILL_GET: i32 = 34;
const PR_SET_MM: i32 = 35;
const PR_SET_CHILD_SUBREAPER: i32 = 36;
const PR_GET_CHILD_SUBREAPER: i32 = 37;
const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_GET_NO_NEW_PRIVS: i32 = 39;
const PR_GET_TID_ADDRESS: i32 = 40;
const PR_SET_THP_DISABLE: i32 = 41;
const PR_GET_THP_DISABLE: i32 = 42;
const PR_MPX_ENABLE_MANAGEMENT: i32 = 43;
const PR_SET_FP_MODE: i32 = 45;
const PR_GET_FP_MODE: i32 = 46;
const PR_CAP_AMBIENT: i32 = 47;
const PR_SVE_SET_VL: i32 = 50;
const PR_SVE_GET_VL: i32 = 51;
const PR_GET_SPECULATION_CTRL: i32 = 52;
const PR_SET_SPECULATION_CTRL: i32 = 53;
const PR_PAC_RESET_KEYS: i32 = 54;
const PR_SET_TAGGED_ADDR_CTRL: i32 = 55;
const PR_GET_TAGGED_ADDR_CTRL: i32 = 56;
const PR_SET_IO_FLUSHER: i32 = 57;
const PR_GET_IO_FLUSHER: i32 = 58;
const PR_SET_SYSCALL_USER_DISPATCH: i32 = 59;
const PR_PAC_GET_ENABLED_KEYS: i32 = 61;
const PR_SCHED_CORE: i32 = 62;
const PR_SME_GET_VL: i32 = 64;
const PR_SET_MDWE: i32 = 65;
const PR_GET_MDWE: i32 = 66;
const PR_SET_MEMORY_MERGE: i32 = 67;
const PR_GET_MEMORY_MERGE: i32 = 68;
const PR_SET_VMA: i32 = 0x5356_4d41;
const PR_GET_AUXV: i32 = 0x4155_5856;

const PR_THP_DISABLE_EXCEPT_ADVISED: u64 = 1 << 1;
const PR_SPEC_STORE_BYPASS: u64 = 0;
const PR_SPEC_ENABLE: u64 = 1 << 1;
const PR_SPEC_DISABLE: u64 = 1 << 2;
const PR_SPEC_FORCE_DISABLE: u64 = 1 << 3;
const PR_SPEC_DISABLE_NOEXEC: u64 = 1 << 4;
const SECBIT_KEEP_CAPS_LOCKED: u64 = 1 << 5;
const PR_MDWE_REFUSE_EXEC_GAIN: u64 = 1;
const PR_MDWE_NO_INHERIT: u64 = 2;

const RW: i32 = libc::PROT_READ | libc::PROT_WRITE;
const RX: i32 = libc::PROT_READ | libc::PROT_EXEC;
const RWX: i32 = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--mdwe-after-exec") => {
            line("PR_GET_MDWE in the exec'd image", prctl(PR_GET_MDWE, 0, 0, 0, 0));
            return;
        }
        Some("--thp-after-exec") => {
            line("PR_GET_THP_DISABLE in the exec'd image", prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0));
            return;
        }
        _ => {}
    }

    println!("## the ones with a value to read back");
    line("PR_SET_PDEATHSIG(SIGTERM)", prctl(PR_SET_PDEATHSIG, libc::SIGTERM as u64, 0, 0, 0));
    line("PR_GET_PDEATHSIG", prctl_get(PR_GET_PDEATHSIG, 0, 0, 0));
    line("PR_SET_PDEATHSIG(0)", prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0));
    line("PR_SET_PDEATHSIG(65)", prctl(PR_SET_PDEATHSIG, 65, 0, 0, 0));
    line("PR_GET_DUMPABLE", prctl(PR_GET_DUMPABLE, 0, 0, 0, 0));
    line("PR_SET_DUMPABLE(0)", prctl(PR_SET_DUMPABLE, 0, 0, 0, 0));
    line("PR_GET_DUMPABLE after", prctl(PR_GET_DUMPABLE, 0, 0, 0, 0));
    line("PR_SET_DUMPABLE(1)", prctl(PR_SET_DUMPABLE, 1, 0, 0, 0));
    line("PR_SET_DUMPABLE(3)", prctl(PR_SET_DUMPABLE, 3, 0, 0, 0));
    line("PR_GET_KEEPCAPS", prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0));
    line("PR_SET_KEEPCAPS(1)", prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0));
    line("PR_GET_KEEPCAPS after", prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0));
    line("PR_GET_SECUREBITS with keepcaps set", prctl(PR_GET_SECUREBITS, 0, 0, 0, 0));
    line("PR_SET_KEEPCAPS(2)", prctl(PR_SET_KEEPCAPS, 2, 0, 0, 0));
    line("PR_SET_KEEPCAPS(0)", prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0));
    {
        let name = b"probe-name\0";
        line("PR_SET_NAME", prctl(PR_SET_NAME, name.as_ptr() as u64, 0, 0, 0));
        let mut back = [0u8; 16];
        let r = unsafe { libc::prctl(PR_GET_NAME, back.as_mut_ptr() as u64, 0, 0, 0) };
        let got = String::from_utf8_lossy(&back[..back.iter().position(|&b| b == 0).unwrap_or(16)]).into_owned();
        line("PR_GET_NAME", if r < 0 { named(errno()).to_string() } else { got });
        let long = b"a-name-longer-than-fifteen-bytes\0";
        line("PR_SET_NAME with a long name", prctl(PR_SET_NAME, long.as_ptr() as u64, 0, 0, 0));
        let r = unsafe { libc::prctl(PR_GET_NAME, back.as_mut_ptr() as u64, 0, 0, 0) };
        let got = String::from_utf8_lossy(&back[..back.iter().position(|&b| b == 0).unwrap_or(16)]).into_owned();
        line("  reads back as", if r < 0 { named(errno()).to_string() } else { got });
        line("PR_SET_NAME(NULL)", prctl(PR_SET_NAME, 0, 0, 0, 0));
        line("PR_GET_NAME(NULL)", prctl(PR_GET_NAME, 0, 0, 0, 0));
    }
    line("PR_GET_TIMERSLACK", prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0));
    line("PR_SET_TIMERSLACK(100000)", prctl(PR_SET_TIMERSLACK, 100_000, 0, 0, 0));
    line("PR_GET_TIMERSLACK after", prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0));
    line("PR_SET_TIMERSLACK(1<<40)", prctl(PR_SET_TIMERSLACK, 1 << 40, 0, 0, 0));
    line("PR_GET_TIMERSLACK after, a long", prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0));
    line("PR_SET_TIMERSLACK(0), the default", prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0));
    line("PR_GET_TIMERSLACK after", prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0));
    line("PR_SET_TIMERSLACK(7)", prctl(PR_SET_TIMERSLACK, 7, 0, 0, 0));
    in_child(|| {
        // The child's default is what the parent had when it forked.
        line("PR_GET_TIMERSLACK in a child", prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0));
        line("PR_SET_TIMERSLACK(9) in the child", prctl(PR_SET_TIMERSLACK, 9, 0, 0, 0));
        line("PR_SET_TIMERSLACK(0) in the child", prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0));
        line("PR_GET_TIMERSLACK, the child's default", prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0));
    });
    line("PR_SET_TIMERSLACK(0) in the parent", prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0));
    line("PR_GET_TIMERSLACK, the parent's default", prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0));
    line("PR_GET_CHILD_SUBREAPER", prctl_get(PR_GET_CHILD_SUBREAPER, 0, 0, 0));
    line("PR_SET_CHILD_SUBREAPER(1)", prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0));
    line("PR_GET_CHILD_SUBREAPER after", prctl_get(PR_GET_CHILD_SUBREAPER, 0, 0, 0));
    line("PR_SET_CHILD_SUBREAPER(0)", prctl(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0));
    line("PR_GET_THP_DISABLE", prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0));
    line("PR_SET_THP_DISABLE(1)", prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0));
    line("PR_GET_THP_DISABLE after", prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0));
    line("PR_SET_THP_DISABLE(1, EXCEPT_ADVISED)", prctl(PR_SET_THP_DISABLE, 1, PR_THP_DISABLE_EXCEPT_ADVISED, 0, 0));
    line("PR_GET_THP_DISABLE after", prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0));
    line("PR_SET_THP_DISABLE(1) with arg3 = 1", prctl(PR_SET_THP_DISABLE, 1, 1, 0, 0));
    line("PR_SET_THP_DISABLE(0, EXCEPT_ADVISED)", prctl(PR_SET_THP_DISABLE, 0, PR_THP_DISABLE_EXCEPT_ADVISED, 0, 0));
    line("PR_GET_THP_DISABLE with a non-zero arg", prctl(PR_GET_THP_DISABLE, 1, 0, 0, 0));
    in_child(|| {
        line("PR_GET_THP_DISABLE in a child", prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0));
        exec_self("--thp-after-exec", "PR_GET_THP_DISABLE in the exec'd image");
    });
    line("PR_SET_THP_DISABLE(0)", prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0));
    line("PR_GET_TID_ADDRESS", {
        let mut out: u64 = 0;
        let r = unsafe { libc::prctl(PR_GET_TID_ADDRESS, &mut out as *mut u64 as u64, 0, 0, 0) };
        if r < 0 { named(errno()).to_string() } else { format!("r={r}, address is {}", if out != 0 { "set" } else { "zero" }) }
    });
    line("PR_GET_TID_ADDRESS(NULL)", prctl(PR_GET_TID_ADDRESS, 0, 0, 0, 0));
    line("PR_GET_SECCOMP", prctl(PR_GET_SECCOMP, 0, 0, 0, 0));
    line("PR_SET_SECCOMP(99), no such mode", prctl(PR_SET_SECCOMP, 99, 0, 0, 0));
    line("PR_GET_NO_NEW_PRIVS", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
    line("PR_GET_NO_NEW_PRIVS with a non-zero arg", prctl(PR_GET_NO_NEW_PRIVS, 1, 0, 0, 0));

    println!("## capabilities and security bits");
    line("PR_CAPBSET_READ(CAP_CHOWN)", prctl(PR_CAPBSET_READ, 0, 0, 0, 0));
    line("PR_CAPBSET_READ(CAP_SYS_ADMIN)", prctl(PR_CAPBSET_READ, 21, 0, 0, 0));
    line("PR_CAPBSET_READ(CAP_CHECKPOINT_RESTORE), the last", prctl(PR_CAPBSET_READ, 40, 0, 0, 0));
    line("PR_CAPBSET_READ(41)", prctl(PR_CAPBSET_READ, 41, 0, 0, 0));
    line("PR_CAPBSET_READ(999)", prctl(PR_CAPBSET_READ, 999, 0, 0, 0));
    line("PR_CAPBSET_DROP(999)", prctl(PR_CAPBSET_DROP, 999, 0, 0, 0));
    // CAP_CHOWN and CAP_DAC_OVERRIDE, because a container's bounding set is
    // the runtime's and these two are in docker's default one.
    in_child(|| {
        line("PR_CAPBSET_DROP(CAP_CHOWN) in a child", prctl(PR_CAPBSET_DROP, 0, 0, 0, 0));
        line("PR_CAPBSET_READ(CAP_CHOWN) after", prctl(PR_CAPBSET_READ, 0, 0, 0, 0));
        line("PR_CAPBSET_READ(CAP_DAC_OVERRIDE) after", prctl(PR_CAPBSET_READ, 1, 0, 0, 0));
    });
    line("PR_GET_SECUREBITS", prctl(PR_GET_SECUREBITS, 0, 0, 0, 0));
    line("PR_SET_SECUREBITS(0)", prctl(PR_SET_SECUREBITS, 0, 0, 0, 0));
    line("PR_SET_SECUREBITS(0xffff)", prctl(PR_SET_SECUREBITS, 0xffff, 0, 0, 0));
    line("PR_SET_SECUREBITS(0x1000)", prctl(PR_SET_SECUREBITS, 0x1000, 0, 0, 0));
    in_child(|| {
        // The two bits 6.14 added, and the first one past them.
        line("PR_SET_SECUREBITS(EXEC_RESTRICT_FILE) in a child", prctl(PR_SET_SECUREBITS, 0x100, 0, 0, 0));
        line("PR_SET_SECUREBITS(EXEC_DENY_INTERACTIVE)", prctl(PR_SET_SECUREBITS, 0x400, 0, 0, 0));
        line("PR_GET_SECUREBITS after", prctl(PR_GET_SECUREBITS, 0, 0, 0, 0));
    });
    in_child(|| {
        line("PR_SET_SECUREBITS(KEEP_CAPS_LOCKED) in a child", prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS_LOCKED, 0, 0, 0));
        line("PR_GET_SECUREBITS after", prctl(PR_GET_SECUREBITS, 0, 0, 0, 0));
        line("PR_SET_KEEPCAPS(1) under the lock", prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0));
        line("PR_SET_KEEPCAPS(2) under the lock", prctl(PR_SET_KEEPCAPS, 2, 0, 0, 0));
        line("PR_SET_SECUREBITS(0), clearing a lock", prctl(PR_SET_SECUREBITS, 0, 0, 0, 0));
        line("PR_SET_SECUREBITS(KEEP_CAPS_LOCKED) again", prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS_LOCKED, 0, 0, 0));
    });
    line("PR_CAP_AMBIENT(IS_SET, CAP_CHOWN)", prctl(PR_CAP_AMBIENT, 1, 0, 0, 0));
    line("PR_CAP_AMBIENT(RAISE, CAP_CHOWN)", prctl(PR_CAP_AMBIENT, 2, 0, 0, 0));
    line("PR_CAP_AMBIENT(LOWER, CAP_CHOWN)", prctl(PR_CAP_AMBIENT, 3, 0, 0, 0));
    line("PR_CAP_AMBIENT(CLEAR_ALL)", prctl(PR_CAP_AMBIENT, 4, 0, 0, 0));
    line("PR_CAP_AMBIENT(CLEAR_ALL, 1)", prctl(PR_CAP_AMBIENT, 4, 1, 0, 0));
    line("PR_CAP_AMBIENT(IS_SET, 999)", prctl(PR_CAP_AMBIENT, 1, 999, 0, 0));
    line("PR_CAP_AMBIENT(RAISE, 999)", prctl(PR_CAP_AMBIENT, 2, 999, 0, 0));
    line("PR_CAP_AMBIENT(IS_SET, CAP_CHOWN, 1)", prctl(PR_CAP_AMBIENT, 1, 0, 1, 0));
    line("PR_CAP_AMBIENT(99)", prctl(PR_CAP_AMBIENT, 99, 0, 0, 0));

    println!("## the architecture ones");
    line("PR_GET_UNALIGN", prctl_get(PR_GET_UNALIGN, 0, 0, 0));
    line("PR_SET_UNALIGN(0)", prctl(PR_SET_UNALIGN, 0, 0, 0, 0));
    line("PR_GET_FPEMU", prctl_get(PR_GET_FPEMU, 0, 0, 0));
    line("PR_GET_TIMING", prctl(PR_GET_TIMING, 0, 0, 0, 0));
    line("PR_SET_TIMING(0)", prctl(PR_SET_TIMING, 0, 0, 0, 0));
    line("PR_SET_TIMING(1)", prctl(PR_SET_TIMING, 1, 0, 0, 0));
    line("PR_GET_ENDIAN", prctl_get(PR_GET_ENDIAN, 0, 0, 0));
    line("PR_GET_TSC", prctl_get(PR_GET_TSC, 0, 0, 0));
    line("PR_GET_TSC(NULL)", prctl(PR_GET_TSC, 0, 0, 0, 0));
    line("PR_SET_TSC(PR_TSC_ENABLE)", prctl(PR_SET_TSC, 1, 0, 0, 0));
    line("PR_SET_TSC(3)", prctl(PR_SET_TSC, 3, 0, 0, 0));
    in_child(|| {
        // Making the counter trap would kill this child's next clock_gettime,
        // which is why it is a child.
        line("PR_SET_TSC(PR_TSC_SIGSEGV) in a child", prctl(PR_SET_TSC, 2, 0, 0, 0));
    });
    line("PR_GET_FP_MODE", prctl(PR_GET_FP_MODE, 0, 0, 0, 0));
    line("PR_SET_FP_MODE(0)", prctl(PR_SET_FP_MODE, 0, 0, 0, 0));
    line("PR_MPX_ENABLE_MANAGEMENT", prctl(PR_MPX_ENABLE_MANAGEMENT, 0, 0, 0, 0));
    line("PR_SVE_GET_VL", prctl(PR_SVE_GET_VL, 0, 0, 0, 0));
    line("PR_SVE_SET_VL(16)", prctl(PR_SVE_SET_VL, 16, 0, 0, 0));
    line("PR_SME_GET_VL", prctl(PR_SME_GET_VL, 0, 0, 0, 0));
    line("PR_PAC_RESET_KEYS(0)", prctl(PR_PAC_RESET_KEYS, 0, 0, 0, 0));
    line("PR_PAC_RESET_KEYS(0x100), no such key", prctl(PR_PAC_RESET_KEYS, 0x100, 0, 0, 0));
    line("PR_PAC_GET_ENABLED_KEYS", prctl(PR_PAC_GET_ENABLED_KEYS, 0, 0, 0, 0));
    line("PR_GET_TAGGED_ADDR_CTRL", prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0));
    line("PR_GET_TAGGED_ADDR_CTRL(1)", prctl(PR_GET_TAGGED_ADDR_CTRL, 1, 0, 0, 0));
    line("PR_SET_TAGGED_ADDR_CTRL(PR_TAGGED_ADDR_ENABLE)", prctl(PR_SET_TAGGED_ADDR_CTRL, 1, 0, 0, 0));
    line("PR_GET_TAGGED_ADDR_CTRL after", prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0));
    line("PR_SET_TAGGED_ADDR_CTRL(0)", prctl(PR_SET_TAGGED_ADDR_CTRL, 0, 0, 0, 0));
    line("PR_SET_TAGGED_ADDR_CTRL(0, 1)", prctl(PR_SET_TAGGED_ADDR_CTRL, 0, 1, 0, 0));
    line("PR_SET_TAGGED_ADDR_CTRL(0xffff)", prctl(PR_SET_TAGGED_ADDR_CTRL, 0xffff, 0, 0, 0));
    line("PR_GET_SPECULATION_CTRL(STORE_BYPASS)", prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0));
    line("PR_GET_SPECULATION_CTRL(INDIRECT_BRANCH)", prctl(PR_GET_SPECULATION_CTRL, 1, 0, 0, 0));
    line("PR_GET_SPECULATION_CTRL(L1D_FLUSH)", prctl(PR_GET_SPECULATION_CTRL, 2, 0, 0, 0));
    line("PR_GET_SPECULATION_CTRL(99)", prctl(PR_GET_SPECULATION_CTRL, 99, 0, 0, 0));
    line("PR_GET_SPECULATION_CTRL(STORE_BYPASS, 1)", prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 1, 0, 0));
    line("PR_SET_SPECULATION_CTRL(99, 0)", prctl(PR_SET_SPECULATION_CTRL, 99, 0, 0, 0));
    line("PR_SET_SPECULATION_CTRL(STORE_BYPASS, 99)", prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 99, 0, 0));
    line("PR_SET_SPECULATION_CTRL(STORE_BYPASS, ENABLE, 1)", prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_ENABLE, 1, 0));
    in_child(|| {
        let get = || prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);
        line("  SET(STORE_BYPASS, DISABLE) in a child", prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0));
        line("  GET after DISABLE", get());
        line("  SET(STORE_BYPASS, ENABLE)", prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_ENABLE, 0, 0));
        line("  GET after ENABLE", get());
        line("  SET(STORE_BYPASS, DISABLE_NOEXEC)", prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE_NOEXEC, 0, 0));
        line("  GET after DISABLE_NOEXEC", get());
        line("  SET(STORE_BYPASS, FORCE_DISABLE)", prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_FORCE_DISABLE, 0, 0));
        line("  GET after FORCE_DISABLE", get());
        line("  SET(STORE_BYPASS, ENABLE) after a force", prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_ENABLE, 0, 0));
        line("  SET(STORE_BYPASS, DISABLE_NOEXEC) after a force", prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE_NOEXEC, 0, 0));
        line("  SET(STORE_BYPASS, DISABLE) after a force", prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0));
        line("  GET at the end", get());
    });

    println!("## memory-deny-write-execute");
    line("PR_GET_MDWE", prctl(PR_GET_MDWE, 0, 0, 0, 0));
    line("PR_GET_MDWE(1)", prctl(PR_GET_MDWE, 1, 0, 0, 0));
    line("PR_SET_MDWE(0)", prctl(PR_SET_MDWE, 0, 0, 0, 0));
    line("PR_SET_MDWE(NO_INHERIT alone)", prctl(PR_SET_MDWE, PR_MDWE_NO_INHERIT, 0, 0, 0));
    line("PR_SET_MDWE(4)", prctl(PR_SET_MDWE, 4, 0, 0, 0));
    line("PR_SET_MDWE(0xffff)", prctl(PR_SET_MDWE, 0xffff, 0, 0, 0));
    line("PR_SET_MDWE(1, 1)", prctl(PR_SET_MDWE, 1, 1, 0, 0));
    line("mmap(RWX) without MDWE", match mmap(RWX) { Ok(_) => "ok".to_string(), Err(e) => named(e).to_string() });
    in_child(|| {
        line("PR_SET_MDWE(REFUSE_EXEC_GAIN) in a child", prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0));
        line("PR_GET_MDWE after", prctl(PR_GET_MDWE, 0, 0, 0, 0));
        line("PR_SET_MDWE(REFUSE_EXEC_GAIN) again", prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0));
        line("PR_SET_MDWE(0) to undo it", prctl(PR_SET_MDWE, 0, 0, 0, 0));
        line("PR_SET_MDWE(REFUSE_EXEC_GAIN|NO_INHERIT) to change it", prctl(PR_SET_MDWE, 3, 0, 0, 0));
        mmap_line("  mmap(RWX) under MDWE", RWX);
        let rw = mmap_line("  mmap(RW) under MDWE", RW);
        mprotect_line("  mprotect(RW -> RX)", rw, RX);
        mprotect_line("  mprotect(RW -> R)", rw, libc::PROT_READ);
        mprotect_line("  mprotect(R -> RX)", rw, RX);
        mprotect_line("  mprotect(R -> RWX)", rw, RWX);
        let rx = mmap_line("  mmap(RX) under MDWE", RX);
        mprotect_line("  mprotect(RX -> RX)", rx, RX);
        mprotect_line("  mprotect(RX -> RW)", rx, RW);
        mprotect_line("  mprotect(RW -> RX), having been RX once", rx, RX);
        let x = mmap_line("  mmap(X) under MDWE", libc::PROT_EXEC);
        mprotect_line("  mprotect(X -> R)", x, libc::PROT_READ);
        mprotect_line("  mprotect(R -> X)", x, libc::PROT_EXEC);
        let none = mmap_line("  mmap(PROT_NONE) under MDWE", libc::PROT_NONE);
        mprotect_line("  mprotect(NONE -> RW)", none, RW);
        mprotect_line("  mprotect(NONE -> X)", mmap(libc::PROT_NONE).ok(), libc::PROT_EXEC);
        // Half the range executable: the whole request is judged.
        let pair = unsafe {
            let p = libc::mmap(std::ptr::null_mut(), 8192, RX, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
            if p == libc::MAP_FAILED { Err(errno()) } else { Ok(p) }
        };
        match pair {
            Ok(p) => {
                let r = unsafe { libc::mprotect(p.cast::<u8>().add(4096).cast(), 4096, libc::PROT_READ) };
                line("  second page of an RX pair made R", if r == 0 { "ok" } else { named(errno()) });
                let r = unsafe { libc::mprotect(p, 8192, RX) };
                line("  mprotect(both pages -> RX)", if r == 0 { "ok" } else { named(errno()) });
            }
            Err(e) => {
                line("  second page of an RX pair made R", named(e));
                line("  mprotect(both pages -> RX)", named(e));
            }
        }
        in_child(|| {
            line("  PR_GET_MDWE in a grandchild", prctl(PR_GET_MDWE, 0, 0, 0, 0));
            mmap_line("  mmap(RWX) in the grandchild", RWX);
        });
        exec_self("--mdwe-after-exec", "PR_GET_MDWE in the exec'd image");
    });
    in_child(|| {
        line("PR_SET_MDWE(REFUSE_EXEC_GAIN|NO_INHERIT) in a child", prctl(PR_SET_MDWE, 3, 0, 0, 0));
        line("PR_GET_MDWE after", prctl(PR_GET_MDWE, 0, 0, 0, 0));
        mmap_line("  mmap(RWX) under MDWE|NO_INHERIT", RWX);
        in_child(|| {
            line("  PR_GET_MDWE in a grandchild", prctl(PR_GET_MDWE, 0, 0, 0, 0));
            mmap_line("  mmap(RWX) in the grandchild", RWX);
        });
        exec_self("--mdwe-after-exec", "PR_GET_MDWE in the exec'd image");
    });

    println!("## the rest");
    line("PR_TASK_PERF_EVENTS_DISABLE", prctl(PR_TASK_PERF_EVENTS_DISABLE, 0, 0, 0, 0));
    line("PR_TASK_PERF_EVENTS_ENABLE", prctl(PR_TASK_PERF_EVENTS_ENABLE, 0, 0, 0, 0));
    line("PR_MCE_KILL_GET", prctl(PR_MCE_KILL_GET, 0, 0, 0, 0));
    line("PR_MCE_KILL_GET(1)", prctl(PR_MCE_KILL_GET, 1, 0, 0, 0));
    line("PR_MCE_KILL(SET, EARLY)", prctl(PR_MCE_KILL, 1, 1, 0, 0));
    line("PR_MCE_KILL_GET after", prctl(PR_MCE_KILL_GET, 0, 0, 0, 0));
    line("PR_MCE_KILL(SET, LATE)", prctl(PR_MCE_KILL, 1, 0, 0, 0));
    line("PR_MCE_KILL_GET after", prctl(PR_MCE_KILL_GET, 0, 0, 0, 0));
    line("PR_MCE_KILL(SET, 3)", prctl(PR_MCE_KILL, 1, 3, 0, 0));
    line("PR_MCE_KILL(CLEAR, 1)", prctl(PR_MCE_KILL, 0, 1, 0, 0));
    line("PR_MCE_KILL(CLEAR)", prctl(PR_MCE_KILL, 0, 0, 0, 0));
    line("PR_MCE_KILL_GET after CLEAR", prctl(PR_MCE_KILL_GET, 0, 0, 0, 0));
    line("PR_MCE_KILL(SET, DEFAULT, 0, 1)", prctl(PR_MCE_KILL, 1, 2, 0, 1));
    line("PR_MCE_KILL(99)", prctl(PR_MCE_KILL, 99, 0, 0, 0));
    line("PR_SET_MM(99)", prctl(PR_SET_MM, 99, 0, 0, 0));
    line("PR_SET_MM(99, 0, 0, 1)", prctl(PR_SET_MM, 99, 0, 0, 1));
    line("PR_SET_MM(99, 0, 1)", prctl(PR_SET_MM, 99, 0, 1, 0));
    line("PR_GET_IO_FLUSHER", prctl(PR_GET_IO_FLUSHER, 0, 0, 0, 0));
    line("PR_SET_IO_FLUSHER(1)", prctl(PR_SET_IO_FLUSHER, 1, 0, 0, 0));
    line("PR_GET_IO_FLUSHER after", prctl(PR_GET_IO_FLUSHER, 0, 0, 0, 0));
    line("PR_SET_IO_FLUSHER(0)", prctl(PR_SET_IO_FLUSHER, 0, 0, 0, 0));
    line("PR_SET_IO_FLUSHER(2)", prctl(PR_SET_IO_FLUSHER, 2, 0, 0, 0));
    line("PR_SET_SYSCALL_USER_DISPATCH(99)", prctl(PR_SET_SYSCALL_USER_DISPATCH, 99, 0, 0, 0));
    line("PR_SCHED_CORE(99)", prctl(PR_SCHED_CORE, 99, 0, 0, 0));
    line("PR_GET_MEMORY_MERGE", prctl(PR_GET_MEMORY_MERGE, 0, 0, 0, 0));
    line("PR_SET_MEMORY_MERGE(0)", prctl(PR_SET_MEMORY_MERGE, 0, 0, 0, 0));
    line("PR_SET_VMA(99)", prctl(PR_SET_VMA, 99, 0, 0, 0));
    line("PR_GET_AUXV into 8 bytes", {
        let mut buf = [0u8; 8];
        let r = unsafe { libc::prctl(PR_GET_AUXV, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0) };
        if r < 0 { named(errno()).to_string() } else { format!("{r} bytes, first key {}", u64::from_ne_bytes(buf)) }
    });
    line("PR_GET_AUXV into 0 bytes", prctl(PR_GET_AUXV, 0, 0, 0, 0));
    line("PR_GET_AUXV into 8 bytes at NULL", prctl(PR_GET_AUXV, 0, 8, 0, 0));
    line("PR_GET_AUXV with a non-zero arg4", {
        let mut buf = [0u8; 8];
        prctl(PR_GET_AUXV, buf.as_mut_ptr() as u64, buf.len() as u64, 1, 0)
    });
    line("PR_GET_AUXV, whole", {
        let mut buf = [0u8; 1024];
        let r = unsafe { libc::prctl(PR_GET_AUXV, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0) };
        if r < 0 {
            named(errno()).to_string()
        } else {
            // Whether the keys up to AT_NULL are a vector -- AT_PAGESZ is in
            // every one -- rather than which keys, since the two kernels
            // legitimately publish different sets.
            let keys: Vec<u64> = buf
                .chunks(16)
                .map(|c| u64::from_ne_bytes(c[..8].try_into().unwrap()))
                .take_while(|&k| k != 0)
                .collect();
            format!("{r} bytes, AT_PAGESZ {}", if keys.contains(&6) { "present" } else { "absent" })
        }
    });
    line("prctl(9999)", prctl(9999, 0, 0, 0, 0));
    line("prctl(0)", prctl(0, 0, 0, 0, 0));
    line("prctl(-1)", prctl(-1, 0, 0, 0, 0));

    println!("## no_new_privs, last, because it is for ever");
    line("PR_SET_NO_NEW_PRIVS(1)", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    line("PR_GET_NO_NEW_PRIVS after", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
    line("PR_SET_NO_NEW_PRIVS(0), cannot be undone", prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0));
    line("PR_SET_NO_NEW_PRIVS(2)", prctl(PR_SET_NO_NEW_PRIVS, 2, 0, 0, 0));
    line("PR_SET_NO_NEW_PRIVS(1, 1), a non-zero arg3", prctl(PR_SET_NO_NEW_PRIVS, 1, 1, 0, 0));
}
