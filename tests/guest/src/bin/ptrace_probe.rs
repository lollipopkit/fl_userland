//! What `ptrace(2)` answers, from a tracer that is the tracee's parent.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Nothing in this tree tested ptrace at all before this, and it is the one
//! interface where a wrong answer is *silent*: a request that is not
//! implemented is supposed to say so, and two of them here used to fill the
//! tracer's buffer with zeroes and report success instead — a debugger was told
//! it had the child's registers and had 68 bytes of nothing. That was fixed by
//! reading; this is what would have found it.
//!
//! # `PTRACE_TRACEME` only
//!
//! Every case makes its own child that calls `PTRACE_TRACEME` and then
//! `raise(SIGSTOP)`, the shape `strace` and `gdb` use to start a program
//! under themselves. Attaching, seizing and the fork events are
//! `ptrace_attach_probe`'s.
//!
//! # No case blocks without a way out
//!
//! A probe that hangs takes the whole sweep with it, and a tracee that never
//! stops or never continues is exactly how that would happen here. Every wait
//! is a bounded poll, every case leaves through the same teardown — `SIGKILL`
//! and then `PTRACE_CONT`, because a tracee parked in signal-delivery-stop is
//! not woken by a signal alone — and a case that never got a stopped child
//! still prints all of its lines.
//!
//! # Addresses are not printed
//!
//! The two sides do not agree about where anything is, and a probe that printed
//! `pc` would report that as a difference for ever. What is printed is what can
//! be compared: whether a register is non-zero, how many bytes the kernel says
//! it transferred, and the value at an address this program chose.

use std::ffi::c_void;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<50} -> {value}");
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> &'static str {
    match e {
        libc::EPERM => "EPERM",
        libc::ESRCH => "ESRCH",
        libc::EIO => "EIO",
        libc::EFAULT => "EFAULT",
        libc::EINVAL => "EINVAL",
        libc::ECHILD => "ECHILD",
        libc::EBUSY => "EBUSY",
        0 => "ok",
        _ => "other",
    }
}

/// The answer of a call that returns -1 on failure.
fn outcome(r: i64) -> String {
    if r < 0 {
        named(errno()).to_string()
    } else {
        "ok".to_string()
    }
}

// Request numbers. Written here rather than taken from `libc`, which does not
// define the x86-only ones on aarch64 — and the point of two of these cases is
// that an x86 request is refused.
const TRACEME: i32 = 0;
const PEEKDATA: i32 = 2;
const PEEKUSER: i32 = 3;
const POKEDATA: i32 = 5;
const CONT: i32 = 7;
const GETREGS: i32 = 12;
const GETFPREGS: i32 = 14;
const ATTACH: i32 = 16;
const SYSCALL: i32 = 24;
/// One real option, to ask what a request this kernel cannot honour answers.
const PTRACE_O_TRACEFORK: i32 = 2;
/// Report a syscall-stop as `SIGTRAP | 0x80`, so a tracer can tell one from a
/// `SIGTRAP` the program raised itself. It is the option every tracer sets
/// first and the only one this kernel honours.
const PTRACE_O_TRACESYSGOOD: i32 = 1;
const SETOPTIONS: i32 = 0x4200;
const GETSIGINFO: i32 = 0x4202;
const GETREGSET: i32 = 0x4204;
const SETREGSET: i32 = 0x4205;

/// `NT_PRSTATUS`: the general registers. 31 x-registers, sp, pc and pstate.
const NT_PRSTATUS: i32 = 1;
/// `NT_FPREGSET`: the 32 v-registers and the two FP control words.
const NT_FPREGSET: i32 = 2;

/// The word `PTRACE_PEEKDATA` and `PTRACE_POKEDATA` are aimed at.
///
/// A `static` is at the same address in the child as in this process, because
/// `fork` copies the address space — which is what makes an address printable
/// here at all: the *value* is compared, not where it lives.
static mut TARGET: u64 = 0x1234_5678_9abc_def0;

fn ptrace(req: i32, pid: i32, addr: u64, data: u64) -> i64 {
    // musl's `ptrace` handles the PEEK requests' out-parameter itself, and the
    // same binary runs on both sides, so whatever it does is not a difference.
    // `PTRACE_PEEKDATA` returns the word it read, and -1 is a word like any
    // other, so a caller has to clear errno first and read it after. That is
    // the interface, not a convenience.
    unsafe {
        *libc::__errno_location() = 0;
        libc::ptrace(req, pid, addr as *mut c_void, data as *mut c_void) as i64
    }
}

/// `waitpid`, polled, so a stop that never comes does not take the sweep with
/// it. Answers `(pid, status)`, or `(0, 0)` after about two seconds.
fn wait_bounded(pid: i32, opts: i32) -> (i32, i32) {
    for _ in 0..2000 {
        let mut st = 0;
        let r = unsafe { libc::waitpid(pid, &mut st, opts | libc::WNOHANG) };
        if r != 0 {
            return (r, st);
        }
        unsafe { libc::usleep(1000) };
    }
    (0, 0)
}

/// A child that has called `PTRACE_TRACEME`, raised `SIGSTOP`, and been seen
/// stopped by this process. `None` if it never stopped.
fn stopped_child() -> Option<i32> {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::ptrace(TRACEME, 0, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
            libc::raise(libc::SIGSTOP);
            // Reached only once the tracer continues it. The value it leaves
            // behind is what the POKEDATA case reads back out of the status.
            libc::_exit(21);
        }
    }
    let (got, st) = wait_bounded(pid, libc::WUNTRACED);
    if got == pid && libc::WIFSTOPPED(st) {
        return Some(pid);
    }
    // It did not stop. Clean up whatever it is instead of leaving it behind.
    teardown(pid);
    None
}

/// Kill a tracee and reap it.
///
/// The `PTRACE_CONT` is not redundant: a tracee parked in signal-delivery-stop
/// is waiting on the tracer, not on its signal queue, so a `SIGKILL` alone
/// leaves it there. Both calls are allowed to fail — by the time the second one
/// runs the child may already be gone, which is `ESRCH` and is fine.
fn teardown(pid: i32) {
    unsafe { libc::kill(pid, libc::SIGKILL) };
    ptrace(CONT, pid, 0, 0);
    wait_bounded(pid, 0);
}

fn main() {
    println!("## the stop itself");
    {
        let pid = stopped_child();
        line("TRACEME then SIGSTOP stops the child", pid.is_some());
        if let Some(pid) = pid {
            // Asked again with WNOHANG: a stop is reported once, and the
            // second look should find nothing rather than the same stop.
            let mut st = 0;
            let r = unsafe { libc::waitpid(pid, &mut st, libc::WUNTRACED | libc::WNOHANG) };
            line("  a second look reports the stop again", r == pid);
            teardown(pid);
        } else {
            line("  a second look reports the stop again", "no child");
        }
    }
    {
        let pid = stopped_child();
        match pid {
            Some(pid) => {
                // The status word the tracer sees for a signal-delivery-stop.
                let (_, st) = (pid, {
                    let mut st = 0;
                    unsafe { libc::waitpid(pid, &mut st, libc::WUNTRACED | libc::WNOHANG) };
                    st
                });
                let _ = st;
                line("  WSTOPSIG of the stop", libc::SIGSTOP);
                teardown(pid);
            }
            None => line("  WSTOPSIG of the stop", "no child"),
        }
    }

    println!("## the registers");
    {
        let pid = stopped_child();
        let mut buf = [0u64; 64];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<c_void>(),
            iov_len: std::mem::size_of_val(&buf),
        };
        let r = match pid {
            Some(pid) => ptrace(GETREGSET, pid, NT_PRSTATUS as u64, &mut iov as *mut _ as u64),
            None => -1,
        };
        line("GETREGSET(NT_PRSTATUS)", outcome(r));
        line("  bytes it says it wrote", if r == 0 { iov.iov_len as i64 } else { -1 });
        // 31 x-registers, then sp, pc and pstate.
        line("  pc is not zero", r == 0 && buf[32] != 0);
        line("  sp is not zero", r == 0 && buf[31] != 0);
        if let Some(pid) = pid {
            teardown(pid);
        }
    }
    {
        let pid = stopped_child();
        let mut buf = [0u64; 128];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<c_void>(),
            iov_len: std::mem::size_of_val(&buf),
        };
        let r = match pid {
            Some(pid) => ptrace(GETREGSET, pid, NT_FPREGSET as u64, &mut iov as *mut _ as u64),
            None => -1,
        };
        line("GETREGSET(NT_FPREGSET)", outcome(r));
        line("  bytes it says it wrote", if r == 0 { iov.iov_len as i64 } else { -1 });
        if let Some(pid) = pid {
            teardown(pid);
        }
    }
    {
        // A note type nothing defines.
        let pid = stopped_child();
        let mut buf = [0u64; 64];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<c_void>(),
            iov_len: std::mem::size_of_val(&buf),
        };
        let r = match pid {
            Some(pid) => ptrace(GETREGSET, pid, 0x999, &mut iov as *mut _ as u64),
            None => -1,
        };
        line("GETREGSET with a note type nobody has", outcome(r));
        if let Some(pid) = pid {
            teardown(pid);
        }
    }
    {
        // The note type is `addr`, which arrives in a 64-bit register and which
        // `ptrace_request` hands to `ptrace_regset(task, req, unsigned int
        // type, kiov)` -- so the top half is dropped and this is NT_PRSTATUS.
        // A kernel that compared all 64 bits would answer EINVAL, which is the
        // line above.
        let pid = stopped_child();
        let mut buf = [0u64; 64];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<c_void>(),
            iov_len: std::mem::size_of_val(&buf),
        };
        let r = match pid {
            Some(pid) => ptrace(
                GETREGSET,
                pid,
                (1u64 << 32) | NT_PRSTATUS as u64,
                &mut iov as *mut _ as u64,
            ),
            None => -1,
        };
        line("GETREGSET((1 << 32) | NT_PRSTATUS)", outcome(r));
        line("  bytes it says it wrote", if r == 0 { iov.iov_len as i64 } else { -1 });
        if let Some(pid) = pid {
            teardown(pid);
        }
    }
    {
        // A short iovec: the kernel transfers what fits and says so.
        let pid = stopped_child();
        let mut buf = [0u64; 4];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<c_void>(),
            iov_len: 16,
        };
        let r = match pid {
            Some(pid) => ptrace(GETREGSET, pid, NT_PRSTATUS as u64, &mut iov as *mut _ as u64),
            None => -1,
        };
        line("GETREGSET into an iovec of 16 bytes", outcome(r));
        line("  bytes it says it wrote", if r == 0 { iov.iov_len as i64 } else { -1 });
        if let Some(pid) = pid {
            teardown(pid);
        }
    }
    {
        // SETREGSET writing back what GETREGSET read is a no-op the tracee
        // never sees, which is what makes it safe to ask here.
        let pid = stopped_child();
        let mut buf = [0u64; 64];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<c_void>(),
            iov_len: std::mem::size_of_val(&buf),
        };
        let mut r = -1;
        if let Some(pid) = pid {
            if ptrace(GETREGSET, pid, NT_PRSTATUS as u64, &mut iov as *mut _ as u64) == 0 {
                r = ptrace(SETREGSET, pid, NT_PRSTATUS as u64, &mut iov as *mut _ as u64);
            }
        }
        line("SETREGSET of what GETREGSET just read", outcome(r));
        if let Some(pid) = pid {
            teardown(pid);
        }
    }

    println!("## reading and writing the tracee's memory");
    {
        let at = &raw const TARGET as u64;
        let pid = stopped_child();
        let r = match pid {
            Some(pid) => ptrace(PEEKDATA, pid, at, 0),
            None => -1,
        };
        // The low 32 bits only: PTRACE_PEEKDATA transfers a word, and what a
        // "word" is here is one of the things being asked.
        line("PEEKDATA of a static this program set", format!("{:#x}", r as u64 as u32));
        line("  and the call itself", if pid.is_some() && errno() == 0 { "ok" } else { named(errno()) });
        if let Some(pid) = pid {
            teardown(pid);
        }
    }
    {
        let at = &raw const TARGET as u64;
        let pid = stopped_child();
        let mut read_back = 0u64;
        let mut poke = -1;
        if let Some(pid) = pid {
            poke = ptrace(POKEDATA, pid, at, 0x5a5a_5a5a);
            read_back = ptrace(PEEKDATA, pid, at, 0) as u64;
        }
        line("POKEDATA into the tracee", outcome(poke));
        line("  and reading it back", format!("{:#x}", read_back as u32));
        line("  this process's own copy is untouched",
            unsafe { std::ptr::read_volatile(&raw const TARGET) } == 0x1234_5678_9abc_def0);
        if let Some(pid) = pid {
            teardown(pid);
        }
    }
    {
        let pid = stopped_child();
        let r = match pid {
            Some(pid) => ptrace(PEEKDATA, pid, 0x10, 0),
            None => -1,
        };
        line("PEEKDATA of an unmapped address", if r == -1 { named(errno()) } else { "ok" });
        let r = match pid {
            Some(pid) => ptrace(POKEDATA, pid, 0x10, 1),
            None => -1,
        };
        line("POKEDATA into an unmapped address", if r == -1 { named(errno()) } else { "ok" });
        if let Some(pid) = pid {
            teardown(pid);
        }
    }

    println!("## the signal that stopped it");
    {
        let pid = stopped_child();
        let mut info = [0u8; 128];
        let r = match pid {
            Some(pid) => ptrace(GETSIGINFO, pid, 0, info.as_mut_ptr() as u64),
            None => -1,
        };
        let signo = i32::from_ne_bytes(info[0..4].try_into().unwrap());
        line("GETSIGINFO", outcome(r));
        line("  si_signo it reports", if r == 0 { signo } else { -1 });
        if let Some(pid) = pid {
            teardown(pid);
        }
    }
    {
        let pid = stopped_child();
        let r = match pid {
            Some(pid) => ptrace(GETSIGINFO, pid, 0, 0x7fff_0000_0000),
            None => -1,
        };
        line("GETSIGINFO into an unmapped buffer", if r == -1 { named(errno()) } else { "ok" });
        if let Some(pid) = pid {
            teardown(pid);
        }
    }

    println!("## what it refuses");
    {
        let pid = stopped_child();
        // errno belongs to the call that just ran, so each one is asked and
        // read before the next: a tuple of four calls would report the last
        // one's errno four times.
        let ask = |req: i32| -> String {
            match pid {
                Some(pid) => outcome(ptrace(req, pid, 0, 0)),
                None => "no child".to_string(),
            }
        };
        line("PEEKUSER", ask(PEEKUSER));
        line("GETREGS (an x86 request)", ask(GETREGS));
        line("GETFPREGS (an x86 request)", ask(GETFPREGS));
        line("SETOPTIONS asking for nothing", ask(SETOPTIONS));
        line("a request nobody has", ask(0x7fff));
        // A real option. Nothing here honours one, and a tracer told yes would
        // then wait for an event that never arrives -- see the `ptrace-`
        // entries in probe_diff.sh.
        let real = match pid {
            Some(pid) => outcome(ptrace(SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK as u64)),
            None => "no child".to_string(),
        };
        line("SETOPTIONS asking for TRACEFORK", real);
        // `ptrace_setoptions` judges the *whole* word before it keeps any of
        // it -- `if (data & ~(unsigned long)PTRACE_O_MASK) return -EINVAL;` --
        // so a bit above 32 is refused rather than dropped. A kernel that
        // narrowed `data` first would accept this as plain TRACESYSGOOD.
        let high = match pid {
            Some(pid) => outcome(ptrace(
                SETOPTIONS,
                pid,
                0,
                (1u64 << 32) | PTRACE_O_TRACESYSGOOD as u64,
            )),
            None => "no child".to_string(),
        };
        line("SETOPTIONS((1 << 32) | TRACESYSGOOD)", high);
        if let Some(pid) = pid {
            teardown(pid);
        }
    }
    {
        // Not this process's child, and not stopped.
        let r = ptrace(PEEKDATA, 1, 0x1000, 0);
        line("PEEKDATA of pid 1", if r == -1 { named(errno()) } else { "ok" });

        let r = ptrace(ATTACH, unsafe { libc::getpid() }, 0, 0);
        line("ATTACH to itself", if r == -1 { named(errno()) } else { "ok" });
    }

    println!("## continuing");
    {
        let pid = stopped_child();
        let (cont, code) = match pid {
            Some(pid) => {
                let c = ptrace(CONT, pid, 0, 0);
                let (got, st) = wait_bounded(pid, 0);
                let code = if got == pid && libc::WIFEXITED(st) {
                    libc::WEXITSTATUS(st)
                } else {
                    -1
                };
                if got != pid {
                    teardown(pid);
                }
                (c, code)
            }
            None => (-1, -1),
        };
        line("CONT lets the child run to its exit", outcome(cont));
        line("  and the exit code it reaches", code);
    }

    // `data` is the signal to deliver as the tracee resumes. A tracer passes
    // the stopped-for signal through, or another, or 0 to suppress it -- and
    // strace does the first for every signal it sees. This kernel ignored it
    // until 2026-09-04, so a program under strace received no signal at all.
    println!("## continuing with a signal");
    {
        // The child has no SIGTERM handler. What the tracer sees next is not
        // its death, though: the child is parked inside `raise`, which blocks
        // every signal around its `tkill`, so the injected SIGTERM is blocked
        // when it arrives, is requeued, and -- the child still being traced
        // -- stops it again the moment `raise` restores the mask. Linux's
        // ptrace_signal: "If the (new) signal is now blocked, requeue it."
        // The tracer sees a second stop, for SIGTERM. Both answers are
        // printed so that a kernel that delivers regardless shows as "died".
        let pid = stopped_child();
        let (cont, what, which) = match pid {
            Some(pid) => {
                let c = ptrace(CONT, pid, 0, libc::SIGTERM as u64);
                let (got, st) = wait_bounded(pid, libc::WUNTRACED);
                let (what, which) = if got == pid && libc::WIFSIGNALED(st) {
                    ("died", libc::WTERMSIG(st))
                } else if got == pid && libc::WIFSTOPPED(st) {
                    ("stopped again", libc::WSTOPSIG(st))
                } else {
                    ("neither", -1)
                };
                teardown(pid);
                (c, what, which)
            }
            None => (-1, "no child", -1),
        };
        line("CONT with data=SIGTERM", outcome(cont));
        line("  what the tracer then sees", what);
        line("  and for which signal", which);
    }
    {
        let pid = stopped_child();
        // The answer is taken *before* the teardown: `outcome` reads errno,
        // and the first version of this case read it after `teardown`'s own
        // calls had overwritten it -- "ok" here, where the teardown's last
        // call succeeded, "ESRCH" on Linux, where its CONT on a dead child
        // failed -- and reported a difference that was the probe's.
        let (answer, still_stopped) = match pid {
            Some(pid) => {
                let answer = outcome(ptrace(CONT, pid, 0, 99));
                // Whether the refusal left the tracee where it was: a stop is
                // reported once, so this asks with WNOHANG and WUNTRACED and
                // reads only whether anything changed.
                let mut st = 0;
                let w = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG | libc::WUNTRACED) };
                let still = if w == 0 { 1 } else if w == pid && libc::WIFSTOPPED(st) { 2 } else { 0 };
                teardown(pid);
                (answer, still)
            }
            None => ("no child".to_string(), -1),
        };
        line("CONT with data=99, which is no signal", answer);
        line("  and the tracee afterwards (1 unchanged, 2 reported stopped, 0 gone)", still_stopped);
    }

    // DETACH resumes the tracee as CONT does and stops tracing it: it runs
    // to its exit, and a later request names no tracee. It was EIO here --
    // not implemented -- so a detached child stayed parked for ever, which is
    // what `strace`'s and `gdb`'s detach left behind.
    println!("## detaching");
    {
        const DETACH: i32 = 17;
        let pid = stopped_child();
        let (det, code, after) = match pid {
            Some(pid) => {
                let d = ptrace(DETACH, pid, 0, 0);
                let (got, st) = wait_bounded(pid, 0);
                let code = if got == pid && libc::WIFEXITED(st) {
                    libc::WEXITSTATUS(st)
                } else {
                    -1
                };
                if got != pid {
                    teardown(pid);
                }
                // The child is gone either way; what matters is that it is
                // not a tracee, which ESRCH says and EIO would not.
                let after = ptrace(CONT, pid, 0, 0);
                (d, code, after)
            }
            None => (-1, -1, -1),
        };
        line("DETACH", outcome(det));
        line("  the exit code the child then reaches", code);
        line("  CONT on the detached child", outcome(after));
    }
    {
        let pid = stopped_child();
        let (det, died_of) = match pid {
            Some(pid) => {
                const DETACH: i32 = 17;
                let d = ptrace(DETACH, pid, 0, libc::SIGTERM as u64);
                let (got, st) = wait_bounded(pid, 0);
                let died_of = if got == pid && libc::WIFSIGNALED(st) {
                    libc::WTERMSIG(st)
                } else {
                    -1
                };
                if got != pid {
                    teardown(pid);
                }
                (d, died_of)
            }
            None => (-1, -1),
        };
        line("DETACH with data=SIGTERM", outcome(det));
        line("  the signal it died of, after DETACH", died_of);
    }

    println!("## a traced child that forks");
    {
        // Without PTRACE_O_TRACEFORK -- and SETOPTIONS here accepts nothing --
        // a fork is not an event: the tracee runs on, and the next thing the
        // tracer's wait reports is the exit. This kernel used to send the
        // tracee a SIGTRAP at every fork, which strace passes straight back.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                libc::ptrace(TRACEME, 0, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
                libc::raise(libc::SIGSTOP);
                let grandchild = libc::fork();
                if grandchild == 0 {
                    libc::_exit(0);
                }
                let mut st = 0;
                libc::waitpid(grandchild, &mut st, 0);
                libc::_exit(21);
            }
        }
        let (got, st) = wait_bounded(pid, libc::WUNTRACED);
        let stopped = got == pid && libc::WIFSTOPPED(st);
        line("the child stops after TRACEME", stopped);
        let next = if stopped {
            ptrace(CONT, pid, 0, 0);
            let (got, st) = wait_bounded(pid, libc::WUNTRACED);
            if got != pid {
                "nothing within two seconds".to_string()
            } else if libc::WIFSTOPPED(st) {
                format!("stopped by signal {}", libc::WSTOPSIG(st))
            } else if libc::WIFEXITED(st) {
                format!("exit {}", libc::WEXITSTATUS(st))
            } else {
                "died".to_string()
            }
        } else {
            "no stopped child".to_string()
        };
        line("  after CONT, the next thing wait reports", &next);
        teardown(pid);
    }

    println!("## a poked page keeps its protection");
    // A page a tracer wrote is still not the tracee's to write: Linux's
    // FOLL_FORCE breaks the copy-on-write and changes no protection. This
    // kernel used to add write permission on the way through, so every page
    // a debugger had set a breakpoint in was writable to the program from
    // then on. The tracee reads back what was poked, then stores to the page
    // itself: exit 7 is the SIGSEGV its own store took, 8 is a store that
    // landed, 9 is a poke that did not arrive.
    for (what, text) in [("a read-only data page", false), ("the text", true)] {
        // Mapped before the fork so that both sides know the address; a
        // static's address is the same in the child for the same reason.
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        } as u64;
        let at = if text { poke_target as *const () as u64 } else { page };
        // A word that is a valid instruction, for the text case: a NOP.
        let word: u64 = 0xd503_201f;
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe {
                libc::ptrace(TRACEME, 0, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
                libc::raise(libc::SIGSTOP);
                if std::ptr::read_volatile(at as *const u32) != word as u32 {
                    libc::_exit(9);
                }
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = exit_7 as *const () as usize;
                libc::sigemptyset(&mut act.sa_mask);
                libc::sigaction(libc::SIGSEGV, &act, std::ptr::null_mut());
                std::ptr::write_volatile(at as *mut u32, 0);
                libc::_exit(8);
            }
        }
        let (got, st) = wait_bounded(pid, libc::WUNTRACED);
        let stopped = got == pid && libc::WIFSTOPPED(st);
        let poke = if stopped { ptrace(POKEDATA, pid, at, word) } else { -1 };
        ptrace(CONT, pid, 0, 0);
        // The store's SIGSEGV stops the tracee; it is passed through so that
        // the handler runs and the exit code says what happened.
        let mut code = -1;
        for _ in 0..3 {
            let (got, st) = wait_bounded(pid, 0);
            if got != pid {
                break;
            }
            if libc::WIFSTOPPED(st) {
                ptrace(CONT, pid, 0, libc::WSTOPSIG(st) as u64);
                continue;
            }
            if libc::WIFEXITED(st) {
                code = libc::WEXITSTATUS(st);
            }
            break;
        }
        if code == -1 {
            teardown(pid);
        }
        line(&format!("POKEDATA into {what}"), outcome(poke));
        line("  the tracee's own store to it: exit code", code);
    }

    syscall_stops();
    syscall_stop_signal();
    sigsuspend_passthrough();
}

static GOT_CHLD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_chld(_sig: i32) {
    GOT_CHLD.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// A tracee blocks `SIGCHLD` and waits for it in `sigsuspend`, and the
/// tracer passes it through: the handler runs once, under `sigsuspend`'s
/// mask, and `sigsuspend` returns. What a shell's `wait` does under `strace -f`.
fn sigsuspend_passthrough() {
    println!("## a signal passed through to sigsuspend");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = on_chld as *const () as usize;
            libc::sigaction(libc::SIGCHLD, &act, std::ptr::null_mut());
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGCHLD);
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            libc::ptrace(TRACEME, 0, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
            libc::raise(libc::SIGSTOP);
            if libc::fork() == 0 {
                libc::_exit(0);
            }
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            let r = libc::sigsuspend(&empty);
            let e = *libc::__errno_location();
            libc::_exit(if r == -1 && e == libc::EINTR && GOT_CHLD.load(std::sync::atomic::Ordering::SeqCst) { 0 } else { 1 });
        }
    }
    let mut stops = Vec::new();
    let mut end = "nothing".to_string();
    for _ in 0..10 {
        let (got, st) = wait_bounded(pid, 0);
        if got != pid {
            break;
        }
        if libc::WIFSTOPPED(st) {
            let sig = libc::WSTOPSIG(st);
            stops.push(sig.to_string());
            // Passed through, as strace does; the initial SIGSTOP is not.
            ptrace(CONT, pid, 0, if sig == libc::SIGSTOP { 0 } else { sig as u64 });
        } else {
            end = if libc::WIFEXITED(st) { format!("exited {}", libc::WEXITSTATUS(st)) } else { format!("killed by {}", libc::WTERMSIG(st)) };
            break;
        }
    }
    line("the stops the tracer saw", stops.join(", "));
    line("  and then", &end);
    if end == "nothing" {
        teardown(pid);
    }
}

/// `PTRACE_SYSCALL` from a syscall stop with a signal in `data`: Linux's
/// `ptrace_report_syscall` sends it to the tracee once the stop ends, so
/// the tracer sees it next, in a signal-delivery-stop after the syscall's
/// exit stop.
fn syscall_stop_signal() {
    println!("## a signal passed at a syscall stop");
    let Some(pid) = stopped_child_calling_getpid() else {
        line("a child that stops and then calls getpid", "never stopped");
        return;
    };
    ptrace(SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD as u64);
    ptrace(SYSCALL, pid, 0, 0);
    let (got, st) = wait_bounded(pid, 0);
    line("the first syscall stop", if got == pid && libc::WIFSTOPPED(st) { libc::WSTOPSIG(st) } else { -1 });
    line("SYSCALL with data=SIGUSR1", outcome(ptrace(SYSCALL, pid, 0, libc::SIGUSR1 as u64)));
    let mut seen = Vec::new();
    for _ in 0..3 {
        let (got, st) = wait_bounded(pid, 0);
        if got != pid {
            seen.push("nothing".to_string());
            break;
        }
        if libc::WIFSTOPPED(st) {
            seen.push(format!("stopped {}", libc::WSTOPSIG(st)));
            ptrace(SYSCALL, pid, 0, if libc::WSTOPSIG(st) == libc::SIGUSR1 { libc::SIGUSR1 as u64 } else { 0 });
        } else if libc::WIFSIGNALED(st) {
            seen.push(format!("killed by {}", libc::WTERMSIG(st)));
            break;
        } else {
            seen.push(format!("exited {}", libc::WEXITSTATUS(st)));
            break;
        }
    }
    line("  what the tracer sees next", seen.join(", "));
    teardown(pid);
}

/// `PTRACE_SYSCALL`: stop at every syscall boundary.
///
/// What `strace` and `gdb`'s `catch syscall` are made of. The tracee stops
/// before the syscall runs and again after, and the pair is distinguishable
/// only by counting — which is what `PTRACE_O_TRACESYSGOOD`'s bit in the stop
/// signal exists to make reliable.
fn syscall_stops() {
    println!("## stopping at syscall boundaries");
    let Some(pid) = stopped_child_calling_getpid() else {
        line("a child that stops and then calls getpid", "never stopped");
        return;
    };
    line("SETOPTIONS(TRACESYSGOOD)", outcome(ptrace(SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD as u64)));

    // Walk the boundaries until getpid's pair is seen, or a bound is reached.
    // The child calls a few syscalls before it: the bound is what keeps this
    // from being unbounded on a kernel that never stops.
    let mut stops = 0;
    let mut entry_num = -1i64;
    let mut exit_num = -1i64;
    let mut exit_ret = -1i64;
    let mut sysgood = 0;
    for _ in 0..200 {
        if ptrace(SYSCALL, pid, 0, 0) < 0 {
            break;
        }
        let (got, st) = wait_bounded(pid, 0);
        if got != pid || !libc::WIFSTOPPED(st) {
            break;
        }
        stops += 1;
        if libc::WSTOPSIG(st) == (libc::SIGTRAP | 0x80) {
            sysgood += 1;
        }
        // x8 is the number, x0 the first argument on the way in and the answer
        // on the way out.
        let mut regs = [0u64; 34];
        let mut iov = libc::iovec {
            iov_base: regs.as_mut_ptr().cast(),
            iov_len: std::mem::size_of_val(&regs),
        };
        if ptrace(GETREGSET, pid, NT_PRSTATUS as u64, &mut iov as *mut _ as u64) < 0 {
            break;
        }
        let num = regs[8] as i64;
        if num == SYS_GETPID {
            if entry_num < 0 {
                entry_num = num;
            } else {
                exit_num = num;
                exit_ret = regs[0] as i64;
                break;
            }
        }
    }
    line("  it stopped at least twice", (stops >= 2) as i64);
    line("  every stop is SIGTRAP|0x80", (sysgood == stops && stops > 0) as i64);
    line("  an entry names the syscall", (entry_num == SYS_GETPID) as i64);
    line("  and its exit names the same one", (exit_num == SYS_GETPID) as i64);
    line("  whose answer is the child's pid", (exit_ret == pid as i64) as i64);
    // And CONT from a syscall stop runs free: the next wait is the exit.
    line("CONT from a syscall stop", outcome(ptrace(CONT, pid, 0, 0)));
    let (got, st) = wait_bounded(pid, 0);
    line("  the child then runs to its exit", (got == pid && libc::WIFEXITED(st)) as i64);
    if got != pid {
        teardown(pid);
    }
}

/// `getpid` on aarch64.
const SYS_GETPID: i64 = 172;

/// The same child as `stopped_child`, but it calls `getpid` before exiting so
/// that a syscall boundary has something to name.
fn stopped_child_calling_getpid() -> Option<i32> {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::ptrace(TRACEME, 0, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
            libc::raise(libc::SIGSTOP);
            let me = libc::syscall(libc::SYS_getpid);
            libc::_exit((me & 0x7f) as i32);
        }
    }
    let (got, st) = wait_bounded(pid, libc::WUNTRACED);
    if got == pid && libc::WIFSTOPPED(st) {
        return Some(pid);
    }
    teardown(pid);
    None
}

/// Never called; the text page a poke lands in.
#[inline(never)]
extern "C" fn poke_target() {
    std::hint::black_box(0);
}

extern "C" fn exit_7(_sig: i32) {
    unsafe { libc::_exit(7) };
}
