//! `PTRACE_SETOPTIONS` and the two event stops behind it, and the width of a
//! peek.
//!
//! Written because `strace` did not run. It sets `PTRACE_O_TRACESYSGOOD |
//! PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT` -- 0x51, measured -- in one call
//! and treats an `EINVAL` as fatal: `PTRACE_SETOPTIONS: Invalid argument`, and
//! it detaches. The kernel honoured the first bit and refused the word.
//!
//! The peek checks are here for the defect the fix uncovered: a peek returned
//! **four** bytes, i386's word, so a tracer advancing by `sizeof(long)` read
//! every other half of every string. `strace` printed the first line of
//! `strace /bin/echo hi` as `execve("/bin", ["/bin", "hi"], ...)`.
//!
//! Every check runs against a real kernel through `differential.sh`, which is
//! the only thing that says what an event status is supposed to be.

use guest_tests::{Harness, check};

const PTRACE_TRACEME: i32 = 0;
const PTRACE_PEEKDATA: i32 = 2;
const PTRACE_POKEDATA: i32 = 5;
const PTRACE_CONT: i32 = 7;
const PTRACE_SYSCALL: i32 = 24;
const PTRACE_SETOPTIONS: i32 = 0x4200;
const PTRACE_GETREGSET: i32 = 0x4204;
const NT_PRSTATUS: usize = 1;

/// `struct iovec`, which is how `PTRACE_GETREGSET` is given its buffer.
#[repr(C)]
struct Iovec {
    base: *mut u8,
    len: usize,
}

const PTRACE_O_TRACESYSGOOD: usize = 0x0000_0001;
const PTRACE_O_TRACEEXEC: usize = 0x0000_0010;
const PTRACE_O_TRACEEXIT: usize = 0x0000_0040;
/// The word `strace` sends, and what used to be refused.
const STRACE_OPTIONS: usize = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;

const PTRACE_EVENT_EXEC: i32 = 4;
const PTRACE_EVENT_EXIT: i32 = 6;

/// A word with both halves set, so a four-byte answer cannot pass by accident:
/// the top half is `0x0123_4567` and uninitialised stack is not that.
static PATTERN: u64 = 0x0123_4567_89ab_cdef;

fn ptrace(req: i32, pid: i32, addr: usize, data: usize) -> i64 {
    unsafe { libc::ptrace(req as _, pid, addr, data) as i64 }
}

/// `errno` after a `ptrace` that answered -1.
fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// The event a stop reports, or 0 for a stop that is not one. Linux packs it
/// into the second byte of the signal: `SIGTRAP | (event << 8)`.
fn event_of(status: i32) -> i32 {
    (status >> 16) & 0xff
}

/// The signal a stop reports.
fn stop_sig(status: i32) -> i32 {
    (status >> 8) & 0xff
}

/// Fork a child that puts itself under the tracer and stops, and wait for that
/// first stop. Answers the child's pid.
fn traced_child(body: fn() -> !) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::ptrace(PTRACE_TRACEME as _, 0, 0, 0);
            libc::raise(libc::SIGSTOP);
        }
        body();
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    pid
}

/// aarch64's `execve`.
const NR_EXECVE: u64 = 221;

/// Continue to the next stop with `PTRACE_SYSCALL` and report what it was:
/// the signal, the event in the second byte, and `x8` -- which holds the
/// syscall number at an entry stop. `None` if the tracee did not stop.
fn syscall_step(pid: i32) -> Option<(i32, i32, u64)> {
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    let mut st = 0;
    let w = unsafe { libc::waitpid(pid, &mut st, 0) };
    if w != pid || !libc::WIFSTOPPED(st) {
        return None;
    }
    let mut regs = [0u64; 34];
    let mut iov = Iovec { base: regs.as_mut_ptr().cast(), len: std::mem::size_of_val(&regs) };
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &mut iov as *mut _ as usize);
    Some((stop_sig(st), event_of(st), regs[8]))
}

fn reap(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }
}

fn main() {
    let mut h = Harness::new();
    // Every wait below is one the kernel is supposed to answer; a kernel that
    // does not would otherwise hang the suite rather than fail this test.
    unsafe { libc::alarm(40) };
    // The orphan group's grandchildren are reparented when their tracer dies,
    // and they should land here rather than on init -- so this process can
    // reap them and the suite does not leave processes behind.
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) };

    // ---------------------------------------------------------------- options
    h.group("setoptions");

    let pid = traced_child(|| loop {
        std::hint::black_box(0u64);
    });

    for (name, opts) in [
        ("nothing", 0usize),
        ("TRACESYSGOOD", PTRACE_O_TRACESYSGOOD),
        ("TRACEEXEC", PTRACE_O_TRACEEXEC),
        ("TRACEEXIT", PTRACE_O_TRACEEXIT),
        ("what strace sends", STRACE_OPTIONS),
    ] {
        let r = ptrace(PTRACE_SETOPTIONS, pid, 0, opts);
        check!(h, r == 0, "SETOPTIONS accepts {name} ({opts:#x}): r={r} errno={}", errno());
    }

    // A bit no kernel defines is still refused, which is what keeps a tracer
    // from waiting for an event nothing generates.
    let r = ptrace(PTRACE_SETOPTIONS, pid, 0, 1usize << 30);
    check!(h, r == -1 && errno() == libc::EINVAL,
        "and refuses a bit nothing defines: r={r} errno={}", errno());

    // ------------------------------------------------------------------- peek
    h.group("peek");

    let addr = &raw const PATTERN as usize;
    unsafe { *libc::__errno_location() = 0 };
    let word = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    check!(h, errno() == 0, "PEEKDATA succeeds: errno={}", errno());
    check!(h, word as u64 == PATTERN,
        "and answers a whole word, not i386's half: {:#018x} want {PATTERN:#018x}", word as u64);

    // The other half of the same defect: a four-byte poke left the top of the
    // word as it was, so a debugger writing a breakpoint wrote half of one.
    // The child's copy is written, and read back from the child.
    let want = 0xfedc_ba98_7654_3210u64;
    let r = ptrace(PTRACE_POKEDATA, pid, addr, want as usize);
    check!(h, r == 0, "POKEDATA succeeds: r={r} errno={}", errno());
    unsafe { *libc::__errno_location() = 0 };
    let back = ptrace(PTRACE_PEEKDATA, pid, addr, 0) as u64;
    check!(h, back == want, "and writes a whole word: {back:#018x} want {want:#018x}");
    check!(h, PATTERN == 0x0123_4567_89ab_cdef,
        "the tracer's own copy is untouched: {PATTERN:#018x}");

    // An unmapped address in the tracee is EIO -- the tracee's address space,
    // not the caller's, which is EFAULT.
    unsafe { *libc::__errno_location() = 0 };
    let r = ptrace(PTRACE_PEEKDATA, pid, 0x10, 0);
    check!(h, r == -1 && errno() == libc::EIO,
        "an unmapped tracee address is EIO: r={r} errno={}", errno());

    reap(pid);

    // ------------------------------------------------------------ exec, event
    h.group("exec event");

    let pid = traced_child(|| unsafe {
        let prog = c"/bin/true";
        let argv = [prog.as_ptr(), std::ptr::null()];
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        libc::execve(prog.as_ptr(), argv.as_ptr().cast_mut(), envp.as_ptr().cast_mut());
        libc::_exit(127)
    });
    let r = ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT);
    check!(h, r == 0, "SETOPTIONS on the child about to exec: r={r} errno={}", errno());
    ptrace(PTRACE_CONT, pid, 0, 0);

    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, libc::WIFSTOPPED(st), "the exec stops the tracee: status={st:#x}");
    check!(h, stop_sig(st) == libc::SIGTRAP, "with SIGTRAP: sig={}", stop_sig(st));
    check!(h, event_of(st) == PTRACE_EVENT_EXEC,
        "and PTRACE_EVENT_EXEC in the second byte: event={} status={st:#x}", event_of(st));

    // ------------------------------------------------------------ exit, event
    h.group("exit event");

    ptrace(PTRACE_CONT, pid, 0, 0);
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, libc::WIFSTOPPED(st), "the exit stops the tracee too: status={st:#x}");
    check!(h, event_of(st) == PTRACE_EVENT_EXIT,
        "with PTRACE_EVENT_EXIT: event={} status={st:#x}", event_of(st));

    // And the tracee is still there to be continued: the stop is *before* the
    // exit, which is the whole point of the option. A kernel that reported the
    // event after the fact would fail here rather than above.
    let r = ptrace(PTRACE_CONT, pid, 0, 0);
    check!(h, r == 0, "the tracee is still alive in the exit stop: r={r} errno={}", errno());
    let mut st = 0;
    let w = unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, w == pid && libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
        "and then exits for real: w={w} exited={} code={}",
        libc::WIFEXITED(st), libc::WEXITSTATUS(st));

    // --------------------------------------------------------- where it lands
    h.group("exec event ordering");

    // *Where* the event stop is taken, which is what makes it an event rather
    // than a signal that arrives eventually. Linux takes it inside `execve`,
    // between that syscall's entry and exit stops; the first version of this
    // queued a SIGTRAP instead, so the tracee did not stop until it was back
    // in userspace and the event arrived *after* the exit stop. strace checks
    // exactly this and said so: `Stray PTRACE_EVENT_EXEC from pid 6, trying to
    // recover...`. Nothing else here would have noticed -- the event is
    // reported either way.
    let pid = traced_child(|| unsafe {
        let prog = c"/bin/true";
        let argv = [prog.as_ptr(), std::ptr::null()];
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        libc::execve(prog.as_ptr(), argv.as_ptr().cast_mut(), envp.as_ptr().cast_mut());
        libc::_exit(127)
    });
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC);

    // Step to the syscall-entry stop of the execve itself: SIGTRAP|0x80 with
    // the number still in x8. There are a handful of stops before it, from
    // whatever `raise` did.
    let mut at_execve_entry = false;
    for _ in 0..12 {
        let Some((sig, ev, nr)) = syscall_step(pid) else { break };
        if sig == libc::SIGTRAP | 0x80 && ev == 0 && nr == NR_EXECVE {
            at_execve_entry = true;
            break;
        }
    }
    check!(h, at_execve_entry, "stepped to execve's syscall-entry stop");

    let next = syscall_step(pid);
    check!(h, next.map(|(s, e, _)| (s, e)) == Some((libc::SIGTRAP, PTRACE_EVENT_EXEC)),
        "the very next stop is the exec event, before execve's exit stop: {next:?}");
    let after = syscall_step(pid);
    check!(h, after.map(|(s, e, _)| (s, e)) == Some((libc::SIGTRAP | 0x80, 0)),
        "and execve's syscall-exit stop is the one after that: {after:?}");

    reap(pid);

    // --------------------------------------------------- no option, no event
    h.group("without the option");

    // A tracer that sets nothing sees the exec as a bare SIGTRAP, which is
    // what a debugger has always seen here and what must not change.
    let pid = traced_child(|| unsafe {
        let prog = c"/bin/true";
        let argv = [prog.as_ptr(), std::ptr::null()];
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        libc::execve(prog.as_ptr(), argv.as_ptr().cast_mut(), envp.as_ptr().cast_mut());
        libc::_exit(127)
    });
    ptrace(PTRACE_CONT, pid, 0, 0);
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, libc::WIFSTOPPED(st) && stop_sig(st) == libc::SIGTRAP,
        "the exec is still a SIGTRAP without the option: status={st:#x}");
    check!(h, event_of(st) == 0, "and carries no event: event={}", event_of(st));

    // And no exit stop either: continuing runs it to completion.
    ptrace(PTRACE_CONT, pid, 0, 0);
    let mut st = 0;
    let w = unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, w == pid && libc::WIFEXITED(st),
        "and exits without stopping again: w={w} status={st:#x}");

    // ------------------------------------------- a tracer that exits holding one
    h.group("orphaned tracee");

    // Linux's `exit_ptrace`: a tracer that leaves detaches its tracees, so one
    // parked in a ptrace stop is not left waiting for a continue that cannot
    // come. Two of these three hung here -- for two different reasons, each of
    // which had to be found separately.
    for stop in [Stop::Signal, Stop::Syscall, Stop::Running] {
        let resumed = orphan_case(stop);
        check!(h, resumed, "a tracee in {} resumes when its tracer exits", stop.name());
    }
    // Anything reparented onto this process, so the suite's next test does not
    // inherit it.
    unsafe {
        let mut st = 0;
        while libc::waitpid(-1, &mut st, libc::WNOHANG) > 0 {}
    }

    std::process::exit(h.finish());
}

/// Which stop the tracee is in when its tracer dies. The three differ in which
/// wait the tracee is parked on, and the fix needed two parts because of it:
/// the detach itself, and the dispatcher's *exit* half of a syscall stop, which
/// is taken on the entry's answer and so stopped an already-detached tracee one
/// step further along.
#[derive(Clone, Copy)]
enum Stop {
    Signal,
    Syscall,
    Running,
}

impl Stop {
    fn name(self) -> &'static str {
        match self {
            Stop::Signal => "signal-delivery-stop",
            Stop::Syscall => "syscall-stop",
            Stop::Running => "no stop",
        }
    }
}

/// Fork a tracer, which forks a tracee, parks it in `stop`, and `_exit`s
/// holding it. Answers whether the tracee got going again.
///
/// The tracee writes a byte to a pipe once it is past the stop, so "did it
/// resume" is a `poll` with a timeout rather than a guess -- and a kernel that
/// leaves it parked answers `false` instead of hanging the suite.
fn orphan_case(stop: Stop) -> bool {
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let (rd, wr) = (fds[0], fds[1]);

    let tracer = unsafe { libc::fork() };
    if tracer == 0 {
        unsafe { libc::close(rd) };
        let tracee = unsafe { libc::fork() };
        if tracee == 0 {
            unsafe {
                libc::ptrace(PTRACE_TRACEME as _, 0, 0, 0);
                libc::raise(libc::SIGSTOP);
                let b = b"r";
                libc::write(wr, b.as_ptr().cast(), 1);
                libc::_exit(0);
            }
        }
        unsafe {
            let mut st = 0;
            libc::waitpid(tracee, &mut st, 0);
            match stop {
                Stop::Signal => {}
                Stop::Syscall => {
                    // Past the SIGSTOP and parked at the next syscall boundary,
                    // which is the `write` above.
                    ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_TRACESYSGOOD);
                    ptrace(PTRACE_SYSCALL, tracee, 0, 0);
                    let mut st = 0;
                    libc::waitpid(tracee, &mut st, 0);
                }
                Stop::Running => {
                    ptrace(PTRACE_CONT, tracee, 0, 0);
                    libc::usleep(100_000);
                }
            }
            libc::_exit(0);
        }
    }

    unsafe { libc::close(wr) };
    let mut st = 0;
    unsafe { libc::waitpid(tracer, &mut st, 0) };

    let mut pfd = libc::pollfd { fd: rd, events: libc::POLLIN, revents: 0 };
    let n = unsafe { libc::poll(&mut pfd, 1, 2000) };
    let mut byte = [0u8; 1];
    let got = n > 0 && unsafe { libc::read(rd, byte.as_mut_ptr().cast(), 1) } == 1;
    unsafe { libc::close(rd) };
    got
}
