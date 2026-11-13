//! `ptrace(2)` from a tracer that did not start its tracee: `PTRACE_ATTACH`,
//! `PTRACE_SEIZE` and `PTRACE_INTERRUPT`, a tracer that is not the parent, and
//! the tracees a fork, a vfork and a thread bring with them -- what `gdb -p`
//! and `strace -f` are made of. `ptrace_probe` is the `PTRACE_TRACEME` half.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Every wait is a bounded poll and every case kills what it made. What two
//! tasks report is printed per task, in the order that task reported it: the
//! order *between* a new child's first stop and its parent's event stop is not
//! fixed on Linux either. No pid is printed, only whose it was.

use std::ffi::c_void;

const TRACEME: i32 = 0;
const CONT: i32 = 7;
const ATTACH: i32 = 16;
const DETACH: i32 = 17;
const SETOPTIONS: i32 = 0x4200;
const GETEVENTMSG: i32 = 0x4201;
const GETSIGINFO: i32 = 0x4202;
const SEIZE: i32 = 0x4206;
const INTERRUPT: i32 = 0x4207;

const O_TRACESYSGOOD: u64 = 1;
const O_TRACEFORK: u64 = 2;
const O_TRACEVFORK: u64 = 4;
const O_TRACECLONE: u64 = 8;
const O_TRACEVFORKDONE: u64 = 0x20;
const O_EXITKILL: u64 = 0x10_0000;

const WALL: i32 = 0x4000_0000;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<56} -> {value}");
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EPERM => "EPERM".into(),
        libc::ESRCH => "ESRCH".into(),
        libc::EIO => "EIO".into(),
        libc::EINVAL => "EINVAL".into(),
        libc::ECHILD => "ECHILD".into(),
        libc::EFAULT => "EFAULT".into(),
        e => format!("errno {e}"),
    }
}

fn ptrace(req: i32, pid: i32, addr: u64, data: u64) -> i64 {
    unsafe {
        *libc::__errno_location() = 0;
        libc::ptrace(req, pid, addr as *mut c_void, data as *mut c_void) as i64
    }
}

fn rc(r: i64) -> String {
    if r < 0 { named(errno()) } else { "ok".into() }
}

/// `waitpid`, polled for about two seconds. `(0, 0)` if nothing came.
fn wait_bounded(pid: i32, opts: i32) -> (i32, i32) {
    for _ in 0..2000 {
        let mut st = 0;
        let r = unsafe { libc::waitpid(pid, &mut st, opts | libc::WNOHANG) };
        if r != 0 {
            return (r, if r < 0 { -errno() } else { st });
        }
        unsafe { libc::usleep(1000) };
    }
    (0, 0)
}

fn status(r: i32, st: i32) -> String {
    if r == 0 {
        return "nothing".into();
    }
    if r < 0 {
        return named(-st);
    }
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
        format!("status {st:#x}")
    }
}

fn wait_once(pid: i32, opts: i32) -> String {
    let (r, st) = wait_bounded(pid, opts);
    status(r, st)
}

fn sigstop_info(pid: i32) -> String {
    let mut info = [0i32; 32];
    let r = ptrace(GETSIGINFO, pid, 0, info.as_mut_ptr() as u64);
    if r < 0 { named(errno()) } else { format!("signo {} code {:#x}", info[0], info[2]) }
}

fn eventmsg(pid: i32) -> Option<u64> {
    let mut msg = 0u64;
    (ptrace(GETEVENTMSG, pid, 0, &raw mut msg as u64) == 0).then_some(msg)
}

fn kill_and_reap(pid: i32) {
    unsafe { libc::kill(pid, libc::SIGKILL) };
    ptrace(CONT, pid, 0, 0);
    wait_bounded(pid, WALL);
}

/// A child blocked reading the pipe whose write end is returned; closing it
/// makes the child exit with `code`.
fn blocked_child(code: i32) -> (i32, i32) {
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(p[1]);
            let mut b = [0u8; 1];
            while libc::read(p[0], b.as_mut_ptr().cast(), 1) != 0 {}
            libc::_exit(code);
        }
    }
    unsafe { libc::close(p[0]) };
    (pid, p[1])
}

fn attach_own_child() {
    let (pid, w) = blocked_child(3);
    unsafe { libc::usleep(20_000) };
    line("ATTACH to a running child", rc(ptrace(ATTACH, pid, 0, 0)));
    line("  what wait then reports", wait_once(pid, 0));
    line("  GETSIGINFO of that stop", sigstop_info(pid));
    line("  its TracerPid is this process", tracer_pid(pid) == unsafe { libc::getpid() }.to_string());
    line("  ATTACH again", rc(ptrace(ATTACH, pid, 0, 0)));
    line("  SEIZE while attached", rc(ptrace(SEIZE, pid, 0, 0)));
    line("  INTERRUPT of a tracee that was not seized", rc(ptrace(INTERRUPT, pid, 0, 0)));
    line("  DETACH", rc(ptrace(DETACH, pid, 0, 0)));
    line("  wait after DETACH, WNOHANG", wait_once_nohang(pid));
    line("  its TracerPid after DETACH", tracer_pid(pid));
    unsafe { libc::close(w) };
    line("  its exit, reported to the parent", wait_once(pid, 0));
}

fn tracer_pid(pid: i32) -> String {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    status.lines().find_map(|l| l.strip_prefix("TracerPid:")).map_or("?".into(), |v| v.trim().to_string())
}

fn wait_once_nohang(pid: i32) -> String {
    let mut st = 0;
    let r = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG | WALL) };
    status(r, if r < 0 { -errno() } else { st })
}

fn attach_refusals() {
    line("ATTACH to itself", rc(ptrace(ATTACH, unsafe { libc::getpid() }, 0, 0)));
    line("ATTACH to a pid nobody has", rc(ptrace(ATTACH, 999_999, 0, 0)));
    line("SEIZE to a pid nobody has", rc(ptrace(SEIZE, 999_999, 0, 0)));
    let (pid, w) = blocked_child(0);
    line("SEIZE with addr not 0", rc(ptrace(SEIZE, pid, 1, 0)));
    line("SEIZE with an option nobody has", rc(ptrace(SEIZE, pid, 0, 1 << 30)));
    line("CONT of a child nobody traces", rc(ptrace(CONT, pid, 0, 0)));
    line("INTERRUPT of a child nobody traces", rc(ptrace(INTERRUPT, pid, 0, 0)));
    unsafe { libc::close(w) };
    wait_bounded(pid, 0);
}

/// Who may attach: `ptrace_may_access(ATTACH_REALCREDS)`. Each target runs
/// as `target_uid`, optionally not dumpable; the attacher is a sibling
/// running as uid 1000.
fn attach_permission() {
    for (name, target_uid, dumpable) in [
        ("uid 1000 attaches a root process", 0u32, true),
        ("uid 1000 attaches a uid 1000 process", 1000, true),
        ("uid 1000 attaches a uid 1000 process, not dumpable", 1000, false),
    ] {
        let mut p = [0i32; 2];
        unsafe { libc::pipe(p.as_mut_ptr()) };
        let target = unsafe { libc::fork() };
        if target == 0 {
            unsafe {
                libc::close(p[1]);
                if target_uid != 0 {
                    libc::syscall(libc::SYS_setresgid, target_uid, target_uid, target_uid);
                    libc::syscall(libc::SYS_setresuid, target_uid, target_uid, target_uid);
                }
                // Explicitly either way: a uid change clears it, which would
                // make every case here the not-dumpable one.
                libc::prctl(libc::PR_SET_DUMPABLE, dumpable as libc::c_ulong, 0, 0, 0);
                let mut b = [0u8; 1];
                while libc::read(p[0], b.as_mut_ptr().cast(), 1) != 0 {}
                libc::_exit(0);
            }
        }
        unsafe { libc::close(p[0]) };
        unsafe { libc::usleep(30_000) };
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let tracer = unsafe { libc::fork() };
        if tracer == 0 {
            unsafe {
                libc::syscall(libc::SYS_setresgid, 1000, 1000, 1000);
                libc::syscall(libc::SYS_setresuid, 1000, 1000, 1000);
            }
            let r = rc(ptrace(SEIZE, target, 0, 0));
            line(name, r);
            let _ = std::io::Write::flush(&mut std::io::stdout());
            unsafe { libc::_exit(0) };
        }
        wait_bounded(tracer, 0);
        unsafe { libc::close(p[1]) };
        wait_bounded(target, 0);
    }
}

/// `R` attaches `T`, which is its sibling: the tracer is not the parent.
fn tracer_not_parent() {
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let target = unsafe { libc::fork() };
    if target == 0 {
        unsafe {
            libc::close(p[1]);
            let mut b = [0u8; 1];
            while libc::read(p[0], b.as_mut_ptr().cast(), 1) != 0 {}
            libc::_exit(3);
        }
    }
    unsafe { libc::close(p[0]) };
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let tracer = unsafe { libc::fork() };
    if tracer == 0 {
        let before = wait_once_nohang(-1);
        line("sibling: wait(-1) before attaching", before);
        line("sibling: ATTACH", rc(ptrace(ATTACH, target, 0, 0)));
        let (r, st) = wait_bounded(-1, 0);
        line("sibling: wait(-1) reports", format!("{} {}", if r == target { "the target" } else { "something else" }, status(r, st)));
        line("sibling: CONT", rc(ptrace(CONT, target, 0, 0)));
        unsafe { libc::close(p[1]) };
        line("sibling: the target's exit, as its tracer", wait_once(target, 0));
        line("sibling: wait again", wait_once_nohang(target));
        let _ = std::io::Write::flush(&mut std::io::stdout());
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(p[1]) };
    line("parent: the tracer's exit", wait_once(tracer, 0));
    line("parent: the target's exit, as its parent", wait_once(target, 0));
}

/// A tracer exits with its sibling attached and stopped: the tracee runs on.
fn tracer_exits_attached() {
    let (target, w) = blocked_child(4);
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let tracer = unsafe { libc::fork() };
    if tracer == 0 {
        ptrace(ATTACH, target, 0, 0);
        wait_bounded(target, 0);
        unsafe { libc::_exit(0) };
    }
    wait_bounded(tracer, 0);
    unsafe { libc::close(w) };
    line("tracer exits with its tracee stopped: the tracee's exit", wait_once(target, 0));
}

fn seize() {
    let (pid, w) = blocked_child(5);
    unsafe { libc::usleep(20_000) };
    line("SEIZE with TRACESYSGOOD", rc(ptrace(SEIZE, pid, 0, O_TRACESYSGOOD)));
    line("  wait, WNOHANG: a seize does not stop it", wait_once_nohang(pid));
    line("  CONT of a running seized tracee", rc(ptrace(CONT, pid, 0, 0)));
    line("  INTERRUPT", rc(ptrace(INTERRUPT, pid, 0, 0)));
    line("  what wait then reports", wait_once(pid, 0));
    line("  GETSIGINFO of that stop", sigstop_info(pid));
    line("  CONT", rc(ptrace(CONT, pid, 0, 0)));
    line("  wait, WNOHANG, after CONT", wait_once_nohang(pid));
    unsafe { libc::close(w) };
    line("  its exit", wait_once(pid, 0));
}

/// A traced child that stops for its tracer, then runs `body`.
fn traced_child(body: impl FnOnce() -> i32) -> Option<i32> {
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::ptrace(TRACEME, 0, std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
            libc::raise(libc::SIGSTOP);
            libc::_exit(body());
        }
    }
    let (r, st) = wait_bounded(pid, 0);
    if r == pid && libc::WIFSTOPPED(st) {
        Some(pid)
    } else {
        kill_and_reap(pid);
        None
    }
}

/// Follow a tracee and everything it brings in until it exits, continuing
/// each stop. Prints what each task reported, the leader first.
///
/// A thread's exit code is not printed: Linux reports the group's when the
/// leader's `exit_group` came before the tracer's wait, and the thread's own
/// otherwise (`wait_task_zombie`), which is a race between the two.
fn follow(name: &str, leader: i32, options: u64, thread: bool) {
    line(&format!("{name}: SETOPTIONS"), rc(ptrace(SETOPTIONS, leader, 0, options)));
    ptrace(CONT, leader, 0, 0);
    let mut leader_log = Vec::new();
    let mut other: Option<i32> = None;
    let mut other_log = Vec::new();
    let mut msgs = Vec::new();
    let mut first_info = None;
    let mut extra = 0;
    for _ in 0..20 {
        let (r, st) = wait_bounded(-1, WALL);
        if r <= 0 {
            leader_log.push(status(r, st));
            break;
        }
        let what = status(r, st);
        if libc::WIFSTOPPED(st) && st >> 16 != 0 {
            msgs.push(eventmsg(r));
            if first_info.is_none() {
                first_info = Some(event_info(r));
            }
        }
        if r == leader {
            leader_log.push(what);
        } else if other.is_none_or(|o| o == r) {
            other = Some(r);
            other_log.push(if thread && libc::WIFEXITED(st) { "exited".into() } else { what });
        } else {
            extra += 1;
        }
        if libc::WIFSTOPPED(st) {
            ptrace(CONT, r, 0, 0);
        } else if r == leader {
            break;
        }
    }
    // The new task's report and its exit may come after the leader's exit.
    if let Some(o) = other {
        if !other_log.iter().any(|s| s.starts_with("exited") || s.starts_with("killed")) {
            let (r, st) = wait_bounded(o, WALL);
            other_log.push(if thread && r > 0 && libc::WIFEXITED(st) { "exited".into() } else { status(r, st) });
        }
    }
    line(&format!("{name}: the traced task reported"), leader_log.join(", "));
    line(&format!("{name}: the new task reported"), if other_log.is_empty() { "nothing".into() } else { other_log.join(", ") });
    let named_it: Vec<String> = msgs
        .iter()
        .map(|m| match (m, other) {
            (Some(m), Some(o)) if *m == o as u64 => "the new task".into(),
            (Some(0), _) => "0".into(),
            (Some(_), _) => "something else".into(),
            (None, _) => "GETEVENTMSG failed".into(),
        })
        .collect();
    line(&format!("{name}: GETEVENTMSG at each event"), named_it.join(", "));
    line(&format!("{name}: reports from a third task"), extra);
    if let Some(info) = first_info {
        line(&format!("{name}: GETSIGINFO at the first event"), info);
    }
}

/// `si_signo`, `si_code`, and whether `si_pid` is the stopped task.
fn event_info(pid: i32) -> String {
    let mut info = [0i32; 32];
    if ptrace(GETSIGINFO, pid, 0, info.as_mut_ptr() as u64) < 0 {
        return named(errno());
    }
    format!("signo {} code {:#x} pid is the tracee {}", info[0], info[2], info[4] == pid)
}

fn fork_events() {
    if let Some(c) = traced_child(|| unsafe {
        let g = libc::fork();
        if g == 0 {
            libc::_exit(5);
        }
        let mut st = 0;
        libc::waitpid(g, &mut st, 0);
        if libc::WEXITSTATUS(st) == 5 { 6 } else { 1 }
    }) {
        follow("TRACEFORK", c, O_TRACEFORK, false);
    }
    if let Some(c) = traced_child(|| unsafe {
        let g = libc::fork();
        if g == 0 {
            libc::_exit(5);
        }
        libc::waitpid(g, std::ptr::null_mut(), 0);
        6
    }) {
        follow("fork without TRACEFORK", c, 0, false);
    }
    if let Some(c) = traced_child(|| unsafe {
        // `libc::vfork` is deprecated because a Rust caller can corrupt
        // the shared stack; the child here only calls `_exit`.
        #[allow(deprecated)]
        let v = libc::vfork();
        if v == 0 {
            libc::_exit(8);
        }
        libc::waitpid(v, std::ptr::null_mut(), 0);
        9
    }) {
        follow("TRACEVFORK|TRACEVFORKDONE", c, O_TRACEVFORK | O_TRACEVFORKDONE, false);
    }
    if let Some(c) = traced_child(|| {
        let t = std::thread::spawn(|| ());
        let _ = t.join();
        7
    }) {
        follow("TRACECLONE, a thread", c, O_TRACECLONE, true);
    }
}

/// A seized tracee forks: the new task's first stop is a trap, not SIGSTOP.
fn seized_fork() {
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::close(p[1]);
            let mut b = [0u8; 1];
            libc::read(p[0], b.as_mut_ptr().cast(), 1);
            let g = libc::fork();
            if g == 0 {
                libc::_exit(5);
            }
            libc::waitpid(g, std::ptr::null_mut(), 0);
            libc::_exit(6);
        }
    }
    unsafe { libc::close(p[0]) };
    unsafe { libc::usleep(20_000) };
    line("SEIZE with TRACEFORK", rc(ptrace(SEIZE, child, 0, O_TRACEFORK)));
    unsafe { libc::write(p[1], b"x".as_ptr().cast(), 1) };
    let mut mine = Vec::new();
    let mut new = Vec::new();
    for _ in 0..12 {
        let (r, st) = wait_bounded(-1, WALL);
        if r <= 0 {
            break;
        }
        if r == child { mine.push(status(r, st)) } else { new.push(status(r, st)) }
        if libc::WIFSTOPPED(st) {
            ptrace(CONT, r, 0, 0);
        } else if r == child {
            break;
        }
    }
    line("  the seized task reported", mine.join(", "));
    line("  the task it forked reported", new.join(", "));
    unsafe { libc::close(p[1]) };
}

/// A tracer that set EXITKILL exits: its tracee is killed.
fn exitkill_on_exit() {
    let (target, w) = blocked_child(0);
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let tracer = unsafe { libc::fork() };
    if tracer == 0 {
        line("EXITKILL tracer: SEIZE", rc(ptrace(SEIZE, target, 0, O_EXITKILL)));
        let _ = std::io::Write::flush(&mut std::io::stdout());
        unsafe { libc::_exit(0) };
    }
    wait_bounded(tracer, 0);
    line("tracer with EXITKILL exits: the tracee", wait_once(target, 0));
    unsafe { libc::close(w) };
    wait_bounded(target, 0);
}

/// The exit event's message is the exit status.
fn exit_event() {
    const O_TRACEEXIT: u64 = 0x40;
    let Some(c) = traced_child(|| 3) else {
        return;
    };
    ptrace(SETOPTIONS, c, 0, O_TRACEEXIT);
    ptrace(CONT, c, 0, 0);
    line("TRACEEXIT: the stop", wait_once(c, 0));
    line("  GETEVENTMSG", eventmsg(c).map_or("failed".into(), |m| format!("{m:#x}")));
    line("  GETSIGINFO", event_info(c));
    ptrace(CONT, c, 0, 0);
    line("  then", wait_once(c, 0));
}

const LISTEN: i32 = 0x4208;

/// Every report the tracer gets for `pid` until none comes for half a
/// second, continuing nothing.
fn drain(pid: i32) -> String {
    let mut seen = Vec::new();
    for _ in 0..4 {
        let mut got = None;
        for _ in 0..500 {
            let mut st = 0;
            let r = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG | WALL) };
            if r != 0 {
                got = Some(status(r, if r < 0 { -errno() } else { st }));
                break;
            }
            unsafe { libc::usleep(1000) };
        }
        match got {
            Some(s) => seen.push(s),
            None => break,
        }
    }
    if seen.is_empty() { "nothing".into() } else { seen.join(", ") }
}

/// A group stop of a tracee: Linux's `do_signal_stop` for a ptraced task
/// takes a ptrace stop, which the tracer must end, and a seized one can be
/// left listening for the SIGCONT.
fn group_stops() {
    for seize in [false, true] {
        let name = if seize { "seized" } else { "attached" };
        let (pid, w) = blocked_child(0);
        unsafe { libc::usleep(20_000) };
        if seize {
            ptrace(SEIZE, pid, 0, 0);
        } else {
            ptrace(ATTACH, pid, 0, 0);
            wait_bounded(pid, 0);
            ptrace(CONT, pid, 0, 0);
        }
        unsafe { libc::kill(pid, libc::SIGSTOP) };
        line(&format!("{name}: SIGSTOP, the tracer sees"), wait_once(pid, 0));
        line(&format!("{name}:   CONT with SIGSTOP"), rc(ptrace(CONT, pid, 0, libc::SIGSTOP as u64)));
        line(&format!("{name}:   then the tracer sees"), wait_once(pid, 0));
        line(&format!("{name}:   GETSIGINFO in that stop"), sigstop_info(pid));
        line(&format!("{name}:   its state"), proc_state(pid));
        if seize {
            line(&format!("{name}:   LISTEN"), rc(ptrace(LISTEN, pid, 0, 0)));
            line(&format!("{name}:   wait, WNOHANG, listening"), wait_once_nohang(pid));
            line(&format!("{name}:   its state, listening"), proc_state(pid));
            line(&format!("{name}:   CONT while listening"), rc(ptrace(CONT, pid, 0, 0)));
            unsafe { libc::kill(pid, libc::SIGCONT) };
            line(&format!("{name}:   SIGCONT, the tracer sees"), wait_once(pid, 0));
            line(&format!("{name}:   GETSIGINFO in that stop"), sigstop_info(pid));
            line(&format!("{name}:   CONT"), rc(ptrace(CONT, pid, 0, 0)));
            line(&format!("{name}:   then"), drain(pid));
        } else {
            line(&format!("{name}:   LISTEN, not seized"), rc(ptrace(LISTEN, pid, 0, 0)));
            line(&format!("{name}:   CONT"), rc(ptrace(CONT, pid, 0, 0)));
            line(&format!("{name}:   its state after CONT"), proc_state(pid));
            line(&format!("{name}:   then"), drain(pid));
        }
        unsafe { libc::close(w) };
        kill_and_reap(pid);
    }
}

/// Attaching to a process its parent already stopped.
fn attach_stopped() {
    for seize in [false, true] {
        let name = if seize { "SEIZE a stopped child" } else { "ATTACH a stopped child" };
        let (pid, w) = blocked_child(0);
        unsafe { libc::usleep(20_000) };
        unsafe { libc::kill(pid, libc::SIGSTOP) };
        let (r, st) = wait_bounded(pid, libc::WUNTRACED);
        line(&format!("{name}: the parent saw"), status(r, st));
        line(name, rc(ptrace(if seize { SEIZE } else { ATTACH }, pid, 0, 0)));
        line(&format!("{name}: then"), drain(pid));
        if seize {
            line(&format!("{name}: INTERRUPT"), rc(ptrace(INTERRUPT, pid, 0, 0)));
            line(&format!("{name}: then"), drain(pid));
            // strace -p's sequence: the interrupt is spent by the group stop
            // it found, so listening does not trap again at once.
            line(&format!("{name}: LISTEN"), rc(ptrace(LISTEN, pid, 0, 0)));
            line(&format!("{name}: then, listening"), drain(pid));
            unsafe { libc::kill(pid, libc::SIGCONT) };
            line(&format!("{name}: SIGCONT, then"), drain(pid));
            unsafe { libc::kill(pid, libc::SIGSTOP) };
            line(&format!("{name}: CONT, SIGSTOP, then"), {
                ptrace(CONT, pid, 0, 0);
                drain(pid)
            });
        }
        line(&format!("{name}: CONT"), rc(ptrace(CONT, pid, 0, 0)));
        line(&format!("{name}: its state after CONT"), proc_state(pid));
        line(&format!("{name}: then"), drain(pid));
        unsafe { libc::close(w) };
        kill_and_reap(pid);
    }
}

fn proc_state(pid: i32) -> String {
    unsafe { libc::usleep(20_000) };
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    s.rsplit_once(") ").and_then(|(_, r)| r.chars().next()).map_or("?".into(), |c| c.to_string())
}

fn exitkill() {
    let Some(c) = traced_child(|| unsafe {
        libc::pause();
        0
    }) else {
        return;
    };
    line("SETOPTIONS(EXITKILL)", rc(ptrace(SETOPTIONS, c, 0, O_EXITKILL)));
    kill_and_reap(c);
}

fn main() {
    attach_own_child();
    attach_refusals();
    attach_permission();
    tracer_not_parent();
    tracer_exits_attached();
    seize();
    fork_events();
    seized_fork();
    exitkill_on_exit();
    exit_event();
    group_stops();
    attach_stopped();
    exitkill();
}
