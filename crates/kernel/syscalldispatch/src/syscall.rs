//! Syscall dispatch hot path and post-syscall bookkeeping.

use super::*;

/// One guest system call.
///
/// # Safety
/// Called on a guest thread; `cpu` is its own.
#[inline(always)]
pub(super) unsafe fn do_syscall(task: *mut ffi::task, cpu: *mut ffi::cpu_state) {
    // Nothing at all when signposts are compiled out: `signpost::enabled` is a
    // `const fn` over a `cfg`, so this whole binding folds away. The C could
    // not do that from another translation unit and paid a load and a branch
    // per syscall to come close.
    let _interval = signpost::enabled()
        .then(|| signpost::Interval::begin(signpost::Category::Syscall, c"syscall"));
    // aarch64: the number is in x8, the arguments in x0..x5, the answer in x0.
    let regs = unsafe { &raw mut (*cpu).regs };

    // The tracer's stop *before* the syscall, for a tracee that asked for it
    // with PTRACE_SYSCALL. The question is two relaxed atomic loads behind a
    // null check on a field this function already has -- a task nothing traces
    // pays a not-taken branch, which is the same shape as the signpost gate
    // two lines up and was measured the same way.
    //
    // The number a tracer may change is not x8 but arm64's `syscallno`,
    // which `NT_ARM_SYSTEM_CALL` reads and writes: it is set from x8 before
    // the stop and read back after, and a tracer writing x8 changes nothing.
    // This read x8 after the stop until 2026-11-13, on the belief that
    // `strace -e inject` and gdb's `set $x8` work that way; on arm64 they do
    // not (`seccomptrace_probe`). -1 skips the call with `-ENOSYS`.
    // `Ptrace` is this crate's dependency rather than a C call, so the two
    // relaxed atomic loads inline: every task has a ptrace state whether or
    // not anything traces it, so a null check alone would not short-circuit
    // and a call would be on every syscall in the system.
    let ptrace = unsafe { (*task).ptrace.as_deref() };
    let stopping = ptrace.is_some_and(|p| p.stops_at_syscalls());
    let mut num = unsafe { (*regs)[8] } as u32;
    if stopping && let Some(p) = ptrace {
        p.set_syscallno(num as i32);
        unsafe { signaldeliver::receive::ptrace_syscall_boundary() };
        num = p.syscallno() as u32;
        if num == u32::MAX {
            unsafe { (*regs)[0] = ENOSYS as i64 as u64 };
            exit_stop(ptrace);
            p.set_syscallno(-1);
            after_syscall(num);
            return;
        }
    }

    // A snapshot for a restart: x0 is about to be clobbered by the return
    // value, so save it, and classify the call from its number and arguments
    // while the arguments are still there. Which class it is -- Linux's
    // ERESTARTSYS, ERESTARTNOHAND or neither -- is
    // crates/kernel/syscallrestart's, and it is argument-dependent because a
    // deadline is an argument.
    //
    // The svc gadget has already advanced cpu.pc past the svc. Recorded so the
    // rewind can check the pc is still exactly here -- that the signal really
    // is for *this* interrupted syscall -- before stepping back over it. This
    // also disarms: whatever was interrupted before, it is not this.
    unsafe {
        let args = std::array::from_fn(|i| (*regs)[i]);
        (*(*task).restart.get()).entered((*cpu).pc, num as u64, &args);
        // What `/proc/<pid>/syscall` reports while this runs; cleared in
        // `after_syscall`, once the task is known to be still there.
        (*task).syscall.enter(num as u64, &args, (*cpu).sp, (*cpu).pc);
    }

    // Seccomp, after the tracer's entry stop and before the call, which is
    // Linux's order. One acquire load and a not-taken branch for a task with
    // no filter -- the ptrace gate's shape above.
    let mode = unsafe { (*task).seccomp.mode() };
    let asked = num;
    if mode != kernel_seccomp::MODE_DISABLED && !unsafe { seccomp_permits(task, cpu, regs, &mut num, mode, false) } {
        // The filter answered for the call: x0 holds what it said, or what
        // the guest passed in for a trap. The exit stop and the bookkeeping
        // still happen, as they do on Linux for a skipped call.
        exit_stop(ptrace);
        after_syscall(num);
        return;
    }

    // A tracer at a seccomp stop made it another call: classified afresh.
    if num != asked {
        unsafe {
            let args = std::array::from_fn(|i| (*regs)[i]);
            (*(*task).restart.get()).entered((*cpu).pc, num as u64, &args);
        }
    }

    match syscall_at(num as usize) {
        None => {
            // Reported only inside the table: a number past every one Linux
            // assigns is `ENOSYS` there too and says nothing. strace skips an
            // injected call by making it 65535 (`(uint16_t)-1` through
            // `NT_ARM_SYSTEM_CALL`), and the line landed in its output.
            if (num as usize) < syscalltable::SYSCALL_TABLE_SIZE && report_once(num) {
                printk(&format!("{} missing syscall {num}", pid_and_comm()));
            }
            unsafe { (*regs)[0] = ENOSYS as i64 as u64 };
        }
        Some(f) => {
            // Asked of the *number*, not of the function it points at: two
            // stubs with the same body are one address after a release link.
            if syscalltable::REPORTED_STUB[num as usize] && report_once(num) {
                printk(&format!("{} stub syscall {num}", pid_and_comm()));
            }
            unsafe { run(f, num, regs) };
        }
    }

    // And the stop *after* it, with the answer already in x0 -- which is what
    // the tracer reads on the exit half.
    exit_stop(ptrace);

    after_syscall(num);
    // `_interval` ends here, on the way out.
}

/// The syscall-exit stop, asked **now**: Linux's `syscall_exit_work` reads the
/// tracer's last word, so a `PTRACE_CONT` from the entry stop runs free
/// through the exit. It was the entry's answer until 2026-11-13, which
/// stopped a tracee continued with `PTRACE_CONT` again at the exit
/// (`seccomptrace_probe`'s entry-stop cases); a detached tracee answers no
/// either way.
#[inline(always)]
fn exit_stop(ptrace: Option<&ffi::ptrace_state>) {
    match ptrace {
        Some(p) if p.stops_at_syscalls() => unsafe { signaldeliver::receive::ptrace_syscall_boundary() },
        // An entry stop with no exit stop after it: the next boundary is an
        // entry again, not this call's exit.
        Some(p) if p.is_traced() => p.leave_syscall_pairing(),
        _ => {}
    }
}

/// Whether the calling task's seccomp state lets syscall `num` run. When it
/// does not, the answer is already in `x0` -- or the task is gone, for the
/// two kill actions and for strict mode, which do not return.
///
/// `num` may change: a tracer at a `SECCOMP_RET_TRACE` stop can make it
/// another call, which the filter is asked about again (`recheck`), and a
/// `TRACE` the second time is let through -- Linux's `__seccomp_filter`
/// with `recheck_after_trace`.
///
/// # Safety
/// As [`do_syscall`]: on the guest thread, with `cpu` and `regs` its own.
#[cold]
unsafe fn seccomp_permits(
    task: *mut ffi::task,
    cpu: *mut ffi::cpu_state,
    regs: *mut [u64; 31],
    num: &mut u32,
    mode: u8,
    recheck: bool,
) -> bool {
    let num_now = *num;
    use kernel_seccomp::{AUDIT_ARCH_AARCH64, Data, MODE_STRICT, Verdict};
    const SIGSYS: c_int = 31;
    const SYS_SECCOMP: i32 = 1;
    if mode == MODE_STRICT {
        if kernel_seccomp::strict_allows(num_now) {
            return true;
        }
        // Linux's `__secure_computing_strict`: `do_exit(SIGKILL)`, this thread.
        unsafe { exitcalls::do_exit(ffi::SIGKILL_ as c_int) };
    }
    let args: [u64; 6] = unsafe { std::array::from_fn(|i| (*regs)[i]) };
    let data = Data {
        nr: num_now as i32,
        arch: AUDIT_ARCH_AARCH64,
        instruction_pointer: unsafe { (*cpu).pc },
        args,
    };
    match unsafe { (*task).seccomp.evaluate(&data) } {
        Verdict::Allow => true,
        Verdict::Errno(e) => {
            unsafe { (*regs)[0] = (-(e as i64)) as u64 };
            false
        }
        Verdict::Enosys => {
            unsafe { (*regs)[0] = ENOSYS as i64 as u64 };
            false
        }
        Verdict::Trace(_) if recheck => true,
        Verdict::Trace(data) => {
            // To the tracer, if it asked for `PTRACE_O_TRACESECCOMP`; `-ENOSYS`
            // otherwise. It may skip the call (number -1, `x0` its answer),
            // change it, or let it run; a `SIGKILL` meanwhile skips it.
            let Some(p) = (unsafe { (*task).ptrace.as_deref() }).filter(|p| p.is_traced()) else {
                unsafe { (*regs)[0] = ENOSYS as i64 as u64 };
                return false;
            };
            p.set_syscallno(num_now as i32);
            if !signaldeliver::receive::ptrace_seccomp_stop(data) {
                unsafe { (*regs)[0] = ENOSYS as i64 as u64 };
                return false;
            }
            if signaldeliver::receive::ptrace_killed_in_stop() {
                return false;
            }
            let after = p.syscallno();
            if after == -1 {
                return false;
            }
            *num = after as u32;
            unsafe { seccomp_permits(task, cpu, regs, num, mode, true) }
        }
        Verdict::Trap(why) => {
            // SIGSYS with the call in `_sigsys`: where it was made (the
            // instruction after the `svc`, which is where `pc` is), its
            // number, the architecture, and the filter's data in `si_errno`.
            // `x0` is left as the guest passed it, which is Linux's
            // `syscall_rollback`.
            let mut b = [0u8; 128];
            b[0..4].copy_from_slice(&SIGSYS.to_le_bytes());
            b[4..8].copy_from_slice(&i32::from(why).to_le_bytes());
            b[8..12].copy_from_slice(&SYS_SECCOMP.to_le_bytes());
            b[16..24].copy_from_slice(&data.instruction_pointer.to_le_bytes());
            b[24..28].copy_from_slice(&data.nr.to_le_bytes());
            b[28..32].copy_from_slice(&AUDIT_ARCH_AARCH64.to_le_bytes());
            let info = kernel_sigqueue::SigInfo::from_le_bytes(&b);
            signaldeliver::deliver_signal(signaldeliver::Target::Me, SIGSYS, info);
            false
        }
        // The last thread takes the process with it, with the status a
        // SIGSYS death leaves; another thread goes alone -- Linux's
        // `SECCOMP_RET_KILL_THREAD`.
        Verdict::KillThread if alone() => unsafe { exitcalls::do_exit_group(SIGSYS) },
        Verdict::KillThread => unsafe { exitcalls::do_exit(SIGSYS) },
        Verdict::KillProcess => unsafe { exitcalls::do_exit_group(SIGSYS) },
    }
}

/// Whether the calling thread is the only one in its group.
fn alone() -> bool {
    let pids = kernel_pids::PidsGuard::take();
    pids.me().and_then(|me| me.group()).is_none_or(|g| g.thread_count() == 1)
}

/// Call it, put the references back, and write the answer into `x0`.
#[inline(always)]
unsafe fn run(f: Syscall, num: u32, regs: *mut [u64; 31]) {
    // Six, not the array. `let a = *regs` copies all 31 registers -- 248 bytes
    // per syscall -- and it showed: getpid went from 101 ns to 110 with it.
    let a: [u64; 6] = unsafe { std::array::from_fn(|i| (*regs)[i]) };
    strace!("{} call {num:<3} ", taskview::current_pid());

    let t0 = if util_iulenv::env().systrace {
        Some(std::time::SystemTime::now())
    } else {
        None
    };

    let result = f(a[0], a[1], a[2], a[3], a[4], a[5]);

    // Everything f_get handed out during that call goes back here. A syscall
    // that leaves by pthread_exit -- do_exit and friends -- never reaches this,
    // but the whole task is going away and task_destroy frees the list.
    fs_fdobj::syscall_refs_drain();
    // The newline is what *ends* the line, and printk accumulates until it sees
    // one: without it every syscall's trace ran into the next -- `= 0x0` and
    // then `2 call 214 brk(...)`, so a return value and the next line's pid
    // fused into one number -- and nothing appeared at all until the 16 KB
    // accumulator overflowed. The C's STRACE ended with one; the migration did
    // not carry it across, and the channel is off by default, so nothing failed.
    strace!(" = {result:#x}\n");

    // IUL_SYSTRACE=1: every slow-path syscall with a timestamp, the pid, the
    // number, the six arguments and the answer. One write, so that two threads
    // cannot interleave an argument line with the other's return value.
    if let Some(t0) = t0 {
        let d = t0.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        eprintln!(
            "[sc] {}.{:06} pid={} n={num}({:x},{:x},{:x},{:x},{:x},{:x}) = {result:#x}",
            d.as_secs(),
            d.subsec_micros(),
            taskview::current_pid(),
            a[0],
            a[1],
            a[2],
            a[3],
            a[4],
            a[5],
        );
    }

    // The syscall answered EINTR, so a restart is now a question -- whether it
    // is due is decided from the class recorded at entry, by whoever is in a
    // position to say whether a handler ran. There used to be a switch over
    // three syscall numbers here.
    if result as i32 == EINTR {
        taskview::with_current_restart(|r| r.interrupted());
    }

    // rt_sigreturn restores the whole CPU from the signal frame, x0 included.
    // Writing a return value over it corrupts what was restored.
    //
    // 139 only. 119 used to be listed here as "sigreturn", which is its *i386*
    // number -- on aarch64 there is no sigreturn syscall at all and 119 is
    // sched_setscheduler, so its return value was never written to x0 and the
    // guest read back the first argument. A failing sched_setscheduler reported
    // the pid it was given, which for the usual pid of 0 is indistinguishable
    // from success.
    const NR_RT_SIGRETURN: u32 = 139;
    if num == NR_RT_SIGRETURN {
        return;
    }

    // See the module comment on why the width is decided rather than tested.
    unsafe {
        (*regs)[0] = if syscalltable::returns_64bit(num) {
            result as u64
        } else {
            let narrow = result as i32;
            if (-4095..0).contains(&narrow) {
                // Sign-extend an errno.
                narrow as i64 as u64
            } else {
                // Zero-extend anything else, which is what a 32-bit success
                // value means.
                narrow as u32 as u64
            }
        };
    }
}

/// The bookkeeping after a syscall returns, and the two ways it may not.
#[inline(always)]
pub(super) fn after_syscall(num: u32) {
    // The syscall just run may have left this thread orphaned: a blocking one
    // -- futex, poll, wait -- can return exactly as another thread's
    // do_exit_group safety valve force-releases us, and once the group leader
    // is reaped task_destroy zeroes this task, so `group` and `exiting` both
    // read back as 0. The bookkeeping below dereferences `group`
    // unconditionally, and with a zeroed one that is an address a few hundred
    // bytes into page zero.
    //
    // Bail the same way the interpreter loop does for a destroyed task:
    // pthread_exit straight out, so the cleanup handler runs. **Not do_exit**:
    // for the zeroed case it would fall through its own `exiting` fast path and
    // dereference `group->exit` one line over, and for the force-released case
    // it clears `current` before pthread_exit, which makes the cleanup handler
    // skip the deferred `mm` release and leak the whole guest address space.
    if taskview::current_is_exiting() || taskview::current_group().is_null() {
        // SAFETY: no Rust frame below this one relies on being unwound; see
        // above.
        unsafe { libc::pthread_exit(std::ptr::null_mut()) };
    }
    taskview::with_current_task(|t| t.syscall.leave());

    // When the group last made real progress, for the futex-stall diagnostic.
    //
    // Only for a **non-blocking** syscall. A blocking one that returns and
    // retries is not forward progress, and refreshing the timestamp for one
    // hides exactly the hang this is meant to find.
    if !BLOCKING.contains(&num) {
        let ns = util_timeabi::monotonic_ns();
        taskview::with_current_group(|g| g.last_progress_ns.store(ns, Ordering::Relaxed));
    }

    // When do_exit_group sends SIGKILL to every thread, one stuck in a
    // retrying syscall -- musl's futex_wait loops on EINTR -- would never get
    // back to the interpreter loop where receive_signals handles it.
    // Or another thread's execve, which ends this one the same way.
    // Through `do_exit_group`, so that the first thread of a group a fatal
    // signal ended from outside leads the exit.
    if let Some(status) = taskview::current_must_leave() {
        // SAFETY: on this guest thread, which does not run again, and not
        // inside a `with_current_fdtable` borrow.
        unsafe { exitcalls::do_exit_group(status as c_int) };
    }
}
