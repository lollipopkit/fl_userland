//! Where the guest comes back to the kernel: the interrupt the interpreter
//! stopped on, and what to do about it.
//!
//! # The hot path
//!
//! `INT_SYSCALL` is the most-executed code in this tree. What it does is:
//! record what a restart would need, index the table, call, put the references
//! back, write the answer into `x0`. Everything else in this file happens once
//! per interrupt of some rarer kind.
//!
//! Measured before and after this moved out of `kernel/calls.c` on 2026-09-01,
//! release build, `tests/guest/src/bin/syscall_bench.rs`, medians of five,
//! against a `compute_bench` control that did not move (163.9 → 163.4 ms):
//!
//! |            | before | after |
//! | ---        | ---    | ---   |
//! | `getpid`   | 101 ns | 105 ns |
//! | `read` 64B | 855 ns | 861 ns |
//! | `write` 8K | 1374 ns | 1375 ns |
//!
//! `getpid` is the purest measurement of dispatch, because the syscall itself
//! does nothing; a real syscall shows no difference at all. The 4 ns is the
//! `strace!` check, which the C compiled to **nothing** when the channel was
//! off and which is a load and a branch here — the price of migrated syscalls
//! not silently dropping out of the trace, which is what
//! `crates/util/strace` exists for.
//!
//! Three things cost more than that and were found by measuring, not by
//! reading. Each is named where it is fixed: a dead `Instant::now()` in
//! `after_syscall` (8 ns), copying all 31 registers where the C read six
//! (5 ns), and reading `current` five times per syscall where the C read a
//! `__thread` variable directly (9 ns) — that last one arriving from the other
//! side of the 2026-08-29 measurement that decided `current` stays in C.
//!
//! # The return value's width is a decision, not a cast
//!
//! A syscall whose C return type is 32 bits produces its value in the low half
//! of `x0`, and **the upper half is unspecified** — AAPCS says so. The compiler
//! usually writes `w0`, which zeroes the top, but a function returning a value
//! already sitting in `x0` need not rewrite it.
//!
//! This used to test `(result >> 32) == 0` before sign-extending an errno, so
//! it depended on that upper half being zero. It stopped being zero the moment
//! `err_map` started returning the low half of a two-field struct: the second
//! field rode out to the guest, which saw `0x1FFFFFF95` where it should have
//! seen `-107` and read it as a successful return of 8589934485. Every negative
//! errno from a 32-bit syscall was affected. So the width is decided from the
//! **declaration** and the upper half ignored for a narrow return.
//!
//! # What stays in C
//!
//! `INT_GPF` and `INT_BREAKPOINT`. Neither is dispatch: the first is every
//! fault-recovery heuristic this emulator has — it walks the page table,
//! resolves a fault against it and decides whether the guest can go on — and
//! the second is a pc range in a particular musl build. Both are the memory
//! subsystem's, and go with `kernel/memory.c` in step 6.


use std::ffi::c_int;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, RwLock};

use strace::strace;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

/// The three fault handlers, which are **this crate's own** — `faults.rs`, a
/// few hundred lines down.
///
/// They were declared in an `extern "C"` block under a keep-c-abi marker saying
/// "the definitions are in another crate and a Rust call would be a cycle",
/// which was never true of these three. That is the shape `CLAUDE.md` records
/// nine of on 2026-09-08: a round trip through the linker to reach a Rust
/// function in the same file's neighbour, left behind by a conversion that
/// moved the definition and not the declaration.
///
/// The `unsafe` blocks at the three call sites went with it: a direct call to a
/// safe path is not one, and each of these is `unsafe` only because it was
/// spelled `extern "C"`.
use crate::faults::{handle_int_breakpoint, handle_int_gpf, handle_int_undefined};

pub mod faults;
mod syscall;

/// The syscalls whose return is not forward progress: `futex`, `nanosleep`,
/// `ppoll`, `epoll_pwait` and `wait4` on aarch64.
///
/// One that returns and retries — musl's `futex_wait` loops on `EINTR` — is a
/// thread going round again, not a thread getting anywhere, and refreshing the
/// progress timestamp for one hides exactly the hang the futex-stall
/// diagnostic exists to find.
const BLOCKING: [u32; 5] = [22, 73, 95, 98, 101];

use guest_errno::c_int_::{EINTR, ENOSYS};

fn current() -> *mut ffi::task {
    taskview::current()
}

use logline::printk;

use syscalltable::Syscall;

/// `SYSCALL_TABLE[num]`, or `None` past the end.
///
/// The table was `kernel/arch/arm64/calls.c` until 2026-09-03 and reached
/// through an `extern static` declared with a length of zero, because its real
/// length was a C constant. It is `crates/kernel/syscalltable` now, so the
/// bound is the array's own and the compiler checks it.
#[inline(always)]
fn syscall_at(num: usize) -> Option<Syscall> {
    syscalltable::SYSCALL_TABLE.get(num).copied().flatten()
}

/// Syscall numbers already reported as missing or stubbed.
///
/// Once each: a guest that calls an unimplemented syscall in a loop would
/// otherwise fill the log with one line per call, which is how a real problem
/// gets buried.
static REPORTED: Mutex<Vec<u32>> = Mutex::new(Vec::new());

fn report_once(num: u32) -> bool {
    let mut seen = REPORTED.lock().unwrap_or_else(|e| e.into_inner());
    if seen.contains(&num) {
        return false;
    }
    seen.try_reserve(1).is_ok() && {
        seen.push(num);
        true
    }
}

/// The embedder's hook on the interpreter's periodic tick. ServerBox uses it to
/// drive its own timers from a thread it does not own.
type TimerTickHook = unsafe extern "C" fn();

static TIMER_TICK_HOOK: RwLock<Option<TimerTickHook>> = RwLock::new(None);

/// `None` removes the hook.
#[unsafe(no_mangle)]
pub extern "C" fn iul_set_timer_tick_hook(hook: Option<TimerTickHook>) {
    *TIMER_TICK_HOOK.write().unwrap_or_else(|e| e.into_inner()) = hook;
}

/// A guest thread has stopped on `interrupt`. Deal with it and return, or
/// leave through `do_exit`/`pthread_exit`.
///
/// # Safety
/// Called from the interpreter loop on a guest thread.
pub unsafe fn handle_interrupt(interrupt: c_int) {
    // Read **once**, which was worth 7 ns of 101 when `current` was a call
    // into C: five reads on the syscall path cost 9 ns, one cost 2. It is
    // crates/kernel/taskview's `thread_local!` as of 2026-09-06 and the read
    // inlines, so the saving is smaller now -- but a single read is still the
    // right shape, because the arms below want one task and not five lookups
    // of the same one.
    //
    // Safe to hold across the arms: `current` changes only in task_start and
    // do_exit, and neither returns here. The one case where the task is
    // *destroyed* under this thread is handled in after_syscall, which reads
    // the fields rather than the variable.
    let task = current();
    let cpu = unsafe { (*task).cpu.get() };
    match interrupt as u32 {
        ffi::INT_SYSCALL => unsafe { syscall::do_syscall(task, cpu) },
        ffi::INT_GPF => unsafe { handle_int_gpf() },
        ffi::INT_UNDEFINED => unsafe { handle_int_undefined() },
        ffi::INT_BREAKPOINT => unsafe { handle_int_breakpoint() },
        ffi::INT_DEBUG => {
            let info = ffi::siginfo_ {
                sig: ffi::SIGTRAP_ as c_int,
                code: ffi::TRAP_TRACE_ as c_int,
                ..Default::default()
            };
            signaldeliver::send_signal(signaldeliver::Target::Me, ffi::SIGTRAP_ as c_int, info);
        }
        ffi::INT_TIMER => {
            let hook = *TIMER_TICK_HOOK.read().unwrap_or_else(|e| e.into_inner());
            if let Some(hook) = hook {
                unsafe { hook() };
            }
        }
        _ => {
            printk(&format!(
                "EXIT[unhandled-int]: pid={} interrupt={interrupt}",
                taskview::current_pid()
            ));
            exitcalls::sys_exit(interrupt as u32);
        }
    }

    unsafe { after_interrupt(cpu) };
}

/// What every interrupt does on its way back to the guest: take any signals,
/// and sit out a group stop.
#[inline(always)]
unsafe fn after_interrupt(cpu: *mut ffi::cpu_state) {
    let traced_stop = signaldeliver::receive::receive_signals();

    // What `/proc/<pid>/syscall` reports while this thread sits out a stop:
    // `-1`, with where it stopped.
    // SAFETY: this thread's registers, between guest instructions.
    let (sp, pc) = unsafe { ((*cpu).sp, (*cpu).pc) };
    let note = |asleep: bool| {
        taskview::with_current_task(|t| if asleep { t.syscall.stopped(sp, pc) } else { t.syscall.leave() });
    };
    // Sleeps while the group is stopped, then claims the right to report the
    // continue: every thread wakes and exactly one of them tells the parent.
    // The claim happens whether or not the sleep did, which is the case where
    // the SIGCONT overtook the stop. See crates/kernel/groupstop.
    // The calling task's group, which it was dereferencing with no null test.
    // A traced thread's group stop is a ptrace stop, which its tracer ends --
    // and may end by letting it run while the group stays stopped, by
    // `PTRACE_LISTEN`, or (seized) not at all until the group continues. A
    // thread asleep in the stop leaves it when a tracer attaches, to take
    // the ptrace stop instead. See `signaldeliver::receive::ptrace_group_stop`.
    use signaldeliver::receive::{GroupStopStep, ptrace_group_stop, ptrace_leaves_group_stop, ptrace_listen_ended};
    let mut traced_stop = traced_stop;
    let mut slept = false;
    let stop_wait = loop {
        let step = ptrace_group_stop();
        traced_stop |= step != GroupStopStep::Untraced;
        let leave: fn(u64) -> bool = match step {
            GroupStopStep::Again => continue,
            GroupStopStep::Released => |_| true,
            GroupStopStep::Listening => |_| taskview::current_ptrace_trap_pending(),
            GroupStopStep::Untraced => ptrace_leaves_group_stop,
        };
        let Some(wait) = taskview::with_current_group(|g| g.stop.wait_while_stopped_until(&note, leave)) else {
            return;
        };
        slept |= wait.was_stopped;
        if step == GroupStopStep::Listening {
            // The group continued, or the tracer interrupted: the trap.
            ptrace_listen_ended();
            continue;
        }
        if step == GroupStopStep::Untraced && taskview::with_current_group(|g| g.stop.is_stopped()) == Some(true) {
            // Left early for a tracer that attached.
            continue;
        }
        break wait;
    };
    // A ptrace stop is the same case: the tracer suppressed the signal, or
    // the stop was a trap with no signal at all, and no handler ran. A
    // handler that did run moved the pc, and the rewind below then finds
    // nothing at the svc to rewind (`take_rewind` is given the pc).
    let was_stopped = slept || stop_wait.was_stopped || traced_stop;

    // The stop is over and no handler ran for it -- a stop is not a handler.
    // Linux restarts the syscall the stop interrupted, so `^Z` then `fg` on a
    // program blocked in read() or pause() goes on waiting rather than
    // surfacing EINTR. Nothing did that here: the wait ended with EINTR, no
    // handler was delivered, and the only rewind was the SA_RESTART one in
    // receive_signal, so every job-control suspend and resume returned early
    // from whatever the process was blocked in.
    //
    // Deliberately not done for *every* interrupt where no handler ran, which
    // is Linux's rule: a signal that stays pending after receive_signals would
    // then rewind into a syscall that answers EINTR again immediately, and a
    // spurious EINTR is a better failure than a livelock. The stop is the case
    // that has been measured -- tests/guest/src/bin/wait_probe.rs -- and after
    // one the signals that caused it have been consumed.
    if was_stopped {
        // SAFETY: this thread's registers, between guest instructions.
        let pc = unsafe { (*cpu).pc };
        let rewind = taskview::with_current_restart(|r| r.take_rewind(pc, false)).flatten();
        if let Some(rewind) = rewind {
            unsafe {
                (*cpu).pc = rewind.pc;
                (*cpu).regs[0] = rewind.arg0;
                // A relative deadline resumes for what is left: the `svc`
                // runs `restart_syscall`, which takes the block the syscall
                // left (Linux's `ERESTART_RESTARTBLOCK`).
                if rewind.restart_syscall {
                    (*cpu).regs[8] = kernel_syscallrestart::nr::NR_RESTART_SYSCALL;
                }
            }
        }
    }

    if stop_wait.report_continue {
        report_continued();
    }
}

/// What the *stop* does, in `receive_signals`, and for the same two reasons: a
/// parent blocked in `wait()` has to be woken, and POSIX says a continued child
/// generates `SIGCHLD`.
///
/// Neither happened, so `waitpid(WCONTINUED)` reported the event only when the
/// wait loop's one-second poll tick came round — measured at 704 ms against a
/// real kernel's microseconds — and no `SIGCHLD` was ever delivered.
fn report_continued() {
    let pids = kernel_pids::PidsGuard::take();
    let Some(me) = kernel_pids::Task::current(pids.held()) else {
        return;
    };
    let leader_pid = me.group().map_or(me.tgid(), kernel_pids::Group::leader_pid);
    if let Some(parent) = me.parent() {
        if let Some(g) = parent.group() {
            kernel_tgroup::tgroup_notify_child_exit(g);
        }
        // `mut`: a union member is written below, and a bindgen union field
        // cannot be named in a struct literal.
        let mut info = ffi::siginfo_ {
            sig: ffi::SIGCHLD_ as c_int,
            code: ffi::CLD_CONTINUED_ as c_int,
            ..Default::default()
        };
        info.__bindgen_anon_1.child.pid = leader_pid;
        info.__bindgen_anon_1.child.uid = me.creds().uid();
        // `SIGCONT`: what Linux's do_notify_parent_cldstop puts in si_status
        // for CLD_CONTINUED, and what a handler reads. This was 0xffff -- the
        // *wait* loop's encoding of a continue, which the handler is not the
        // wait loop and never decodes.
        info.__bindgen_anon_1.child.status = ffi::SIGCONT_ as c_int;
        signaldeliver::send_exit_signal(parent, ffi::SIGCHLD_ as c_int, info);
    }
}

/// The calling task, for a log line.
fn pid_and_comm() -> String {
    format!("{}({})", taskview::current_pid(), taskview::current_comm())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_narrow_errno_is_sign_extended_and_a_narrow_success_is_not() {
        // The rule the module comment is about. `result` arrives as 64 bits
        // whose upper half is unspecified for a 32-bit syscall, so the answer
        // must depend on the low half alone.
        let narrow = |result: i64| {
            let n = result as i32;
            if (-4095..0).contains(&n) {
                n as i64 as u64
            } else {
                n as u32 as u64
            }
        };
        // -107 = ENOTCONN, with rubbish in the upper half.
        assert_eq!(narrow(0x1_ffff_ff95u64 as i64), u64::MAX - 106);
        assert_eq!(narrow(-107), u64::MAX - 106);
        // A success, likewise.
        assert_eq!(narrow(0x1_0000_0005u64 as i64), 5);
        assert_eq!(narrow(0), 0);
        // -4096 is not an errno: it is a large positive value a 32-bit syscall
        // can legitimately return, and sign-extending it would make it one.
        assert_eq!(narrow(-4095), u64::MAX - 4094);
        assert_eq!(narrow(-4096), 0xffff_f000);
    }

    #[test]
    fn only_the_five_blocking_numbers_skip_the_progress_timestamp() {
        // A blocking syscall that returns and retries is not forward progress,
        // and refreshing the timestamp for one hides the hang this exists to
        // find. The numbers are futex, nanosleep, ppoll, epoll_pwait and wait4
        // on aarch64.
        assert_eq!(BLOCKING, [22, 73, 95, 98, 101]);
        for n in [0u32, 1, 63, 64, 221, 260] {
            assert!(!BLOCKING.contains(&n), "{n} is not a blocking syscall");
        }
    }

    #[test]
    fn a_number_is_reported_once() {
        // A guest calling an unimplemented syscall in a loop would otherwise
        // put one line per call in the log, which is how a real problem gets
        // buried.
        assert!(report_once(0xdead));
        assert!(!report_once(0xdead));
        assert!(report_once(0xbeef));
    }
}
