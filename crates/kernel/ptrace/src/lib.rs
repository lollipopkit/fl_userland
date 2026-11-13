//! `ptrace(2)`: the per-task tracing state and the syscall over it.
//!
//! A tracer reaches a tracee four ways: `PTRACE_TRACEME` (the parent),
//! `PTRACE_ATTACH` and `PTRACE_SEIZE` (anyone `ptrace_may_access` lets in,
//! since 2026-11-13), and a fork, vfork or clone of a tracee whose tracer
//! asked for that event, which brings the new task along. The tracer edge is
//! `crates/kernel/proctree`'s, beside the parent one, so a tracee keeps its
//! real parent and need not be the tracer's child -- or a process at all: a
//! tracee is a thread.
//!
//! # Syscall stops, and what still stands between this and `strace(1)`
//!
//! Since 2026-09-04 a tracer can ask for `PTRACE_O_TRACESYSGOOD` and continue a
//! tracee with `PTRACE_SYSCALL`, which stops it before each syscall runs and
//! again after — the pair `strace` prints one line from, and what `gdb`'s
//! `catch syscall` is made of. The tracer reads the number and the arguments
//! from `PTRACE_GETREGSET` on the entry half and the answer on the exit half,
//! and may *change* them: the number is read out of `x8` after the stop, not
//! before, so writing a different one there runs the tracer's call.
//!
//! `ptrace_probe`'s section is the measurement — 68 cases, none differing from
//! a real kernel.
//!
//! # `strace` runs, and what `strace -f` needs
//!
//! Since 2026-09-08. What stood between it and this kernel was one `EINVAL`:
//! it sets `TRACESYSGOOD | TRACEEXEC | TRACEEXIT` in a single
//! `PTRACE_SETOPTIONS` and treats a refusal as fatal. Both new options are
//! honoured by taking a real stop at the point the event names --
//! `crates/kernel/signaldeliver`'s `ptrace_event_stop`, from `execve` and from
//! `do_exit` -- and *where* that stop is taken is the load-bearing part: a
//! queued `SIGTRAP` reports the same number one stop too late, and strace says
//! `Stray PTRACE_EVENT_EXEC`.
//!
//! # `strace -f`, `gdb -p`
//!
//! Since 2026-11-13. What they needed was a tracer that is not the parent,
//! and every layer that assumed one:
//!
//! - **finding the tracee** is by tid and then asking who traces it, not a
//!   walk of the caller's children;
//! - **`wait`** walks the tracer's tracees beside its children, reports a
//!   ptrace stop without `WUNTRACED` and a tracee without `__WALL`, and holds
//!   a traced thread's exit for its tracer (`proctree::ExitReport`);
//! - **a traced process's exit** goes to the tracer first, and to the real
//!   parent once the tracer has waited (`exitcalls::ptrace_release_zombie`);
//! - **a seized tracee** stops by a trap, `PTRACE_EVENT_STOP`, which is
//!   what `PTRACE_INTERRUPT` asks for and what a seized tracee's new task
//!   stops at first; the trap ends a blocked wait as a signal would and the
//!   syscall is restarted after it.
//!
//! - **a group stop** is a ptrace stop for a traced thread (Linux's
//!   `do_signal_stop` for a ptraced task): an attached tracee reports the
//!   stop signal with no `siginfo_` and runs on once continued, the group
//!   still stopped; a seized one reports `PTRACE_EVENT_STOP`, stops again if
//!   continued while the group is stopped, and `PTRACE_LISTEN` leaves it in
//!   the group stop to trap when that ends. A tracer that attaches to a
//!   stopped thread wakes it into the ptrace stop.
//!
//! `ptrace_attach_probe` is the measurement. `PTRACE_O_TRACESECCOMP` is not
//! done: `crates/kernel/seccomp` answers `SECCOMP_RET_TRACE` with `ENOSYS`.
//!
//! A tracer that exits **does** detach its tracees, since 2026-09-08 --
//! `exitcalls`' `exit_ptrace`, which kills those that asked for
//! `PTRACE_O_EXITKILL`. Before
//! that a tracee parked in a stop waited for a continue that could not come,
//! which is what `Ctrl-C` on an `strace` produced. See
//! `docs/changelog/2026-09-08-a-tracee-whose-tracer-died-waited-for-ever.md`,
//! including the second half of it: the dispatcher takes a syscall's *exit*
//! stop on the entry's answer, so a detached tracee stopped again one step
//! along.
//!
//! # The state and the syscall moved together, and then apart
//!
//! `struct task` carried a seven-field sub-struct with a lock and a condition
//! variable of its own, and `kernel/ptrace.c` was the only thing that used four
//! of them. Splitting *those* would have meant an accessor per field, so they
//! became one object here.
//!
//! **The object left on 2026-09-11** and is `crates/kernel/ptracestate`. That
//! is a different split and it is about the graph rather than about the fields:
//! `struct task` holds the object by pointer, a type `struct task` names has to
//! be below `crates/kernel/taskview`, and *this* crate's closure is 65 crates
//! and contains it -- `kernel-mmapcalls` for `PTRACE_PEEKDATA`,
//! `kernel-proctree` and `kernel-pids` to find the tracee, `kernel-usercopy` to
//! answer it. So the field was an opaque `ptrace_state` placeholder and 29
//! reads cast it back. The state needs the guest ABI numbers and a lock.
//!
//! Everything there is re-exported here, so a caller still writes
//! `kernel_ptrace::ptrace_is_traced`.
//!
//! # One exit, because the lock is a guard
//!
//! [`find_stopped_child`] answers with the tracee's state **locked**, and every
//! arm of the syscall operates under that lock. The C had `find_child` return
//! with the lock held and each arm release it, and two arms did not: the
//! `PTRACE_PEEKUSER` `EIO` path and, after that was fixed in the same file,
//! `PTRACE_GETSIGINFO`'s `EFAULT` path. A held ptrace lock is permanent — the
//! next `ptrace` on that child blocks, and so does the child's own
//! signal-delivery-stop. A guard cannot be forgotten.
//!
//! # Lock order
//!
//! `pids_lock`, then this lock, then `sighand`'s.
//!
//! This lock is taken **before** `sighand`'s: `PTRACE_KILL` calls `send_signal`
//! under it, and a tracee in [`Ptrace::wait_while_stopped`] takes `sighand`'s to
//! ask whether a `SIGKILL` has arrived. `signal_delivery_stop` releases
//! `sighand`'s lock before taking this one for exactly that reason.
//!
//! And **after** `pids_lock`, since 2026-09-04: the tracer finds its tracee by
//! walking its children, and a task found through the process tree can be
//! reaped and freed the moment that lock is dropped -- by the tracer's own
//! other thread in `wait4`, for a multithreaded debugger. The walk, the lookup
//! and the use are one hold of [`PidsGuard`], the shape
//! `crates/kernel/rescalls`'s `prlimit` has. Until then the walk took nothing,
//! as the C had not, under a TODO saying the order had to be checked against
//! the wait loop first. Checked: the wait loop holds `pids_lock` across its
//! condition wait and asks this lock for a stop report from inside it, which
//! is the same order; the tracee's side takes `pids_lock` to notify its tracer
//! and *releases* it before parking on this lock; and nothing that holds this
//! lock takes `pids_lock`. `tools/lock-order.py` reads the Rust and would
//! report the cycle if one of those stopped being true.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_int;

use kernel_pids::PidsGuard;
use strace::strace;
use usercopy::GuestMem;
use util_guestlock::GuestGuard;

mod hooks;
pub use hooks::{set_signal_hook, set_wake_hook, signal_hook_installed, wake_hook_installed};
#[path = "regset.rs"]
mod regset;
#[path = "requests.rs"]
mod requests;
pub use requests::sys_ptrace;
#[cfg(test)]
use requests::{options_valid, resume_signal};

pub(crate) use hooks::{signal, wake};

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/* `pub struct Task { _private: [u8; 0] }` was here until 2026-09-11, described
 * as "opaque to this crate: every use of one is a pointer handed back to C".
 * There is no C, and this crate depends on `crates/kernel/taskview` -- so it
 * was a **second rendering** of `struct task`, zero-sized beside the real one,
 * and every call into `proctree`, `taskview` or `usercopy` cast between them.
 * Eight casts the compiler could not check, for a type it could. */

/// The five this file answers with, and what each means here:
///
/// - `EPERM` is "you may not", which is not the same as "there is no such
///   thing";
/// - `EIO` is what Linux answers for a request `arch_ptrace` does not have,
///   and for a tracee address that is not mapped;
/// - `EFAULT` is the *caller's* buffer being unreadable;
/// - `ESRCH` is `ptrace_check_attach`'s answer for a pid that is not this
///   process's stopped tracee.
pub(crate) use guest_errno::Errno;

/* `CONT`, `struct State`, `struct Ptrace` and `src/abi.rs`'s twelve raw-pointer
 * adapters were here until 2026-09-11. They are `crates/kernel/ptracestate`,
 * re-exported below so that every caller still writes
 * `kernel_ptrace::ptrace_is_traced`.
 *
 * The split is not tidying. `struct task` holds this object by pointer and a
 * type `struct task` names has to be below `crates/kernel/taskview` -- but this
 * crate is the *syscall*, so its closure is 65 crates and contains `taskview`:
 * `PTRACE_PEEKDATA` needs `kernel-mmapcalls`, finding the tracee needs
 * `kernel-proctree` and `kernel-pids`, answering it needs `kernel-usercopy`.
 * The state itself needs the guest ABI numbers and a lock, and nothing else.
 * That is the same shape `crates/kernel/rlimitstate` is the result of. */
pub use kernel_ptracestate::*;

#[cfg(test)]
mod tests;
