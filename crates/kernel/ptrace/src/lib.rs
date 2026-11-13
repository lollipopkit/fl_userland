//! `ptrace(2)`: the per-task tracing state and the syscall over it.
//!
//! Only `PTRACE_TRACEME` is reachable — attaching to a process that is already
//! running is not implemented — so a tracee here is always a child of its
//! tracer, and always one that asked to be traced. That is the shape `gdb` and
//! `strace` use to start a program under themselves.
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
//! **`strace -f` does not**, and needs the one structural thing this crate has
//! never had: a **tracer that is not the parent**. `PTRACE_TRACEME` is the only
//! way in, so a tracee is always its tracer's child, and `find_stopped_child`
//! walks children. `TRACEFORK` and its two siblings auto-attach the *grandchild*
//! to the same tracer, and `wait4` has to report it. That is the same
//! separation `PTRACE_ATTACH` and `PTRACE_SEIZE` need, along with a **group
//! stop** counting as a ptrace stop in `find_stopped_child` (Linux's
//! `ptrace_check_attach` accepts one) and `PTRACE_LISTEN`. Each is a layer that
//! only shows up when the one before it works, which is why they are written
//! down here rather than guessed at.
//!
//! `process_vm_readv` is a stub, which strace uses to read a tracee's memory
//! and falls back to `PTRACE_PEEKDATA` for.
//!
//! A tracer that exits **does** detach its tracees, since 2026-09-08 --
//! [`ptrace_detach_on_tracer_exit`], called from `reparent_children`. Before
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
pub use hooks::{kill_hook_installed, set_kill_hook};
#[path = "regset.rs"]
mod regset;
#[path = "requests.rs"]
mod requests;
pub use requests::sys_ptrace;
#[cfg(test)]
use requests::{OPTIONS_HONOURED, options_valid, resume_signal};

/// Kill a stopped tracee — the one thing this crate needs from the layer above
/// it, and a hook because the edge only runs one way otherwise.
///
/// `crates/kernel/signaldeliver` calls nine functions out of this crate (every
/// ptrace stop is on the delivery path), so a direct call to its `send_signal`
/// is a cycle cargo refuses. It was a `send_signal` declared in an
/// `extern "C"` block until 2026-09-09 — the same call resolved by the linker
/// on name alone, and one of the last four places a `*mut task` crossed a C ABI
/// boundary.
///
/// `PTRACE_KILL` is the only caller and SIGKILL is the only signal it sends, so
/// the hook is the *operation* rather than a general signal-sending function:
/// nothing here has to name a `siginfo_`, and the lock order this crate's
/// module comment states — this lock before `sighand`'s — is a property of the
/// one call site either way.
pub(crate) use hooks::kill;

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
