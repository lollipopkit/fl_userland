//! `struct task`, `struct tgroup` and `struct task_cleanup` — Rust's, since
//! 2026-09-05.
//!
//! # Why they are here and not generated
//!
//! They were `kernel/task.h`'s until no C read a field of either: the last
//! three were `kernel/log.c`'s `current_pid`, `kernel/task.c`'s two fp syncs
//! and the embedder example's `current->fs`, and each got an accessor. A
//! definition nothing in C reads is not a C definition; it is a Rust one
//! written in C, and every crate that touched it paid a bindgen run for the
//! privilege.
//!
//! The synchronization types are defined in Rust too, but their host pthread
//! layout changes with `-DLOCK_DEBUG=1`. They are fields here, so this struct
//! still changes shape with that flag — which is what makes the LOCK_DEBUG
//! build worth running after a migration.
//!
//! `struct cpu_state` was on that list too, "whose layout `asbestos/offsets.c`
//! publishes to the assembly". That file stopped existing on 2026-09-06, two
//! days before anyone re-read the sentence: `crates/tools/cpuoffsets` and
//! `offset_of!` publish it. It is `src/cpustate.rs` since 2026-09-08.
//!
//! # The members held by value are the real types
//!
//! `creds`, `thread_attr`, `proc_attr`, `syscall_restart` and `group_exit` are
//! `crates/kernel/creds`', `procattr`'s, `syscallrestart`'s and `groupexit`'s
//! own types, re-exported here under the names the C prototypes use. Each was
//! an `unsigned char _opaque[N]` in `kernel/task.h` with a `static_assert` in
//! `kernel/task.c` pinning N — because C had to reserve the right amount of
//! space for a struct it could not see. It reserves space for nothing now, so
//! there is one representation and no second copy to keep in step.
//!
//! What made that safe is that all four crates are **leaves**: nearly
//! everything depends on `taskview`, so an edge out of it is a cycle unless
//! the far end has no dependencies of its own.
//!
//! It is also what makes `struct tgroup` not `Copy`. bindgen derived it and it
//! was never true: `exit` is a `GroupExit`, whose one field is an `AtomicU64`
//! holding the exiting flag and the status in one word so that a reader cannot
//! see them apart.

#![allow(non_camel_case_types)]

#[path = "cleanup.rs"]
mod cleanup_layout;
#[path = "current.rs"]
pub(crate) mod current;
#[path = "group.rs"]
mod group_layout;
#[path = "task.rs"]
mod task_layout;

pub use cleanup_layout::*;
pub use current::*;
pub use group_layout::*;
pub use task_layout::*;

// **There are none left on `struct task` or `struct tgroup`** (2026-09-29,
// when `posix_timers_state` below was the last). The `handle!` macro that
// wrote them went with it; what follows is why they existed and how each was
// found not to need to, kept because the next struct to be surveyed will have
// some.
//
// The Rust objects a task or a group points at, as bindgen spells an
// incomplete type.
//
// No header defines any of these — each is a Rust object behind an opaque
// pointer — so every crate would generate exactly this placeholder. They were
// reached through `struct task` while it was C's; now that it is not, nothing
// in a header mentions them and bindgen has nothing to emit, so they are
// written out here and imported like the rest of the shared set.
//
// **The reason they stayed placeholders was wrong, and two of them are real
// types now** (2026-09-09). It said: `Ctty` holds a `Mutex` and `HostThreads`
// an `Arc`, so neither is `#[repr(C)]`, and naming one here would make
// `struct task` itself not FFI-safe while `*mut task` is a parameter of
// `extern "C"` declarations.
//
// **The correction written in its place was wrong too** (measured 2026-09-11).
// It said `improper_ctypes` fires only on a type passed by value and that a
// raw pointer is FFI-safe whatever it points at. It is not: the lint recurses
// through one level of raw pointer. What is true is that the **two lints are
// different lints**, and only one of them recurses:
//
// ```ignore
// #![deny(improper_ctypes, improper_ctypes_definitions)]
// pub struct SigHand { _m: Mutex<u32> }
// #[repr(align(16))] pub struct Task { pub sighand: Option<Arc<SigHand>> }
// unsafe extern "C" { pub fn decl(t: *mut Task); }   // error: `extern` block
//                                                    // uses type `Task`,
//                                                    // which is not FFI-safe
// #[unsafe(no_mangle)] pub extern "C" fn defn(_t: *mut Task) {}   // clean
// ```
//
// A **declaration** recurses and rejects; a **definition** does not recurse
// and is silent. With `#[repr(C)]` on the pointee the declaration recurses one
// level further and names the field's type — `uses type std::sync::Mutex<u32>`
// — so a `#[repr(C)]` field-less placeholder, which is what these are, is the
// one shape clean under both.
//
// So what makes this tree's six `*mut task` signatures clean is that **all six
// are definitions**: `task_self`, `task_start`, `exit_handler` and three
// `#[no_mangle]` test doubles. No `extern "C" {}` block in `crates/` names a
// `*mut task`, and `rg -n 'extern "C"\s*\{' -A20 --glob '*.rs' crates` piped
// through `rg '\*mut (ffi::)?task\b'` is what says so. The day one of them
// becomes a declaration, the warning appears and a placeholder is what
// silences it. This tree's C sees `struct task;` — an opaque forward
// declaration in `iul.h` and nothing that defines it.
//
// What actually keeps a placeholder is **layering**, which is a different
// constraint and a real one: a type `struct task` names has to be *below* it.
// `kernel-ptrace` depends on half the tree, so naming it from here is a cycle
// cargo refuses.
//
// **`ctty` was on that list and should not have been** (2026-09-11).
// `kernel-ctty`'s transitive closure is twelve crates — `fs-pollset`,
// `fs-tty`, `jobctl`, `ldisc`, `libc`, `ttyreg`, `util-currentpid`,
// `util-guestlock`, `util-locks`, `util-synctypes`, `util-timeabi`,
// `util-waitfor` — and `kernel-taskview` is not among them. "It depends on
// `fs-tty`" is true and does not imply a cycle; `tools/crate-layers.py` puts
// `kernel` and `fs` in one layer, so the edge is sideways and allowed. The
// criterion is the *closure*, not the first dependency, and the query is
// `cargo tree -p <crate> --prefix none --no-dedupe | sort -u`.
//
// `crates/kernel/offloadreg` has **no dependencies at all**, which is the
// easy version of the same question. A `.cast()` is a conversion the compiler
// cannot check, which is why the shared definitions live in `taskview`.

/// POSIX timers owned by a thread group: `crates/kernel/posixtimers`.
///
/// The last `handle!` entry on either struct until 2026-09-29. It was kept
/// opaque by one edge, `kernel-posixtimers -> kernel-pids`, taken for
/// `TaskRef` -- two integers. The comment here said the answer would be the
/// split `ptracestate` is, and it was smaller than that: the *state* was
/// already out of the syscall, and it was the one type it held that lived in
/// the wrong crate. `TaskRef` is `crates/util/identity`'s now.
pub use kernel_posixtimers::Timers as posix_timers_state;

/// Whether a task is traced and what stopped it.
///
/// `crates/kernel/ptracestate` since 2026-09-11, where this was the last
/// `handle!` entry on `struct task`. The owning crate *was* `kernel-ptrace`,
/// whose closure is 65 crates and contains this one — it needs
/// `kernel-mmapcalls` for `PTRACE_PEEKDATA`, `kernel-proctree` and
/// `kernel-pids` to find the tracee and `kernel-usercopy` to answer it. The
/// state needs the guest ABI numbers and a lock.
///
/// So the answer was not a hook and not an exemption: it is the split
/// `crates/kernel/rlimitstate` is the result of, applied a second time. That is
/// the general answer for a placeholder whose owner is a **syscall family**,
/// which `posix_timers_state` turned out not to need.
pub use kernel_ptracestate::Ptrace as ptrace_state;

/// Where a task resolves a path from: its working directory, its root and its
/// umask, shared by every thread of a `CLONE_FS` group.
///
/// Named since 2026-09-11. What kept it opaque was one dependency:
/// `kernel-fsinfo` called `fs_fdobj::fd_retain` and `fs_fdobj::fd_close`, and
/// `fs-fdobj`'s closure is 41 crates and contains this one. Those two functions
/// were one line each over `crates/fs/fd`, then the refcount, with no
/// dependencies at all (the count is `kernel-abi`'s `Arc` since 2026-10-17) — `CLAUDE.md`'s "check whether the function you want is
/// a wrapper over something below you", which is the shape that settled two
/// cycles on 2026-09-09 and is answer 1 rather than a hook.
pub use fsinfo::FsInfo as fs_info;

/* `groupstop`, `group_rusage_state` and `itimer_state` were three more entries
 * here until 2026-09-11, and each was a **second rendering**: `kernel-abi`
 * already re-exported `grouprusage::GroupRusage` as `group_rusage` and
 * `itimer::Itimer` as `itimer`, and had a `group_stop` placeholder of its own
 * beside this one. Two zero-sized types for one object cannot disagree at
 * runtime and nothing could have caught it if they did.
 *
 * `struct tgroup` names `ffi::group_stop`, `ffi::group_rusage` and
 * `ffi::itimer` now, all three real. */

/// The Rust objects a task and a group hold **by value**, under the names the
/// C prototypes use.
///
/// Each was an `unsigned char _opaque[N]` in `kernel/task.h` with a
/// `static_assert` in `kernel/task.c` pinning N against the number the owning
/// crate asserts for its own type — because C had to reserve the right amount
/// of space for a struct it could not see. It can see none of them now and
/// reserves space for nothing, so there is one representation and nothing to
/// keep in step; the size assertions went with the second copy.
///
/// The four crates below have **no dependencies of their own**, which is what
/// makes this safe to do from `taskview`: nearly everything depends on this
/// crate, so an edge out of it has to be a leaf or it is a cycle.
pub use kernel_creds::{Creds as creds, Groups as groups};
pub use kernel_groupexit::GroupExit as group_exit;
pub use kernel_procattr::{ProcAttr as proc_attr, ThreadAttr as thread_attr};
pub use kernel_syscallrestart::SyscallRestart as syscall_restart;

/// A task's signal queue, held **by pointer** and named rather than erased
/// since 2026-09-11.
///
/// It was a `#[repr(C)]` placeholder in `crates/kernel/abi` and cost every
/// reader of `task.signals` a `.cast()`. What made naming it possible is the
/// same one-line criterion the eight before it used — does the owning crate
/// reach `taskview`? `kernel-sigqueue` has two dependencies, `kernel-abi` and
/// `kernel-sigdisp`, and neither reaches here.
///
/// The re-export is here rather than in `kernel-abi` because it *cannot* be
/// there: `kernel-sigqueue` depends on `kernel-abi` for `siginfo_`, so the
/// reverse edge is a cycle. `taskview::ffi` globs both crates, and a name two
/// globs define is ambiguous rather than shadowed — so the placeholder had to
/// be deleted from `kernel-abi` in the same commit.
///
/// Under the C name, so that `ffi::sigqueue_state` still resolves everywhere it
/// is written and each `.cast()` became a no-op that could be removed a crate
/// at a time.
pub use kernel_sigqueue::Signals as sigqueue_state;

// `sighand`, an alias of `kernel_sighand::SigHand` under the C name, was here
// until 2026-10-17. It outlived its last user: the task's field and the
// cleanup slot both name `SigHand`, and `sighand/src/abi.rs` is gone.

/// The live-host-thread count a group and its tasks share, likewise named
/// since 2026-09-11.
///
/// **Two comments in this tree said this had already been done** — this file's
/// and `crates/kernel/abi/src/lib.rs`'s, both dated 2026-09-09, both saying
/// `hostthreads` and `offloadreg` "have no dependencies at all, so those two
/// are named directly and eleven casts went with them". Only `offloadreg` was:
/// `host_threads_state` was still in the `handle!` list below and nine cast
/// sites still undid it. A comment is not a check.
///
/// (Spelled "cast" rather than with the parentheses on purpose. The number
/// this tree watches comes from
/// `rg -o '\.cast(_mut|_const)?\(\)' --glob '*.rs' crates | wc -l`, which
/// counts prose as well as code — seventeen of the 691 on 2026-09-11 were in a
/// comment. Writing the call in a sentence makes the measurement move the
/// wrong way.)
pub use kernel_hostthreads::HostThreads as host_threads_state;

/// The controlling terminal a thread group holds, named since 2026-09-11.
///
/// It was kept opaque by a written-down blocker that reads as a layering
/// argument and is not one: "`kernel-ctty` depends on `fs-tty`". True, and it
/// does not imply a cycle —
/// `cargo tree -p kernel-ctty --prefix none --no-dedupe -e normal` is fourteen
/// crates and `kernel-taskview` is not among them, so the edge is not even
/// upward: `tools/crate-layers.py` puts `kernel` and `fs` in one layer. The
/// criterion is the **transitive closure**, and the first dependency is not it.
///
/// `Ctty` holds a `Mutex`, which the older version of the blocker said made
/// `struct tgroup` not FFI-safe. See the `handle!` comment below for why that
/// is a question about `improper_ctypes` versus `improper_ctypes_definitions`
/// and not about this field: no `extern "C" {}` block in `crates/` names a
/// `*mut tgroup` either.
pub use ::ctty::Ctty as ctty;

// `zeroed_default!`, a `Default` that was a `memset`, was here for
// `tgroup` until 2026-09-30: every field was a scalar, a pointer or a
// `#[repr(C)]` struct of those, so all-zero was a value. `ctty` is held by
// value now and holds a `Mutex`, for which it is not, and the three tests that
// used it read the fields they are about out of zeroed memory instead.
