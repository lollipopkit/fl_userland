//! The types, and nothing that does anything with them.
//!
//! Split out of `crates/kernel/taskview` on 2026-09-09. That crate was two
//! things in one: 3,500 lines of type definitions and 760 of accessors over
//! `current`. Everything in the tree depends on the first half — 81 crates —
//! so `taskview` was **exempt from `tools/crate-layers.py` everywhere**, and an
//! exemption that broad is a gate covering nothing.
//!
//! With the types here, `taskview` is an ordinary crate the layering rule
//! applies to, and this one is the foundation: it depends on `libc` and on the
//! four leaf crates whose objects `struct task` holds **by value**, and on
//! nothing else. It is the only crate the rule exempts.
//!
//! # What is in it
//!
//! `abi.rs` holds the types the headers used to define — the guest's wire
//! formats, whose `#[repr(C)]` is the Linux ABI and not a C-compiler contract.
//! `constants.rs` holds the guest ABI constants separately from those layouts.
//! The sibling modules hold the types written by hand and the layout families
//! that deserve their own source files: `struct cpu_state`, whose offsets the
//! gadgets index; `struct fd`; `struct mount`; signal layouts; and time and
//! resource layouts.
//!
//! Which file a name is in is a question about its history rather than about
//! how a consumer names it, so they are one namespace: `taskview::ffi` re-exports
//! all re-exported modules, and every consumer still writes
//! `taskview::ffi::task`.

#![allow(non_camel_case_types)]

// `r#` on two of them because a module and a type may not share a name in a
// glob re-export, and `mount` and `task` are both.
#[allow(dead_code)]
mod abi;
mod constants;
mod err_ptr;
mod fd_ops;
mod fd_types;
mod identity;
mod filesystem_types;
mod fs_ops;
mod inode_types;
mod io_types;
mod memory_types;
mod mount_types;
mod network_types;
mod register_types;
mod stat_types;
mod system_types;
mod time_types;
mod tty_types;

pub use abi::*;
pub use constants::*;
pub use err_ptr::{err_ptr, is_err, is_err_value, ptr_err};
/* `cpustate` was a module here until 2026-09-09, and `mmu`, `tlb`, `tlb_entry`
 * and the `PAGE_*`/`MEM_*`/`P_*`/`TLB_*` constants were in `abi.rs`. They are
 * `crates/emu/abi` now: the emulator's types, which `crates/emu/tlb` and three
 * `asbestos` crates were naming a *kernel* crate to reach. Re-exported, so
 * `struct task` still embeds a `cpu_state` and every consumer still writes
 * `taskview::ffi::tlb`. */
pub use emu_abi::*;
/// Six objects a task or a descriptor holds **by pointer**, re-exported under
/// the names the rest of the tree writes.
///
/// Each was an opaque placeholder — a `#[repr(C)]` empty struct — until
/// 2026-09-09, and each cost every reader of the field a `.cast()`, which is a
/// conversion the compiler cannot check. What kept them opaque was layering: a
/// type `struct task` names has to be *below* it. All six owning crates are
/// **leaves**, so naming the real type is not a cycle.
///
/// Under the C names rather than their own, so that `ffi::poll_watchers` still
/// resolves everywhere it is written and the casts become no-ops the compiler
/// accepts — which is what lets them be removed one crate at a time rather than
/// all at once.
///
/// **This list said `hostthreads` was one of them and it was not** (corrected
/// 2026-09-11): `host_threads_state` was still an opaque placeholder in
/// `crates/kernel/taskview` and nine sites still cast it back. It is
/// `kernel_hostthreads::HostThreads` now, re-exported from `taskview` rather
/// than here — see below for the two the same constraint applies to.
///
/// **Two of the shared objects cannot be re-exported from this crate at all**,
/// and the reason is worth stating because it decides where every future one
/// goes: `kernel-sigqueue` and `kernel-hostthreads` sit *above* this crate or
/// beside it, so `taskview` is the lowest crate that can name them. Its
/// `task_types.rs` holds those two, and `taskview::ffi` globs both halves, so a
/// consumer still writes `ffi::sigqueue_state`. A name defined by both globs is
/// **ambiguous rather than shadowed**, so a placeholder here and a re-export
/// there cannot coexist for even one commit.
pub type fdtable = ::fdtable::Table<FdOwned>;
pub use grouprusage::GroupRusage as group_rusage;
/// Whether a thread group is stopped and what it reports to `wait`.
///
/// Named since 2026-09-11, where it was **two** placeholders — this crate's
/// `group_stop` and `crates/kernel/taskview`'s `groupstop` — for one object,
/// with a cast between them at `crates/fs/proc`'s snapshot. `kernel-groupstop`
/// stands on `util-guestlock` and nothing else, so naming it here is not a
/// cycle.
pub use groupstop::GroupStop as group_stop;
pub use itimer::Itimer as itimer;
pub use pollset::Watchers as poll_watchers;

pub use fd_ops::*;
pub use fd_types::*;
pub use identity::*;
pub use filesystem_types::*;
pub use fs_ops::*;
pub use inode_types::*;
pub use io_types::*;
pub use memory_types::*;
pub use mount_types::*;
pub use network_types::*;
pub use register_types::*;
/// `siginfo_` and `sigval_`, which are `crates/kernel/siginfo`'s.
pub use kernel_siginfo::*;
/// `struct fd`'s host directory stream, which `crates/util/hostdir` owns.
pub use util_hostdir::HostDir;
pub use stat_types::*;
pub use system_types::*;
pub use time_types::*;
pub use tty_types::*;
/* `task_types` was a module here until 2026-09-09: `struct task`, `tgroup`,
 * `task_cleanup` and the `current` thread-local. They are
 * `crates/kernel/taskview`'s now, and the move is what lets that crate depend
 * on `kernel-sighand` -- which is the prerequisite for `task.sighand` being an
 * `Option<Arc<SigHand>>` instead of an erased pointer.
 *
 * Nothing else in this crate referenced them: `task_types.rs` was a leaf of it,
 * importing the guest width aliases and the placeholder handles and being
 * imported by nothing. That is what made the move a rename rather than a
 * split. `taskview::ffi` re-exports both halves, so every consumer still writes
 * `taskview::ffi::task`. */
