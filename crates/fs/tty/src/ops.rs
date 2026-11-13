//! The two things a terminal cannot do for itself.
//!
//! A terminal's rules are about *processes* — which session owns it, which
//! group is in its foreground, who gets stopped for reading from the
//! background — and about a *host device* on the other side of the console
//! driver. Neither is this crate's, and both are behind one trait each, bound
//! once before any terminal exists.
//!
//! Everything else is here: the object, its lifetime, its line discipline, its
//! ioctls, the pseudoterminal pair, and the waiting.
//!
//! # They were two `#[repr(C)]` tables until 2026-09-09
//!
//! Eighteen and four `Option<extern "C" fn>` in a `static mut`, filled in by
//! `tty_bind_ops`, with the *real* interface — the methods below — written on
//! top of them as eighteen `map_or(default, |f| f())`. Three things went with
//! the tables:
//!
//! - **Eighteen defaults, one per field.** "There might be no `caller_pgid`"
//!   was said eighteen separate times and answered with a literal each time.
//!   It is one [`Unbound`] implementation now, so what an unbound terminal
//!   layer does is in one place and can be read.
//! - **`static mut`.** Two of them, read through `&raw const`, which is the
//!   shape `static_mut_refs` exists to warn about.
//! - **A second rendering.** `taskview::ffi::tty_task_ops` and
//!   `tty_console_ops` were the same two structs generated from the C, and by
//!   the end their only remaining mention was a test stub's declaration. Both
//!   are gone.
//!
//! There is nobody on the other side of a C ABI here: `crates/fs/ttydev` binds
//! the task side and the console driver, and `iul.h` declares neither.

use std::ffi::c_int;
use std::sync::{Arc, OnceLock};

use crate::tty::Tty;

pub type Pid = c_int;

/// Which terminal, as a value the process layer holds but never reads.
///
/// A `usize` until 2026-09-16 — `Arc::as_ptr(tty) as usize` at one end and a
/// cast back at the other — which is an integer that is really a pointer, and
/// a conversion nothing checks in either direction: `set_controlling(pgid)`
/// type-checked, and so did `is_controlling(some_index)`.
///
/// `Identity<T>` is `crates/util/identity`'s and is exactly this idea; it
/// already carries `crates/kernel/pids`' process-group keys and
/// `crates/fs/inode`'s mount keys. What the process layer does with one is
/// compare it against what a thread group holds, and hand it back to
/// `tty_retain`/`tty_release` — which is `as_ptr`, and is why that method
/// exists.
pub type TtyId = util_identity::Identity<crate::tty::Tty>;

/// The task side. Every method is something only the process layer can answer,
/// and the ones marked "pids_lock held" are called with it held by
/// [`with_pids_lock`] — the order is pids_lock, then a terminal's own
/// lock, and this crate never takes them the other way round.
pub trait TaskOps: Sync {
    fn pgid(&self) -> Pid;
    fn sid(&self) -> Pid;
    fn pid(&self) -> Pid;
    /// Whether the caller is a session leader, which is what `TIOCSCTTY` and
    /// an `open` that claims a controlling terminal both require.
    fn is_session_leader(&self) -> bool;
    /// Whether the caller already has a controlling terminal.
    fn has_tty(&self) -> bool;
    /// `CAP_SYS_ADMIN`, which lets `TIOCSCTTY` steal a terminal.
    fn sys_admin(&self) -> bool;
    /// pids_lock held.
    fn orphaned(&self, pids: &PidsHeld, pgid: Pid) -> bool;
    /// Has the caller ignored *or blocked* this signal? Consulted before the
    /// orphan question, which is Linux's order and the cheaper one.
    fn ignores(&self, sig: c_int) -> bool;
    /// pids_lock held.
    fn signal_group_locked(&self, pids: &PidsHeld, pgid: Pid, sig: c_int);
    /// Takes pids_lock itself. For the input path, which must not hold it.
    fn signal_group(&self, pgid: Pid, sig: c_int);
    /// The session a process group is in. `None` when there is no such group.
    /// pids_lock held.
    fn session_of(&self, pids: &PidsHeld, pgid: Pid) -> Option<Pid>;
    /// SIGHUP and then SIGCONT to the session's leader.
    fn hangup(&self, pids: &PidsHeld, sid: Pid);
    /// The caller's effective ids, for the owner of a new pty's node.
    fn caller_ids(&self) -> (u32, u32);

    /// Whether `tty` is the caller's controlling terminal.
    fn is_controlling(&self, tty: TtyId) -> bool;
    /// Make `tty` the caller's controlling terminal, taking a reference to it.
    /// pids_lock held.
    fn set_controlling(&self, pids: &PidsHeld, tty: &Arc<Tty>);
    /// Take `tty` away from every group in session `sid`, releasing the
    /// reference each held. pids_lock held.
    fn steal_controlling(&self, pids: &PidsHeld, sid: Pid, tty: TtyId);

    /// Run `f` with `pids_lock` held, releasing it however `f` ends.
    ///
    /// One scoped call since 2026-10-01, where it was `pids_lock` and
    /// `pids_unlock`: the implementation behind them was a pair of `unsafe fn`
    /// in `crates/kernel/pids`, and the guard that kept them paired was this
    /// crate's. The implementor's own guard is what pairs them now.
    fn locked(&self, f: &mut dyn FnMut());
}

/// The console driver: a host device, and the only driver that is not this
/// crate's. `crates/tools/iul` and an embedder both enable it with
/// `iul_enable_console`.
pub trait ConsoleOps: Sync {
    /// Prepare the host terminal, filling in the initial window size and
    /// termios with [`super::tty::set_console_state`].
    ///
    /// An `&Arc` since 2026-09-30. It was an `unsafe fn` taking `*mut Tty`,
    /// and the one implementation handed that pointer to a reader thread with
    /// no count behind it: the thread outlived the terminal whenever the
    /// last user went while a byte was on its way in. The thread holds a
    /// `Weak` now, which is what the `Arc` is for.
    fn init(&self, tty: &std::sync::Arc<super::tty::Tty>, num: c_int) -> c_int;
    /// Write to the host. Returns the count, or a negative guest errno.
    ///
    /// A `(*const u8, usize)` pair and an `unsafe fn` until 2026-09-15. The
    /// one caller holds a `&[u8]` and was writing `bytes.as_ptr(),
    /// bytes.len()`; the chain below it — this trait, `fs/ttydev`'s
    /// implementation, `ttyreal::real_tty_write` — carried the pair unchanged
    /// down to the `libc::write` that genuinely wants one. Only the last step
    /// needs a pointer, so only the last step has one.
    fn write(&self, num: c_int, buf: &[u8]) -> isize;
    /// Put the host terminal back and stop the reader thread.
    fn cleanup(&self, num: c_int);
    /// Whether this major has been enabled at all.
    fn enabled(&self, major: c_int) -> bool;
}

/// What the task side answers before anything binds one.
///
/// One implementation rather than eighteen `map_or` defaults, so the answers
/// can be read together: no process has this terminal, nobody is privileged,
/// no group is orphaned, and nothing is signalled. That is the right shape for
/// a terminal layer with no processes above it, which is what a unit test has.
struct Unbound;

impl TaskOps for Unbound {
    fn pgid(&self) -> Pid {
        0
    }
    fn sid(&self) -> Pid {
        0
    }
    fn pid(&self) -> Pid {
        0
    }
    fn is_session_leader(&self) -> bool {
        false
    }
    fn has_tty(&self) -> bool {
        false
    }
    fn sys_admin(&self) -> bool {
        false
    }
    fn orphaned(&self, _pids: &PidsHeld, _pgid: Pid) -> bool {
        false
    }
    fn ignores(&self, _sig: c_int) -> bool {
        false
    }
    fn signal_group_locked(&self, _pids: &PidsHeld, _pgid: Pid, _sig: c_int) {}
    fn signal_group(&self, _pgid: Pid, _sig: c_int) {}
    fn session_of(&self, _pids: &PidsHeld, _pgid: Pid) -> Option<Pid> {
        None
    }
    fn hangup(&self, _pids: &PidsHeld, _sid: Pid) {}
    fn caller_ids(&self) -> (u32, u32) {
        (0, 0)
    }
    fn is_controlling(&self, _tty: TtyId) -> bool {
        false
    }
    fn set_controlling(&self, _pids: &PidsHeld, _tty: &Arc<Tty>) {}
    fn steal_controlling(&self, _pids: &PidsHeld, _sid: Pid, _tty: TtyId) {}
    fn locked(&self, f: &mut dyn FnMut()) {
        f();
    }
}

static TASK: OnceLock<&'static dyn TaskOps> = OnceLock::new();
static CONSOLE: OnceLock<&'static dyn ConsoleOps> = OnceLock::new();

/// Bind both. Called once, from `become_first_process`, before any terminal
/// exists — so there is no ordering to get wrong and no lock to take.
///
/// The first call wins, which is what a `OnceLock` gives and what the
/// `static mut` this replaced did not: two binders used to leave whichever ran
/// last, silently.
pub fn tty_bind_ops(task: &'static dyn TaskOps, console: &'static dyn ConsoleOps) {
    let _ = TASK.set(task);
    let _ = CONSOLE.set(console);
}

pub fn task() -> &'static dyn TaskOps {
    *TASK.get().unwrap_or(&(&Unbound as &'static dyn TaskOps))
}

/// The console driver, or `None` when nothing bound one — which is what a
/// build with no console, and every unit test, has.
pub fn console() -> Option<&'static dyn ConsoleOps> {
    CONSOLE.get().copied()
}

/// The caller's effective user and group, which a new pty's node belongs to.
pub fn caller_ids() -> (u32, u32) {
    task().caller_ids()
}

/// Proof, inside [`with_pids_lock`], that `pids_lock` is held.
///
/// **This crate cannot name `kernel_pids::PidsHeld`**: `kernel-pids` depends
/// on `fs-tty`, so the edge back would be a cargo cycle. So there are two
/// tokens for one fact, and `crates/fs/ttydev` — which sits on both sides — is
/// where they meet: it implements the `TaskOps` this crate calls, and it turns
/// a `&PidsHeld` from here into the `kernel_pids` one.
///
/// Only [`with_pids_lock`] can make one, which is what makes it a proof rather
/// than a comment. It is what found the defect in
/// `docs/changelog/2026-09-16-the-one-caller-that-never-held-the-lock.md`.
/// `!Sync`, so a reference cannot carry the proof to another thread.
pub struct PidsHeld(std::marker::PhantomData<*const ()>);

/// Holds `pids_lock` for the duration of `f`. Everything a terminal does that
/// reaches the process layer goes through this, so the order — pids first,
/// then the terminal's own lock — is stated once.
///
/// A free function rather than a method, because a generic method cannot be
/// called on a `dyn` trait and boxing the closure to make it one would allocate
/// on the path a `TIOCSPGRP` takes.
pub fn with_pids_lock<T>(f: impl FnOnce(&PidsHeld) -> T) -> T {
    // `TaskOps::locked` takes a `dyn FnMut` -- a generic method cannot be
    // called through `dyn` -- so the `FnOnce` and its answer cross in two
    // `Option`s. Nothing is allocated, on the path a `TIOCSPGRP` takes.
    let mut f = Some(f);
    let mut answer = None;
    task().locked(&mut || {
        if let Some(f) = f.take() {
            answer = Some(f(&PidsHeld(std::marker::PhantomData)));
        }
    });
    answer.expect("TaskOps::locked runs its closure")
}
