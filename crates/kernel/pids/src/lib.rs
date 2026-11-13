//! The pid registry: which process group and session each process is in, and
//! how many tasks each user has.
//!
//! # Why the membership moved here
//!
//! It was two intrusive lists per pid entry and two id fields per thread group,
//! updated at separate call sites, and on 2026-08-23 the same mistake was found
//! in two of them a day apart:
//!
//! ```c
//! list_remove(&tgroup->pgroup);
//! tgroup->pgid = pgid;                       // the number the record is for
//! list_add(&pid->pgroup, &tgroup->pgroup);   // the number of whoever asked
//! ```
//!
//! `setpgid` filed a joining process under its own number instead of the
//! group's, and `setsid` called from a non-leader thread filed both records
//! under the calling thread's tid. Both times the *fields* were right, so
//! `getpgid` and `getsid` answered correctly and only a signal to the group
//! showed anything — `send_group_signal` and `pgrp_is_orphaned` walk the list,
//! not the field.
//!
//! Here there is one operation per move and it does the whole move, so the
//! index and the number cannot disagree. `check` asserts that in every test.
//!
//! # What a handle is
//!
//! A `struct tgroup *`, which this never dereferences: it is a key. Lifetime
//! stays with C, and `remove` is what a thread group calls on its way out.
//!
//! # Locking
//!
//! There is no lock *in* this module: `pids_lock` is the one lock over all of
//! it, and a second one would have to be ordered against it for no gain. What
//! changed on 2026-09-16 is that "every entry point runs under `pids_lock`"
//! stopped being a sentence and became a parameter — see the note above the
//! registry API below.

//! How many tasks each user has, and whether one more is allowed.
//!
//! `RLIMIT_NPROC` was defined, given a default of 1024 in `kernel/init.c`, and
//! enforced nowhere. Nothing bounded how many processes a guest could create,
//! and the pid table has `MAX_PID + 1` = 32769 entries — so a guest that forked
//! and never waited filled it with zombies, and `task_create_`'s allocation
//! loop then spun for ever **holding `pids_lock`**. That is not a failed fork;
//! it is the whole emulator, and the application embedding it, stopped.
//!
//! # What it counts
//!
//! Every task, threads included, which is what Linux's `copy_process` does —
//! the check is in the clone path and does not distinguish. And zombies, which
//! is also Linux: the count is dropped in `release_task`, when the parent
//! reaps, not when the process exits. A guest that forks and never waits is
//! exactly the case the limit exists for.
//!
//! # Where it differs from Linux, deliberately
//!
//! Linux moves a process's count between users when its real uid changes, in
//! `set_user()`. This records the uid a task was counted against and drops that
//! one when the task goes, so a process that calls `setuid` still counts
//! against the user it was created by until it exits. Getting the Linux
//! behaviour needs the uid transition to reach here, which means
//! `crates/kernel/creds` calling in; it is written down rather than guessed at.

use std::sync::atomic::Ordering;
use model::{ProcCount, Registry};
use taskview::ffi::{TaskId, TgroupId};
pub use model::{Pid, Table, TaskRef};
use std::ffi::{c_int, c_uint};
mod access;
mod model;

use std::marker::PhantomData;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

// ---------------------------------------------------------------------------
// The registry API. Every entry point takes `&PidsHeld`, which is the proof
// that `pids_lock` is held.
//
// It was a `pids_lock is held` clause -- a `# Safety` section on five of them
// and prose on the other seven -- on twelve *safe* functions until 2026-09-16.
// A contract the signature did not carry and the compiler could not check,
// over two `static mut` that `registry()` and `procs()` handed out as
// `&'static mut` -- two calls without the lock is two `&'static mut` to one
// static, which is the aliasing UB `CLAUDE.md` records a release build hanging
// on in August. Both are a `Mutex` since 2026-10-01; see [`REGISTRY`].
//
// `PidsHeld` cannot be made outside this crate without either holding a
// `PidsGuard` or writing `unsafe` -- its field is private, `PidsGuard::held`
// is free, and `PidsHeld::assume` is the one escape hatch, with one caller.
// So a `&PidsHeld` parameter is the contract, checked.
//
// **The classifier that found these does not see all of them.**
// `clippy::unnecessary_safety_doc` fires on a `# Safety` *heading*, so the
// seven that stated the same rule in prose were invisible to it -- which is
// why `docs/prompts/12` sized this at twelve from a count of five. A rule
// written as prose is a rule no tool can count.
// ---------------------------------------------------------------------------

/// The registry, behind a `Mutex` of its own **inside** `pids_lock`.
///
/// It was a `static mut` handed out as `&'static mut` by this function, sound
/// only because every caller takes a `&PidsHeld` -- and still two live
/// `&'static mut` to one static whenever one caller's borrow outlived its
/// statement. The inner lock is never contended, since `pids_lock` already
/// serialises every caller; what it buys is that the access is sound by
/// construction, and a nested borrow is a deadlock rather than aliasing.
/// `pids_lock` stays the lock that keeps a looked-up task alive.
static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::new()));

fn registry() -> MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The next free pid at or above the cursor, or -EAGAIN when every number is
/// taken. `max` is the highest that may be handed out.
///
/// The `&PidsHeld` **is** the "pids_lock is held" clause that used to be a
/// `# Safety` section here. See the module comment.
///
/// Not `#[unsafe(no_mangle)]` since 2026-09-06. No C source calls it, no
/// `ffi::` reaches it, and no header the embedder example compiles against
/// declares it -- so the export was a second interface with nobody on the
/// other side, and an optimisation barrier: LTO must emit an externally
/// visible function as written and cannot specialise the call.
///
/// **The number is reserved** until [`set_task`] fills it or clears it: the
/// caller builds its task before publishing it, and owes a `set_task` either
/// way.
pub fn pidreg_alloc(_pids: &PidsHeld, max: c_int) -> c_int {
    // -11 is _EAGAIN, which is what Linux answers when it runs out of pids.
    registry().alloc(max).unwrap_or(-11)
}

/// Reserve the number `id` for a new task, as [`pidreg_alloc`] does for one it
/// chooses: 0, or -17 (`_EEXIST`) when it is taken -- Linux's answer to a
/// `set_tid` naming a pid in use.
pub fn pidreg_reserve(_pids: &PidsHeld, id: c_int) -> c_int {
    if registry().reserve(id) { 0 } else { -17 }
}

/// The task at a number, or null.
///
/// # The pointer types are `taskview`'s, and were `c_void` until 2026-09-06
///
/// `kernel/pidreg.h` declares these `struct task *` and `struct tgroup *`;
/// this file declared every one of them `*mut c_void`. Two renderings of one
/// interface that disagreed, and **through the C ABI nothing checked** — a
/// caller got bindgen's typed version from the header and this got the opaque
/// one, and they met at a symbol.
///
/// The registry itself stays opaque: `Table` and `Membership` hold `usize`
/// because a pid is a key and a group handle is an identity, neither of which
/// is dereferenced here. So the erasure happens **once, in
/// the crate that does it on purpose**, rather than at every call site as a
/// `.cast()` the compiler cannot check.
///
/// The identity is never dereferenced here; handing back a pointer is
/// [`TaskId::as_ptr`], which promises nothing about what is at the address —
/// **the `&PidsHeld` the caller passes is what does**, and it is why this is
/// no longer an `unsafe fn`.
pub fn pidreg_task(_pids: &PidsHeld, id: c_int) -> *mut taskview::ffi::task {
    registry()
        .tasks
        .get(id)
        .map_or(std::ptr::null_mut(), TaskId::as_ptr)
}

/// Non-zero if the number could be recorded. A null `task` clears the slot,
/// which is what `task_destroy` does.
pub fn set_task(_pids: &PidsHeld, id: c_int, task: *mut taskview::ffi::task) -> c_uint {
    registry().tasks.set(id, TaskId::from_ptr(task)) as c_uint
}

/// Swap the tasks at two numbers; see [`Table::exchange`].
pub fn exchange(_pids: &PidsHeld, a: c_int, b: c_int) -> bool {
    registry().tasks.exchange(a, b)
}

/// A new thread group starts where its parent is.
pub fn insert_like(_pids: &PidsHeld, group: TgroupId, parent: TgroupId) {
    registry().members.insert_like(group, parent)
}

// `set_pgid` and `set_sid` were free functions over a `TgroupId` until
// 2026-09-30, and `crates/kernel/groupcalls` paired each with a store to the
// group's own cached field. They are [`Group::set_pgid`] and
// [`Group::set_sid`], which do both, so the registry and the field cannot be
// moved apart.

/// Removes a thread group from the process group and session indexes.
pub fn remove(_pids: &PidsHeld, group: TgroupId) {
    registry().members.remove(group)
}

/// How many thread groups are in this process group.
pub fn pidreg_pgroup_len(_pids: &PidsHeld, pgid: c_int) -> c_uint {
    registry().members.pgroup(pgid).len() as c_uint
}

/// The `i`th member, or `None` past the end.
///
/// Indices are stable for as long as `pids_lock` is held and nothing moves a
/// group, which is the same guarantee walking the intrusive list gave.
pub fn pgroup_at(pids: &PidsHeld, pgid: c_int, i: c_uint) -> Option<Group<'_>> {
    let id = *registry().members.pgroup(pgid).get(i as usize)?;
    // SAFETY: a registered group, under the lock `pids` proves is held.
    unsafe { Group::from_raw(pids, id.as_ptr()) }
}

pub fn pidreg_session_len(_pids: &PidsHeld, sid: c_int) -> c_uint {
    registry().members.session(sid).len() as c_uint
}

pub fn session_at(pids: &PidsHeld, sid: c_int, i: c_uint) -> Option<Group<'_>> {
    let id = *registry().members.session(sid).get(i as usize)?;
    // SAFETY: as `pgroup_at`.
    unsafe { Group::from_raw(pids, id.as_ptr()) }
}

/// A thread group, borrowed for as long as `pids_lock` is held.
///
/// What [`Task`] is for a task. A group is freed only under `pids_lock`
/// (`tgroup_release` and `tgroup_free_new` both take a `&PidsHeld`), so one
/// found under the lock stays for as long as the proof does, and the fields
/// read here are the ones that lock or an atomic covers.
///
/// Every read goes through the field rather than a `&tgroup`: the group's
/// threads write other fields of it without this lock, and a shared reference
/// to the whole struct would assert they do not.
#[derive(Clone, Copy)]
pub struct Group<'a> {
    ptr: std::ptr::NonNull<taskview::ffi::tgroup>,
    _held: PhantomData<&'a PidsHeld>,
}

impl<'a> Group<'a> {
    /// # Safety
    /// `group` is null or a live thread group, and `pids` proves the lock
    /// that keeps it live.
    pub unsafe fn from_raw(_pids: &'a PidsHeld, group: *mut taskview::ffi::tgroup) -> Option<Group<'a>> {
        Some(Group {
            ptr: std::ptr::NonNull::new(group)?,
            _held: PhantomData,
        })
    }

    /// The calling task's own group, or `None` for a thread with no task or a
    /// task on its way out.
    ///
    /// Safe: a group is freed only under `pids_lock`, after its last thread
    /// has left it, and the calling thread is one of its threads for as long
    /// as `pids` proves the lock is held. Three crates wrote this as
    /// `unsafe { Group::from_raw(pids, taskview::current_group()) }`.
    pub fn current(pids: &'a PidsHeld) -> Option<Group<'a>> {
        // SAFETY: as above.
        unsafe { Group::from_raw(pids, taskview::current_group()) }
    }

    /// A group the caller already has a reference to -- its own, through
    /// `taskview::with_current_group` -- as a handle. Safe: the reference is
    /// the proof of liveness `from_raw` asks for, and a `&tgroup` is sound
    /// (see its type comment).
    pub fn from_ref(_pids: &'a PidsHeld, group: &'a taskview::ffi::tgroup) -> Group<'a> {
        Group {
            ptr: std::ptr::NonNull::from(group),
            _held: PhantomData,
        }
    }

    /// The group itself, for as long as the lock that keeps it registered.
    ///
    /// A `&tgroup` is sound: every field a thread writes while this is held is
    /// an atomic, its own lock, or locked by `pids_lock` (see the type
    /// comment), and the group is freed only under that lock.
    pub fn tgroup(self) -> &'a taskview::ffi::tgroup {
        // SAFETY: `from_raw`/`from_ref` took a live group and a `&PidsHeld`
        // for `'a`; the group cannot be freed while the lock is held.
        unsafe { self.ptr.as_ref() }
    }

    /// The pointer, for a call that takes one.
    pub fn raw(self) -> *mut taskview::ffi::tgroup {
        self.ptr.as_ptr()
    }

    pub fn id(self) -> TgroupId {
        TgroupId::from_ptr(self.raw()).expect("non-null")
    }

    pub fn sid(self) -> Pid {
        self.tgroup().sid.load(Ordering::Relaxed)
    }

    pub fn pgid(self) -> Pid {
        self.tgroup().pgid.load(Ordering::Relaxed)
    }

    /// The leader, which is written once, before the group is registered.
    pub fn leader(self) -> *mut taskview::ffi::task {
        self.tgroup().leader()
    }

    /// The leader, lent under the same lock: a group's leader is freed with
    /// the group.
    pub fn leader_task(self) -> Option<Task<'a>> {
        Task::new(self.leader())
    }

    /// The leader's pid, or 0 for a group that has none.
    pub fn leader_pid(self) -> Pid {
        self.leader_task().map_or(0, |t| t.pid())
    }

    /// Its `i`th thread, oldest first.
    pub fn thread(self, i: u32) -> Option<Task<'a>> {
        Task::new(proctree::group_at(self.raw(), i))
    }

    /// How many threads it has.
    pub fn thread_count(self) -> u32 {
        proctree::group_len(self.raw())
    }

    /// The group's threads, lent under the same lock; see [`Task::children`].
    pub fn threads(self) -> impl Iterator<Item = Task<'a>> {
        (0..).map_while(move |i| Task::new(proctree::group_at(self.raw(), i)))
    }

    /// The condition variable its threads park on in `wait`, initialised for
    /// every live group.
    pub fn child_exit(self) -> &'a taskview::ffi::cond_t {
        &self.tgroup().child_exit
    }

    /// Whether it asked with `PR_SET_CHILD_SUBREAPER` to collect orphaned
    /// descendants. Locked by this lock.
    pub fn child_subreaper(self) -> bool {
        self.tgroup().attr.child_subreaper()
    }

    /// Whether the group is exiting, and with what status.
    pub fn exit_pending(self) -> Option<u32> {
        self.tgroup().exit.pending()
    }

    /// Whether the group is stopped, and what that reports to `wait`.
    pub fn stop(self) -> &'a taskview::ffi::group_stop {
        &self.tgroup().stop
    }

    /// What its exited threads and reaped children consumed.
    pub fn times(self) -> &'a taskview::ffi::group_rusage {
        &self.tgroup().times
    }

    /// Record that the group did real work just now, for the safety valves.
    pub fn note_progress(self, now_ns: u64) {
        self.tgroup().last_progress_ns.store(now_ns, Ordering::Relaxed);
    }

    /// The resource limits, which are atomic words another thread may store
    /// while this reads.
    pub fn limits(self) -> &'a kernel_rlimitstate::Limits {
        &self.tgroup().limits
    }

    /// The nice value, which is shared by the group's threads here.
    pub fn nice(self) -> std::ffi::c_int {
        self.tgroup().nice()
    }

    pub fn set_nice(self, nice: std::ffi::c_int) {
        self.tgroup().set_nice(nice)
    }

    /// `/proc/<pid>/oom_score_adj`; see `crates/fs/proc`'s `oom`.
    pub fn oom_score_adj(self) -> std::ffi::c_int {
        self.tgroup().oom_score_adj()
    }
    pub fn oom_score_adj_min(self) -> std::ffi::c_int {
        self.tgroup().oom_score_adj_min()
    }

    /// Both together, under `pids_lock`, which the borrow says is held: the
    /// write is a decision over the two old values.
    pub fn set_oom_score_adj(self, adj: std::ffi::c_int, min: std::ffi::c_int) {
        let g = self.tgroup();
        g.oom_score_adj.store(adj, std::sync::atomic::Ordering::Relaxed);
        g.oom_score_adj_min.store(min, std::sync::atomic::Ordering::Relaxed);
    }

    /// The controlling terminal, which the group holds by value.
    pub fn ctty(self) -> &'a taskview::ffi::ctty {
        &self.tgroup().ctty
    }

    /// Moves this group into process group `pgid`: the registry's index and
    /// the group's cached number, which are one fact.
    pub fn set_pgid(self, pgid: Pid) {
        registry().members.set_pgid(self.id(), pgid);
        self.tgroup().pgid.store(pgid, Ordering::Relaxed);
    }

    /// Moves this group into session `sid`, as [`Self::set_pgid`] does.
    pub fn set_sid(self, sid: Pid) {
        registry().members.set_sid(self.id(), sid);
        self.tgroup().sid.store(sid, Ordering::Relaxed);
    }
}

/// Tasks per user, for `RLIMIT_NPROC`. Inside `pids_lock`, as [`REGISTRY`].
static PROCS: LazyLock<Mutex<ProcCount>> = LazyLock::new(|| Mutex::new(ProcCount::new()));

fn procs() -> MutexGuard<'static, ProcCount> {
    PROCS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether the task may be created, taking the count if it may.
///
/// A plain Rust API: `crates/kernel/taskcalls` is the only caller, and was
/// declaring these two by hand across the C ABI once `task_create_` moved —
/// which `tools/extern-signatures.py` checks and `tools/dead-exports.py`
/// reported as a second interface with nobody on the other side.
pub fn proccount_try_add(_pids: &PidsHeld, uid: c_uint, limit: c_uint, exempt: bool) -> bool {
    procs().try_add(uid, limit, exempt)
}

pub fn proccount_remove(_pids: &PidsHeld, uid: c_uint) {
    procs().remove(uid)
}
#[cfg(test)]
#[path = "pids_tests.rs"]
mod tests;

// ---------------------------------------------------------------------------
// The lock over the registry
// ---------------------------------------------------------------------------

/// `pids_lock`, held for the length of a scope.
///
/// What it protects is not only the table. **A task found through the registry
/// can exit and be freed the moment the lock is dropped**, so every caller has
/// to hold it across the lookup *and* the use of what the lookup found — which
/// is why the task is reached through the guard rather than returned from it.
/// The C spelled that as `lock(&pids_lock)` and a matching `unlock` at each
/// exit, and one path in `timer_create` returned in between and left it held:
/// the next fork, exit, wait or kill then waited for ever.
///
/// `tgroup->lock` nests inside this one, which is the order `do_exit_group`
/// establishes.
pub struct PidsGuard {
    _held: locks::mutex::Guard<'static>,
}

/// **The lock is held** — a proof, not an owner.
///
/// Separate from [`PidsGuard`] because two different callers need to say the
/// same thing for different reasons:
///
/// - most callers hold a guard and get one with [`PidsGuard::held`], free;
/// - `crates/fs/ttydev` cannot. It implements `fs-tty`'s `TaskOps`, and
///   `fs/tty` takes `pids_lock` through that very trait before calling back
///   in — so by the time `ttydev` runs, the lock is held by a frame that
///   **cannot name this type**: `kernel-pids` depends on `fs-tty`, so the edge
///   back is a cargo cycle. That one site uses [`PidsHeld::assume`].
///
/// Dropping one releases nothing, which is the whole point: a second type that
/// *did* own the lock would have to carry a "did I take it" flag, and a manual
/// ownership flag is the shape this migration exists to remove.
///
/// `!Sync`, so a `&PidsHeld` cannot vouch for the lock on another thread.
pub struct PidsHeld(PhantomData<*const ()>);

// SAFETY: made only by `PidsGuard::held` and `assume`, both on the thread
// holding `pids_lock`, and `!Sync` keeps the reference there.
unsafe impl locks::mutex::Held for PidsHeld {
    fn held(&self) -> &locks::mutex::lock_t {
        &pids_lock
    }
}

impl PidsGuard {
    /// The proof, from the guard. Free.
    pub fn held(&self) -> &PidsHeld {
        // SAFETY: `PidsHeld` is a zero-sized marker with no invariant beyond
        // "the lock is held", which `self` is the evidence for.
        &PidsHeld(PhantomData)
    }
}

impl PidsHeld {
    /// # Safety
    /// `pids_lock` is held by this thread, and stays held for `'a`.
    ///
    /// **One caller**, `crates/fs/ttydev`, and its justification is a
    /// `fs_tty::ops::PidsHeld` — the token `fs/tty`'s `with_pids_lock` hands
    /// its closure, which that function makes only after taking this lock
    /// through `TaskOps`. The two tokens exist because the dependency edge
    /// between those crates runs one way only.
    pub unsafe fn assume<'a>() -> &'a PidsHeld {
        &PidsHeld(PhantomData)
    }
}

impl PidsGuard {
    /// The calling task's credentials, to change; `None` on a thread with no
    /// task.
    ///
    /// `pids_lock` is the field's lock: every reader of *another* task's
    /// `Creds` holds it (see `crates/kernel/idcalls`' `with_creds_locked`).
    /// `&mut self` is what keeps a `&Creds` this guard lent through
    /// [`Task::creds`] from living beside the `&mut`.
    fn current_creds_mut(&mut self) -> Option<&mut kernel_creds::Creds> {
        // SAFETY: this thread's own live task, the field's lock held for the
        // borrow, and no other borrow from this guard alive.
        unsafe { taskview::current_creds().as_mut() }
    }

    /// Change the calling task's credentials: Linux's `commit_creds`, and
    /// the one way a `set*id`, `setfs*id`, `setgroups` or `execve` writes
    /// them. `None` on a thread with no task.
    ///
    /// A change of identity ([`kernel_creds::Creds::changes_identity`])
    /// leaves the process undumpable, in the same hold of `pids_lock` as the
    /// change: `/proc` reads both under it to decide who may look at the
    /// process. Until 2026-11-12 no credential change touched `dumpable`, so
    /// a root process that called `setuid(65534)` stayed readable by every
    /// other uid-65534 process (`dumpable_probe`).
    pub fn commit_current_creds<R>(&mut self, f: impl FnOnce(&mut kernel_creds::Creds) -> R) -> Option<R> {
        let creds = self.current_creds_mut()?;
        let before = *creds;
        let out = f(creds);
        if creds.changes_identity(&before) {
            taskview::with_current_group(|g| g.attr.on_identity_change());
        }
        Some(out)
    }

    /// Borrow the calling task's credentials for a change that is **not** a
    /// commit: Linux's `override_creds`, which `access(2)` uses to check as
    /// the real ids and then puts back. It does not touch `dumpable`, because
    /// the process never presents the borrowed identity to anyone.
    pub fn override_current_creds<R>(&mut self, f: impl FnOnce(&mut kernel_creds::Creds) -> R) -> Option<R> {
        self.current_creds_mut().map(f)
    }

    pub fn take() -> PidsGuard {
        // Recursion deadlocks rather than being undefined: a default mutex,
        // and `-DLOCK_DEBUG=1` names the site.
        PidsGuard { _held: locks::guard!(&pids_lock) }
    }

    /// The lock if it is free, and `None` rather than a wait.
    ///
    /// **For a signal handler**, which is the one caller: `crates/tools/iul`'s
    /// `IUL_DUMP_ON_SIGTERM` handler walks the registry for each guest thread's
    /// microbenchmark counter, and it runs on whichever thread took the signal
    /// — possibly one already holding this lock, where `take` would be a
    /// self-deadlock and `pthread_mutex_lock` is not async-signal-safe anyway.
    ///
    /// Until 2026-09-16 that handler read the registry with nothing held at
    /// all. A `None` here costs a diagnostic line; a deadlock costs the dump
    /// the handler exists to produce.
    pub fn try_take() -> Option<PidsGuard> {
        // `try_guard!` is the `if` this was not: `then_some` built and dropped
        // a guard -- an unlock -- on the failing branch, releasing a lock
        // another thread held. `a_failed_try_take_leaves_the_holders_lock_held`.
        Some(PidsGuard { _held: locks::try_guard!(&pids_lock)? })
    }

    /// The task with this pid, including a zombie.
    ///
    /// Borrowed from the guard: the handle cannot outlive the lock, and the
    /// lock is what keeps the task alive.
    pub fn find(&self, pid: Pid) -> Option<Task<'_>> {
        // SAFETY: this guard is what holds pids_lock, which is what keeps
        // the task alive. `Table` holds a `TaskId` — an identity, because a
        // pid lookup never dereferences one — and this is the boundary where
        // the lock makes it safe to name the object again.
        Task::new(
            registry()
                .tasks
                .get(pid)
                .map_or(std::ptr::null_mut(), TaskId::as_ptr),
        )
    }

    /// The same, but `None` for a zombie.
    ///
    /// A zombie is a task that has exited and not been reaped. It has no
    /// address space, no descriptor table and no signal state, so almost
    /// everything that looks a task up wants this one — `/proc/<pid>` answers
    /// through [`PidsGuard::find`], which is why the obvious test for the
    /// zombie-reaping bug passed against the bug.
    pub fn find_live(&self, pid: Pid) -> Option<Task<'_>> {
        self.find(pid).filter(|t| !t.is_zombie())
    }

    /// A [`TaskRef`] to the task at `pid` now, zombie included, or `None`.
    /// For something that will look the task up again later, after this
    /// guard is gone.
    pub fn refer(&self, pid: Pid) -> Option<TaskRef> {
        registry().tasks.refer(pid)
    }

    /// The task a reference names, or `None` once it has gone — reaped, or
    /// reaped and its number handed to another.
    pub fn find_by_ref(&self, r: TaskRef) -> Option<Task<'_>> {
        // SAFETY: as `find`.
        Task::new(
            registry()
                .tasks
                .by_ref(r)
                .map_or(std::ptr::null_mut(), TaskId::as_ptr),
        )
    }
}

/// A task the registry is holding, for as long as `pids_lock` is.
///
/// # A `&task`, since 2026-10-16
///
/// It held a raw pointer and lent nothing until that day, because a shared
/// reference asserts that nothing writes the struct while it lives and the
/// task's own thread wrote `task->cpu` on every guest instruction. Every
/// field written after publication is an atomic, a lock, an `UnsafeCell` or an
/// `ArcSlot` now, so the reference is sound and the field reads are safe Rust;
/// what stays `unsafe` is a read through a cell or a slot, each under the rule
/// that field states. The lifetime is the other half: the task is live only
/// while the lock is held.
///
/// The fields it exposes are the ones `pids_lock` covers. Anything under
/// another lock — `task->mm` under `general_lock`, the signal state under
/// `sighand->lock` — needs a second guard.
///
/// # The lifetime is the whole point, and there is no test for it
///
/// Keeping the handle past the guard is what the C spelling allowed —
/// `proc_get_task` returned a pointer and `pids_lock` was released by a
/// separate call — and it is a use-after-free, because a task is not
/// refcounted. This does not compile:
///
/// ```text
/// let task = {
///     let guard = PidsGuard::take();
///     guard.find(1)
/// };                       // the lock is released here
/// let _ = task.unwrap().pid();
/// ```
///
/// A ```` ```compile_fail ```` doctest for it was written and **removed**,
/// because it passed against a version of this struct with no lifetime in it.
/// The reason is worth knowing: a standalone doctest is linked, this crate
/// calls `pids_lock_acquire` out of `kernel/task.c`, and nothing links that
/// for a doctest — so rustdoc counted the *link* error as the expected
/// compile failure and the test was green whatever the code said. It is the
/// shape CLAUDE.md's "a test that passes against nothing" section is about,
/// and it was caught by backing the lifetime out and watching the test stay
/// green.
///
/// What does enforce it is every caller: 25 sites take the guard and the
/// handle together, and a build fails the moment one of them separates them.
#[derive(Clone, Copy)]
pub struct Task<'a> {
    task: &'a taskview::ffi::task,
    _guard: PhantomData<&'a PidsGuard>,
}

impl<'a> Task<'a> {
    /// Private, and every caller passes a pointer the registry or the process
    /// tree answered under the lock `'a` is, or `from_raw`'s caller's.
    fn new(ptr: *mut taskview::ffi::task) -> Option<Task<'a>> {
        // SAFETY: as above -- null or a task `pids_lock` keeps live for `'a`;
        // and a `&task` is sound (see `taskview::with_current_task`).
        let task = unsafe { ptr.as_ref() }?;
        Some(Task { task, _guard: PhantomData })
    }

    /// The task registered at `pid`, zombie included, for as long as `pids`
    /// proves the lock -- [`PidsGuard::find`] for a caller with the proof
    /// rather than the guard.
    pub fn by_pid(pids: &'a PidsHeld, pid: Pid) -> Option<Task<'a>> {
        Task::new(pidreg_task(pids, pid))
    }

    /// The calling thread's task, or `None` for a thread with no task.
    ///
    /// Safe: the task is this thread's and lives for as long as the thread
    /// runs it, which is at least as long as `pids` proves the lock held.
    pub fn current(pids: &'a PidsHeld) -> Option<Task<'a>> {
        // SAFETY: as above.
        unsafe { Task::from_raw(pids, taskview::current()) }
    }

    /// A task found some other way than the registry -- `crates/kernel/proctree`'s
    /// thread and child lists -- lent for as long as `pids` proves the lock.
    ///
    /// # Safety
    /// `ptr` is null or a live task, kept live by the lock `pids` proves.
    pub unsafe fn from_raw(_pids: &'a PidsHeld, ptr: *mut taskview::ffi::task) -> Option<Task<'a>> {
        Task::new(ptr)
    }

    /// The task itself, for as long as the lock keeps it.
    pub fn task(&self) -> &'a taskview::ffi::task {
        self.task
    }

    /// The pointer, for a C call that takes one.
    ///
    /// Every such call is `unsafe` at its own site, which is where the
    /// callee's contract is; this only says the pointer is live.
    pub fn raw(&self) -> *mut taskview::ffi::task {
        std::ptr::from_ref(self.task).cast_mut()
    }

    /// The thread id. Immutable for the life of the task.
    pub fn pid(&self) -> Pid {
        self.task.pid()
    }

    /// The process id — the pid of the thread group leader. Immutable.
    pub fn tgid(&self) -> Pid {
        self.task.tgid.load(Ordering::Relaxed)
    }

    /// Whether this is the thread group leader, which is what every
    /// process-level operation checks.
    pub fn is_leader(&self) -> bool {
        self.pid() == self.tgid()
    }

    /// The thread group, or `None` for a task on its way out. The group
    /// outlives its threads under pids_lock.
    pub fn group(&self) -> Option<Group<'a>> {
        // SAFETY: the group is live under the lock `'a` is.
        unsafe { Group::from_raw(&PidsHeld(PhantomData), self.task.group.load(Ordering::Acquire)) }
    }

    /// The credentials, which are locked by pids_lock — this guard.
    ///
    /// Typed, because `struct task` holds a `Creds` by value and both sides of
    /// this call are Rust. It was `*mut c_void` while `kernel/task.h` reserved
    /// bytes for a struct C could not see.
    ///
    /// A reference since 2026-09-30: every writer -- the `set*id` calls,
    /// `faccessat`'s fs-id swap and a setuid `execve` -- holds this lock, so
    /// no byte of the struct changes while the borrow lives.
    pub fn creds(&self) -> &'a kernel_creds::Creds {
        // SAFETY: the field's writers hold the lock `'a` is.
        unsafe { &*self.task.creds.get() }
    }

    /// The per-thread attributes -- the name, the parent-death signal --
    /// as a copy taken under their lock.
    pub fn attr(&self) -> taskview::ffi::thread_attr {
        *locks::locked!(self.attr_lock())
    }

    /// The same, to change under their lock.
    pub fn with_attr_mut<R>(&self, f: impl FnOnce(&mut taskview::ffi::thread_attr) -> R) -> R {
        f(&mut locks::locked!(self.attr_lock()))
    }

    fn attr_lock(&self) -> &'a locks::mutex::Mutex<taskview::ffi::thread_attr> {
        &self.task.attr
    }

    /// The name `prctl(PR_SET_NAME)` and `execve` give it, as a string.
    pub fn comm(&self) -> String {
        self.with_attr_mut(|a| String::from_utf8_lossy(a.name()).into_owned())
    }

    /// When it started, in ticks since boot. Written once, before the task
    /// is published.
    pub fn start_ticks(&self) -> u64 {
        self.task.start_ticks()
    }

    /// The `sched_setaffinity` mask, 0 for "never set". Locked by this lock.
    pub fn cpu_affinity(&self) -> u64 {
        self.task.cpu_affinity.load(Ordering::Relaxed)
    }

    /// Its descriptor table, with a reference of the caller's own, or `None`
    /// once it has exited. Every store of null -- `do_exit`, the group-exit
    /// valve, a failed fork -- holds this lock, which is what makes the clone
    /// here more than a resurrection.
    pub fn files(&self) -> Option<std::sync::Arc<taskview::ffi::fdtable>> {
        // SAFETY: every taker of the slot holds the lock `'a` is.
        unsafe { self.task.files.clone_arc() }
    }

    /// Its filesystem context -- cwd, root, umask -- by the same rule as
    /// [`Self::files`].
    pub fn fs(&self) -> Option<&'a taskview::ffi::fs_info> {
        // SAFETY: as `files`.
        unsafe { self.task.fs.as_ptr().as_ref() }
    }

    /// Stores a new mask. A plain word, and every reader and writer holds
    /// this lock; nothing borrows the field, so the write aliases nothing.
    pub fn set_cpu_affinity(&self, mask: u64) {
        self.task.cpu_affinity.store(mask, Ordering::Relaxed);
    }

    /// Whether it has called `execve` since it was forked, which is what
    /// makes a child's process group its own to change. Locked by pids_lock.
    pub fn did_exec(&self) -> bool {
        self.task.did_exec.get()
    }

    /// Its tracing state, which is allocated with the task and lives as long
    /// as it does.
    pub fn ptrace(&self) -> Option<&'a taskview::ffi::ptrace_state> {
        self.task.ptrace.as_deref()
    }

    /// Its signal table, its queue and its process's shared set, or `None`
    /// for a task whose table the group-exit valve has taken or that has no
    /// group.
    pub fn signal_queue(&self) -> Option<kernel_sighand::Queue<'a>> {
        let shared = self.group()?.tgroup().shared_signals.get();
        // SAFETY: the queue lives as long as the task and the set as long as
        // its group, which outlives it under this lock; both are written under
        // `hand`'s lock, which `Queue` takes.
        self.sighand().map(|hand| unsafe { kernel_sighand::Queue::new(hand, self.task.signals.get(), shared) })
    }

    /// The address space, as a pointer: retaining it needs `general_lock`,
    /// which is not this lock -- `execve` swaps it holding only that one.
    /// `taskcalls::GeneralGuard::mm` is the retain.
    pub fn mm(&self) -> *mut taskview::ffi::mm {
        self.task.mm.as_ptr().cast_mut()
    }

    /// Send `sig` to the host thread running this task; nothing before the
    /// thread has started. While the lock is held the task is live, so the
    /// thread id has not been reused.
    pub fn kill_host_thread(&self, sig: c_int) {
        if let Some(thread) = self.task.thread.get() {
            // SAFETY: a thread id this task's thread set, still running it.
            unsafe { libc::pthread_kill(thread, sig) };
        }
    }

    /// Its signal dispositions, or `None` once it has given them up. Every
    /// writer of the field holds this lock, so the table outlives the borrow.
    pub fn sighand(&self) -> Option<&'a kernel_sighand::SigHand> {
        // SAFETY: as above -- the slot is not emptied while `'a` lasts.
        unsafe { self.task.sighand.as_ptr().as_ref() }
    }

    /// Mark it a zombie: exited, not yet reaped. Written under this lock.
    pub fn mark_zombie(&self) {
        self.task.zombie.set(true);
    }

    /// Whether the task is asleep in a system call: what `/proc` reports as
    /// `S`. Written by the task's own thread, so a reader may see it one
    /// transition stale.
    pub fn is_blocked(&self) -> bool {
        self.task.blocking.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the task has exited and not been reaped. Locked by pids_lock.
    pub fn is_zombie(&self) -> bool {
        self.task.zombie.get()
    }

    /// Whether it has started to exit. Set by its own `do_exit` and by the
    /// group-exit valve, both under this lock.
    pub fn is_exiting(&self) -> bool {
        self.task.exiting.get()
    }

    /// The status its own `exit` recorded, which is final once it is a zombie.
    pub fn exit_code(&self) -> u32 {
        self.task.exit_code.load(Ordering::Relaxed)
    }

    /// The signal its parent is sent when it exits: `SIGCHLD` for a process,
    /// something else for a `clone` child. Set at creation.
    pub fn exit_signal(&self) -> c_int {
        self.task.exit_signal.load(Ordering::Relaxed)
    }

    /// Whether this is its group's leader, by identity rather than by number.
    pub fn leads_group(&self) -> bool {
        self.group().is_some_and(|g| g.leader() == self.raw())
    }

    /// This task's children, lent under the same lock.
    ///
    /// Read by index, one `child_at` per step, so an iteration stays valid
    /// across a child that is reparented behind it -- but not across one
    /// that is freed, which the caller does only as its last step.
    pub fn children(self) -> impl Iterator<Item = Task<'a>> {
        (0..).map_while(move |i| Task::new(proctree::child_at(self.raw(), i)))
    }

    /// The parent, or `None` for init and for a task that has been detached.
    pub fn parent(self) -> Option<Task<'a>> {
        Task::new(proctree::parent(self.raw()))
    }

    /// The real uid, which `wait` reports. Locked by pids_lock.
    pub fn uid(&self) -> u32 {
        self.creds().uid()
    }
}

impl PidsGuard {
    /// The calling task, lent under this guard, or `None` on a thread that
    /// has none.
    pub fn me(&self) -> Option<Task<'_>> {
        Task::new(taskview::current())
    }

    /// How many pid numbers hold a task. What `sysinfo`'s `procs` reports.
    pub fn task_count(&self) -> usize {
        registry().tasks.used()
    }

    /// Every thread group in this process group, oldest first.
    ///
    /// The identities name groups that are alive for as long as this guard is
    /// held and no longer, which is the caller's reason to be holding it.
    pub fn pgroup(&self, pgid: Pid) -> Vec<TgroupId> {
        registry().members.pgroup(pgid).to_vec()
    }
}

/// `pids_lock`, which every entry point above runs under.
///
/// **What it protects is not only the table.** A task found through it can exit
/// and be freed the moment the lock is dropped, so every caller holds it across
/// the lookup *and* the use — which is what [`PidsGuard`] makes the only shape a
/// Rust caller can write.
///
/// It was `kernel/task.c`'s until 2026-09-06, as a `lock_t` with a
/// `PTHREAD_MUTEX_INITIALIZER`, because a crate could not take one without
/// mirroring the layout or calling in. `crates/util/locks` is the acquire now
/// and the layout is still generated, so neither is needed.
///
/// **A `static`, not a `static mut`, since 2026-09-16.** `CLAUDE.md`'s survey
/// of the tree's 26 `static mut` listed this one under "a global lock is held",
/// which is a reason for the *writes* and not for the item: what actually kept
/// it was that taking `&pids_lock` was denied by `static_mut_refs`, so every
/// use spelled `&raw mut pids_lock`. `lock_t` carries its own `UnsafeCell` and
/// its own `Sync` now, so a shared reference to it is the ordinary thing and
/// there is no mutable global left here. The symbol does not move: a `static`
/// whose type has interior mutability is still writable data.
#[unsafe(no_mangle)]
pub static pids_lock: locks::mutex::lock_t = locks::mutex::lock_t::new();

// `pids_lock_ref` was here until 2026-10-17, for `waitcalls`' wait to name the
// lock it parks under; a `&PidsHeld` is that now (`locks::mutex::Held`).

/// Whether this thread holds `pids_lock`.
///
/// **Not for deciding anything** — a thread that has to ask whether it holds a
/// lock has lost track of its own protocol. It is for asserting the one rule
/// that has no other home: *nothing that waits may run under this lock*.
/// `crates/kernel/exitcalls`' `Deferred` uses it, and
/// `docs/changelog/2026-09-16-the-exit-path-waited-for-a-timer-under-the-lock-the-timer-needed.md`
/// is the deadlock that made the rule worth checking rather than writing down.
///
/// `lock_t` tracks its owner unconditionally, so this is a load and a compare
/// and needs no `-DLOCK_DEBUG=1` — which matters, because that build is the one
/// nobody runs by default and this rule is broken on a path that is.
pub fn held_by_this_thread() -> bool {
    locks::mutex::held_by_this_thread(&pids_lock)
}

// A `__mod_init_func` constructor initialised `pids_lock` before `main` until
// 2026-10-16, with a flag and a startup assertion that it had run, because a
// zeroed static is not a mutex on Darwin. `lock_t::new` is
// `PTHREAD_MUTEX_INITIALIZER` in a `const fn`, so the static is ready as
// written.

/* `pids_lock_acquire` and `pids_lock_release` were here until 2026-10-01: an
 * `unsafe fn` pair whose last caller outside [`PidsGuard`] was
 * `crates/fs/ttydev`'s `TaskOps`, which takes a `PidsGuard` now. */
