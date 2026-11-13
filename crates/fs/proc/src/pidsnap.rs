//! What `/proc/<pid>/stat`, `status` and `limits` report out of the task.
//!
//! **The copy is the point.** The C read a field, formatted it, read the next —
//! around forty `proc_printf` calls, each of which can reallocate the output
//! buffer — with `pids_lock`, `general_lock`, the thread group's lock and
//! `sighand`'s lock all held. `pids_lock` alone is what `fork`, `exit`, `wait`
//! and `kill` need. So a snapshot is taken under the locks and nothing is
//! formatted under them; [`super::pid`] does the formatting from a value it
//! owns.
//!
//! This was `fs/proc/pid.c` and is Rust because every field it reads is either a
//! `struct task` field — generated, so there is no accessor for it — or a call
//! into a crate that is already Rust: `sighand`, `groupstop`, `proctree`,
//! `creds`, `procattr`, `ctty`, `tty`, `fdtable`, `sigqueue`, `rlimit`. The C
//! was the code joining them, which is the shape a family moves in.
//!
//! # The lock order, and the deadlock it avoids
//!
//! This file used to hold `sighand->lock` across the whole snapshot, and to take
//! it *below* the thread group's lock — the opposite of the order the signal
//! path took them, since `receive_signals` holds `sighand->lock` and called
//! `receive_signal`, which took the group's underneath it for a stopping signal.
//! `pids_lock` did not serialise the two: this side holds it for the whole
//! snapshot and `receive_signals` never takes it at all. A guest reading
//! `/proc/<pid>/stat` while that process was being stopped deadlocked.
//!
//! The inversion is gone rather than reordered: everything needed from `sighand`
//! comes out in **one call**, before anything else is taken. The group's lock has
//! since gone entirely.
//!
//! # The page-table walk happens with nothing held
//!
//! `vsize`, the rss numbers and the segment breakdown all cost a walk of the
//! whole page table, and doing that under `pids_lock` is the mistake
//! `docs/changelog/2026-08-22-proc-pid-stat-snapshot.md` records. Every one of
//! them is filled after the guard has been dropped.

use pagetable::memlock::Held;
use std::ffi::{c_int, c_uint};

use crate::ffi;

use fs_devices::dev_make;
use kernel_pids::{Group, PidsGuard, Task};

/// The largest supplementary-group list `/proc/<pid>/status` will print.
///
/// `Groups` holds 32, which is `MAX_GROUPS` in `kernel/task.h`; this is the
/// bound on the copy, so a longer list one day is truncated rather than
/// overflowing.
pub const MAX_GROUPS: usize = 32;

/// The task `/proc/<pid>` is about, found through the pid table with that
/// table's lock **held** for as long as this exists.
///
/// **The lock is what keeps the task alive.** Tasks are not refcounted, so a
/// pointer found through the registry can be freed the moment the lock is
/// dropped; holding the guard across the lookup *and* the use is the only
/// shape this can be written in. The C spelled it as `proc_get_task` returning
/// with `pids_lock` held and a `proc_put_task` at each exit, and every reader
/// in this crate went through that pair until 2026-09-04 -- a put that an early
/// return forgets is a lock held for ever. A guard cannot be forgotten, and
/// [`Found::task`] lends a handle whose borrow cannot outlive the guard.
///
/// `None` when there is no such task or when it is mid-exit: between `exiting`
/// and `zombie` a thread is giving up its address space, its descriptors and
/// its signal state, and nothing here may look at them. **A zombie is
/// answered**, since 2026-09-04. It has none of those things either, and every
/// reader below says what it answers without them -- which is what Linux
/// answers: a `Z` in `stat`, an empty `cmdline`, an `ESRCH` from `environ`. It
/// was rejected before, so an unreaped child was not in `/proc` at all, `ps`
/// could not show a `<defunct>` process, and the obvious test for the
/// zombie-reaping bug passed against the bug.
///
/// One definition, shared by every `/proc/<pid>` entry — which tasks this
/// answers for is one rule.
///
/// # Why it lends a handle and not a `&task`
///
/// It lent a `&task` from 2026-09-04 until 2026-09-05, and that was unsound: a
/// shared reference asserts that **nothing** writes the struct while it lives,
/// and the task's own thread writes `task->cpu` on every guest instruction it
/// interprets. `pids_lock` does not stop that; nothing does, because the CPU
/// state is the running thread's own. `task->mm` has the same shape one level
/// down — `brk` writes it under `general_lock`, and a `&mm` covers the whole
/// struct.
///
/// So it copied the fields out, into a `TaskFields` of raw pointers, until
/// 2026-09-30. It lends a [`kernel_pids::Task`] now, whose every accessor reads
/// one field under the lock that covers it and says which, and whose lifetime
/// is this guard's. It holds the **pid** rather than the pointer and finds the
/// task again for each loan: the lookup is a hash probe, and it means nothing
/// here turns a raw pointer back into a task.
pub(crate) struct Found {
    pid: ffi::pid_t_,
    pids: PidsGuard,
}

impl Found {
    /// The task `/proc/<pid>` is about, or `None`.
    pub(crate) fn get(entry: &mut ffi::proc_entry) -> Option<Found> {
        Found::for_pid(entry.pid)
    }

    /// The same, for a caller that has a pid rather than an entry —
    /// `crates/fs/proc`'s `net` module walks the pid space and has no entry.
    pub(crate) fn for_pid(pid: ffi::pid_t_) -> Option<Found> {
        let pids = PidsGuard::take();
        let task = pids.find(pid)?;
        if (task.is_exiting() && !task.is_zombie()) || task.group().is_none() {
            return None;
        }
        Some(Found { pid, pids })
    }

    /// The task, lent for as long as this holds the lock.
    pub(crate) fn task(&self) -> Task<'_> {
        self.pids.find(self.pid).expect("a task found under this guard is still there")
    }

    /// Its thread group, which [`Found::for_pid`] checked is there; a group
    /// outlives its tasks under `pids_lock`.
    pub(crate) fn group(&self) -> Group<'_> {
        self.task().group().expect("checked under this guard")
    }
}

/// Who owns `/proc/<pid>`'s entry of this mode: Linux's `task_dump_owner`.
///
/// The task's **effective** ids -- the real ones until 2026-11-12, so a
/// setuid program's directory belonged to the user who ran it -- except that
/// a process that is not dumpable, or a zombie, which has no address space to
/// be dumpable about, has its entries owned by root. That is what keeps one
/// user out of another's `environ`, `maps` and `fd` once the process has
/// changed identity. The per-process directories that are `dr-xr-xr-x`
/// (`/proc/<pid>` itself, `task`, `fdinfo`) keep the task's ids regardless:
/// Linux exempts exactly that mode, because tools read a process's effective
/// uid off the directory's owner. Measured by `dumpable_probe`.
///
/// `None` when there is no such task.
pub(crate) fn dump_owner(pid: ffi::pid_t_, mode: u32) -> Option<(u32, u32)> {
    const PER_PROCESS_DIR: u32 = libc::S_IFDIR as u32 | 0o555;
    const SUID_DUMP_USER: c_int = 1;
    let found = Found::for_pid(pid)?;
    let task = found.task();
    let hidden = task.is_zombie() || found.group().tgroup().attr.dumpable() != SUID_DUMP_USER;
    if mode != PER_PROCESS_DIR && hidden {
        return Some((0, 0));
    }
    let creds = task.creds();
    Some((creds.euid(), creds.egid()))
}

/// How many threads `stat` and `status` report. A zombie has left its group's
/// thread list and is still one thread, which is what Linux's `nr_threads`
/// says for it until it is reaped.
fn thread_count(group: Group<'_>) -> i64 {
    i64::from(group.thread_count()).max(1)
}

/// How many threads `pid`'s process has, for `task`'s link count.
pub(crate) fn threads(pid: ffi::pid_t_) -> Option<i64> {
    Found::for_pid(pid).map(|f| thread_count(f.group()))
}

/// `task->general_lock`, held for a scope.
///
/// It guards `task->mm` across the swap `execve` does. Reading `task->mm`
/// without it and then retaining is a resurrection: the refcount may already
/// have reached zero.
///
/// The definition moved to `crates/kernel/taskcalls`, which owns the lock,
/// when `crates/kernel/procvmcalls` needed the same rule and was written
/// without it. A rule enforced by a guard that each caller writes out is
/// enforced once per copy.
pub(crate) use taskcalls::GeneralGuard as General;

/// The shared guard takes a raw pointer and says what it needs; a [`Found`]
/// is what meets it, so this takes one rather than a pointer.
pub(crate) fn general_of(found: &Found) -> General<'_> {
    // Nothing in this crate holds a `general_lock` while taking another.
    General::of(found.task().task())
}

/// The state character. No sleep state is visible to this kernel, so anything
/// that is neither a zombie nor stopped reports `R`.
fn state_of(found: &Found) -> u8 {
    if found.task().is_zombie() {
        b'Z'
    } else if found.group().stop().is_stopped() {
        b'T'
    } else if found.task().is_blocked() {
        // Every live task was `R` until 2026-10-18, so `ps` showed a shell
        // waiting for its child as running (`tests/guest` proc_state).
        b'S'
    } else {
        b'R'
    }
}

fn parent_pid(task: Task<'_>) -> c_int {
    task.parent().map_or(0, |p| p.pid())
}

/// The four signal masks, in **one** acquisition of `sighand`'s lock. See the
/// module comment. Zeroes for a task whose table has gone, as the old entry
/// point answered.
fn signal_masks(task: Task<'_>) -> kernel_sighand::SignalStatus {
    task.signal_queue().map_or_else(Default::default, |queue| queue.status_snapshot())
}

/// What `/proc/<pid>/stat` reports.
#[derive(Default)]
pub struct PidStat {
    pub pid: c_int,
    pub comm: String,
    pub state: u8,
    pub ppid: c_int,
    pub pgid: c_int,
    pub sid: c_int,
    pub tty_dev: c_int,
    pub tty_pgrp: c_int,
    pub nthreads: i64,
    pub stack_start: u64,
    pub pending: u64,
    pub blocked: u64,
    pub ignored: u64,
    pub caught: u64,
    pub exit_signal: c_int,
    pub nice: c_int,
    /// Fields 23 and 24, which used to be hardcoded zeroes — so `ps` reported
    /// VSZ 0 for every process. `vsize` is bytes and `rss` is pages, which is
    /// how Linux writes them.
    pub vsize: u64,
    pub rss_pages: u64,
    /// Field 22, in hundredths of a second since boot. Zero here dated every
    /// process to the boot, so `ps -o etime` gave each one the machine's whole
    /// uptime as its age.
    pub start_ticks: u64,
    /// Fields 47–51: where the argument and environment strings are. A reader
    /// that wants a command line without opening `/proc/<pid>/cmdline` takes
    /// them from here, and 48–51 were simply absent — the line stopped at 39
    /// where Linux writes 52.
    pub start_brk: u64,
    /// Fields 26, 27, 45 and 46, which were zero until 2026-11-12: nothing
    /// recorded where the code and data were.
    pub code: (u64, u64),
    pub data: (u64, u64),
    /// Whether the reader has ptrace access to the task, Linux's `permitted`
    /// in `do_task_stat`: without it the addresses, `wchan` and the exit code
    /// are blanked (`procaccess_probe`). They were shown to anyone.
    pub permitted: bool,
    /// Whether the address space is there; a zombie has none, and Linux's
    /// `startcode` and `endcode` say 0 for it rather than the 1 a reader
    /// without access gets.
    pub has_mm: bool,
    /// Field 35, `wchan`: 1 for a task asleep, which Linux has said instead
    /// of an address since 5.16 -- to a reader with access, and for the
    /// process's own file only while it has one thread.
    pub wchan: bool,
    pub arg_start: u64,
    pub arg_end: u64,
    pub env_start: u64,
    pub env_end: u64,
    pub exit_code: c_int,
}

pub fn stat(entry: &mut ffi::proc_entry) -> Option<PidStat> {
    let mut out = PidStat::default();
    let mm;
    {
        let found = Found::get(entry)?;
        let task = found.task();
        let general = general_of(&found);
        let masks = signal_masks(task);
        let group = found.group();
        out.pid = task.pid();
        out.comm = task.comm();
        out.state = state_of(&found);
        out.ppid = parent_pid(task);
        out.pgid = group.pgid();
        out.sid = group.sid();
        out.nthreads = thread_count(group);
        out.exit_signal = task.exit_signal();
        out.nice = group.nice();
        out.start_ticks = task.start_ticks();
        out.permitted = crate::pidentry::may_read(&found);
        let whole = entry.pid == task.tgid();
        out.wchan = out.permitted && (!whole || out.nthreads < 2) && !matches!(out.state, b'R');
        out.exit_code = if task.is_zombie() {
            task.exit_code() as c_int
        } else {
            0
        };
        // The thread's own pending set only, and every mask cut to 31 bits:
        // Linux's `& 0x7fffffffUL`, "for Linux 2.0 compatibility". This cut
        // two of them at 32 and the other two not at all.
        const STAT_MASK: u64 = 0x7fff_ffff;
        out.pending = masks.pending & STAT_MASK;
        out.blocked = masks.blocked & STAT_MASK;
        out.ignored = masks.ignored & STAT_MASK;
        out.caught = masks.caught & STAT_MASK;

        // The address space is **retained** here and read below, outside every
        // lock this block holds. See `read_mm_fields`.
        mm = general.mm();

        // With a reference of this reader's own. It was `peek`, an identity
        // turned back into a pointer and read through: sound only because
        // every path that gives a group's terminal up holds `pids_lock` too,
        // which nothing here said. The reference is dropped under
        // `pids_lock`, as `steal_controlling`'s are, and cannot be the last
        // while the group holds its own.
        match group.ctty().retain() {
            // -1, not 0, when there is no controlling terminal -- that is
            // what Linux writes, and 0 is a process group `ps` would
            // attribute the terminal to.
            None => {
                out.tty_dev = 0;
                out.tty_pgrp = -1;
            }
            Some(user) => {
                let tty = user.tty();
                out.tty_dev = dev_make(tty.kind.major() as u32, tty.num as u32) as c_int;
                out.tty_pgrp = tty.foreground_group();
            }
        }
    }
    // Outside every lock above; see the module comment.
    out.has_mm = mm.is_some();
    if let Some(mm) = mm {
        read_mm_fields(&mm, &mut out);
    }
    let (total, resident, _shared) = statm_counts(entry);
    out.vsize = total * ffi::PAGE_SIZE as u64;
    out.rss_pages = resident;
    Some(out)
}

/// The six address-space fields `/proc/<pid>/stat` reports, **under the lock
/// their writers hold**.
///
/// They were read inside `general_lock` with the comment "Immutable once execve
/// has set them, and read here under the same general_lock the rest of this
/// snapshot takes". Neither half was true. `crates/kernel/execcalls`'
/// `place_image` and `finish_stack` write all six, holding `mem->lock` for
/// writing and **after** `execve` has already published the space; `sys_brk`
/// writes `brk` under the same lock. `general_lock` is what makes the *object*
/// live — it is what `execve` holds across the swap — and it says nothing about
/// whether a field is raced on. Running the two together is the mistake this
/// tree made four times in two days; see
/// `docs/object-model-arc.md`'s 9.5 survey.
///
/// `arg_start`/`arg_end` and `env_start`/`env_end` are **pairs**, which is what
/// makes it more than a stale word: a reader that catches one of each image
/// reports a range that never existed.
///
/// Read here rather than in the block above so that no new lock order is
/// created. The caller retains the space under `general_lock` and releases it
/// after, which is the shape `crates/fs/proc`'s `Space` already uses for
/// exactly this reason — nesting `mem->lock` inside `general_lock` would be a
/// new order, and `mem->lock → pids_lock` already exists through a descriptor
/// teardown under `pt_unmap_always`.
fn read_mm_fields(mm: &mmapcalls::mm::MmRef, out: &mut PidStat) {
    let held = mm.read();
    let image = held.image();
    out.stack_start = image.stack_start;
    out.start_brk = image.start_brk;
    out.code = image.code;
    out.data = image.data;
    (out.arg_start, out.arg_end) = image.argv;
    (out.env_start, out.env_end) = image.env;
}

/// What `/proc/<pid>/status` reports.
///
/// Name-keyed rather than positional, unlike `stat` — so a field this cannot
/// answer is *omitted* rather than present and zero. A reader looks fields up by
/// name and a wrong number is worse than an absent one.
#[derive(Default)]
pub struct PidStatus {
    pub comm: String,
    pub state: u8,
    pub umask: c_uint,
    pub tgid: c_int,
    pub pid: c_int,
    pub ppid: c_int,
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    pub fdsize: u64,
    pub groups: Vec<u32>,
    pub nthreads: i64,
    /// Whether the task still has filesystem state and an address space. A
    /// zombie has neither, and the lines that describe them -- `Umask`, and
    /// `VmPeak` through `untag_mask` -- are *omitted* for it, as Linux omits
    /// them, rather than printed as zeroes.
    pub has_fs: bool,
    pub has_mm: bool,
    pub vm_size_kb: u64,
    pub vm_rss_kb: u64,
    /// The breakdown `ps`, `top` and every memory monitor reads. Classified by
    /// page flags and the mm's own segment boundaries, in the same walk that
    /// produces `vm_size_kb` — there was no breakdown at all, so
    /// `/proc/<pid>/status` had 21 fields where Linux has 58.
    pub vm_data_kb: u64,
    pub vm_stk_kb: u64,
    pub vm_exe_kb: u64,
    pub vm_lib_kb: u64,
    pub rss_anon_kb: u64,
    pub rss_file_kb: u64,
    pub rss_shmem_kb: u64,
    /// The pid as each namespace sees it. There are no pid namespaces here, so
    /// every view is the outer one — which is what a single-namespace Linux
    /// reports too, and what a container runtime reading `NSpid` compares.
    pub nstgid: c_int,
    pub nspid: c_int,
    pub nspgid: c_int,
    pub nssid: c_int,
    pub pending: u64,
    pub shd_pending: u64,
    pub blocked: u64,
    pub ignored: u64,
    pub caught: u64,
    pub cpus_allowed: u64,
    /// The five capability sets, read with the ids under `pids_lock`.
    pub caps: Option<kernel_creds::caps::Caps>,
    /// Queued signals and the limit on them, which is what `SigQ` reports as
    /// `queued/limit`.
    pub sigq_count: u64,
    pub sigq_limit: u64,
    pub vol_ctxt: u64,
    pub nonvol_ctxt: u64,
    pub no_new_privs: bool,
    /// `Seccomp:` and `Seccomp_filters:`.
    pub seccomp_mode: u8,
    pub seccomp_filters: usize,
}

pub fn status(entry: &mut ffi::proc_entry) -> Option<PidStatus> {
    let mut out = PidStatus::default();
    {
        let found = Found::get(entry)?;
        let task = found.task();
        let _general = general_of(&found);
        let masks = signal_masks(task);
        let group = found.group();
        let creds = task.creds();
        out.comm = task.comm();
        out.state = state_of(&found);
        out.tgid = task.tgid();
        out.pid = task.pid();
        out.ppid = parent_pid(task);
        out.uid = creds.uid();
        out.euid = creds.euid();
        out.suid = creds.suid();
        out.gid = creds.gid();
        out.egid = creds.egid();
        out.sgid = creds.sgid();
        // The fs ids, which `setfsuid` moves away from the effective ones.
        // They were the effective ids here, under a comment saying setfsuid
        // was not implemented, long after it was (`dumpable_probe`).
        out.fsuid = creds.fsuid();
        out.fsgid = creds.fsgid();
        out.nthreads = thread_count(group);
        let fs = task.fs();
        out.has_fs = fs.is_some();
        out.has_mm = !task.mm().is_null();
        out.nstgid = out.tgid;
        out.nspid = out.pid;
        out.nspgid = group.pgid();
        out.nssid = group.sid();
        out.pending = masks.pending;
        out.shd_pending = masks.shared;
        out.blocked = masks.blocked;
        out.ignored = masks.ignored;
        out.caught = masks.caught;
        out.cpus_allowed = if task.cpu_affinity() != 0 {
            task.cpu_affinity()
        } else {
            rescalls::sched_all_cpus_mask()
        };

        if let Some(fs) = fs {
            out.umask = fs.umask();
        }
        if let Some(files) = task.files() {
            out.fdsize = files.size() as u64;
        }

        // The slice itself, where this took a length and a pointer from two
        // calls and put them back together with `from_raw_parts` -- and then
        // tested the pointer for null, which the address of a field cannot be.
        let list = creds.groups().as_slice();
        out.groups = list[..list.len().min(MAX_GROUPS)].to_vec();

        // Under `sighand->lock`, as `signal_masks` reads the masks: the queue
        // is not internally locked. It was read through a bare `&Signals`
        // until 2026-10-16, racing the delivery that holds the lock.
        out.sigq_count = task.signal_queue().map_or(0, |q| q.lock().queue().queued()) as u64;
        if let Some(sigpending) = group.limits().get(ffi::RLIMIT_SIGPENDING_) {
            out.sigq_limit = sigpending.cur;
        }
        out.caps = Some(*creds.caps());
        out.no_new_privs = task.attr().no_new_privs();
        let seccomp = &task.task().seccomp;
        out.seccomp_mode = seccomp.mode();
        // SAFETY: `pids_lock` is held for this block, which is what `TSYNC`
        // replaces another thread's chain under.
        out.seccomp_filters = unsafe { seccomp.filter_count() };
    }
    // Outside every lock above; see the module comment.
    let kb = ffi::PAGE_SIZE as u64 / 1024;
    if let Ok(c) = crate::pidmem::vm_counts(entry) {
        out.vm_size_kb = c.total * kb;
        out.vm_rss_kb = c.resident * kb;
        // `shared` is counted and status does not report it.
        out.vm_data_kb = c.data * kb;
        out.vm_stk_kb = c.stack * kb;
        out.vm_exe_kb = c.exe * kb;
        out.vm_lib_kb = c.lib * kb;
        out.rss_anon_kb = c.rss_anon * kb;
        out.rss_file_kb = c.rss_file * kb;
        out.rss_shmem_kb = c.rss_shmem * kb;
    }
    Some(out)
}

/// The sixteen rlimits, in `RLIMIT_*` order, which is the order
/// `/proc/<pid>/limits` lists them in. The names and units are presentation and
/// live in [`super::pid`].
pub fn limits(entry: &mut ffi::proc_entry) -> Option<Vec<(u64, u64)>> {
    let found = Found::get(entry)?;
    let limits = found.group().limits();
    let mut out = Vec::with_capacity(ffi::RLIMIT_NLIMITS_ as usize);
    for i in 0..ffi::RLIMIT_NLIMITS_ {
        // A resource this build does not know is reported as the zero pair,
        // which is what the out-parameter's untouched default answered.
        let v = limits.get(i).unwrap_or_default();
        out.push((v.cur, v.max));
    }
    Some(out)
}

/// Mapped and resident page counts, with a *reference* to the address space
/// rather than the pid lock. Zero when there is no such task.
fn statm_counts(entry: &mut ffi::proc_entry) -> (u64, u64, u64) {
    match crate::pidmem::vm_counts(entry) {
        Ok(c) => (c.total, c.resident, c.shared),
        Err(_) => (0, 0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_terminal_number_is_packed_the_way_fs_dev_h_packs_one() {
        // This file had its own copy of `dev_make` and it was the obvious
        // encoding rather than Linux's, so /proc/<pid>/stat reported a terminal
        // number `ps` attributes to nothing. One definition now, in
        // crates/fs/devices, with the round-trip test.
        assert_eq!(dev_make(4, 1), 0x401);
        assert_eq!(dev_make(136, 3), (136 << 8) | 3);
        assert_eq!(dev_make(0, 0), 0);
    }

    #[test]
    fn the_group_list_is_bounded_by_what_status_prints() {
        // `Groups` holds MAX_GROUPS in kernel/task.h and this is the copy's
        // bound; the two agreeing is what stops a longer list one day being a
        // buffer overrun rather than a truncation.
        assert_eq!(MAX_GROUPS, 32);
    }
}
