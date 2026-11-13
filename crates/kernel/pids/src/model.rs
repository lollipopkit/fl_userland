//! Pure pid, membership, and per-user process-count models.

use std::collections::HashMap;
use std::ffi::c_int;

/// The guest's pid type.
pub type Pid = c_int;

/// Which thread group. A `usize` — the address cast to an integer — until
/// 2026-09-15, with "this function never dereferences it" written out once per
/// mutator. That is a property of the value, so it is on the type now: see
/// [`taskview::ffi::Identity`].
pub(crate) type Handle = taskview::ffi::TgroupId;

/// Which task, for the pid table. Was a `usize` with **`0` meaning empty**,
/// which is the sentinel `Option` exists for — and `Option<TaskId>` is the
/// same eight bytes, because `NonNull` has a niche. `crates/kernel/abi`'s
/// `the_empty_slot_is_free` asserts that.
pub(crate) type TaskId = taskview::ffi::TaskId;

/// A task named across time. `crates/util/identity`'s since 2026-09-29, so
/// that a crate can hold one without depending on the pid table.
pub use util_identity::TaskRef;

/// Which process group and session one thread group is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ids {
    pgid: Pid,
    sid: Pid,
}

/// Which task is at which pid number, and which number to try next.
///
/// A `Vec` indexed by the number, where the C had a static array of `MAX_PID +
/// 1` entries — 32769 of them, allocated whether a guest ever forks or not.
/// This grows to the highest number in use, so a guest that never gets past pid
/// 40 pays for 40.
///
/// The lookup is the same one load it always was. What changes is that "the
/// table is full" is a count rather than a scan of every number: the loop in
/// `task_create_` had no bound at all until 2026-08-23, and a bounded scan of
/// 32768 entries is still a scan.
#[derive(Debug, Default)]
pub struct Table {
    /// Which task is at this pid, if any. Index is the pid.
    slots: Vec<Option<TaskId>>,
    /// How many times each slot has held a task, which is what a [`TaskRef`]
    /// is checked against. Grows with `slots`.
    generations: Vec<u32>,
    /// Where the next search starts. Numbers go up and wrap, so a pid is not
    /// reused immediately after it is freed — which is what makes a stale pid
    /// in a guest's hands usually fail rather than name someone else.
    cursor: Pid,
    /// How many slots hold a task. `alloc` fails on this rather than walking.
    used: usize,
    /// Numbers handed out by `alloc` and not yet filled. A task is built
    /// before it is published, since 2026-09-30, so its number has to be spoken
    /// for in between -- or a second fork on another thread would be handed the
    /// same one. [`Table::set`] takes the reservation, either way.
    reserved: std::collections::HashSet<Pid>,
}

impl Table {
    pub fn new() -> Table {
        Table::default()
    }

    pub fn get(&self, id: Pid) -> Option<TaskId> {
        if id < 0 {
            return None;
        }
        self.slots.get(id as usize).copied().flatten()
    }

    /// A reference to the task at a number now, or `None` for an empty slot.
    pub fn refer(&self, id: Pid) -> Option<TaskRef> {
        self.get(id)?;
        Some(TaskRef {
            pid: id,
            generation: self.generations[id as usize],
        })
    }

    /// The task a reference names, or null: the slot is empty, or has been
    /// filled again since the reference was taken.
    pub fn by_ref(&self, r: TaskRef) -> Option<TaskId> {
        let task = self.get(r.pid)?;
        if self.generations[r.pid as usize] != r.generation {
            return None;
        }
        Some(task)
    }

    /// Puts a task at a number. Only [`alloc`](Self::alloc) hands out numbers,
    /// so this is the follow-up to it rather than a way to claim one.
    ///
    /// Every task stored is a new generation of the number, whether or not
    /// the slot was empty: a reference taken before never names it.
    pub fn set(&mut self, id: Pid, task: Option<TaskId>) -> bool {
        if id < 0 {
            return false;
        }
        let i = id as usize;
        if i >= self.slots.len() {
            let more = i + 1 - self.slots.len();
            if self.slots.try_reserve(more).is_err() || self.generations.try_reserve(more).is_err()
            {
                return false;
            }
            self.slots.resize(i + 1, None);
            self.generations.resize(i + 1, 0);
        }
        self.reserved.remove(&id);
        let was = std::mem::replace(&mut self.slots[i], task);
        if task.is_some() {
            self.generations[i] = self.generations[i].wrapping_add(1);
        }
        match (was.is_none(), task.is_none()) {
            (true, false) => self.used += 1,
            (false, true) => self.used -= 1,
            _ => {}
        }
        true
    }

    /// Swaps the tasks at two numbers, each number keeping its generation:
    /// a [`TaskRef`] to either still names whatever is at that number now.
    /// `execve` from a thread that is not the leader, which takes the
    /// process's number and leaves its own on the old leader -- Linux's
    /// `exchange_tids`, under which a pidfd for the process stays valid.
    /// `false`, and nothing changed, if either number is empty.
    pub fn exchange(&mut self, a: Pid, b: Pid) -> bool {
        if self.get(a).is_none() || self.get(b).is_none() {
            return false;
        }
        self.slots.swap(a as usize, b as usize);
        true
    }

    pub fn clear(&mut self, id: Pid) {
        self.set(id, None);
    }

    /// Whether `alloc` has handed this number out and nothing has filled it.
    pub fn is_reserved(&self, id: Pid) -> bool {
        self.reserved.contains(&id)
    }

    pub fn used(&self) -> usize {
        self.used
    }
}

/// Every thread group's process group and session, and the reverse indices.
///
/// One mutator per move, each maintaining all three maps. That is the whole
/// point: see the note at the top of this file.
#[derive(Debug, Default)]
pub struct Membership {
    of: HashMap<Handle, Ids>,
    by_pgid: HashMap<Pid, Vec<Handle>>,
    by_sid: HashMap<Pid, Vec<Handle>>,
}

fn index_add(index: &mut HashMap<Pid, Vec<Handle>>, key: Pid, h: Handle) {
    let v = index.entry(key).or_default();
    if !v.contains(&h) {
        v.push(h);
    }
}

fn index_remove(index: &mut HashMap<Pid, Vec<Handle>>, key: Pid, h: Handle) {
    if let Some(v) = index.get_mut(&key) {
        v.retain(|&x| x != h);
        if v.is_empty() {
            index.remove(&key);
        }
    }
}

impl Membership {
    #[cfg(test)]
    pub fn new() -> Membership {
        Membership::default()
    }

    /// The process group and session of `h`, if it is registered.
    #[cfg(test)]
    pub fn ids(&self, h: Handle) -> Option<(Pid, Pid)> {
        self.of.get(&h).map(|i| (i.pgid, i.sid))
    }

    /// Registers `h` in the same group and session as `like`, which is what a
    /// new thread group inherits from its parent.
    ///
    /// A `like` that is not registered — the very first process — puts `h`
    /// nowhere, and the caller's `set_pgid`/`set_sid` place it.
    pub fn insert_like(&mut self, h: Handle, like: Handle) {
        let Some(ids) = self.of.get(&like).copied() else {
            return;
        };
        self.of.insert(h, ids);
        index_add(&mut self.by_pgid, ids.pgid, h);
        index_add(&mut self.by_sid, ids.sid, h);
    }

    /// Moves `h` into process group `pgid`, out of wherever it was.
    ///
    /// The one operation, rather than a remove and an add a caller has to pair
    /// up with a field assignment.
    pub fn set_pgid(&mut self, h: Handle, pgid: Pid) {
        let sid = self.of.get(&h).map(|i| i.sid).unwrap_or(0);
        if let Some(old) = self.of.get(&h).copied() {
            index_remove(&mut self.by_pgid, old.pgid, h);
        }
        self.of.insert(h, Ids { pgid, sid });
        index_add(&mut self.by_pgid, pgid, h);
        if sid != 0 {
            index_add(&mut self.by_sid, sid, h);
        }
    }

    /// Moves `h` into session `sid`, out of wherever it was.
    pub fn set_sid(&mut self, h: Handle, sid: Pid) {
        let pgid = self.of.get(&h).map(|i| i.pgid).unwrap_or(0);
        if let Some(old) = self.of.get(&h).copied() {
            index_remove(&mut self.by_sid, old.sid, h);
        }
        self.of.insert(h, Ids { pgid, sid });
        index_add(&mut self.by_sid, sid, h);
        if pgid != 0 {
            index_add(&mut self.by_pgid, pgid, h);
        }
    }

    /// Takes `h` out of both. What a thread group does on its way out.
    pub fn remove(&mut self, h: Handle) {
        if let Some(ids) = self.of.remove(&h) {
            index_remove(&mut self.by_pgid, ids.pgid, h);
            index_remove(&mut self.by_sid, ids.sid, h);
        }
    }

    pub fn pgroup(&self, pgid: Pid) -> &[Handle] {
        self.by_pgid.get(&pgid).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn session(&self, sid: Pid) -> &[Handle] {
        self.by_sid.get(&sid).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Whether a number is still spoken for as a group or a session, which is
    /// what keeps a pid from being reused while a session id still names it.
    pub fn number_in_use(&self, id: Pid) -> bool {
        !self.pgroup(id).is_empty() || !self.session(id).is_empty()
    }

    /// Every index entry is backed by a forward entry saying the same thing,
    /// and every forward entry appears in both indices. Asserted by each test;
    /// the two bugs this crate exists for were exactly this invariant broken.
    #[cfg(test)]
    pub(crate) fn check(&self) {
        for (&h, ids) in &self.of {
            assert!(
                self.pgroup(ids.pgid).contains(&h),
                "handle {h:?} missing from pgroup {}",
                ids.pgid
            );
            assert!(
                self.session(ids.sid).contains(&h),
                "handle {h:?} missing from session {}",
                ids.sid
            );
        }
        for (&pgid, v) in &self.by_pgid {
            for &h in v {
                assert_eq!(
                    self.of.get(&h).map(|i| i.pgid),
                    Some(pgid),
                    "stale pgroup entry"
                );
            }
        }
        for (&sid, v) in &self.by_sid {
            for &h in v {
                assert_eq!(
                    self.of.get(&h).map(|i| i.sid),
                    Some(sid),
                    "stale session entry"
                );
            }
        }
    }
}

/// Per-user task counts.
#[derive(Debug, Default)]
pub struct ProcCount {
    counts: HashMap<u32, u32>,
}

impl ProcCount {
    pub fn new() -> ProcCount {
        ProcCount::default()
    }

    /// How many tasks `uid` has.
    pub fn get(&self, uid: u32) -> u32 {
        self.counts.get(&uid).copied().unwrap_or(0)
    }

    /// Counts one more for `uid`, or refuses.
    ///
    /// `exempt` is the superuser, which Linux lets past the limit —
    /// `capable(CAP_SYS_RESOURCE)` in `copy_process`. It still *counts*, so a
    /// process that drops privilege afterwards is not free.
    ///
    /// A limit of 0 admits nothing, which is what a guest asking for 0 means.
    pub fn try_add(&mut self, uid: u32, limit: u32, exempt: bool) -> bool {
        let have = self.get(uid);
        if !exempt && have >= limit {
            return false;
        }
        // try_reserve, not the plain insert: the number of distinct uids is
        // bounded by what the guest can set, and aborting the process on an
        // allocation failure is worse than failing the fork.
        if !self.counts.contains_key(&uid) && self.counts.try_reserve(1).is_err() {
            return false;
        }
        *self.counts.entry(uid).or_insert(0) += 1;
        true
    }

    /// Gives back one of `uid`'s. The entry goes when it reaches zero, so a
    /// guest that creates processes under many uids does not leave a map entry
    /// per uid for ever.
    pub fn remove(&mut self, uid: u32) {
        if let Some(n) = self.counts.get_mut(&uid) {
            *n -= 1;
            if *n == 0 {
                self.counts.remove(&uid);
            }
        }
    }

    /// How many users have any tasks. For `/proc` and for tests.
    #[cfg(test)]
    pub fn users(&self) -> usize {
        self.counts.len()
    }
}

/// The whole registry: the numbers and what is in them.
///
/// One struct because allocating a number has to ask both — a number is free
/// only when no task holds it *and* nothing still names it as a process group
/// or a session, which is how a session id outlives its leader.
#[derive(Debug, Default)]
pub struct Registry {
    pub tasks: Table,
    pub members: Membership,
}

impl Registry {
    pub fn new() -> Registry {
        Registry::default()
    }

    /// Whether a number is free to hand out.
    pub fn free(&self, id: Pid) -> bool {
        self.tasks.get(id).is_none()
            && !self.tasks.is_reserved(id)
            && !self.members.number_in_use(id)
    }

    /// The next free number at or after the cursor, **reserved** until
    /// [`Table::set`] fills or clears it; `None` when every one is taken.
    ///
    /// `max` is the highest number that may be handed out. The search wraps
    /// once and gives up, where the C spun for ever holding `pids_lock` — not a
    /// failed fork but the emulator stopped dead.
    pub fn alloc(&mut self, max: Pid) -> Option<Pid> {
        if max < 1 {
            return None;
        }
        for _ in 0..max {
            self.cursor_next(max);
            if self.free(self.tasks.cursor) {
                let id = self.tasks.cursor;
                if self.tasks.reserved.try_reserve(1).is_err() {
                    return None;
                }
                self.tasks.reserved.insert(id);
                return Some(id);
            }
        }
        None
    }

    /// Reserve exactly `id`, as [`Registry::alloc`] reserves the one it
    /// finds; `false` if it is taken. `clone3`'s `set_tid` is the caller.
    pub fn reserve(&mut self, id: Pid) -> bool {
        if !self.free(id) || self.tasks.reserved.try_reserve(1).is_err() {
            return false;
        }
        self.tasks.reserved.insert(id);
        true
    }

    fn cursor_next(&mut self, max: Pid) {
        self.tasks.cursor += 1;
        if self.tasks.cursor > max {
            self.tasks.cursor = 1;
        }
    }
}
