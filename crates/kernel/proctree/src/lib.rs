//! Who belongs to whom: a process's parent and children, and a thread group's
//! threads.
//!
//! Three fields of `struct task` — a `parent` pointer, a `children` list head
//! and a `siblings` link — that only ever meant one thing between them. Every
//! walk over them was an intrusive-list macro, and every one of those had to
//! be the *safe* variant or not, depending on whether the body could remove an
//! entry — which `do_wait`'s does, by reaping.
//!
//! The rules are Linux's and are all here rather than spread over the four
//! files that used to open-code them:
//!
//! - a child is added to its parent at creation and removed at destruction;
//! - when a thread exits, its children are reparented — to another thread of
//!   its own group if there is one, and otherwise up the tree to the nearest
//!   ancestor that asked to be a subreaper, or to init;
//! - a task's children are its own, not its thread group's. `wait()` with no
//!   pid is defined over the whole group, which is why `do_wait` walks the
//!   children of every thread rather than of the caller.
//!
//! # The thread list
//!
//! `struct tgroup`'s was the other intrusive list, and its comment said it was
//! "locked by pids_lock, **by majority vote**" — an accurate description of a
//! list some callers took `pids_lock` for, some `group->lock`, and some both.
//! The structure is safe here whichever they hold, because it has one of its
//! own; the callers keep theirs, which is what still orders them against
//! everything else they touch.
//!
//! It also makes counting a count. `/proc/<pid>/stat`'s `nthreads` walked the
//! whole list for its length, twice per read.
//!
//! # Being told when a key dies
//!
//! A side table has to be told, and the compiler does not check that it was.
//! The intrusive lists could not have this problem: the links were *in* the
//! freed memory, so a `free` took them with it. Here a `struct task` or a
//! `struct tgroup` that is freed without [`Tree::remove`] or
//! [`Tree::group_forget`] leaves an entry behind — and the next `malloc` to
//! return that address inherits it, which is worse than a leak.
//!
//! So an address arriving that is *already* registered is counted and reported
//! through `/proc/iul/objects`, where a guest can see it: `proctree_stale`
//! should always be zero. The entry is replaced rather than merged, which is
//! the right recovery — the new task genuinely has no children yet — so the
//! count is a diagnostic and not a behaviour change.
//!
//! # No C ABI
//!
//! Every function here was a `#[no_mangle] extern "C" fn` behind
//! `kernel/proctree.h`, and **no C called any of them** — the header existed
//! so that twelve Rust crates could bindgen a declaration and call through it
//! in an `unsafe` block. They are plain Rust functions now and the header is
//! gone, which removes 41 `unsafe` blocks that discharged nothing and lets the
//! calls inline. `member_keeps_group_alive` was already reached this way and
//! is the shape the rest follow.
//!
//! # Identities, not pointers
//!
//! A task is a pointer the crate compares, stores and hands back, and **never
//! reads through**. `pids_lock` is the caller's and is held for every call,
//! exactly as it was — this is a change of data structure, not of lock
//! protocol. That is also why every function here is safe: any pointer value
//! is a valid key.
//!
//! That paragraph was true on 2026-09-05 and **the code said it in a comment**:
//! `type TaskAddress = usize`, `type GroupAddress = usize`, with a
//! `task_address` going in and a `task_pointer` coming back out. Since
//! 2026-09-15 it is [`taskview::ffi::Identity`], so the compiler holds it:
//! [`Tree`] names no pointer at all, and `api.rs` is the one boundary that
//! converts.
//!
//! Two things that were possible and are not:
//!
//! - **`groups: HashMap<GroupAddress, Vec<TaskAddress>>` was two `usize`
//!   maps.** `group_add(group, task)` with its arguments the wrong way round
//!   compiled. This crate's own tests were writing `task(100) as Group` to get
//!   a group to test with, which is that confusion in miniature — they say
//!   `group(100)` now, and the two helpers answer different types.
//! - **`task_pointer(addr) -> Task` turned an integer back into a pointer**,
//!   unchecked, and it is what let a key be dereferenced by mistake. There is
//!   no such function: `TaskId::as_ptr` exists, hands back the number it was
//!   made from, and promises nothing — the caller's `pids_lock` is what makes
//!   the address live.
//!
//! The signatures still name `struct task` and `struct tgroup`, and that is
//! new on 2026-09-05. They were `*mut c_void` while the C ABI existed, because
//! twelve crates each generated their own `struct task` and one header could
//! not name all of them; `crates/kernel/taskview` owns the type for the whole
//! tree now, so the alternative to naming it is a `.cast()` at every one of
//! the forty-one call sites — and a cast that erases a type is what lets a
//! `struct tgroup *` be passed where a `struct task *` was meant.
//!
//! # Null
//!
//! The public API takes and answers pointers, so a null can arrive at any of
//! the fifteen entry points. Three of them — `add`, `group_add`,
//! `group_add_new` — refused one by hand, and the other twelve let it through
//! as **key `0`**, which missed because nothing could ever have inserted it.
//!
//! `Identity::from_ptr` answers `None` for a null, so each entry point now
//! says what it means once, in a `let else`: a refusal for the three that
//! insert, and the miss it always was for the twelve that look up. The two
//! behaviours are identical and the reasoning is no longer "key 0 happens not
//! to collide".

use std::collections::HashMap;

/// A `struct task *`, as the **API** spells one. Compared and stored, never
/// read through — see [`TaskId`], which is what [`Tree`] holds.
pub type Task = *mut taskview::ffi::task;
/// A `struct tgroup *`. The same.
pub type Group = *mut taskview::ffi::tgroup;

/// What the tree is actually keyed on.
///
/// These were `type TaskAddress = usize` and `type GroupAddress = usize` until
/// 2026-09-15, with a `task_address` in and a `task_pointer` back out — an
/// integer↔pointer round trip the compiler could not check, and **two `usize`
/// maps side by side**: `groups: HashMap<GroupAddress, Vec<TaskAddress>>`
/// would have accepted its two arguments the wrong way round.
///
/// [`taskview::ffi::Identity`] is the same property the module comment above
/// already claimed — "compared, stored and handed back, and never read
/// through" — expressed so that the compiler holds it. `Tree` names no
/// pointer at all now; `api.rs` is the one boundary that converts, which is
/// also where the null checks already were.
pub use taskview::ffi::{TaskId, TgroupId};

mod api;
pub use api::{
    add, child_at, children_len, counts, group_add, group_add_new, group_at, group_forget,
    group_len, group_remove, is_ancestor, parent, remove, set_parent,
};


/// A guest pid.
pub type Pid = i32;

/// What the orphan rule needs to know about one member of a process group.
///
/// The C fills one of these per member while it holds `pids_lock` and walks the
/// registry; the rule itself is here, where its three exceptions can be
/// asserted.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    /// The thread group's session.
    pub sid: Pid,
    /// Whether its leader is still running — **not** a zombie and not on its
    /// way out.
    pub leader_alive: bool,
    /// Whether the leader still has a parent this kernel can see.
    pub has_parent: bool,
    pub parent_pid: Pid,
    pub parent_pgid: Pid,
    pub parent_sid: Pid,
}

/// Whether this member is evidence that the group is **not** orphaned.
///
/// POSIX: a process group is orphaned when no member has a parent that is in a
/// different process group of the same session. Such a parent is someone who
/// could still `SIGCONT` the group, which is the whole question — an orphaned
/// group gets `EIO` where a live one gets `SIGTTIN`, because there is nobody
/// left to continue it.
///
/// Three exceptions, each of which Linux's `will_become_orphaned_pgrp` also
/// makes and each of which was found the hard way:
///
/// - **A dead member proves nothing.** Linux skips `p->exit_state &&
///   thread_group_empty(p)`. Without it a zombie whose parent is still around
///   kept the whole group looking alive — and that is the ordinary shape of a
///   pipeline, not a corner case: a shell's job leader exits while its children
///   carry on in the same group, and it stays a zombie until someone waits.
/// - **init cannot continue anything.** `is_global_init(p->real_parent)` in the
///   same walk. It matters here more than on Linux, because everything that has
///   not called `setsid` shares init's session — so without it the session test
///   would pass for every orphan in the initial session.
/// - **A parent in the same group is not a way out.** It is in the group being
///   asked about, so it is subject to the same stop.
pub fn member_keeps_group_alive(m: &Member, pgid: Pid) -> bool {
    if !m.leader_alive || !m.has_parent {
        return false;
    }
    if m.parent_pid == 1 {
        return false;
    }
    m.parent_pgid != pgid && m.parent_sid == m.sid
}

/// Whether the group is orphaned, over every member.
///
/// **A group with no members is orphaned**, which is what a `^C` aimed at a
/// foreground group that has already exited asks — the ordinary state between a
/// job finishing and the shell reclaiming the terminal.
pub fn pgroup_is_orphaned<'a>(pgid: Pid, members: impl IntoIterator<Item = &'a Member>) -> bool {
    !members
        .into_iter()
        .any(|m| member_keeps_group_alive(m, pgid))
}

#[derive(Default)]
struct Node {
    parent: Option<TaskId>,
    /// In the order they were created, which is the order `do_wait` sees them
    /// in. The C list added at the head, so it was newest-first; nothing
    /// depends on either, and oldest-first is the one a reader expects.
    children: Vec<TaskId>,
}

#[derive(Default)]
pub struct Tree {
    nodes: HashMap<TaskId, Node>,
    /// A thread group's threads, in the order they were created. The leader is
    /// first, because it is the one the group was made for.
    groups: HashMap<TgroupId, Vec<TaskId>>,
    /// How many times an address arrived that was still registered — which
    /// means whoever had it before was freed without saying so. Always zero;
    /// `/proc/iul/objects` is where a guest can check that.
    stale: u64,
}

impl Tree {
    /// A task enters the tree, with a parent or as the first process.
    pub fn add(&mut self, task: TaskId, parent: Option<TaskId>) -> bool {
        if self.nodes.try_reserve(1).is_err() {
            return false;
        }
        // A `struct task` at an address that is still registered means the one
        // before it was freed without remove. Replaced, not merged:
        // the new task has no children, whatever the old one left behind.
        if let Some(old) = self.nodes.remove(&task) {
            self.stale += 1;
            if let Some(p) = old.parent
                && let Some(parent) = self.nodes.get_mut(&p)
            {
                parent.children.retain(|&c| c != task);
            }
        }
        self.nodes.entry(task).or_default().parent = parent;
        if let Some(p) = parent {
            let node = self.nodes.entry(p).or_default();
            if node.children.try_reserve(1).is_err() {
                return false;
            }
            node.children.push(task);
        }
        true
    }

    /// A task leaves the tree.
    ///
    /// Its children go with it rather than being left pointing at an entry
    /// that is not there — they have already been reparented by the time this
    /// runs, and a child still here is a caller that skipped that.
    pub fn remove(&mut self, task: TaskId) {
        let Some(node) = self.nodes.remove(&task) else {
            return;
        };
        if let Some(p) = node.parent
            && let Some(parent) = self.nodes.get_mut(&p)
        {
            parent.children.retain(|&c| c != task);
        }
        for child in node.children {
            if let Some(c) = self.nodes.get_mut(&child) {
                c.parent = None;
            }
        }
    }

    pub fn parent(&self, task: TaskId) -> Option<TaskId> {
        self.nodes.get(&task)?.parent
    }

    /// Move a task to a new parent, or to none. False if the move is refused.
    ///
    /// A task may not become its own ancestor, and this is what makes
    /// [`Tree::is_ancestor`]'s "which nothing here can create" true. It was not:
    ///
    /// `task_create_` linked every child under the creating thread, including a
    /// `CLONE_THREAD` one -- where Linux gives a thread its creator's *parent*.
    /// So a thread was a child of its creator. When the creator exited, the
    /// reparenting loop moved its children to "the first surviving thread of my
    /// group", which was that same thread, and the thread became its own
    /// parent. The next exit walked the ancestors of that and never stopped: a
    /// guest process whose worker thread called `exit()` hung forever.
    ///
    /// The parent edge is fixed at its source, in `copy_task`. This is here
    /// because a data structure that can be put in a state its own readers
    /// cannot survive is the wrong shape, and because the next caller to
    /// reparent by hand will not remember either.
    pub fn set_parent(&mut self, task: TaskId, parent: Option<TaskId>) -> bool {
        if !self.nodes.contains_key(&task) {
            return false;
        }
        // `is_ancestor` is "at or above", so this covers `parent == task`.
        if let Some(p) = parent
            && self.is_ancestor(p, task)
        {
            return false;
        }
        if let Some(old) = self.nodes.get(&task).and_then(|node| node.parent)
            && let Some(node) = self.nodes.get_mut(&old)
        {
            node.children.retain(|&c| c != task);
        }
        self.nodes.get_mut(&task).expect("checked").parent = parent;
        if let Some(p) = parent {
            let node = self.nodes.entry(p).or_default();
            if node.children.try_reserve(1).is_ok() {
                node.children.push(task);
            }
        }
        true
    }

    pub fn children_len(&self, task: TaskId) -> usize {
        self.nodes.get(&task).map_or(0, |n| n.children.len())
    }

    /// The `i`th child, or `None` past the end.
    ///
    /// Indices are stable for as long as `pids_lock` is held and nothing moves
    /// a task — the same guarantee walking the intrusive list gave, and the
    /// same one `kernel_pids::pgroup_at` offers for a process group.
    pub fn child_at(&self, task: TaskId, i: usize) -> Option<TaskId> {
        self.nodes.get(&task)?.children.get(i).copied()
    }

    /// Is `maybe_ancestor` at or above `task` in the tree?
    ///
    /// Bounded by the number of tasks whatever the shape of the links. That
    /// bound is belt and braces now that [`Tree::set_parent`] refuses a move
    /// that would make one, and it stays: this is the function that refusal is
    /// written in terms of, so it has to terminate on a tree that is being
    /// checked rather than assume the answer.
    pub fn is_ancestor(&self, task: TaskId, maybe_ancestor: TaskId) -> bool {
        let mut at = Some(task);
        for _ in 0..=self.nodes.len() {
            match at {
                None => return false,
                Some(t) if t == maybe_ancestor => return true,
                Some(t) => at = self.nodes.get(&t).and_then(|n| n.parent),
            }
        }
        false
    }

    // --- thread group membership ---

    /// A group that has no threads yet is one this is the first call for. One
    /// that has some is either a second thread joining, or -- if the caller
    /// says this is a new group -- an address whose previous owner was freed
    /// without group_forget.
    pub fn group_add_new(&mut self, group: TgroupId, task: TaskId) -> bool {
        if self.groups.contains_key(&group) {
            self.stale += 1;
            self.groups.remove(&group);
        }
        self.group_add(group, task)
    }

    pub fn group_add(&mut self, group: TgroupId, task: TaskId) -> bool {
        if self.groups.try_reserve(1).is_err() {
            return false;
        }
        let threads = self.groups.entry(group).or_default();
        if threads.try_reserve(1).is_err() {
            return false;
        }
        // Idempotent: adding a thread twice would make the group outlive its
        // last exit by the number of duplicates.
        if !threads.contains(&task) {
            threads.push(task);
        }
        true
    }

    /// Remove a thread. True if the group is now empty, which is what decides
    /// whether the process is dead.
    pub fn group_remove(&mut self, group: TgroupId, task: TaskId) -> bool {
        let Some(threads) = self.groups.get_mut(&group) else {
            return true;
        };
        threads.retain(|&t| t != task);
        threads.is_empty()
    }

    pub fn group_len(&self, group: TgroupId) -> usize {
        self.groups.get(&group).map_or(0, |t| t.len())
    }

    /// The `i`th thread, or `None` past the end. Stable under the caller's
    /// lock, like [`Tree::child_at`].
    pub fn group_at(&self, group: TgroupId, i: usize) -> Option<TaskId> {
        self.groups.get(&group)?.get(i).copied()
    }

    /// The group is being freed.
    pub fn group_forget(&mut self, group: TgroupId) {
        self.groups.remove(&group);
    }

    /// How many tasks and groups are registered, and how many addresses have
    /// arrived that were still registered. The last is always zero.
    pub fn counts(&self) -> (usize, usize, u64) {
        (self.nodes.len(), self.groups.len(), self.stale)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
