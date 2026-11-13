//! Process tree and thread-group operations over the shared registry.

use super::*;
use std::ffi::c_uint;
use std::sync::Mutex;

// --------------------------------------------------------------- Shared registry API
//
// `pids_lock` is the caller's for every one of these. The mutex below is not a
// second lock in the protocol -- it is what makes the table safe to touch at
// all from Rust, and it is never held across a call back into C.

static TREE: Mutex<Option<Tree>> = Mutex::new(None);

fn with<T>(f: impl FnOnce(&mut Tree) -> T) -> T {
    let mut guard = TREE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(guard.get_or_insert_with(Tree::default))
}

// The boundary. Callers hold `*mut task` and `*mut tgroup`, because that is
// what `struct task`'s fields are; `Tree` holds identities and names no
// pointer. Every conversion in this crate is in this file, and a null becomes
// `None` -- which for a lookup is the miss it always was, and for an insert is
// the refusal the three insert paths already spelled out by hand.

/// A task enters the tree. `parent` may be null, for the first process.
/// False if the table cannot grow, or if `task` is null.
pub fn add(task: Task, parent: Task) -> bool {
    let Some(task) = TaskId::from_ptr(task) else {
        return false;
    };
    with(|t| t.add(task, TaskId::from_ptr(parent)))
}

pub fn remove(task: Task) {
    let Some(task) = TaskId::from_ptr(task) else {
        return;
    };
    with(|t| t.remove(task));
}

/// The task's parent, or null.
pub fn parent(task: Task) -> Task {
    let Some(task) = TaskId::from_ptr(task) else {
        return std::ptr::null_mut();
    };
    with(|t| t.parent(task)).map_or(std::ptr::null_mut(), TaskId::as_ptr)
}

/// Move a task to a new parent. A null parent detaches it, which is what a
/// task whose parent is gone and which has no init to fall back on gets.
///
/// False if the move was refused because it would have made the task its own
/// ancestor. A caller that ignores this leaves the task where it was, which is
/// the safe half of the answer.
pub fn set_parent(task: Task, parent: Task) -> bool {
    let Some(task) = TaskId::from_ptr(task) else {
        return false;
    };
    with(|t| t.set_parent(task, TaskId::from_ptr(parent)))
}

pub fn children_len(task: Task) -> c_uint {
    let Some(task) = TaskId::from_ptr(task) else {
        return 0;
    };
    with(|t| t.children_len(task)) as c_uint
}

/// The `i`th child, or null past the end.
pub fn child_at(task: Task, i: c_uint) -> Task {
    let Some(task) = TaskId::from_ptr(task) else {
        return std::ptr::null_mut();
    };
    with(|t| t.child_at(task, i as usize)).map_or(std::ptr::null_mut(), TaskId::as_ptr)
}

/// Whether `maybe_ancestor` is `task` or above it. Bounded, so a cycle ends
/// the walk rather than hanging it.
pub fn is_ancestor(task: Task, maybe_ancestor: Task) -> bool {
    let (Some(task), Some(maybe_ancestor)) =
        (TaskId::from_ptr(task), TaskId::from_ptr(maybe_ancestor))
    else {
        return false;
    };
    with(|t| t.is_ancestor(task, maybe_ancestor))
}

/// A thread joins its group. False if the table cannot grow.
pub fn group_add(group: Group, task: Task) -> bool {
    let (Some(group), Some(task)) = (TgroupId::from_ptr(group), TaskId::from_ptr(task)) else {
        return false;
    };
    with(|t| t.group_add(group, task))
}

/// A thread leaves. True if the group is now empty -- which is what tells the
/// caller the process is dead. A group that was never registered is empty,
/// which is what a null answers too.
pub fn group_remove(group: Group, task: Task) -> bool {
    let (Some(group), Some(task)) = (TgroupId::from_ptr(group), TaskId::from_ptr(task)) else {
        return true;
    };
    with(|t| t.group_remove(group, task))
}

pub fn group_len(group: Group) -> c_uint {
    let Some(group) = TgroupId::from_ptr(group) else {
        return 0;
    };
    with(|t| t.group_len(group)) as c_uint
}

/// The `i`th thread, or null past the end.
pub fn group_at(group: Group, i: c_uint) -> Task {
    let Some(group) = TgroupId::from_ptr(group) else {
        return std::ptr::null_mut();
    };
    with(|t| t.group_at(group, i as usize)).map_or(std::ptr::null_mut(), TaskId::as_ptr)
}

/// The first thread of a *new* group. Separate from group_add so
/// that an address whose previous owner was freed without
/// group_forget is noticed rather than joined.
pub fn group_add_new(group: Group, task: Task) -> bool {
    let (Some(group), Some(task)) = (TgroupId::from_ptr(group), TaskId::from_ptr(task)) else {
        return false;
    };
    with(|t| t.group_add_new(group, task))
}

pub fn group_forget(group: Group) {
    let Some(group) = TgroupId::from_ptr(group) else {
        return;
    };
    with(|t| t.group_forget(group));
}

/// For `/proc/iul/objects`: registered tasks, registered groups, and how many
/// addresses have arrived that were still registered. The last is always zero
/// -- anything else is a `struct task` or `struct tgroup` freed without saying
/// so, and the next allocation at that address inheriting what it left.
///
/// It took three `*mut u64` and wrote through them from a **safe** `extern
/// "C"` function until 2026-09-05, which is a contract a safe function cannot
/// make. Every caller was Rust, so it returns a tuple.
pub fn counts() -> (u64, u64, u64) {
    let (t, g, s) = with(|tree| tree.counts());
    (t as u64, g as u64, s)
}
