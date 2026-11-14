//! `SEM_UNDO` state and thread-group exit handling.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use plan::Op;

use super::{CHANGED, plan, table};

/// The adjustments one thread group would have to reverse if it died now.
///
/// Keyed by set id and semaphore, and a zero adjustment is removed rather than
/// kept -- so a process that acquires and releases in the ordinary way leaves
/// nothing behind, which is what stops this growing without bound in a loop.
type Undo = HashMap<(i32, usize), i32>;

/// Per thread group, in one IPC namespace: the set ids are that namespace's.
#[derive(Default)]
struct Undos(Mutex<HashMap<i32, Undo>>);

/// The calling task's IPC namespace's adjustments. A group's list is applied
/// when it leaves the namespace (`unshare`, `setns`), so it never holds
/// adjustments to two namespaces' sets.
fn undos() -> Arc<Undos> {
    taskview::current_ipc().part()
}

fn undos_in(ipc: &taskview::nsproxy::Ipc) -> Arc<Undos> {
    ipc.part()
}

/// Record what this thread group would have to reverse.
pub(super) fn record_undo(id: i32, ops: &[Op]) {
    if !ops
        .iter()
        .any(|o| o.flags & plan::SEM_UNDO != 0 && o.op != 0)
    {
        return;
    }
    let tgid = taskview::current_tgid();
    let undos = undos();
    let mut u = undos.0.lock().unwrap_or_else(|e| e.into_inner());
    let list = u.entry(tgid).or_default();
    for o in ops {
        if o.flags & plan::SEM_UNDO == 0 || o.op == 0 {
            continue;
        }
        let slot = list.entry((id, o.num as usize)).or_insert(0);
        *slot -= o.op as i32;
        if *slot == 0 {
            list.remove(&(id, o.num as usize));
        }
    }
    if list.is_empty() {
        u.remove(&tgid);
    }
}

/// Drop adjustments belonging to a removed set.
pub(super) fn forget_undos_for(id: i32) {
    let undos = undos();
    let mut u = undos.0.lock().unwrap_or_else(|e| e.into_inner());
    u.retain(|_, list| {
        list.retain(|(set_id, _), _| *set_id != id);
        !list.is_empty()
    });
}

/// Whether this thread group holds `SEM_UNDO` adjustments: the list
/// `kcmp(KCMP_SYSVSEM)` compares. A group with none has no list, which is
/// Linux's NULL `undo_list` until the first `SEM_UNDO` operation; Linux keeps
/// an emptied list where this drops it.
///
/// Asked of the namespace the group's task is in.
pub fn has_undo(ipc: &taskview::nsproxy::Ipc, tgid: i32) -> bool {
    undos_in(ipc).0.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&tgid)
}

/// Reverse the adjustments: the last thread of a group is exiting, or the
/// group is leaving its IPC namespace. The calling task's namespace's.
pub fn group_exiting(tgid: i32) {
    let Some(list) = undos()
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&tgid)
    else {
        return;
    };
    for ((id, num), adj) in list {
        let table = table();
        let Some(set) = table.lock().unwrap_or_else(|e| e.into_inner()).get(id) else {
            continue;
        };
        let mut s = set.state.lock();
        if s.removed || num >= s.sems.len() {
            continue;
        }
        let want = s.sems[num].value as i32 + adj;
        if !(0..=plan::SEMVMX).contains(&want) {
            continue;
        }
        s.sems[num].value = want as u16;
        s.sems[num].pid = tgid;
        drop(s);
        set.state.notify(CHANGED);
    }
}
