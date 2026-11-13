//! Tests for process-tree and thread-group state.

use super::*;

fn member(sid: Pid, parent_pgid: Pid, parent_sid: Pid) -> Member {
    Member {
        sid,
        leader_alive: true,
        has_parent: true,
        parent_pid: 100,
        parent_pgid,
        parent_sid,
    }
}

/// The rule itself: a parent in a *different* group of the *same* session
/// is someone who could still continue this one.
#[test]
fn a_parent_elsewhere_in_the_session_keeps_the_group_alive() {
    // pgid 7, session 3; the parent is in group 5 of session 3.
    assert!(member_keeps_group_alive(&member(3, 5, 3), 7));
    // The parent is in this very group, so it is stopped too.
    assert!(!member_keeps_group_alive(&member(3, 7, 3), 7));
    // The parent is in another session entirely, which POSIX does not count
    // -- a different session's terminal is not this one's.
    assert!(!member_keeps_group_alive(&member(3, 5, 9), 7));
}

/// A member that has already died proves nothing about who could continue
/// the group.
///
/// Without this a zombie whose parent is still around kept the whole group
/// looking alive — and a shell's job leader exiting while its children carry
/// on in the same group is the ordinary shape of a pipeline.
#[test]
fn a_dead_member_is_no_evidence() {
    let mut m = member(3, 5, 3);
    assert!(member_keeps_group_alive(&m, 7));
    m.leader_alive = false;
    assert!(!member_keeps_group_alive(&m, 7));
}

/// init cannot continue anything.
///
/// It matters here more than on Linux: everything that has not called
/// `setsid` shares init's session, so without this the session test would
/// pass for every orphan in the initial session.
#[test]
fn init_is_not_a_way_out() {
    let mut m = member(3, 5, 3);
    m.parent_pid = 1;
    assert!(!member_keeps_group_alive(&m, 7));
    m.parent_pid = 2;
    assert!(member_keeps_group_alive(&m, 7));
}

/// A member with no parent left is no evidence either.
#[test]
fn a_member_whose_parent_is_gone_is_no_evidence() {
    let mut m = member(3, 5, 3);
    m.has_parent = false;
    assert!(!member_keeps_group_alive(&m, 7));
}

/// One live member is enough, and an empty group is orphaned.
///
/// The empty case is what a `^C` aimed at a foreground group that has
/// already exited asks — the ordinary state between a job finishing and the
/// shell reclaiming the terminal.
#[test]
fn the_group_answer_is_over_every_member() {
    let dead = Member {
        leader_alive: false,
        ..member(3, 5, 3)
    };
    let live = member(3, 5, 3);
    assert!(pgroup_is_orphaned(7, &[] as &[Member]));
    assert!(pgroup_is_orphaned(7, &[dead, dead]));
    assert!(!pgroup_is_orphaned(7, &[dead, live]));
    assert!(!pgroup_is_orphaned(7, &[live, dead]));
}

/// A distinct task, and no task at all: `Tree` keys on an identity it never
/// dereferences, so `n` only has to be distinct and non-zero. It was
/// `n as Task` — an integer cast to a `*mut task` — until 2026-09-15, which
/// was sound for the same reason and said so nowhere.
fn task(n: usize) -> TaskId {
    TaskId::from_ptr(n as *mut _).expect("n is not zero")
}

/// The same, for a thread group. Distinct from [`task`] by *type* now: the
/// two maps were both keyed on `usize`, so a test — or `group_add` — could
/// have passed one where the other was meant.
fn group(n: usize) -> TgroupId {
    TgroupId::from_ptr(n as *mut _).expect("n is not zero")
}

fn children(t: &Tree, of: TaskId) -> Vec<TaskId> {
    (0..t.children_len(of))
        .filter_map(|i| t.child_at(of, i))
        .collect()
}

#[test]
fn a_child_is_added_to_its_parent_and_removed_with_itself() {
    let mut t = Tree::default();
    assert!(t.add(task(1), None));
    assert!(t.add(task(2), Some(task(1))));
    assert!(t.add(task(3), Some(task(1))));
    assert_eq!(t.parent(task(2)), Some(task(1)));
    assert_eq!(children(&t, task(1)), vec![task(2), task(3)]);
    t.remove(task(2));
    assert_eq!(children(&t, task(1)), vec![task(3)]);
    assert_eq!(t.parent(task(2)), None);
}

#[test]
fn children_come_back_in_the_order_they_were_created() {
    let mut t = Tree::default();
    t.add(task(1), None);
    for n in 2..=6 {
        t.add(task(n), Some(task(1)));
    }
    assert_eq!(children(&t, task(1)), (2..=6).map(task).collect::<Vec<_>>());
    assert_eq!(t.child_at(task(1), 5), None, "past the end");
}

#[test]
fn reparenting_moves_a_child_from_one_list_to_the_other() {
    let mut t = Tree::default();
    t.add(task(1), None);
    t.add(task(2), Some(task(1)));
    t.add(task(3), Some(task(1)));
    t.add(task(4), Some(task(2)));
    // 2 exits: its children go to 3.
    t.set_parent(task(4), Some(task(3)));
    assert_eq!(t.parent(task(4)), Some(task(3)));
    assert_eq!(children(&t, task(2)), vec![]);
    assert_eq!(children(&t, task(3)), vec![task(4)]);
}

/// The loop `do_exit` runs: take the children off one at a time from the
/// end, so that removing one cannot shift an index still to be visited.
#[test]
fn every_child_can_be_reparented_in_one_pass() {
    let mut t = Tree::default();
    t.add(task(1), None);
    t.add(task(99), Some(task(1)));
    for n in 2..=10 {
        t.add(task(n), Some(task(1)));
    }
    let mut moved = Vec::new();
    for i in (0..t.children_len(task(1))).rev() {
        let child = t.child_at(task(1), i).unwrap();
        moved.push(child);
        t.set_parent(child, Some(task(99)));
    }
    // 99 is itself a child of 1 and gets moved to itself, which must not
    // make it its own parent or lose it.
    assert!(t.children_len(task(1)) <= 1);
    assert_eq!(moved.len(), 10);
}

#[test]
fn a_detached_task_has_no_parent_and_is_in_nobodys_list() {
    let mut t = Tree::default();
    t.add(task(1), None);
    t.add(task(2), Some(task(1)));
    t.set_parent(task(2), None);
    assert_eq!(t.parent(task(2)), None);
    assert_eq!(children(&t, task(1)), vec![]);
}

/// Removing a task must not leave its children pointing at an entry that
/// is not there. They have been reparented by then in the real thing; a
/// child still here is a caller that skipped it, and the honest answer is
/// "no parent" rather than a stale one.
#[test]
fn removing_a_task_detaches_whatever_is_still_under_it() {
    let mut t = Tree::default();
    t.add(task(1), None);
    t.add(task(2), Some(task(1)));
    t.add(task(3), Some(task(2)));
    t.remove(task(2));
    assert_eq!(t.parent(task(3)), None);
    assert_eq!(children(&t, task(1)), vec![]);
    assert_eq!(t.len(), 2);
}

#[test]
fn an_ancestor_is_found_and_a_stranger_is_not() {
    let mut t = Tree::default();
    t.add(task(1), None);
    t.add(task(2), Some(task(1)));
    t.add(task(3), Some(task(2)));
    t.add(task(9), Some(task(1)));
    assert!(t.is_ancestor(task(3), task(1)));
    assert!(t.is_ancestor(task(3), task(2)));
    assert!(
        t.is_ancestor(task(3), task(3)),
        "a task is its own ancestor"
    );
    assert!(!t.is_ancestor(task(3), task(9)));
    assert!(!t.is_ancestor(task(1), task(3)));
}

/// Nothing here can build a cycle, but the walk is bounded anyway: the
/// subreaper search in `find_new_parent` chases parents, and a hang there
/// is a process that never exits.
#[test]
fn a_cycle_ends_the_walk_rather_than_hanging_it() {
    let mut t = Tree::default();
    t.add(task(1), None);
    t.add(task(2), Some(task(1)));
    // Built by writing the field, because set_parent refuses it now -- and
    // that refusal is the subject of the tests below. What is under test
    // here is that `is_ancestor` terminates on a tree that already has one,
    // which is what makes it usable *as* the refusal's own check.
    t.nodes.get_mut(&task(1)).unwrap().parent = Some(task(2));
    assert!(!t.is_ancestor(task(1), task(404)));
    assert!(t.is_ancestor(task(1), task(2)));
}

#[test]
fn a_task_may_not_become_its_own_parent() {
    // The move that hung the emulator. A thread was recorded as a child of
    // the thread that created it, so when that one exited the reparenting
    // loop handed its children to "the first surviving thread of my group"
    // -- the same thread.
    let mut t = Tree::default();
    t.add(task(1), None);
    t.add(task(2), Some(task(1)));
    assert!(!t.set_parent(task(2), Some(task(2))));
    assert_eq!(
        t.parent(task(2)),
        Some(task(1)),
        "and it is left where it was"
    );
    assert_eq!(t.children_len(task(1)), 1, "still its parent's child, once");
}

#[test]
fn a_task_may_not_become_its_own_ancestor_further_up() {
    // The two-step version. Nothing in the tree does this today; refusing
    // one step and not two would be a guard that reads as a proof and is
    // not one.
    let mut t = Tree::default();
    t.add(task(1), None);
    t.add(task(2), Some(task(1)));
    t.add(task(3), Some(task(2)));
    assert!(!t.set_parent(task(1), Some(task(3))));
    assert_eq!(t.parent(task(1)), None);
    // And the move that is *not* a cycle still goes through, so the guard
    // is not refusing everything.
    assert!(t.set_parent(task(3), Some(task(1))));
    assert_eq!(t.parent(task(3)), Some(task(1)));
    assert_eq!(t.children_len(task(2)), 0);
}

#[test]
fn detaching_is_never_a_cycle() {
    let mut t = Tree::default();
    t.add(task(1), None);
    t.add(task(2), Some(task(1)));
    assert!(t.set_parent(task(2), None));
    assert_eq!(t.parent(task(2)), None);
}

#[test]
fn a_task_that_is_not_in_the_tree_answers_nothing() {
    let mut t = Tree::default();
    assert_eq!(t.parent(task(404)), None);
    assert_eq!(t.children_len(task(404)), 0);
    assert_eq!(t.child_at(task(404), 0), None);
    t.remove(task(404));
    assert!(!t.set_parent(task(404), Some(task(1))));
    assert_eq!(t.parent(task(404)), None, "set_parent does not create one");
    assert!(t.is_empty());
}

/// The shape `do_wait` walks: a group's children are spread over its
/// threads, because a child belongs to the thread that forked it.
#[test]
fn a_childs_parent_is_the_thread_that_forked_it() {
    let mut t = Tree::default();
    let (main, worker) = (task(1), task(2));
    t.add(main, None);
    t.add(worker, Some(main));
    t.add(task(10), Some(worker));
    assert_eq!(children(&t, main), vec![worker]);
    assert_eq!(children(&t, worker), vec![task(10)]);
    // Which is why waiting from `main` has to look at `worker`'s list too.
    assert_eq!(t.parent(task(10)), Some(worker));
}

#[test]
fn a_group_holds_its_threads_in_creation_order() {
    let mut t = Tree::default();
    let group = group(100);
    assert!(t.group_add(group, task(1)));
    assert!(t.group_add(group, task(2)));
    assert!(t.group_add(group, task(3)));
    assert_eq!(t.group_len(group), 3);
    assert_eq!(t.group_at(group, 0), Some(task(1)), "the leader first");
    assert_eq!(t.group_at(group, 3), None);
}

/// Adding the same thread twice would make the group outlive its last
/// exit by the number of duplicates, because removal takes one at a time.
#[test]
fn adding_a_thread_twice_adds_it_once() {
    let mut t = Tree::default();
    let group = group(100);
    t.group_add(group, task(1));
    t.group_add(group, task(1));
    assert_eq!(t.group_len(group), 1);
    assert!(t.group_remove(group, task(1)), "and one removal empties it");
}

#[test]
fn removing_the_last_thread_says_the_group_is_dead() {
    let mut t = Tree::default();
    let g = group(100);
    t.group_add(g, task(1));
    t.group_add(g, task(2));
    assert!(!t.group_remove(g, task(1)), "one left");
    assert!(t.group_remove(g, task(2)), "none left");
    // And a group nothing ever joined is empty, which is the honest answer
    // for a caller asking about one that has already been forgotten.
    assert!(t.group_remove(group(999), task(1)));
}

#[test]
fn a_thread_can_be_removed_while_the_group_is_walked_backwards() {
    let mut t = Tree::default();
    let group = group(100);
    for n in 1..=5 {
        t.group_add(group, task(n));
    }
    // What do_exit_group's forced teardown does: drop every thread but one.
    for i in (0..t.group_len(group)).rev() {
        let th = t.group_at(group, i).unwrap();
        if th != task(3) {
            t.group_remove(group, th);
        }
    }
    assert_eq!(t.group_len(group), 1);
    assert_eq!(t.group_at(group, 0), Some(task(3)));
}

/// The failure a side table has that an intrusive list did not: a
/// `struct task` freed without saying so, and the next malloc returning
/// that address. The new task must not inherit the old one's children.
#[test]
fn an_address_that_arrives_still_registered_is_counted_and_replaced() {
    let mut t = Tree::default();
    t.add(task(1), None);
    t.add(task(2), Some(task(1)));
    t.add(task(3), Some(task(2)));
    assert_eq!(t.counts().2, 0);
    // task(2) is freed without remove, and a new one lands on it.
    t.add(task(2), Some(task(1)));
    assert_eq!(t.counts().2, 1, "counted");
    assert_eq!(t.children_len(task(2)), 0, "and not inheriting");
    assert_eq!(t.children_len(task(1)), 1, "nor listed twice under 1");
}

#[test]
fn a_group_address_that_arrives_still_in_use_is_counted_and_replaced() {
    let mut t = Tree::default();
    let group = group(100);
    t.group_add_new(group, task(1));
    t.group_add(group, task(2));
    assert_eq!(t.counts().2, 0);
    // The group is freed without forget, and a new one lands on it.
    t.group_add_new(group, task(3));
    assert_eq!(t.counts().2, 1);
    assert_eq!(t.group_len(group), 1, "one thread, not three");
    assert_eq!(t.group_at(group, 0), Some(task(3)));
}

#[test]
fn the_counts_follow_what_is_registered() {
    let mut t = Tree::default();
    assert_eq!(t.counts(), (0, 0, 0));
    t.add(task(1), None);
    t.group_add_new(group(100), task(1));
    assert_eq!(t.counts(), (1, 1, 0));
    t.remove(task(1));
    t.group_forget(group(100));
    assert_eq!(t.counts(), (0, 0, 0));
}

#[test]
fn the_c_api_adds_walks_and_reparents() {
    // Pointers, not identities: this is the test *for* the boundary in
    // `api.rs`, where a caller's `*mut task` becomes a key and a null becomes
    // the refusal or the miss.
    let ptr = |n: usize| n as Task;
    let (a, b, c) = (ptr(0x1000), ptr(0x2000), ptr(0x3000));
    assert!(add(a, std::ptr::null_mut()));
    assert!(add(b, a));
    assert!(add(c, a));
    assert_eq!(parent(b), a);
    assert_eq!(children_len(a), 2);
    assert_eq!(child_at(a, 0), b);
    assert_eq!(child_at(a, 2), std::ptr::null_mut());
    assert!(is_ancestor(c, a));

    set_parent(c, b);
    assert_eq!(parent(c), b);
    assert!(is_ancestor(c, a), "still, through b");

    remove(c);
    remove(b);
    remove(a);
    assert_eq!(parent(b), std::ptr::null_mut());
    assert!(!add(std::ptr::null_mut(), a));
}

/// Every entry point, handed a null.
///
/// **A characterisation test, not a regression test.** It passes against the
/// code before 2026-09-15 as well, and that is what it is for: a null used to
/// travel in as key `0` and miss because nothing could ever insert one, and it
/// is now refused by a `let else` in each of the fifteen entry points. The two
/// are meant to be indistinguishable, so this is what says the conversion
/// changed no behaviour — and what will fail if one of those arms is later
/// given the wrong answer.
#[test]
fn a_null_is_refused_by_the_three_that_insert_and_missed_by_the_rest() {
    let nil: Task = std::ptr::null_mut();
    let nil_group: Group = std::ptr::null_mut();
    let a = 0x9000 as Task;
    add(a, nil);

    // The three that insert refuse.
    assert!(!add(nil, a));
    assert!(!group_add(nil_group, a), "no group");
    assert!(!group_add(0x9100 as Group, nil), "no task");
    assert!(!group_add_new(nil_group, a));
    assert!(!group_add_new(0x9100 as Group, nil));

    // The rest miss, each with the answer its type calls "nothing".
    assert_eq!(parent(nil), nil);
    assert_eq!(children_len(nil), 0);
    assert_eq!(child_at(nil, 0), nil);
    assert!(!set_parent(nil, a));
    assert!(!is_ancestor(nil, a));
    assert!(!is_ancestor(a, nil));
    assert_eq!(group_len(nil_group), 0);
    assert_eq!(group_at(nil_group, 0), nil);
    // "The group is now empty" is the honest answer for a group that was never
    // there, and it is what key `0` answered too.
    assert!(group_remove(nil_group, a));
    remove(nil);
    group_forget(nil_group);

    remove(a);
}
