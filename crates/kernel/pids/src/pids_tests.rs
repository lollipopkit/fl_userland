//! Tests for PID registry membership and process counts.

use super::*;
use crate::model::{Handle, Membership, TaskId};

/// Handles are keys, so any three distinct addresses will do — and none of
/// them names a thread group that exists. That is the property
/// `taskview::ffi::Identity` is built around: it is never dereferenced, so
/// constructing one is safe and a test can say what it is about without
/// building three processes to say it.
const fn h(addr: usize) -> Handle {
    match Handle::from_ptr(addr as *mut _) {
        Some(h) => h,
        None => panic!("not null"),
    }
}
const A: Handle = h(0x1000);
const B: Handle = h(0x2000);
const C: Handle = h(0x3000);
/// A task identity, for the pid table's tests.
const fn task(addr: usize) -> TaskId {
    match TaskId::from_ptr(addr as *mut _) {
        Some(t) => t,
        None => panic!("not null"),
    }
}

#[test]
fn an_empty_registry_answers_nothing() {
    let m = Membership::new();
    assert_eq!(m.ids(A), None);
    assert!(m.pgroup(1).is_empty());
    assert!(m.session(1).is_empty());
    assert!(!m.number_in_use(1));
    m.check();
}

#[test]
fn joining_a_group_files_it_under_that_group() {
    // The bug this crate exists for: setpgid filed a joining process under
    // its own number, so the group's list did not contain it and every
    // signal to the group missed it -- while getpgid still agreed.
    let mut m = Membership::new();
    m.set_sid(A, 10);
    m.set_pgid(A, 10);
    m.set_sid(B, 10);
    m.set_pgid(B, 20);
    m.check();
    // B joins A's group.
    m.set_pgid(B, 10);
    m.check();
    assert_eq!(m.ids(B), Some((10, 10)));
    assert_eq!(m.pgroup(10).len(), 2, "both members are in it");
    assert!(m.pgroup(10).contains(&A) && m.pgroup(10).contains(&B));
    assert!(
        m.pgroup(20).is_empty(),
        "and none is left behind in the old one"
    );
}

#[test]
fn a_session_is_recorded_under_the_session_number() {
    // The other bug: setsid from a non-leader thread filed both records
    // under the calling thread's number.
    let mut m = Membership::new();
    m.set_sid(A, 7);
    m.set_pgid(A, 7);
    m.check();
    assert_eq!(m.session(7), &[A]);
    assert!(m.session(999).is_empty(), "not under some other number");
}

#[test]
fn moving_between_groups_leaves_nothing_stale() {
    let mut m = Membership::new();
    m.set_sid(A, 1);
    for pgid in [5, 6, 7, 5, 8] {
        m.set_pgid(A, pgid);
        m.check();
        assert_eq!(m.pgroup(pgid), &[A]);
    }
    assert_eq!(m.ids(A), Some((8, 1)));
    for pgid in [5, 6, 7] {
        assert!(m.pgroup(pgid).is_empty(), "group {pgid} still lists it");
    }
}

#[test]
fn a_child_starts_where_its_parent_is() {
    let mut m = Membership::new();
    m.set_sid(A, 3);
    m.set_pgid(A, 4);
    m.insert_like(B, A);
    m.check();
    assert_eq!(m.ids(B), Some((4, 3)));
    assert_eq!(m.pgroup(4).len(), 2);
    assert_eq!(m.session(3).len(), 2);
}

#[test]
fn a_child_of_an_unregistered_parent_is_nowhere() {
    // The first process, before anything has placed it.
    let mut m = Membership::new();
    m.insert_like(B, A);
    m.check();
    assert_eq!(m.ids(B), None);
}

#[test]
fn removing_takes_it_out_of_both() {
    let mut m = Membership::new();
    m.set_sid(A, 3);
    m.set_pgid(A, 4);
    m.set_sid(B, 3);
    m.set_pgid(B, 4);
    m.remove(A);
    m.check();
    assert_eq!(m.ids(A), None);
    assert_eq!(m.pgroup(4), &[B]);
    assert_eq!(m.session(3), &[B]);
    m.remove(B);
    m.check();
    assert!(!m.number_in_use(3));
    assert!(!m.number_in_use(4));
}

#[test]
fn removing_one_that_is_not_there_is_nothing() {
    let mut m = Membership::new();
    m.remove(A);
    m.check();
}

#[test]
fn a_number_stays_in_use_while_it_names_a_session() {
    // A session id outlives its leader: the number may not be handed out
    // again while anything is still in that session, which is what
    // pid_empty was asking with two list_empty calls.
    let mut m = Membership::new();
    m.set_sid(A, 9);
    m.set_pgid(A, 11);
    m.remove(A);
    assert!(!m.number_in_use(9));
    m.set_sid(B, 9);
    m.set_pgid(B, 12);
    assert!(m.number_in_use(9), "still a session");
    assert!(m.number_in_use(12));
    assert!(!m.number_in_use(11), "the old group is gone");
    m.check();
}

#[test]
fn setting_the_same_group_twice_does_not_duplicate_it() {
    let mut m = Membership::new();
    m.set_sid(A, 1);
    m.set_pgid(A, 2);
    m.set_pgid(A, 2);
    m.set_pgid(A, 2);
    m.check();
    assert_eq!(m.pgroup(2).len(), 1);
}

#[test]
fn three_groups_in_one_session() {
    let mut m = Membership::new();
    for (h, pgid) in [(A, 10), (B, 20), (C, 30)] {
        m.set_sid(h, 10);
        m.set_pgid(h, pgid);
    }
    m.check();
    assert_eq!(m.session(10).len(), 3);
    assert_eq!(m.pgroup(10), &[A]);
    assert_eq!(m.pgroup(20), &[B]);
    assert_eq!(m.pgroup(30), &[C]);
}

#[test]
fn the_table_starts_empty_and_grows_to_what_is_used() {
    let mut t = Table::new();
    // `None` where this read `0` until 2026-09-15: an empty slot is the
    // absence of a task, and `Option<TaskId>` is the same eight bytes as the
    // `usize` that spelled it with a sentinel.
    assert_eq!(t.get(1), None);
    assert_eq!(t.get(100000), None, "past the end is not a fault");
    assert_eq!(t.get(-1), None, "and neither is a negative number");
    assert_eq!(t.used(), 0);
    assert!(t.set(40, Some(task(0x1000))));
    assert_eq!(t.get(40), Some(task(0x1000)));
    assert_eq!(t.used(), 1);
    t.clear(40);
    assert_eq!(t.get(40), None);
    assert_eq!(t.used(), 0);
}

#[test]
fn setting_the_same_slot_twice_counts_once() {
    let mut t = Table::new();
    t.set(3, Some(task(0x1000)));
    t.set(3, Some(task(0x2000)));
    assert_eq!(t.used(), 1);
    assert_eq!(t.get(3), Some(task(0x2000)));
    t.clear(3);
    t.clear(3);
    assert_eq!(t.used(), 0, "and clearing twice does not go negative");
}

/// A non-leader `execve` swaps the process's number and its own: a reference
/// to the process's number -- a pidfd -- names the exec'ing task afterwards,
/// and one to the thread's old number names the old leader, which is about
/// to be released. A set would have made both stale.
#[test]
fn an_exchange_keeps_each_numbers_references() {
    let mut t = Table::new();
    t.set(10, Some(task(0x100)));
    t.set(12, Some(task(0x120)));
    let (process, thread) = (t.refer(10).unwrap(), t.refer(12).unwrap());
    assert!(t.exchange(10, 12));
    assert_eq!(t.by_ref(process), Some(task(0x120)));
    assert_eq!(t.by_ref(thread), Some(task(0x100)));
    assert_eq!(t.used(), 2);
    assert!(!t.exchange(10, 13), "an empty number is not exchanged");
    assert_eq!(t.get(10), Some(task(0x120)));
}

/// The pid-reuse rule. A reference taken from a task names that task and
/// nothing else: not the empty slot after it is reaped, and not the next
/// task to be handed the same number.
#[test]
fn a_reference_stops_naming_a_number_once_it_is_filled_again() {
    let mut t = Table::new();
    assert!(t.refer(5).is_none(), "nothing there yet");
    t.set(5, Some(task(0x50)));
    let first = t.refer(5).unwrap();
    assert_eq!(first.pid, 5);
    assert_eq!(t.by_ref(first), Some(task(0x50)));

    t.clear(5);
    assert!(t.refer(5).is_none());
    assert_eq!(t.by_ref(first), None, "the task is gone");

    t.set(5, Some(task(0x51)));
    assert_eq!(t.by_ref(first), None, "another task at the same number");
    let second = t.refer(5).unwrap();
    assert_ne!(first, second);
    assert_eq!(t.by_ref(second), Some(task(0x51)));

    // A reference to a number the table has never grown to is nothing,
    // not a panic.
    assert_eq!(
        t.by_ref(TaskRef {
            pid: 4000,
            generation: 1
        }),
        None
    );
    assert_eq!(
        t.by_ref(TaskRef {
            pid: -1,
            generation: 1
        }),
        None
    );
}

#[test]
fn numbers_go_up_and_wrap() {
    // Not reusing a number immediately is what makes a stale pid in a
    // guest's hands usually fail rather than name someone else.
    let mut r = Registry::new();
    assert_eq!(r.alloc(4), Some(1));
    r.tasks.set(1, Some(task(0x10)));
    assert_eq!(r.alloc(4), Some(2));
    r.tasks.set(2, Some(task(0x20)));
    assert_eq!(r.alloc(4), Some(3));
    r.tasks.set(3, Some(task(0x30)));
    assert_eq!(r.alloc(4), Some(4));
    r.tasks.set(4, Some(task(0x40)));
    // Full.
    assert_eq!(r.alloc(4), None, "every number taken");
    // Freeing the middle one hands it back, after the wrap.
    r.tasks.clear(2);
    assert_eq!(r.alloc(4), Some(2));
}

/// A number handed out and not yet filled is not handed out again: a task is
/// built before it is published, and two forks on two threads would otherwise
/// be given the same pid. Filling it or clearing it takes the reservation.
#[test]
fn a_number_handed_out_is_spoken_for_until_it_is_filled() {
    let mut r = Registry::new();
    assert_eq!(r.alloc(3), Some(1));
    assert_eq!(r.alloc(3), Some(2), "1 is reserved");
    assert_eq!(r.alloc(3), Some(3));
    assert_eq!(r.alloc(3), None, "all three reserved, none filled");
    r.tasks.clear(2);
    assert_eq!(r.alloc(3), Some(2), "a cleared reservation is free again");
    r.tasks.set(1, Some(task(0x10)));
    assert!(!r.tasks.is_reserved(1), "filling it takes the reservation");
    assert_eq!(r.tasks.used(), 1, "and a reservation was never a task");
}

#[test]
fn a_full_table_answers_rather_than_spinning() {
    // The loop this replaces had no bound at all: a guest that forked and
    // never waited filled the table with zombies and the next fork spun for
    // ever holding pids_lock.
    let mut r = Registry::new();
    for i in 1..=8 {
        r.tasks.set(i, Some(task(0x1000 + i as usize)));
    }
    assert_eq!(r.alloc(8), None);
    assert_eq!(r.alloc(8), None, "and again, without moving");
}

#[test]
fn a_number_a_session_still_names_is_not_free() {
    // A session id outlives its leader, and the number may not be handed
    // out again while anything is still in that session.
    let mut r = Registry::new();
    r.tasks.set(1, Some(task(0x10)));
    r.tasks.set(2, Some(task(0x20)));
    r.members.set_sid(A, 3);
    r.members.set_pgid(A, 3);
    assert!(!r.free(3));
    // 1 and 2 hold tasks, 3 names a session: nothing is left.
    assert_eq!(r.alloc(3), None);
    r.members.remove(A);
    assert!(r.free(3));
    assert_eq!(r.alloc(3), Some(3));
}

#[test]
fn a_limit_below_one_hands_out_nothing() {
    let mut r = Registry::new();
    assert_eq!(r.alloc(0), None);
    assert_eq!(r.alloc(-1), None);
}

#[test]
fn an_empty_count_is_zero() {
    let p = ProcCount::new();
    assert_eq!(p.get(0), 0);
    assert_eq!(p.get(1000), 0);
    assert_eq!(p.users(), 0);
}

#[test]
fn the_limit_is_the_count_not_the_count_plus_one() {
    // `have >= limit` refuses, so a limit of 2 admits exactly two. Written
    // as `>` it would admit three, which is the same off-by-one that made
    // timer_settime index one past its array.
    let mut p = ProcCount::new();
    assert!(p.try_add(7, 2, false));
    assert!(p.try_add(7, 2, false));
    assert!(!p.try_add(7, 2, false));
    assert_eq!(p.get(7), 2);
}

#[test]
fn a_limit_of_zero_admits_nothing() {
    let mut p = ProcCount::new();
    assert!(!p.try_add(7, 0, false));
    assert_eq!(p.get(7), 0);
}

#[test]
fn the_superuser_goes_past_it_and_is_still_counted() {
    // Still counted, so a process that drops privilege afterwards does not
    // get its share back.
    let mut p = ProcCount::new();
    assert!(p.try_add(0, 1, true));
    assert!(p.try_add(0, 1, true));
    assert_eq!(p.get(0), 2);
}

#[test]
fn users_do_not_share_a_limit() {
    let mut p = ProcCount::new();
    assert!(p.try_add(7, 1, false));
    assert!(!p.try_add(7, 1, false));
    assert!(p.try_add(8, 1, false), "a different user has its own");
    assert_eq!(p.users(), 2);
}

#[test]
fn removing_makes_room_again() {
    let mut p = ProcCount::new();
    assert!(p.try_add(7, 1, false));
    assert!(!p.try_add(7, 1, false));
    p.remove(7);
    assert_eq!(p.get(7), 0);
    assert!(p.try_add(7, 1, false));
}

#[test]
fn an_emptied_user_leaves_no_entry() {
    // Otherwise a guest creating processes under many uids leaves a map
    // entry per uid for the life of the process.
    let mut p = ProcCount::new();
    for uid in 0..100 {
        assert!(p.try_add(uid, 10, false));
    }
    assert_eq!(p.users(), 100);
    for uid in 0..100 {
        p.remove(uid);
    }
    assert_eq!(p.users(), 0);
}

#[test]
fn removing_one_that_is_not_there_does_nothing() {
    // The exit path calls this for every task, and a task that was never
    // counted -- the very first one, before the count existed -- must not
    // wrap the counter to four billion.
    let mut p = ProcCount::new();
    p.remove(7);
    assert_eq!(p.get(7), 0);
    assert!(p.try_add(7, 1, false));
    assert_eq!(p.get(7), 1);
}

/// The owner word answers for *this* thread, which is what makes it usable as
/// an assertion.
///
/// Written because the first back-out of `crates/kernel/exitcalls`' `Deferred`
/// did not fire and the helper was the suspect. It was not: the back-out was
/// wrong, twice, because Rust drops locals in **reverse** declaration order and
/// both attempts still put the guard's drop first. A gate that does not fire is
/// two hypotheses, and this settles one of them here rather than through a
/// guest.
#[test]
fn the_lock_knows_whether_this_thread_holds_it() {
    assert!(!super::held_by_this_thread(), "held before taking it");
    let g = super::PidsGuard::take();
    assert!(super::held_by_this_thread(), "not held after taking it");
    drop(g);
    assert!(!super::held_by_this_thread(), "still held after dropping it");
}

/// A `try_take` that finds the lock held gives back nothing -- and in
/// particular does not release the holder's lock.
///
/// It was `free.then_some(PidsGuard(()))`, and `then_some` evaluates its
/// argument whether or not `free` is true: on the failing branch a guard was
/// built and dropped, and its `Drop` unlocked a mutex another thread held.
/// `crates/asbestos/blockcache`'s `SyncGuard::try_take` records the same
/// shape crashing `task_race` five runs of five.
#[test]
fn a_failed_try_take_leaves_the_holders_lock_held() {
    let held = PidsGuard::take();
    let other = std::thread::spawn(|| PidsGuard::try_take().is_none()).join().unwrap();
    assert!(other, "the lock was free to another thread while held here");
    assert!(held_by_this_thread(), "the failed try_take released this thread's lock");
    drop(held);
    assert!(PidsGuard::try_take().is_some());
}
