//! Every descriptor table this crate makes is given back, with every entry.
//!
//! **This is the only check in the tree that can see a leaked table.** The
//! failure mode of object model step 9.2 — turning `Table`'s hand-rolled
//! `AtomicUsize shares` into an `Arc`'s strong count — is a count one too high,
//! which keeps the table and every open file description in it for ever and
//! breaks nothing anything asserts. In particular:
//!
//! - `tests/guest/src/bin/fd_limit.rs` cannot see it. It measures descriptor
//!   *numbers* inside one table against `RLIMIT_NOFILE`; a leaked table is a
//!   second table, and the guest's numbering in the first is identical.
//! - `/proc/iul/objects` counts tasks, cleanup structs and mappings. It has
//!   never counted tables.
//! - The host's resident size moves by a few hundred bytes plus whatever the
//!   entry vector holds, which is inside the noise of anything that could
//!   measure it from a test.
//!
//! So the observable is a counter, [`fdtable::table_live_count`]. Two things
//! about where this test lives, both learned rather than reasoned:
//!
//! - It is an integration test rather than a `#[cfg(test)] mod` for the reason
//!   `crates/kernel/eventfd/tests/live_count.rs` gives about its own counter:
//!   cargo runs a crate's unit tests as threads of **one** process, and this
//!   crate's `src/tests.rs` makes tables in eight of them.
//! - **A separate binary is not enough — it has to be one `#[test]`.** cargo
//!   runs the test functions *within* a binary in parallel too, so several
//!   cases each reading a `before` another had already moved is a failure that
//!   looks like a leak. That is what happened to
//!   `crates/kernel/pagetable/tests/live_mappings.rs`, which is why the cases
//!   below are blocks of one function.
//!
//! Backed out to check it bites, three ways. Making `Drop for Table` skip its
//! entry loop is red at "the table's own teardown releases what it still
//! holds", `left: 0, right: 2`. Making [`fdtable::from_raw`] answer `None`
//! rather than reclaiming the reference — the `Arc` equivalent of a
//! `fdtable_release` that did not decrement — is red at "the field's own share
//! did not free the table", `left: 1, right: 0`. And making
//! [`fdtable::clone_raw`] increment twice, which is the refcount-one-too-high
//! this whole file exists for, is red at "the reader gave its share back, so
//! the field's is the only one left".

use std::ffi::c_int;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fdtable::{Ops, Table, table_live_count as live};

/// How many entry `release` callbacks have run. A leaked *table* and a leaked
/// *entry* are different defects — the second is a host file descriptor that is
/// never closed — and only the pair of counters tells them apart.
static RELEASES: AtomicUsize = AtomicUsize::new(0);

/// The finalizer, which runs when the **last** reference to one descriptor
/// goes. A leaked *table* and a leaked *entry* are different defects -- the
/// second is a host file descriptor that is never closed -- and only the pair
/// of counters tells them apart.
fn finalize() {
    RELEASES.fetch_add(1, Ordering::Relaxed);
}

/// A fixture description, whose last reference going is [`finalize`] -- as
/// `Drop for fd` is the product's.
struct Fake;

impl Drop for Fake {
    fn drop(&mut self) {
        finalize();
    }
}

/// The table's entry type here: a counted reference, as the product's is an
/// `Arc<fd>`.
#[derive(Clone)]
struct Fd(#[allow(dead_code)] Arc<Fake>); // held for its count, never read

impl fdtable::Descriptor for Fd {
    fn close(self) -> c_int {
        drop(self);
        0
    }
}

/// One field since 2026-09-12. An entry owns its reference, so the table
/// releases what it holds; `remove_locks` is not a lifetime operation.
fn ops() -> Ops<Fd> {
    Ops { remove_locks: None }
}

/// A reference to a fresh fixture description.
fn fake(_n: usize) -> Fd {
    Fd(Arc::new(Fake))
}

/// `is_shared` takes a raw table: it asks about the count behind `struct task`'s
/// field, which is a raw word.
fn raw(table: &Arc<Table<Fd>>) -> *mut Table<Fd> {
    Arc::as_ptr(table).cast_mut()
}

fn releases() -> usize {
    RELEASES.load(Ordering::Relaxed)
}

#[test]
fn every_table_and_every_entry_in_it_is_given_back() {
    assert_eq!(live(), 0, "something made a table before this test started");

    // ---- One table, two entries, one release.
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    assert_eq!(live(), 1);
    table.install_lowest(fake(1), 0, false, 32).ok();
    table.install_lowest(fake(2), 0, false, 32).ok();
    let before = releases();
    drop(table);
    assert_eq!(live(), 0, "the table was not freed");
    assert_eq!(
        releases() - before,
        2,
        "the table's own teardown releases what it still holds"
    );

    // ---- A share is a share: the first release of two frees nothing.
    //
    // This is what `CLONE_FILES` does, and what `/proc/<pid>/fd` does for the
    // length of one directory read.
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    table.install_lowest(fake(1), 0, false, 32).ok();
    let second = table.clone();
    assert!(unsafe { fdtable::is_shared(raw(&table)) });
    let before = releases();
    drop(table);
    assert_eq!(live(), 1, "one of two shares going must free nothing");
    assert_eq!(releases() - before, 0, "and must release no entry");
    assert!(!unsafe { fdtable::is_shared(raw(&second)) });
    drop(second);
    assert_eq!(live(), 0);
    assert_eq!(releases() - before, 1);

    // ---- A copy is a second table, not a second share.
    //
    // `fork` without `CLONE_FILES`: every occupied slot gains a reference and
    // the two tables are then independent. Releasing one must free one.
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    table.install_lowest(fake(1), 0, false, 32).ok();
    table.install_lowest(fake(2), 0, false, 32).ok();
    let copy = table.copy().expect("the copy allocates");
    assert_eq!(live(), 2, "a copy is a second table");
    assert!(
        !unsafe { fdtable::is_shared(raw(&table)) },
        "and neither of the two is shared"
    );
    let before = releases();
    drop(copy);
    assert_eq!(live(), 1);
    // **Zero, not two.** The copy took a *reference* per slot, not a second
    // description, so dropping it takes each count from 2 to 1 and finalizes
    // nothing. This asserted 2 until 2026-09-12, when the entries held
    // addresses and the table called a `release` callback per slot whether or
    // not it was the last -- so the number it counted was releases, and the
    // number that matters is finalizations.
    assert_eq!(releases() - before, 0, "the original still holds both");
    drop(table);
    assert_eq!(live(), 0);
    assert_eq!(releases() - before, 2, "and the last table to go frees them");

    // ---- Emptying a table is not freeing it.
    //
    // `execve` runs `exec_close` and keeps the table; `close_range`
    // empties a span of it. A destructor that ran on the last *entry* rather
    // than the last *share* would free the table under its owner here.
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    table.install_lowest(fake(1), 0, true, 32).ok();
    table.install_lowest(fake(2), 0, false, 32).ok();
    let before = releases();
    table.exec_close();
    assert_eq!(live(), 1, "exec closes descriptors, not the table");
    assert_eq!(releases() - before, 1, "the CLOEXEC one only");
    table.close_range(0, u32::MAX, false);
    assert_eq!(live(), 1, "close_range closes descriptors, not the table");
    assert_eq!(releases() - before, 2);
    drop(table);
    assert_eq!(live(), 0);
    assert_eq!(
        releases() - before,
        2,
        "an emptied table releases nothing a second time"
    );

    // ---- `take` hands the reference out; the table must not release
    // it again when it goes.
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    table.install_lowest(fake(1), 0, false, 32).ok();
    let taken = table.take(0);
    assert!(taken.is_some(), "take answers the reference the slot held");
    let before = releases();
    drop(table);
    assert_eq!(live(), 0);
    assert_eq!(
        releases() - before,
        0,
        "a slot taken out is the caller's reference now"
    );

    // ---- The task's field: a share held in a slot, and taken back out.
    //
    // `set` is what publishes the table, `clone_arc` is what `/proc/<pid>/fd`
    // takes under `pids_lock`, and `take` is what `do_exit` gives back.
    let table = Table::new(0, ops()).expect("a table with no slots allocates");
    table.install_lowest(fake(1), 0, false, 32).ok();
    let field = util_arcslot::ArcSlot::new(Some(table));
    assert_eq!(live(), 1);

    let reader = unsafe { field.clone_arc() }.expect("the field is not empty");
    assert!(unsafe { fdtable::is_shared(field.as_ptr()) }, "the reader's share");
    drop(reader);
    assert_eq!(
        live(),
        1,
        "a share taken through the field and given back frees the table"
    );
    assert!(
        !unsafe { fdtable::is_shared(field.as_ptr()) },
        "the reader gave its share back, so the field's is the only one left"
    );

    // `fork(CLONE_FILES)`: the child's field holds a share of its own.
    let child = util_arcslot::ArcSlot::new(unsafe { field.clone_arc() });
    assert!(unsafe { fdtable::is_shared(field.as_ptr()) });
    drop(child);
    assert_eq!(live(), 1, "the child's share went, not the parent's");
    let before = releases();
    drop(field.take());
    assert_eq!(live(), 0, "the field's own share did not free the table");
    assert_eq!(releases() - before, 1, "and the entry went with it");

    // An empty field is a task on its way out, which every reader has to expect.
    assert!(unsafe { field.clone_arc() }.is_none());
    assert!(field.take().is_none());
    assert!(!unsafe { fdtable::is_shared::<Fd>(std::ptr::null()) });

    assert_eq!(live(), 0, "a table outlived the test");
}
