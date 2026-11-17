//! The ordering rule and the boundary rule, which are the whole of what this
//! table decides.
//!
//! The mounts are real `struct mount`s with no filesystem: the table reads a
//! point and a refcount and nothing else. Until 2026-10-01 they were a
//! two-field stand-in cast to `*mut mount` and read through `cfg`-swapped
//! accessors, because the table held raw pointers.

use super::*;

fn fake(point: &str) -> Arc<ffi::mount> {
    Arc::new(ffi::mount {
        point: CString::new(point).unwrap(),
        ..Default::default()
    })
}

/// Inserts it, and keeps a pointer to compare against and retain from.
fn insert(point: &str) -> Mount {
    let m = fake(point);
    let p = Arc::as_ptr(&m).cast_mut();
    mounts_insert(m);
    p
}

/// One table for the whole process, so the tests run one at a time and each
/// empties it first.
static SERIAL: Mutex<()> = Mutex::new(());

fn fresh() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    with(|t| t.mounts.clear());
    g
}

fn find(path: &str) -> String {
    let c = CString::new(path).unwrap();
    // The reference mount_find takes is given back when `m` goes out of
    // scope, which is what makes the removal tests below see a zero count.
    let m = mount_find(&c);
    m.point.to_string_lossy().into_owned()
}

/// The defect this ordering exists for.
///
/// `/dev` is a prefix of `/dev/pts/0`, which belongs to `/dev/pts`. A lookup
/// that answers with any prefix-matching mount answers `/dev`, and because the
/// path walk resolves component by component the `/dev` lookup always came
/// first — so every `/dev/pts/N` was `ENOENT` and no pty slave could be opened.
#[test]
fn the_longest_matching_point_wins() {
    let _g = fresh();
    // Inserted shortest-first, so the ordering has to do the work.
    {
        insert("");
        insert("/dev");
        insert("/dev/pts");
    }
    assert_eq!(find("/dev/pts/0"), "/dev/pts");
    assert_eq!(find("/dev/null"), "/dev");
    assert_eq!(
        find("/etc/passwd"),
        "",
        "the root owns what nothing else does"
    );
}

/// Insertion order must not change the answer.
#[test]
fn the_order_is_kept_however_they_arrive() {
    let _g = fresh();
    {
        insert("/dev/pts");
        insert("");
        insert("/dev");
    }
    assert_eq!(find("/dev/pts/0"), "/dev/pts");
    // And the table itself is in descending order of point length.
    let lens: Vec<usize> = with_mounts(|ms| ms.iter().map(|m| point_of(m).len()).collect());
    assert!(
        lens.windows(2).all(|w| w[0] >= w[1]),
        "not descending: {lens:?}"
    );
}

/// A prefix that does not end on a component boundary is a different
/// directory.
#[test]
fn a_prefix_that_is_not_a_component_boundary_does_not_own_it() {
    let _g = fresh();
    {
        insert("");
        insert("/jail");
    }
    assert_eq!(find("/jail/x"), "/jail");
    assert_eq!(find("/jail"), "/jail", "the point itself");
    assert_eq!(find("/jail-old/x"), "", "not /jail");
}

#[test]
fn a_mount_in_use_cannot_be_taken() {
    let _g = fresh();
    insert("");
    let dev = insert("/dev");
    let held = unsafe { MountRef::retain(dev) };
    assert_eq!(mounts_take_point(c"/dev").err(), Some(EBUSY));
    drop(held);
    assert!(mounts_take_point(c"/dev").is_ok_and(|m| Arc::as_ptr(&m) == dev));
    assert_eq!(mounts_len(), 1, "and it is gone");
    // A second take finds nothing rather than removing whatever is left.
    assert_eq!(mounts_take_point(c"/dev").err(), Some(EINVAL));
}

#[test]
fn taking_by_point_reports_which_way_it_failed() {
    let _g = fresh();
    insert("");
    let dev = insert("/dev");
    assert_eq!(mounts_take_point(c"/nope").err(), Some(EINVAL), "no such point");

    let held = unsafe { MountRef::retain(dev) };
    assert_eq!(mounts_take_point(c"/dev").err(), Some(EBUSY), "still in use");

    drop(held);
    assert!(mounts_take_point(c"/dev").is_ok_and(|m| Arc::as_ptr(&m) == dev));
}

/// What makes a rename or an rmdir `EBUSY`, with the same boundary rule the
/// other way round.
#[test]
fn a_directory_with_something_mounted_under_it_is_busy() {
    let _g = fresh();
    {
        insert("");
        insert("/mnt/x");
    }
    let ask = |p: &str| {
        let c = CString::new(p).unwrap();
        contains_mount_point(&c)
    };
    assert!(ask("/mnt"), "/mnt/x is under it");
    assert!(ask("/mnt/x"), "and the point itself counts");
    assert!(!ask("/mnt/y"));
    assert!(!ask("/mnt-other"), "not a component boundary");
    assert!(ask(""), "everything is under the root");
}

/// Every path through [`MountRef`] leaves the count where it started, and the
/// one that does not is the shape `crates/kernel/memfdcalls` got wrong.
///
/// A descriptor's `mount` field is written by three functions and released by
/// one — `fd_finalize` — so a writer that stores the pointer *without* a
/// retain makes every close an unbalanced decrement. That is what memfd did
/// until 2026-09-12: `(*fd).mount = TABLES.mount` with no `+1`, against a
/// `-1` on every close. It was invisible because that mount is a leaked `Box`
/// the table never holds, so nothing ever read the count back.
///
/// The three shapes below are the whole of the type's arithmetic. The second
/// is the one that matters: `into_raw` must **not** decrement, or the field
/// would hold a reference nobody took, and `from_raw` must not increment, or
/// the close would give back one more than it was handed.
#[test]
fn the_guard_is_balanced_on_every_path_including_through_a_c_field() {
    let _g = fresh();
    let root = insert("");
    let count = || with_mounts(|ms| ms[0].refcount.load(SeqCst));
    assert_eq!(count(), 0, "a mount at rest holds nothing");

    // 1. A scope: find, use, drop.
    {
        let c = CString::new("/anything").unwrap();
        let m = mount_find(&c);
        assert_eq!(count(), 1, "mount_find takes one");
        assert_eq!(m.as_ptr(), root);
    }
    assert_eq!(count(), 0, "and the scope gives it back");

    // 2. Through a `#[repr(C)]` field: retain, into_raw, from_raw, drop. This
    //    is `adhoc_fd_create_for` and `fd_finalize`, and the count must be
    //    held for the whole of the middle -- a descriptor is open.
    let stored = unsafe { MountRef::retain(root) }.into_raw();
    assert_eq!(count(), 1, "into_raw hands the reference on, it does not drop it");
    drop(unsafe { MountRef::from_raw(stored) });
    assert_eq!(count(), 0, "and from_raw's drop is the release");

    // 3. Nested: two holders, and only the last one puts it back.
    let a = unsafe { MountRef::retain(root) };
    let b = unsafe { MountRef::retain(root) };
    assert_eq!(count(), 2);
    drop(a);
    assert_eq!(mounts_take_point(c"").err(), Some(EBUSY), "still in use");
    drop(b);
    assert_eq!(count(), 0);
    assert!(mounts_take_point(c"").is_ok(), "and now it can be unmounted");
}

/// Halting takes the mounts one at a time and stops at the first in use,
/// answering its point rather than spinning on it.
#[test]
fn taking_the_first_stops_at_one_in_use() {
    let _g = fresh();
    insert("");
    let dev = insert("/dev");
    let held = unsafe { MountRef::retain(dev) };
    let mine = current_mounts();
    assert_eq!(take_first(&mine).map(|r| r.err()), Some(Some(c"/dev".to_owned())));
    assert_eq!(mounts_len(), 2, "nothing was taken");
    drop(held);
    assert!(take_first(&mine).is_some_and(|r| r.is_ok()));
    assert!(take_first(&mine).is_some_and(|r| r.is_ok()));
    assert!(take_first(&mine).is_none());
}

/// Halting reaches every namespace's table, not only the halting thread's:
/// a mount only another namespace has is taken too, and a busy table is
/// passed over rather than ending the walk.
#[test]
fn halting_takes_every_namespaces_mounts() {
    let _g = fresh();
    let dev = insert("/dev");
    let held = unsafe { MountRef::retain(dev) };
    let theirs = taskview::nsproxy::Inherit::inherit(&*current_mounts());
    theirs.with(|t| {
        let only_theirs = Arc::new(ffi::mount { point: c"/only-theirs".to_owned(), ..Default::default() });
        t.mounts.insert(0, only_theirs);
    });
    let mut busy_tables = Vec::new();
    let mut taken = Vec::new();
    let mut busy_points = Vec::new();
    while let Some(r) = mounts_take_first_anywhere(&mut busy_tables) {
        match r {
            Ok(m) => taken.push(m.point.clone()),
            Err(p) => busy_points.push(p),
        }
    }
    assert_eq!(busy_points, [c"/dev".to_owned()], "ours is busy and passed over");
    assert!(taken.contains(&c"/only-theirs".to_owned()), "a mount only the other namespace has: {taken:?}");
    assert!(theirs.with(|t| t.mounts.is_empty()), "the other namespace's table is emptied");
    drop(held);
    current_mounts().with(|t| t.mounts.clear());
}

/// A new namespace's copy of a mount is the same filesystem with its own
/// id and nobody inside it.
#[test]
fn a_copy_shares_the_filesystem_and_not_the_id() {
    let _g = fresh();
    let p = insert("/copied");
    let held = mount_find(c"/copied/x");
    let copy = taskview::nsproxy::Inherit::inherit(&*current_mounts());
    let theirs = copy.with(|t| Arc::clone(t.mounts.iter().find(|m| point_of(m) == b"/copied").unwrap()));
    // SAFETY: in the table, and this test's.
    let ours = unsafe { &*p };
    assert!(Arc::ptr_eq(&ours.sb, &theirs.sb), "one superblock");
    assert_eq!(ours.id(), theirs.id(), "one filesystem identity");
    assert_ne!(ours.id, theirs.id, "two mount ids");
    assert_eq!(theirs.refcount.load(SeqCst), 0, "the holder is in ours");
    drop(held);
}

/// A table dropped with a mount still in use parks it until nothing is.
#[test]
fn a_busy_mount_of_a_dropped_table_is_parked_until_idle() {
    let _g = fresh();
    insert("/parked");
    let copy = taskview::nsproxy::Inherit::inherit(&*current_mounts());
    let theirs = copy.with(|t| Arc::clone(t.mounts.iter().find(|m| point_of(m) == b"/parked").unwrap()));
    // SAFETY: held by the `Arc` above, which outlives the reference.
    let held = unsafe { MountRef::retain(Arc::as_ptr(&theirs).cast_mut()) };
    drop(copy);
    let weak = Arc::downgrade(&theirs);
    drop(theirs);
    sweep_parked();
    assert!(weak.upgrade().is_some(), "still in use: parked");
    drop(held);
    sweep_parked();
    assert!(weak.upgrade().is_none(), "idle: freed");
}

/// A detached mount's files report `0:id` as their device, as a mounted
/// one's do: `st_dev` comes from the superblock since mounts share one, and
/// a detached mount's was left at its `Default`, so every pipe, socket and
/// memfd reported device 0 (`fdinfo_probe`'s epoll `sdev:`).
#[test]
fn a_detached_mount_reports_its_own_device() {
    struct NoFs;
    impl ffi::FsOps for NoFs {
        fn name(&self) -> Option<&'static std::ffi::CStr> {
            None
        }
        fn magic(&self) -> u32 {
            0
        }
    }
    static NO_FS: NoFs = NoFs;
    let id = next_mount_id();
    let m = DetachedMount::leak(&NO_FS, id);
    // SAFETY: leaked, so never freed.
    let m = unsafe { &*m.as_ptr() };
    assert_eq!(m.sb.dev, id);
    assert_ne!(m.dev(), 0);
}
