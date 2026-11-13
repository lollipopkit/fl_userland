use super::*;

fn dir_inode() -> Arc<Inode> {
    Inode::new(S_IFDIR | 0o755, 0, 0, 0)
}
fn file_inode() -> Arc<Inode> {
    Inode::new(S_IFREG | 0o644, 0, 0, 0)
}
fn root() -> Arc<Dirent> {
    Dirent::new_root(Inode::new(S_IFDIR | 0o777, 0, 0, 0))
}

#[test]
fn a_dropped_tree_frees_its_inodes() {
    // In C, parent and child were strong references to each other, so a
    // tmpfs tree never reached refcount zero and tmpfs_umount was a TODO
    // that leaked it. A Weak parent is what makes this pass.
    let root = root();
    let leaf = file_inode();
    let watch = Arc::downgrade(&leaf);
    let dir = link_into(&root, b"dir", dir_inode()).unwrap();
    link_into(&dir, b"file", leaf).unwrap();

    assert!(watch.upgrade().is_some());
    drop(dir);
    drop(root);
    assert!(watch.upgrade().is_none(), "the tree should have been freed");
}

#[test]
fn path_walks_all_the_way_up() {
    let root = root();
    let a = link_into(&root, b"a", dir_inode()).unwrap();
    let b = link_into(&a, b"b", dir_inode()).unwrap();
    let c = link_into(&b, b"c", file_inode()).unwrap();
    assert_eq!(root.path_within_mount(), b"");
    assert_eq!(c.path_within_mount(), b"/a/b/c");
}

#[test]
fn unlink_removes_the_name_and_keeps_an_open_inode_alive() {
    let root = root();
    let file = link_into(&root, b"f", file_inode()).unwrap();
    let inode = Arc::clone(&file.inode);
    inode.lock().data = b"contents".to_vec().into();

    unlink_from(&root, b"f", false).unwrap();

    assert!(root.children().lookup(b"f").is_none());
    assert_eq!(inode.lock().nlink, 0);
    // Still readable through the reference an open fd would hold.
    assert_eq!(inode.lock().data.in_memory().unwrap(), b"contents");
    assert_eq!(unlink_from(&root, b"f", false).unwrap_err(), ENOENT);
}

#[test]
fn a_hardlink_shares_the_inode_and_the_link_count() {
    let root = root();
    let a = link_into(&root, b"a", file_inode()).unwrap();
    let b = link_into(&root, b"b", Arc::clone(&a.inode)).unwrap();

    assert_eq!(a.inode.ino, b.inode.ino);
    assert_eq!(a.inode.lock().nlink, 2);
    unlink_from(&root, b"a", false).unwrap();
    assert_eq!(b.inode.lock().nlink, 1);
}

#[test]
fn rmdir_requires_an_empty_directory() {
    let root = root();
    let dir = link_into(&root, b"d", dir_inode()).unwrap();
    link_into(&dir, b"inside", file_inode()).unwrap();

    assert_eq!(unlink_from(&root, b"d", true).unwrap_err(), ENOTEMPTY);
    unlink_from(&dir, b"inside", false).unwrap();
    unlink_from(&root, b"d", true).unwrap();
    assert!(root.children().lookup(b"d").is_none());
}

#[test]
fn rmdir_on_a_file_and_unlink_on_a_directory_are_refused() {
    let root = root();
    link_into(&root, b"f", file_inode()).unwrap();
    link_into(&root, b"d", dir_inode()).unwrap();
    assert_eq!(unlink_from(&root, b"f", true).unwrap_err(), ENOTDIR);
    assert_eq!(
        unlink_from(&root, b"d", false).unwrap_err(),
        crate::errno::EISDIR
    );
}

#[test]
fn rename_moves_an_entry_and_its_subtree() {
    let root = root();
    let src = link_into(&root, b"src", dir_inode()).unwrap();
    link_into(&src, b"child", file_inode()).unwrap();
    let dst = link_into(&root, b"dst", dir_inode()).unwrap();

    rename(&root, b"src", &dst, b"moved", 0).unwrap();

    assert!(root.children().lookup(b"src").is_none());
    let moved = dst.children().lookup(b"moved").unwrap();
    assert!(moved.children().lookup(b"child").is_some());
    assert_eq!(moved.path_within_mount(), b"/dst/moved");
}

#[test]
fn rename_over_an_existing_file_replaces_it() {
    let root = root();
    let a = link_into(&root, b"a", file_inode()).unwrap();
    a.inode.lock().data = b"new".to_vec().into();
    link_into(&root, b"b", file_inode()).unwrap();

    rename(&root, b"a", &root, b"b", 0).unwrap();

    assert!(root.children().lookup(b"a").is_none());
    let b = root.children().lookup(b"b").unwrap();
    assert_eq!(b.inode.lock().data.in_memory().unwrap(), b"new");
}

#[test]
fn noreplace_refuses_an_existing_destination_and_changes_nothing() {
    let root = root();
    let a = link_into(&root, b"a", file_inode()).unwrap();
    a.inode.lock().data = b"new".to_vec().into();
    let b = link_into(&root, b"b", file_inode()).unwrap();
    b.inode.lock().data = b"old".to_vec().into();

    assert_eq!(
        rename(&root, b"a", &root, b"b", RENAME_NOREPLACE).unwrap_err(),
        EEXIST
    );
    // Both ends untouched: the point of the flag is that whoever got there
    // first keeps the name.
    assert_eq!(
        root.children().lookup(b"a").unwrap().inode.lock().data.in_memory().unwrap(),
        b"new"
    );
    assert_eq!(
        root.children().lookup(b"b").unwrap().inode.lock().data.in_memory().unwrap(),
        b"old"
    );
}

#[test]
fn noreplace_onto_a_free_name_is_a_plain_rename() {
    let root = root();
    link_into(&root, b"a", file_inode()).unwrap();
    rename(&root, b"a", &root, b"b", RENAME_NOREPLACE).unwrap();
    assert!(root.children().lookup(b"a").is_none());
    assert!(root.children().lookup(b"b").is_some());
}

#[test]
fn exchange_swaps_two_names_and_keeps_both_inodes() {
    let root = root();
    let a = link_into(&root, b"a", file_inode()).unwrap();
    a.inode.lock().data = b"AAA".to_vec().into();
    let b = link_into(&root, b"b", file_inode()).unwrap();
    b.inode.lock().data = b"BBB".to_vec().into();
    let (a_ino, b_ino) = (a.inode.ino, b.inode.ino);

    rename(&root, b"a", &root, b"b", RENAME_EXCHANGE).unwrap();

    // Neither name is gone, and each now names the other's inode. A pair
    // of plain renames cannot produce this: one of the two names would not
    // exist in between.
    // One statement each: as two elements of a tuple, the first
    // MutexGuard is a temporary that lives to the end of the statement and
    // the second lock on the same children map deadlocks against it. The
    // note above `let existing` in `rename` is about the same hazard.
    let a2 = root.children().lookup(b"a").unwrap();
    let b2 = root.children().lookup(b"b").unwrap();
    assert_eq!(a2.inode.ino, b_ino);
    assert_eq!(b2.inode.ino, a_ino);
    assert_eq!(a2.inode.lock().data.in_memory().unwrap(), b"BBB");
    assert_eq!(b2.inode.lock().data.in_memory().unwrap(), b"AAA");
}

#[test]
fn exchange_across_directories_moves_both_and_their_subtrees() {
    let root = root();
    let d = link_into(&root, b"d", dir_inode()).unwrap();
    let sub = link_into(&root, b"sub", dir_inode()).unwrap();
    link_into(&d, b"child", file_inode()).unwrap();
    let f = link_into(&sub, b"f", file_inode()).unwrap();
    f.inode.lock().data = b"F".to_vec().into();

    rename(&root, b"d", &sub, b"f", RENAME_EXCHANGE).unwrap();

    // The directory is now /sub/f and carries its child; the file is /d.
    let moved_dir = sub.children().lookup(b"f").unwrap();
    assert!(moved_dir.children().lookup(b"child").is_some());
    assert_eq!(moved_dir.path_within_mount(), b"/sub/f");
    let moved_file = root.children().lookup(b"d").unwrap();
    assert_eq!(moved_file.inode.lock().data.in_memory().unwrap(), b"F");
}

#[test]
fn exchange_needs_both_ends_to_exist() {
    let root = root();
    link_into(&root, b"a", file_inode()).unwrap();
    assert_eq!(
        rename(&root, b"a", &root, b"gone", RENAME_EXCHANGE).unwrap_err(),
        ENOENT
    );
    assert!(root.children().lookup(b"a").is_some());
}

#[test]
fn exchange_will_not_detach_a_subtree_in_either_direction() {
    // Swapping a directory with something inside it would leave the
    // subtree hanging off nothing, the same way renaming into it would --
    // and an exchange moves both ends, so it has to be refused whichever
    // way round the pair is given.
    let root = root();
    let outer = link_into(&root, b"outer", dir_inode()).unwrap();
    let inner = link_into(&outer, b"inner", dir_inode()).unwrap();
    // Created first: an exchange needs both ends to exist, so without it
    // the lookup answers ENOENT and the ancestry check is never reached --
    // which is what this test would then have been asserting.
    link_into(&inner, b"x", file_inode()).unwrap();
    assert_eq!(
        rename(&root, b"outer", &inner, b"x", RENAME_EXCHANGE).unwrap_err(),
        EINVAL
    );
    assert_eq!(
        rename(&inner, b"x", &root, b"outer", RENAME_EXCHANGE).unwrap_err(),
        EINVAL
    );
}

#[test]
fn renaming_a_directory_into_itself_is_refused() {
    // Allowing it would detach the subtree from the tree entirely.
    let root = root();
    let outer = link_into(&root, b"outer", dir_inode()).unwrap();
    let inner = link_into(&outer, b"inner", dir_inode()).unwrap();
    assert_eq!(
        rename(&root, b"outer", &inner, b"x", 0).unwrap_err(),
        EINVAL
    );
}

#[test]
fn indices_are_monotonic_so_seekdir_keeps_meaning_the_same_entry() {
    let root = root();
    for name in [&b"a"[..], b"b", b"c"] {
        link_into(&root, name, file_inode()).unwrap();
    }
    let b_index = root.children().lookup(b"b").unwrap().index();
    unlink_from(&root, b"b", false).unwrap();
    assert_eq!(root.children().at_or_after(b_index).unwrap().name(), b"c");
    let d = link_into(&root, b"d", file_inode()).unwrap();
    assert!(d.index() > b_index, "an index must not be reused");
}
