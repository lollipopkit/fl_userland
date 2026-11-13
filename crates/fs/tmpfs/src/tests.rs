//! Tests for tmpfs path lookup and parent resolution.

use super::*;

fn root() -> Arc<Dirent> {
    Dirent::new_root(Inode::new(S_IFDIR | 0o777, 0, 0, 0))
}

#[test]
fn empty_path_is_the_mount_root() {
    let root = root();
    assert!(Arc::ptr_eq(&lookup(&root, b"").unwrap(), &root));
}

#[test]
fn components_match_path_next_component() {
    let got: Vec<&[u8]> = components(b"/a/b").collect();
    assert_eq!(got, vec![&b"a"[..], b"b"]);
    // A lone slash yields one empty component, matching no name — the same
    // as the C, where it produced an empty `component` buffer.
    assert_eq!(components(b"/").collect::<Vec<_>>(), vec![&b""[..]]);
    // The empty path yields nothing: it is the mount root.
    assert_eq!(components(b"").count(), 0);
}

#[test]
fn lookup_descends_and_reports_missing_names() {
    let root = root();
    let dir = link_into(&root, b"dir", Inode::new(S_IFDIR | 0o755, 0, 0, 0)).unwrap();
    link_into(&dir, b"file", Inode::new(S_IFREG | 0o644, 0, 0, 0)).unwrap();

    assert_eq!(lookup(&root, b"/dir/file").unwrap().name(), b"file");
    assert_eq!(lookup(&root, b"/dir/nope").unwrap_err(), ENOENT);
    // Descending through a regular file is ENOTDIR, not ENOENT.
    assert_eq!(lookup(&root, b"/dir/file/x").unwrap_err(), ENOTDIR);
}

#[test]
fn an_overlong_component_is_enametoolong() {
    let root = root();
    let mut path = vec![b'/'];
    path.extend(std::iter::repeat_n(b'x', MAX_NAME + 1));
    assert_eq!(lookup(&root, &path).unwrap_err(), ENAMETOOLONG);
}

#[test]
fn lookup_parent_splits_the_last_component() {
    let root = root();
    let dir = link_into(&root, b"dir", Inode::new(S_IFDIR | 0o755, 0, 0, 0)).unwrap();
    let (parent, name) = lookup_parent(&root, b"/dir/new").unwrap();
    assert!(Arc::ptr_eq(&parent, &dir));
    assert_eq!(name, b"new");
    assert_eq!(lookup_parent(&root, b"/dir/").unwrap_err(), EEXIST);
}
