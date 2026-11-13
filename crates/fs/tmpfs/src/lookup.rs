//! Mount-relative tmpfs path resolution.

use super::*;

// ============================================================
// Path resolution
// ============================================================

/// Split a mount-relative path into components.
///
/// The empty path is the mount root. Otherwise the path starts with `/` and the
/// components are what lies between the slashes — including empty ones, which
/// then match no name, exactly as the C did.
pub(crate) fn components(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    let empty = path.is_empty();
    let rest = if empty { path } else { &path[1..] };
    rest.split(|&b| b == b'/').filter(move |_| !empty)
}

pub(crate) fn lookup(root: &Arc<Dirent>, path: &[u8]) -> Result<Arc<Dirent>> {
    let mut cursor = Arc::clone(root);
    for component in components(path) {
        if component.len() > MAX_NAME {
            return Err(ENAMETOOLONG);
        }
        if !cursor.is_dir() {
            return Err(ENOTDIR);
        }
        let next = cursor.children().lookup(component).ok_or(ENOENT)?;
        cursor = next;
    }
    Ok(cursor)
}

/// Resolve everything but the last component, returning it alongside.
pub(crate) fn lookup_parent<'a>(
    root: &Arc<Dirent>,
    path: &'a [u8],
) -> Result<(Arc<Dirent>, &'a [u8])> {
    let split = path.iter().rposition(|&b| b == b'/').ok_or(EEXIST)?;
    let (dir_path, name) = path.split_at(split);
    let name = &name[1..]; // drop the '/'
    if name.is_empty() {
        return Err(EEXIST); // a trailing slash names nothing new
    }
    if name.len() > MAX_NAME {
        return Err(ENAMETOOLONG);
    }
    let parent = lookup(root, dir_path)?;
    if !parent.is_dir() {
        return Err(ENOTDIR);
    }
    Ok((parent, name))
}
