//! In-memory bind mount table and path resolution.

use std::os::raw::c_int;

#[cfg(test)]
use crate::MAX_PATH;

use guest_errno::c_int_::ENOMEM;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mount {
    /// The guest prefix, normalised.
    pub path: String,
    /// The host directory it stands for, without a trailing slash.
    pub host_path: String,
    /// Writes under it are refused with `EROFS`. The guest's root bypasses the
    /// ordinary permission check, so the mode bits in `meta.db` are not enough.
    pub read_only: bool,
}

#[derive(Default)]
pub struct Table {
    mounts: Vec<Mount>,
    /// The host path of the fakefs `data/` directory, once the embedder says.
    rootfs_data: Option<String>,
}

/// The remainder of `path` after the `prefix` it is under, or `None`.
///
/// The boundary rule is `bindpath::is_under`'s, including its answer for the
/// root: `/` contains everything, and the remainder is then the whole path.
fn suffix_under<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    if !bindpath::is_under(prefix, path) {
        return None;
    }
    Some(if prefix == "/" {
        // The root's own remainder is empty; anything under it keeps its
        // leading slash, so joining reconstitutes the path either way.
        if path == "/" { "" } else { path }
    } else {
        &path[prefix.len()..]
    })
}

/// A prefix and a remainder, without the `//` that concatenating a root prefix
/// with an absolute remainder would produce.
fn join(prefix: &str, rest: &str) -> String {
    if rest.is_empty() {
        return prefix.to_string();
    }
    if prefix.ends_with('/') {
        return format!("{prefix}{}", rest.trim_start_matches('/'));
    }
    format!("{prefix}{rest}")
}

impl Table {
    /// The mount a guest path belongs to: the longest prefix that contains it.
    pub fn find(&self, path: &str) -> Option<&Mount> {
        self.mounts
            .iter()
            .filter(|mount| bindpath::is_under(&mount.path, path))
            .max_by_key(|mount| mount.path.len())
    }

    /// Where a guest path goes on the host, or `None` if it is not under a
    /// mount. `path` must already be normalised.
    pub fn translate(&self, path: &str) -> Option<String> {
        let mount = self.find(path)?;
        let rest = suffix_under(&mount.path, path).expect("find matched");
        Some(join(&mount.host_path, rest))
    }

    /// Whether writing to this path must be refused. One lookup, then the flag.
    pub fn is_read_only(&self, path: &str) -> bool {
        self.find(path).is_some_and(|mount| mount.read_only)
    }

    pub fn is_under_any(&self, path: &str) -> bool {
        self.find(path).is_some()
    }

    /// A host path back to the guest path it is reachable at.
    ///
    /// Longest match here too: taking the first matching host prefix returned
    /// the outer mount's guest path for something belonging to a nested one.
    pub fn resolve(&self, host: &str) -> Option<String> {
        let mut best: Option<(&Mount, &str)> = None;
        for mount in &self.mounts {
            // A mount whose host path *contains* the fakefs data directory
            // would reverse-map every rootfs-internal descriptor to a guest
            // path under itself, which corrupts execve and metadata lookups.
            if self.contains_rootfs(&mount.host_path) {
                continue;
            }
            let Some(rest) = host_suffix(&mount.host_path, host) else {
                continue;
            };
            if best.is_none_or(|(current, _)| mount.host_path.len() > current.host_path.len()) {
                best = Some((mount, rest));
            }
        }
        let (mount, rest) = best?;
        Some(join(&mount.path, rest))
    }

    /// Is `host_path` the registered fakefs data directory, or an ancestor of
    /// it? False until the embedder registers one, so the suppression is a
    /// no-op for anything that does not opt in.
    fn contains_rootfs(&self, host_path: &str) -> bool {
        self.rootfs_data
            .as_deref()
            .is_some_and(|rootfs| bindpath::is_under(host_path, rootfs))
    }

    /// Add a mount, replacing any registration at the same guest path.
    ///
    /// `Ok(true)` when the host path is new or has changed, which is what
    /// decides whether the caller has symlink and `meta.db` work to do. Asking
    /// separately would be two operations with a gap between them.
    pub fn insert(
        &mut self,
        path: String,
        host_path: String,
        read_only: bool,
    ) -> Result<bool, c_int> {
        let changed = match self.mounts.iter_mut().find(|mount| mount.path == path) {
            Some(existing) => {
                let changed = existing.host_path != host_path;
                existing.host_path = host_path;
                existing.read_only = read_only;
                changed
            }
            None => {
                // Rust aborts on allocation failure and the C returned ENOMEM,
                // so the growth is asked for rather than assumed.
                self.mounts.try_reserve(1).map_err(|_| ENOMEM)?;
                self.mounts.push(Mount {
                    path,
                    host_path,
                    read_only,
                });
                true
            }
        };
        Ok(changed)
    }

    /// Remove the mount registered at exactly this guest path.
    pub fn remove(&mut self, path: &str) -> Option<Mount> {
        let index = self.mounts.iter().position(|mount| mount.path == path)?;
        Some(self.mounts.remove(index))
    }

    pub fn clear(&mut self) {
        self.mounts.clear();
    }

    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    pub fn set_rootfs_data(&mut self, path: Option<&str>) {
        self.rootfs_data = path.map(trim_host_path);
    }
}

/// The remainder of `host` after the `mount` prefix, at a component boundary.
///
/// `F_GETPATH` resolves `/var` to `/private/var` on iOS, so a mount registered
/// under `/var/` is also tried against the resolved path with that prefix
/// removed. Without it, every descriptor inside such a mount reported a host
/// path that matched nothing and reversed to no guest path at all.
fn host_suffix<'a>(mount: &str, host: &'a str) -> Option<&'a str> {
    if let Some(rest) = suffix_under(mount, host) {
        return Some(rest);
    }
    if mount.starts_with("/var/") && host.starts_with("/private/var/") {
        return suffix_under(mount, &host["/private".len()..]);
    }
    None
}

/// A host path as the table stores it: any trailing slash removed, so the
/// boundary comparisons have one form to deal with. The root keeps its slash,
/// because the empty string is not a path.
pub(crate) fn trim_host_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_of(mounts: &[(&str, &str, bool)]) -> Table {
        let mut table = Table::default();
        for (path, host, read_only) in mounts {
            table
                .insert(path.to_string(), trim_host_path(host), *read_only)
                .expect("room");
        }
        table
    }

    #[test]
    fn a_path_belongs_to_the_longest_mount_that_contains_it() {
        let table = table_of(&[
            ("/mnt", "/host/outer", false),
            ("/mnt/sub", "/host/inner", false),
        ]);
        assert_eq!(
            table.translate("/mnt/sub/file"),
            Some("/host/inner/file".into())
        );
        assert_eq!(
            table.translate("/mnt/other/file"),
            Some("/host/outer/other/file".into())
        );
        assert_eq!(table.translate("/mnt"), Some("/host/outer".into()));
        assert_eq!(table.translate("/elsewhere"), None);
    }

    /// The defect this crate was written for. `/mnt` read-only and `/mnt/rw`
    /// writable: asking for the longest *read-only* match found `/mnt` and
    /// refused every write under `/mnt/rw`. Asking whether the longest match
    /// is read-only cannot.
    #[test]
    fn a_writable_mount_nested_in_a_read_only_one_is_writable() {
        let table = table_of(&[("/mnt", "/host/ro", true), ("/mnt/rw", "/host/rw", false)]);
        assert!(table.is_read_only("/mnt/file"));
        assert!(
            !table.is_read_only("/mnt/rw/file"),
            "the nested mount is writable"
        );
        // And the other way round, which the old rule got right by accident.
        let table = table_of(&[("/mnt", "/host/rw", false), ("/mnt/ro", "/host/ro", true)]);
        assert!(!table.is_read_only("/mnt/file"));
        assert!(table.is_read_only("/mnt/ro/file"));
        // A path under no mount at all is not read-only.
        assert!(!table.is_read_only("/elsewhere"));
    }

    #[test]
    fn a_path_that_climbs_out_does_not_match_the_mount_it_started_in() {
        // "/mnt/../etc/passwd" is /etc/passwd, and rewriting it under the
        // mount's host directory would have escaped that directory.
        let normalized = bindpath::normalize("/mnt/../etc/passwd", MAX_PATH).unwrap();
        let table = table_of(&[("/mnt", "/host", false)]);
        assert_eq!(normalized, "/etc/passwd");
        assert_eq!(table.translate(&normalized), None);
    }

    #[test]
    fn a_mount_at_the_root_contains_everything() {
        let table = table_of(&[("/", "/host", true)]);
        assert!(table.is_read_only("/anything/at/all"));
        assert_eq!(table.translate("/etc"), Some("/host/etc".into()));
        assert_eq!(table.translate("/"), Some("/host".into()));
    }

    /// A host path of `/` keeps its slash — the empty string is not a path —
    /// and joining must not then produce `//etc`.
    #[test]
    fn a_host_root_does_not_produce_a_double_slash() {
        let table = table_of(&[("/mnt", "/", false)]);
        assert_eq!(table.translate("/mnt/etc"), Some("/etc".into()));
        assert_eq!(table.resolve("/etc"), Some("/mnt/etc".into()));
    }

    #[test]
    fn a_guest_root_does_not_produce_a_double_slash() {
        let table = table_of(&[("/", "/host", false)]);
        assert_eq!(table.resolve("/host/etc"), Some("/etc".into()));
    }

    #[test]
    fn a_host_path_reverses_to_the_longest_mount_that_holds_it() {
        let table = table_of(&[("/outer", "/host/a", false), ("/inner", "/host/a/b", false)]);
        assert_eq!(table.resolve("/host/a/b/file"), Some("/inner/file".into()));
        assert_eq!(
            table.resolve("/host/a/c/file"),
            Some("/outer/c/file".into())
        );
        assert_eq!(table.resolve("/host/z"), None);
        // At a component boundary: /host/ab is not under /host/a.
        assert_eq!(table.resolve("/host/ab"), None);
    }

    /// `F_GETPATH` answers `/private/var/…` for a mount registered at `/var/…`
    /// on iOS. Without this every descriptor inside such a mount reversed to
    /// nothing.
    #[test]
    fn a_var_mount_matches_the_private_var_the_host_reports() {
        let table = table_of(&[("/guest", "/var/mobile/x", false)]);
        assert_eq!(
            table.resolve("/private/var/mobile/x/file"),
            Some("/guest/file".into())
        );
        assert_eq!(
            table.resolve("/var/mobile/x/file"),
            Some("/guest/file".into())
        );
        // Still a component boundary after the prefix is stripped.
        assert_eq!(table.resolve("/private/var/mobile/xyz"), None);
    }

    /// A mount whose host directory *contains* the fakefs data directory would
    /// reverse-map every rootfs-internal descriptor to a guest path under
    /// itself, which corrupts execve and metadata lookups.
    #[test]
    fn a_mount_containing_the_rootfs_reverses_nothing() {
        let mut table = table_of(&[("/all", "/host", false)]);
        assert_eq!(
            table.resolve("/host/data/bin/sh"),
            Some("/all/data/bin/sh".into()),
            "no rootfs registered: the suppression is off"
        );
        table.set_rootfs_data(Some("/host/data"));
        assert_eq!(table.resolve("/host/data/bin/sh"), None);
        // The forward direction is unaffected — only reversing is ambiguous.
        assert_eq!(
            table.translate("/all/data/bin/sh"),
            Some("/host/data/bin/sh".into())
        );
        // A sibling prefix is not an ancestor: /host2 does not contain
        // /host/data even though the two strings share one.
        let mut table = table_of(&[("/all", "/host2", false)]);
        table.set_rootfs_data(Some("/host/data"));
        assert_eq!(table.resolve("/host2/file"), Some("/all/file".into()));
    }

    /// A trailing slash on the registered rootfs path must not defeat the
    /// boundary comparison. The C stripped it "defensively"; here it is the
    /// same normalisation the host paths get.
    #[test]
    fn a_trailing_slash_on_the_rootfs_path_still_suppresses() {
        let mut table = table_of(&[("/all", "/host", false)]);
        table.set_rootfs_data(Some("/host/data/"));
        assert_eq!(table.resolve("/host/data/bin/sh"), None);
    }

    #[test]
    fn registering_the_same_guest_path_twice_replaces_it() {
        let mut table = table_of(&[("/mnt", "/host/one", false)]);
        assert_eq!(
            table.insert("/mnt".into(), "/host/one".into(), false),
            Ok(false),
            "the same host path is not a change"
        );
        assert_eq!(
            table.insert("/mnt".into(), "/host/two".into(), true),
            Ok(true),
            "a different host path is"
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table.translate("/mnt/f"), Some("/host/two/f".into()));
        assert!(table.is_read_only("/mnt/f"));
    }

    #[test]
    fn unregistering_takes_only_the_exact_mount() {
        let mut table = table_of(&[("/mnt", "/host/a", false), ("/mnt/sub", "/host/b", false)]);
        assert!(table.remove("/mnt/nothing").is_none());
        let removed = table.remove("/mnt/sub").expect("the nested mount");
        assert_eq!(removed.host_path, "/host/b");
        assert_eq!(table.len(), 1);
        // And what was routed through it falls back to the outer mount.
        assert_eq!(
            table.translate("/mnt/sub/file"),
            Some("/host/a/sub/file".into())
        );
    }

    /// The C stored the host path as given and then concatenated, so a host
    /// path ending in a slash produced `//` in every translated path — and,
    /// worse, the reverse direction's prefix comparison never matched what
    /// `F_GETPATH` reports.
    #[test]
    fn a_trailing_slash_on_a_host_path_does_not_survive() {
        let table = table_of(&[("/mnt", "/host/a/", false)]);
        assert_eq!(table.translate("/mnt/f"), Some("/host/a/f".into()));
        assert_eq!(table.resolve("/host/a/f"), Some("/mnt/f".into()));
    }

    #[test]
    fn clearing_leaves_nothing_to_match() {
        let mut table = table_of(&[("/mnt", "/host", true)]);
        table.clear();
        assert!(table.is_empty());
        assert!(!table.is_read_only("/mnt/f"));
        assert_eq!(table.translate("/mnt/f"), None);
        assert_eq!(table.resolve("/host/f"), None);
    }
}
