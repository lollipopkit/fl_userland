//! Turning the host path of an open descriptor back into a guest path.
//!
//! `getpath` answers "where is this descriptor, in the guest's terms". The
//! host can only say where it is in the host's terms, so the mount's source
//! directory has to come off the front. In C this was a sequence of `memmove`,
//! `strcpy` and `strlcpy` into the caller's `MAX_PATH` buffer with the
//! arithmetic done by hand; here it is a function on slices, so the only place
//! a length can be got wrong is the single copy in `lib.rs` that fills the
//! caller's buffer.

/// A prefix only matches at a component boundary.
///
/// `/var/app` does not contain `/var/application`, and a plain `strncmp` said
/// it did — the descriptor's path was then reported as the middle of a word.
fn has_prefix(path: &[u8], prefix: &[u8]) -> bool {
    if !path.starts_with(prefix) {
        return false;
    }
    // A prefix ending in a slash carries its own boundary.
    if prefix.last() == Some(&b'/') {
        return true;
    }
    matches!(path.get(prefix.len()), None | Some(b'/'))
}

/// What is left of `path` after `prefix`, as an absolute guest path.
fn strip(path: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
    if !has_prefix(path, prefix) {
        return None;
    }
    let rest = &path[prefix.len()..];
    Some(if rest.is_empty() || rest == b"/" {
        // The descriptor is the mount root itself.
        b"/".to_vec()
    } else if rest[0] == b'/' {
        rest.to_vec()
    } else {
        // Only reachable when the prefix ended in a slash, which ate the
        // separator along with it.
        let mut out = vec![b'/'];
        out.extend_from_slice(rest);
        out
    })
}

/// The guest path for a descriptor the host reports at `host_path`, on a mount
/// whose source directory is `source`.
///
/// Falls back to `/` when the host path is not under the mount at all. That
/// happens for real: `F_GETPATH` resolves symlinks, so a descriptor opened
/// through a bind mount reports a path outside the mount source once the bind
/// mount table has been cleared — after an app restart, before the embedder
/// has re-registered its mounts. There is no correct answer at that point, and
/// the root is the one that cannot be mistaken for a real location.
pub fn guest_path(host_path: &[u8], source: &[u8]) -> Vec<u8> {
    // A mount rooted at the host's own root needs no translation: the guest
    // path and the host path are the same string.
    if source == b"/" {
        return host_path.to_vec();
    }
    if let Some(rest) = strip(host_path, source) {
        return rest;
    }
    // Darwin resolves `/var` to `/private/var`, so a mount whose source was
    // recorded as `/var/...` is reported by `F_GETPATH` one component deeper
    // than it was mounted.
    if source.starts_with(b"/var/")
        && let Some(under_private) = host_path.strip_prefix(b"/private")
        && let Some(rest) = strip(under_private, source)
    {
        return rest;
    }
    b"/".to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(host: &str, source: &str) -> String {
        String::from_utf8(guest_path(host.as_bytes(), source.as_bytes())).unwrap()
    }

    #[test]
    fn a_root_mount_needs_no_translation() {
        assert_eq!(p("/tmp/x", "/"), "/tmp/x");
        assert_eq!(p("/", "/"), "/");
    }

    #[test]
    fn the_source_comes_off_the_front() {
        assert_eq!(p("/Users/me/rootfs/tmp/x", "/Users/me/rootfs"), "/tmp/x");
    }

    #[test]
    fn the_mount_root_itself_is_slash_not_the_empty_string() {
        // The C produced "" here and the caller repaired it. Answering the
        // question correctly is cheaper than repairing the answer.
        assert_eq!(p("/Users/me/rootfs", "/Users/me/rootfs"), "/");
        assert_eq!(p("/Users/me/rootfs/", "/Users/me/rootfs"), "/");
    }

    #[test]
    fn a_prefix_must_end_on_a_component_boundary() {
        // The bug this exists for: /var/app is not a prefix of
        // /var/application, and strncmp said it was.
        assert_eq!(p("/var/application/f", "/var/app"), "/");
    }

    #[test]
    fn a_source_with_a_trailing_slash_still_yields_an_absolute_path() {
        assert_eq!(p("/mnt/root/tmp", "/mnt/root/"), "/tmp");
        assert_eq!(p("/mnt/root/", "/mnt/root/"), "/");
    }

    #[test]
    fn darwin_private_var_is_folded_back() {
        assert_eq!(p("/private/var/m/root/tmp/x", "/var/m/root"), "/tmp/x");
        assert_eq!(p("/private/var/m/root", "/var/m/root"), "/");
    }

    #[test]
    fn private_is_only_tried_for_a_var_source() {
        // Otherwise a mount at /privateer would swallow the wrong prefix.
        assert_eq!(p("/private/opt/x/f", "/opt/x"), "/");
    }

    #[test]
    fn a_path_outside_the_mount_falls_back_to_the_root() {
        assert_eq!(p("/elsewhere/f", "/Users/me/rootfs"), "/");
        assert_eq!(p("/", "/Users/me/rootfs"), "/");
    }

    #[test]
    fn paths_are_bytes_not_text() {
        // Host filenames have no declared encoding; a name that is not UTF-8
        // must come back exactly as it went in.
        let host = b"/mnt/r/\xff\xfe/f";
        assert_eq!(guest_path(host, b"/mnt/r"), b"/\xff\xfe/f".to_vec());
    }
}
