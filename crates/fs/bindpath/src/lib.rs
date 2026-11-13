//! Lexical path normalisation and prefix matching for bind mounts.
//!
//! `fakefs_bind_mount` grafts a host directory into the guest tree, and a bind
//! mount may be read-only. Deciding whether a guest path lies under one is
//! therefore a permission decision, and it is made by two pure string
//! operations: normalise the path lexically, then see whether a mount's path is
//! a **prefix at a component boundary**.
//!
//! Lexical, not resolving: this runs before the filesystem is touched, so it
//! cannot follow symlinks the way `crates/fs/path` does. The two are different
//! operations rather than two copies of one.
//!
//! Both were `static` functions in `fs/fake.c` with no test of their own. The
//! properties below are the point of moving them: a normaliser that can be
//! walked above the root, or a prefix rule that matches `/foo` against
//! `/foobar`, is a read-only mount that does not hold.
//!
//! [`relative`] is the third, and it came from the same file for the same
//! reason. A bind mount is a symlink inside the fakefs `data/` directory
//! pointing at the host directory it grafts in, and it is written *relative*
//! so that moving the whole fakefs does not break it. Getting the number of
//! `..` wrong points the symlink somewhere else, which is silent — the mount
//! appears to work and reads a different tree.
//!
//! **No C ABI.** `bindpath_normalize` and `bindpath_relative` were exported for
//! `fs/fake.c` and the last call to either became Rust when `crates/fs/bindstash`
//! and `crates/fs/fake` did. `tools/dead-exports.py` could not see that, because
//! the two `extern` declarations were still sitting in `fs/fake.c` and a
//! declaration is a name in C — the same way a name in a *comment* kept nine
//! exports alive until that rule changed on 2026-09-03. Deleting the
//! declarations is what made the tool fail on these two.

/// Normalise `path` lexically: absolute, no empty or `.` components, `..`
/// resolved against what is already there, and never above the root.
///
/// Returns `None` only when the result would not fit in `out_len` bytes
/// including the NUL. Truncation is reported rather than absorbed: a path cut
/// short can match a mount prefix that the whole path does not, and the caller
/// would then translate it as if it belonged there.
pub fn normalize(path: &str, out_len: usize) -> Option<String> {
    let mut out = String::from("/");
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            // Drop the last component. At the root there is nothing to drop,
            // and `..` there stays at the root rather than walking out of it.
            if let Some(cut) = out.rfind('/') {
                out.truncate(if cut == 0 { 1 } else { cut });
            }
            continue;
        }
        if out.len() > 1 {
            out.push('/');
        }
        out.push_str(seg);
        if out.len() + 1 > out_len {
            return None;
        }
    }
    if out.len() + 1 > out_len {
        return None;
    }
    Some(out)
}

/// Is `path` the mount at `mount`, or under it?
///
/// Both are expected to be normalised. The match is at a component boundary,
/// so `/foo` does not contain `/foobar`.
///
/// The root is the case that needs saying: `/` contains everything. The C this
/// replaces required the byte after the prefix to be `/` or NUL, which for a
/// mount path of `/` means the byte after the leading slash — so a mount
/// registered at the root matched nothing but the root itself, and a read-only
/// one protected nothing.
pub fn is_under(mount: &str, path: &str) -> bool {
    if mount == "/" {
        return path.starts_with('/');
    }
    if !path.starts_with(mount) {
        return false;
    }
    matches!(path.as_bytes().get(mount.len()), None | Some(b'/'))
}

/// A relative path from the directory `from` to the file `to`, both absolute
/// and both already normalised.
///
/// `None` if the result would not fit in `out_len` bytes including the NUL.
/// The C truncated instead and returned success, and a truncated symlink
/// target names a different file.
///
/// # The `..` count
///
/// It is the number of components of `from` past the common prefix, and the C
/// computed it as *the number of slashes after the prefix, plus one if `from`
/// does not end in a slash*. Those agree only when the prefix ends exactly at
/// a component boundary in the middle of `from`; they differ at both edges:
///
/// - `from = "/a"`, `to = "/a/b"`: the prefix is all of `from`, so no `..` is
///   needed and the answer is `b`. The C said `../b`, which from `/a` is `/b`.
/// - `from = "/a/b"`, `to = "/a"`: one `..`. The C said `../..`, which is `/`.
///
/// It only bites when the two paths share a deep prefix — which is exactly the
/// case of a bind mount whose host directory is near the fakefs itself, and
/// which a desktop user does by mounting a directory the rootfs lives under.
pub fn relative(from: &str, to: &str, out_len: usize) -> Option<String> {
    let from_parts: Vec<&str> = from.split('/').filter(|s| !s.is_empty()).collect();
    let to_parts: Vec<&str> = to.split('/').filter(|s| !s.is_empty()).collect();
    let common = from_parts
        .iter()
        .zip(&to_parts)
        .take_while(|(a, b)| a == b)
        .count();

    let mut out = String::new();
    for _ in 0..from_parts.len() - common {
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str("..");
    }
    for part in &to_parts[common..] {
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(part);
    }
    // The two name the same place. A symlink to "." is what the C produced
    // here too, and it is the only answer that is not a path.
    if out.is_empty() {
        out.push('.');
    }
    (out.len() < out_len).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIG: usize = 4096;

    fn norm(p: &str) -> String {
        normalize(p, BIG).expect("fits")
    }

    #[test]
    fn the_ordinary_shapes() {
        assert_eq!(norm("/a/b"), "/a/b");
        assert_eq!(norm("a/b"), "/a/b");
        assert_eq!(norm("//a///b//"), "/a/b");
        assert_eq!(norm("/a/./b"), "/a/b");
        assert_eq!(norm("/a/b/.."), "/a");
        assert_eq!(norm("/a/b/../c"), "/a/c");
        assert_eq!(norm(""), "/");
        assert_eq!(norm("/"), "/");
        assert_eq!(norm("."), "/");
    }

    /// The property that matters most: no input walks out of the root.
    #[test]
    fn dotdot_never_escapes_the_root() {
        for p in [
            "..",
            "/..",
            "/../..",
            "../../..",
            "/a/../..",
            "/a/../../b",
            "/././../.",
            "//../..//",
            "/a/b/../../../../c",
        ] {
            let out = norm(p);
            assert!(out.starts_with('/'), "{p:?} -> {out:?}");
            assert!(!out.starts_with("/.."), "{p:?} -> {out:?} climbed out");
            assert!(!out.contains("/../"), "{p:?} -> {out:?} kept a ..");
        }
        assert_eq!(norm("/a/b/../../../../c"), "/c");
    }

    /// Normalising an already-normal path changes nothing, so a caller that
    /// normalises twice cannot get a different answer the second time.
    #[test]
    fn normalising_is_idempotent() {
        for p in [
            "/",
            "/a",
            "/a/b/c",
            "..",
            "/a/../b",
            "//x//y//",
            "/a/./b/..",
        ] {
            let once = norm(p);
            let twice = norm(&once);
            assert_eq!(once, twice, "{p:?}");
        }
    }

    #[test]
    fn a_prefix_only_matches_at_a_component_boundary() {
        assert!(is_under("/foo", "/foo"));
        assert!(is_under("/foo", "/foo/bar"));
        assert!(!is_under("/foo", "/foobar"));
        assert!(!is_under("/foo", "/foo.txt"));
        assert!(!is_under("/foo/bar", "/foo"));
        assert!(!is_under("/foo", "/bar/foo"));
    }

    /// The root contains everything. The C required the byte after the prefix
    /// to be `/` or NUL, which for a mount path of `/` is the byte after the
    /// leading slash -- so a mount at the root matched only the root, and a
    /// read-only one protected nothing under it.
    #[test]
    fn the_root_contains_everything() {
        assert!(is_under("/", "/"));
        assert!(is_under("/", "/a"));
        assert!(is_under("/", "/a/b/c"));
    }

    /// Truncation is refused, not absorbed. A path cut short can match a mount
    /// prefix the whole path does not.
    #[test]
    fn a_result_that_does_not_fit_is_refused() {
        assert_eq!(normalize("/aaaa/bbbb", 8), None);
        assert!(normalize("/aaaa/bbbb", 11).is_some());
        // Exactly the boundary: 10 characters plus the NUL.
        assert_eq!(normalize("/aaaa/bbbb", 10), None);
    }

    fn rel(from: &str, to: &str) -> String {
        relative(from, to, BIG).expect("fits")
    }

    #[test]
    fn a_relative_target_climbs_out_and_back_in() {
        assert_eq!(rel("/x/y", "/x/z"), "../z");
        assert_eq!(rel("/a/b/c", "/a/q"), "../../q");
        assert_eq!(
            rel("/tmp/fs/data/var", "/Users/x/y"),
            "../../../../Users/x/y"
        );
        assert_eq!(rel("/", "/a/b"), "a/b");
        assert_eq!(rel("/a", "/a"), ".");
        assert_eq!(rel("/", "/"), ".");
    }

    /// The two edges the C got wrong, and the only ones it got wrong: they
    /// need the common prefix to end at one end of `from` rather than in the
    /// middle of it.
    #[test]
    fn a_target_inside_the_link_directory_needs_no_dotdot() {
        // The C said "../b", which from /a is /b.
        assert_eq!(rel("/a", "/a/b"), "b");
        assert_eq!(rel("/a/b", "/a/b/c/d"), "c/d");
    }

    #[test]
    fn a_target_that_is_an_ancestor_needs_exactly_as_many_as_it_climbs() {
        // The C said "../..", which from /a/b is /.
        assert_eq!(rel("/a/b", "/a"), "..");
        assert_eq!(rel("/a/b/c", "/a"), "../..");
        assert_eq!(rel("/a/b/c", "/"), "../../..");
    }

    /// Whatever the pair, resolving the answer from `from` has to land on
    /// `to`. Sweeping rather than sampling, because the two defects above
    /// were both at an edge a hand-written case would have to think to reach.
    #[test]
    fn resolving_the_answer_lands_on_the_target() {
        let paths = ["/", "/a", "/a/b", "/a/b/c", "/a/x", "/q", "/q/b", "/a/bb"];
        for from in paths {
            for to in paths {
                let r = rel(from, to);
                // Resolve `r` against `from` the way the kernel would.
                let joined = if from == "/" {
                    format!("/{r}")
                } else {
                    format!("{from}/{r}")
                };
                let landed = normalize(&joined, BIG).unwrap();
                assert_eq!(landed, to, "from {from:?} to {to:?} gave {r:?}");
            }
        }
    }

    /// Truncation is refused rather than absorbed, here for the same reason as
    /// in `normalize`: a symlink target cut short names a different file, and
    /// the C returned success either way.
    #[test]
    fn a_relative_target_that_does_not_fit_is_refused() {
        assert_eq!(relative("/a/b/c", "/a/q", 7), None);
        assert!(relative("/a/b/c", "/a/q", 8).is_some());
    }

    /// Whatever the input, a normalised path is one `is_under("/")` accepts and
    /// is a valid prefix subject. Sweeping rather than sampling.
    #[test]
    fn every_normalised_path_is_well_formed() {
        let parts = ["", ".", "..", "a", "bb", "/"];
        for a in parts {
            for b in parts {
                for c in parts {
                    let input = format!("{a}/{b}/{c}");
                    let out = norm(&input);
                    assert!(out.starts_with('/'), "{input:?} -> {out:?}");
                    assert!(!out.ends_with('/') || out == "/", "{input:?} -> {out:?}");
                    assert!(!out.contains("//"), "{input:?} -> {out:?}");
                    assert!(!out.contains("/./"), "{input:?} -> {out:?}");
                    assert!(is_under("/", &out), "{input:?} -> {out:?}");
                }
            }
        }
    }
}
