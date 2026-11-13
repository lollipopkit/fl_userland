//! Guest path normalization.
//!
//! Paths here are bytes, not `str`. A tar pathname is a C string with no
//! declared encoding, `meta.db` stores `paths.path` as a blob, and a rootfs
//! legitimately contains names that are not UTF-8. Going through `String`
//! would reject or mangle them, so nothing in this module decodes.
//!
//! Every path in this file arrives from a tarball, which is to say from
//! somewhere untrusted. The C version normalized into a caller-supplied
//! `char[MAX_PATH]` and never checked how much it wrote, so an archive entry
//! with a pathname longer than 4096 bytes overflowed the caller's stack
//! buffer — and tar's pax extended headers put no limit on pathname length.
//! Normalizing into an owned `Vec` is what removes that; the length limit
//! below is kept anyway, because a fakefs is extracted onto a real filesystem
//! with its own limit and rejecting early gives a better message than a later
//! ENAMETOOLONG.

/// Longest normalized path accepted, matching the `MAX_PATH` the C version
/// sized its buffer with.
pub const MAX_PATH: usize = 4096;

/// Normalize `path` into the form fakefs stores: `( '/' component )*`.
///
/// The root is the empty string, not `"/"` — that is the representation
/// `meta.db` uses for it.
///
/// Returns `None` if the path escapes the root via `..`, or if the result
/// would exceed [`MAX_PATH`]. Both mean "skip this archive entry".
pub fn normalize(path: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(path.len() + 1);

    for component in path.split(|&b| b == b'/') {
        match component {
            // Repeated, leading and trailing slashes all produce empty
            // components; a lone "." keeps the position it is in.
            b"" | b"." => continue,
            // No dotdot allowed. This is an exact match on the whole
            // component, so a name like "..foo" stays a normal name, as it
            // did in C.
            b".." => return None,
            _ => {}
        }
        out.push(b'/');
        out.extend_from_slice(component);
        if out.len() > MAX_PATH {
            return None;
        }
    }

    Some(out)
}

/// Strip the leading `/` so a normalized path can be used with the `*at()`
/// syscalls against the fakefs `data/` directory fd.
///
/// `crates/fs/fakeschema` owns it. This crate *writes* a fakefs and
/// `crates/fs/fake` reads one, so the rule that decides which host file an
/// inode's contents live in has to have one definition for the same reason the
/// schema does -- it was written out four times until 2026-09-06.
pub use fakeschema::fix;

/// Render a path for a diagnostic. Lossy on purpose: this is for humans, and
/// never for anything that touches the filesystem or the database.
pub fn display(path: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_the_empty_string() {
        // meta.db stores the root as the empty blob, so every spelling of the
        // root has to reach it.
        for input in [&b""[..], b"/", b"///", b".", b"./", b"/./"] {
            assert_eq!(normalize(input).as_deref(), Some(&b""[..]), "{input:?}");
        }
    }

    #[test]
    fn every_path_gets_exactly_one_leading_slash() {
        for input in [&b"bin"[..], b"/bin", b"//bin", b"./bin"] {
            assert_eq!(normalize(input).as_deref(), Some(&b"/bin"[..]), "{input:?}");
        }
    }

    #[test]
    fn interior_and_trailing_separators_collapse() {
        assert_eq!(normalize(b"a//b").as_deref(), Some(&b"/a/b"[..]));
        assert_eq!(normalize(b"a/./b").as_deref(), Some(&b"/a/b"[..]));
        assert_eq!(normalize(b"/a/b/").as_deref(), Some(&b"/a/b"[..]));
        assert_eq!(normalize(b"a/b///c//").as_deref(), Some(&b"/a/b/c"[..]));
    }

    #[test]
    fn dotdot_is_refused_anywhere() {
        // This is the path traversal guard: a tarball saying "../etc/passwd"
        // must not write outside the fakefs data directory.
        for input in [
            &b".."[..],
            b"../etc/passwd",
            b"/../etc/passwd",
            b"a/../b",
            b"a/..",
            b"a/b/../../..",
        ] {
            assert_eq!(normalize(input), None, "{input:?}");
        }
    }

    #[test]
    fn dotdot_is_matched_as_a_whole_component() {
        // "..foo" and "..." are ordinary names. The C version tested for a
        // component boundary after the two dots; keep that.
        assert_eq!(normalize(b"..foo").as_deref(), Some(&b"/..foo"[..]));
        assert_eq!(normalize(b"...").as_deref(), Some(&b"/..."[..]));
        assert_eq!(normalize(b"a/..b/c").as_deref(), Some(&b"/a/..b/c"[..]));
    }

    #[test]
    fn non_utf8_names_survive_unchanged() {
        // A rootfs may carry names in any encoding. Going through String
        // would have replaced these bytes with U+FFFD and written a different
        // filename than the archive asked for.
        let latin1 = b"/usr/share/\xe9t\xe9";
        assert_eq!(normalize(latin1).as_deref(), Some(&latin1[..]));

        let lone_surrogate_ish = b"bad\xed\xa0\x80name";
        assert_eq!(
            normalize(lone_surrogate_ish).as_deref(),
            Some(&b"/bad\xed\xa0\x80name"[..])
        );
    }

    #[test]
    fn overlong_paths_are_refused_rather_than_overflowing() {
        // The C version wrote this into a 4096-byte stack buffer with no
        // bounds check, and pax extended headers impose no length limit.
        let long = b"a/".repeat(MAX_PATH);
        assert_eq!(normalize(&long), None);

        // Just under and just over the limit, to pin the boundary.
        let ok = b"b".repeat(MAX_PATH - 1);
        assert_eq!(normalize(&ok).map(|p| p.len()), Some(MAX_PATH));
        let too_long = b"b".repeat(MAX_PATH);
        assert_eq!(normalize(&too_long), None);
    }

    #[test]
    fn fix_makes_paths_usable_with_at_syscalls() {
        assert_eq!(fix(b""), b".");
        assert_eq!(fix(b"/bin"), b"bin");
        assert_eq!(fix(b"/a/b"), b"a/b");
    }

    #[test]
    fn normalize_then_fix_never_yields_an_absolute_path() {
        // openat() with an absolute path ignores the dirfd, which would put
        // the extracted file outside the fakefs entirely.
        for input in [&b"/"[..], b"//etc//passwd", b"a/b", b"./x", b""] {
            let normalized = normalize(input).expect("should normalize");
            assert_ne!(fix(&normalized).first(), Some(&b'/'), "{input:?}");
        }
    }
}
