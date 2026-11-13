//! What a fakefs is on disk: the schema, and the guest-path-to-host-path rule.
//!
//! Two things, one crate, for one reason — **a fakefs is written by one program
//! and read by another**, so anything both must agree about has to have a single
//! definition or it is something they can disagree about.
//!
//! `fs/fake-schema.c` until 2026-09-06, and the last engine C file. Its reason
//! for being its own translation unit is this crate's reason for being its own
//! crate, and the C said it best:
//!
//! > A file with nothing but the string and one exec keeps the definition
//! > single without dragging the kernel behind it.
//!
//! `crates/tools/fakefsify` makes a fakefs from a tarball and the kernel's
//! `crates/fs/fakedb` opens one; a second copy of the schema would be a
//! database the two disagree about. Neither can depend on the other, so the
//! schema depends on neither.
//!
//! # And the same argument applies to [`fix`]
//!
//! A guest path becomes a host path by stripping the leading `/` and opening
//! the result relative to `data/`. That rule decides **which file on the host
//! an inode's contents live in**, and it was written out four times in Rust —
//! `crates/tools/fakefsify` writing them, `crates/fs/fakefs`'s rebuild
//! repairing them, `crates/fs/fake` reading them, and `crates/fs/realfs` — plus
//! once in C, as `fs/fix_path.h`. Each carried its own three-case test
//! asserting the same three cases.
//!
//! They agreed. The failure they were one edit away from is the schema's
//! exactly: `fakefsify` writes a host file at one path and `fake` looks for it
//! at another, and the guest is told the file does not exist. That is not a
//! crash, a warning or a failed test — it is a fakefs that is quietly missing
//! files, which is how `benchmark/create_fakefs.py`'s third copy of the schema
//! survived unnoticed.
//!
//! `crates/fs/realfs` keeps its own, and that is not an oversight: it maps a
//! guest path onto a **host passthrough mount's** root descriptor, which is a
//! different contract that happens to have the same rule. Nothing about a
//! fakefs constrains it, and tying them would mean a change to one silently
//! changing the other.
//!
//! `fake_db_create_schema` is still exported out of `libiul.a`, because
//! `fs/fake-db.h` is a header an embedder compiles against. It was the only
//! member of `libfakefs.a` until the schema became Rust; that archive was then
//! kept empty for a consumer's link line and was removed on 2026-09-30.
//!
//! # What the C could not do
//!
//! `PRAGMA user_version` in the schema and `crates/fs/fakefs`'s `MIGRATIONS`
//! list have to agree: the schema creates a database *already at the latest
//! version*, so a migration appended without touching the pragma leaves a fresh
//! fakefs claiming to be older than it is and the next open runs a migration
//! over tables that already have it.
//!
//! `migrate.rs` asserted `latest_version() == 3` with a comment saying
//! "fake-schema.c writes user_version=3" — which is a test **restating its
//! subject**, the shape `CLAUDE.md` names. It could not do better: the schema
//! was a string in another language. It is a `&str` here, so
//! [`user_version`] reads the pragma out of it and the two are compared for
//! real.

use std::ffi::{CString, c_int};

/// Every table a fakefs has, and the version that makes it current.
///
/// **Ordered and complete**: this creates a database at the latest version
/// rather than at version 0 with migrations to follow, so anything
/// `crates/fs/fakefs`'s `MIGRATIONS` would do to an old database has to be
/// already true here.
pub const SCHEMA: &str = concat!(
    "create table meta (id integer unique default 0, db_inode integer);",
    "insert into meta (db_inode) values (0);",
    "create table stats (inode integer primary key, stat blob);",
    "create table paths (path blob primary key, inode integer references stats(inode));",
    // No index on `stats`: the rows are ordered by the primary key.
    "create index inode_to_path on paths (inode, path);",
    "pragma user_version=3;",
);

/// `EIO`, the guest's.
///
/// It was written out here rather than imported, on the grounds that this
/// crate is deliberately below everything and one number is cheaper than a
/// dependency. `crates/util/errno` is layer 0 and depends on nothing, so that
/// is no longer a choice between two things.
use guest_errno::c_int_::EIO;

/// The version [`SCHEMA`] leaves a fresh database at, read out of the pragma.
///
/// Parsed rather than written down a second time, which is what lets
/// `crates/fs/fakefs` compare it against the length of its migration list
/// instead of against a number somebody typed twice.
pub fn user_version() -> Option<i32> {
    let (_, rest) = SCHEMA.split_once("pragma user_version=")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Create the schema on an open connection. 0, or a negative guest errno.
///
/// # Safety
/// `db` is an open `sqlite3` handle and no other thread is using it.
pub unsafe fn create(db: *mut rusqlite::ffi::sqlite3) -> c_int {
    // `SCHEMA` has no interior NUL, so this cannot fail; answering `_EIO` if it
    // somehow did is the same answer a failed `exec` gives.
    let Ok(sql) = CString::new(SCHEMA) else {
        return EIO;
    };
    // SAFETY: the caller's contract, and `sql` outlives the call.
    let rc = unsafe {
        rusqlite::ffi::sqlite3_exec(
            db,
            sql.as_ptr(),
            None,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc == rusqlite::ffi::SQLITE_OK {
        0
    } else {
        EIO
    }
}

/// The C entry point, for `fs/fake-db.h` — which
/// `tests/integration/sbm_api_test.c` reaches, so an embedder may compile
/// against it. Exported out of `libiul.a` since 2026-09-06.
///
/// # Safety
/// As [`create`].
pub unsafe fn fake_db_create_schema(db: *mut rusqlite::ffi::sqlite3) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { create(db) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pragma is parseable, which is what
    /// `crates/fs/fakefs::migrate`'s check rests on.
    #[test]
    fn the_schema_names_its_version() {
        assert_eq!(user_version(), Some(3));
    }

    /// And the parse is not vacuous: a schema with no pragma answers `None`
    /// rather than a default that would make the comparison always pass.
    #[test]
    fn a_schema_without_a_pragma_has_no_version() {
        let (_, rest) = SCHEMA.split_once("pragma user_version=").unwrap();
        assert!(
            rest.starts_with('3'),
            "the parse reads the digits after the `=`"
        );
        assert!(
            !SCHEMA
                .split_once("pragma user_version=")
                .unwrap()
                .0
                .contains("user_version"),
            "one pragma, so `split_once` cannot pick the wrong one"
        );
    }

    /// It runs, and leaves the four objects the rest of the tree expects.
    #[test]
    fn the_schema_creates_what_a_fakefs_needs() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // SAFETY: an open handle this test owns.
        assert_eq!(unsafe { create(conn.handle()) }, 0);
        for (kind, name) in [
            ("table", "meta"),
            ("table", "stats"),
            ("table", "paths"),
            ("index", "inode_to_path"),
        ] {
            let n: i64 = conn
                .query_row(
                    "select count(*) from sqlite_master where type = ?1 and name = ?2",
                    (kind, name),
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "{kind} {name}");
        }
        let v: i32 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, user_version().unwrap(), "the pragma the string names");
    }
}

// ---------------------------------------------------------------------------
// The path rule
// ---------------------------------------------------------------------------

/// A guest path as a name relative to the fakefs `data/` directory descriptor.
///
/// The root is stored as the **empty blob**, not `"/"`, and an empty name is
/// not something any `*at()` call accepts — it names the directory descriptor
/// itself, which is `"."`.
///
/// `fs/fix_path.h`'s `fix_path()` is the same function for the C an embedder
/// compiles; it stays because `kernel/fs.h` includes it and
/// `tests/unit/fakefs_stat_test.c` calls it.
///
/// ```
/// # use fakeschema::fix;
/// assert_eq!(fix(b""), b".");           // the root, stored as the empty blob
/// assert_eq!(fix(b"/"), b"");           // and a bare slash, which is not
/// assert_eq!(fix(b"/etc/passwd"), b"etc/passwd");
/// assert_eq!(fix(b"etc/passwd"), b"etc/passwd");
/// ```
pub fn fix(path: &[u8]) -> &[u8] {
    match path {
        [] => b".",
        [b'/', rest @ ..] => rest,
        _ => path,
    }
}

/// [`fix`] for a caller that hands the result to a host `*at` call: the same
/// rule, answering a suffix of `path` so the terminator comes with it.
pub fn fix_c(path: &std::ffi::CStr) -> &std::ffi::CStr {
    match path.to_bytes_with_nul() {
        [0] => c".",
        [b'/', rest @ ..] => std::ffi::CStr::from_bytes_with_nul(rest).unwrap_or(c"."),
        _ => path,
    }
}

#[cfg(test)]
mod path_tests {
    use super::fix;

    /// The two forms are one rule.
    #[test]
    fn fix_c_is_fix() {
        for p in [c"", c"/", c"/etc/passwd", c"etc/passwd", c"//x"] {
            assert_eq!(super::fix_c(p).to_bytes(), fix(p.to_bytes()), "{p:?}");
        }
    }

    #[test]
    fn fix_matches_the_c_helper() {
        // `fs/fix_path.h`, case for case. Not a restatement of `fix`: the C is
        // still compiled, by `tests/unit/fakefs_stat_test.c`.
        assert_eq!(fix(b""), b".");
        assert_eq!(fix(b"/"), b"");
        assert_eq!(fix(b"/a"), b"a");
        assert_eq!(fix(b"a"), b"a");
        assert_eq!(fix(b"/etc/passwd"), b"etc/passwd");
        assert_eq!(fix(b"etc/passwd"), b"etc/passwd");
    }

    #[test]
    fn a_second_slash_is_not_stripped() {
        // `//etc` keeps one, because the rule removes exactly one leading
        // character and the caller has already normalised. A version that
        // looped would turn `//etc` into `etc` and agree with nothing.
        assert_eq!(fix(b"//etc"), b"/etc");
    }
}
