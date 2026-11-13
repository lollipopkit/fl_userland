//! What `meta.db` stores, and the two tricks it stores it with.
//!
//! A fakefs keeps file contents as real host files and everything a host
//! cannot represent — ownership, modes, device nodes — in a SQLite database of
//! `paths` (path blob → inode) and `stats` (inode → a packed blob). This crate
//! owns the packed blob and the range arithmetic the subtree operations use.
//! The connection, the prepared statements and the transactions are [`db`],
//! which replaced `fs/fake-db.c`.
//!
//! It is the same split as `crates/fs/dirent` and `crates/fs/cmsg`, for the
//! same reason: what is here is a *format*, and a format is where the bugs
//! were.
//!
//! # The blob was cast, not decoded
//!
//! ```c
//! *stat = *(struct iul_stat *) sqlite3_column_blob(stmt, 1);
//! ```
//!
//! No length, and `meta.db` is **a file on disk that something else wrote**.
//! `crates/fs/fakefs`'s `rebuild.rs` exists precisely because a fakefs gets
//! copied, restored and moved between machines. A row whose `stat` column is
//! NULL makes that a null dereference; one that is short reads past the end of
//! SQLite's buffer and puts whatever follows into a guest's `st_mode`.
//!
//! [`IulStat::decode`] takes a slice and checks its length, which makes both
//! inexpressible.
//!
//! # `/` is 0x2f and `0` is 0x30
//!
//! Deleting or renaming a whole subtree is one statement because of that: the
//! children of `p` are exactly the paths in the half-open blob range
//! `[p + "/", p + "0")`, which an index can answer as a range scan. The
//! arithmetic is small and load-bearing — a rename that gets it wrong moves
//! somebody else's files — and it was written out twice, in two functions, in
//! C. [`subtree_range`] is the one copy.

// The connection, the statements and the transactions. `fs/fake-db.c` was
// where the SQLite handle's lifetime was; it is here now, and what is left in
// C is the VFS operations that use it.
/// The database itself. Public because `crates/fs/fake` opens and closes it
/// -- the mount owns the connection and the C ABI is only how *C* reaches it.
pub mod db;
pub use db::{Db, InodeT, Tx};

/// What `stats.stat` holds: the four things a host filesystem cannot be asked
/// to remember for a guest.
///
/// **This is an on-disk format.** `crates/tools/fakefsify` writes it,
/// `fs/fake-schema.c` creates the table, and a database written by one build
/// is read by another — so the encoding is fixed here and asserted, rather
/// than being whatever a C compiler laid `struct iul_stat` out as.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct IulStat {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
}

/// Sixteen bytes, four little-endian `u32`s, in this order. Every fakefs on
/// disk has this and nothing may change it.
pub const IUL_STAT_SIZE: usize = 16;

impl IulStat {
    /// A blob out of the database, or `None` if it is not one.
    ///
    /// Short *and* long are refused. A longer blob is a database written by
    /// something that knows a field this build does not, and guessing which
    /// four of its fields are the ones meant here is worse than declining.
    pub fn decode(blob: &[u8]) -> Option<IulStat> {
        if blob.len() != IUL_STAT_SIZE {
            return None;
        }
        let at = |i: usize| u32::from_le_bytes(blob[i..i + 4].try_into().unwrap());
        Some(IulStat {
            mode: at(0),
            uid: at(4),
            gid: at(8),
            rdev: at(12),
        })
    }

    pub fn encode(&self) -> [u8; IUL_STAT_SIZE] {
        let mut out = [0u8; IUL_STAT_SIZE];
        out[0..4].copy_from_slice(&self.mode.to_le_bytes());
        out[4..8].copy_from_slice(&self.uid.to_le_bytes());
        out[8..12].copy_from_slice(&self.gid.to_le_bytes());
        out[12..16].copy_from_slice(&self.rdev.to_le_bytes());
        out
    }
}

/// The blob range that covers everything strictly under `path`.
///
/// `(low, high)`, half-open: `low <= p < high` selects exactly the children.
/// It works because `/` is 0x2f and `0` is 0x30 — consecutive — so appending
/// each gives the two ends of the range of paths that begin with `path + "/"`.
/// The path itself is *not* in it and has to be matched separately, which is
/// why every statement using this also says `or path = ?`.
///
/// It is one statement instead of a walk, and it is why `paths.path` is a blob
/// with an index rather than a text column: a blob compares by bytes, and this
/// arithmetic is about bytes.
pub(crate) fn subtree_range(path: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut low = Vec::with_capacity(path.len() + 1);
    low.extend_from_slice(path);
    low.push(b'/');
    let mut high = Vec::with_capacity(path.len() + 1);
    high.extend_from_slice(path);
    high.push(b'0');
    (low, high)
}

/// Whether `path` is `dir` or below it, on a component boundary. The root is
/// the empty path and is above everything.
pub fn is_under(dir: &[u8], path: &[u8]) -> bool {
    path.starts_with(dir) && (dir.is_empty() || matches!(path.get(dir.len()), None | Some(b'/')))
}

/// A path with its first `start` bytes replaced by `replacement`.
///
/// This is the SQL function `change_prefix`, which `path_rename` uses to move a
/// whole subtree in one statement: `start` is the length of the old prefix and
/// `replacement` is the new one.
///
/// `None` when `start` is past the end of `path`. The C computed
/// `in_size - start + replacement_size` in `size_t` and would have wrapped to
/// an enormous allocation; the `WHERE` clause makes it unreachable today,
/// which is an argument the arithmetic should not have needed.
pub(crate) fn change_prefix(path: &[u8], start: usize, replacement: &[u8]) -> Option<Vec<u8>> {
    let tail = path.get(start..)?;
    let mut out = Vec::new();
    out.try_reserve_exact(replacement.len() + tail.len()).ok()?;
    out.extend_from_slice(replacement);
    out.extend_from_slice(tail);
    Some(out)
}

#[cfg(test)]
/// Is `candidate` at or under `path`, by the same rule the range expresses?
///
/// Not used by the statements — they use the range — but it is the property
/// the range is *for*, and having it lets a test check the two agree.
pub(crate) fn is_at_or_under(path: &[u8], candidate: &[u8]) -> bool {
    if candidate == path {
        return true;
    }
    let (low, high) = subtree_range(path);
    candidate >= &low[..] && candidate < &high[..]
}

// --------------------------------------------------------------- C binding

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stat_round_trips_and_its_layout_is_fixed() {
        let stat = IulStat {
            mode: 0o100644,
            uid: 1000,
            gid: 20,
            rdev: 0,
        };
        let blob = stat.encode();
        assert_eq!(blob.len(), 16);
        assert_eq!(IulStat::decode(&blob), Some(stat));
        // The order and endianness are the on-disk format. Written out rather
        // than derived, so a change to the struct fails here instead of
        // silently reinterpreting every fakefs in the world.
        assert_eq!(
            blob,
            [
                0xa4, 0x81, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0, 0, 0, 0
            ]
        );
    }

    /// The defect: the C cast the column pointer and read sixteen bytes from
    /// wherever it pointed. A NULL column and a short blob are both things a
    /// database that has been copied, truncated or written by another build
    /// can hold.
    #[test]
    fn a_blob_that_is_not_a_stat_is_refused() {
        assert_eq!(IulStat::decode(&[]), None);
        assert_eq!(IulStat::decode(&[0; 15]), None);
        assert_eq!(IulStat::decode(&[0; 17]), None, "longer is not this format");
        assert!(IulStat::decode(&[0; 16]).is_some());
    }

    #[test]
    fn a_subtree_range_covers_the_children_and_nothing_else() {
        let p = b"/a/b";
        for under in [&b"/a/b"[..], b"/a/b/c", b"/a/b/c/d", b"/a/b/."] {
            assert!(
                is_at_or_under(p, under),
                "{:?}",
                String::from_utf8_lossy(under)
            );
        }
        // The neighbours that a naive prefix match would take. `/a/b0` is the
        // one the range's upper end is chosen to exclude, and it is a name a
        // guest can create.
        for outside in [
            &b"/a/bc"[..],
            b"/a/b0",
            b"/a/b0/c",
            b"/ab",
            b"/a",
            b"/",
            b"/a/c",
        ] {
            assert!(
                !is_at_or_under(p, outside),
                "{:?}",
                String::from_utf8_lossy(outside)
            );
        }
    }

    /// The range is bytes, and a path is bytes: a name with a NUL or a
    /// non-UTF-8 byte in it is a name a guest can make, and the arithmetic has
    /// to hold for it too.
    #[test]
    fn a_subtree_range_is_about_bytes() {
        let p = b"/a\xff";
        assert!(is_at_or_under(p, b"/a\xff/c"));
        assert!(!is_at_or_under(p, b"/a\xffc"));
        let (low, high) = subtree_range(p);
        assert_eq!(low, b"/a\xff/");
        assert_eq!(high, b"/a\xff0");
    }

    /// The whole point of `/` and `0` being consecutive: nothing sorts between
    /// them, so the half-open range has no gap and no overlap.
    #[test]
    fn nothing_sorts_between_the_two_ends() {
        assert_eq!(b'0' - b'/', 1);
        let (low, high) = subtree_range(b"/x");
        // Every child begins with `low`, and every one of those is below
        // `high` because the byte at that position is '/' rather than '0'.
        for suffix in ["a", "z", "\u{7f}", ""] {
            let child = format!("/x/{suffix}").into_bytes();
            assert!(child >= low && child < high, "{child:?}");
        }
    }

    #[test]
    fn change_prefix_moves_a_subtree() {
        assert_eq!(
            change_prefix(b"/old/deep/file", 4, b"/new").unwrap(),
            b"/new/deep/file"
        );
        // The renamed path itself, where the tail is empty.
        assert_eq!(change_prefix(b"/old", 4, b"/new").unwrap(), b"/new");
        // A replacement of a different length, which is the ordinary case.
        assert_eq!(
            change_prefix(b"/a/x", 2, b"/muchlonger").unwrap(),
            b"/muchlonger/x"
        );
    }

    /// The C computed `in_size - start + replacement_size` in `size_t`, so a
    /// `start` past the end wrapped to an enormous allocation. Its `WHERE`
    /// clause makes that unreachable, which is an argument the arithmetic
    /// should not have needed.
    #[test]
    fn change_prefix_refuses_a_start_past_the_end() {
        assert_eq!(change_prefix(b"/ab", 4, b"/new"), None);
        assert_eq!(change_prefix(b"", 1, b"/new"), None);
        assert_eq!(change_prefix(b"/ab", 3, b"/new").unwrap(), b"/new");
    }

    /// Renaming a tree and then asking the range about it: the two agree, and
    /// the paths the range did not cover are the ones the rename did not move.
    #[test]
    fn a_rename_moves_exactly_what_the_range_covers() {
        let all: Vec<&[u8]> = vec![
            b"/src",
            b"/src/a",
            b"/src/a/b",
            b"/srcx",
            b"/src0",
            b"/other",
        ];
        let moved: Vec<Vec<u8>> = all
            .iter()
            .map(|p| {
                if is_at_or_under(b"/src", p) {
                    change_prefix(p, 4, b"/dst").unwrap()
                } else {
                    p.to_vec()
                }
            })
            .collect();
        assert_eq!(
            moved,
            vec![
                b"/dst".to_vec(),
                b"/dst/a".to_vec(),
                b"/dst/a/b".to_vec(),
                b"/srcx".to_vec(),
                b"/src0".to_vec(),
                b"/other".to_vec(),
            ]
        );
    }
}
