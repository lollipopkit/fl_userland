//! The fakefs metadata database.
//!
//! A fakefs is a `data/` directory of real files plus `meta.db`, a SQLite
//! database holding the ownership, modes and device numbers that iOS will not
//! give an app for real. See CLAUDE.md and `crates/fs/fakedb`.

use std::path::Path;

use rusqlite::Connection;

use crate::error::{Error, Result};

/// The packed stat blob stored in `stats.stat`.
///
/// The layout has to match `crates/fs/fakedb`'s `IulStat` byte for byte:
/// the kernel reads these rows back with a struct copy. Four `u32`s, native
/// byte order, no padding.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IulStat {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
}

impl IulStat {
    pub const SIZE: usize = 16;

    pub fn to_blob(self) -> [u8; Self::SIZE] {
        let mut blob = [0u8; Self::SIZE];
        blob[0..4].copy_from_slice(&self.mode.to_ne_bytes());
        blob[4..8].copy_from_slice(&self.uid.to_ne_bytes());
        blob[8..12].copy_from_slice(&self.gid.to_ne_bytes());
        blob[12..16].copy_from_slice(&self.rdev.to_ne_bytes());
        blob
    }

    /// Parse a blob out of `stats.stat`.
    ///
    /// The C version cast the blob pointer straight to `struct iul_stat *` and
    /// dereferenced it without consulting `sqlite3_column_bytes`, so a short
    /// row — a truncated or hand-edited database — read past the end of
    /// sqlite's buffer.
    pub fn from_blob(blob: &[u8]) -> Result<IulStat> {
        if blob.len() < Self::SIZE {
            return Err(Error::Corrupt(format!(
                "stat blob is {} bytes, expected {}",
                blob.len(),
                Self::SIZE
            )));
        }
        let word = |i: usize| u32::from_ne_bytes([blob[i], blob[i + 1], blob[i + 2], blob[i + 3]]);
        Ok(IulStat {
            mode: word(0),
            uid: word(4),
            gid: word(8),
            rdev: word(12),
        })
    }

    pub fn file_type(self) -> u32 {
        self.mode & libc::S_IFMT as u32
    }

    pub fn is_regular(self) -> bool {
        self.file_type() == libc::S_IFREG as u32
    }

    pub fn is_symlink(self) -> bool {
        self.file_type() == libc::S_IFLNK as u32
    }
}

/// Open `<fs>/meta.db` for writing, creating it, and install the schema.
pub fn create(meta_db: &Path) -> Result<Connection> {
    let conn = Connection::open(meta_db)?;
    // WAL, matching what the C version set. The kernel opens the same file.
    conn.pragma_update(None, "journal_mode", "wal")?;

    // SAFETY: the handle is borrowed for the duration of the call, which only
    // runs `sqlite3_exec` on it.
    let rc = unsafe { fakeschema::create(conn.handle()) };
    if rc != 0 {
        return Err(Error::Corrupt(format!(
            "creating the fakefs schema failed ({rc})"
        )));
    }
    Ok(conn)
}

/// Open an existing `<fs>/meta.db` for export.
///
/// Read-write, though export writes no rows, and deliberately not
/// `SQLITE_OPEN_CREATE`, so a missing database is still an error.
///
/// A fakefs is created with `journal_mode=wal`, and that setting lives in the
/// database header. Opening a WAL database requires the `-shm` WAL-index file,
/// which a `SQLITE_OPEN_READONLY` connection is not allowed to create — so as
/// soon as `-shm` is gone, which is exactly what happens when whatever last
/// used the fakefs closed cleanly, a read-only open fails at first use with
/// SQLITE_CANTOPEN, "unable to open database file". The C version passed
/// SQLITE_OPEN_READONLY and hit this: `unfakefsify` worked only on a fakefs
/// that still had a live `-shm` beside it.
pub(crate) fn open_for_export(meta_db: &Path) -> Result<Connection> {
    use rusqlite::OpenFlags;
    let conn = Connection::open_with_flags(meta_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_layout_matches_struct_iul_stat() {
        // If this changes, every existing meta.db becomes unreadable by the
        // kernel, which copies the blob straight into a struct.
        let stat = IulStat {
            mode: 0x0000_81a4,
            uid: 0x1122_3344,
            gid: 0x5566_7788,
            rdev: 0x99aa_bbcc,
        };
        let blob = stat.to_blob();
        assert_eq!(blob.len(), 16);
        assert_eq!(&blob[0..4], &0x0000_81a4u32.to_ne_bytes());
        assert_eq!(&blob[4..8], &0x1122_3344u32.to_ne_bytes());
        assert_eq!(&blob[8..12], &0x5566_7788u32.to_ne_bytes());
        assert_eq!(&blob[12..16], &0x99aa_bbccu32.to_ne_bytes());
        assert_eq!(IulStat::from_blob(&blob).unwrap(), stat);
    }

    #[test]
    fn short_blob_is_rejected_not_read_past_the_end() {
        // The C version dereferenced this.
        for len in 0..IulStat::SIZE {
            let short = vec![0u8; len];
            assert!(
                matches!(IulStat::from_blob(&short), Err(Error::Corrupt(_))),
                "{len} bytes should be rejected"
            );
        }
        assert!(IulStat::from_blob(&[0u8; IulStat::SIZE]).is_ok());
    }

    #[test]
    fn longer_blob_is_accepted_for_forward_compatibility() {
        // A future schema may append fields; the kernel's struct copy reads
        // the prefix, so do the same rather than refusing.
        let mut blob = IulStat::default().to_blob().to_vec();
        blob.push(0xff);
        assert!(IulStat::from_blob(&blob).is_ok());
    }
}
