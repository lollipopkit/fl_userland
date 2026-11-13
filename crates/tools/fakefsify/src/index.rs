//! Host directory -> fakefs, in place.
//!
//! `import` unpacks a tarball; this describes a `data/` that already exists,
//! which is what the integration scripts have: a rootfs copied (or symlinked)
//! into `<fakefs>/data`. Every entry is recorded as owned by root with the
//! host's mode, and a row's inode is the host file's, so the database is
//! current the moment it is written and the first mount does not rebuild it.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rusqlite::{Transaction, params};

use crate::db::{self, IulStat};
use crate::error::{Error, IoContext, Result};

pub fn index(fs: &Path) -> Result<()> {
    let meta_db = fs.join("meta.db");
    // **Never over an existing meta.db.** For a fakefs the database is the
    // authority: a symlink is a host regular file holding the target, and a
    // mode or an owner is a row. Re-deriving them from the host turns every
    // symlink the guest made into a regular file.
    if meta_db.exists() {
        return Err(Error::Io {
            doing: format!("indexing {}", fs.display()),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "meta.db exists and is the authority; unpack the tree again instead",
            ),
        });
    }
    let data = fs.join("data");

    let mut conn = db::create(&meta_db)?;
    let db_inode = std::fs::metadata(&meta_db)
        .doing(|| format!("stat {}", meta_db.display()))?
        .ino();
    let tx = conn.transaction()?;
    tx.execute("update meta set db_inode = ?", params![db_inode as i64])?;
    // The root is stat'ed *through* a symlink: `data` may be a link to the
    // tree (`tests/integration/full.sh` makes one), and recording "/" as a
    // symlink sends every path walk into ELOOP.
    let root = std::fs::metadata(&data).doing(|| format!("stat {}", data.display()))?;
    record(&tx, b"", &root)?;
    walk(&tx, &data, &mut Vec::new())?;
    tx.commit()?;
    Ok(())
}

/// Record every entry under `dir`, whose guest path is `prefix`.
fn walk(tx: &Transaction, dir: &Path, prefix: &mut Vec<u8>) -> Result<()> {
    for entry in std::fs::read_dir(dir).doing(|| format!("reading {}", dir.display()))? {
        let entry = entry.doing(|| format!("reading {}", dir.display()))?;
        let meta = entry
            .metadata()
            .doing(|| format!("stat {}", entry.path().display()))?;
        let len = prefix.len();
        prefix.push(b'/');
        prefix.extend_from_slice(entry.file_name().as_bytes());
        record(tx, prefix, &meta)?;
        // `DirEntry::metadata` does not follow a symlink, so a link to a
        // directory is recorded and not descended into.
        if meta.is_dir() {
            walk(tx, &entry.path(), prefix)?;
        }
        prefix.truncate(len);
    }
    Ok(())
}

fn record(tx: &Transaction, path: &[u8], meta: &std::fs::Metadata) -> Result<()> {
    let stat = IulStat {
        mode: meta.mode(),
        ..IulStat::default()
    };
    let inode = meta.ino() as i64;
    // `or ignore`: hard links share an inode and therefore a row.
    tx.execute(
        "insert or ignore into stats (inode, stat) values (?, ?)",
        params![inode, stat.to_blob()],
    )?;
    tx.execute(
        "insert or replace into paths (path, inode) values (?, ?)",
        params![path, inode],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_root_as_the_empty_path_and_keeps_symlinks() {
        let fs = std::env::temp_dir().join(format!("fakefsify-index-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fs);
        let tree = fs.with_extension("tree");
        let _ = std::fs::remove_dir_all(&tree);
        std::fs::create_dir_all(tree.join("bin")).unwrap();
        std::fs::write(tree.join("bin/sh"), b"x").unwrap();
        std::os::unix::fs::symlink("sh", tree.join("bin/ash")).unwrap();
        std::os::unix::fs::symlink("bin", tree.join("usr")).unwrap();
        std::fs::create_dir(&fs).unwrap();
        std::os::unix::fs::symlink(&tree, fs.join("data")).unwrap();

        index(&fs).unwrap();
        assert!(index(&fs).is_err(), "a second index must refuse");

        let conn = rusqlite::Connection::open(fs.join("meta.db")).unwrap();
        let mode = |p: &[u8]| -> u32 {
            let blob: Vec<u8> = conn
                .query_row(
                    "select stat from stats join paths using (inode) where path = ?",
                    params![p],
                    |r| r.get(0),
                )
                .unwrap();
            IulStat::from_blob(&blob).unwrap().file_type()
        };
        assert_eq!(mode(b""), libc::S_IFDIR as u32, "root through the data symlink");
        assert_eq!(mode(b"/bin"), libc::S_IFDIR as u32);
        assert_eq!(mode(b"/bin/sh"), libc::S_IFREG as u32);
        assert_eq!(mode(b"/bin/ash"), libc::S_IFLNK as u32);
        assert_eq!(mode(b"/usr"), libc::S_IFLNK as u32);
        let rows: i64 = conn
            .query_row("select count(*) from paths", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 5, "a symlinked directory is not descended into");

        drop(conn);
        std::fs::remove_dir_all(&fs).unwrap();
        std::fs::remove_dir_all(&tree).unwrap();
    }
}
