//! Rebuild `paths` and `stats` against the inode numbers `data/` actually has.
//!
//! Runs when `meta.db`'s recorded inode does not match the file it was found
//! in, which means the fakefs was copied, restored from a backup, or moved
//! between devices: the real files are intact but every inode number recorded
//! against them is stale.
//!
//! In pseudocode:
//!
//! ```text
//! seen = {}
//! for path, inode in paths_old:
//!     real_inode = stat(path).st_ino     # skip the row if the file is gone
//!     if inode in seen:                  # a second name for one inode
//!         unlink(path); link(seen[inode], path)
//!     else:
//!         seen[inode] = path
//!     new.stats[real_inode] = old.stats[inode]
//!     new.paths[path] = real_inode
//! ```

use std::collections::HashMap;
use std::os::fd::BorrowedFd;

use rusqlite::Connection;
use rustix::fs::AtFlags;

use crate::errno::Result;

// A stored path as a name relative to the fakefs `data/` directory fd.
// `crates/fs/fakeschema` owns the rule; see its module comment for why it is
// there rather than written out once per crate.
use fakeschema::fix as fix_path;

pub fn rebuild(conn: &Connection, root: BorrowedFd<'_>) -> Result<()> {

    conn.execute_batch(
        "begin;
         create table paths_old (path blob primary key, inode integer);
         create table stats_old (inode integer primary key, stat blob);
         insert into paths_old select * from paths;
         insert into stats_old select * from stats;
         delete from paths;
         delete from stats;",
    )?;

    // inode as recorded in the old table -> the first path found for it.
    //
    // Reserved up front against the row count. Rust aborts the process when an
    // allocation fails, and this is the one unbounded allocation here — a
    // rootfs has hundreds of thousands of paths. The C version returned
    // _ENOMEM from a failed malloc so the mount failed rather than the app,
    // and try_reserve is what keeps that: see the panic note in CLAUDE.md.
    let row_count: i64 = conn.query_row("select count(*) from paths_old", [], |r| r.get(0))?;
    let mut first_path_for_inode: HashMap<i64, Vec<u8>> = HashMap::new();
    first_path_for_inode
        .try_reserve(row_count.clamp(0, i64::from(u32::MAX)) as usize)
        .map_err(|_| crate::errno::Error::OutOfMemory)?;

    {
        let mut get_paths = conn.prepare("select path, inode from paths_old")?;
        let mut read_stat = conn.prepare("select stat from stats_old where inode = ?")?;
        let mut write_path = conn.prepare("insert into paths (path, inode) values (?, ?)")?;
        let mut write_stat = conn.prepare("replace into stats (inode, stat) values (?, ?)")?;

        let mut rows = get_paths.query([])?;
        while let Some(row) = rows.next()? {
            let path: Vec<u8> = row.get(0)?;
            let inode: i64 = row.get(1)?;

            let mut real_inode = match rustix::fs::statat(root, fix_path(&path), AtFlags::empty()) {
                Ok(stat) => stat.st_ino as i64,
                // meta.db knows a path that data/ does not have. Dropping the
                // row is what makes the rebuild a repair.
                Err(_) => continue,
            };

            match first_path_for_inode.get(&inode) {
                Some(target) => {
                    // A second name for an inode the old table already had:
                    // make it a hardlink again. The unlink frees the name for
                    // linkat; if either fails the file stays an independent
                    // copy, as it did in C.
                    let _ = rustix::fs::unlinkat(root, fix_path(&path), AtFlags::empty());
                    let _ = rustix::fs::linkat(
                        root,
                        fix_path(target),
                        root,
                        fix_path(&path),
                        AtFlags::empty(),
                    );
                    // Stat again. The relink changed which file this path
                    // names, so the number read above is stale — the C version
                    // recorded it anyway, which left the two paths sharing one
                    // file on disk but holding separate stat rows, so changing
                    // the mode of one did not change the other. Re-reading is
                    // also what covers a relink that failed: the path then
                    // still names its own file, or is gone entirely.
                    match rustix::fs::statat(root, fix_path(&path), AtFlags::empty()) {
                        Ok(stat) => real_inode = stat.st_ino as i64,
                        Err(_) => continue,
                    }
                }
                None => {
                    first_path_for_inode.insert(inode, path.clone());
                }
            }

            // A path with no stat row carries no metadata worth keeping.
            let stat: Vec<u8> = match read_stat.query_row([inode], |r| r.get(0)) {
                Ok(stat) => stat,
                Err(rusqlite::Error::QueryReturnedNoRows) => continue,
                Err(e) => return Err(e.into()),
            };

            write_stat.execute(rusqlite::params![real_inode, &stat[..]])?;
            write_path.execute(rusqlite::params![&path[..], real_inode])?;
        }
    }

    conn.execute_batch(
        "drop table paths_old;
         drop table stats_old;
         commit;",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TempDir, current_schema, user_version};
    use std::os::fd::AsFd;

    /// Open a directory fd the way `fake_db_init` hands one in.
    fn open_dir(path: &std::path::Path) -> std::os::fd::OwnedFd {
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("opening data dir")
    }

    /// Populate `paths`/`stats` with inode numbers that are deliberately not
    /// the ones the files have — the situation a rebuild exists for.
    fn stale_db(entries: &[(&[u8], i64)]) -> Connection {
        let conn = current_schema();
        for (path, inode) in entries {
            conn.execute(
                "insert or ignore into stats (inode, stat) values (?, ?)",
                rusqlite::params![inode, &[0xabu8, 0xcd][..]],
            )
            .unwrap();
            conn.execute(
                "insert into paths (path, inode) values (?, ?)",
                rusqlite::params![path, inode],
            )
            .unwrap();
        }
        conn
    }

    fn paths_in(conn: &Connection) -> Vec<(Vec<u8>, i64)> {
        conn.prepare("select path, inode from paths order by path")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn inode_numbers_are_replaced_with_the_ones_on_disk() {
        let tmp = TempDir::new("rebuild-inodes");
        std::fs::write(tmp.path().join("a"), b"a").unwrap();
        let real = std::fs::metadata(tmp.path().join("a")).unwrap();
        let real_inode = {
            use std::os::unix::fs::MetadataExt;
            real.ino() as i64
        };

        let conn = stale_db(&[(b"/a", 4242)]);
        let dir = open_dir(tmp.path());

        rebuild(&conn, dir.as_fd()).expect("rebuild");

        assert_eq!(paths_in(&conn), vec![(b"/a".to_vec(), real_inode)]);
        // The stat blob followed the path to its new inode.
        let stat: Vec<u8> = conn
            .query_row(
                "select stat from stats where inode = ?",
                [real_inode],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stat, vec![0xab, 0xcd]);
    }

    #[test]
    fn two_paths_on_one_recorded_inode_become_hardlinks_again() {
        let tmp = TempDir::new("rebuild-hardlink");
        // Two independent files, as a copy of a fakefs would leave them.
        std::fs::write(tmp.path().join("one"), b"same").unwrap();
        std::fs::write(tmp.path().join("two"), b"same").unwrap();
        assert_ne!(ino(&tmp.path().join("one")), ino(&tmp.path().join("two")));

        let conn = stale_db(&[(b"/one", 77), (b"/two", 77)]);
        let dir = open_dir(tmp.path());

        rebuild(&conn, dir.as_fd()).expect("rebuild");

        // Relinked on disk...
        let shared = ino(&tmp.path().join("one"));
        assert_eq!(
            shared,
            ino(&tmp.path().join("two")),
            "the second path should have been relinked to the first"
        );
        // ...and both rows record that one inode. The C version stat'd before
        // relinking and stored the number the file had beforehand, so the two
        // paths ended up sharing a file on disk while pointing at separate
        // stat rows.
        let rows = paths_in(&conn);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1, rows[1].1, "both paths should share an inode");
        assert_eq!(rows[0].1, shared as i64, "and it should be the real one");
        // One stat row, reachable from either name.
        let stats: i64 = conn
            .query_row("select count(*) from stats", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stats, 1);
    }

    #[test]
    fn a_path_with_no_file_is_dropped() {
        let tmp = TempDir::new("rebuild-missing");
        std::fs::write(tmp.path().join("present"), b"x").unwrap();

        let conn = stale_db(&[(b"/present", 1), (b"/gone", 2)]);
        let dir = open_dir(tmp.path());

        rebuild(&conn, dir.as_fd()).expect("rebuild");

        let rows = paths_in(&conn);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, b"/present".to_vec());
    }

    #[test]
    fn the_root_row_survives() {
        // The root is the empty blob and fix_path turns it into ".", which
        // stats the data directory itself. Losing this row would make the
        // whole filesystem unreachable.
        let tmp = TempDir::new("rebuild-root");
        let conn = stale_db(&[(b"", 1)]);
        let dir = open_dir(tmp.path());

        rebuild(&conn, dir.as_fd()).expect("rebuild");

        let rows = paths_in(&conn);
        assert_eq!(rows.len(), 1, "the root row should still be there");
        assert_eq!(rows[0].0, Vec::<u8>::new());
    }

    #[test]
    fn a_failed_rebuild_leaves_the_old_rows_in_place() {
        // Force a failure partway by dropping the table the loop writes into.
        let tmp = TempDir::new("rebuild-rollback");
        std::fs::write(tmp.path().join("a"), b"a").unwrap();
        let conn = stale_db(&[(b"/a", 5)]);
        let dir = open_dir(tmp.path());

        conn.execute_batch("begin; create table paths_old (x); commit;")
            .unwrap();

        let err = rebuild(&conn, dir.as_fd()).expect_err("should fail");
        assert_eq!(err.errno(), crate::EIO);
        let _ = conn.execute_batch("rollback");

        // Presenting an empty filesystem as a complete one is the thing the
        // rollback exists to prevent.
        assert_eq!(paths_in(&conn), vec![(b"/a".to_vec(), 5)]);
        assert_eq!(user_version(&conn), 3);
    }

    fn ino(path: &std::path::Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).unwrap().ino()
    }
}
