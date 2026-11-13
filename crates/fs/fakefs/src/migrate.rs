//! Schema migrations.
//!
//! `pragma user_version` records how many of the migrations below have run.
//! Adding one means appending to `MIGRATIONS` — the index is the version it
//! upgrades *from*, so nothing may be reordered or removed, and the count is
//! the version a current database reports.
//!
//! Keep this in step with `fs/fake-schema.c`, which creates a database already
//! at the latest version: a fresh `meta.db` and a migrated one have to end up
//! with the same schema.

use rusqlite::Connection;

use crate::errno::Result;

/// Indexed by the version being upgraded from.
const MIGRATIONS: &[&str] = &[
    // version 0 -> 1: add another index
    "create index inode_to_path on paths (inode, path);",
    // version 1 -> 2: add foreign key constraint on paths, create trigger to
    // automatically clean up stats
    "create table paths_new (path blob primary key, inode integer references stats(inode));\
     insert into paths_new select * from paths where exists (select 1 from stats where inode = paths.inode);\
     drop table paths; alter table paths_new rename to paths;\
     create index inode_to_path on paths (inode, path);\
     delete from stats where not exists (select 1 from paths where inode = stats.inode);\
     create trigger delete_path after delete on paths \
     when not exists (select 1 from paths where inode = old.inode) \
     begin \
     delete from stats where not exists (select 1 from paths where inode = old.inode) and inode = old.inode; \
     end;",
    // version 2 -> 3: the trigger was a mistake
    "drop trigger delete_path",
];

/// The version a database is at once every migration has run.
pub fn latest_version() -> i32 {
    MIGRATIONS.len() as i32
}

pub fn migrate(conn: &Connection) -> Result<()> {
    let mut version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

    conn.execute_batch("begin")?;
    while version < latest_version() {
        conn.execute_batch(MIGRATIONS[version as usize])?;
        version += 1;
    }
    // Placeholders are not allowed in pragmas, hence the format!. `version` is
    // an i32 this function computed, not anything from outside.
    conn.execute_batch(&format!("pragma user_version = {version}"))?;
    conn.execute_batch("commit")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{schema_at_version_zero, table_exists, user_version};

    #[test]
    fn migrates_a_version_zero_database_to_the_latest() {
        let conn = schema_at_version_zero();
        assert_eq!(user_version(&conn), 0);

        migrate(&conn).expect("migrate");

        assert_eq!(user_version(&conn), latest_version());
        // The schema creates a database *already at the latest version*, so
        // this is the number `crates/fs/fakeschema`'s `pragma user_version`
        // has to be. It used to be `assert_eq!(latest_version(), 3)` with a
        // comment saying "fake-schema.c writes user_version=3" -- a test
        // restating its subject, which is what a check against a string in
        // another language had to be. The pragma is parsed out of the schema
        // now, so appending a migration without touching it fails here.
        assert_eq!(
            latest_version(),
            fakeschema::user_version().expect("the schema names a version"),
            "a fresh fakefs must claim the version the migration list ends at"
        );
        // Version 3 dropped the trigger version 2 added.
        assert!(!trigger_exists(&conn, "delete_path"));
        assert!(index_exists(&conn, "inode_to_path"));
    }

    #[test]
    fn migrating_an_up_to_date_database_changes_nothing() {
        let conn = schema_at_version_zero();
        migrate(&conn).expect("first migrate");
        let before = schema_dump(&conn);

        migrate(&conn).expect("second migrate");

        assert_eq!(user_version(&conn), latest_version());
        assert_eq!(schema_dump(&conn), before, "a second run should be a no-op");
    }

    #[test]
    fn version_2_drops_rows_whose_stats_are_missing() {
        // The version 1 -> 2 migration adds a foreign key from paths to stats,
        // so it has to drop paths pointing at inodes with no stat row.
        let conn = schema_at_version_zero();
        conn.execute_batch(
            "insert into stats (inode, stat) values (1, x'00');
             insert into paths values (x'2f6b657074', 1);
             insert into paths values (x'2f64726f70706564', 99);",
        )
        .unwrap();

        migrate(&conn).expect("migrate");

        let paths: Vec<Vec<u8>> = conn
            .prepare("select path from paths order by path")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(paths, vec![b"/kept".to_vec()]);
    }

    #[test]
    fn a_failing_migration_rolls_back_and_leaves_the_version_alone() {
        // Make the version 0 -> 1 migration fail by having its index already
        // there, and check nothing was left half-applied.
        let conn = schema_at_version_zero();
        conn.execute_batch("create index inode_to_path on paths (inode, path);")
            .unwrap();

        let err = migrate(&conn).expect_err("duplicate index should fail");
        assert_eq!(err.errno(), crate::EIO);

        // The C version rolled back from the caller; do the same here so the
        // assertion below describes the state the caller sees.
        let _ = conn.execute_batch("rollback");
        assert_eq!(
            user_version(&conn),
            0,
            "user_version is only bumped once every migration has run"
        );
        assert!(table_exists(&conn, "paths"));
        assert!(
            !table_exists(&conn, "paths_new"),
            "the version 2 migration's scratch table should not survive"
        );
    }

    fn trigger_exists(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "select count(*) from sqlite_master where type = 'trigger' and name = ?",
            [name],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
            > 0
    }

    fn index_exists(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "select count(*) from sqlite_master where type = 'index' and name = ?",
            [name],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
            > 0
    }

    fn schema_dump(conn: &Connection) -> Vec<String> {
        conn.prepare("select coalesce(sql, '') from sqlite_master order by type, name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }
}
