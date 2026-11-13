//! Helpers shared by the unit tests.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

/// The schema a fresh `meta.db` gets, matching `crates/fs/fakeschema`.
///
/// Kept as a literal so that a copy that drifts shows up as a failing
/// migration test rather than silently.
const CURRENT_SCHEMA: &str = "\
    create table meta (id integer unique default 0, db_inode integer);
    insert into meta (db_inode) values (0);
    create table stats (inode integer primary key, stat blob);
    create table paths (path blob primary key, inode integer references stats(inode));
    create index inode_to_path on paths (inode, path);
    pragma user_version=3;";

/// The schema as it was before any migration ran: no `inode_to_path` index and
/// no foreign key from `paths` to `stats`, both of which migrations added.
const SCHEMA_V0: &str = "\
    create table meta (id integer unique default 0, db_inode integer);
    insert into meta (db_inode) values (0);
    create table stats (inode integer primary key, stat blob);
    create table paths (path blob primary key, inode integer);
    pragma user_version=0;";

pub(crate) fn current_schema() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory database");
    conn.execute_batch(CURRENT_SCHEMA).expect("current schema");
    conn
}

pub(crate) fn schema_at_version_zero() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory database");
    conn.execute_batch(SCHEMA_V0).expect("v0 schema");
    conn
}

pub fn user_version(conn: &Connection) -> i32 {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("reading user_version")
}

pub(crate) fn table_exists(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "select count(*) from sqlite_master where type = 'table' and name = ?",
        [name],
        |r| r.get::<_, i64>(0),
    )
    .unwrap()
        > 0
}

/// A scratch directory that removes itself.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fakefs-rs-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("creating scratch directory");
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
