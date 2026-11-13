//! Integration-style tests for the fake filesystem database.

use super::*;
/// The schema `crates/tools/fakefsify` writes, at the version
/// `fakefs_migrate` considers current. Written out here rather than shared
/// so that a change to the real one shows up as a failing migration test
/// instead of both moving together.
const SCHEMA: &str = "
    create table meta (id integer unique default 0, db_inode integer);
    insert into meta (db_inode) values (0);
    create table stats (inode integer primary key, stat blob);
    create table paths (path blob primary key, inode integer references stats(inode));
    create index inode_to_path on paths (inode, path);
    pragma user_version=3;";

/// A database of our own, removed on drop.
struct TempDb {
    dir: std::path::PathBuf,
}

impl TempDb {
    fn new(tag: &str) -> TempDb {
        let mut dir = std::env::temp_dir();
        dir.push(format!("fakedb-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp directory");
        let conn = Connection::open(dir.join("meta.db")).expect("a database");
        conn.execute_batch(SCHEMA).expect("the schema");
        drop(conn);
        TempDb { dir }
    }
    fn open(&self) -> Db {
        Db::open(
            self.dir.join("meta.db").to_str().expect("utf8"),
            libc_at_fdcwd(),
        )
        .expect("it opens")
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn libc_at_fdcwd() -> std::os::fd::BorrowedFd<'static> {
    rustix::fs::CWD // nothing here reads the root, but the rebuild takes one
}

/// Cargo runs a crate's tests as **threads**, and the leak checks below
/// read the process-wide descriptor count. Every test here takes this, so
/// no other one has a database open while that count is being compared.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn stat(mode: u32) -> IulStat {
    IulStat {
        mode,
        uid: 501,
        gid: 20,
        rdev: 0,
    }
}

#[test]
fn a_database_missing_its_tables_fails_to_open() {
    let _serial = serial();
    // The C prepared all sixteen statements at init, so this failed the
    // *mount*. prepare_cached is lazy, which would have turned it into a
    // filesystem that mounts and then fails every operation.
    let mut dir = std::env::temp_dir();
    dir.push(format!("fakedb-notables-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temp directory");
    let path = dir.join("meta.db");
    let conn = Connection::open(&path).expect("a database");
    conn.execute_batch(
        "create table meta (id integer unique default 0, db_inode integer);
         insert into meta (db_inode) values (0);
         pragma user_version=3;",
    )
    .expect("half a schema");
    drop(conn);
    assert!(Db::open(path.to_str().expect("utf8"), libc_at_fdcwd()).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_path_round_trips() {
    let _serial = serial();
    let t = TempDb::new("roundtrip");
    let db = t.open();

    let mut tx = db.write();
    let inode = tx.path_create(b"/hello", &stat(0o100644));
    assert!(tx.commit());
    assert_ne!(inode, 0);

    let tx = db.read();
    let (back, back_inode) = tx.path_stat(b"/hello").expect("found");
    assert!(tx.commit());
    assert_eq!(back, stat(0o100644));
    assert_eq!(back_inode, inode);
}

#[test]
fn a_write_invalidates_what_the_cache_said() {
    let _serial = serial();
    // The whole risk of the cache. A mode that a chmod changed, answered
    // from a cache that nothing emptied, is a permission check against the
    // old mode -- which is exactly how the C's path cache was wrong.
    let t = TempDb::new("cacheinval");
    let db = t.open();

    let mut tx = db.write();
    let inode = tx.path_create(b"/f", &stat(0o100644));
    assert!(tx.commit());

    // Populate.
    assert_eq!(db.lookup_path(b"/f").expect("found").0.mode, 0o100644);
    assert!(db.cache_len() > 0);

    // Change it, and the cache must not answer with the old mode.
    let mut tx = db.write();
    assert!(tx.inode_write_stat(inode, &stat(0o100600)));
    assert!(tx.commit());
    assert_eq!(db.cache_len(), 0, "the commit emptied it");
    assert_eq!(db.lookup_path(b"/f").expect("found").0.mode, 0o100600);
}

#[test]
fn a_negative_answer_is_invalidated_by_the_create_that_makes_it_wrong() {
    let _serial = serial();
    // Negative answers are cached, which is most of the value -- the walk
    // asks about components that do not exist. A create must take it back.
    let t = TempDb::new("cachenegative");
    let db = t.open();
    assert!(db.lookup_path(b"/later").is_none());
    assert!(db.cache_len() > 0, "the miss was cached");

    let mut tx = db.write();
    tx.path_create(b"/later", &stat(0o100644));
    assert!(tx.commit());
    assert!(
        db.lookup_path(b"/later").is_some(),
        "and the create took it back"
    );
}

#[test]
fn an_unlink_and_a_rename_invalidate_too() {
    let _serial = serial();
    let t = TempDb::new("cachemove");
    let db = t.open();
    let mut tx = db.write();
    tx.path_create(b"/a", &stat(0o100644));
    tx.path_create(b"/gone", &stat(0o100644));
    assert!(tx.commit());
    assert!(db.lookup_path(b"/a").is_some());
    assert!(db.lookup_path(b"/gone").is_some());

    let mut tx = db.write();
    tx.unlink(b"/gone");
    assert!(tx.commit());
    assert!(
        db.lookup_path(b"/gone").is_none(),
        "the unlink took it back"
    );

    let mut tx = db.write();
    assert!(tx.rename(b"/a", b"/b"));
    assert!(tx.commit());
    assert!(
        db.lookup_path(b"/a").is_none(),
        "the rename took the old name back"
    );
    assert!(db.lookup_path(b"/b").is_some());
}

#[test]
fn a_rolled_back_write_leaves_no_cache_entry_describing_it() {
    let _serial = serial();
    let t = TempDb::new("cacherollback");
    let db = t.open();
    assert!(db.lookup_path(b"/r").is_none());
    let mut tx = db.write();
    tx.path_create(b"/r", &stat(0o100644));
    tx.rollback();
    assert!(db.lookup_path(b"/r").is_none(), "it was never created");
}

#[test]
fn the_cache_is_bounded() {
    let _serial = serial();
    let t = TempDb::new("cachebound");
    let db = t.open();
    for i in 0..(CACHE_MAX + 100) {
        let _ = db.lookup_path(format!("/miss/{i}").as_bytes());
    }
    assert!(
        db.cache_len() <= CACHE_MAX,
        "held {} of at most {CACHE_MAX}",
        db.cache_len()
    );
}

#[test]
fn lookup_inode_and_lookup_path_agree() {
    let _serial = serial();
    let t = TempDb::new("cacheagree");
    let db = t.open();
    let mut tx = db.write();
    let inode = tx.path_create(b"/x", &stat(0o100644));
    assert!(tx.commit());
    assert_eq!(db.lookup_inode(b"/x"), inode);
    assert_eq!(db.lookup_path(b"/x").expect("found").1, inode);
    assert_eq!(db.lookup_inode(b"/not-there"), 0);
}

#[test]
fn readers_and_a_writer_do_not_deadlock() {
    let _serial = serial();
    // The lock order this could get wrong: a commit holds the connection
    // and then takes the cache, so a lookup that held the cache while
    // waiting for the connection would close the cycle. Threads doing both
    // at once is what would find it.
    let t = TempDb::new("cachelocks");
    let db = std::sync::Arc::new(t.open());
    {
        let mut tx = db.write();
        for i in 0..32 {
            tx.path_create(format!("/f{i}").as_bytes(), &stat(0o100644));
        }
        assert!(tx.commit());
    }
    std::thread::scope(|scope| {
        for _ in 0..6 {
            let db = db.clone();
            scope.spawn(move || {
                for i in 0..500 {
                    let _ = db.lookup_path(format!("/f{}", i % 32).as_bytes());
                }
            });
        }
        for _ in 0..2 {
            let db = db.clone();
            scope.spawn(move || {
                for i in 0..100 {
                    let mut tx = db.write();
                    tx.inode_write_stat(1, &stat(0o100600 | (i & 1)));
                    tx.commit();
                }
            });
        }
    });
    // And the rows are still what they were.
    for i in 0..32 {
        assert!(db.lookup_path(format!("/f{i}").as_bytes()).is_some());
    }
}

#[test]
fn a_missing_path_is_not_found_rather_than_an_error() {
    let _serial = serial();
    let t = TempDb::new("missing");
    let db = t.open();
    let tx = db.read();
    assert_eq!(tx.path_inode(b"/nothing"), 0);
    assert!(tx.path_stat(b"/nothing").is_none());
    assert!(tx.commit());
}

#[test]
fn a_rollback_leaves_nothing() {
    let _serial = serial();
    let t = TempDb::new("rollback");
    let db = t.open();
    let mut tx = db.write();
    tx.path_create(b"/gone", &stat(0o100644));
    tx.rollback();

    let tx = db.read();
    assert_eq!(tx.path_inode(b"/gone"), 0);
    assert!(tx.commit());
}

#[test]
fn a_dropped_transaction_rolls_back_and_leaves_the_connection_usable() {
    let _serial = serial();
    // The state the doc comment used to claim was impossible. Dropping a
    // value is always allowed; what was not handled is what the drop left
    // behind, which was an open SQLite transaction on the connection the
    // next caller takes -- so one lost error path would have turned into a
    // database that refuses every later write.
    let t = TempDb::new("dropped");
    let db = t.open();
    {
        let mut tx = db.write();
        tx.path_create(b"/half", &stat(0o100644));
        // No commit, no rollback. Just gone.
    }

    // Nothing was written...
    let tx = db.read();
    assert_eq!(
        tx.path_inode(b"/half"),
        0,
        "the dropped transaction went back"
    );
    assert!(tx.commit());

    // ...and the connection still works, which is the half that matters:
    // a leaked `begin` makes the *next* one fail, not this one.
    let mut tx = db.write();
    tx.path_create(b"/after", &stat(0o100644));
    assert!(tx.commit(), "a later transaction still commits");
    let tx = db.read();
    assert_ne!(tx.path_inode(b"/after"), 0);
    assert!(tx.commit());
}

#[test]
fn a_committed_transaction_is_not_rolled_back_by_its_own_drop() {
    let _serial = serial();
    // `commit` takes `self`, so the guard runs at the end of it. It has to
    // know the decision was made -- otherwise every commit would be
    // followed by a rollback of the transaction it just closed.
    let t = TempDb::new("commit-then-drop");
    let db = t.open();
    let mut tx = db.write();
    tx.path_create(b"/kept", &stat(0o100644));
    assert!(tx.commit());
    let tx = db.read();
    assert_ne!(tx.path_inode(b"/kept"), 0, "the commit stood");
    assert!(tx.commit());
}

#[test]
fn a_subtree_rename_moves_the_children_and_not_the_neighbours() {
    let _serial = serial();
    // '/' is 0x2f and '0' is 0x30, so the children of /dir are exactly the
    // half-open blob range between them -- and /dirty, whose name starts
    // with the same characters, is not one of them.
    let t = TempDb::new("rename");
    let db = t.open();
    let mut tx = db.write();
    for p in [
        &b"/dir"[..],
        b"/dir/a",
        b"/dir/b/c",
        b"/dirty",
        b"/dir-next-door",
    ] {
        tx.path_create(p, &stat(0o100644));
    }
    assert!(tx.commit());

    let mut tx = db.write();
    assert!(tx.rename(b"/dir", b"/moved"));
    assert!(tx.commit());

    let tx = db.read();
    for gone in [&b"/dir"[..], b"/dir/a", b"/dir/b/c"] {
        assert_eq!(
            tx.path_inode(gone),
            0,
            "{:?} moved",
            String::from_utf8_lossy(gone)
        );
    }
    for there in [
        &b"/moved"[..],
        b"/moved/a",
        b"/moved/b/c",
        b"/dirty",
        b"/dir-next-door",
    ] {
        assert_ne!(
            tx.path_inode(there),
            0,
            "{:?} is there",
            String::from_utf8_lossy(there)
        );
    }
    assert!(tx.commit());
}

#[test]
fn deleting_a_tree_takes_the_children_and_not_the_neighbours() {
    let _serial = serial();
    let t = TempDb::new("deltree");
    let db = t.open();
    let mut tx = db.write();
    for p in [&b"/dir"[..], b"/dir/a", b"/dir/b/c", b"/dirty"] {
        tx.path_create(p, &stat(0o100644));
    }
    assert!(tx.commit());

    let mut tx = db.write();
    assert!(tx.delete_tree(b"/dir"));
    assert!(tx.commit());

    let tx = db.read();
    assert_eq!(tx.path_inode(b"/dir"), 0);
    assert_eq!(tx.path_inode(b"/dir/a"), 0);
    assert_eq!(tx.path_inode(b"/dir/b/c"), 0);
    assert_ne!(tx.path_inode(b"/dirty"), 0);
    assert!(tx.commit());
}

#[test]
fn a_link_shares_the_inode_and_an_unlink_reports_it() {
    let _serial = serial();
    let t = TempDb::new("link");
    let db = t.open();
    let mut tx = db.write();
    let inode = tx.path_create(b"/one", &stat(0o100644));
    assert!(tx.link(b"/one", b"/two"));
    assert!(tx.commit());

    let tx = db.read();
    assert_eq!(tx.path_inode(b"/two"), inode);
    assert!(tx.commit());

    let mut tx = db.write();
    assert_eq!(tx.unlink(b"/two"), inode);
    assert_eq!(tx.unlink(b"/two"), 0, "and again says nothing was there");
    assert!(tx.commit());
}

#[test]
fn linking_from_a_path_with_no_row_is_refused_rather_than_fatal() {
    let _serial = serial();
    // This was a die(): a meta.db whose paths table disagrees with what is
    // under data/ took the whole application down from inside link(2).
    let t = TempDb::new("badlink");
    let db = t.open();
    let mut tx = db.write();
    assert!(!tx.link(b"/not-there", b"/dst"));
    assert!(tx.commit());
    let tx = db.read();
    assert_eq!(tx.path_inode(b"/dst"), 0);
    assert!(tx.commit());
}

#[test]
fn every_path_for_an_inode_comes_back() {
    let _serial = serial();
    let t = TempDb::new("paths");
    let db = t.open();
    let mut tx = db.write();
    let inode = tx.path_create(b"/a", &stat(0o100644));
    assert!(tx.link(b"/a", b"/b"));
    assert!(tx.link(b"/a", b"/c"));
    assert!(tx.commit());

    let mut paths = db.paths_for_inode(inode);
    paths.sort();
    assert_eq!(paths, vec![b"/a".to_vec(), b"/b".to_vec(), b"/c".to_vec()]);
    assert!(db.paths_for_inode(inode + 999).is_empty());
}

#[test]
fn an_orphaned_stat_is_collected_and_a_referenced_one_is_not() {
    let _serial = serial();
    let t = TempDb::new("orphan");
    let db = t.open();
    let mut tx = db.write();
    let lonely = tx.path_create(b"/lonely", &stat(0o100644));
    let shared = tx.path_create(b"/shared", &stat(0o100644));
    assert!(tx.link(b"/shared", b"/shared2"));
    assert!(tx.commit());

    let mut tx = db.write();
    tx.unlink(b"/lonely");
    tx.unlink(b"/shared");
    assert!(tx.commit());

    db.inode_orphaned(lonely);
    db.inode_orphaned(shared);

    let tx = db.read();
    assert!(tx.inode_stat(lonely).is_none(), "no path names it");
    assert!(tx.inode_stat(shared).is_some(), "/shared2 still does");
    assert!(tx.commit());
}

#[test]
fn a_stat_blob_that_is_not_one_is_not_found() {
    let _serial = serial();
    // meta.db is a file on disk. A NULL column used to be a null
    // dereference and a short one read past sqlite's buffer into a guest's
    // st_mode.
    let t = TempDb::new("badblob");
    let db = t.open();
    let mut tx = db.write();
    let inode = tx.path_create(b"/f", &stat(0o100644));
    assert!(tx.run(sql::WRITE_STAT, params![&b"short"[..], inode as i64]));
    assert!(tx.commit());

    let tx = db.read();
    assert!(tx.path_stat(b"/f").is_none());
    assert!(tx.inode_stat(inode).is_none());
    assert!(tx.commit());

    let mut tx = db.write();
    assert!(tx.run(
        "update stats set stat = NULL where inode = ?",
        params![inode as i64]
    ));
    assert!(tx.commit());
    let tx = db.read();
    assert!(tx.path_stat(b"/f").is_none());
    assert!(tx.commit());
}

#[test]
fn a_failed_write_takes_its_whole_transaction_with_it() {
    let _serial = serial();
    // The one that needed a whole unit test in C. `PRAGMA max_page_count`
    // bounds the database per connection and a write past it is
    // SQLITE_FULL -- a real error and not lock contention, which is the
    // class the full volume and the corrupt file are reached by.
    let t = TempDb::new("full");
    let db = t.open();
    let mut tx = db.write();
    let first = tx.path_create(b"/first", &stat(0o100644));
    assert!(tx.commit());
    assert_ne!(first, 0);

    {
        let conn = db.inner.lock().expect("not poisoned");
        conn.execute_batch("pragma max_page_count = 2")
            .expect("a bound");
    }

    let mut refused = false;
    for i in 0..4096 {
        let mut tx = db.write();
        let ino = tx.path_create(format!("/pad/{i}").as_bytes(), &stat(0o100644));
        let committed = tx.commit();
        if ino == 0 || !committed {
            assert_eq!(ino, 0, "a refused create reports no inode");
            assert!(!committed, "and its transaction does not commit");
            refused = true;
            break;
        }
    }
    assert!(
        refused,
        "no write was refused; max_page_count did not bound this database, \
         so the rest of this test proves nothing"
    );

    {
        let conn = db.inner.lock().expect("not poisoned");
        conn.execute_batch("pragma max_page_count = 1073741823")
            .expect("the bound lifts");
    }

    // Nothing names /first's inode but /first. A path row pointing at
    // another file's inode is two guest paths sharing one host file.
    assert_eq!(db.paths_for_inode(first), vec![b"/first".to_vec()]);

    // And no stats row was committed without a path row to reach it by.
    let orphans: i64 = {
        let conn = db.inner.lock().expect("not poisoned");
        conn.query_row(
            "select count(*) from stats where inode not in (select inode from paths)",
            [],
            |r| r.get(0),
        )
        .expect("counted")
    };
    assert_eq!(
        orphans, 0,
        "a transaction was committed without its second statement"
    );

    // Still usable: a failed write is an operation that did not happen.
    let mut tx = db.write();
    let after = tx.path_create(b"/after", &stat(0o100644));
    assert!(tx.commit());
    assert!(after != 0 && after != first);
}

#[test]
fn opening_something_that_is_not_a_database_fails_rather_than_aborting() {
    let _serial = serial();
    let mut dir = std::env::temp_dir();
    dir.push(format!("fakedb-notadb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temp directory");
    let path = dir.join("meta.db");
    std::fs::write(&path, b"this is not a database").expect("a file");
    assert!(Db::open(path.to_str().expect("utf8"), libc_at_fdcwd()).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn opening_a_path_that_is_not_there_fails() {
    let _serial = serial();
    assert!(Db::open("/nonexistent-directory-here/meta.db", libc_at_fdcwd()).is_err());
}
// ------------------------------------------------------- the C boundary
//
// `tests/unit/fakedb_test.c` until 2026-09-08, where it lived because these
// are "the handle, its lifetime, and what an embedder sees when a mount
// fails -- which a Rust unit test cannot reach". It can: `fakedb_open` and
// `fakedb_close` are forty lines up this file.
//
// Until recently a failure in any of these paths was a `die()`, so there
// was nothing to assert about. What is asserted is what replaced it: an
// error fails the mount and leaves nothing behind.
//
// **A leak is not visible from inside the process**, so the proxy is the
// host descriptor count: an sqlite handle that was not closed holds at
// least one, and one held after a failed open is exactly the bug these
// paths had. Measured as a delta over a repeated operation, which is what
// tells a leak from a one-off allocation.

/// Counting `/dev/fd` is portable enough for macOS and Linux, which is
/// where this runs.
fn open_fd_count() -> usize {
    std::fs::read_dir("/dev/fd").map(|d| d.count()).unwrap_or(0)
}

/// A database file with the given SQL, and nothing else.
fn make_db(path: &std::path::Path, sql: &str) {
    let _ = std::fs::remove_file(path);
    let conn = Connection::open(path).expect("a database");
    conn.execute_batch(sql).expect("the sql");
    drop(conn);
}

/// It was `open_c`, answering a `(*mut Db, c_int)` pair -- a null and an out
/// parameter -- because that is what `fakedb_open` was. The `Result` is the
/// same two facts with no way to read the errno of a success.
fn open_db(path: &std::path::Path) -> Result<Box<Db>, c_int> {
    let c = std::ffi::CString::new(path.to_str().expect("utf8")).expect("no NUL");
    super::abi::open(&c, libc_at_fdcwd())
}

/// A current-schema database opens, works, and closes without leaving a
/// descriptor. "Works" is what says the statements prepared against the
/// right schema; the semantics of each are the tests above.
///
/// It drove six C-ABI shims -- `fakedb_write`, `fakedb_path_create`,
/// `fakedb_commit`, `fakedb_read`, `fakedb_path_stat`, `fakedb_close` -- and
/// on 2026-09-16 it was their **only** caller, so they were six exported
/// functions and two `transmute`s kept alive by one test. The subject is
/// unchanged: open, do the four operations, drop, count descriptors.
#[test]
fn open_then_close_is_clean() {
    let _serial = serial();
    let t = TempDb::new("cboundary");
    let path = t.dir.join("meta.db");
    let before = open_fd_count();

    let db = open_db(&path).expect("a current-schema database opens");

    let s = stat(0o100644);
    let inode = {
        let mut tx = db.write();
        let inode = tx.path_create(b"/hello", &s);
        assert!(tx.commit());
        inode
    };
    assert_ne!(inode, 0);

    let tx = db.read();
    let (back, back_inode) = tx.path_stat(b"/hello").expect("the row just written");
    assert!(tx.commit());
    assert_eq!(back.mode, s.mode);
    assert_eq!(back.uid, s.uid);
    assert_eq!(back_inode, inode);

    drop(db);
    assert_eq!(open_fd_count(), before);
}

// `closing_null_is_safe` was here until 2026-09-16: `fakedb_close(null)`,
// for "the mount's failure path reaches this with a pointer that was never
// opened". There is no `fakedb_close` -- the database is a `Box` its owner
// drops -- and a failed open answers `Err`, so there is no null to pass. The
// null that remains is the mount's own union arm, and `fakefs_rs_umount`
// tests it where it lives.

/// Three ways to fail a mount, none of which may keep a descriptor: a file
/// that is not a database, a file that is not there, and an open database
/// missing the tables the statements name.
#[test]
fn a_failed_open_keeps_nothing() {
    let _serial = serial();
    let mut dir = std::env::temp_dir();
    dir.push(format!("fakedb-failopen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temp directory");

    // Not an SQLite file: the header check fails on the first statement.
    let garbage = dir.join("garbage.db");
    std::fs::write(&garbage, vec![b'A'; 4096]).expect("write");
    // A mount of a container that is not there.
    let absent = dir.join("absent.db");
    // An open database with half a schema. Prepared at open for exactly
    // this reason: `prepare_cached` is lazy, and lazily this would be a
    // filesystem that mounts and then fails every operation -- the same
    // broken database presented as a working one.
    let empty = dir.join("empty.db");
    const HALF: &str = "create table meta (id integer unique default 0, db_inode integer);
                        insert into meta (db_inode) values (0);
                        pragma user_version=3;";
    make_db(&empty, HALF);

    for (name, path, remake) in [
        ("garbage", &garbage, false),
        ("absent", &absent, false),
        ("half a schema", &empty, true),
    ] {
        // Once to settle any first-call allocation, then measured.
        assert!(open_db(path).is_err(), "{name} opened");
        let before = open_fd_count();
        for _ in 0..8 {
            if remake {
                make_db(path, HALF);
            }
            let err = open_db(path).err().unwrap_or_else(|| panic!("{name} opened"));
            assert!(err < 0, "{name}: err {err}");
        }
        assert_eq!(open_fd_count(), before, "{name} leaked a descriptor");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same schema at version 0, before any migration has run.
const SCHEMA_V0: &str = "
    create table meta (id integer unique default 0, db_inode integer);
    insert into meta (db_inode) values (0);
    create table stats (inode integer primary key, stat blob);
    create table paths (path blob primary key, inode integer);";

fn user_version(path: &std::path::Path) -> i64 {
    let conn = Connection::open(path).expect("open");
    conn.query_row("pragma user_version", [], |r| r.get(0))
        .expect("query")
}

/// A version-0 database migrates on the way in, and opening it again finds
/// nothing to do. The migration is what used to `die()` on any SQLite
/// error.
#[test]
fn migration_runs_and_is_not_repeated() {
    let _serial = serial();
    let mut dir = std::env::temp_dir();
    dir.push(format!("fakedb-v0-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temp directory");
    let path = dir.join("v0.db");
    make_db(&path, SCHEMA_V0);

    drop(open_db(&path).expect("a v0 database migrates and opens"));
    assert_eq!(user_version(&path), 3);

    drop(open_db(&path).expect("the second open finds nothing to do"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A migration that cannot run rolls back rather than leaving the schema
/// half changed.
///
/// **The scenario matters, and `tests/unit/fakedb_test.c`'s did not.** It
/// put a stray `paths_new` in the way, which is the *first* statement of
/// the version-2 migration -- so that migration failed before it had
/// changed anything, and the assertions passed with the `begin` taken out
/// of `crates/fs/fakefs`'s `migrate` entirely. Backing the transaction out
/// and watching the test still pass is what found it.
///
/// A **trigger** named `delete_path`, on `stats`, is the shape that fails
/// *late*. It survives `drop table paths` -- which is what takes the
/// index and any trigger on `paths` with it -- and collides with the
/// `create trigger delete_path` at the end of version 2, after the drop,
/// the rename and the index. (A *table* by that name does not: sqlite lets
/// a table and a trigger share a name, which is the first thing this test
/// tried.) Without a rollback the
/// database is left with a version-2 `paths` and `user_version` still 0, so
/// the next open re-runs version 0's `create index inode_to_path` against
/// an index that is already there and fails **for ever**.
#[test]
fn failed_migration_rolls_back() {
    let _serial = serial();
    let mut dir = std::env::temp_dir();
    dir.push(format!("fakedb-v0blocked-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temp directory");
    let path = dir.join("v0-blocked.db");
    make_db(&path, SCHEMA_V0);
    {
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "create trigger delete_path after delete on stats \
             begin delete from stats where inode = old.inode; end;",
        )
        .expect("block it");
    }

    // Fails the mount instead of aborting the process.
    assert!(open_db(&path).is_err());
    // And left the version where it was, so nothing thinks it ran.
    assert_eq!(user_version(&path), 0);

    // The schema is the one it started with. `paths` gains a
    // `references stats(inode)` in version 2, so its stored SQL is what
    // says whether that step survived.
    let conn = Connection::open(&path).expect("open");
    let sql: String = conn
        .query_row(
            "select sql from sqlite_master where type='table' and name='paths'",
            [],
            |r| r.get(0),
        )
        .expect("paths still exists");
    assert!(
        !sql.contains("references"),
        "version 2 was left half applied: {sql}"
    );
    assert!(
        conn.query_row(
            "select count(*) from sqlite_master where name='inode_to_path'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .expect("query")
            == 0,
        "version 1's index was left behind, so the next open re-creates it and fails"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
/// Making a fakefs where one already is fails, rather than writing a
/// second schema over the first.
///
/// `crates/fs/fake`'s `fake_db_create` is a one-line wrapper over this and
/// is what `crates/tools/fakefsify` and the CLI's `/dev` setup call.
#[test]
fn creating_a_fakefs_over_one_that_exists_fails() {
    let _serial = serial();
    let base = std::env::temp_dir().join(format!("fakedb-create-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("a temp directory");

    let create = |name: &str| {
        let dir = base.join(name);
        let c = std::ffi::CString::new(dir.to_str().expect("utf8")).expect("no NUL");
        super::abi::create_at(&c)
    };

    assert_eq!(create("reused"), Ok(()));
    let again = create("reused");
    assert!(
        matches!(again, Err(e) if e < 0),
        "creating over an existing fakefs answered {again:?}"
    );

    // The control: a directory nothing has used works, so the failure above
    // is the collision rather than this being broken.
    assert_eq!(create("fresh"), Ok(()));
    let _ = std::fs::remove_dir_all(&base);
}

/// `RENAME_EXCHANGE`'s rows: each subtree under the other's name, inodes
/// unchanged, nothing left at the temporary prefix.
#[test]
fn an_exchange_swaps_two_subtrees() {
    let _serial = serial();
    let t = TempDb::new("exchange");
    let db = t.open();
    let mut tx = db.write();
    tx.path_create(b"/a", &stat(0o40755));
    tx.path_create(b"/a/x", &stat(0o100644));
    tx.path_create(b"/b", &stat(0o100600));
    assert!(tx.commit());
    let (a, ax, b) = (db.lookup_path(b"/a").unwrap(), db.lookup_path(b"/a/x").unwrap(), db.lookup_path(b"/b").unwrap());

    let mut tx = db.write();
    assert!(tx.exchange(b"/a", b"/b"));
    assert!(tx.commit());
    assert_eq!(db.lookup_path(b"/b"), Some(a), "the directory is at the other name");
    assert_eq!(db.lookup_path(b"/b/x"), Some(ax), "with what was under it");
    assert_eq!(db.lookup_path(b"/a"), Some(b), "and the file at its name");
    assert!(db.lookup_path(b"/a/x").is_none());
    assert!(db.lookup_path(b"\0exchange").is_none(), "nothing was left aside");
}

#[test]
fn under_is_on_a_component_boundary() {
    assert!(crate::is_under(b"/a", b"/a"));
    assert!(crate::is_under(b"/a", b"/a/b"));
    assert!(!crate::is_under(b"/a", b"/ab"));
    assert!(crate::is_under(b"", b"/anything"));
    assert!(!crate::is_under(b"/a/b", b"/a"));
}
