//! The `meta.db` connection: opening it, the statements, and the transactions.
//!
//! This replaces `fs/fake-db.c`. What that file was is a hand-rolled statement
//! cache — sixteen `sqlite3_stmt *` fields, sixteen `sqlite3_finalize` calls
//! and a `PREPARE_OR_FAIL` macro — around a connection whose errors were
//! `die()`, plus a mutex held across `begin`/`commit` pairs that nothing in the
//! type system connected to the statements they were meant to protect.
//!
//! Three things change.
//!
//! **A transaction is a value.** `db_begin_write(fs)` and then
//! `path_create(fs, ...)` were two calls with nothing relating them: the
//! statement functions took the same `fs` whether or not a transaction was
//! open, and whether or not the mutex the transaction takes was held. Here
//! every statement is a method on [`Tx`], which exists only between a `begin`
//! and its `commit` and holds the lock for exactly that long. A statement
//! outside its transaction stops being a thing anyone can write.
//!
//! **An error is a value too.** `db_check_error` called `die()` for anything
//! that was not lock contention, so a `meta.db` that was corrupt, full, or on a
//! volume iOS had not unlocked yet took the whole application down from inside
//! a guest's `write()`. That was replaced with a flag and a rollback shortly
//! before this migration; here it is a `Result`, and the flag is gone with it.
//!
//! **The statements are `prepare_cached`.** Same reuse, no cache to maintain
//! and no way to add a statement and forget to finalize it.
//!
//! # Where this lock sits
//!
//! `tools/lock-order.py` reads only C, so moving the transaction mutex here
//! took it out of that tool's sight. CLAUDE.md's rule for that is to write the
//! ordering down in the crate instead, which is this.
//!
//! The lock is taken by [`Db::read`] and [`Db::write`] and held until the
//! transaction commits or rolls back. Two orderings involve it:
//!
//! - **`g_bind_change_lock` (fs/fake.c) → this.** `fakefs_bind_mount` holds the
//!   registration lock across `bind_meta_stash`, which opens a write
//!   transaction.
//! - **This → the bind-mount table (`crates/fs/bindmount`).** `fakefs_stat`
//!   opens a read transaction and then translates the path, which takes the
//!   table's lock.
//!
//! The inversion to avoid is therefore taking `g_bind_change_lock`, or the
//! bind-mount table's lock, while a transaction is open. `fakefs_bind_mount`
//! says so where it registers: it deliberately does *not* hold the
//! registration across the database work, because the registration blocks and
//! `fakefs_stat` translates while holding a read transaction.
//!
//! Nothing else is held across a transaction. In particular no `struct fd` or
//! `struct mount` lock is: the VFS operations open one, do their statements and
//! close it within a single function body, which is what making the
//! transaction a value was for.
//!
//! # What could not change
//!
//! The SQL, the schema and the pragmas. `meta.db` is a file on disk that
//! `crates/tools/fakefsify` writes and that gets copied between machines; the
//! tuning pragmas were measured. Both are carried across unchanged and the
//! comments explaining them come with them.

use std::collections::HashMap;
use std::os::fd::BorrowedFd;
use std::os::raw::c_int;
use std::sync::{Mutex, MutexGuard, RwLock};

use logline::printk;
use rusqlite::{Connection, OpenFlags, functions::FunctionFlags, params};

use crate::{IulStat, subtree_range};

#[path = "abi.rs"]
mod abi;
pub use abi::{create_at, open};

/// A guest errno, negative. `crates/util/errno` owns the numbers.
mod guest {
    pub use guest_errno::c_int_::{EINVAL, EIO};
}

pub type InodeT = u64;

type PathCache = RwLock<HashMap<Vec<u8>, Option<(IulStat, InodeT)>>>;

/// How many rows the lookup cache holds before it is emptied.
///
/// A path is its own key, so an entry is the path plus 24 bytes; a few thousand
/// is well under a megabyte. When it fills it is cleared rather than evicted
/// one at a time: the working set of a build or an `npm` run is a directory
/// tree that is walked repeatedly, so the useful entries come straight back,
/// and an eviction policy is a thing to get wrong for no measured gain.
const CACHE_MAX: usize = 4096;

/// The database. C holds a `*mut Db` and the mount owns it.
pub struct Db {
    /// Serialises transactions. SQLite's own mutex made one connection safe to
    /// use from several threads; it did not make a `begin`/`commit` pair
    /// atomic against another thread's, which is what this is for and what the
    /// C allocated an `sqlite3_mutex` to do.
    inner: Mutex<Connection>,
    /// What `paths`/`stats` said about a guest path, including that it said
    /// nothing.
    ///
    /// Resolving a path asks the mount about every component, and on fakefs
    /// each question is a SQLite round trip — measured at 1.5 us, against 0.5
    /// for the host `lstat` the same question costs on realfs. A tree that is
    /// walked repeatedly, which is what a build or an `npm` run does, asks the
    /// same questions over and over.
    ///
    /// **Invalidation is: any transaction ending empties it.** That is
    /// deliberately blunt. A read transaction cannot have changed anything, so
    /// clearing on one is waste — but the read paths do not open a transaction
    /// at all ([`Db::lookup`]), so in practice the rule is "cleared on every
    /// write", and it needs no analysis of which statement touched which row to
    /// be right. The C's path cache was removed for being wrong in three ways,
    /// one of which was that nothing invalidated it; the note in
    /// `crates/fs/path`'s walk says the thing to cache is the stat behind the
    /// permission check, which is this.
    ///
    /// Negative answers are cached too. The walk asks about components that do
    /// not exist — an `open` with `O_CREAT` asks about its own target — and a
    /// miss costs the same round trip as a hit.
    ///
    /// **Lock order: never hold this while waiting for `inner`.** A commit
    /// holds `inner` and then takes this, so a lookup that held this while
    /// taking `inner` would close the cycle. [`Db::lookup_path`] releases each
    /// before taking the next.
    cache: PathCache,
}

/// An open transaction, and the only thing the statements can be reached
/// through.
///
/// Holds the lock for its lifetime. `commit` and `rollback` consume it, so the
/// lock is released exactly once — and a path that returns without doing either
/// **rolls back**, which is the safe half of the answer.
///
/// The comment here used to say such a path "does not compile". It does:
/// dropping a value is always allowed, and dropping this one left the SQLite
/// transaction open on a connection the next caller would take. What makes the
/// sentence true is the `Drop` below.
pub struct Tx<'a> {
    conn: MutexGuard<'a, Connection>,
    /// Emptied when this transaction ends. See [`Db::cache`].
    cache: &'a PathCache,
    /// Whether a statement in this transaction failed. `commit` rolls back
    /// instead when it is set: a transaction that lost one of its statements
    /// must not be committed without it, and half of a rename is worse than no
    /// rename at all.
    failed: bool,
    /// Whether `commit` or `rollback` has decided. `Drop` rolls back when it
    /// has not.
    done: bool,
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        // Nobody decided. Rolling back is the safe half: the alternative is
        // leaving the transaction open on a connection the next caller takes,
        // which turns one lost error path into a database that refuses every
        // later write.
        //
        // `fs/fake.c` never reaches this today -- every one of its paths calls
        // one or the other, which is fourteen `return`s in `fakefs_setattr`
        // alone -- and it cannot reach it even in principle, because a C caller
        // that drops the handle leaks the `Box` and this never runs. What it
        // covers is the crate's own code and every Rust caller the migration
        // adds, which is the direction that half of `fs/fake.c` is going.
        log("fakefs db: a transaction ended without commit or rollback");
        let _ = self.conn.execute_batch("rollback");
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
}

impl Db {
    /// Open `path`, migrate it, rebuild it if its inode has changed, and make
    /// it ready for use.
    pub fn open(path: &str, root: BorrowedFd<'_>) -> Result<Db, i32> {
        let conn =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).map_err(|e| {
                log(&format!("fakefs db: opening {path}: {e}"));
                guest::EINVAL
            })?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))
            .map_err(|_| guest::EIO)?;
        register_change_prefix(&conn)?;

        // Correctness, not tuning: the subtree statements rely on foreign keys,
        // and WAL is what lets a reader and a writer coexist.
        exec(&conn, "pragma journal_mode=wal")?;
        exec(&conn, "pragma foreign_keys=true")?;

        // Apple-friendly tuning. The fakefs db is read-mostly during normal use
        // (writes happen for chmod / chown / mknod / new files). Signpost data
        // showed 78K db_exec calls totalling 122ms = 8% of `npm --version` user
        // CPU. Four knobs help on macOS:
        //
        //  - mmap_size lets sqlite read pages through mmap instead of read()
        //    syscalls, so the unified buffer cache serves repeats at memcpy
        //    speed.
        //  - cache_size, negative, is KB of in-process page cache. The default
        //    is 2 MB; 64 MB fits the working set.
        //  - synchronous=NORMAL under WAL is durable across process crashes
        //    (as FULL is) but skips an fsync per commit.
        //  - temp_store=MEMORY keeps sort and temp tables off disk.
        //
        // Best-effort: a failure here loses a performance knob and not
        // correctness, so it is logged and the mount goes ahead.
        for pragma in [
            "pragma mmap_size=268435456", // 256 MB
            "pragma cache_size=-65536",   // 64 MB
            "pragma synchronous=NORMAL",
            "pragma temp_store=MEMORY",
        ] {
            if exec(&conn, pragma).is_err() {
                log(&format!(
                    "fakefs db: tuning pragma failed, continuing: {pragma}"
                ));
            }
        }

        // The migration and the rebuild are crates/fs/fakefs.
        let err = fakefs::fakefs_migrate(&conn);
        if err < 0 {
            return Err(err);
        }

        // After a fakefs is compressed, transmitted and uncompressed, its inode
        // numbers are different. The inode of the database file itself is
        // stored inside the database; if it does not match, everything else in
        // there describes files that have moved.
        let db_inode = match std::fs::metadata(path) {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                m.ino()
            }
            Err(e) => {
                // This used to be ERRNO_DIE. A meta.db that went away
                // underneath us -- the container deleted while mounted, an iOS
                // data-protection unlock that has not happened yet -- is a
                // mount that cannot be made, not a reason to abort the process.
                log(&format!("fakefs db: stat {path}: {e}"));
                return Err(guest::EIO);
            }
        };

        let stored: Option<i64> = conn
            .query_row("select db_inode from meta", [], |r| r.get(0))
            .ok();
        if let Some(stored) = stored
            && stored as u64 != db_inode
        {
            let err = fakefs::fakefs_rebuild(&conn, root);
            if err < 0 {
                return Err(err);
            }
        }
        conn.execute("update meta set db_inode = ?", params![db_inode as i64])
            .map_err(|e| {
                log(&format!("fakefs db: recording the database inode: {e}"));
                guest::EIO
            })?;

        exec(
            &conn,
            "delete from stats where not exists (select 1 from paths where inode = stats.inode)",
        )?;

        prewarm(&conn)?;

        Ok(Db {
            inner: Mutex::new(conn),
            cache: RwLock::new(HashMap::new()),
        })
    }

    fn begin(&self, sql: &str) -> Tx<'_> {
        let conn = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut tx = Tx {
            conn,
            cache: &self.cache,
            failed: false,
            done: false,
        };
        tx.run(sql, params![]);
        tx
    }

    /// A read transaction: `begin deferred`.
    pub fn read(&self) -> Tx<'_> {
        self.begin("begin deferred")
    }

    /// A write transaction: `begin immediate`, which takes the write lock now
    /// rather than discovering at the first write that another process has it.
    pub fn write(&self) -> Tx<'_> {
        self.begin("begin immediate")
    }

    /// One statement, with no transaction around it.
    ///
    /// A read that is a single `select` does not need one: SQLite gives every
    /// statement an implicit transaction already, and an explicit `begin
    /// deferred` / `commit` pair around one `select` is two more statements to
    /// execute for the same answer. `fakefs_stat` is the most frequent
    /// operation a fakefs sees — an `npm` run makes millions — and it was
    /// paying three statement executions per lookup.
    ///
    /// The lock is still taken, for as long as the one statement runs. What
    /// goes away is the pair around it.
    fn lookup<T>(&self, f: impl FnOnce(&Connection) -> Option<T>) -> Option<T> {
        let conn = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f(&conn)
    }

    /// [`Tx::path_stat`] without a transaction, answered from [`Db::cache`]
    /// when it can be.
    ///
    /// The three locks are taken one at a time and never nested: the cache
    /// read, then the connection, then the cache write. Holding the cache
    /// while waiting for the connection would close a cycle against
    /// [`Tx::commit`], which holds the connection and then takes the cache.
    pub fn lookup_path(&self, path: &[u8]) -> Option<(IulStat, InodeT)> {
        if let Ok(cache) = self.cache.read()
            && let Some(hit) = cache.get(path)
        {
            return *hit;
        }
        let answer = {
            let conn = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            read_path_stat(&conn, path)
        };
        if let Ok(mut cache) = self.cache.write() {
            if cache.len() >= CACHE_MAX {
                cache.clear();
            }
            cache.insert(path.to_vec(), answer);
        }
        answer
    }

    /// [`Tx::path_inode`] without a transaction.
    ///
    /// Answered from the same cache: the inode is part of what a path lookup
    /// returns, so asking for it alone would be a second round trip for a
    /// subset of an answer already held.
    pub fn lookup_inode(&self, path: &[u8]) -> InodeT {
        self.lookup_path(path).map(|(_, inode)| inode).unwrap_or(0)
    }

    /// [`Tx::inode_stat`] without a transaction. See [`Db::lookup`].
    ///
    /// Not cached: it is keyed by inode rather than path, and its one caller
    /// (`fakefs_fstat`) is once per `fstat` rather than once per path
    /// component.
    pub fn lookup_stat(&self, inode: InodeT) -> Option<IulStat> {
        self.lookup(|conn| read_inode_stat(conn, inode))
    }

    /// How many rows the cache holds. For tests and for /proc/iul/objects.
    pub fn cache_len(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Every path that names `inode`.
    ///
    /// Its own transaction, and it *ends* before the caller does anything with
    /// the answer. The C read a path out of a live statement and then called
    /// `realfs.open` on it with the database mutex still held, so a host open
    /// -- which blocks -- stopped every other fakefs operation in the process.
    pub fn paths_for_inode(&self, inode: InodeT) -> Vec<Vec<u8>> {
        let tx = self.read();
        let out = {
            let Ok(mut stmt) = tx.conn.prepare_cached(sql::PATHS_FOR_INODE) else {
                return Vec::new();
            };
            let rows = stmt.query_map(params![inode as i64], |r| r.get::<_, Vec<u8>>(0));
            match rows {
                Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
                Err(_) => Vec::new(),
            }
        };
        tx.commit();
        out
    }

    /// Drop the `stats` row for `inode` if no path names it any more.
    pub fn inode_orphaned(&self, inode: InodeT) {
        let mut tx = self.write();
        tx.run(sql::ORPHANED, params![inode as i64]);
        tx.commit();
    }
}

/// The three read statements, shared by [`Tx`] and [`Db::lookup`] so there is
/// one copy of each and the same SQL constant behind both.
fn read_path_inode(conn: &Connection, path: &[u8]) -> Option<InodeT> {
    conn.prepare_cached(sql::PATH_INODE)
        .and_then(|mut s| s.query_row(params![path], |r| r.get::<_, i64>(0)))
        .ok()
        .map(|i| i as InodeT)
}

fn read_path_stat(conn: &Connection, path: &[u8]) -> Option<(IulStat, InodeT)> {
    let mut stmt = conn.prepare_cached(sql::PATH_STAT).ok()?;
    let row: Option<(i64, Option<Vec<u8>>)> = stmt
        .query_row(params![path], |r| Ok((r.get(0)?, r.get(1)?)))
        .ok();
    let (inode, blob) = row?;
    // Decoded, not cast. The blob is whatever is in the file; a NULL column
    // made this a null dereference in C and a short one read past the end of
    // sqlite's buffer into a guest's st_mode.
    let stat = IulStat::decode(blob.as_deref().unwrap_or(&[]))?;
    Some((stat, inode as InodeT))
}

fn read_inode_stat(conn: &Connection, inode: InodeT) -> Option<IulStat> {
    let mut stmt = conn.prepare_cached(sql::INODE_STAT).ok()?;
    let blob: Option<Vec<u8>> = stmt.query_row(params![inode as i64], |r| r.get(0)).ok()?;
    IulStat::decode(blob.as_deref().unwrap_or(&[]))
}

impl Tx<'_> {
    /// Run a statement, recording a failure on the transaction.
    fn run(&mut self, sql: &str, args: &[&dyn rusqlite::ToSql]) -> bool {
        match self
            .conn
            .prepare_cached(sql)
            .and_then(|mut s| s.execute(args))
        {
            Ok(_) => true,
            Err(e) => {
                log(&format!("fakefs db: {sql}: {e}"));
                self.failed = true;
                false
            }
        }
    }

    /// Commit, unless a statement failed — in which case the whole transaction
    /// goes back. Returns whether it committed.
    pub fn commit(mut self) -> bool {
        self.done = true;
        // Whatever this transaction did, the cache may describe rows it
        // changed. Emptied here rather than reasoned about statement by
        // statement: see Db::cache.
        //
        // Taken while `conn` is held, which is the only order this pair is
        // ever taken in -- Db::lookup_path releases each before the next.
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
        if self.failed {
            log("fakefs db: rolling back a transaction that lost a statement");
            let _ = self.conn.execute_batch("rollback");
            return false;
        }
        match self.conn.execute_batch("commit") {
            Ok(()) => true,
            Err(e) => {
                log(&format!("fakefs db: commit: {e}"));
                let _ = self.conn.execute_batch("rollback");
                false
            }
        }
    }

    pub fn rollback(mut self) {
        self.done = true;
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
        let _ = self.conn.execute_batch("rollback");
    }

    /// The inode `path` names, or 0.
    pub fn path_inode(&self, path: &[u8]) -> InodeT {
        read_path_inode(&self.conn, path).unwrap_or(0)
    }

    /// The stat and the inode `path` names.
    pub fn path_stat(&self, path: &[u8]) -> Option<(IulStat, InodeT)> {
        read_path_stat(&self.conn, path)
    }

    /// Create `path` with `stat`. The new inode, or 0.
    ///
    /// Two statements, and the second is `insert or replace into paths values
    /// (?, last_insert_rowid())`. `last_insert_rowid()` after an insert that
    /// did *not* happen is the previous one's, so a failed first statement used
    /// to be followed by a path row pointing at another file's inode — and a
    /// fakefs inode names a host file under `data/`, so two guest paths then
    /// shared one file's contents permanently. The `?` is what stops it.
    pub fn path_create(&mut self, path: &[u8], stat: &IulStat) -> InodeT {
        if !self.run(sql::CREATE_STAT, params![stat.encode().as_slice()]) {
            return 0;
        }
        let inode = self.conn.last_insert_rowid() as InodeT;
        if !self.run(sql::SET_PATH, params![path, inode as i64]) {
            return 0;
        }
        inode
    }

    /// An inode with no path: an `O_TMPFILE` file's, which `link_inode` may
    /// name and `Db::inode_orphaned` removes if nothing does.
    pub fn inode_create(&mut self, stat: &IulStat) -> InodeT {
        if !self.run(sql::CREATE_STAT, params![stat.encode().as_slice()]) {
            return 0;
        }
        self.conn.last_insert_rowid() as InodeT
    }

    /// Make `path` name `inode`.
    pub fn link_inode(&mut self, path: &[u8], inode: InodeT) -> bool {
        self.run(sql::SET_PATH, params![path, inode as i64])
    }

    /// The stat for `inode`.
    pub fn inode_stat(&self, inode: InodeT) -> Option<IulStat> {
        read_inode_stat(&self.conn, inode)
    }

    pub fn inode_write_stat(&mut self, inode: InodeT, stat: &IulStat) -> bool {
        self.run(
            sql::WRITE_STAT,
            params![stat.encode().as_slice(), inode as i64],
        )
    }

    /// Make `dst` name what `src` names.
    ///
    /// False if `src` has no row. That was a `die()`: a `meta.db` whose `paths`
    /// table disagrees with what is under `data/` — a partial restore — took
    /// the application down from inside the guest's `link(2)`, where the caller
    /// had a host link to undo and an errno to return and could do neither.
    pub fn link(&mut self, src: &[u8], dst: &[u8]) -> bool {
        let inode = self.path_inode(src);
        if inode == 0 {
            log("fakefs db: link: the source has no row");
            return false;
        }
        self.run(sql::SET_PATH, params![dst, inode as i64])
    }

    /// Remove `path`'s row. The inode it named, or 0 if it had none.
    pub fn unlink(&mut self, path: &[u8]) -> InodeT {
        let inode = self.path_inode(path);
        if inode == 0 {
            return 0; // already gone, or never tracked
        }
        self.run(sql::UNLINK, params![path]);
        inode
    }

    /// Move `src` and everything under it to `dst`.
    ///
    /// One statement, because the children of `p` are exactly the paths in the
    /// half-open blob range `[p + "/", p + "0")` — see [`subtree_range`].
    pub fn rename(&mut self, src: &[u8], dst: &[u8]) -> bool {
        let (low, high) = subtree_range(src);
        self.run(sql::RENAME, params![src.len() as i64, dst, low, high, src])
    }

    /// Swap `a` and everything under it with `b` and everything under it:
    /// `RENAME_EXCHANGE`.
    ///
    /// Three prefix substitutions through a name no guest path can have -- a
    /// guest path is the empty root or begins with `/`, and none holds a NUL --
    /// inside the caller's transaction, so the swap is all or nothing. Neither
    /// may be under the other: the substitution would carry one inside the
    /// other's rows, and Linux refuses that exchange with EINVAL anyway, which
    /// is the caller's to answer before this is reached.
    pub fn exchange(&mut self, a: &[u8], b: &[u8]) -> bool {
        const ASIDE: &[u8] = b"\0exchange";
        debug_assert!(!crate::is_under(a, b) && !crate::is_under(b, a));
        self.rename(a, ASIDE) && self.rename(b, a) && self.rename(ASIDE, b)
    }

    /// Delete `path`'s row and every row below it.
    ///
    /// Used when a bind mount's host target changes or goes away, where the
    /// rows describe files that are no longer there and would otherwise be
    /// reused for entirely different ones.
    pub fn delete_tree(&mut self, path: &[u8]) -> bool {
        let (low, high) = subtree_range(path);
        self.run(sql::DELETE_TREE, params![low, high, path])
    }
}

/// Prepare every statement once, at open.
///
/// `prepare_cached` is lazy, and that would be a behaviour change rather than
/// an implementation detail: the C prepared all sixteen at init, so a `meta.db`
/// with no `paths` table **failed the mount**. Lazily, it would mount and then
/// fail every operation, which is the same database presented as a working
/// filesystem.
///
/// It also keeps the first operation on a fresh mount from paying for sixteen
/// prepares, which is what the cache was for.
fn prewarm(conn: &Connection) -> Result<(), i32> {
    for sql in STATEMENTS {
        conn.prepare_cached(sql).map_err(|e| {
            log(&format!("fakefs db: preparing `{sql}`: {e}"));
            guest::EIO
        })?;
    }
    Ok(())
}

/// Every statement the mount runs.
///
/// Constants rather than literals at the use sites, because the statement cache
/// is keyed by the SQL *text*: a method whose string differed from
/// [`STATEMENTS`]' by one space would prepare a second copy, and the schema
/// check at open would then not cover the statement the method actually runs. A
/// test can only notice that after the fact; a constant makes it not happen.
mod sql {
    pub const PATH_INODE: &str = "select inode from paths where path = ?";
    pub const PATH_STAT: &str = "select inode, stat from stats natural join paths where path = ?";
    pub const CREATE_STAT: &str = "insert into stats (stat) values (?)";
    pub const SET_PATH: &str = "insert or replace into paths (path, inode) values (?, ?)";
    pub const INODE_STAT: &str = "select stat from stats where inode = ?";
    pub const WRITE_STAT: &str = "update stats set stat = ? where inode = ?";
    pub const UNLINK: &str = "delete from paths where path = ?";
    pub const DELETE_TREE: &str = "delete from paths where (path >= ? and path < ?) or path = ?";
    pub const RENAME: &str = "update or replace paths set path = change_prefix(path, ?, ?) \
                              where (path >= ? and path < ?) or path = ?";
    pub const PATHS_FOR_INODE: &str = "select path from paths where inode = ?";
    pub const ORPHANED: &str = "delete from stats where inode = ? and not exists \
                                (select 1 from paths where inode = stats.inode)";
}

const STATEMENTS: &[&str] = &[
    sql::PATH_INODE,
    sql::PATH_STAT,
    sql::CREATE_STAT,
    sql::SET_PATH,
    sql::INODE_STAT,
    sql::WRITE_STAT,
    sql::UNLINK,
    sql::DELETE_TREE,
    sql::RENAME,
    sql::PATHS_FOR_INODE,
    sql::ORPHANED,
];

fn exec(conn: &Connection, sql: &str) -> Result<(), i32> {
    conn.execute_batch(sql).map_err(|e| {
        log(&format!("fakefs db: {sql}: {e}"));
        guest::EIO
    })
}

/// `change_prefix(path, start, replacement)`, for the subtree rename.
///
/// The rewrite is [`crate::change_prefix`]. In C this was a wrapper whose
/// arithmetic was `in_size - start + replacement_size` in `size_t`, so a start
/// past the end wrapped to an enormous allocation, and `sqlite3_malloc`'s
/// result went into `memcpy` with no null check.
fn register_change_prefix(conn: &Connection) -> Result<(), i32> {
    conn.create_scalar_function(
        "change_prefix",
        3,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let path: Vec<u8> = ctx.get(0)?;
            let start: i64 = ctx.get(1)?;
            let replacement: Vec<u8> = ctx.get(2)?;
            if start < 0 || start as usize > path.len() {
                return Err(rusqlite::Error::UserFunctionError(
                    "change_prefix: start is outside the path".into(),
                ));
            }
            crate::change_prefix(&path, start as usize, &replacement).ok_or_else(|| {
                rusqlite::Error::UserFunctionError("change_prefix: bad arguments".into())
            })
        },
    )
    .map_err(|e| {
        log(&format!("fakefs db: registering change_prefix: {e}"));
        guest::EIO
    })
}

fn log(message: &str) {
    printk(message);
}

#[cfg(test)]
#[path = "db_tests.rs"]
mod tests;
