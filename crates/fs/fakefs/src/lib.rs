//! The parts of fakefs that repair or upgrade a `meta.db`.
//!
//! Both entry points run against the connection `crates/fs/fakedb` opened
//! and still owns, during mount, before the filesystem is usable. Both wrap everything in a transaction and roll back on failure,
//! because a half-applied migration or a half-rebuilt table would present an
//! incomplete filesystem as a complete one.
//!
//! Failure here fails the mount, not the process — see the note in
//! CLAUDE.md's Rust section. That is why [`run`] turns a panic into an error code
//! instead of letting it unwind into the mount.

mod errno;
mod migrate;
mod rebuild;
#[cfg(test)]
mod test_util;

use std::panic::{AssertUnwindSafe, catch_unwind};

use libc::c_int;
use std::os::fd::BorrowedFd;
use logline::printk;
use rusqlite::Connection;

pub use errno::{EIO, ENOMEM};

/// Bring a `meta.db` up to the current schema version.
pub fn fakefs_migrate(conn: &Connection) -> c_int {
    run("migrate", conn, migrate::migrate)
}

/// Rebuild `paths` and `stats` against the inode numbers `data/` actually has.
///
/// Called when `meta.db`'s recorded inode does not match the file it was found
/// in, which means the fakefs was copied or restored and every inode number in
/// it is stale. `root` is the fakefs `data/` directory.
pub fn fakefs_rebuild(conn: &Connection, root: BorrowedFd<'_>) -> c_int {
    run("rebuild", conn, |conn| rebuild::rebuild(conn, root))
}

/// Run the operation, flatten the result to a guest errno, and let nothing
/// unwind past this frame.
///
/// Both took a raw `sqlite3 *` until 2026-09-29, and re-wrapped it with
/// `Connection::from_handle` -- twice on the failure path -- because C called
/// them. The one caller is `crates/fs/fakedb`, which holds the `Connection`
/// itself.
fn run(
    what: &str,
    conn: &Connection,
    op: impl FnOnce(&Connection) -> Result<(), errno::Error>,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| op(conn))) {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            printk(&format!("fakefs {what}: {e}"));
            rollback(conn);
            e.errno()
        }
        Err(_) => {
            // A panic is a bug in this code, but taking the process down loses
            // a mount that the caller is prepared to fail.
            printk(&format!("fakefs {what}: panicked"));
            rollback(conn);
            EIO
        }
    }
}

/// Undo anything half-applied.
///
/// Unconditional, because the failure may have come from before `begin`, where
/// this is a no-op. Errors are ignored for the same reason.
fn rollback(conn: &Connection) {
    let _ = conn.execute_batch("rollback");
}
