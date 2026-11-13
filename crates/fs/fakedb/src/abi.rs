//! Opening and creating a `meta.db`.
//!
//! # There is no raw-pointer boundary here any more
//!
//! This file was one, and said so at length: `Db` and `Tx` crossed it as raw
//! pointers, `fakedb_read` and `fakedb_write` each carried a
//! `transmute::<Tx<'_>, Tx<'static>>`, and the argument for keeping them —
//! surveyed 2026-09-12 — was
//!
//! > The boundary is still real: the `Db` lives in `(*mount).state.fakefs`, a
//! > `*mut c_void` in `struct mount`'s union, so nothing holds a `&Db` for a
//! > `Tx` to borrow from.
//!
//! **That stopped being true on 2026-09-16**, when `crates/fs/fake` grew
//! `FakefsMount::db() -> Option<&fakedb::Db>` — a borrow tied to a held mount
//! reference — and `crates/kernel/offloadexec`, the last caller of the six `Tx`
//! functions, started using `Db::write` directly. The six then had no caller
//! but **one test in this crate**, which is `CLAUDE.md`'s "`pub` is not a
//! reachability signal": nothing warns about a `pub fn` in a library crate, so
//! six exported functions with two `transmute`s between function-shaped
//! lifetimes sat there reading as the interface.
//!
//! The reason written above them was not wrong when it was written. It is the
//! same shape as the `current` measurement `CLAUDE.md` records: **a blocker
//! that was true about a tree that no longer exists**, and re-reading it is
//! what finds the next one.
//!
//! What is left takes borrows and answers `Result`. The one raw pointer the
//! database still crosses is the `Box::into_raw` into the mount's union, and
//! that is `crates/fs/fake`'s — one place, at the field that requires it.

use super::*;
use std::ffi::CStr;

/// A guest errno for a `meta.db` that cannot be created.
mod create_err {
    pub use guest_errno::c_int_::{EINVAL, EIO, ENAMETOOLONG};
}

/// The longest path `create_at` will build a `meta.db` under.
///
/// `MAX_PATH`, not the host's `PATH_MAX`: the directory is named by an
/// embedder or by this kernel's own boot path, and both speak in guest-sized
/// paths.
const MAX_DIR: usize = 4096 - "/meta.db".len() - 1;

/// Creates an empty fakefs at `dir`: the directory, its `data/`, and a
/// `meta.db` with the schema and the root row in it.
///
/// **The root is the empty blob**, not `"/"`, and that row is what makes the
/// mount point resolvable at all — without it every path under the mount
/// misses. It is written here rather than by the schema because the schema is
/// shared with `fakefsify`, which fills the tree itself.
///
/// A directory whose name leaves no room for `/meta.db` is refused rather than
/// truncated: `mkdir` at a truncated path *creates* something, at a name
/// nothing will look for again.
pub fn create_at(dir: &CStr) -> Result<(), c_int> {
    let dir_s = dir.to_str().map_err(|_| create_err::EINVAL)?;
    if dir_s.len() > MAX_DIR {
        return Err(create_err::ENAMETOOLONG);
    }
    for path in [dir_s.to_string(), format!("{dir_s}/data")] {
        if let Err(e) = std::fs::create_dir(&path)
            && e.kind() != std::io::ErrorKind::AlreadyExists
        {
            // The host's errno, negated into this kernel's convention. The two
            // numberings agree for the ones `mkdir` answers.
            return Err(-(e.raw_os_error().unwrap_or(-create_err::EIO)));
        }
    }

    let db_path = format!("{dir_s}/meta.db");
    let conn = rusqlite::Connection::open(&db_path).map_err(|_| create_err::EIO)?;
    // The schema has exactly one definition, in `crates/fs/fakeschema`, because
    // a second copy would be a database two tools disagree about. A Rust call
    // since 2026-09-06, where it was `fs/fake-schema.c` through the C ABI.
    // SAFETY: the connection is live for this call.
    let err = unsafe { fakeschema::create(conn.handle()) };
    if err < 0 {
        return Err(err);
    }
    let root = IulStat {
        mode: 0o040755, /* S_IFDIR | 0755 */
        uid: 0,
        gid: 0,
        rdev: 0,
    };
    conn.execute(
        "insert into stats (inode, stat) values (1, ?1)",
        [&root.encode()[..]],
    )
    .map_err(|_| create_err::EIO)?;
    conn.execute("insert into paths (path, inode) values (x'', 1)", [])
        .map_err(|_| create_err::EIO)?;
    Ok(())
}

/// Open `db_path`, owned.
///
/// A `*mut Db` with the errno written through an out-parameter until
/// 2026-09-16 — two ways to say "it failed", of which the caller had to check
/// the first and read the second. The `Box` is what the mount parks in its
/// union, so the one `into_raw` in the tree is at the field that needs it.
pub fn open(db_path: &CStr, root: std::os::fd::BorrowedFd<'_>) -> Result<Box<Db>, c_int> {
    let path = db_path.to_str().map_err(|_| guest::EINVAL)?;
    Db::open(path, root).map(Box::new).inspect_err(|_| {
        log(&format!(
            "fakefs db: {path} could not be opened; the mount fails"
        ));
    })
}
