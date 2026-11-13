//! Register files created by native offloads in a fakefs database.

use super::paths::{guest_cwd, with_root_fakefs};
use super::*;

// ---------------------------------------------------------------------------
// Registering what a native run created
// ---------------------------------------------------------------------------

/// The dylib redirects every path transparently, so this kernel does not know
/// which files a native run created. What it can do is look: any regular file
/// in a directory the command mentioned, with no row in `meta.db`, is one.
fn register_file_if_new(db: &fakedb::Db, guest_path: &[u8], host_path: &Path) {
    let Ok(meta) = std::fs::metadata(host_path) else {
        return;
    };
    if !meta.is_file() {
        return;
    }

    // `fakedb::Db`'s own API, not its C ABI shims. This went through
    // `fakedb_write`/`fakedb_path_inode`/`fakedb_path_create`/`fakedb_commit`
    // until 2026-09-16 -- a `*mut Tx<'static>` from a `Box::into_raw`, a
    // `CString` per call and a `transmute` away of the transaction's lifetime,
    // for a Rust function three crates over. `Tx<'_>` borrows the database and
    // rolls back if it is dropped without a decision, so the early return
    // below needs no `commit` to avoid leaving the connection in one.
    let mut tx = db.write();
    if tx.path_inode(guest_path) != 0 {
        tx.commit();
        return;
    }

    use std::os::unix::fs::PermissionsExt;
    const S_IFREG: u32 = 0o100000;
    // `fakedb::IulStat`, not this crate's bindgen `iul_stat`: the disk
    // format has one owner, and its comment says so -- "sixteen bytes,
    // four little-endian u32s, in this order. Every fakefs on disk has
    // this and nothing may change it."
    // A native offload runs on a guest thread, which has a task.
    let (euid, egid) = taskview::with_current_creds(|c| (c.euid(), c.egid())).unwrap_or((0, 0));
    let stat = fakedb::IulStat {
        mode: S_IFREG | (meta.permissions().mode() & 0o777),
        uid: euid,
        gid: egid,
        rdev: 0,
    };
    tx.path_create(guest_path, &stat);
    if !tx.commit() {
        printk(&format!(
            "native_offload: could not register {} in fakefs",
            String::from_utf8_lossy(guest_path)
        ));
        return;
    }
    printk(&format!(
        "native_offload: registered {} in fakefs",
        String::from_utf8_lossy(guest_path)
    ));
}

/// One directory, not recursive.
fn scan_dir_for_new_files(db: &fakedb::Db, guest_dir: &[u8]) {
    let Some(host_dir) = host_path_for_guest(guest_dir) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(&host_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.as_bytes();
        if name.first() == Some(&b'.') {
            continue;
        }
        // A symlink or a directory is not a file this run produced. The C
        // tested d_type and let DT_UNKNOWN through, which register_file_if_new
        // then rejected with a stat; this asks the same question once.
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(true) {
            continue;
        }
        let mut guest_path = guest_dir.to_vec();
        if guest_path.last() != Some(&b'/') {
            guest_path.push(b'/');
        }
        guest_path.extend_from_slice(name);
        register_file_if_new(db, &guest_path, &host_dir.join(entry.file_name()));
    }
}

/// Every directory the command named, plus the working directory.
///
/// Native processes commonly write to the cwd through a relative name — yt-dlp
/// calls ffmpeg with one — so it is always scanned.
pub(super) fn register_new_files(argv: &[Vec<u8>]) {
    // Only when the guest's root is a fakefs: on realfs the host files *are*
    // the guest's and there is no database to put a row in.
    //
    // All of it inside the closure, which is what holds the root mount: the
    // scans below are `read_dir`s and transactions and used to run with the
    // reference already released. See `with_root_fakefs`.
    with_root_fakefs(|db| register_into(db, argv));
}

fn register_into(db: &fakedb::Db, argv: &[Vec<u8>]) {
    let cwd = guest_cwd();
    if let Some(ref cwd) = cwd {
        scan_dir_for_new_files(db, cwd);
    }

    // From 1: argv[0] is the program, not a file it was asked about.
    for arg in argv.iter().skip(1) {
        let looks_like_path = arg.starts_with(b"/") || arg.starts_with(b"./");
        if !looks_like_path || contains(arg, b"://") {
            continue;
        }
        // Both as a file, and as a directory to scan for pattern-generated
        // siblings.
        if let Some(host) = host_path_for_guest(arg) {
            register_file_if_new(db, arg, &host);
        }
        let Some(slash) = arg.iter().rposition(|&b| b == b'/') else {
            continue;
        };
        if slash == 0 {
            continue;
        }
        let parent = &arg[..slash];
        if cwd.as_deref() != Some(parent) {
            scan_dir_for_new_files(db, parent);
        }
    }
}

pub(super) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
