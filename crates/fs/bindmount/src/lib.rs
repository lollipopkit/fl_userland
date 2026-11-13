//! Where a guest path goes when it is not in the fakefs.
//!
//! A bind mount grafts a host directory into the guest tree: `/var/minis` is
//! really `~/Library/…/minis`, and every `open`, `stat` and `unlink` under it
//! has to be rewritten on the way in. The reverse direction exists too, for a
//! descriptor whose host path has to be reported back to the guest.
//!
//! The lexical part — normalising a path and deciding whether one is under
//! another — is `crates/fs/bindpath`, where the properties are tested: `..`
//! never walks above the root, normalising twice changes nothing, a prefix
//! matches only at a component boundary, and `/` contains everything. This
//! crate is the *table*: which mounts there are, which one a path belongs to,
//! and what that answers about writing to it.
//!
//! # One question, one lookup
//!
//! Everything here asks "which mount does this path belong to", and the answer
//! is the longest prefix. Nested mounts are the whole reason: with `/mnt`
//! registered before `/mnt/sub`, matching by table order routed everything
//! under the nested mount through the outer one and the nested registration did
//! nothing at all.
//!
//! The read-only rule still had that defect after the general one was fixed,
//! because it asked a *different* question: it looked for the longest
//! **read-only** match instead of asking whether the longest match is
//! read-only. A writable mount nested inside a read-only one was therefore
//! read-only — every write under it `EROFS`, with nothing to say why. There is
//! one lookup now and the flag is read off its answer, so the two cannot
//! disagree.
//!
//! # No fixed table
//!
//! The C had 32 slots of two `PATH_MAX` buffers each — 262 kB of static
//! whether or not a mount was ever registered — and a slot reused by a later
//! registration was part of why `fakefs_bind_unmount` needed a second lock.
//! A `Vec<Mount>` keyed by guest path has neither.

use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock};

mod table;

use table::trim_host_path;
pub use table::{Mount, Table};

/// What the C called `MAX_PATH`. A path longer than this cannot be normalised,
/// and truncation is refused rather than absorbed — a path cut short can match
/// a mount prefix the whole path does not.
pub const MAX_PATH: usize = 4096;

use guest_errno::c_int_::{EINVAL, ENAMETOOLONG};

/// The embedder's own translation, which knows about routes that are not in
/// the table: a per-session mapping it resolves itself.
pub type TranslateHook = unsafe extern "C" fn(
    path: *const c_char,
    fs_context: u64,
    out: *mut c_char,
    out_size: usize,
) -> bool;

pub type ReverseHook =
    unsafe extern "C" fn(host: *const c_char, out: *mut c_char, out_size: usize) -> bool;

// ---------------------------------------------------------------------------
// The one table, and the hooks beside it.
//
// The table is written by the embedder — a session switch, a settings toggle —
// while guest threads translate paths through it on every open, stat and
// unlink. Nothing synchronised the two before `g_bind_lock`: a lookup could
// read a slot with its guest path already replaced and its host path not.

static TABLE: Mutex<Option<Table>> = Mutex::new(None);

/// How many mounts the table holds, readable without taking its lock.
///
/// Every path operation asks whether the path is under a bind mount, and the
/// answer is almost always no: a fakefs with none registered is the common
/// case, and one with a few is still "no" for every path outside them. Asking
/// used to mean `bindpath::normalize` — which allocates a `String` and walks
/// the path — and then the table's mutex and a scan, and `fakefs_stat` asked
/// twice per call. Reading this first turns the common answer into one atomic
/// load.
///
/// Kept in step by `with_table`, which stores the length after every access:
/// the closure takes `&mut Table`, so any call may have changed it, and one
/// relaxed store is cheaper than working out which ones do.
static MOUNT_COUNT: AtomicUsize = AtomicUsize::new(0);

/// True when the table is empty, so a lookup cannot match.
///
/// Acquire, paired with the release store in `with_table`: a thread that sees a
/// non-zero count also sees the mount that made it non-zero.
fn table_is_empty() -> bool {
    MOUNT_COUNT.load(Ordering::Acquire) == 0
}
static TRANSLATE_HOOK: RwLock<Option<TranslateHook>> = RwLock::new(None);
static REVERSE_HOOK: RwLock<Option<ReverseHook>> = RwLock::new(None);
static TRANSLATE_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static REVERSE_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

fn with_table<T>(f: impl FnOnce(&mut Table) -> T) -> T {
    let mut guard: MutexGuard<'_, Option<Table>> = TABLE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let table = guard.get_or_insert_with(Table::default);
    let out = f(table);
    // After the closure, because it takes `&mut` and may have registered or
    // removed one. Release, so a thread that reads a non-zero count also sees
    // the mount behind it.
    MOUNT_COUNT.store(table.len(), Ordering::Release);
    out
}


/// `value` as a C string of at most `limit` bytes with its NUL, or `None`:
/// refusing rather than truncating, because a path cut short can name
/// something the whole path does not.
fn fitted(value: &str, limit: usize) -> Option<CString> {
    if value.len() + 1 > limit {
        return None;
    }
    CString::new(value).ok()
}

/// Ask a C hook to write into a `limit`-byte buffer, and read back what it
/// wrote. The buffer is the hook's contract; nothing past this sees it.
fn from_hook(limit: usize, call: impl FnOnce(*mut c_char, usize) -> bool) -> Option<CString> {
    let mut out = vec![0u8; limit];
    if !call(out.as_mut_ptr().cast(), out.len()) {
        return None;
    }
    CStr::from_bytes_until_nul(&out).ok().map(CStr::to_owned)
}

pub fn bindmount_set_translate_hook(hook: Option<TranslateHook>) {
    let installed = hook.is_some();
    *TRANSLATE_HOOK.write().unwrap_or_else(|e| e.into_inner()) = hook;
    TRANSLATE_HOOK_INSTALLED.store(installed, Ordering::Release);
}

pub fn bindmount_set_reverse_hook(hook: Option<ReverseHook>) {
    let installed = hook.is_some();
    *REVERSE_HOOK.write().unwrap_or_else(|e| e.into_inner()) = hook;
    REVERSE_HOOK_INSTALLED.store(installed, Ordering::Release);
}

/// Where the fakefs's `data/` directory is on the host, or `None` to clear.
pub fn bindmount_set_rootfs_data_path(path: Option<&CStr>) {
    let path = path.and_then(|p| p.to_str().ok()).filter(|path| !path.is_empty());
    with_table(|table| table.set_rootfs_data(path));
}

/// Where a guest path goes on the host, of at most `limit` bytes with its NUL,
/// and whether the embedder's hook was what answered.
///
/// The embedder's hook wins over the table, and the flag says when it did: a
/// hook-routed path must not be recorded in `meta.db`, whose `paths` table is
/// keyed by guest path globally while the hook can map one guest path to a
/// different host file per context.
///
/// It took the path as a pointer and wrote into a caller's buffer through two
/// more, with a `bool` out-parameter beside them, until 2026-09-30. The buffer
/// only exists for the hook now, which is C and takes one.
pub fn bindmount_translate(path: &CStr, fs_context: u64, limit: usize) -> Option<(CString, bool)> {
    // The hook is the embedder's own routing and is consulted even with an
    // empty table, so this early-out needs both to be absent.
    let hook_installed = TRANSLATE_HOOK_INSTALLED.load(Ordering::Acquire);
    if !hook_installed && table_is_empty() {
        return None;
    }
    let hook = hook_installed
        .then(|| *TRANSLATE_HOOK.read().unwrap_or_else(|e| e.into_inner()))
        .flatten();
    let normalized = bindpath::normalize(path.to_str().ok()?, MAX_PATH)?;
    if let Some(hook) = hook {
        let as_c = CString::new(normalized.as_str()).ok()?;
        // Not under the table lock: the hook is the embedder's code and may
        // call back in.
        // SAFETY: `as_c` is NUL-terminated and the buffer is `size` bytes,
        // which is the hook's whole contract.
        if let Some(host) = from_hook(limit, |out, size| unsafe { hook(as_c.as_ptr(), fs_context, out, size) }) {
            return Some((host, true));
        }
    }
    let host = with_table(|table| table.translate(&normalized))?;
    Some((fitted(&host, limit)?, false))
}

/// A host path back to the guest path it is reachable at, of at most `limit`
/// bytes with its NUL.
pub fn bindmount_resolve(host: &CStr, limit: usize) -> Option<CString> {
    let host = host.to_str().ok()?;
    if let Some(guest) = with_table(|table| table.resolve(host)).and_then(|g| fitted(&g, limit)) {
        return Some(guest);
    }
    // A table miss falls through to the embedder's own reverse hook, which
    // knows about per-context routes the table does not have.
    if !REVERSE_HOOK_INSTALLED.load(Ordering::Acquire) {
        return None;
    }
    let hook = (*REVERSE_HOOK.read().unwrap_or_else(|e| e.into_inner()))?;
    let as_c = CString::new(host).ok()?;
    // SAFETY: as in `bindmount_translate`.
    from_hook(limit, |out, size| unsafe { hook(as_c.as_ptr(), out, size) })
}

pub fn bindmount_is_under(path: &CStr) -> bool {
    normalized_query(path, Table::is_under_any)
}

/// Whether a write to this path must be refused with `EROFS`.
pub fn bindmount_is_read_only(path: &CStr) -> bool {
    normalized_query(path, Table::is_read_only)
}

/// A `&CStr` since 2026-09-29. It took a `*const c_char`, was a *safe* `fn`,
/// and dereferenced it -- so the `# Safety` on the two `unsafe fn`s above it
/// was the only thing keeping the pointer honest, and nothing stopped a third
/// caller.
fn normalized_query(path: &CStr, f: impl FnOnce(&Table, &str) -> bool) -> bool {
    // Nothing registered, so nothing can match, and normalizing the path to
    // find that out is the whole cost of asking.
    if table_is_empty() {
        return false;
    }
    let Ok(path) = path.to_str() else {
        return false;
    };
    let Some(normalized) = bindpath::normalize(path, MAX_PATH) else {
        return false;
    };
    with_table(|table| f(table, &normalized))
}

/// Register a mount.
///
/// Returns 1 when the host path is new or has changed — the caller then has
/// the symlink and `meta.db` work to do — 0 when the registration already
/// pointed at this host path, or a negative guest errno.
///
/// The guest path is normalised here so the table only ever holds normalised
/// prefixes, which is what every lookup compares against: a route registered
/// as `/mnt/./sub` was matched against `/mnt/sub` and never found.
///
pub fn bindmount_register(path: &CStr, host_path: &CStr, read_only: bool) -> c_int {
    let (Ok(path), Ok(host_path)) = (path.to_str(), host_path.to_str()) else {
        return EINVAL;
    };
    let Some(normalized) = bindpath::normalize(path, MAX_PATH) else {
        return ENAMETOOLONG;
    };
    let host_path = trim_host_path(host_path);
    match with_table(|table| table.insert(normalized, host_path, read_only)) {
        Ok(changed) => changed as c_int,
        Err(e) => e,
    }
}

/// Remove the mount at this guest path. False if there was none.
pub fn bindmount_unregister(path: &CStr) -> bool {
    let Ok(path) = path.to_str() else {
        return false;
    };
    let Some(normalized) = bindpath::normalize(path, MAX_PATH) else {
        return false;
    };
    with_table(|table| table.remove(&normalized)).is_some()
}

/// Every mount forgotten, for a fakefs being mounted or unmounted.
pub fn bindmount_clear() {
    with_table(Table::clear);
}
