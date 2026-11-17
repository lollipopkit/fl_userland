//! Which mounts there are, and which one owns a path.
//!
//! The table, its lock and the ordering invariant, from `fs/mount.c`. What a
//! mount *is* stays there: `struct mount` is allocated by C, its `fs_ops` table
//! is C's, and `crates/fs/fake` reaches into its union. This owns the
//! collection, which is the same split `crates/fs/bindmount` makes for the bind
//! mounts.
//!
//! # The order is the answer
//!
//! A mount owns a path when its point is a prefix of it **ending on a component
//! boundary**, and several mounts can satisfy that: `/dev` is a prefix of
//! `/dev/pts/0`, which belongs to `/dev/pts`. So the list is kept in descending
//! order of point length and the first match wins.
//!
//! That is not a tidiness rule. A thread-local cache that stood here answered
//! with *any* prefix-matching mount, and because `path_normalize` walks a path
//! component by component, the lookup for `/dev/pts/0` was always preceded by
//! one for `/dev` — so it always answered with the wrong filesystem, every
//! `/dev/pts/N` came back `ENOENT`, and no pty slave could be opened.
//!
//! # The refcount is not under the lock
//!
//! `mount_find` takes it, because it walks the list. [`MountRef::retain`] and
//! [`MountRef::drop`] do not: a retain is made by something that already holds
//! a reference, so the struct cannot go away under it, and a release only ever
//! decreases. It matters
//! because the path walk finds and releases a mount **once per component** —
//! two global acquisitions per component per thread is what made resolving a
//! path serialise across threads, with 31 of ~150 profile samples per thread
//! blocked in those two functions.
//!
//! Taking one *away* is the exception and holds the lock throughout, because
//! finding a mount and committing to removing it have to be one step. Read
//! outside it the refcount says nothing: a lookup could pass through
//! `mount_find` after the check saw zero and before the unlink, and come away
//! with a reference to a mount whose umount was already running.


use std::ffi::{CStr, CString, c_int};
use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Mutex};

use taskview::ffi;

/// A `struct mount *`, for the descriptor and inode fields that hold one.
type Mount = *mut ffi::mount;

use guest_errno::c_int_::{EBUSY, EINVAL};

/// The mounts, in descending order of point length. See the module comment.
///
/// **The table owns them** since 2026-10-01: an `Arc` per mount, made by
/// `crates/fs/mount` and handed back to it by [`mounts_take_point`] for the
/// teardown. They were `Box::into_raw` addresses in a `Vec` of a `NonNull`
/// newtype with an `unsafe impl Send`, freed by whoever took one out, and the
/// tests stood fake structs in for them through three `cfg`-swapped accessors.
///
/// An `Arc` and not a `Box`: a `Box` asserts it is the only path to its
/// contents, and every [`MountRef`] and descriptor holds another. The `Arc`'s
/// strong count is always one -- nothing else clones it -- which is what lets
/// the umount take `&mut` with `Arc::get_mut`.
#[derive(Default)]
struct Table {
    mounts: Vec<Arc<ffi::mount>>,
}

/// One mount namespace's table: a part of its `nsproxy::Space`, copied into
/// a namespace made from it ([`taskview::nsproxy::Inherit`]).
pub struct Mounts(Mutex<Table>);

/// Every table there is, weakly, so that halting can unmount every
/// namespace's mounts and not only the halting thread's
/// ([`mounts_take_first_anywhere`]). Pruned of dead entries as tables are
/// made.
static TABLES: Mutex<Vec<std::sync::Weak<Mounts>>> = Mutex::new(Vec::new());

impl Mounts {
    fn registered(table: Table) -> Arc<Mounts> {
        let m = Arc::new(Mounts(Mutex::new(table)));
        let mut all = TABLES.lock().unwrap_or_else(|p| p.into_inner());
        all.retain(|w| w.strong_count() != 0);
        all.push(Arc::downgrade(&m));
        m
    }

    fn with<T>(&self, f: impl FnOnce(&mut Table) -> T) -> T {
        f(&mut self.0.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

pub fn mounts_of(mnt: &taskview::nsproxy::Space) -> Arc<Mounts> {
    mnt.inherited::<Mounts>()
}

pub fn with_mounts_in<T>(mounts: &Mounts, f: impl FnOnce(&[&ffi::mount]) -> T) -> T {
    mounts.with(|t| {
        let ms: Vec<&ffi::mount> = t.mounts.iter().map(Arc::as_ref).collect();
        f(&ms)
    })
}

static PARKED: Mutex<Vec<Arc<ffi::mount>>> = Mutex::new(Vec::new());

impl Drop for Table {
    fn drop(&mut self) {
        let busy_mounts: Vec<_> = self.mounts.drain(..).filter(|m| busy(m)).collect();
        if !busy_mounts.is_empty() {
            PARKED.lock().unwrap_or_else(|p| p.into_inner()).extend(busy_mounts);
        }
    }
}

impl taskview::nsproxy::Inherit for Mounts {
    fn fresh() -> Arc<Mounts> {
        Mounts::registered(Table::default())
    }

    /// Every mount copied: its own id and an idle count, the superblock
    /// shared ([`ffi::mount::copy`]).
    fn inherit(&self) -> Arc<Mounts> {
        let copied = self.with(|t| t.mounts.iter().map(|m| Arc::new(m.copy(next_mount_id()))).collect());
        Mounts::registered(Table { mounts: copied })
    }
}

pub fn sweep_parked() {
    PARKED
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .retain(|m| busy(m));
}

fn current_mounts() -> Arc<Mounts> {
    taskview::with_current_nsproxy(|ns| ns.mnt.inherited::<Mounts>())
}

fn with<T>(f: impl FnOnce(&mut Table) -> T) -> T {
    current_mounts().with(f)
}

fn point_of(mount: &ffi::mount) -> &[u8] {
    mount.point.to_bytes()
}

fn busy(mount: &ffi::mount) -> bool {
    mount.refcount.load(SeqCst) != 0
}

/// Does `point` own `path`? A prefix, ending on a component boundary.
///
/// The boundary is what stops `/jail-old` from being owned by `/jail`: a
/// prefix that ends mid-component names a different directory.
fn owns(point: &[u8], path: &[u8]) -> bool {
    path.starts_with(point) && matches!(path.get(point.len()), None | Some(b'/'))
}

/// A reference to a mount, given back when this is dropped.
///
/// **Not an `Arc`, and that is the whole of what `struct mount`'s count is.**
/// An `Arc` frees at zero; this count's zero is the *resting* state of every
/// mounted filesystem — a `/dev` no path walk is currently inside sits at zero
/// for the life of the guest. What ends a mount is [`mounts_take_point`], which
/// refuses with `EBUSY` while the count is **not** zero and unlinks it when it
/// is. So the count answers "is anybody inside" and not "does anybody own it",
/// and the only thing a handle type can buy here is that the decrement is a
/// scope rather than a line somebody has to remember to write.
///
/// Two sites hand the reference to a field instead of holding it in a scope —
/// `struct fd`'s `mount` and `struct inode_data`'s — and those use
/// [`MountRef::into_raw`] and [`MountRef::from_raw`]. That is an erasure at a
/// boundary with a written contract rather than a second implementation of the
/// count: every `+1` and every `-1` in the tree is one of the functions below.
#[must_use = "dropping this releases the reference; a mount found and not held \
              is a lookup whose answer was thrown away"]
pub struct MountRef(std::ptr::NonNull<ffi::mount>);

impl MountRef {
    /// A reference to a mount whose memory the caller can show is live: the
    /// table lock is held, or the mount is in no table.
    fn of(mount: &ffi::mount) -> Self {
        mount.refcount.fetch_add(1, SeqCst);
        Self(std::ptr::NonNull::from(mount))
    }

    /// Another reference to a mount that cannot go away while this runs.
    ///
    /// # Safety
    ///
    /// `mount` is live and no concurrent umount can unlink it: the caller
    /// already holds a reference of its own.
    pub unsafe fn retain(mount: Mount) -> Self {
        // SAFETY: the caller's contract.
        Self::of(unsafe { &*mount })
    }

    /// Adopts the reference recorded in a field, so that dropping this gives
    /// it back.
    ///
    /// # Safety
    ///
    /// The reference came from [`MountRef::into_raw`], and the field it came
    /// from is not read again — this is the only owner now.
    pub unsafe fn from_raw(mount: Mount) -> Self {
        Self(std::ptr::NonNull::new(mount).expect("MountRef::from_raw of a null mount"))
    }

    /// Hands the reference to a field whose teardown gives it back with
    /// [`MountRef::from_raw`].
    pub fn into_raw(self) -> Mount {
        let mount = self.0.as_ptr();
        std::mem::forget(self);
        mount
    }

    /// The mount, borrowed for as long as this reference is held.
    pub fn as_ptr(&self) -> Mount {
        self.0.as_ptr()
    }
}

/// The mount, borrowed for as long as this reference is held.
///
/// The reference is what makes it sound: a mount whose count is not zero
/// cannot be unlinked -- [`mounts_take_point`] answers `EBUSY` -- and so is not
/// freed, and what a `&mount` reads is either immutable after the mount is
/// made or atomic.
impl std::ops::Deref for MountRef {
    type Target = ffi::mount;

    fn deref(&self) -> &ffi::mount {
        // SAFETY: as above.
        unsafe { self.0.as_ref() }
    }
}

impl Drop for MountRef {
    fn drop(&mut self) {
        // No lock. See the module comment: a release only ever decreases, and
        // the path walk does one per component.
        self.refcount.fetch_sub(1, SeqCst);
    }
}

/// The next mount id, for a mount in the table and for a detached one alike:
/// Linux numbers its internal mounts (pipefs, sockfs, anon_inodefs) from the
/// same allocator as the ones in `mountinfo`, and `statx`'s `stx_mnt_id` and
/// `/proc/<pid>/fdinfo`'s `mnt_id:` report them.
///
/// From 1, so that 0 stays available as "no mount", and never reused: an id is
/// an identity a caller may hold across the mount going away, and handing the
/// same number to the next mount would make two different filesystems compare
/// equal. There is no wrap to worry about -- a `u32` is four billion mounts.
pub fn next_mount_id() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// A mount that belongs to no table and is never freed: what a descriptor no
/// path can reach points at -- `crates/fs/adhoc`'s anonymous, pipe and socket
/// filesystems, `crates/kernel/memfdcalls`' memfd one and the mqueue one.
pub struct DetachedMount(&'static ffi::mount);

impl DetachedMount {
    /// `id` is the mount id its files report: [`next_mount_id`], or 0 for a
    /// mount whose Linux counterpart reports 0.
    pub fn leak(fs: &'static dyn ffi::FsOps, id: u32) -> DetachedMount {
        DetachedMount(Box::leak(Box::new(ffi::mount {
            fs: Some(fs),
            id,
            // The device its files report is the superblock's.
            sb: Arc::new(ffi::Superblock::new(id)),
            ..Default::default()
        })))
    }

    pub fn as_ptr(&self) -> Mount {
        self.0.as_ptr()
    }

    /// A reference, for a descriptor's `mount` field. Safe where
    /// [`MountRef::retain`] is not, because nothing can free this one.
    pub fn retain(&self) -> MountRef {
        MountRef::of(self.0)
    }
}

/// The mount that owns this path, with a reference taken.
///
/// The path is normalised; the root mount's point is the empty string, so there
/// is always an answer — this panics rather than answering null, which is why
/// no caller checks.
pub fn mount_find(path: &CStr) -> MountRef {
    let path = path.to_bytes();
    with(|t| {
        // The first match in descending-length order is the longest, which is
        // the one that owns it.
        let found = t
            .mounts
            .iter()
            .find(|m| owns(point_of(m), path))
            // The root's point is "" and owns everything, so this cannot miss
            // unless nothing is mounted -- which would mean no root.
            .or_else(|| t.mounts.last())
            .expect("no root filesystem is mounted");
        // Under the table lock, which is what keeps a mount in the table
        // alive and makes the retain legal here.
        MountRef::of(found)
    })
}

/// The mount that owns the path in `buf`, with a reference taken, **and the
/// path trimmed to be relative to it**.
///
/// The two go together: the mount's point is a prefix of the path, and every
/// caller wants the rest. Trimming in place is what makes this one call
/// rather than two.
///
/// `buf` holds a NUL-terminated normalised guest path, and the answer's path
/// is too -- the trim only moves the contents down.
pub fn find_mount_and_trim_path(buf: &mut [u8]) -> MountRef {
    let len = buf.iter().position(|&b| b == 0).expect("a NUL-terminated path");
    let path = CStr::from_bytes_with_nul(&buf[..=len]).expect("the first NUL ends it");
    let mount = mount_find(path);
    let point = point_of(&mount).len();
    // `copy_within` is `memmove`: the two ranges overlap whenever the point is
    // shorter than what follows it, which is every path below a mount point.
    buf.copy_within(point..len, 0);
    buf[len - point] = 0;
    mount
}

/// Adds a mount, keeping the order the lookup depends on.
pub fn mounts_insert(mount: Arc<ffi::mount>) {
    with(|t| {
        let len = point_of(&mount).len();
        // Before the first entry whose point is no longer than this one, which
        // keeps the list in descending order. A new mount at the same length as
        // an existing one goes *first*, as the C's `<=` did.
        let at = t
            .mounts
            .iter()
            .position(|m| point_of(m).len() <= len)
            .unwrap_or(t.mounts.len());
        t.mounts.insert(at, mount);
    });
}

/// Takes the mount at `at` out of the table so the caller can tear it down,
/// or `EBUSY` while something still holds a reference.
///
/// The refcount check and the unlink are one step under the lock, and the
/// teardown is **not**: a filesystem's `umount` does file and database work
/// that must not run with this held. Once it is off the list no lookup can
/// reach it, and the refcount was zero, so nothing already in flight can
/// either.
fn take_at(t: &mut Table, at: usize) -> Result<Arc<ffi::mount>, c_int> {
    if busy(&t.mounts[at]) {
        return Err(EBUSY);
    }
    Ok(t.mounts.remove(at))
}

/// The mount whose point is exactly this, taken out of the table.
///
/// One call rather than a lookup and a removal, because the mount found by a
/// separate lookup could be removed and freed by a concurrent umount before
/// this one looked at it. `EINVAL` for no such point and `EBUSY` for one still
/// in use.
pub fn mounts_take_point(point: &CStr) -> Result<Arc<ffi::mount>, c_int> {
    let point = point.to_bytes();
    with(|t| {
        let at = t.mounts.iter().position(|m| point_of(m) == point).ok_or(EINVAL)?;
        take_at(t, at)
    })
}

/// The first mount in table order, taken out -- or, for one still in use, its
/// point. `None` once the table is empty. It was `mounts_at(i)`, which
/// answered a pointer "only valid until the next umount".
fn take_first(table: &Mounts) -> Option<Result<Arc<ffi::mount>, CString>> {
    table.with(|t| {
        let first = t.mounts.first()?;
        let point = first.point.clone();
        Some(take_at(t, 0).map_err(|_| point))
    })
}

/// For halting, which removes every mount of **every** mount namespace: a
/// namespace's own mounts are in no other table, and a fakefs among them
/// would otherwise exit with its database open. The calling thread's table
/// first, as it always was; then the others; then the parked mounts of
/// tables already gone, now that whatever was busy in them has exited.
///
/// Each answer is as [`take_first`]'s for one table: a mount taken out, or
/// the point of one still in use, which ends that table. `None` once nothing
/// is left to take.
pub fn mounts_take_first_anywhere(skip: &mut Vec<usize>) -> Option<Result<Arc<ffi::mount>, CString>> {
    let mine = current_mounts();
    let mut tables = vec![Arc::clone(&mine)];
    tables.extend(
        TABLES
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .filter(|t| !Arc::ptr_eq(t, &mine)),
    );
    for table in &tables {
        let key = Arc::as_ptr(table) as usize;
        if skip.contains(&key) {
            continue;
        }
        match take_first(table) {
            Some(Ok(m)) => return Some(Ok(m)),
            Some(Err(point)) => {
                skip.push(key);
                return Some(Err(point));
            }
            None => {}
        }
    }
    let mut parked = PARKED.lock().unwrap_or_else(|p| p.into_inner());
    let at = parked.iter().position(|m| !busy(m))?;
    Some(Ok(parked.swap_remove(at)))
}

/// Is anything mounted at or under `path`?
///
/// What makes a rename or an rmdir of it `EBUSY`. The boundary rule again: a
/// mount at `/mnt/x` is under `/mnt`, and one at `/mnt-other` is not.
pub fn contains_mount_point(path: &CStr) -> bool {
    let path = path.to_bytes();
    with(|t| t.mounts.iter().any(|m| owns(path, point_of(m))))
}

/// Is something mounted exactly at `path`? `/` is the root's point, which
/// is the empty string.
pub fn is_mount_point(path: &CStr) -> bool {
    let path = path.to_bytes();
    let path = if path == b"/" { &b""[..] } else { path };
    with(|t| t.mounts.iter().any(|m| point_of(m) == path))
}

/// How many mounts there are.
pub fn mounts_len() -> usize {
    with(|t| t.mounts.len())
}

/// Every mount, in table order, **with the lock held** for the length of the
/// call.
///
/// For a reader: `/proc/mounts` formats each one, and a mount it is halfway
/// through must not be freed under it. Holding the lock across the formatting
/// is what the C list walk did and is the reason it was safe.
///
/// Nothing may mount or umount from inside `f` — the lock is not recursive.
pub fn with_mounts<T>(f: impl FnOnce(&[&ffi::mount]) -> T) -> T {
    with(|t| {
        let mounts: Vec<&ffi::mount> = t.mounts.iter().map(Arc::as_ref).collect();
        f(&mounts)
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod id_tests {
    use super::next_mount_id;

    #[test]
    fn ids_start_at_one_and_never_repeat() {
        let a = next_mount_id();
        let b = next_mount_id();
        assert!(a >= 1);
        assert_ne!(a, b);
        assert!(b > a);
    }
}
