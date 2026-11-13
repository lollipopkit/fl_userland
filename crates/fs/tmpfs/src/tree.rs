//! The in-memory directory tree.
//!
//! Three things here differ from the C this replaces, and they are why it was
//! rewritten rather than translated:
//!
//! - **`parent` is a `Weak`.** In C both directions were strong references — a
//!   directory retained its children and every child retained its parent — so
//!   no tree ever reached refcount zero. That is why `tmpfs_umount` could only
//!   be a `TODO`; unmounting leaked the whole filesystem.
//! - **One lock per inode covers its whole body.** The C version had a lock on
//!   the inode and another on the dirent, taken in varying orders, and one path
//!   released a lock it had never taken.
//! - **An inode is reached through `Arc`, so hardlinks and open-but-unlinked
//!   files work.** The C version had neither: `unlink` was not implemented at
//!   all, so nothing was ever removed.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::contents::Contents;
use crate::errno::{EEXIST, EINVAL, ENOENT, ENOTDIR, ENOTEMPTY, Result};

/// Longest single path component, matching `MAX_NAME` in `kernel/fs.h`.
pub const MAX_NAME: usize = 256;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

impl Timespec {
    pub fn now() -> Timespec {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Timespec {
                sec: d.as_secs() as i64,
                nsec: d.subsec_nanos() as i64,
            },
            // Before the epoch: not worth failing an mkdir over.
            Err(_) => Timespec::default(),
        }
    }
}

/// Everything about an inode that changes, behind one lock.
#[derive(Debug)]
pub struct Body {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    /// Number of directory entries pointing here. Not the `Arc` count, which
    /// also counts open file descriptors — an unlinked file with an open fd
    /// has `nlink == 0` and is still readable, which is what POSIX requires.
    pub nlink: u32,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    /// When the inode was made, and the one timestamp nothing ever changes.
    ///
    /// A tmpfs on Linux reports it: the inode exists only in memory, so the
    /// creation time is simply the moment it was allocated, and
    /// `statx(STATX_BTIME)` answers. Every other timestamp here has a setter;
    /// this one deliberately has none, which is what makes it a birth time.
    pub btime: Timespec,
    /// Contents of a regular file, or the target of a symlink. Empty for
    /// everything else. See `crate::contents`.
    pub data: Contents,
    /// Extended attributes, by name.
    ///
    /// A `BTreeMap` and not a `HashMap`, so `listxattr` answers in a stable
    /// order — Linux's tmpfs keeps them in a list and reports insertion order,
    /// and *some* fixed order is what makes a listing reproducible between two
    /// runs. Which order it is is not observable through the interface, because
    /// the list is a set: `xattr_probe` asks about membership rather than
    /// position for exactly that reason.
    ///
    /// Empty for almost every inode, and a `BTreeMap::new()` allocates nothing,
    /// so the cost of the field on a filesystem nobody sets an attribute on is
    /// the pointer.
    pub xattrs: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Body {
    pub fn file_type(&self) -> u32 {
        self.mode & S_IFMT
    }
    pub fn is_dir(&self) -> bool {
        self.file_type() == S_IFDIR
    }
    pub fn is_lnk(&self) -> bool {
        self.file_type() == S_IFLNK
    }
    pub fn size(&self) -> u64 {
        self.data.len()
    }
    pub fn touch_mtime(&mut self) {
        let now = Timespec::now();
        self.mtime = now;
        self.ctime = now;
    }
}

#[derive(Debug)]
pub struct Inode {
    pub ino: u64,
    pub body: Mutex<Body>,
    /// The host file the contents moved to when the file was first mapped.
    /// Outside `body` so that the page table can borrow it without a lock;
    /// set once, under `body`'s.
    pub(crate) host: OnceLock<OwnedFd>,
}

/// Bytes of file content held across every tmpfs mount in this process.
///
/// statfs used to report a zeroed capacity, on the reasoning that a filesystem
/// bounded by host memory has no block count worth reporting. What that
/// actually produced was `f_blocks` of zero, which `df` divides by and which
/// tells a program checking for free space that there is none of anything.
/// Reporting a nominal capacity and a real usage is more use than reporting
/// nothing, and this is what the usage is counted in.
pub static TMPFS_BYTES: AtomicU64 = AtomicU64::new(0);

/// Records a file's data growing or shrinking. Saturating, because a mistake
/// in the accounting should skew a number `df` prints rather than panic a
/// filesystem operation.
pub(crate) fn account_bytes(before: usize, after: usize) {
    if after >= before {
        TMPFS_BYTES.fetch_add((after - before) as u64, Ordering::Relaxed);
    } else {
        let freed = (before - after) as u64;
        let _ = TMPFS_BYTES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(freed))
        });
    }
}

impl Drop for Inode {
    fn drop(&mut self) {
        // The last reference is going: whatever the file held is free again.
        // Without this, unlinking every file in a tmpfs left the usage at its
        // high-water mark for the life of the process.
        let len = match self.body.get_mut() {
            Ok(body) => body.data.len(),
            Err(poisoned) => poisoned.into_inner().data.len(),
        };
        account_bytes(len as usize, 0);
    }
}

impl Inode {
    /// The file type bits, for a caller that wants the kind and not the whole
    /// body — readdir, which reports it as `d_type`.
    pub fn mode(&self) -> u32 {
        crate::lock(&self.body).mode
    }

    pub fn new(mode: u32, uid: u32, gid: u32, rdev: u64) -> Arc<Inode> {
        static NEXT_INO: AtomicU64 = AtomicU64::new(1);
        let now = Timespec::now();
        Arc::new(Inode {
            ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
            body: Mutex::new(Body {
                mode,
                uid,
                gid,
                rdev,
                nlink: 0,
                atime: now,
                mtime: now,
                ctime: now,
                btime: now,
                data: Contents::default(),
                xattrs: std::collections::BTreeMap::new(),
            }),
            host: OnceLock::new(),
        })
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Body> {
        self.body.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_dir(&self) -> bool {
        self.lock().is_dir()
    }
}

/// Children of a directory, ordered by the index they were created with.
///
/// The index is what `telldir` reports and `seekdir` takes back, so it has to
/// be stable across insertion and removal and to increase monotonically. A
/// `BTreeMap` keyed on it keeps `readdir` in creation order and makes `seekdir`
/// a range lookup rather than the linear scan it was.
#[derive(Debug, Default)]
pub struct Children {
    by_index: BTreeMap<u64, Arc<Dirent>>,
    next_index: u64,
}

impl Children {
    pub fn is_empty(&self) -> bool {
        self.by_index.is_empty()
    }

    pub fn lookup(&self, name: &[u8]) -> Option<Arc<Dirent>> {
        self.by_index.values().find(|d| d.is_named(name)).cloned()
    }

    /// The first entry at or after `index`, which is what `seekdir` needs.
    pub fn at_or_after(&self, index: u64) -> Option<Arc<Dirent>> {
        self.by_index.range(index..).next().map(|(_, d)| d.clone())
    }

    /// The entry strictly after `index`, for advancing a `readdir` cursor.
    pub fn after(&self, index: u64) -> Option<Arc<Dirent>> {
        self.by_index
            .range(index + 1..)
            .next()
            .map(|(_, d)| d.clone())
    }

    pub fn first(&self) -> Option<Arc<Dirent>> {
        self.by_index.values().next().cloned()
    }

    fn remove_named(&mut self, name: &[u8]) -> Option<Arc<Dirent>> {
        let index = self.by_index.iter().find(|(_, d)| d.is_named(name))?.0;
        let index = *index;
        self.by_index.remove(&index)
    }
}

/// Where an entry currently sits: its name, its position in its parent's
/// ordering, and the parent itself.
///
/// Behind a lock because `rename` moves it. The three fields used to be plain
/// members of `Dirent`, so a rename could not change them and made a *new*
/// `Dirent` at the destination instead, carrying the children across. An open
/// directory descriptor holds an `Arc<Dirent>`, so it was left holding the old
/// one — now childless — and a directory renamed while something was reading
/// it simply stopped returning entries. On Linux a descriptor refers to the
/// directory, not to its name, and iteration is unaffected.
#[derive(Debug)]
pub struct Place {
    pub name: Vec<u8>,
    /// Position in the parent's ordering. Meaningless for a mount root.
    pub index: u64,
    /// Weak, so a tree can actually be dropped. See the module comment.
    pub parent: Weak<Dirent>,
}

impl std::fmt::Debug for Dirent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dirent")
            .field("name", &String::from_utf8_lossy(&self.name()).into_owned())
            .finish_non_exhaustive()
    }
}

pub struct Dirent {
    pub inode: Arc<Inode>,
    pub place: Mutex<Place>,
    pub children: Mutex<Children>,
}

impl Dirent {
    /// This entry's current name. Cloned: it can change under a rename, so a
    /// borrow would be a borrow of something the lock is protecting.
    pub fn name(&self) -> Vec<u8> {
        self.place().name.clone()
    }

    /// Whether this entry is currently called `name`.
    pub fn is_named(&self, name: &[u8]) -> bool {
        self.place().name == name
    }

    pub fn index(&self) -> u64 {
        self.place().index
    }

    pub fn parent(&self) -> Option<Arc<Dirent>> {
        self.place().parent.upgrade()
    }

    pub fn place(&self) -> MutexGuard<'_, Place> {
        // Poison is not a state this tree can be in: nothing here panics
        // while holding one, and a mount that failed the mount is torn down.
        self.place.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The root of a mount: no parent, no meaningful index.
    pub fn new_root(inode: Arc<Inode>) -> Arc<Dirent> {
        inode.lock().nlink = 1;
        Arc::new(Dirent {
            inode,
            place: Mutex::new(Place {
                name: Vec::new(),
                index: 0,
                parent: Weak::new(),
            }),
            children: Mutex::new(Children::default()),
        })
    }

    pub fn children(&self) -> std::sync::MutexGuard<'_, Children> {
        self.children.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_dir(&self) -> bool {
        self.inode.is_dir()
    }

    /// Absolute path of this entry within its mount, as `getpath` reports it.
    ///
    /// Walks up through `parent`. The C version's loop never advanced the entry
    /// it was looking at, so it wrote the same name over and over until it ran
    /// out of buffer and returned ENAMETOOLONG for everything below the root.
    pub fn path_within_mount(self: &Arc<Dirent>) -> Vec<u8> {
        let mut components: Vec<Vec<u8>> = Vec::new();
        let mut cursor = Arc::clone(self);
        while let Some(parent) = cursor.parent() {
            components.push(cursor.name());
            cursor = parent;
        }
        let mut path = Vec::new();
        for component in components.iter().rev() {
            path.push(b'/');
            path.extend_from_slice(component);
        }
        path
    }
}

/// Attach `inode` to `parent` under `name`, as a new directory entry.
///
/// Fails with `EEXIST` if the name is taken. The caller holds no lock; this
/// takes the parent's for the check and the insert together, so two threads
/// racing to create one name cannot both win.
pub(crate) fn link_into(
    parent: &Arc<Dirent>,
    name: &[u8],
    inode: Arc<Inode>,
) -> Result<Arc<Dirent>> {
    if !parent.is_dir() {
        return Err(ENOTDIR);
    }
    let mut children = parent.children();
    if children.lookup(name).is_some() {
        return Err(EEXIST);
    }
    let index = children.next_index;
    children.next_index += 1;
    inode.lock().nlink += 1;
    let dirent = Arc::new(Dirent {
        inode,
        place: Mutex::new(Place {
            name: name.to_vec(),
            index,
            parent: Arc::downgrade(parent),
        }),
        children: Mutex::new(Children::default()),
    });
    children.by_index.insert(index, Arc::clone(&dirent));
    drop(children);
    parent.inode.lock().touch_mtime();
    Ok(dirent)
}

/// Remove `name` from `parent`.
///
/// `want_dir` picks the `rmdir` rules (must be a directory, must be empty)
/// over the `unlink` ones (must not be a directory).
pub(crate) fn unlink_from(parent: &Arc<Dirent>, name: &[u8], want_dir: bool) -> Result<()> {
    if !parent.is_dir() {
        return Err(ENOTDIR);
    }
    // "." and ".." are resolved above this layer, but rmdir("x/..") would
    // arrive here as a name and must not unlink anything.
    if name == b"." || name == b".." {
        return Err(EINVAL);
    }
    let mut children = parent.children();
    let victim = children.lookup(name).ok_or(ENOENT)?;
    let is_dir = victim.is_dir();
    if want_dir {
        if !is_dir {
            return Err(ENOTDIR);
        }
        if !victim.children().is_empty() {
            return Err(ENOTEMPTY);
        }
    } else if is_dir {
        // Linux reports EISDIR here on most filesystems; the VFS above turns
        // an unlink of a directory away before it reaches us, but be explicit.
        return Err(crate::errno::EISDIR);
    }
    children.remove_named(name);
    drop(children);
    // The inode itself lives until the last Arc goes — an open fd keeps an
    // unlinked file readable, which is what POSIX asks for.
    victim.inode.lock().nlink -= 1;
    parent.inode.lock().touch_mtime();
    Ok(())
}

/// Move `old_name` in `old_parent` to `new_name` in `new_parent`.
///
/// A new entry is created rather than the old one being mutated, because a
/// `Dirent`'s parent and name are immutable. The inode is shared, so an fd open
/// across the rename keeps reading the same file.
/// Whether `node` is `start` or any directory above it.
///
/// Moving a directory under itself detaches the subtree, and both a rename and
/// an exchange can ask for it — the exchange in either direction, since both
/// ends move.
fn is_ancestor(node: &Arc<Dirent>, start: &Arc<Dirent>) -> bool {
    let mut cursor = Some(Arc::clone(start));
    while let Some(cur) = cursor {
        if Arc::ptr_eq(&cur, node) {
            return true;
        }
        cursor = cur.parent();
    }
    false
}

/// `renameat2`'s flags, as the guest spells them (`kernel/fs.h`).
pub const RENAME_NOREPLACE: u32 = 1 << 0;
pub const RENAME_EXCHANGE: u32 = 1 << 1;

pub fn rename(
    old_parent: &Arc<Dirent>,
    old_name: &[u8],
    new_parent: &Arc<Dirent>,
    new_name: &[u8],
    flags: u32,
) -> Result<()> {
    if !old_parent.is_dir() || !new_parent.is_dir() {
        return Err(ENOTDIR);
    }
    let source = old_parent.children().lookup(old_name).ok_or(ENOENT)?;

    // RENAME_EXCHANGE swaps two names that both already exist, and its whole
    // value is that nothing observes an intermediate state -- so it is done
    // here, under the same locks, rather than as two renames.
    if flags & RENAME_EXCHANGE != 0 {
        let target = new_parent.children().lookup(new_name).ok_or(ENOENT)?;
        // Exchanging a directory with something inside it would detach a
        // subtree just as a rename into it would, and in both directions.
        if (source.is_dir() && is_ancestor(&source, new_parent))
            || (target.is_dir() && is_ancestor(&target, old_parent))
        {
            return Err(EINVAL);
        }
        if Arc::ptr_eq(&source, &target) {
            return Ok(());
        }
        // Swap where each one sits. The children maps keep pointing at the
        // same two Dirents, so an open descriptor -- which holds an Arc to the
        // directory rather than to its name -- follows the entry it opened.
        let (src_index, dst_index) = (source.index(), target.index());
        {
            let mut a = source.place();
            let mut b = target.place();
            std::mem::swap(&mut a.name, &mut b.name);
            std::mem::swap(&mut a.index, &mut b.index);
            std::mem::swap(&mut a.parent, &mut b.parent);
        }
        if Arc::ptr_eq(old_parent, new_parent) {
            let mut children = old_parent.children();
            children.by_index.insert(src_index, Arc::clone(&target));
            children.by_index.insert(dst_index, Arc::clone(&source));
        } else {
            old_parent
                .children()
                .by_index
                .insert(src_index, Arc::clone(&target));
            new_parent
                .children()
                .by_index
                .insert(dst_index, Arc::clone(&source));
        }
        return Ok(());
    }

    // Renaming a directory into its own subtree would detach that subtree.
    if source.is_dir() && is_ancestor(&source, new_parent) {
        return Err(EINVAL);
    }

    // Replacing an existing destination is allowed.
    //
    // The lookup is bound to its own statement on purpose: as the tail of an
    // `if let` scrutinee, the temporary MutexGuard would live until the end of
    // the block, and unlink_from below locks the same children — a deadlock
    // against ourselves.
    let existing = new_parent.children().lookup(new_name);
    if let Some(existing) = existing {
        // RENAME_NOREPLACE is the atomic create-if-absent a lock file uses.
        // The check has to be here, holding what the move below holds: done by
        // the caller it would be a lookup and then a rename, which is the race
        // the flag exists to remove.
        if flags & RENAME_NOREPLACE != 0 {
            return Err(EEXIST);
        }
        let want_dir = existing.is_dir();
        if want_dir && !existing.children().is_empty() {
            return Err(ENOTEMPTY);
        }
        unlink_from(new_parent, new_name, want_dir)?;
    }

    // Move the entry rather than replace it.
    //
    // This used to link a *new* Dirent in at the destination and carry the
    // children across. An open descriptor holds an Arc<Dirent>, so it was left
    // holding the old one, which now had no children: a directory renamed
    // while something was reading it stopped returning entries, and anything
    // resolved relative to that descriptor stopped finding them. A descriptor
    // refers to the directory, not to its name.
    // Out of the old parent by the index it has there, read before the place
    // below overwrites it. By index and not by name: the two parents may be
    // the same directory, in which case the name is about to be taken.
    let old_index = source.index();
    {
        let mut old_children = old_parent.children();
        old_children.by_index.remove(&old_index);
    }
    let index = {
        // Taken after the guard above is dropped: a rename within one
        // directory has old_parent and new_parent as the same Dirent, and
        // holding its children twice is a deadlock against ourselves.
        let mut children = new_parent.children();
        let index = children.next_index;
        children.next_index += 1;
        children.by_index.insert(index, Arc::clone(&source));
        index
    };
    {
        let mut place = source.place();
        place.name = new_name.to_vec();
        place.index = index;
        place.parent = Arc::downgrade(new_parent);
    }
    // nlink is untouched: the entry moved, it was not unlinked and relinked.
    // The old code's link_into/unlink_from pair cancelled out to the same
    // thing, by a longer route.
    old_parent.inode.lock().touch_mtime();
    if !Arc::ptr_eq(old_parent, new_parent) {
        new_parent.inode.lock().touch_mtime();
    }
    Ok(())
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tests;
