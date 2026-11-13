//! `struct mount` — one mounted filesystem. Rust's, since 2026-09-05.
//!
//! # Why it is here
//!
//! The same reason `struct task` and `struct fd` are: **no C reads a field of
//! it.** It needed no accessor to get there either — the last C readers went
//! when `fs/fake.c` and the mount table did, and `kernel/fs.h` was already
//! down to prototypes over it.
//!
//! It is in `taskview` because `struct fd` holds one and a shared type has to
//! sit below everything that uses it; `crates/fs/mount`, which makes and
//! unmakes them, is not below `crates/fs/fdobj`.
//!
//! # `refcount` is an `AtomicU32`, not a word a tool watches
//!
//! It was `atomic_uint` in the C, which bindgen emits as a plain `u32`, so
//! `crates/fs/mount` cast its address at each use and `tools/atomic-fields.py`
//! checked that nobody skipped the cast. The field is the atomic now — the
//! fourth this week to stop needing that tool, after `task_cleanup`'s four
//! pointers, `tgroup.last_progress_ns` and the signalfd mask.
//!
//! **It is deliberately not guarded by `mounts_lock`.** A retain is made by
//! something that already holds a reference, so the struct cannot go away
//! under it, and a release only ever decreases. It matters because the path
//! walk calls `mount_find` and drops the `MountRef` once per component: two global
//! mutex acquisitions per component per thread is what made resolving a path
//! serialise across threads, and a profile of four threads calling `stat` put
//! 31 of ~150 samples per thread blocked in those two functions.

#![allow(non_camel_case_types)]

use std::sync::atomic::AtomicU32;

/// The `meta.db` connection: `crates/fs/fakedb`'s `Db`.
///
/// A field-less placeholder until 2026-09-29, with a cast at each of the six
/// places `crates/fs/fake` read the field. What kept it one was
/// `fs-fakedb -> kernel-logline -> kernel-syslogcalls -> kernel-usercopy ->
/// kernel-taskview -> kernel-abi`: the log's ring lived in the syscall crate
/// that reads it, so printing a line depended on the syscall layer. The ring is
/// `logline`'s now and `fs-fakedb` reaches nothing that reaches this crate.
///
/// The cost is that this crate's closure contains `rusqlite`. Every build of
/// `libiul.a` compiles it anyway; what moves is only when.
pub use fakedb::Db as fakedb;

/// One mounted filesystem.
#[repr(C)]
#[derive(Default)]
pub struct mount {
    /// Where it is mounted, as a guest path. Empty for the root.
    ///
    /// The three strings are owned since 2026-09-29. They were `strdup`s
    /// `do_mount` made and `destroy_without_umount` freed, and realfs swapped
    /// `source` for a `realpath` result and `free`d the old one in between --
    /// three owners of one allocation, agreeing by convention.
    pub point: std::ffi::CString,
    /// What was mounted — a host path, or a device name.
    pub source: std::ffi::CString,
    /// The options string, as `/proc/mounts` reports it.
    pub info: std::ffi::CString,
    /// `MS_*`: read-only, `nosuid`, and the rest.
    pub flags: ::std::os::raw::c_int,
    /// What `statx(STATX_MNT_ID)` reports for a file on this mount, and what
    /// `name_to_handle_at` answers as its mount id: a small number, unique for
    /// the life of the process, assigned when the mount is made.
    ///
    /// Linux's is an id per mount *namespace* entry and is likewise not a
    /// device number — two mounts of one filesystem have different ids.
    /// systemd asks for it to decide whether two directories are on the same
    /// mount, which is how it walks a path without following one out of a
    /// tree; with no id it fell back to `name_to_handle_at`, and with that a
    /// stub it gave up.
    pub id: u32,
    /// The filesystem's operations.
    ///
    /// A `*const fs_ops` — a table of twenty-three nullable function pointers
    /// and two data fields — until 2026-09-11. `None` only between the
    /// allocation and the assignment in `do_mount`, which is what `Default`
    /// gives.
    pub fs: Option<&'static dyn crate::FsOps>,
    /// How many descriptors and walks are holding this mount.
    ///
    /// See the module comment for why it is not under `mounts_lock`.
    /// `fs_mounttable::mounts_take_point` reads it under that lock and refuses a `umount`
    /// if it is not zero; a release that lands just after that read leaves the
    /// check seeing 1 and answering `EBUSY`, which is what a release blocking
    /// on the lock did before — conservative in the same direction.
    pub refcount: AtomicU32,
    /// The host directory a realfs or fakefs mount is rooted at, for the `*at`
    /// calls that do the work. Read with [`mount::root`].
    ///
    /// An `OwnedFd` since 2026-09-29, and it was an `int` nothing closed:
    /// realfs has no `umount` and fakefs's freed only its database, so every
    /// unmount of either left one host descriptor open for the life of the
    /// process. The mount is a `Box`, so dropping it closes this.
    pub root_fd: Option<std::os::fd::OwnedFd>,
    /// What the filesystem keeps per mount. See [`mount_state`].
    pub state: mount_state,
}

impl mount {
    /// The device number every file on this mount reports as `st_dev`:
    /// `0:id`, the anonymous major Linux gives its virtual filesystems, with
    /// the mount's own id as the minor.
    ///
    /// Each filesystem used to answer the host's `st_dev`, and the root, `/dev`
    /// and `/dev/shm` are three directories on one host disk -- so all three
    /// were `1:18`, `df /tmp` named `/dev/shm`, and anything that finds a
    /// mount boundary by comparing devices (`find -xdev`, `du -x`, `cp -x`)
    /// saw none (`tests/guest` mount_dev). In the guest's `dev_t`
    /// encoding: the minor's low byte, then its high bits from bit 20.
    pub fn dev(&self) -> u64 {
        u64::from((self.id & 0xff) | ((self.id & 0xfff00) << 12))
    }

    /// Stamp what no filesystem knows about itself onto a stat answer from
    /// this mount: which mount, and its device.
    pub fn stamp(&self, st: &mut crate::statbuf) {
        st.mount_id = self.id;
        st.dev = self.dev();
    }

    /// The same mount as a pointer, for a callee that has not been converted
    /// to take a reference yet.
    ///
    /// Sound because nothing writes a mount's fields through such a pointer:
    /// `FsOps::mount` and `FsOps::umount` are the only two that write at all,
    /// they take a `&mut`, and each runs where nothing else holds the mount —
    /// `do_mount` calls the first before `mounts_insert`, and `fs_mount::destroy`
    /// calls the second after the table has handed it over with a refcount of
    /// zero. `refcount` itself is an `AtomicU32`, which is what lets every
    /// other holder have a `&`.
    ///
    /// **The number of calls to this is the size of the remaining
    /// conversion.**
    pub fn as_ptr(&self) -> *mut mount {
        (&raw const *self).cast_mut()
    }

    /// The host directory this mount is rooted at, for as long as the mount
    /// is borrowed. `None` for a filesystem that has none -- tmpfs, procfs,
    /// devpts -- and for a realfs or fakefs mount whose own `mount` has not
    /// run.
    pub fn root(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd as _;
        self.root_fd.as_ref().map(std::os::fd::OwnedFd::as_fd)
    }

    /// This mount's identity, for a table keyed on which mount a thing is on.
    ///
    /// See [`crate::Identity`], which is what this is: an address used as a
    /// key and never as an access.
    pub fn id(&self) -> crate::MountId {
        crate::MountId::of(self)
    }
}

/// What a mount's filesystem keeps for it, **owned**.
///
/// A `#[repr(C)]` union of two raw pointers until 2026-09-29: tmpfs parked a
/// `Box<Arc<Dirent>>` in one arm as a `c_void`, fakefs a `Box<Db>` in the
/// other, each read it back with an `unsafe` union read and a cast, and each
/// freed it by hand in its `umount`. Nothing about the union said which arm a
/// mount held, so every reader's `# Safety` said "this mount is one of mine".
/// An enum says it, dropping the mount drops what it owns, and tmpfs's
/// `downcast_ref` checks the type the cast used to assume.
#[derive(Default)]
pub enum mount_state {
    /// Nothing, which is every mount type but these two.
    #[default]
    None,
    /// The `meta.db` connection, which `crates/fs/fakedb` defines.
    Fakefs(Box<fakedb>),
    /// A filesystem's own state -- tmpfs's root directory -- whose type this
    /// crate does not know.
    Data(Box<dyn std::any::Any + Send + Sync>),
}

impl mount_state {
    /// The database, if this is a fakefs.
    pub fn fakefs(&self) -> Option<&fakedb> {
        match self {
            Self::Fakefs(db) => Some(db),
            _ => None,
        }
    }

    /// A filesystem's own state, if it is a `T`.
    pub fn data<T: 'static>(&self) -> Option<&T> {
        match self {
            Self::Data(d) => d.downcast_ref(),
            _ => None,
        }
    }
}

/// A device number in `stat`'s encoding (see [`mount::dev`]) as the kernel
/// holds it, `MAJOR << 20 | MINOR`: what `/proc/<pid>/fdinfo` prints as an
/// epoll or inotify target's `sdev:`. The two agree only for a device whose
/// major is 0 and minor below 256.
pub fn kernel_dev(dev: u64) -> u32 {
    let dev = dev as u32;
    let major = (dev & 0xfff00) >> 8;
    let minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    major << 20 | minor
}

/// Linux's generic file handle for an identifying (`AT_HANDLE_FID`) handle:
/// `FILEID_INO64_GEN`, the inode number and a generation of 0. What
/// `name_to_handle_at` answers for a filesystem with no export operations --
/// every one here -- and what an inotify watch's fdinfo line shows.
pub const FILEID_INO64_GEN: i32 = 0x81;

/// [`FILEID_INO64_GEN`]'s twelve bytes.
pub fn fid_ino64_gen(ino: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&ino.to_le_bytes());
    out
}

/// Linux's `MNT_UNIQUE_ID_OFFSET`: unique mount ids are above it, so that one
/// cannot be mistaken for the reused kind `/proc/self/mountinfo` prints, and
/// `statmount` and `listmount` answer EINVAL for an id at or below it.
pub const MNT_UNIQUE_ID_OFFSET: u64 = 1 << 31;

/// The unique id of the mount numbered `id`. This kernel never reuses an id
/// (`crates/fs/mount`'s `next_id`), so the unique one is the same number moved
/// above the offset, and the two always name the same mount.
pub fn unique_mount_id(id: u32) -> u64 {
    MNT_UNIQUE_ID_OFFSET + u64::from(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `stat`'s encoding of `MKDEV(major, minor)`, as glibc's `makedev` packs it.
    fn encoded(major: u64, minor: u64) -> u64 {
        (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12)
    }

    #[test]
    fn the_kernel_form_of_a_device_is_major_above_bit_twenty() {
        assert_eq!(kernel_dev(encoded(0, 0x2d)), 0x2d);
        assert_eq!(kernel_dev(encoded(1, 3)), 1 << 20 | 3);
        // A minor past a byte, as a mount id past 255 is.
        assert_eq!(kernel_dev(encoded(0, 0x1234)), 0x1234);
        assert_eq!(kernel_dev(encoded(259, 0x101)), 259 << 20 | 0x101);
    }
}
