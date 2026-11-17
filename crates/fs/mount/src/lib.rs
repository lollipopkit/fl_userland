//! What a mount *is*: the allocation, the strings, and the teardown order.
//!
//! Which mounts there are and which one owns a path are `crates/fs/mounttable`,
//! which holds the list, its lock and the descending-length order the lookup
//! depends on. The list of filesystem types and the two syscalls are
//! `crates/fs/mountcalls`. What was left in `fs/mount.c` is this: making one,
//! and taking one down.
//!
//! # The order is the whole content of a umount
//!
//! The refcount check and the unlink happen inside `mounts_take_point`, under the
//! table's lock, and the filesystem's own `umount` runs **after** — it does file
//! and database work that must not hold a global lock. Once the mount is off the
//! list no lookup can reach it, and the refcount was zero, so nothing already in
//! flight can either.
//!
//! Read *outside* the lock the refcount says nothing: a lookup could pass
//! through `mount_find` after the check saw zero and before the unlink, and come
//! away with a reference to a mount whose `umount` was already running. For
//! fakefs that meant `fake_db_deinit` finalising the prepared statements the new
//! operation was about to use, and then the struct holding them being freed.
//!
//! # The allocation is Rust's on both sides
//!
//! A mount is made here and freed here, and nothing else frees one, so it is a
//! `Box`. The three strings are separate allocations for the same reason: they
//! are copies of the caller's, and the caller's may be a guest string on a stack
//! that is about to go.


use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::Arc;

/// `struct mount` and `struct fs_ops`, which are `crates/kernel/taskview`'s
/// own Rust.
use taskview::ffi;

use fs_mounttable::{mounts_insert, mounts_take_point};

mod errno {
    pub use guest_errno::c_int_::EINVAL;
}

/// Make a mount and put it in the table.
///
/// The strings are copied: the caller's may be a guest string on a stack
/// that is about to go.
pub fn mount(
    fs: &'static dyn ffi::FsOps,
    source: &CStr,
    point: &CStr,
    info: &CStr,
    flags: c_int,
) -> Result<(), c_int> {
    let id = fs_mounttable::next_mount_id();
    let mut mount = Arc::new(ffi::mount {
        point: point.to_owned(),
        source: source.to_owned(),
        info: info.to_owned(),
        flags,
        fs: Some(fs),
        id,
        sb: Arc::new(ffi::Superblock::new(id)),
        ..Default::default()
    });
    // `&mut` in place rather than before the `Arc` is made: a filesystem may
    // key state on the mount's address, so the mount must not move after
    // this runs.
    let m = Arc::get_mut(&mut mount).expect("a fresh Arc is unique");
    let err = fs.mount(m);
    if err < 0 {
        // The filesystem's own mount failed, so nothing has this yet, and
        // its superblock has no filesystem to take down.
        return Err(err);
    }
    // From here the superblock's drop is the filesystem's `umount`.
    m.sb_mut().fs = Some(fs);
    mounts_insert(mount);
    fs_mounttable::sweep_parked();
    Ok(())
}

/// Make a mount and put it in the table: `iul.h`'s entry point.
///
/// `fs` is what `iul.h` calls a `const struct fs_ops *`: the address of one of
/// the four exported statics. It is an opaque pointer on the C side and
/// nothing reads through it there.
///
/// # Safety
/// `fs` is null or a [`ffi::FsHandle`] that outlives the mount; the three
/// strings are null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn do_mount(
    fs: *const ffi::FsHandle,
    source: *const c_char,
    point: *const c_char,
    info: *const c_char,
    flags: c_int,
) -> c_int {
    // `EINVAL` rather than a dereference. The C prototype cannot stop an
    // embedder passing null and the old code went straight through `(*fs)`.
    let Some(fs) = (unsafe { ffi::FsHandle::deref(fs) }) else {
        return errno::EINVAL;
    };
    if point.is_null() || source.is_null() || info.is_null() {
        return errno::EINVAL;
    }
    // SAFETY: the caller's contract, and none is null.
    let [source, point, info] = [source, point, info].map(|s| unsafe { CStr::from_ptr(s) });
    mount(fs, source, point, info, flags).err().unwrap_or(0)
}

/// Drop a mount the table has handed over. The filesystem's own `umount`
/// runs if this was the last copy of it: [`ffi::Superblock`]'s drop.
fn destroy(mount: Arc<ffi::mount>) {
    // The table held the only `Arc` and its refcount was zero when it came
    // off, so nothing else can reach it.
    debug_assert_eq!(Arc::strong_count(&mount), 1, "the mount table held the only Arc");
    drop(mount);
}

/// Unmount whatever is mounted at `point`: `EINVAL` for a point that carries
/// nothing, `EBUSY` while anything still holds the mount.
pub fn umount(point: &CStr) -> Result<(), c_int> {
    destroy(mounts_take_point(point)?);
    fs_mounttable::sweep_parked();
    Ok(())
}

/// Unmount everything in every mount namespace, for halting. A table whose
/// first mount is still in use is left -- removing the rest of it past that
/// mount would spin -- and the first such mount's point is the answer once
/// every other table is done.
pub fn umount_all() -> Result<(), CString> {
    let mut busy_tables = Vec::new();
    let mut first_busy = None;
    while let Some(taken) = fs_mounttable::mounts_take_first_anywhere(&mut busy_tables) {
        match taken {
            Ok(mount) => destroy(mount),
            Err(point) => {
                first_busy.get_or_insert(point);
            }
        }
    }
    fs_mounttable::sweep_parked();
    first_busy.map_or(Ok(()), Err)
}

/// [`umount`], for an embedder detaching a filesystem it mounted.
///
/// # Safety
/// `point` is NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn do_umount(point: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    umount(unsafe { CStr::from_ptr(point) }).err().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A null string is refused before anything is allocated. It answered
    /// `ENOMEM` until 2026-09-29, from a copy helper that returned `None` for
    /// null and was otherwise about running out of memory.
    #[test]
    fn a_null_string_is_einval() {
        struct Nothing;
        impl ffi::FsOps for Nothing {
            fn name(&self) -> Option<&'static CStr> {
                None
            }
            fn magic(&self) -> u32 {
                0
            }
        }
        static FS: ffi::FsHandle = ffi::FsHandle(&Nothing);
        let s = c"x".as_ptr();
        for (source, point, info) in [
            (std::ptr::null(), s, s),
            (s, std::ptr::null(), s),
            (s, s, std::ptr::null()),
        ] {
            assert_eq!(unsafe { do_mount(&FS, source, point, info, 0) }, errno::EINVAL);
        }
    }

    /// `struct mount`'s offsets. This crate allocates one and hands out the
    /// pointer, so the layout is worth pinning even though nothing outside
    /// Rust reads it any more — the size is what says a field was added or a
    /// pointer changed width.
    #[test]
    fn struct_mount_is_where_it_was() {
        // 56 until 2026-09-11, when `fs` became `Option<&dyn FsOps>`: a trait
        // object is a **fat** pointer, so the filesystem costs sixteen bytes
        // where the `*const fs_ops` it replaced cost eight, and `refcount`
        // moved with it. One mount per mount point, so unlike `struct fd`'s
        // eight bytes this is not paid per object a guest can make.
        // 64 until 2026-09-29, when the union of `data` and the fakefs
        // database became `mount_state`: two variants that each hold a
        // pointer, one of them fat, need a tag -- twenty-four bytes where the
        // union was eight. Paid once per mount. 80 until the three strings
        // became `CString`s later that day, a boxed slice each: sixteen bytes
        // where the `char *` was eight. 88 since 2026-11-14, when the root
        // descriptor and `mount_state` moved into the shared `Superblock` and
        // an `Arc` of it took their place.
        assert_eq!(std::mem::size_of::<ffi::mount>(), 88);
        assert_eq!(std::mem::offset_of!(ffi::mount, point), 0);
        // 32 until the strings were owned.
        assert_eq!(std::mem::offset_of!(ffi::mount, fs), 56);
        // 40 until `fs` became fat, 48 until the strings were owned, 72
        // until `sb` went ahead of it.
        assert_eq!(std::mem::offset_of!(ffi::mount, refcount), 80);
        // `sb` has no offset asserted; the size above is what says it moved.
    }
}

