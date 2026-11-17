//! `mount(2)`, `umount2(2)`, and the list of filesystems a guest may name.
//!
//! The mount *table* — which mounts there are and which one owns a path — has
//! been `crates/fs/mounttable` since 2026-08-31. This is the layer above it:
//! the two syscalls and the registry of filesystem types. What a mount *is*
//! stays in C, because `struct mount` carries a union `crates/fs/fake` reaches
//! into: the allocation, the filesystem's own `mount` and `umount`, and the
//! strings are `do_mount` and `do_umount` in `fs/mount.c`.
//!
//! # Both calls need `CAP_SYS_ADMIN`, and neither checked
//!
//! The mount table is global — there are no mount namespaces here — so an
//! unprivileged `mount` put a filesystem of the caller's choosing in front of
//! anyone's files, and a tmpfs over `/etc` needs no ownership of anything
//! underneath it. An unprivileged `umount` took a filesystem away from every
//! process rather than from its own view of one.


use std::ffi::{CStr, c_int};
use std::sync::Mutex;

use strace::strace;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

use guest_errno::Errno;

mod statmount;
pub use statmount::{sys_listmount, sys_statmount};

/// A registered filesystem.
///
/// A `usize` holding an `fs_ops` table's address until 2026-09-11, with the
/// typed pointer reconstructed at each use. It is the handle itself now —
/// `&'static FsHandle` is `Sync` because a filesystem is, so there is nothing
/// left for the integer to be working around.
#[derive(Clone, Copy)]
struct Fs(&'static ffi::FsHandle);

// The four this kernel is built with, named as ordinary dependencies since
// 2026-09-09. They were four `extern "C"` statics under a keep-c-abi marker,
// and the marker gave two reasons.
//
// The first was a **cycle**: `crates/fs/proc` called this crate's
// `fs_registered_name` for `/proc/filesystems`, so `use proc::procfs` closed a
// loop. That one call is a hook now — `proc::set_registered_name_hook`,
// installed below — and it was the whole of that crate's dependency on this
// one, so the loop is gone rather than routed around.
//
// The second was size: "a `use` pulls four filesystems' object code into
// anything that links this crate, including its own test binary, for four
// pointers". That was never what the declarations bought. `FILESYSTEMS` holds a
// pointer to each table and each table holds function pointers into its
// filesystem, so the linker keeps all four either way; what an `extern` static
// removed was the compiler's ability to check the type, and it cost a
// `#[no_mangle] static realfs` **duplicate** in this crate's own test binary
// (`tools/dup-stubs.py` reported it).
/// Which filesystems a guest may name in `mount(2)`.
///
/// A `Vec`, where the C had a fixed array of ten with an `assert(!"reached
/// filesystem limit")` at the end of it. There is no reason for a limit: the
/// list is written once at startup and read on every mount.
static FILESYSTEMS: Mutex<Vec<Fs>> = Mutex::new(Vec::new());

/// Put the four this kernel is built with in the list, and tell procfs how to
/// read it.
///
/// **Called explicitly, from `become_first_process`.** It was seeded on first
/// use until 2026-09-09, on the argument that nothing should then depend on an
/// initialiser running before the first `mount(2)`. That argument had a hole
/// the whole time and this change fell in it: the *reader* triggered the
/// seeding, so `/proc/filesystems` worked only because
/// `fs_registered_name` went through `filesystems()`. Nothing mounts procfs
/// through this crate — `crates/tools/iul` and every embedder call
/// `fs_mount::do_mount` with the table directly — so with the read moved behind
/// a hook, a guest that never called `mount(2)` saw an **empty**
/// `/proc/filesystems`. `guest_tests.sh`'s `proc status` caught it.
///
/// An explicit call at a point that always runs is the fix, and it is the
/// honest shape anyway: a registry seeded by whoever assembles the kernel,
/// rather than by whoever happens to read it first. Idempotent, so an embedder
/// that calls `become_first_process` twice gets one list.
pub fn register_default_filesystems() {
    let mut list = FILESYSTEMS.lock().unwrap_or_else(|e| e.into_inner());
    if !list.is_empty() {
        return;
    }
    // `/proc/filesystems` reads this list and procfs is in it, so the crate
    // that owns the file is told how to read the registry rather than
    // depending on it -- which is what let the four tables below become
    // ordinary dependencies. See `crates/fs/proc`'s `FS_NAMES`.
    proc::set_registered_name_hook(fs_registered_names);
    list.extend([
        Fs(&realfs::realfs),
        Fs(&proc::procfs),
        Fs(&devpts::devptsfs),
        Fs(&tmpfs::tmpfs),
    ]);
}

fn filesystems() -> std::sync::MutexGuard<'static, Vec<Fs>> {
    FILESYSTEMS.lock().unwrap_or_else(|e| e.into_inner())
}

/// The names of the registered filesystems, for `/proc/filesystems`.
///
/// One per index with null past the end until 2026-10-17, so a filesystem with
/// no name would have ended the list early; none is registered, and none is
/// skipped now either way.
pub fn fs_registered_names() -> Vec<&'static CStr> {
    filesystems().iter().filter_map(|fs| fs.0.0.name()).collect()
}

/// The filesystem with this name.
///
/// A filesystem with no name cannot be reached from here at all, which is what
/// `FsOps::name` answering `None` means — the ad-hoc ones are not registered
/// and were never in this list. It used to be a null `name` field skipped by a
/// null check.
fn fs_by_name(name: &[u8]) -> Option<&'static ffi::FsHandle> {
    filesystems()
        .iter()
        .find(|fs| fs.0.0.name().is_some_and(|n| n.to_bytes() == name))
        .map(|fs| fs.0)
}

// ---------------------------------------------------------------------------
// The syscalls
// ---------------------------------------------------------------------------

/// The flags `mount(2)` accepts at all. Anything else is `EINVAL` rather than
/// silently dropped, so a caller asking for `MS_BIND` finds out it did not
/// happen.
const MS_SUPPORTED: u32 =
    ffi::MS_READONLY_ | ffi::MS_NOSUID_ | ffi::MS_NODEV_ | ffi::MS_NOEXEC_ | ffi::MS_SILENT_;
/// The subset a mount actually stores. `MS_SILENT` only asks for quieter
/// kernel logging, which this has no equivalent of.
const MS_FLAGS: u32 = ffi::MS_READONLY_ | ffi::MS_NOSUID_ | ffi::MS_NODEV_ | ffi::MS_NOEXEC_;

const MS_REC: u32 = 0x4000;
const MS_UNBINDABLE: u32 = 1 << 17;
const MS_PRIVATE: u32 = 1 << 18;
const MS_SLAVE: u32 = 1 << 19;
const MS_SHARED: u32 = 1 << 20;
const PROPAGATION: u32 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;

/// `mount(2)` with a propagation type: Linux's `do_change_type`, which reads
/// neither the source nor the type. One type, with `MS_REC` and `MS_SILENT`
/// the only company it may have, on a path where something is mounted.
///
/// Every mount here is private: none receives or sends mounts to a peer. So
/// `MS_PRIVATE` is what already is, and `MS_SLAVE` and `MS_UNBINDABLE`
/// differ from it only by a peer to receive from and by `MS_BIND`, neither of
/// which there is. `MS_SHARED` would need peer groups, which are not built:
/// `EINVAL`, as from a kernel that refuses it, rather than a success after
/// which a mount does not propagate.
fn change_type(point_addr: u64, flags: u32) -> Result<(), Errno> {
    let kind = flags & PROPAGATION;
    if kind.count_ones() != 1 || flags & !(PROPAGATION | MS_REC | ffi::MS_SILENT_) != 0 {
        return Err(Errno::EINVAL);
    }
    let point_raw = read_path(point_addr)?;
    strace!("mount(.., {:?}, .., {flags:#x}, ..)", String::from_utf8_lossy(as_str(&point_raw)));
    // The path has to exist (`ENOENT`) before it can be a mount point.
    let mut st = ffi::statbuf::default();
    let err = fs_generic::generic_statat(ffi::At::Pwd, cstr(&point_raw), &mut st, true);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    let point = resolved(&point_raw, ffi::N_SYMLINK_FOLLOW)?;
    if !fs_mounttable::is_mount_point(cstr(&point)) || kind == MS_SHARED {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Reads a NUL-terminated guest string into a buffer of `MAX_PATH`.
fn read_path(addr: u64) -> Result<Vec<u8>, Errno> {
    let mut raw = vec![0u8; ffi::MAX_PATH as usize];
    let err = mmapcalls::usermem::read_current_string(addr, &mut raw);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    Ok(raw)
}

fn as_str(raw: &[u8]) -> &[u8] {
    &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())]
}

pub fn sys_mount(
    source_addr: u64,
    point_addr: u64,
    type_addr: u64,
    flags: u32,
    data_addr: u64,
) -> Result<(), Errno> {
    // CAP_SYS_ADMIN on Linux, and nothing checked it here. See this module's
    // comment for what an unprivileged mount could do.
    if !taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    if flags & PROPAGATION != 0 {
        return change_type(point_addr, flags);
    }
    let source = read_path(source_addr)?;
    let point_raw = read_path(point_addr)?;
    // A null data pointer is "no options", not a fault: mount(2)'s fifth
    // argument is filesystem-specific and most callers pass NULL.
    let data = if data_addr != 0 {
        read_path(data_addr)?
    } else {
        vec![0u8; 1]
    };
    // A type name is a short identifier, not a path.
    let mut type_raw = [0u8; 100];
    let err = mmapcalls::usermem::read_current_string(type_addr, &mut type_raw);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }

    strace!(
        "mount({:?}, {:?}, {:?}, {flags:#x}, {:?})",
        String::from_utf8_lossy(as_str(&source)),
        String::from_utf8_lossy(as_str(&point_raw)),
        String::from_utf8_lossy(as_str(&type_raw)),
        String::from_utf8_lossy(as_str(&data)),
    );

    if flags & !MS_SUPPORTED != 0 {
        return Err(Errno::EINVAL);
    }

    let Some(fs) = fs_by_name(as_str(&type_raw)) else {
        return Err(Errno::EINVAL);
    };

    // The point has to exist and has to be a directory, and both questions are
    // asked before anything is allocated.
    let mut stat = ffi::statbuf::default();
    let err = fs_generic::generic_statat(ffi::At::Pwd, cstr(&point_raw), &mut stat, true);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    if stat.mode & ffi::S_IFMT != ffi::S_IFDIR {
        return Err(Errno::ENOTDIR);
    }

    let point = resolved(&point_raw, ffi::N_SYMLINK_FOLLOW)?;

    // No outer lock: `mounts_insert` takes the table's own, and holding a
    // global one across a filesystem's mount is the hazard the umount path was
    // taken apart for.
    fs_mount::mount(fs.0, cstr(&source), cstr(&point), cstr(&data), (flags & MS_FLAGS) as c_int)
        .map_err(Errno::from_negative_or_eio)
}

/// `umount2`'s only flag here: resolve the target without following a final
/// symlink.
const UMOUNT_NOFOLLOW: u32 = 8;

pub fn sys_umount2(target_addr: u64, flags: u32) -> Result<(), Errno> {
    // CAP_SYS_ADMIN, as for mount.
    if !taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let target_raw = read_path(target_addr)?;
    strace!(
        "umount2({:?}, {flags:#x})",
        String::from_utf8_lossy(as_str(&target_raw))
    );
    let follow = if flags & UMOUNT_NOFOLLOW != 0 {
        ffi::N_SYMLINK_NOFOLLOW
    } else {
        ffi::N_SYMLINK_FOLLOW
    };
    let target = resolved(&target_raw, follow)?;

    // `umount` takes the table's lock itself -- it has to, so that finding
    // the mount and committing to removing it are one step -- and releases it
    // on every path out. Taking it here as well deadlocked the calling thread
    // against itself on every umount(2): lock_t is not recursive.
    fs_mount::umount(cstr(&target)).map_err(Errno::from_negative_or_eio)
}

/// A buffer `read_path` filled, up to its terminator.
fn cstr(raw: &[u8]) -> &CStr {
    CStr::from_bytes_until_nul(raw).unwrap_or(c"")
}

/// A guest path resolved against this task, NUL-terminated.
fn resolved(raw: &[u8], follow: u32) -> Result<Vec<u8>, Errno> {
    let mut path = fs_generic::normalize::resolve(ffi::At::Pwd, cstr(raw).to_bytes(), follow as c_int)
        .map_err(Errno::from_negative_or_eio)?
        .path;
    path.push(0);
    Ok(path)
}

/* `mod stub_filesystems` was here: four `#[no_mangle] pub static` doubles of
 * the filesystem tables, one of them a live duplicate of
 * `crates/fs/realfs`'s. They existed because the four tables were `extern "C"`
 * statics here, so a test binary had to resolve the symbols; the note beside
 * `realfs` said removing it "links the real table instead and that needs
 * `fakefs_bind_mount_resolve_path` and `file_locks_destroy`, which nothing here
 * provides".
 *
 * Both of those are gone as of 2026-09-09 — one is a direct call into
 * `crates/fs/bindmount`, the other a hook — so the real tables link, and the
 * test below asserts the names the *product* registers rather than four names
 * this module wrote down. */

#[cfg(test)]
mod tests {
    use super::*;

    /// The four filesystems a guest can name without an embedder registering
    /// anything.
    #[test]
    fn the_default_filesystems_are_registered_and_named() {
        register_default_filesystems();
        assert_eq!(fs_registered_names(), [c"real", c"proc", c"devpts", c"tmpfs"]);
    }

    /// Looking one up by name, which is what `mount(2)`'s type argument does.
    ///
    /// Seeds first, and that is not boilerplate: the registry was seeded on
    /// first read until 2026-09-09, so a test that did not seed passed or
    /// failed depending on **which test in this binary ran first**. It found
    /// out the hard way — this one went red the moment the seeding became
    /// explicit, and `cargo test` stops at the first failing binary, so the
    /// suite's total dropped from 1968 to 427 with no other signal.
    #[test]
    fn a_filesystem_is_found_by_its_exact_name() {
        register_default_filesystems();
        assert!(fs_by_name(b"tmpfs").is_some());
        assert!(fs_by_name(b"real").is_some());
        // Not a prefix and not a suffix: the whole name is the comparison, so
        // "tmp" and "tmpfs2" are neither of them tmpfs.
        assert!(fs_by_name(b"tmp").is_none());
        assert!(fs_by_name(b"tmpfs2").is_none());
        assert!(fs_by_name(b"").is_none());
        // ext4 is a real filesystem and not one of these.
        assert!(fs_by_name(b"ext4").is_none());
    }

    /// The supported set, and the subset a mount stores.
    ///
    /// `MS_SILENT` is accepted and not stored, which is right: it asks for
    /// quieter kernel logging and there is no logging here to quieten. Every
    /// other bit is refused, so a caller asking for `MS_BIND` — which this
    /// does not do — finds out rather than being told it worked.
    #[test]
    fn only_five_mount_flags_are_accepted_and_four_are_kept() {
        assert_eq!(MS_SUPPORTED & !MS_FLAGS, ffi::MS_SILENT_);
        assert_ne!(MS_FLAGS & ffi::MS_READONLY_, 0);
        assert_ne!(MS_FLAGS & ffi::MS_NOSUID_, 0);
        assert_ne!(MS_FLAGS & ffi::MS_NODEV_, 0);
        assert_ne!(MS_FLAGS & ffi::MS_NOEXEC_, 0);
        // MS_BIND is 0x1000 on Linux and is not in the set.
        assert_eq!(MS_SUPPORTED & 0x1000, 0);
    }

    /// A guest string is whatever precedes the first NUL, and a buffer with no
    /// NUL at all is the whole buffer rather than a read past the end.
    #[test]
    fn a_guest_string_stops_at_its_terminator() {
        assert_eq!(as_str(b"tmpfs\0\0\0"), b"tmpfs");
        assert_eq!(as_str(b"\0rest"), b"");
        assert_eq!(as_str(b"no terminator"), b"no terminator");
        assert_eq!(as_str(b""), b"");
    }

    /// Seeding the registry tells procfs how to read it, and nothing else can
    /// catch it if it stops.
    ///
    /// `/proc/filesystems` would be **empty** rather than wrong — an empty
    /// hook and an empty registry produce the same file — so no assertion about
    /// its contents distinguishes a missing install. `mount -t ext4` would
    /// still fail with the same error a guest gets for a filesystem this kernel
    /// does not have.
    ///
    /// The seeding is what installs it, and `become_first_process` is what
    /// calls the seeding — which is the part `guest_tests.sh` caught missing
    /// when the seeding was lazy and nothing triggered it.
    #[test]
    fn seeding_the_registry_tells_procfs_how_to_read_it() {
        register_default_filesystems();
        assert!(proc::registered_name_hook_installed());
    }
}
