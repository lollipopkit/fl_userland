//! `memfd_create(2)`: an anonymous file that lives in memory, and the seals
//! that make it safe to share.
//!
//! It was `syscall_silent_stub` -- `ENOSYS` with no trace -- and every library
//! that asks for one falls back to a file under `/dev/shm` or `/tmp`, which is
//! why nothing failed. What a memfd is *for* is a file with no name that two
//! processes can map shared and that one of them can seal: a Wayland client
//! hands its compositor a buffer it can no longer shrink, wasmtime instantiates
//! a module from a sealed image with copy-on-write mappings.
//!
//! # The file is a host file
//!
//! A `mkstemp` under `TMPDIR`, unlinked at once, so it has no name anywhere and
//! goes when the last descriptor does (`realfs::unlinked_host_file`). What a
//! memfd is mapped with is `MAP_SHARED`, and a host file mapped shared is one
//! set of pages for every guest process, which are all threads of this one
//! host process; this kernel's tmpfs moves a file into one of these when it is
//! first mapped, for the same reason. The descriptor's operations are realfs's -- it *is* a
//! realfs descriptor, with `real_fd` set -- behind three wrappers that ask the
//! seals first: `write`, `pwrite` and `mmap`, and the mount's `fsetattr` for
//! `ftruncate`.
//!
//! # Seals
//!
//! Linux's, from `mm/memfd.c` and `mm/shmem.c`: `F_SEAL_SEAL` stops further
//! sealing, `SHRINK` and `GROW` stop `ftruncate` in one direction each and
//! `GROW` stops a write past the end, `WRITE` and `FUTURE_WRITE` stop writes
//! and new writable shared mappings, `EXEC` takes the execute bits off. A memfd
//! made without `MFD_ALLOW_SEALING` starts with `F_SEAL_SEAL`, so it can never
//! be sealed at all. One thing Linux checks that this does not: `F_SEAL_WRITE`
//! is `EBUSY` while a writable shared mapping exists, which needs a count of
//! them that the page table does not keep per file.
//!
//! The seals live in a [`Memfd`] hung off the descriptor's `fs_data`, which is
//! the slot `struct fd` keeps for whatever a filesystem needs per description;
//! two descriptors from a `dup` share it, as they share the seals on Linux.


use std::ffi::{c_int, c_uint};
use std::sync::atomic::{AtomicU32, Ordering};

use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

mod callbacks;
mod rules;
pub use rules::add_seals;
use rules::{flags_ok, initial_mode, initial_seals};

/// `MFD_*`, from `include/uapi/linux/memfd.h`.
pub mod mfd {
    pub const CLOEXEC: u32 = 0x1;
    pub const ALLOW_SEALING: u32 = 0x2;
    pub const HUGETLB: u32 = 0x4;
    pub const NOEXEC_SEAL: u32 = 0x8;
    pub const EXEC: u32 = 0x10;
    pub const ALL: u32 = CLOEXEC | ALLOW_SEALING | HUGETLB | NOEXEC_SEAL | EXEC;
    /// The huge page size rides in bits 26..31, and only with `HUGETLB`.
    pub const HUGE_MASK: u32 = 0x3f << 26;
    /// `MFD_NAME_MAX_LEN`: `NAME_MAX` less the `memfd:` prefix.
    pub const NAME_MAX_LEN: usize = 249;
}

/// `F_SEAL_*`, from `include/uapi/linux/fcntl.h`.
pub mod seal {
    pub const SEAL: u32 = 0x0001;
    pub const SHRINK: u32 = 0x0002;
    pub const GROW: u32 = 0x0004;
    pub const WRITE: u32 = 0x0008;
    pub const FUTURE_WRITE: u32 = 0x0010;
    pub const EXEC: u32 = 0x0020;
    pub const ALL: u32 = SEAL | SHRINK | GROW | WRITE | FUTURE_WRITE | EXEC;
}

/// What a memfd keeps per open file description.
struct Memfd {
    /// What `/proc/<pid>/fd` and `/proc/<pid>/maps` show, less the
    /// ` (deleted)` every one of these carries: `/memfd:<name>` for a
    /// `memfd_create`, and whatever Linux names the kernel's own -- `/[aio]`
    /// for an AIO ring.
    path: Vec<u8>,
    seals: AtomicU32,
    /// Told when a shared mapping goes, after the count below has come
    /// down. A System V segment is one of these files, and its `nattch` is
    /// that count; this is how the registry learns it may destroy a segment
    /// that `IPC_RMID` marked while it was attached. `crates/kernel/sysvshm`.
    on_unmapped: Option<fn(&ffi::fd)>,
    /// What the kernel made this file for, given back by [`internal_owner`]:
    /// a System V segment's IPC namespace, which `on_unmapped` and `shmdt`
    /// reach the segment through after the task has left it.
    owner: Option<Box<dyn std::any::Any + Send + Sync>>,
    /// The owner: the creator's fs ids, or what `fchown` set since. Kept
    /// here rather than on the host file, whose owner a host user cannot
    /// change and which is the host's user anyway.
    uid: AtomicU32,
    gid: AtomicU32,
    /// Live `MAP_SHARED` mappings made while writes were possible: Linux's
    /// `i_mmap_writable`, counted up in [`memfd_mmap`] and down by the page
    /// table through [`fd_shared_mapping_gone`]. `F_SEAL_WRITE` is `EBUSY`
    /// while it is non-zero.
    shared_maps: AtomicU32,
}

// ------------------------------------------------------------- the descriptor

/// The mount, a [`fs_mounttable::DetachedMount`]. Its address was a `usize`
/// here until 2026-09-29, "reconstructed only at C API boundaries" -- a `*mut`
/// is not `Sync`, which is the whole reason, and that type says it once.
///
/// The descriptor operations used to be a second leaked allocation in here.
/// They are [`MemfdOps`], an ordinary static, because a trait implementation is
/// not something anything writes through.
static MOUNT: std::sync::LazyLock<fs_mounttable::DetachedMount> =
    // Mount id 0, as Linux's: `shm_mnt` is the first mount it makes and its
    // ids are allocated from 0, so a memfd's `stx_mnt_id` and fdinfo
    // `mnt_id:` are 0 there while a pipe's are not (`fdinfo_probe`).
    std::sync::LazyLock::new(|| fs_mounttable::DetachedMount::leak(&MEMFD_FS, 0));

/// `TMPFS_MAGIC`: a memfd is a tmpfs file on Linux, and `fstatfs` says so.
const TMPFS_MAGIC: i32 = 0x0102_1994;

/// A memfd's driver: a host file, so most of it is realfs's, with the four
/// operations that have to know about the sealing and the accounting.
///
/// Delegating by *name* rather than by copying a function pointer out of
/// realfs's table, which is what it did while that was one: a call to
/// `REALFS_FDOPS.read` is the same dispatch and the compiler checks the
/// signature.
struct MemfdOps;

static MEMFD_FDOPS: MemfdOps = MemfdOps;

impl ffi::FdOps for MemfdOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::FILE
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        realfs::REALFS_FDOPS.read(fd, buf)
    }
    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        callbacks::memfd_write(fd, buf)
    }
    fn pread(&self, fd: &ffi::fd, buf: &mut [u8], off: i64) -> isize {
        realfs::REALFS_FDOPS.pread(fd, buf, off)
    }
    fn pwrite(&self, fd: &ffi::fd, buf: &[u8], off: i64) -> isize {
        callbacks::memfd_pwrite(fd, buf, off)
    }
    fn lseek(&self, fd: &ffi::fd, off: i64, whence: c_int) -> i64 {
        realfs::REALFS_FDOPS.lseek(fd, off, whence)
    }
    fn position(&self, fd: &ffi::fd) -> i64 {
        realfs::REALFS_FDOPS.position(fd)
    }
    unsafe fn mmap(&self, fd: &ffi::fd,
        mem: *mut ffi::mem,
        start: ffi::page_t,
        pages: ffi::pages_t,
        offset: i64,
        prot: c_int,
        flags: c_int,
    ) -> Option<c_int> {
        Some(unsafe { callbacks::memfd_mmap(fd, mem, start, pages, offset, prot, flags) })
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        realfs::REALFS_FDOPS.poll(fd)
    }
    /// Yes, by way of realfs: a memfd's contents are a host file and its
    /// readiness is the host's answer about `real_fd`.
    fn poll_follows_host_fd(&self) -> bool {
        realfs::REALFS_FDOPS.poll_follows_host_fd()
    }
    fn ioctl_size(&self, cmd: c_int) -> isize {
        realfs::REALFS_FDOPS.ioctl_size(cmd)
    }
    fn ioctl(&self, fd: &ffi::fd, cmd: c_int, arg: ffi::IoctlArg<'_>) -> c_int {
        realfs::REALFS_FDOPS.ioctl(fd, cmd, arg)
    }
    fn fsync(&self, fd: &ffi::fd) -> c_int {
        realfs::REALFS_FDOPS.fsync(fd)
    }
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        callbacks::memfd_close(fd)
    }
    fn setflags(&self, fd: &ffi::fd, flags: u32) -> c_int {
        realfs::REALFS_FDOPS.setflags(fd, flags)
    }
}

/// A memfd's filesystem: three operations over a host file, and the magic that
/// makes `fstatfs` say tmpfs, which is what a memfd is on Linux.
struct MemfdFs;

static MEMFD_FS: MemfdFs = MemfdFs;

impl ffi::FsOps for MemfdFs {
    /// `tmpfs`, which is what Linux reports for a memfd and what a program
    /// reading `/proc/<pid>/maps` expects to see.
    fn name(&self) -> Option<&'static std::ffi::CStr> {
        Some(c"tmpfs")
    }
    fn magic(&self) -> u32 {
        TMPFS_MAGIC as u32
    }
    fn fstat(&self, fd: &ffi::fd) -> Option<Result<ffi::statbuf, c_int>> {
        Some(callbacks::memfd_fstat(fd))
    }
    fn fsetattr(&self, fd: &ffi::fd, attr: ffi::Attr) -> c_int {
        callbacks::memfd_fsetattr(fd, attr)
    }
    fn getpath(&self, fd: &ffi::fd, buf: &mut [u8]) -> c_int {
        callbacks::memfd_getpath(fd, buf)
    }
}

/// The state of a descriptor, if it is a memfd.
///
/// Borrowed from `fd`, where it claimed `'static`; and the downcast is the
/// type check, where it was a test of `fd.ops` followed by a cast.
fn state(fd: &ffi::fd) -> Option<&Memfd> {
    fd.fs_data::<Memfd>()
}

/// The host file's size, for the seals that compare against it.
fn size_of(fd: &ffi::fd) -> Result<i64, Errno> {
    Ok(host_stat(fd)?.st_size)
}

/// The host file's `stat`, and `EIO` for anything that stops it: the seals
/// that ask have no better errno to give.
fn host_stat(fd: &ffi::fd) -> Result<rustix::fs::Stat, Errno> {
    fd.host()
        .and_then(|host| rustix::fs::fstat(host).ok())
        .ok_or(Errno::EIO)
}

pub fn sys_memfd_create(name_addr: u64, flags: c_uint) -> Result<i64, Errno> {
    flags_ok(flags)?;
    // Huge pages are a property of a host this kernel does not have; Linux
    // without hugetlbfs answers the same.
    if flags & mfd::HUGETLB != 0 {
        return Err(Errno::ENOSYS);
    }
    // `strnlen_user(uname, MFD_NAME_MAX_LEN + 1)`: a fault is EFAULT and a
    // name that does not end within the limit is EINVAL.
    let mut name = [0u8; mfd::NAME_MAX_LEN + 1];
    let len = match GuestMem::current().read_string(name_addr, &mut name) {
        Ok(n) => n,
        Err(e) if e == guest_errno::c_int_::ENAMETOOLONG => return Err(Errno::EINVAL),
        Err(_) => return Err(Errno::EFAULT),
    };
    let name = name[..len].to_vec();
    strace!(
        "memfd_create({:?}, {flags:#x})",
        String::from_utf8_lossy(&name)
    );

    let mut path = b"/memfd:".to_vec();
    path.extend_from_slice(&name);
    let fd = make(path, initial_mode(flags), initial_seals(flags), 0, None, None)?;
    let cloexec = if flags & mfd::CLOEXEC != 0 {
        ffi::O_CLOEXEC_ as c_int
    } else {
        0
    };
    Errno::split(fs_fdobj::f_install(fd, cloexec) as i64)
}

/// The descriptor, made and not installed: one reference, the caller's.
fn make(
    path: Vec<u8>,
    mode: u32,
    seals: u32,
    size: u64,
    on_unmapped: Option<fn(&ffi::fd)>,
    owner: Option<Box<dyn std::any::Any + Send + Sync>>,
) -> Result<fs_fdobj::Owned, Errno> {
    // The page table calls this when the last shared page of a mapping goes.
    // Installed here rather than at boot because this is the only place a
    // descriptor that counts them is made; the first call wins.
    pagetable::set_shared_mapping_gone_hook(fd_shared_mapping_gone);
    // Closed as it drops, on either refusal below.
    let host = realfs::unlinked_host_file(mode).map_err(|_| Errno::ENOMEM)?;
    if size != 0 && rustix::fs::ftruncate(&host, size).is_err() {
        return Err(Errno::ENOMEM);
    }
    let mut fd = fs_fdobj::NewFd::new(Some(&MEMFD_FDOPS));
    let (uid, gid) = taskview::current_fsids();
    let state = Memfd {
        path,
        seals: AtomicU32::new(seals),
        on_unmapped,
        owner,
        uid: AtomicU32::new(uid),
        gid: AtomicU32::new(gid),
        shared_maps: AtomicU32::new(0),
    };
    {
        fd.real_fd = Some(host);
        // **With a reference**, which this did not take until 2026-09-12: the
        // field was assigned straight from the static and `fd_finalize`
        // released it anyway, so every memfd close decremented a count nothing
        // had incremented. Unobservable, because this mount is a leaked `Box`
        // that `mounts_insert` never sees and `mounts_take_point` therefore never
        // asks about --
        fd.set_mount(MOUNT.retain());
        fd.type_ = 0o100000; // S_IFREG
        // `O_LARGEFILE` too, which `memfd_create` opens with and `F_GETFL`
        // reports; it answered `O_RDWR` alone (`fdinfo_probe`).
        fd.set_flags(ffi::O_RDWR_ | ffi::O_LARGEFILE_);
        fd.set_fs_data(state);
        // The inode is where a file's locks live: without one `flock` and
        // `F_SETLK` on a memfd answered `EBADF`, which Linux grants
        // (`fdinfo_probe`).
        let mut st = ffi::statbuf::default();
        if fs_inode::generic_attach_inode(&mut fd, &mut st) < 0 {
            return Err(Errno::ENOMEM);
        }
        Ok(fd.into_owned())
    }
}

/// A memfd the kernel makes for itself: a System V shared memory segment is
/// one, and an AIO ring is another, `size` bytes long and never sealed. Not
/// installed in any table; the caller holds the one reference. The owner is
/// the calling process's fs ids, as for a `memfd_create`.
///
/// `path` is the whole name `/proc` shows before ` (deleted)`, because the
/// kernel's own files are not `memfd:` ones on Linux: an AIO ring's mapping is
/// `/[aio] (deleted)` there.
///
/// `on_unmapped` is called with the descriptor each time a shared mapping
/// of it goes, after [`shared_mappings`] has come down; `owner` is what
/// [`internal_owner`] answers for it.
pub fn create_internal(
    path: &[u8],
    size: u64,
    mode: u32,
    on_unmapped: Option<fn(&ffi::fd)>,
    owner: Option<Box<dyn std::any::Any + Send + Sync>>,
) -> Result<fs_fdobj::Owned, Errno> {
    // `retain` and `release` beside this were the other two halves of the
    // handle it answers, written by hand, until 2026-09-29.
    make(path.to_vec(), mode, 0, size, on_unmapped, owner)
}

/// The `owner` [`create_internal`] was given, if `fd` is such a file and it
/// is a `T`.
pub fn internal_owner<T: std::any::Any>(fd: &ffi::fd) -> Option<&T> {
    state(fd)?.owner.as_deref()?.downcast_ref()
}

/// How many shared mappings of the file are live, if it is a memfd.
pub fn shared_mappings(fd: &ffi::fd) -> Option<u32> {
    state(fd).map(|m| m.shared_maps.load(Ordering::Acquire))
}

/// Whether a shared mapping of `fd` may not become writable: `F_SEAL_WRITE`
/// or `F_SEAL_FUTURE_WRITE` is set. `mprotect` asks, because a read-only
/// shared mapping made under either seal is allowed and a `PROT_WRITE` added
/// to it afterwards would be the write the seal exists to stop -- Linux
/// clears `VM_MAYWRITE` on such a mapping and `mprotect` answers `EACCES`.
pub fn shared_write_sealed(fd: &ffi::fd) -> bool {
    state(fd)
        .is_some_and(|m| m.seals.load(Ordering::Acquire) & (seal::WRITE | seal::FUTURE_WRITE) != 0)
}

pub fn memfd_get_seals(fd: &ffi::fd) -> Result<c_int, Errno> {
    match state(fd) {
        Some(m) => Ok(m.seals.load(Ordering::Acquire) as c_int),
        None => Err(Errno::EINVAL),
    }
}

pub fn memfd_add_seals(fd: &ffi::fd, seals: c_uint) -> Result<(), Errno> {
    let Some(m) = state(fd) else {
        return Err(Errno::EINVAL);
    };
    // A descriptor that cannot write cannot seal: Linux checks FMODE_WRITE
    // before anything else, and a memfd reopened read-only through procfs is
    // such a descriptor.
    if fd.flags() & ffi::O_ACCMODE_ == 0 {
        return Err(Errno::EPERM);
    }
    let executable = callbacks::mode_of(fd)
        .map(|m| m & 0o111 != 0)
        .unwrap_or(false);
    // `fetch_update`'s closure can only say "no", so the reason comes back out
    // through this rather than through its Err -- which carries the value the
    // load saw and not why the rule refused.
    let mut refused = None;
    let updated = m
        .seals
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
            match add_seals(
                cur,
                seals,
                executable,
                m.shared_maps.load(Ordering::Acquire),
            ) {
                Ok(new) => Some(new),
                Err(e) => {
                    refused = Some(e);
                    None
                }
            }
        });
    match (updated, refused) {
        (Err(_), Some(e)) => Err(e),
        _ => Ok(()),
    }
}

/// The page table has dropped the last page of a `MAP_SHARED` mapping of
/// `fd`. Nothing unless `fd` is a memfd; see `kernel/memfd.h`.
pub fn fd_shared_mapping_gone(fd: &ffi::fd) {
    if let Some(m) = state(fd) {
        // Only the mappings that were counted come back down: one made under
        // a write seal was not, and the seal cannot have gone since.
        let _ = m
            .shared_maps
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
        if let Some(tell) = m.on_unmapped {
            tell(fd);
        }
    }
}
