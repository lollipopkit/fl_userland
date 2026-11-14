//! The three filesystems a descriptor with no name lives on.
//!
//! An eventfd, a timerfd, an epoll set, a pipe and a socket are all descriptors
//! nothing can open by path, and each still has to answer `fstat`, `fstatfs`
//! and `/proc/<pid>/fd`. Linux gives them three filesystems — `anon_inodefs`,
//! `pipefs` and `sockfs` — and so does this.
//!
//! # Three, because `fstatfs` reports which
//!
//! Measured against a real arm64 kernel rather than read out of a header:
//!
//! | | magic |
//! | --- | --- |
//! | pipe | `0x50495045` |
//! | socket | `0x534f434b` |
//! | eventfd, timerfd, epoll | `0x09041934` |
//!
//! This was one number for all of them, with a `FIXME` saying it was "wrong for
//! pipes and sockets". The `FIXME` was right, and `0x09041934` is
//! `ANON_INODE_FS_MAGIC` — so it was correct for the three it happened to name
//! and wrong for the two it did not.
//!
//! # The file type is set in both places at once
//!
//! `fd->type` was left zero for every ad-hoc descriptor: `fs/generic.c` is the
//! only other thing that sets it, and only for a path that was opened. So
//! `S_ISFIFO(fd->type)` was false for a pipe and every caller asking that
//! question got the wrong answer — `fadvise64` was one, where Linux answers
//! `ESPIPE` for a FIFO and this reported success. Here one function decides the
//! type and both fields are written from it.


use std::any::TypeId;
use std::collections::HashMap;
use std::ffi::{CStr, c_int};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

mod errno {
    pub use guest_errno::c_int_::EINVAL;
}

/// Which of the three filesystems an ad-hoc descriptor lives on.
///
/// It was `ffi::adhoc_kind`, a `c_uint` with three constants, and every match
/// on it needed a `_ =>` arm that answered "anon" for a fourth value no caller
/// could name — in four places, including the one that decides the file type.
/// An enum has no fourth value, and the facts that differ between the three
/// live on it rather than in four parallel `match`es keyed by the same
/// integer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// `anon_inodefs`: an eventfd, a timerfd, a signalfd, an epoll set, an
    /// inotify instance, a pidfd.
    Anon,
    Pipe,
    Socket,
    /// `nsfs`: a namespace, opened through `/proc/<pid>/ns/<name>`.
    Ns,
}

impl Kind {
    /// What `fstatfs` reports.
    ///
    /// Measured against a real arm64 kernel rather than read out of a header.
    /// This was one number for all three, with a `FIXME` saying it was "wrong
    /// for pipes and sockets" — which was right: `0x09041934` is
    /// `ANON_INODE_FS_MAGIC`, correct for the three it happened to name.
    fn magic(self) -> u32 {
        match self {
            Kind::Anon => 0x0904_1934,
            Kind::Pipe => 0x5049_5045,
            Kind::Socket => 0x534f_434b,
            Kind::Ns => 0x6e73_6673,
        }
    }

    /// The `S_IFMT` bits an ad-hoc descriptor has.
    ///
    /// `Anon` has none. Linux's `alloc_anon_inode` does give one, and matching
    /// it is a separate question from this one.
    fn file_type(self) -> u32 {
        match self {
            Kind::Anon => 0,
            Kind::Pipe => ffi::S_IFIFO,
            Kind::Socket => ffi::S_IFSOCK,
            // `nsfs`'s inodes are `S_IFREG | 0444`.
            Kind::Ns => ffi::S_IFREG,
        }
    }

    /// Whether the descriptor gets an inode number of its own at creation.
    ///
    /// A pipe's two ends **share** one, which only their creator can arrange:
    /// `crates/fs/pipecalls` asks [`adhoc_next_inode`] once for the pair.
    fn own_inode(self) -> bool {
        matches!(self, Kind::Socket)
    }

    fn filesystem(self) -> &'static fs_mounttable::DetachedMount {
        match self {
            Kind::Anon => &ANON_FS,
            Kind::Pipe => &PIPE_FS,
            Kind::Socket => &SOCK_FS,
            Kind::Ns => &NS_FS,
        }
    }

    /// What `/proc/<pid>/fd/<n>` reads back, as Linux spells it.
    ///
    /// Measured by `procfs_probe` against a real kernel: `pipe:[ino]`,
    /// `socket:[ino]`, and for an anonymous inode `anon_inode:` followed by
    /// the kind's name, which has brackets for every kind but `inotify`.
    fn proc_name(self, inode: u64, anon: Option<&CStr>) -> String {
        match self {
            Kind::Pipe => format!("pipe:[{inode}]"),
            Kind::Socket => format!("socket:[{inode}]"),
            Kind::Ns => format!("{}:[{inode}]", anon.map_or(std::borrow::Cow::Borrowed("?"), CStr::to_string_lossy)),
            Kind::Anon => match anon {
                Some(name) => format!("anon_inode:{}", name.to_string_lossy()),
                None => "anon_inode:[unknown]".to_string(),
            },
        }
    }

    /// Which one this descriptor is on, or `None` for a descriptor that is not
    /// ad-hoc at all.
    ///
    /// The mount *is* the tag, so this is an address comparison — but it
    /// answers an `Option` where the version before it answered `Anon` for a
    /// descriptor on any other filesystem, and a separate `is_adhoc_fd`
    /// existed to ask the question this one now answers.
    pub fn of(fd: &ffi::fd) -> Option<Kind> {
        [Kind::Anon, Kind::Pipe, Kind::Socket, Kind::Ns]
            .into_iter()
            .find(|k| std::ptr::eq(fd.mount, k.filesystem().as_ptr()))
    }
}

/// A `mount` and its `fs_ops`, both **leaked onto the heap**.
///
/// Not `static`s holding the structs by value, which is what this was first and
/// which was undefined behaviour: the mount has to point at the ops, the address
/// of a `LazyLock`'s contents is not known until it has been placed, and filling
/// the pointer in afterwards means writing through a `&'static self`. The C then
/// writes the refcount through the same pointer.
///
/// A release build with LTO acts on the `noalias` a shared reference implies.
/// The debug build was fine and the release build hung in `fd_finalize` at
/// process exit — the same shape as the `timerfd` blocking read that held a
/// `&mut` across a wait, and as
/// `docs/changelog/2026-08-31-a-release-build-hung-closing-a-descriptor.md`.
///
/// `Box::into_raw` is the fix rather than an `UnsafeCell`, because what the C
/// needs is a `*mut` that no live Rust reference aliases. The allocation is
/// never freed: there are three, and they outlive every descriptor on them,
/// which is the life of the process.
/// The three ad-hoc filesystems, which differ only in their magic number.
///
/// A struct with a field rather than three copies of a table: the magic used
/// to be `fs_ops.magic`, a data field in a heap-allocated table, and all three
/// tables were otherwise identical.
struct AdhocFs {
    magic: u32,
}

impl ffi::FsOps for AdhocFs {
    /// **None on purpose.** These are not registered filesystems: none appears
    /// in `/proc/filesystems`, none can be named to `mount(2)`, and the mounts
    /// behind them are private and never in the mount table. It was a `name`
    /// field left at null, which reads the same as one nobody filled in.
    fn name(&self) -> Option<&'static std::ffi::CStr> {
        None
    }
    fn magic(&self) -> u32 {
        self.magic
    }
    fn fstat(&self, fd: &ffi::fd) -> Option<Result<ffi::statbuf, c_int>> {
        Some(adhoc_fstat(fd))
    }
    fn fsetattr(&self, fd: &ffi::fd, attr: ffi::Attr) -> c_int {
        adhoc_fsetattr(fd, attr)
    }
    fn getpath(&self, fd: &ffi::fd, buf: &mut [u8]) -> c_int {
        adhoc_getpath(fd, buf)
    }
}

/// One of the three mounts, leaked for the life of the process: a
/// [`fs_mounttable::DetachedMount`], whose comment has the reason it is on the
/// heap and not a `static`.
fn filesystem(kind: Kind) -> fs_mounttable::DetachedMount {
    // Leaked, like the mount: `mount->fs` is a `&'static dyn FsOps`, and
    // there are three of these for the life of the process.
    let fs: &'static AdhocFs = Box::leak(Box::new(AdhocFs {
        magic: kind.magic(),
    }));
    fs_mounttable::DetachedMount::leak(fs, fs_mounttable::next_mount_id())
}

static ANON_FS: std::sync::LazyLock<fs_mounttable::DetachedMount> =
    std::sync::LazyLock::new(|| filesystem(Kind::Anon));
static PIPE_FS: std::sync::LazyLock<fs_mounttable::DetachedMount> =
    std::sync::LazyLock::new(|| filesystem(Kind::Pipe));
static SOCK_FS: std::sync::LazyLock<fs_mounttable::DetachedMount> =
    std::sync::LazyLock::new(|| filesystem(Kind::Socket));
static NS_FS: std::sync::LazyLock<fs_mounttable::DetachedMount> =
    std::sync::LazyLock::new(|| filesystem(Kind::Ns));

/// Inode numbers for pipes and sockets, which `/proc/<pid>/fd` names by
/// number -- `pipe:[12345]` -- and which is how `lsof` and `ss` pair a
/// pipe's two ends and match a socket to its `/proc/net` line. Unique for
/// the life of the process, never reused, and starting above the numbers a
/// small root filesystem's files have so that a pipe and a file are not
/// confused by a program comparing inodes across mounts.
static NEXT_INODE: AtomicU64 = AtomicU64::new(1 << 20);

/// The one inode every anonymous descriptor shares: Linux's `anon_inode_inode`,
/// which `anon_inode_getfile` hands to an eventfd, an epoll set, a timerfd, a
/// signalfd and an inotify instance alike, so `fstat` answers one nonzero
/// number for all of them. It answered 0 (`fdinfo_probe`). A pidfd has an
/// inode of its own, which `crates/kernel/pidfdcalls` sets.
static ANON_INODE: std::sync::LazyLock<u64> = std::sync::LazyLock::new(adhoc_next_inode);

/// A fresh inode number for a pipe or a socket.
pub fn adhoc_next_inode() -> u64 {
    NEXT_INODE.fetch_add(1, Ordering::Relaxed)
}

/// What an anonymous descriptor is called, by its driver: Linux's
/// `anon_inode_getfd` takes a name per kind and `/proc/<pid>/fd` shows it as
/// `anon_inode:<name>`. The creator says which at creation, and every
/// descriptor with the same driver is the same kind.
///
/// Keyed by `TypeId` since 2026-09-11. It was the operation table's *address*,
/// which said the same thing only for as long as each driver was one heap or
/// static object; a driver is a type now, and two values of one type are the
/// same kind whether or not they share an address.
static ANON_NAMES: Mutex<Option<HashMap<TypeId, &'static CStr>>> = Mutex::new(None);

fn anon_name(ops: Option<&'static dyn ffi::FdOps>) -> Option<&'static CStr> {
    let id = ops?.as_any().type_id();
    let guard = ANON_NAMES.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref()?.get(&id).copied()
}

/// A descriptor of `kind` on its private mount, not yet published: the
/// caller fills in what the driver needs and calls [`fs_fdobj::NewFd::publish`]
/// or `into_owned`.
///
/// It answered a published `*mut fd`, null for "out of memory", and was an
/// `unsafe fn` "called on a guest thread" with nothing in it that needed one;
/// every caller then installed its driver state through the raw pointer.
pub fn adhoc_new(ops: Option<&'static dyn ffi::FdOps>, kind: Kind) -> fs_fdobj::NewFd {
    let mut fd = fs_fdobj::NewFd::new(ops);
    fd.set_mount(kind.filesystem().retain());
    fd.stat = ffi::statbuf::default();
    if kind.own_inode() {
        fd.stat.inode = adhoc_next_inode();
    } else if kind == Kind::Anon {
        fd.stat.inode = *ANON_INODE;
    }
    // Both places that record a file type, set together and from one source.
    fd.type_ = kind.file_type() as _;
    fd.stat.mode = kind.file_type();
    // **Readable and writable**, which is what Linux's `anon_inode_getfd`
    // gives every one of these: an eventfd, a timerfd, a signalfd, an epoll
    // set, an inotify instance and a pidfd all report `O_RDWR` from
    // `fcntl(F_GETFL)` there. The flags were left at zero, which is
    // `O_RDONLY`, and that is visible two ways -- through `F_GETFL`, and
    // through the errno a `write` to one answers, since "not open for writing"
    // is `EBADF` and "open for writing with no write method" is `EINVAL`. A
    // `write` to a timerfd was the second and read as the first.
    fd.set_flags(fd.flags() | ffi::O_RDWR_);
    fd
}

/// An anonymous descriptor -- an eventfd, an epoll set, a timerfd -- with the
/// name `/proc/<pid>/fd` shows for its kind, spelled as Linux spells it in
/// `anon_inode_getfd`: `[eventfd]`, `[eventpoll]`, `inotify`. `None` for a
/// descriptor with no kind to name, which reads back as `[unknown]`.
pub fn adhoc_anon(ops: Option<&'static dyn ffi::FdOps>, name: Option<&'static CStr>) -> fs_fdobj::NewFd {
    if let (Some(name), Some(ops)) = (name, ops) {
        let mut guard = ANON_NAMES.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .get_or_insert_with(HashMap::new)
            .entry(ops.as_any().type_id())
            .or_insert(name);
    }
    adhoc_new(ops, Kind::Anon)
}

fn adhoc_fstat(fd: &ffi::fd) -> Result<ffi::statbuf, c_int> {
    // `fd.stat` is the creation-time copy, which nothing writes after the
    // descriptor is published; the three a `fchmod` or `fchown` can change are
    // read back from their atomics. Before 2026-09-15 this was `*stat =
    // fd.stat` alone, racing `adhoc_fsetattr`'s writes into that same struct.
    let mut stat = fd.stat;
    stat.mode = fd.attr_mode();
    stat.uid = fd.attr_uid();
    stat.gid = fd.attr_gid();
    Ok(stat)
}

/// A **safe** `fn` taking `&fd` since 2026-09-15, which is what took the last
/// `*mut fd` out of [`ffi::FsOps`]. The three fields it writes are atomics on
/// the descriptor now rather than fields of a `statbuf` that `adhoc_fstat`
/// copies whole.
fn adhoc_fsetattr(fd: &ffi::fd, attr: ffi::Attr) -> c_int {
    match attr {
        ffi::Attr::Uid(uid) => fd.set_attr_uid(uid),
        ffi::Attr::Gid(gid) => fd.set_attr_gid(gid),
        // The type bits are the object's and not the caller's: a chmod
        // changes permission, not what the thing is.
        ffi::Attr::Mode(mode) => {
            let old = fd.attr_mode();
            fd.set_attr_mode((old & ffi::S_IFMT) | (u32::from(mode) & !ffi::S_IFMT));
        }
        // There is nothing to truncate.
        ffi::Attr::Size(_) => return errno::EINVAL,
    }
    0
}

/// What `/proc/<pid>/fd/<n>` reads back.
///
/// Bounded by the caller's buffer since 2026-09-14, which is the version of
/// this the comment below was asking for. The longest of these names is about
/// thirty characters, so neither the `sprintf` this replaced nor the unchecked
/// copy that replaced *that* could overrun — but nothing said so, and the next
/// kind of ad-hoc descriptor to be added would have been adding to a format
/// string with no length.
fn adhoc_getpath(fd: &ffi::fd, buf: &mut [u8]) -> c_int {
    // `Anon` for a descriptor that somehow is not on one of the three, which
    // is what the version before this answered for every other filesystem.
    let kind = Kind::of(fd).unwrap_or(Kind::Anon);
    let anon = match kind {
        Kind::Anon => anon_name(fd.ops),
        Kind::Ns => fd.driver_state::<taskview::nsproxy::Ns>().map(|ns| ns.kind().name()),
        _ => None,
    };
    ffi::fill_path(buf, kind.proc_name(fd.stat.inode, anon).as_bytes())
}

/// Whether this descriptor is on one of the three.
///
/// One line over [`Kind::of`], which is the same question with the answer kept.
pub fn is_adhoc_fd(fd: &ffi::fd) -> bool {
    Kind::of(fd).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three magics, measured against a real arm64 kernel. This was one
    /// number for all of them — correct for the three it happened to name and
    /// wrong for the two it did not.
    #[test]
    fn each_filesystem_reports_its_own_magic() {
        assert_eq!(Kind::Anon.magic(), 0x0904_1934);
        // Both are ASCII, which is how they are recognisable in a hexdump and
        // is worth stating because a transposed digit would not be.
        assert_eq!(&Kind::Pipe.magic().to_be_bytes(), b"PIPE");
        assert_eq!(&Kind::Socket.magic().to_be_bytes(), b"SOCK");
        assert_ne!(Kind::Pipe.magic(), Kind::Anon.magic());
        assert_ne!(Kind::Socket.magic(), Kind::Anon.magic());
    }

    /// A pipe is a FIFO and a socket is a socket, whatever they are opened as.
    /// `fd->type` was zero for every one of these, so `S_ISFIFO(fd->type)` was
    /// false for a pipe.
    #[test]
    fn a_kind_decides_the_file_type() {
        assert_eq!(Kind::Pipe.file_type(), ffi::S_IFIFO);
        assert_eq!(Kind::Socket.file_type(), ffi::S_IFSOCK);
        assert_eq!(Kind::Anon.file_type(), 0);
    }

    /// Three distinct mounts. `is_adhoc_fd` compares addresses, so two kinds
    /// sharing one would make `fstatfs` answer the same magic for both — which
    /// is the defect this file had.
    #[test]
    fn the_three_mounts_are_distinct() {
        let a = Kind::Anon.filesystem().as_ptr();
        let p = Kind::Pipe.filesystem().as_ptr();
        let s = Kind::Socket.filesystem().as_ptr();
        assert_ne!(a, p);
        assert_ne!(a, s);
        assert_ne!(p, s);
        // And each is stable: `Kind::of` compares against these addresses long
        // after the descriptor was made.
        assert_eq!(a, Kind::Anon.filesystem().as_ptr());
    }

    /// Each mount points at its own `fs_ops`, and that is what carries the
    /// magic. Filled in when the mount is built, which is possible because the
    /// ops are a separate allocation with an address of their own.
    /// The names `/proc/<pid>/fd` shows, as `procfs_probe` measured them.
    #[test]
    fn a_descriptor_with_no_path_is_named_the_way_linux_names_it() {
        assert_eq!(Kind::Pipe.proc_name(4711, None), "pipe:[4711]");
        assert_eq!(Kind::Socket.proc_name(12, None), "socket:[12]");
        assert_eq!(
            Kind::Anon.proc_name(0, Some(c"[eventfd]")),
            "anon_inode:[eventfd]"
        );
        // inotify is the one Linux spells without brackets.
        assert_eq!(Kind::Anon.proc_name(0, Some(c"inotify")), "anon_inode:inotify");
        assert_eq!(Kind::Anon.proc_name(0, None), "anon_inode:[unknown]");
    }

    /// Two sockets are two inodes, and a number is never handed out twice.
    #[test]
    fn inode_numbers_are_unique_and_never_zero() {
        let a = adhoc_next_inode();
        let b = adhoc_next_inode();
        assert_ne!(a, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn a_mount_reaches_its_own_magic() {
        for kind in [Kind::Anon, Kind::Pipe, Kind::Socket] {
            let m = kind.filesystem().as_ptr();
            let fs =
                unsafe { (*m).fs }.unwrap_or_else(|| panic!("{kind:?} has no filesystem"));
            assert_eq!(fs.magic(), kind.magic(), "{kind:?}");
            // None on purpose: these are not registered filesystems.
            assert!(fs.name().is_none(), "{kind:?}");
        }
    }
}

#[cfg(test)]
mod layout {
    /// `struct fd`'s layout is a contract with the C, and this crate writes
    /// three of its fields through a bindgen view of it. Measured from the C
    /// with `offsetof`.
    #[test]
    fn struct_fd_is_where_the_c_says() {
        use super::ffi;
        // 408 until 2026-09-01, when `struct fd_sockrestart` -- an intrusive
        // list node and a backlog on every descriptor -- left with
        // crates/fs/sockrestart; 384 until 2026-09-04, when the socket member
        // grew three stored options (`stored_opts`) and became the union's
        // largest, which every descriptor pays eight bytes for; 392 until
        // later the same day, when `f_owner` arrived as two ints; 400 until
        // 2026-09-05, when the socket member became a pointer to
        // crates/fs/sock's `SocketState` like every other arm of the union.
        // **Every descriptor was carrying a socket's forty-eight bytes.** 352
        // until 2026-09-07, when `struct statbuf` gained a creation time --
        // `statx(STATX_BTIME)` had answered "I do not know" for every file on
        // every mount, and there was nowhere to put one.
        //
        // Eight bytes and not twenty-four: `int64_t btime`, `dword_t
        // btime_nsec` and `dword_t has_btime` in declaration order cost 24,
        // because a 64-bit field after a 32-bit one needs four bytes of
        // padding and the struct then rounds up. The two 32-bit halves sit in
        // holes the existing timestamps already left and `btime` goes last,
        // where the struct is already 8-aligned. That is why the three are not
        // written next to each other in `fs/stat.h`, and it is worth the eight
        // bytes because `struct fd` embeds one of these.
        // 360 until 2026-09-11, when `ops` became `Option<&dyn FdOps>`: a
        // trait object is a **fat** pointer, so the driver costs sixteen bytes
        // where a `*const fd_ops` cost eight, and every field after it moved.
        // That is the price of the conversion and it is paid per descriptor;
        // what it buys is in `crates/kernel/abi/src/fd_ops.rs`. The same eight
        // bytes were measured on the poll path once before and were not
        // separable.
        // 368 until 2026-09-15, when the three attributes a driver may change
        // after publication became `AtomicU32` on the descriptor: twelve bytes
        // and four of padding. What it buys is that `fchmod` on a pipe no
        // longer races `fstat`'s hundred-byte copy of `stat`, and that
        // `FsOps::fsetattr` takes a `&fd` like every other method of that
        // trait. The alternative -- adhoc keeping its own state behind
        // `fs_data` -- costs an allocation per pipe and socket and a lock on
        // every `fstat`, which is why it was measured and declined.
        // 384 until 2026-09-29, when `change_path` became an
        // `Option<CString>`: a `CString` is a boxed slice, so sixteen bytes
        // where the `char *` was eight. It moved `stat` with it. 392 until
        // `inotify_path` did the same, later that day. 400 until `fs_data`
        // became a `OnceLock<Box<dyn Any>>` the same evening: a fat pointer
        // and the `Once`'s state word, twenty-four bytes where the
        // `AtomicPtr` was eight. What it buys is that each filesystem's state
        // is owned and typed, so a close no longer frees it by hand. 416
        // until `dir` became a `OnceLock<Box<HostDir>>`, the `Once`'s state
        // word beside the pointer. 424 until `union fd_state` became
        // `driver_state`, an `Option<Box<dyn Any>>`: a fat pointer where the
        // union was one thin one. The size itself is asserted once, by
        // `crates/fs/fdobj`'s `the_allocation_is_the_size_the_c_measures`.
        assert_eq!(std::mem::size_of::<ffi::statbuf>(), 120);
        // The union is ahead of `stat`, so it moved with the growth: 152
        // until 2026-09-04, 160 until `f_owner` landed later that day, 168
        // until the socket member shrank, 120 until `ops` became fat, 128
        // until `change_path` did, 136 until `inotify_path` did, 144 until
        // `fs_data` did, 160 until `dir` did, 168 until `driver_state` did,
        // 176 until `unnamed` did.
        assert_eq!(std::mem::offset_of!(ffi::fd, stat), 184);
        // Before `ops`, so this one did not move.
        assert_eq!(std::mem::offset_of!(ffi::fd, type_), 12);
        // Also after the union: 104 until 2026-09-04, 112 until 2026-09-05,
        // 64 until `ops` became fat, 72 until `inotify_path` did (it is ahead
        // of `mount`, which `change_path` is not), 80 until `fs_data` did, 96
        // until `driver_state` did.
        assert_eq!(std::mem::offset_of!(ffi::fd, mount), 104);
    }
}

/// A namespace file's driver. The namespace is the description's driver
/// state, a [`taskview::nsproxy::Ns`]: it is what `setns` joins, and holding
/// it keeps the namespace alive, as an open `nsfs` file does on Linux.
struct NsFile;

static NS_FILE: NsFile = NsFile;

impl ffi::FdOps for NsFile {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::NONE
    }
    /// Opening `/proc/<pid>/fd/<n>` onto one is a new descriptor onto the same
    /// namespace, as `ns_get_path` gives.
    fn reopen(&self, fd: &ffi::fd, _flags: c_int) -> Result<ffi::FdOwned, c_int> {
        let ns = fd.driver_state::<taskview::nsproxy::Ns>().ok_or(errno::EINVAL)?;
        Ok(adhoc_ns(ns.clone()))
    }
}

/// A descriptor onto namespace `ns`: what opening `/proc/<pid>/ns/<name>`
/// answers. `nsfs`'s inode is the namespace's number, `S_IFREG | 0444`, owned
/// by root, and the file is opened read-only.
pub fn adhoc_ns(ns: taskview::nsproxy::Ns) -> fs_fdobj::Owned {
    let mut fd = adhoc_new(Some(&NS_FILE), Kind::Ns);
    fd.stat.inode = ns.inum().into();
    fd.stat.mode = ffi::S_IFREG | 0o444;
    fd.set_flags(fd.flags() & !ffi::O_RDWR_);
    fd.set_driver_state(Box::new(ns));
    fd.into_owned()
}
