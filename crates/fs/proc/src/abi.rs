//! `struct proc_entry`, `struct proc_dir_entry` and `struct proc_children`.
//!
//! These are procfs's own, and this crate is procfs. `fs/proc.h` declared them
//! until 2026-09-08 and the only thing that read that header was this crate's
//! `build.rs` — so it was a Rust definition written in C, and every rebuild
//! paid a bindgen run over sixteen headers to get it back.
//!
//! `struct proc_data` is not here. It is [`crate::data::ProcData`], a `Vec` and
//! a flag, and has been since 2026-09-05.
//!
//! # There are no raw pointers in either of them, since 2026-09-16
//!
//! Both types carried the C's, for as long as they had been Rust's: a
//! `*mut proc_dir_entry` for the table row, a `*const c_char` for its name, and
//! eight callbacks taking `*mut proc_entry` and `*mut proc_data`. None of it
//! crossed a language boundary — no header declares either struct, nothing
//! outside this crate names one, and the callbacks are plain Rust `fn`
//! pointers.
//!
//! What the pointers cost was that **every one of them erased a borrow the
//! caller already had**. `readlink(&mut entry, &mut target)` was already
//! passing a `&mut` and coercing it; `meta` was written in nine places and
//! every one of them is `(&raw const <a static>).cast_mut().cast()` — take the
//! address of a `static`, throw away the `const`, then cast between a
//! `#[repr(transparent)]` newtype and its field. Three conversions to say
//! `&PROC_PID_FD.0`.
//!
//! So the callbacks take borrows, `meta` is an `Option<&'static
//! proc_dir_entry>` and `name` an `Option<&'static CStr>`, and the eight
//! callbacks are **safe** `fn` — a `proc_entry` no longer has a field whose
//! validity a caller has to promise. `readdir` answers `Option<proc_entry>`
//! rather than writing through an out-parameter and returning a `bool`.
//!
//! `parent` is deleted. It was written null in `blank()` and **read nowhere**:
//! a field from the C that nothing has used for as long as this was Rust.

#![allow(non_camel_case_types)]

use crate::data::ProcData as proc_data;
use taskview::ffi::{mode_t_, off_t, pid_t_, sdword_t};

type ProcRead = fn(entry: &mut proc_entry, buf: &mut [u8], off: off_t) -> isize;
type ProcWrite = fn(entry: &mut proc_entry, buf: &[u8], off: off_t) -> isize;
type ProcMagic = fn(entry: &mut proc_entry) -> Result<Option<crate::ffi::FdOwned>, std::ffi::c_int>;

/// One open thing in `/proc`: which entry it is, and which pid or descriptor it
/// is about.
///
/// `pid` and `fd` are what make a single `proc_dir_entry` serve every process:
/// the entry says *what* `/proc/<pid>/status` prints and this says *whose*.
///
/// # It owns its two strings, and did not until 2026-09-14
///
/// `name` was a `*mut c_char` and `child_names` a `libc::malloc`'d
/// NUL-terminated array of them, balanced by **fourteen hand-written
/// `cleanup(&mut entry)` calls** on every path of every lookup, readdir and
/// open — the shape `MountRef` and `Owned` already replaced for mounts and
/// descriptors. They are Rust's now, so the balance is `Drop`'s and there is
/// nothing to forget.
///
/// `#[repr(C)]` and the six offset assertions went with them. They were kept
/// because "the entries are still reached through `extern "C"` signatures",
/// which had stopped being true: nothing outside this crate names this type,
/// no header declares it, and the table's function pointers are plain
/// `unsafe fn`. A layout nothing depends on is not a contract, and the
/// assertions were the cost of pretending it was — `Option<CString>` is one
/// niche-optimised pointer and `Vec<CString>` is three, so the numbers could
/// not have stayed anyway.
#[derive(Debug, Default, Clone)]
pub struct proc_entry {
    /// The table row this is an instance of.
    ///
    /// `None` only for a default-constructed one, which is what `readdir`'s
    /// caller used to hand in as an out-parameter and no longer does; every
    /// entry a lookup answers has a row. The tables are `static`, which is
    /// what the lifetime says and what the nine `(&raw const …).cast_mut()`
    /// sites were each saying by hand.
    pub meta: Option<&'static proc_dir_entry>,
    pub index: std::ffi::c_ulong,
    /// The names a directory's `readdir` is walking, when it had to ask an
    /// embedder for them. Empty for every entry but `/proc/iul/defaults`.
    pub child_names: Vec<std::ffi::CString>,
    /// This entry's own name, when it is computed rather than in the table.
    pub name: Option<std::ffi::CString>,
    pub pid: pid_t_,
    pub fd: sdword_t,
}

impl proc_entry {
    /// The name as the embedder hooks take it: a `*const c_char`, or null.
    ///
    /// The pointer is valid while `self` is, which is what the hooks need —
    /// each is called and returns before this entry can move.
    pub fn name_ptr(&self) -> *const std::ffi::c_char {
        self.name
            .as_ref()
            .map_or(std::ptr::null(), |n| n.as_ptr())
    }
}

/// What a name in `/proc` *is*: a mode and whichever of these operations it
/// answers.
///
/// Every pointer is optional and most entries set one or two. Which ones are
/// set is what distinguishes a file from a directory from a symlink here —
/// `children` or `readdir` makes it a directory, `readlink` a symlink.
///
/// **A table of records, not a vtable, which is why it stays `Option<fn>`.**
/// `/proc`'s tree is arrays of these: each row is a name and the two or three
/// things that name answers, and a trait would mean one type per row. What did
/// go on 2026-09-09 is the C pretence — `#[repr(C)]` and `extern "C"` on eight
/// fields nothing outside Rust fills.
#[derive(Debug, Default, Copy, Clone)]
pub struct proc_dir_entry {
    /// The name, when it is in the table. `None` for a row whose name is
    /// computed — the numbered entries under `/proc/<pid>/fd` — which is what
    /// `getname` is for and was a null pointer to say.
    pub name: Option<&'static std::ffi::CStr>,
    pub mode: mode_t_,
    /// A file whose *name* is computed, for the numbered entries under
    /// `/proc/<pid>/fd`.
    pub getname: Option<fn(entry: &mut proc_entry, buf: &mut [u8])>,
    /// The whole contents, built in one go.
    pub show: Option<fn(entry: &mut proc_entry, data: &mut proc_data) -> std::ffi::c_int>,
    /// A write.
    pub update: Option<fn(entry: &mut proc_entry, data: &mut proc_data) -> std::ffi::c_int>,
    /// A buffer and a length, not a `proc_data`: these two work in the
    /// *caller's* memory. The C reused one struct for that by pointing its
    /// `data` at the caller's buffer and its `capacity` at the caller's length;
    /// `ProcData` owns a `Vec` and cannot borrow, which is what made the
    /// pretence visible.
    pub pread: Option<ProcRead>,
    pub pwrite: Option<ProcWrite>,
    pub readlink: Option<fn(entry: &mut proc_entry, buf: &mut [u8]) -> std::ffi::c_int>,
    /// The open file this link stands for, when it has no name to follow,
    /// or the errno following it answers: see `FsOps::magic_link`.
    /// `fd/<n>`, `ns/*` and `map_files/*` have one.
    pub magic: Option<ProcMagic>,
    /// A magic link: one that stands for a task's open file or directory --
    /// `fd/<n>`, `cwd`, `root`, `exe` -- whatever its text says. See
    /// `FsOps::is_magic_link`, which is what `openat2`'s `RESOLVE_*` flags ask.
    pub jumps: bool,
    pub unlink: Option<fn(entry: &mut proc_entry) -> std::ffi::c_int>,
    /// A directory with a static list.
    ///
    /// A `*mut proc_children` -- a count and a `[proc_dir_entry; 0]` flexible
    /// array member -- until 2026-09-14. The tables could not build one of
    /// those, so `crates/fs/proc` had a second type, `ChildrenRepr<N>`, with
    /// the same two fields and the length they actually have, an offset
    /// assertion pinning the two together and a cast between them at every
    /// table. That is one type rendered twice, which is the shape this tree
    /// has found seven of; a slice is the rendering that needs neither.
    pub children: Option<&'static [proc_dir_entry]>,
    /// A directory whose contents are enumerated one at a time: the entry at
    /// `*index`, having advanced it, or `None` at the end.
    ///
    /// A `bool` and a `*mut proc_entry` out-parameter until 2026-09-16, whose
    /// contract — "fills `next` or answers false" — the `Option` now is. Every
    /// caller already built the out-parameter fresh each time round the loop,
    /// so nothing is copied that was not being written anyway.
    pub readdir:
        Option<fn(entry: &mut proc_entry, index: &mut std::ffi::c_ulong) -> Option<proc_entry>>,
    pub inode: std::ffi::c_int,
    /// Who may use this entry beyond what its mode says: `0` or a negative
    /// guest errno. Asked on every lookup in a directory and on opening it,
    /// on opening a file, and on reading or following a link; stat-ing the
    /// entry itself is not asked, as Linux's `stat` of `/proc/<pid>/maps`
    /// is not.
    pub guard: Option<fn(entry: &proc_entry) -> std::ffi::c_int>,
    /// The other direction: the task's own thread group may search and list
    /// this directory whoever owns it. Linux's `proc_fd_permission`, for
    /// `fd`, which is root's once the process is not dumpable -- and which a
    /// process that has just called `setuid` still lists to close what it
    /// inherited.
    pub own_group_passes: bool,
    /// How a directory's link count is worked out. It is computed on every
    /// path walk through the directory, so none of these lists anything.
    pub links: Links,
    /// In `/proc/<pid>` and not in `/proc/<pid>/task/<tid>`: Linux's
    /// `tgid_base_stuff` entries that `tid_base_stuff` does not have.
    pub process_only: bool,
    /// This row is the thread directory's copy: an entry that answers for the
    /// whole process in `/proc/<pid>` (`io`) answers for the thread here.
    pub in_thread_dir: bool,
}

/// A directory's `st_nlink`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Links {
    /// Linux's 2 plus the subdirectories: those in `children`, and none for a
    /// generated directory (`fd`, `fdinfo`), whose entries are not
    /// directories.
    #[default]
    Subdirs,
    /// 2 plus one per thread: `task`.
    Threads,
    /// 1, "not counted". Linux's sysctl tree, and `/proc` itself, whose
    /// count is every process and would mean walking the pid space.
    One,
}

// The size and thirteen field offsets were asserted here until 2026-09-09,
// because `fs/proc.h` declared this struct and the two renderings had to agree.
// Nothing declares it now: no header, no assembly, and it is not a guest wire
// format -- it is a table of rows describing `/proc`, built and read in this
// crate alone. So there is no layout to agree about, and Rust packs it smaller
// than the C order did.
//
// `proc_entry` above keeps its assertions: it is the runtime object a
// descriptor points at.

// `struct proc_children` was here until 2026-09-14: a count and a
// `[proc_dir_entry; 0]` flexible array member, with three layout assertions and
// a sibling type in `crate::root` that had the same fields and a real length.
// The field above is a slice, so there is no count to keep in step with an
// array, no `as_ptr().add(i)`, and nothing to assert.
