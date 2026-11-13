//! What a descriptor's driver can do: [`FdOps`].
//!
//! # It was a `#[repr(C)]` table of fifteen `Option<fn>` until 2026-09-11
//!
//! `struct fd_ops` held fifteen nullable function pointers, `struct fd` held a
//! `*const fd_ops`, and every call was `(*(*fd).ops).read` — a null test, an
//! `unsafe` call through a pointer read out of guest-adjacent memory, and a
//! fallback nobody had written down. Four things went with it, and only the
//! first is about `unsafe`:
//!
//! - **Fifteen defaults, one per field.** "There might be no `telldir`" was
//!   said once in `crates/fs/dircalls` and answered with `fd->offset`;
//!   "there might be no `fsync`" was said once in `crates/kernel/fdattr` and
//!   answered with success. Both are reasonable and neither was a decision
//!   anybody recorded — they are default method bodies here, with the reason
//!   on them. `Option::None` is not a choice; a default method is.
//!
//! - **Three address comparisons standing in for a question.** `fs/poll`
//!   asked whether a descriptor's `poll` *was* `realfs_poll` to decide whether
//!   readiness comes from a host descriptor, `fs/devices` asked whether it was
//!   `ready_poll`, and `fs/fdobj` asked whether the driver's `close` was the
//!   same function as the mount's so as not to run it twice. All three used
//!   `std::ptr::fn_addr_eq`, which answers "does this behave like that one"
//!   and never "is this the one I mean" — a release link folds two identical
//!   bodies to one address. They are [`FdOps::poll_follows_host_fd`],
//!   [`FdOps::readiness_is_constant`] and [`FdOps::close_covers_mount`] now:
//!   three questions a driver answers about itself.
//!
//!   The `close` one had already cost a bug. `fakefs` replaced
//!   `fd_ops.close` with a cache-freeing function of its own, which broke the
//!   pointer identity that had been suppressing the mount's close, so
//!   `realfs_close` ran twice and closed the host descriptor twice — showing
//!   up as the guest's `closedir` answering `EBADF`. See
//!   `fakefs_does_not_claim_the_mounts_close_and_realfs_does` in
//!   `crates/fs/fake`.
//!
//! - **Nine "is this descriptor mine?" tests by table address.** eventfd,
//!   timerfd, signalfd, inotify, epoll, pidfd, memfd, pipe and sockrestart
//!   each compared `(*fd).ops` against their own table, because a table is one
//!   object and sharing it is what "same kind" meant. That is a downcast, and
//!   it is [`FdOps::as_any`] now — `std::any::Any`, which answers about the
//!   *type* rather than about an address the linker is free to share.
//!
//! - **A table rendered twice.** `dev_ops` embedded an `fd_ops` by value and
//!   `fs/devices` filled four of them field by field at first use, inside a
//!   `LazyLock`, so what `/dev/null` could do was spread over five statements
//!   and a `Default`. The four are unit structs with `impl FdOps` now.
//!
//! # Why `dyn` and not a type parameter
//!
//! A descriptor's driver is chosen at `open` time out of sixteen, and one
//! `struct fd` has to be able to hold any of them, so there is nothing for a
//! type parameter to be. It is also not a cost: the call this replaces already
//! loaded a function pointer out of `fd->ops` and called it indirectly, so a
//! vtable call is the same two loads and the same indirect branch. The
//! difference is that the compiler now owns the table.
//!
//! # Why [`FdOps::caps`] exists, which is the one thing said twice
//!
//! Three callers have to know whether an operation exists *before* they call
//! it, and the answer decides which errno the guest sees:
//!
//! - `sendfile` rejects a non-seekable input, and a pair of descriptors that
//!   cannot be read or written, **before** it reads the offset argument out of
//!   guest memory — so `EINVAL` beats `EFAULT`, which is the order Linux has.
//! - The rewind after a failed delivery picks its strategy before the read:
//!   a descriptor that can seek is one whose bytes are still there.
//! - `read` falls back to `pread` at the descriptor's own offset, and `write`
//!   to `pwrite`, so the caller has to know which of the four exist.
//!
//! Rust cannot ask an implementation which methods it overrode, so this is the
//! one place a driver says something twice: [`FdOps::caps`] must name the
//! operations it implements. It is **required**, with no default, so that a
//! new driver cannot answer it by omission the way the `Option<fn>` table did.
//! Linux has the same seam and the same answer — `FMODE_LSEEK` beside
//! `f_op->llseek`.

use crate::{dir_entry, dword_t, fd, mem, off_t, off_t_, page_t, pages_t};
use std::any::Any;

pub use ioctlarg::{IoctlArg, Plain};
use std::ffi::{c_int, c_ulong};

/// `_EIO`, which is what an operation a driver does not have answers when the
/// caller did not ask [`FdOps::caps`] first.
use guest_errno::c_int_::EIO;
/// `_EINVAL`, `_ENOTTY` -- not a terminal, which is what an unrecognised ioctl
/// is -- and `_ENOTDIR`, for a `readdir` on a driver that has no directories.
use guest_errno::c_int_::{ENOTDIR, ENOTTY, ENXIO};

/// Which of the optional byte-stream operations a driver implements.
///
/// See the module comment for why this is required rather than derived from
/// which methods the implementation overrode.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct Caps {
    /// [`FdOps::read`]: a stream read at the descriptor's own position.
    pub read: bool,
    /// [`FdOps::write`]: a stream write at the descriptor's own position.
    pub write: bool,
    /// [`FdOps::pread`]: a read at a caller-given offset.
    pub read_at: bool,
    /// [`FdOps::pwrite`]: a write at a caller-given offset.
    pub write_at: bool,
    /// [`FdOps::lseek`]: what "seekable" means to `sendfile` and to the rewind
    /// after a failed delivery.
    pub seek: bool,
}

impl Caps {
    /// Nothing: a descriptor that is polled and closed and no more, which is
    /// what epoll and pidfd are.
    pub const NONE: Caps = Caps {
        read: false,
        write: false,
        read_at: false,
        write_at: false,
        seek: false,
    };
    /// A stream in both directions and no positional access: a pipe, a socket,
    /// an eventfd.
    pub const STREAM: Caps = Caps {
        read: true,
        write: true,
        ..Caps::NONE
    };
    /// Readable as a stream and nothing else: timerfd, signalfd, inotify.
    pub const READ_ONLY_STREAM: Caps = Caps {
        read: true,
        ..Caps::NONE
    };
    /// Everything: a host file through realfs, or a memfd.
    pub const FILE: Caps = Caps {
        read: true,
        write: true,
        read_at: true,
        write_at: true,
        seek: true,
    };

    /// Whether `read(2)` can be answered at all, directly or by seeking to the
    /// descriptor's position and using [`FdOps::pread`].
    pub fn readable(&self) -> bool {
        self.read || self.read_at
    }

    /// Whether `write(2)` can be answered at all.
    pub fn writable(&self) -> bool {
        self.write || self.write_at
    }
}

/// A `&dyn Any` for any implementor, so that "is this descriptor one of mine?"
/// is a downcast rather than a comparison of table addresses.
///
/// Blanket, so no driver writes it out.
pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// What the thing behind an open file description can do.
///
/// One implementation per driver, held by `struct fd` as
/// `Option<&'static dyn FdOps>`.
///
/// # Why the descriptor is a `&fd`
///
/// It was a `*mut fd` until 2026-09-14, and the reason written here was: "a
/// descriptor is shared between threads and its fields are written while
/// another thread reads them, so a `&fd` would assert an exclusivity that does
/// not hold". That is the rule
/// `docs/changelog/2026-09-05-a-shared-reference-to-a-struct-another-thread-writes.md`
/// records, and it was **true about `struct fd` as it was then**.
///
/// A shared reference does not assert exclusivity; it asserts that nothing
/// mutates the object except through something that synchronises. The seven
/// fields a live description writes are atomics now — see `struct fd` — so
/// there is nothing left for a `&fd` to be wrong about, and every method below
/// is a safe `fn`. The fourteen `unsafe fn` and the block around every
/// implementation body went with it.
///
/// [`FdOps::close`] is the exception and takes a `&mut fd`, which is what it
/// has: it runs from `fd_finalize` at a strong count of zero, so no other
/// reference to the description exists. That is also why it is the only method
/// that may write the `state` union.
///
/// Nothing left to state about the descriptor, which is why this is not an
/// `unsafe trait` and has no `# Safety` section. One method is still an
/// `unsafe fn`, for `mmap`'s address space. `ioctl` was the second until
/// 2026-09-30, for a `*mut c_void` argument whose size the caller had got
/// from `ioctl_size`; it is an [`IoctlArg`] now, a slice of that size.
///
/// `readdir` was a third until its `dir_entry` became a `&mut`: it is an
/// out-parameter the caller owns, so there was nothing for a pointer to buy.
pub trait FdOps: AsAny + Send + Sync + 'static {
    /// Which of the five optional stream operations this driver has.
    ///
    /// Required: see the module comment. A driver whose `caps` claims an
    /// operation it does not implement reaches the default body below, which
    /// answers `_EIO`.
    fn caps(&self) -> Caps;

    // ---- the byte stream ------------------------------------------------

    // The four below took a `*mut c_void` and a `usize` until 2026-09-14, and
    // the buffer is always this kernel's own -- `crates/kernel/rwcalls` copies
    // in before a write and out after a read, so that no driver is handed a
    // guest address and writes it without the page table's checks. The two
    // halves therefore had a `Vec` or an array behind them at every call, were
    // split apart to make the call, and were put back together with
    // `from_raw_parts` in most of the thirty implementations.
    //
    // The count in the answer is still the driver's to get right; what a slice
    // takes away is the *length*, which no longer travels separately from the
    // thing it is the length of.

    /// Read at the descriptor's own position, advancing it.
    ///
    fn read(&self, _fd: &fd, _buf: &mut [u8]) -> isize {
        EIO as isize
    }

    /// Write at the descriptor's own position, advancing it.
    ///
    fn write(&self, _fd: &fd, _buf: &[u8]) -> isize {
        EIO as isize
    }

    /// Read at `off`, leaving the descriptor's own position alone.
    ///
    fn pread(&self, _fd: &fd, _buf: &mut [u8], _off: off_t) -> isize {
        EIO as isize
    }

    /// Write at `off`, leaving the descriptor's own position alone.
    ///
    fn pwrite(&self, _fd: &fd, _buf: &[u8], _off: off_t) -> isize {
        EIO as isize
    }

    /// Move the position. Answers where it ended up.
    ///
    fn lseek(&self, _fd: &fd, _off: off_t_, _whence: c_int) -> off_t_ {
        EIO as off_t_
    }

    // ---- directories ----------------------------------------------------

    /// The next entry, or `Ok(None)` at the end.
    ///
    /// The default is `_ENOTDIR`, which is the answer a driver with no
    /// directories gives and what `getdents64` already returns for a
    /// descriptor that is not open on one.
    ///
    /// # It was `-> c_int` with an out parameter until 2026-09-16
    ///
    /// *"The next entry, or 0 at the end"* — plus a negative errno, so one
    /// `int` carried three meanings and the entry itself was in a buffer the
    /// caller had zeroed. `crates/fs/dircalls`' loop needed four lines of
    /// comment to say which number meant what, and two tests (`err < 0`,
    /// `err == 0`) before it could use the entry.
    ///
    /// `Result<Option<dir_entry>, c_int>` is those three states, and the
    /// nesting is the right way round: a failure is the outer answer, and
    /// "is there another one" is the inner. Returning the entry costs nothing
    /// — the caller was allocating a fresh `dir_entry::default()` per
    /// iteration to pass in.
    fn readdir(&self, _fd: &fd) -> Result<Option<dir_entry>, c_int> {
        Err(ENOTDIR)
    }

    /// Where the directory stream is now.
    ///
    /// The default is the descriptor's own `offset`, which is the answer
    /// unless the mount keeps a cursor of its own — the host-passthrough one
    /// does, because a `DIR *`'s `telldir` is not a byte offset into anything.
    ///
    fn telldir(&self, fd: &fd) -> c_ulong {
        fd.offset() as c_ulong
    }

    /// Where the description is, without moving it: Linux's `f_pos`, which
    /// `/proc/<pid>/fdinfo` prints as `pos:` for this descriptor and for an
    /// epoll set's members. Asked about another task's descriptor, so it must
    /// not change anything -- an `lseek(SEEK_CUR)` would, here: procfs
    /// regenerates a file on a seek and tmpfs moves a directory's cursor.
    ///
    /// The default is the descriptor's own `offset`, which is the position for
    /// every driver that keeps one and 0 for those with none (a pipe, a
    /// socket, an anonymous inode), as Linux's is. The host-passthrough one
    /// asks the host.
    fn position(&self, fd: &fd) -> off_t_ {
        fd.offset()
    }

    /// Put the directory stream back to `ptr`.
    ///
    /// The default does nothing: the caller has already written the
    /// descriptor's own `offset`, which is the whole of the position for a
    /// driver that keeps no cursor.
    ///
    fn seekdir(&self, _fd: &fd, _ptr: c_ulong) {}

    // ---- mapping and readiness ------------------------------------------

    /// Map `pages` of this description into `mem` at `start`.
    ///
    /// `None` for a driver that cannot be mapped, and the caller says what
    /// that is: `mmap(2)` answers `_ENODEV`, which is Linux's
    /// `if (!file->f_op->mmap) return -ENODEV`, while the ELF loader answers
    /// `_EIO` because it is not serving a guest's `mmap` call. Two different
    /// answers to the same absence, which is why this is an `Option` and not a
    /// default errno.
    ///
    /// # Safety
    /// See the trait. `mem` is the address space to map into, and is live.
    #[allow(clippy::too_many_arguments)]
    unsafe fn mmap(
        &self,
        _fd: &fd,
        _mem: *mut mem,
        _start: page_t,
        _pages: pages_t,
        _offset: off_t,
        _prot: c_int,
        _flags: c_int,
    ) -> Option<c_int> {
        None
    }

    /// The host file a mapping of this description shows, which the page
    /// table asks for the file's size and identity when it decides whether a
    /// page is past the end. The description's own `real_fd` by default; a
    /// driver whose file moves to a host file only when first mapped (tmpfs)
    /// answers that file, which no description's `real_fd` holds.
    fn mapped_file<'a>(&self, fd: &'a fd) -> Option<std::os::fd::BorrowedFd<'a>> {
        fd.host()
    }

    /// The readiness bits this driver can answer for itself.
    ///
    /// `None` is not "nothing is ready": it means the driver has no opinion,
    /// and the two callers read it differently on purpose. `fs/poll` reports 0
    /// — a descriptor that is always ready in both directions and whose caller
    /// asks the host instead — while the `EFAULT`/`EAGAIN` decision in
    /// `rwcalls` treats no opinion as ready, so that a read into an unwritable
    /// buffer answers `EFAULT` rather than pretending it would have blocked.
    /// An `Option` rather than a sentinel because those two are different
    /// questions and 0 is a real answer to the first.
    ///
    fn poll(&self, _fd: &fd) -> Option<c_int> {
        None
    }

    /// Whether this driver's readiness is the host's answer about the
    /// descriptor's `real_fd`.
    ///
    /// Was an `fn_addr_eq` against `realfs_poll`, which had to be an address
    /// comparison because a fakefs descriptor has a table of its own and
    /// forwards `poll` to realfs — so comparing *tables* answered no for every
    /// file in a fakefs. Both drivers answer `true` here, which is the fact
    /// that was being approximated.
    fn poll_follows_host_fd(&self) -> bool {
        false
    }

    /// The host's poll bits for `real_fd`, corrected by what this driver knows
    /// and the host's bits conflate -- asked before realfs's own fixups, on
    /// every path that polls the host (`poll`, a transient set, epoll). The
    /// default changes nothing.
    fn host_revents(&self, _fd: &fd, revents: c_int) -> c_int {
        revents
    }

    /// Whether this driver is ready in both directions for ever, so that a
    /// poll set need not watch it.
    ///
    /// Was an `fn_addr_eq` against `fs/devices`' `ready_poll`.
    fn readiness_is_constant(&self) -> bool {
        false
    }

    /// Whether this driver is a **regular file whose readiness changes**, so
    /// that `epoll_ctl` takes it where it refuses every other regular file.
    ///
    /// Linux's test is `file_can_poll` -- does the file have a `poll` method
    /// -- and a regular file usually has none; `crates/kernel/epollcalls`
    /// asks the type for that reason. A POSIX message queue is a regular file
    /// with one (`mqueue_abi` waits on one with epoll on a real kernel).
    fn regular_file_polls(&self) -> bool {
        false
    }

    // ---- ioctl ----------------------------------------------------------

    /// How many bytes of the argument `cmd` names, or a negative for a command
    /// this driver does not have.
    ///
    /// Asked before [`FdOps::ioctl`], so a driver that answers `-1` here never
    /// reaches it: the pair is why `tools/ops-table-pairs.py` exists, and a
    /// trait is what stops the two from being set independently. The default
    /// refuses every command, which is `_ENOTTY` at the call site.
    fn ioctl_size(&self, _cmd: c_int) -> isize {
        -1
    }

    /// Run `cmd`. Only reached when [`FdOps::ioctl_size`] answered a size:
    /// [`IoctlArg::Value`] for zero, otherwise a buffer of exactly that many
    /// bytes.
    fn ioctl(&self, _fd: &fd, _cmd: c_int, _arg: IoctlArg<'_>) -> c_int {
        ENOTTY
    }

    // ---- lifetime and flags ---------------------------------------------

    /// Flush what this description holds.
    ///
    /// The default is success. `fsync` on a thing with nothing to flush is not
    /// an error — that is what `crates/kernel/fdattr` answered for a null
    /// entry, and it is the right answer rather than an accident of the table.
    ///
    fn fsync(&self, _fd: &fd) -> c_int {
        0
    }

    /// A descriptor table let go of one reference to this description:
    /// `close`, a `dup2` over it, `close_range`, an exec's close-on-exec, or
    /// the table itself going at exit. Linux's `f_op->flush`, which
    /// `filp_close` calls on every one of those and not only on the last.
    ///
    /// Runs on the thread whose table it is. The default has nothing to do;
    /// POSIX message queues drop the caller's `mq_notify` registration here,
    /// which a close of a *duplicate* does on Linux (`mqueue_probe`).
    fn flush(&self, _fd: &fd) {}

    /// Release what this description holds. The default keeps nothing and so
    /// has nothing to do.
    ///
    /// Called once, when the last reference goes.
    fn close(&self, _fd: &mut fd) -> c_int {
        0
    }

    /// Whether [`FdOps::close`] already does what the mount's `fs_ops::close`
    /// would do, so that `fd_close` must not call it as well.
    ///
    /// Was `fn_addr_eq(driver_close, fs_close)` — "skip the mount's close when
    /// it is literally the same function" — and breaking that coincidence is
    /// what closed a host descriptor twice once already. A driver says so
    /// itself now.
    fn close_covers_mount(&self) -> bool {
        false
    }

    /// Take the new `O_NONBLOCK` and friends. The default accepts them: the
    /// flags live on the descriptor, and a driver that does not need to hear
    /// about a change does not have to.
    ///
    fn setflags(&self, _fd: &fd, _flags: dword_t) -> c_int {
        0
    }

    /// A new description onto what `fd` is open on, opened with `flags`: what
    /// `open("/proc/<pid>/fd/<n>")` gives for a description with no path, which
    /// Linux follows to the open file rather than reading its link as a name.
    ///
    /// The default is `_ENXIO`, Linux's answer for a socket, an eventfd and the
    /// other anonymous inodes; a pipe reopens (`tests/guest` fdlink_probe).
    fn reopen(&self, _fd: &fd, _flags: c_int) -> Result<crate::FdOwned, c_int> {
        Err(ENXIO)
    }

    /// The lines this driver adds to `/proc/<pid>/fdinfo/<n>` after the four
    /// every descriptor has (`pos`, `flags`, `mnt_id`, `ino`): Linux's
    /// `f_op->show_fdinfo`, each line ending in `\n`, in its layout -- an
    /// eventfd's count, a timerfd's deadline, an epoll set's members.
    ///
    /// Here rather than in `crates/fs/proc` because each driver's state is
    /// its own, and procfs asking every type in turn is the downcast this
    /// trait replaced. The default adds nothing, which is what a regular file
    /// or a pipe shows.
    fn show_fdinfo(&self, _fd: &fd, _out: &mut String) {}
}

/// Whether two descriptors are answered by the same driver.
///
/// The `Option<&dyn>` compares by vtable *and* data address, neither of which
/// is a promise — so this asks `Any` about the concrete type instead.
pub fn same_driver(a: Option<&'static dyn FdOps>, b: Option<&'static dyn FdOps>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.as_any().type_id() == b.as_any().type_id(),
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Reader;
    impl FdOps for Reader {
        fn caps(&self) -> Caps {
            Caps::READ_ONLY_STREAM
        }
        fn read(&self, _fd: &fd, buf: &mut [u8]) -> isize {
            buf.len() as isize
        }
    }

    struct Nothing;
    impl FdOps for Nothing {
        fn caps(&self) -> Caps {
            Caps::NONE
        }
    }

    static READER: Reader = Reader;
    static NOTHING: Nothing = Nothing;

    #[test]
    fn caps_say_which_operations_are_there() {
        assert!(READER.caps().readable());
        assert!(!READER.caps().writable());
        assert!(!NOTHING.caps().readable());
    }

    /// The downcast that replaced nine comparisons of table addresses. Two
    /// distinct unit structs are zero-sized, so their *addresses* may well be
    /// equal — which is exactly why the identity test cannot be one.
    #[test]
    fn a_driver_is_identified_by_type_and_not_by_address() {
        let a: &'static dyn FdOps = &READER;
        let b: &'static dyn FdOps = &NOTHING;
        assert!(a.as_any().is::<Reader>());
        assert!(!a.as_any().is::<Nothing>());
        assert!(!same_driver(Some(a), Some(b)));
        assert!(same_driver(Some(a), Some(&READER)));
    }

    #[test]
    fn the_defaults_are_the_ones_the_call_sites_used_to_apply() {
        let ops: &dyn FdOps = &NOTHING;
        // A real descriptor, where this passed `std::ptr::null_mut()` until
        // the methods took a reference. The defaults ignore it either way;
        // what changed is that "ignored" no longer has to be spelled as a
        // pointer the caller promises not to use.
        let mut fd = fd::default();
        // fsync on a thing with nothing to flush succeeds.
        assert_eq!(ops.fsync(&fd), 0);
        // setflags is accepted; the flags live on the descriptor.
        assert_eq!(ops.setflags(&fd, 0), 0);
        // no ioctl is recognised, which is `_ENOTTY` at the call site.
        assert!(ops.ioctl_size(0) < 0);
        // no opinion about readiness, which is not the same as "not ready".
        assert!(ops.poll(&fd).is_none());
        // close of a driver that keeps nothing has nothing to do.
        assert_eq!(ops.close(&mut fd), 0);
        assert!(!ops.poll_follows_host_fd());
        assert!(!ops.readiness_is_constant());
        assert!(!ops.close_covers_mount());
    }
}
