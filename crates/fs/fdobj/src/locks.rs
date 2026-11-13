//! Descriptor lock and condition-variable helpers.

use super::*;

// ---------------------------------------------------------------------------
// The pthread objects a description embeds
// ---------------------------------------------------------------------------
//
// `kernel/fs.c`'s six one-line functions until 2026-09-03, and the file is gone
// with them. They were there because `lock_init`, `cond_init` and their pairs
// are macros over a `lock_t`, and `wait_for` was the one interruptible wait —
// so a crate could reach none of them. The macros still cannot be called from
// Rust and are still behind the `sync_*` shims; what changed is that the layout
// is *generated*, so this crate can take the address of the field, and that
// `wait_for` is `crates/util/waitfor`'s.
//
// `fd->lock` is what makes a positional read atomic against another syscall on
// the same descriptor: `pread` holds it across a seek-read-seek on a filesystem
// with no `pread` of its own.

/// `fd->lock`, held for the length of a scope.
///
/// One definition rather than one per syscall crate: `crates/kernel/rwcalls`
/// wrote this and `crates/fs/dircalls` needed it, and a lock taken and released
/// by hand at each exit is the shape the C had — with paths that returned in
/// between.
///
/// What it is *for* is that the operations under it are sequences. A positional
/// read on a filesystem with no `pread` is a seek, a read and a seek back; a
/// `getdents64` is a `telldir`, a run of `readdir`s and a `seekdir` to put the
/// entry that did not fit back. Neither is atomic against another syscall on
/// the same descriptor without this, and Linux holds `f_pos_lock` across both.
#[must_use = "the lock is released when this is dropped, so dropping it at once releases it at once"]
pub struct FdGuard<'a> {
    fd: &'a ffi::fd,
    held: ::locks::mutex::Guard<'a>,
}

impl<'a> FdGuard<'a> {
    /// Take it.
    ///
    /// **Safe since 2026-09-16.** It took a `*mut ffi::fd` and carried "`fd` is
    /// live and this thread does not already hold its lock": the borrow is the
    /// first half, and the second is a caller's rule that deadlocks rather than
    /// being undefined -- `fd->lock` is a default mutex and `-DLOCK_DEBUG=1` is
    /// what names the site. That is the same argument `locks::mutex::lock_at`
    /// records, one layer down.
    pub fn new(fd: &'a ffi::fd) -> FdGuard<'a> {
        FdGuard { fd, held: ::locks::guard!(&fd.lock) }
    }

    /// Wake everything parked on this description.
    ///
    /// Under the lock, which is what makes `crates/kernel/inotifycalls`' read
    /// correct: a reader takes the lock before releasing the registry's, so a
    /// notify cannot land between its empty read and its wait.
    pub fn notify(&self) {
        waitfor::notify_all(&self.fd.cond);
    }

    /// Park until something notifies this description or a signal arrives,
    /// holding the lock again on return. No timeout: every caller waits for
    /// an event rather than a deadline.
    ///
    /// These two and the pair that took and released the lock by hand were
    /// four `unsafe fn` over `*mut ffi::fd` until 2026-09-30, each with the
    /// contract "this thread holds `fd`'s lock". Holding the guard is that
    /// contract.
    #[must_use = "an interrupted wait answers EINTR, which the caller must see"]
    pub fn wait(&self) -> std::ffi::c_int {
        waitfor::wait_for(&self.fd.cond, &self.held, None)
    }
}
