//! Descriptor member adapters for transient poll sets and epoll.

use super::*;

// -------------------------------------------------------- the member vtable
//
// What `crates/fs/pollset` needs to know about a member descriptor. It holds
// member handles through the typed trait and asks through here.

fn member_poll(fd: &ffi::fd) -> c_int {
    fd_poll_types(fd)
}

fn member_host_fd(fd: &ffi::fd) -> c_int {
    if is_realfs(fd) {
        fd.host().map_or(-1, |h| std::os::fd::AsRawFd::as_raw_fd(&h))
    } else {
        EPOLL_FD.get().map_or(-1, |e| (e.backend)(fd))
    }
}

fn member_host_events(fd: &ffi::fd) -> c_short {
    if is_realfs(fd) {
        realfs::map::realfs_poll_events(fd) as c_short
    } else {
        // The only other host-backed member is an epoll set, whose backend
        // becomes readable when the set does.
        libc::POLLIN
    }
}

fn member_host_fixup(fd: &ffi::fd, revents: c_short) -> c_int {
    if is_realfs(fd) {
        return poll_add_aliases(realfs::map::realfs_poll_fixup(fd, revents as c_int));
    }
    // An epoll set. The backend answers for host transitions, but a ready queue
    // filled by a member with no host descriptor -- an eventfd, a timerfd, a
    // tty -- produces none, so a quiet backend is not an answer. -1 asks the
    // description itself, which is a mutex and a queue check.
    if revents & libc::POLLIN != 0 {
        bits::READ
    } else {
        -1
    }
}

fn member_is_socket(fd: &ffi::fd) -> bool {
    sockrestart::sockrestart_is_socket(fd)
}

/// A description a transient set holds: a reference, and the address beside
/// it so that each method's borrow is one load rather than a read through the
/// owner handle's control block -- `Owned::as_ptr`'s note asks for exactly
/// that on a per-member scan, and `poll_bench` at 1800 descriptors is where
/// this tree has twice measured whether such an indirection is free.
pub struct Member {
    fd: std::ptr::NonNull<ffi::fd>,
    _held: fs_fdobj::Owned,
}

impl Member {
    pub fn new(held: fs_fdobj::Owned) -> Member {
        Member { fd: std::ptr::NonNull::from(&*held), _held: held }
    }

    fn get(&self) -> &ffi::fd {
        // SAFETY: `_held` is a reference to this description, alive for as
        // long as `self` is.
        unsafe { self.fd.as_ref() }
    }
}

/// This kernel's descriptors, as `crates/fs/pollset` sees them. A marker:
/// every method is an associated function over a [`Member`].
///
/// A safe impl since 2026-10-01: it was an `unsafe impl` over
/// `NonNull<ffi::fd>` handles that the set retained with `fd_retain` and
/// released with `fd_close`, and each method dereferenced its handle on that
/// promise. The handle owns its reference now.
pub struct Fd;

impl pollset::Members for Fd {
    type Fd = Member;

    fn poll(fd: &Member) -> c_int {
        member_poll(fd.get())
    }
    fn host_fd(fd: &Member) -> c_int {
        member_host_fd(fd.get())
    }
    fn host_events(fd: &Member) -> c_short {
        member_host_events(fd.get())
    }
    fn host_fixup(fd: &Member, revents: c_short) -> c_int {
        member_host_fixup(fd.get(), revents)
    }
    fn is_socket(fd: &Member) -> bool {
        member_is_socket(fd.get())
    }

    fn map_errno() -> c_int {
        kernel_errno::errno_map()
    }

    // One bracket for the whole set, where the C walked every member and took
    // sockrestart's global lock once per socket -- 1800 acquisitions a pass for
    // a server polling that many, on a lock every thread shares. The count only
    // ever answers "is it zero".
    fn begin_listen_wait() {
        sockrestart::sockrestart_begin_listen_wait_bare();
    }
    fn end_listen_wait() {
        sockrestart::sockrestart_end_listen_wait_bare();
    }
    fn should_restart_listen_wait() -> bool {
        sockrestart::sockrestart_should_restart_listen_wait()
    }
}

/// A transient set for `poll()`, `ppoll()`, `select()` or `pselect()`: built,
/// waited on once, destroyed.
pub type Set = pollset::PollSet<Fd>;

/// One, ready to have members added.
pub fn poll_create_transient() -> Set {
    Set::new(bits::ERR | bits::HUP)
}

/// Register a descriptor; the set keeps the reference `fd` carries.
pub fn poll_add_fd(set: &mut Set, fd: fs_fdobj::Owned, types: c_int, info: u64) -> c_int {
    let watchers = std::sync::Arc::clone(&fd.poll_watchers);
    set.add(Member::new(fd), watchers, types, info)
}

// -------------------------------------------------------------------- epoll
//
// Both directions of the link between a description and the sets watching it
// live in crates/kernel/epoll; what is here is what needs `struct fd` — a
// member's readiness, its host descriptor and whether it is a socket.

/// The three questions only `crates/kernel/epollcalls` can answer about a
/// descriptor, because the answer to all of them starts with "is `fd->ops` the
/// epoll table", and that table is its object.
///
/// # Why a hook
///
/// Calling it directly made the wait loop depend on the epoll *syscalls*, which
/// depend on `crates/fs/devices` for `readiness_is_constant`, which depends on
/// this crate: a cycle, and a cycle because a descriptor-layer wait loop was
/// reaching up into a syscall family. Same shape as `crates/fs/inotify`'s
/// notify hook and `crates/kernel/pidfd`'s wakeup.
///
/// Nothing is installed until the first `epoll_create1`, and before then no
/// descriptor is an epoll set, so [`EpollFd::is_instance`] answering false is
/// the right answer rather than a default.
pub struct EpollFd {
    /// Is this descriptor an epoll set at all? A different question from
    /// whether it has state: a set whose state failed to allocate is still one.
    pub is_instance: fn(fd: &ffi::fd) -> bool,
    /// Has the set behind it anything to report? False for a descriptor that is
    /// not one.
    pub is_ready: fn(fd: &ffi::fd) -> bool,
    /// The host descriptor the set waits on, or -1 — including for a descriptor
    /// that is not a set.
    pub backend: fn(fd: &ffi::fd) -> c_int,
}

static EPOLL_FD: std::sync::OnceLock<EpollFd> = std::sync::OnceLock::new();

/// Install the three. The first call wins, so every `epoll_create1` may call it.
pub fn set_epoll_fd_hook(ops: EpollFd) {
    let _ = EPOLL_FD.set(ops);
}

fn epoll_member_poll(fd: &ffi::fd) -> c_int {
    // An outer backend reports the inner backend fd becoming readable. Transfer
    // those host transitions into the inner durable queue before asking whether
    // the epoll description itself is readable.
    if let Some(e) = EPOLL_FD.get()
        && (e.is_instance)(fd)
    {
        return if (e.is_ready)(fd) { bits::READ } else { 0 };
    }
    member_poll(fd)
}

// `epoll_member_is_socket` was here, and was `member_is_socket` with a
// `c_int::from(..)` on the way out and a `!= 0` at its one call site -- a
// `bool` through an integer and back for nothing, and a second copy of a
// one-line function. Both went on 2026-09-16; the trait method calls
// `member_is_socket` directly.

/// This kernel's descriptors, as `crates/kernel/epoll` sees them.
///
/// The three methods took a `usize` key and cast it back to a `*mut ffi::fd`
/// until 2026-09-16 — an integer-to-pointer conversion the compiler cannot
/// check, beside an associated `Member` type that named the right thing and
/// was never used. They take a `&ffi::fd` now and the trait's `Member` is what
/// says so.
///
/// It was a `kernel_epoll::Ops` static of three function pointers until
/// 2026-09-09, and bindgen's `epoll_state_ops` before that — the same three
/// rendered twice, meeting through a C ABI call that reinterpreted and checked
/// nothing, which is the shape `crates/kernel/taskview` exists to prevent and
/// the same one `siginfo_`, `timeval_` and `pollset_ops` were found in.
pub struct EpollMember;

impl kernel_epoll::Members for EpollMember {
    type Member = ffi::fd;

    fn poll(fd: &ffi::fd) -> c_int {
        epoll_member_poll(fd)
    }
    fn host_fd(fd: &ffi::fd) -> c_int {
        member_host_fd(fd)
    }
    fn is_socket(fd: &ffi::fd) -> bool {
        member_is_socket(fd)
    }
}

/// The four `epoll_watch_*` functions below are Rust-only since 2026-09-06.
/// `crates/kernel/epollcalls` is their only caller, so a C ABI would add an
/// interface nobody uses and an optimisation barrier on the epoll path.
///
/// **Safe since 2026-09-30**: they took the member as a `*mut ffi::fd` only
/// to dereference it, and had no `# Safety` section saying so -- a crate-level
/// `allow(clippy::missing_safety_doc)` was over them. The member is a `&fd`
/// and the set the `&Arc` [`kernel_epoll::epoll_add`] needs.
pub fn epoll_watch_add(
    epoll: &std::sync::Arc<kernel_epoll::Epoll>,
    nested: Option<&kernel_epoll::Epoll>,
    member: &fs_fdobj::Owned,
    fd_no: c_int,
    types: c_int,
    data: u64,
) -> c_int {
    let err = kernel_epoll::epoll_add::<EpollMember>(
        epoll,
        nested,
        &member.downgrade(),
        &member.poll_watchers,
        fd_no,
        types as u32,
        data,
    );
    if err < 0 { err } else { 0 }
}

pub fn epoll_watch_mod(epoll: &kernel_epoll::Epoll, member: &ffi::fd, fd_no: c_int, types: c_int, data: u64) -> c_int {
    kernel_epoll::epoll_modify::<EpollMember>(epoll, member, fd_no, types as u32, data)
}

pub fn epoll_watch_del(
    epoll: &std::sync::Arc<kernel_epoll::Epoll>,
    nested: Option<&kernel_epoll::Epoll>,
    member: &ffi::fd,
    fd_no: c_int,
) -> c_int {
    let err = kernel_epoll::epoll_delete::<EpollMember>(epoll, nested, member, &member.poll_watchers, fd_no);
    if err < 0 { err } else { 0 }
}

pub fn epoll_copy_ready(
    epoll: &kernel_epoll::Epoll,
    events: &mut [kernel_epoll::Event],
    timeout: std::time::Duration,
) -> c_int {
    kernel_epoll::epoll_take_ready::<EpollMember>(epoll, events, timeout)
}

/// Publish a readiness transition.
///
/// No descriptor lock: each side of the reverse edge holds its own reference to
/// the list, so nothing here can be freed underneath. What the caller must
/// still not hold is a lock the description's own poll operation acquires — a
/// watcher may ask for that while delivering.
pub fn poll_wakeup(fd: &ffi::fd, events: c_int) {
    pollset::poll_watchers_notify(&fd.poll_watchers, events as u32);
}
