//! Socket descriptor lifecycle and the driver a socket descriptor carries.

use super::*;

fn sock_close(fd: &mut ffi::fd) -> c_int {
    sockrestart::sockrestart_end_listen(fd);
    // The names this socket bound, in the two namespaces. Taken out under
    // the lock so that this and a `bind` still unwinding its own failure
    // cannot both get them, and dropped outside it -- which is the release.
    if let Some(state) = state_of(fd) {
        drop(std::mem::take(&mut *state.names()));
    }
    // The kernel's end of a netlink pair closes with the state, below.
    // Without that every `ip addr` in a guest leaked a host descriptor,
    // which is the shape `eventfd_leak` exists for.
    // Everything still in flight: what this socket never received, and what
    // it sent to a connection nobody accepted. Nothing will collect either
    // now, and the queued objects hold retained descriptors, so they are
    // drained before the endpoint goes.
    let peer = state_of(fd).map_or(0, SocketState::peer);
    sock_rs_drain_scm(peer);
    // And the endpoint, which takes the peer's edge back to us with it and
    // withdraws any handshake still outstanding. A peer that reads the edge
    // afterwards gets a handle that is not in the table, which is what makes
    // the raw `struct fd *` this used to hold unnecessary.
    // Empty by now: the drain above took everything. `Table::close` gives
    // back whatever is left, and anything left would be a caller that did
    // not drain.
    let left = unixpeer::with_table(|t| t.close(peer));
    debug_assert!(left.is_empty(), "drained before close");
    // The state itself, last: everything above reads it.
    drop(fd.take_driver_state::<SocketState>());
    realfs::realfs_close(fd)
}

/// A socket's driver: three operations of its own and the rest realfs's,
/// because a socket here *is* a host socket reached through `real_fd`.
///
/// It used to copy realfs's table and overwrite three fields, so that an
/// operation added there arrived here rather than being silently null. That is
/// four explicit delegations instead — see the note on `crates/fs/fake`'s
/// driver for why inheriting silently is the weaker property.
pub(crate) struct SocketFd;

static SOCKET_FDOPS: SocketFd = SocketFd;

impl ffi::FdOps for SocketFd {
    /// A stream in both directions and no position: a socket cannot seek,
    /// which is what makes `sendfile` *from* one `EINVAL`.
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::STREAM
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        sock_read(fd, buf)
    }
    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        sock_write(fd, buf)
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        realfs::REALFS_FDOPS.poll(fd)
    }
    fn host_revents(&self, fd: &ffi::fd, revents: c_int) -> c_int {
        crate::state::host_revents(fd, revents)
    }
    /// Yes: readiness is the host's answer about the socket's `real_fd`.
    fn poll_follows_host_fd(&self) -> bool {
        realfs::REALFS_FDOPS.poll_follows_host_fd()
    }
    fn ioctl_size(&self, cmd: c_int) -> isize {
        realfs::REALFS_FDOPS.ioctl_size(cmd)
    }
    fn ioctl(&self, fd: &ffi::fd, cmd: c_int, arg: ffi::IoctlArg<'_>) -> c_int {
        realfs::REALFS_FDOPS.ioctl(fd, cmd, arg)
    }
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        sock_close(fd)
    }
    fn setflags(&self, fd: &ffi::fd, flags: u32) -> c_int {
        realfs::REALFS_FDOPS.setflags(fd, flags)
    }
    /// `unix_show_fdinfo`, for a unix socket: the descriptors queued for it
    /// to receive. Linux counts a *listening* socket's pending connections
    /// there instead; a host listener does not say how many it has, so a
    /// listener here shows its (empty) queue.
    fn show_fdinfo(&self, fd: &ffi::fd, out: &mut String) {
        let Some(h) = crate::state::state_of(fd).map(|s| s.peer()).filter(|&h| h != 0) else {
            return;
        };
        let n = unixpeer::with_table(|t| t.queued_fds(h));
        out.push_str(&format!("scm_fds: {n}\n"));
    }
}

/// The driver a socket descriptor carries.
///
/// It was `#[no_mangle]` for "the C that still installs a socket descriptor",
/// and there has been no such C since 2026-09-06. Its one remaining caller was
/// `crates/fs/sockrestart`, reaching it by symbol to tell a socket from any
/// other descriptor; that crate is told once, here.
pub fn socket_fdops_get() -> Option<&'static dyn ffi::FdOps> {
    // Tell `crates/fs/sockrestart` which driver means "socket", so it can pick
    // the descriptors its accept-restart bracket applies to. A hook, because
    // that crate is *below* this one — this crate calls its bracket around
    // every blocking accept — and it was a `socket_fdops_get` declared there in
    // an `extern "C"` block until 2026-09-09.
    //
    // This function is the only way the driver is obtained and every socket
    // goes through it, so "not installed" still means "no socket exists".
    //
    // It used to install an *address*, and getting that right needed a note:
    // the first attempt installed it from inside a `LazyLock` initialiser,
    // which publishes the address of a **local** that is then moved into the
    // lock's storage, so what was installed was not the table any descriptor
    // carried. A `TypeId` has no such failure mode.
    sockrestart::set_socket_fdops(&SOCKET_FDOPS);
    Some(&SOCKET_FDOPS)
}
