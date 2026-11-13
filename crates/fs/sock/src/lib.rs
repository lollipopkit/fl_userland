// `send` and `recv` are not syscalls on aarch64 -- there are no numbers for
// them, and libc implements both by calling sendto and recvfrom with a null
// address. `sys_send` and `sys_recv` existed here as one-line forwards that
// nothing in the tree referenced, in C for as long as this file has existed;
// they became visible only when they moved, because `dead_exports` reads Rust
// exports and the C ones were in nobody's sight.
//! The socket family.
//!
//! `fs/sock.c` was 2187 lines around five Rust crates -- `sockabi` (the
//! constant tables), `sockaddr` (how long an address has to be), `unixname`
//! (the abstract namespace), `unixpeer` (what one end knows about the other)
//! and `msghdr` (the sixteen bytes a `sendmsg` is described by). What was left
//! in C was the code joining them, which is what this is.
//!
//! A socket here is a *host* socket with guest-facing rules on top: the guest's
//! constants are translated, the guest's address is checked, and for `AF_UNIX`
//! a second object -- the peer edge in `crates/fs/unixpeer` -- carries what a
//! host unix socket cannot: the credentials, the names each side reports, and
//! the descriptors in flight.
//!
//! `struct fd` is still C, so the socket's four fields are read and written
//! through the generated bindings. That is the same arrangement `crates/fs/fake`
//! has, and it ends when `struct task` moves: `f_get` and `f_install` are calls
//! into the calling task's descriptor table.


use std::ffi::{c_int, c_uint};
use std::os::fd::{BorrowedFd, OwnedFd};
// Every module here does `use super::*`, and the per-field atomics in
// `SocketState` are read and written from six of them.
pub(crate) use std::sync::atomic::Ordering;

use sockabi::guest;
use strace::strace;

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

mod host;

mod state;
mod ancillary;
use state::{SocketState, state_of};

mod netlink_ops;
pub(crate) use netlink_ops::netlink_send;
pub use netlink_ops::{netlink_deliver, netlink_of};
use netlink_ops::netlink_socket;

mod address;
use address::{SOCKADDR_MAX, put_addr, unix_addr, write_host_addr};

mod options;
pub use options::{sys_getsockopt, sys_setsockopt};

mod accept;
use accept::{UNIX_HANDSHAKE_MAGIC, io_full};
pub use accept::{sys_accept, sys_accept4};

mod buffer;
use buffer::{O_NONBLOCK_GUEST, read_addr, send_err, send_flags, to_real_flags};
pub use buffer::{sys_recvfrom, sys_sendto};

mod message;
use message::sock_rs_drain_scm;
pub use message::{sys_recvmsg, sys_sendmsg};

mod io;
use io::{sock_read, sock_write};

mod unix;
pub(crate) use unix::{AddrFor, autobind_on_named_socket, read_addr_for};

mod proc;
pub use proc::{NetInfo, net_info};

mod batch;
pub use batch::{sys_recvmmsg, sys_sendmmsg};

mod wait;
pub(crate) use wait::interrupted_accept;

mod create;
pub use create::*;
pub(crate) use create::{fd_create, fd_new};

mod query;
pub use query::*;

mod lifecycle;
pub use lifecycle::socket_fdops_get;

mod connection;
pub use connection::*;
pub use wait::sock_wait_readable_for_rs;
pub(crate) use wait::caller_cred;

/// The guest errno type, from `crates/util/errno`.
///
/// The names this crate answers with that are not obvious: `ESOCKTNOSUPPORT`
/// is "this family does not carry this type" and `EPROTONOSUPPORT` is "…or
/// this protocol"; `ENOPROTOOPT` is an unknown option of a level that exists
/// and `EOPNOTSUPP` a level nothing answers for at all.
pub(crate) use guest_errno::Errno;

/// The low four bits of a `type` argument are the type; the rest are flags.
///
/// Not `sockabi::guest::TYPE_MASK`, which is 0xff: that one is what a *type
/// argument* may set, and this is what is stored on the descriptor. Linux's
/// `SOCK_TYPE_MASK` is 0xf.
const SOCKET_TYPE_MASK: c_int = 0xf;

/// syscall returns (`crates/kernel/syscallrefs`), so this borrows rather than
/// owns: there is nothing to drop.
///
/// A `usize` until 2026-09-16 — the descriptor's address with the type taken
/// off and put back by `self.0 as *mut ffi::fd` — which made `Sock(anything)`
/// constructible from any integer. It became a `*mut ffi::fd` that morning and
/// a **borrow** the same evening, which is what the paragraph above was
/// already describing: `f_get`'s reference is held until the syscall returns,
/// so there is nothing here to own and nothing to drop.
///
/// **Two ways to hold one**, since 2026-09-30. A syscall looks the socket up
/// by number and holds the [`fs_fdobj::FdRef`] that answers -- which has no
/// lifetime to borrow from, only the syscall it belongs to -- and `/proc/net`
/// and the driver's `write` are handed a `&ffi::fd` by their caller. `get` used
/// to make the first a `&'a` of the caller's choosing out of a raw pointer,
/// which is how it could return a borrow of nothing; the borrow checker found
/// that the day `f_get` stopped answering a pointer.
///
/// The state is checked when the handle is made, so a `Sock` that exists is a
/// socket and [`Sock::state`] has nothing left to decide.
#[derive(Clone, Copy)]
struct Sock<'a> {
    fd: Desc<'a>,
}

#[derive(Clone, Copy)]
enum Desc<'a> {
    Syscall(fs_fdobj::FdRef),
    Lent(&'a ffi::fd),
}

/// A host errno `rustix` handed back, as the guest's -- with the `SIGPIPE`
/// that goes with `EPIPE`.
fn rx_err(e: rustix::io::Errno) -> Errno {
    Errno::from_negative_or_eio(kernel_errno::raised(e.raw_os_error()))
}

/// The host socket, or `EBADF` for a description with none -- which is what
/// the host answered when it was handed -1 for it.
fn host_of(fd: &ffi::fd) -> Result<BorrowedFd<'_>, Errno> {
    fd.host().ok_or(Errno::EBADF)
}

/// The fields, read through: `sock.host()`, `sock.flags()`. The inherent
/// methods below are named so that none of them shadows one.
impl std::ops::Deref for Sock<'_> {
    type Target = ffi::fd;
    fn deref(&self) -> &ffi::fd {
        match &self.fd {
            Desc::Syscall(fd) => fd,
            Desc::Lent(fd) => fd,
        }
    }
}

impl<'a> Sock<'a> {
    /// The socket at this number, or why not.
    ///
    /// `EBADF` for a descriptor that is not open and `ENOTSOCK` for one that is
    /// open and is not a socket. Every caller used to answer `EBADF` for both,
    /// so `listen(open("/dev/null"), 5)` said "bad file descriptor" about one
    /// that plainly exists. Measured against a real arm64 kernel.
    fn get(num: c_int) -> Result<Sock<'a>, Errno> {
        let fd = fs_fdobj::f_get(num).ok_or(Errno::EBADF)?;
        state_of(&fd).ok_or(Errno::ENOTSOCK)?;
        Ok(Sock { fd: Desc::Syscall(fd) })
    }

    /// A reference of the caller's own, for a socket found by number -- the
    /// syscall holds one already. `None` for a lent description, which has
    /// nothing to retain through safely.
    fn retain(&self) -> Option<fs_fdobj::Owned> {
        match self.fd {
            Desc::Syscall(fd) => Some(fd.retain()),
            Desc::Lent(_) => None,
        }
    }

    /// The socket this description is, or `None` if it is not one.
    fn of(fd: &'a ffi::fd) -> Option<Sock<'a>> {
        state_of(fd)?;
        Some(Sock { fd: Desc::Lent(fd) })
    }

    /// The host socket, borrowed from the description.
    fn real(&self) -> Result<BorrowedFd<'_>, Errno> {
        host_of(self)
    }

    /// Whether the *host* socket is nonblocking, which it can be without the
    /// guest's flag -- `fcntl` on the host descriptor sets only that one.
    fn host_nonblocking(&self) -> bool {
        self.host()
            .and_then(|h| rustix::fs::fcntl_getfl(h).ok())
            .is_some_and(|f| f.contains(rustix::fs::OFlags::NONBLOCK))
    }

    /// This socket's state, **shared**.
    ///
    /// Safe, and that is the point: it hands out a `&SocketState`, whose every
    /// mutable field carries its own synchronisation. It used to answer a
    /// `&mut` from a `&self` on a `Copy` handle behind an
    /// `#[allow(clippy::mut_from_ref)]` — two calls, two live `&mut` to one
    /// object — with a contract saying "no other borrow is live" that no
    /// syscall entry point can check. See `crates/fs/sock`'s `state` module.
    ///
    /// The downcast is repeated rather than cached, because a cached `&'a`
    /// would need something of lifetime `'a` to borrow from, and a syscall's
    /// `FdRef` is not that. It is a type-id comparison.
    pub(crate) fn state(&self) -> &SocketState {
        state_of(self).expect("a Sock is only made for a socket")
    }

    fn domain(&self) -> c_int {
        self.state().domain
    }

    fn ty(&self) -> c_int {
        self.state().type_
    }

    fn protocol(&self) -> c_int {
        self.state().protocol
    }

    fn peer(&self) -> u64 {
        self.state().peer()
    }

    /// An option the host has no equivalent for and Linux stores. `slot` is
    /// one of `crates/fs/sockabi`'s `STORE_*`; anything else reads as zero
    /// and stores nowhere, so a slot the table names and the array does not
    /// is a test failure in `sockabi` rather than an out-of-bounds write.
    fn stored(&self, slot: c_int) -> i32 {
        let opts = &self.state().stored_opts;
        usize::try_from(slot)
            .ok()
            .and_then(|i| opts.get(i))
            .map_or(0, |v| v.load(Ordering::Relaxed))
    }

    fn set_stored(&self, slot: c_int, value: i32) {
        let opts = &self.state().stored_opts;
        if let Some(at) = usize::try_from(slot).ok().and_then(|i| opts.get(i)) {
            at.store(value, Ordering::Relaxed);
        }
    }

    fn is_unix(&self) -> bool {
        self.domain() == guest::PF_LOCAL
    }

    /// A netlink socket, which is a pair rather than a host socket.
    fn is_netlink(&self) -> bool {
        self.domain() == guest::PF_NETLINK
    }

    /// This socket's address, locked. See [`state::Names`].
    fn names(&self) -> std::sync::MutexGuard<'_, state::Names> {
        self.state().names()
    }

    /// Gives both names back, on a bind that got as far as claiming one and
    /// then failed.
    ///
    /// Taken out under the lock and dropped outside it: `unixname::Handle`'s
    /// release takes the abstract namespace's table lock, and holding this
    /// socket's while it does would be an ordering nothing else here needs.
    fn drop_names(&self) {
        let taken = std::mem::take(&mut *self.names());
        drop(taken);
    }
}


// ---------------------------------------------------------------------------
// Guest memory
// ---------------------------------------------------------------------------

use usercopy::GuestMem;

/// A `u32` at `addr` — the width every socket length argument has.
fn get_u32(addr: u64) -> Result<u32, Errno> {
    let mut word = [0u8; 4];
    match GuestMem.read(addr, &mut word) {
        0 => Ok(u32::from_le_bytes(word)),
        _ => Err(Errno::EFAULT),
    }
}

fn put_u32(addr: u64, value: u32) -> Result<(), Errno> {
    if GuestMem.write(addr, &value.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The calls that only ask the host
// ---------------------------------------------------------------------------

pub fn sys_listen(sock_fd: c_int, backlog: c_int) -> Result<(), Errno> {
    strace!("listen({sock_fd}, {backlog})");
    let sock = Sock::get(sock_fd)?;
    let host = sock.host().ok_or(Errno::EBADF)?;
    rustix::net::listen(host, backlog).map_err(rx_err)?;
    sock.state().listening.store(true, Ordering::Relaxed);
    if let Some(owned) = sock.retain() {
        sockrestart::sockrestart_begin_listen(&owned, backlog, sock.protocol());
    }
    Ok(())
}

pub fn sys_shutdown(sock_fd: c_int, how: c_uint) -> Result<(), Errno> {
    strace!("shutdown({sock_fd}, {how})");
    let sock = Sock::get(sock_fd)?;
    let how = match how {
        0 => rustix::net::Shutdown::Read,
        1 => rustix::net::Shutdown::Write,
        2 => rustix::net::Shutdown::Both,
        // Linux's answer, and the host's when it was handed the number.
        _ => return Err(Errno::EINVAL),
    };
    let host = sock.host().ok_or(Errno::EBADF)?;
    let reading = matches!(how, rustix::net::Shutdown::Read | rustix::net::Shutdown::Both);
    let writing = matches!(how, rustix::net::Shutdown::Write | rustix::net::Shutdown::Both);
    let shut = rustix::net::shutdown(host, how);
    if writing && shut.is_ok() {
        sock.state().write_shut.store(true, Ordering::Relaxed);
    }
    if reading && (shut.is_ok() || shut == Err(rustix::io::Errno::NOTCONN)) {
        sock.state().read_shut.store(true, Ordering::Relaxed);
        sockrestart::sockrestart_wake_accepting(&sock);
    }
    if let Err(e) = shut {
        // Linux's unix_shutdown sets the flag and answers 0 whatever state the
        // socket is in -- it does not consult the peer, and a socket with no
        // peer simply has nothing to tell. Only the internet families answer
        // ENOTCONN.
        //
        // Measured: shutdown on a never-connected AF_UNIX socket is 0 on a real
        // arm64 kernel and was ENOTCONN here, because the *host's* shutdown was
        // asked and Darwin refuses it. A program that shuts a socket down on its
        // way out, without tracking whether it ever connected, saw a failure
        // that means nothing.
        if e == rustix::io::Errno::NOTCONN && sock.is_unix() {
            return Ok(());
        }
        return Err(rx_err(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
