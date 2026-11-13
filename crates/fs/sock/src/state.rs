//! State owned by one socket descriptor.
//!
//! The socket syscall glue reaches this through the descriptor's opaque pointer.
//! Keeping the state and its sentinel values here makes the lifetime invariant
//! visible without changing the descriptor layout.
//!
//! # Every mutable field carries its own synchronisation
//!
//! A descriptor is shared: `dup`, or `CLONE_FILES`, which every pthread is.
//! None of `bind`, `connect`, `listen` or `setsockopt` takes `fd->lock` — Linux
//! does not either, it takes `lock_sock()` — so two threads reach this object
//! at once whenever a program calls any of them on one socket.
//!
//! Until 2026-09-14 [`state_of`] answered a `&mut SocketState` with a lifetime
//! the caller chose, and `Sock::state` handed one out from a `&self` on a
//! `Copy` handle behind `#[allow(clippy::mut_from_ref)]`. Two calls, two live
//! `&mut` to one object: the aliasing UB
//! `docs/changelog/2026-08-31-a-release-build-hung-closing-a-descriptor.md` records.
//! Its contract said "no other borrow of this socket's state is live", which is
//! not a thing a syscall entry point can check.
//!
//! So the accessor answers a **shared** reference and the mutable fields are
//! each an atomic or a lock. Which one is decided by what the field is for:
//! [`Names`] is a lock because "has it got an address?" and "take this one" are
//! one question, and the rest are single values nothing else is consistent
//! with.

use std::ffi::c_int;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use crate::ffi;

/// The socket's address, and the lock that makes taking one atomic.
///
/// Linux's `unix_sock::addr` under `unix_sock::bindlock`, and it is a lock for
/// Linux's reason: `bind` tests "does this socket already have a name" and then
/// takes one, and a second thread between those two steps means **both** claim.
/// The loser's claim is then stored over the winner's and never released, so
/// the name stays taken for the life of the process. Measured on 2026-09-14 at
/// 13 to 25 leaked names per 400 rounds of two threads, once the ordering half
/// of the same defect was fixed —
/// `docs/changelog/2026-09-14-a-refused-second-bind-stole-the-sockets-name.md`.
///
/// Held across the whole claim, which for a path includes the VFS walk and the
/// `mknod`: that is what makes a refused bind create nothing. Nothing below it
/// — the VFS, `crates/fs/unixname` — knows sockets exist, so there is no way
/// back to this lock from inside it.
#[derive(Default)]
pub(super) struct Names {
    /// The inode a path bind created or found, held so the node stays alive
    /// while there is a listener.
    pub(super) inode: Option<fs_inode::Ref>,
    /// The abstract name this socket bound, in `crates/fs/unixname`. Owned:
    /// dropping it releases the name.
    pub(super) abstract_: Option<unixname::Handle>,
}

impl Names {
    /// Whether the socket has an address. Linux's `u->addr`.
    pub(super) fn any(&self) -> bool {
        self.inode.is_some() || self.abstract_.is_some()
    }
}

// Both fields were a `usize` until 2026-09-14 -- one an `Arc` leaked with
// `into_raw`, the other a `Box::into_raw(Box::new(Handle)) as usize`. Giving
// them back was written out on three paths, each reading the field, calling a
// release, and storing 0; the comment above the third said that doing it twice
// "corrupted the allocator's free list". `Option::take` is that sequence, and
// `Option<T>` is what makes the second one a no-op rather than a double free.

/// It was eight members of `struct fd`'s union until 2026-09-05, and the only
/// arm of that union that was not a single pointer: every other kind of
/// descriptor keeps its state in the crate that understands it, and this one
/// spelled itself out in a type forty-five crates can see. Allocated by
/// [`fd_new`] and freed by `sock_close`, which are the two places a socket
/// description begins and ends.
///
/// Not `#[repr(C)]`: nothing but this crate ever looks at it, and `struct fd`
/// holds it as an opaque pointer.
///
/// `Default` is derived. It was written out until 2026-09-29 for one field:
/// `netlink_end` was an `AtomicI32` that had to start at **-1**, because 0 is
/// a valid descriptor -- the guest's standard input -- and a derived default
/// plus the `end >= 0` check in `sock_close` would have closed stdin every
/// time any socket was closed. An empty `OnceLock<OwnedFd>` has no number to
/// get wrong.
#[derive(Default)]
pub(super) struct SocketState {
    // Written by `fd_new` into the box before the descriptor exists, and never
    // again. No synchronisation because there is no second writer.
    pub(super) domain: c_int,
    pub(super) type_: c_int,
    pub(super) protocol: c_int,

    /// The socket's address. See [`Names`].
    pub(super) names: Mutex<Names>,

    /// Everything about the socket at the other end, in `crates/fs/unixpeer`:
    /// the peer edge, the names each side reports, the credentials
    /// `SO_PEERCRED` answers with, and the control messages in flight.
    ///
    /// A *handle*, not a pointer — six fields and a global lock used to live
    /// in `struct fd`, with the peer held as a raw `struct fd *` in both
    /// directions and no reference either way. 0 for a socket that is not
    /// `AF_LOCAL`.
    ///
    /// Written once, by `fd_new`, and only for `AF_LOCAL`. Atomic because it is
    /// written *after* the box is built — through the shared reference every
    /// other reader uses — rather than because two threads race for it.
    pub(super) unix_peer: AtomicU64,

    /// A non-blocking connect that answered `EINPROGRESS` and whose result
    /// nobody has collected with a second `connect()` yet. Linux returns 0
    /// from that call and Darwin `EISCONN`, and this is what tells them apart.
    pub(super) connect_in_progress: AtomicBool,

    /// `shutdown(SHUT_RD)` or `SHUT_RDWR` has been called. What it changes is
    /// a blocking `accept`, which Linux ends with `EINVAL` -- the one already
    /// waiting and any that starts later. The host's own shutdown ends
    /// neither on a Darwin listening socket, so this is where the answer
    /// comes from; see `accept_common`.
    pub(super) read_shut: AtomicBool,

    /// `shutdown(SHUT_WR)` or `SHUT_RDWR` has been called. Darwin then
    /// reports this socket `POLLHUP` and not writable; Linux keeps it
    /// writable (a write is EPIPE) and reports HUP only once both directions
    /// are shut. See `host_revents`.
    pub(super) write_shut: AtomicBool,

    /// On an IPv6 socket, which pktinfo the guest asked for: `IP_PKTINFO`
    /// (Linux applies it to the IPv4 datagrams a dual-stack socket receives;
    /// Darwin refuses it) and `IPV6_RECVPKTINFO`. The host is asked for the
    /// second if either is set. See `crate::ancillary`.
    pub(super) v6_ip_pktinfo: AtomicBool,
    pub(super) v6_ipv6_pktinfo: AtomicBool,

    /// A netlink socket's own end of the pair; empty for anything else. It
    /// closes when the state is dropped, which is `sock_close`'s last step.
    ///
    /// `AF_NETLINK` is not a host socket: the host has no such family, and what
    /// a guest wants from it is an answer this kernel composes. So the
    /// descriptor is one end of an `AF_UNIX` datagram pair and this is the
    /// other — a request written by the guest is answered by writing the reply
    /// into this end, and the guest reads it back through the ordinary path.
    ///
    /// A pair rather than a queue of our own because *everything else then
    /// works*: `poll`, `O_NONBLOCK`, `recvmsg`'s message boundaries, a blocking
    /// read that a signal interrupts. A queue would be a second implementation
    /// of all of it.
    pub(super) netlink_end: std::sync::OnceLock<OwnedFd>,

    /// Whether `listen` has been called, for `/proc/net/*`'s state column.
    ///
    /// Recorded rather than asked, because **macOS's `getsockopt` has no
    /// `SO_ACCEPTCONN`** -- it answers -1 both before and after `listen`, so
    /// there is nothing to read back. A socket reported as closed when it is
    /// listening is exactly the wrong answer for the caller who reads
    /// `/proc/net/tcp` to find out whether something is up.
    pub(super) listening: AtomicBool,

    /// Options the host has no equivalent for and Linux *stores*: a set is
    /// accepted and a get reads back what was set. Measured by `sock_probe`:
    /// `SO_PRIORITY`, `TCP_USER_TIMEOUT` and `TCP_DEFER_ACCEPT` read back as
    /// set on a real kernel. Indexed by `crates/fs/sockabi`'s `STORE_*` slots.
    ///
    /// One atomic per slot rather than a lock: the slots are independent and a
    /// reader of one is not asking about another.
    pub(super) stored_opts: [AtomicI32; 3],
}


impl SocketState {
    /// The address, locked. Poison is ignored: this crate's own panics are
    /// caught at the C ABI shim and a socket whose bind panicked is still a
    /// socket somebody has to be able to close.
    pub(super) fn names(&self) -> std::sync::MutexGuard<'_, Names> {
        self.names.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn peer(&self) -> u64 {
        self.unix_peer.load(Ordering::Relaxed)
    }

    /// The kernel's end of a netlink socket's pair.
    pub(super) fn netlink(&self) -> Option<BorrowedFd<'_>> {
        self.netlink_end.get().map(|fd| fd.as_fd())
    }
}

/// The state behind a socket description, or `None` for any other kind.
///
/// A **shared** reference: see the module comment for what a `&mut` here cost.
///
/// The description's driver state since 2026-09-29, so the question "is this
/// a socket" and the read are one downcast. It was an `unsafe fn` over a
/// union arm, whose contract was that the caller had checked the operations
/// table first -- and before 2026-09-16 it answered a reference for **any**
/// lifetime, so a caller could hold the state after the description had gone.
impl SocketState {
    pub(super) fn v6_wants(&self) -> crate::ancillary::V6Wants {
        crate::ancillary::V6Wants {
            ip_pktinfo: self.v6_ip_pktinfo.load(Ordering::Relaxed),
            ipv6_pktinfo: self.v6_ipv6_pktinfo.load(Ordering::Relaxed),
        }
    }

    pub(super) fn set_v6_wants(&self, w: crate::ancillary::V6Wants) {
        self.v6_ip_pktinfo.store(w.ip_pktinfo, Ordering::Relaxed);
        self.v6_ipv6_pktinfo.store(w.ipv6_pktinfo, Ordering::Relaxed);
    }
}

pub(super) fn state_of(fd: &ffi::fd) -> Option<&SocketState> {
    fd.driver_state()
}

/// The host's poll bits for this socket, with its own `SHUT_WR` read as Linux
/// reads it.
///
/// Darwin reports a socket that has shut its own writing side as `POLLHUP`
/// and not writable. Linux keeps it writable -- the write is EPIPE -- and
/// reports HUP only when the receiving side is finished too: shut here, or a
/// stream whose peer has sent its end. So `nc -u`, which shuts its write side
/// at the end of its input and polls for a reply, was woken at once by the
/// HUP and blocked in a read that nothing would answer (`tests/guest`
/// udp_probe).
pub(super) fn host_revents(fd: &ffi::fd, revents: c_int) -> c_int {
    let hup = libc::POLLHUP as c_int;
    let Some(state) = state_of(fd) else {
        return revents;
    };
    if revents & hup == 0 || !state.write_shut.load(Ordering::Relaxed) {
        return revents;
    }
    let out = revents | libc::POLLOUT as c_int;
    if state.read_shut.load(Ordering::Relaxed) || (revents & libc::POLLIN as c_int != 0 && peer_finished(fd, state)) {
        return out;
    }
    out & !hup
}

/// Whether a stream's peer has sent its end: a peek finds end-of-file.
fn peer_finished(fd: &ffi::fd, state: &SocketState) -> bool {
    if state.type_ != crate::guest::SOCK_STREAM {
        return false;
    }
    let Some(host) = fd.host() else {
        return false;
    };
    let mut b = [0u8; 1];
    rustix::net::recv(host, &mut b, rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT).is_ok_and(|(n, _)| n == 0)
}
