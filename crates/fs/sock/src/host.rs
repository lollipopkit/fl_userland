//! The host's socket calls, as safe functions over a borrowed descriptor.
//!
//! **Every `unsafe` the crate's syscalls need is here.** What `rustix` covers
//! is `rustix`, which takes a `BorrowedFd` and a slice and returns the errno it
//! read -- so no call site holds a pointer, and none can read `errno` after
//! something else has moved it. What it does not is the address argument's
//! `SocketAddrArg`, the raw `getsockopt`/`setsockopt` an option the guest names
//! needs, and the four calls that **return** an address.
//!
//! Those four are `libc` because `rustix` answers "no address" for two
//! different things this crate reports differently: a host that wrote nothing
//! (a connected socket -- nothing is reported to the guest) and, on Darwin, an
//! `AF_UNIX` address with an empty path (an unnamed end -- the family alone is
//! reported). [`AddrBuf`] keeps what the host wrote, length and all.
//!
//! Addresses stay **bytes**: the guest's are translated into the host's layout
//! by `unix.rs` and back by `address.rs`, and a typed address would have to be
//! taken apart again at both ends. What this module adds is the one place
//! that knows where the family is in them.

use std::ffi::c_int;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use rustix::io::Errno as HostErrno;
use rustix::net::addr::{SocketAddrArg, SocketAddrLen, SocketAddrOpaque};
use rustix::net::{AddressFamily, Protocol, RecvFlags, SendFlags, SocketFlags, SocketType};

use crate::SOCKADDR_MAX;

pub(crate) type HostResult<T> = Result<T, HostErrno>;

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// Where `sa_family` is in a host `sockaddr`, and how wide.
///
/// `{ u8 sa_len; u8 sa_family; ... }` on Darwin and `{ u16 sa_family; ... }`
/// on Linux, so a little-endian `u16` of the first two bytes is the family on
/// one host and `sa_len | family << 8` on the other -- which made
/// `getsockname` on an inet socket answer `EINVAL`. Read through the host's
/// own struct rather than an offset written down here.
const FAMILY_AT: usize = std::mem::offset_of!(libc::sockaddr, sa_family);
const FAMILY_SIZE: usize = size_of::<libc::sa_family_t>();

/// The host family of an address, or `None` if it is too short to have one.
pub(crate) fn family(addr: &[u8]) -> Option<c_int> {
    let bytes = addr.get(FAMILY_AT..FAMILY_AT + FAMILY_SIZE)?;
    let mut word = [0u8; 4];
    word[..FAMILY_SIZE].copy_from_slice(bytes);
    // `sa_family_t` is one byte or two, native-endian either way; the zero
    // padding makes both a `u32` of the same value on a little-endian host.
    Some(u32::from_le_bytes(word) as c_int)
}

/// Writes the host family into an address. See [`family`].
pub(crate) fn set_family(addr: &mut [u8], family: c_int) {
    let value = family as libc::sa_family_t;
    addr[FAMILY_AT..FAMILY_AT + FAMILY_SIZE].copy_from_slice(&value.to_ne_bytes());
}

/// A host address the kernel filled in: the bytes and how many it wrote.
///
/// Zeroed before the call, so a host that reports no address leaves
/// `AF_UNSPEC` rather than whatever the stack held.
#[derive(Clone, Copy)]
pub(crate) struct AddrBuf {
    bytes: [u8; SOCKADDR_MAX],
    len: libc::socklen_t,
}

impl AddrBuf {
    fn new() -> AddrBuf {
        AddrBuf {
            bytes: [0; SOCKADDR_MAX],
            len: SOCKADDR_MAX as libc::socklen_t,
        }
    }

    /// The address as the host wrote it, bounded by the buffer: a length the
    /// host reports beyond it is what the address would have been.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..(self.len as usize).min(self.bytes.len())]
    }

    /// Whether the host wrote an address at all: a length, and a family.
    pub(crate) fn is_some(&self) -> bool {
        self.len > 0 && family(self.as_slice()).is_some_and(|f| f != libc::AF_UNSPEC)
    }

    fn parts(&mut self) -> (*mut libc::sockaddr, *mut libc::socklen_t) {
        (self.bytes.as_mut_ptr().cast(), &mut self.len)
    }
}

fn last() -> HostErrno {
    HostErrno::from_io_error(&std::io::Error::last_os_error()).unwrap_or(HostErrno::IO)
}

fn check(r: isize) -> HostResult<usize> {
    if r < 0 { Err(last()) } else { Ok(r as usize) }
}

/// A host address as bytes, for a call that takes one.
pub(crate) struct Addr<'a>(pub(crate) &'a [u8]);

// SAFETY: the pointer and length are one live slice, valid for the whole call
// to `f`, which is what the trait asks for.
unsafe impl SocketAddrArg for Addr<'_> {
    unsafe fn with_sockaddr<R>(&self, f: impl FnOnce(*const SocketAddrOpaque, SocketAddrLen) -> R) -> R {
        f(self.0.as_ptr().cast(), self.0.len() as SocketAddrLen)
    }
}

// ---------------------------------------------------------------------------
// Making sockets
// ---------------------------------------------------------------------------

/// 0 is "the family's default", which `rustix` spells `None`.
fn protocol(raw: c_int) -> Option<Protocol> {
    std::num::NonZeroU32::new(raw as u32).map(Protocol::from_raw)
}

/// `domain`, `ty` and `protocol` are the host's, already translated; `ty` may
/// carry the host's type flags.
pub(crate) fn socket(domain: c_int, ty: c_int, proto: c_int) -> HostResult<OwnedFd> {
    rustix::net::socket(AddressFamily::from_raw(domain as _), SocketType::from_raw(ty as u32), protocol(proto))
}

pub(crate) fn socketpair(domain: c_int, ty: c_int, proto: c_int) -> HostResult<(OwnedFd, OwnedFd)> {
    rustix::net::socketpair(
        AddressFamily::from_raw(domain as _),
        SocketType::from_raw(ty as u32),
        SocketFlags::empty(),
        protocol(proto),
    )
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

pub(crate) fn bind(fd: BorrowedFd<'_>, addr: &[u8]) -> HostResult<()> {
    rustix::net::bind(fd, &Addr(addr))
}

pub(crate) fn connect(fd: BorrowedFd<'_>, addr: &[u8]) -> HostResult<()> {
    rustix::net::connect(fd, &Addr(addr))
}

/// Dissolve a datagram socket's association: `connect` to a whole
/// `sockaddr` of `AF_UNSPEC`, which Darwin does and then answers
/// `EAFNOSUPPORT` for, having done it. Not `rustix::net::connect_unspec`: it
/// passes only the family's two bytes, which Darwin answers `EINVAL` --
/// ambiguous with a real refusal.
pub(crate) fn disconnect(fd: BorrowedFd<'_>) -> HostResult<()> {
    let mut unspec = [0u8; 16];
    unspec[0] = 16; // sa_len
    unspec[1] = libc::AF_UNSPEC as u8;
    match connect(fd, &unspec) {
        Ok(()) | Err(HostErrno::AFNOSUPPORT) => Ok(()),
        Err(e) => Err(e),
    }
}

/// This end's name.
pub(crate) fn sockname(fd: BorrowedFd<'_>) -> HostResult<AddrBuf> {
    let mut out = AddrBuf::new();
    let (addr, len) = out.parts();
    // SAFETY: `addr` is `*len` writable bytes, both out of `out`.
    check(unsafe { libc::getsockname(fd.as_raw_fd(), addr, len) } as isize)?;
    Ok(out)
}

/// The peer's name.
pub(crate) fn peername(fd: BorrowedFd<'_>) -> HostResult<AddrBuf> {
    let mut out = AddrBuf::new();
    let (addr, len) = out.parts();
    // SAFETY: as `sockname`.
    check(unsafe { libc::getpeername(fd.as_raw_fd(), addr, len) } as isize)?;
    Ok(out)
}

/// Accept one connection, and its peer's address as the host wrote it.
pub(crate) fn accept(fd: BorrowedFd<'_>) -> HostResult<(OwnedFd, AddrBuf)> {
    let mut peer = AddrBuf::new();
    let (addr, len) = peer.parts();
    // SAFETY: as `sockname`.
    let n = check(unsafe { libc::accept(fd.as_raw_fd(), addr, len) } as isize)?;
    // SAFETY: `accept` just made it, and nothing else has the number.
    Ok((unsafe { OwnedFd::from_raw_fd(n as c_int) }, peer))
}

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

/// `flags` is the host's `MSG_*`, already translated.
pub(crate) fn send_to(fd: BorrowedFd<'_>, buf: &[u8], flags: c_int, addr: Option<&[u8]>) -> HostResult<usize> {
    let flags = SendFlags::from_bits_retain(flags as u32);
    match addr {
        Some(addr) => rustix::net::sendto(fd, buf, flags, &Addr(addr)),
        None => rustix::net::send(fd, buf, flags),
    }
}

/// Bytes received into `buf`, and the sender's address as the host wrote it
/// -- which it does not for a connected socket; see [`AddrBuf::is_some`].
pub(crate) fn recv_from(fd: BorrowedFd<'_>, buf: &mut [u8], flags: c_int) -> HostResult<(usize, AddrBuf)> {
    let mut from = AddrBuf::new();
    let (addr, len) = from.parts();
    // SAFETY: `buf` is `buf.len()` writable bytes, and `addr` as `sockname`.
    let n = check(unsafe { libc::recvfrom(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), flags, addr, len) })?;
    // The host's count is of the datagram, which `MSG_TRUNC` lets exceed the
    // buffer on some hosts; what is *in* the buffer is the smaller.
    Ok((n.min(buf.len()), from))
}

/// The same, without asking for the address.
pub(crate) fn recv(fd: BorrowedFd<'_>, buf: &mut [u8], flags: c_int) -> HostResult<usize> {
    rustix::net::recv(fd, buf, RecvFlags::from_bits_retain(flags as u32)).map(|(n, _)| n)
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// An option the guest names, into `value`; answers how many bytes the host
/// wrote. Raw because the option is the guest's choice, translated: a typed
/// wrapper per option would be the table in `crates/fs/sockabi` twice.
pub(crate) fn getsockopt(fd: BorrowedFd<'_>, level: c_int, name: c_int, value: &mut [u8]) -> HostResult<usize> {
    let mut len = value.len() as libc::socklen_t;
    // SAFETY: `value` is `len` writable bytes and `len` is a local; the host
    // writes at most `len` and says how many.
    check(unsafe { libc::getsockopt(fd.as_raw_fd(), level, name, value.as_mut_ptr().cast(), &mut len) } as isize)?;
    Ok((len as usize).min(value.len()))
}

pub(crate) fn setsockopt(fd: BorrowedFd<'_>, level: c_int, name: c_int, value: &[u8]) -> HostResult<()> {
    // SAFETY: `value` is `value.len()` readable bytes, which is all the host
    // reads.
    check(unsafe {
        libc::setsockopt(fd.as_raw_fd(), level, name, value.as_ptr().cast(), value.len() as libc::socklen_t)
    } as isize)?;
    Ok(())
}

/// An `int` option.
pub(crate) fn getsockopt_int(fd: BorrowedFd<'_>, level: c_int, name: c_int) -> HostResult<c_int> {
    let mut value = [0u8; size_of::<c_int>()];
    let n = getsockopt(fd, level, name, &mut value)?;
    if n != value.len() {
        return Err(HostErrno::INVAL);
    }
    Ok(c_int::from_ne_bytes(value))
}

pub(crate) fn setsockopt_int(fd: BorrowedFd<'_>, level: c_int, name: c_int, value: c_int) -> HostResult<()> {
    setsockopt(fd, level, name, &value.to_ne_bytes())
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// `sendmsg`: `bufs` to `name` if one is given, carrying `rights` as the one
/// descriptor of an `SCM_RIGHTS` message if one is given.
///
/// A message with no vectors is legal and sends no bytes, but the host
/// refuses `msg_iovlen == 0` -- Darwin's `sendit` answers `EMSGSIZE` -- so
/// that case goes as a single vector of length zero.
pub(crate) fn send_msg(
    fd: BorrowedFd<'_>,
    bufs: &[Vec<u8>],
    name: Option<&[u8]>,
    rights: Option<BorrowedFd<'_>>,
    flags: c_int,
) -> HostResult<usize> {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage};
    use std::io::IoSlice;

    let mut iov: Vec<IoSlice<'_>> = bufs.iter().map(|b| IoSlice::new(b)).collect();
    if iov.is_empty() {
        iov.push(IoSlice::new(&[]));
    }
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let passed = rights.map(|r| [r]);
    if let Some(passed) = &passed {
        // Room for exactly this one, sized by the same macro.
        let pushed = control.push(SendAncillaryMessage::ScmRights(passed));
        debug_assert!(pushed);
    }
    let flags = SendFlags::from_bits_retain(flags as u32);
    match name {
        Some(name) => rustix::net::sendmsg_addr(fd, &Addr(name), &iov, &mut control, flags),
        None => rustix::net::sendmsg(fd, &iov, &mut control, flags),
    }
}

/// What a `recvmsg` got.
pub(crate) struct Received {
    /// What landed in the buffers.
    pub(crate) bytes: usize,
    /// The message's whole length, when the caller asked for it with
    /// `datagram_len`: Linux's answer to `MSG_TRUNC` on a message socket,
    /// which Darwin does not give ([`pending_datagram_len`]). `bytes`
    /// otherwise.
    pub(crate) full_len: usize,
    /// The host's `msg_flags`, untranslated.
    pub(crate) flags: c_int,
    /// The sender, as the host wrote it; see [`AddrBuf::is_some`].
    pub(crate) name: AddrBuf,
    /// The descriptor an `SCM_RIGHTS` carried, owned -- so it closes however
    /// the caller ends, which is what the placeholder is for.
    pub(crate) rights: Option<OwnedFd>,
    /// Every other control message, in the host's terms; see
    /// `crate::ancillary`.
    pub(crate) control: Vec<HostCmsg>,
}

/// The size of the datagram at the head of the receive queue: Darwin's
/// `SO_NREAD`, which for a message socket is the first message's length --
/// not the queue's total, which `FIONREAD` answers. 0 for an empty queue and
/// for a zero-length datagram alike.
///
/// For `MSG_TRUNC` on a message socket, where Linux answers the datagram's
/// full length and Darwin answers what fitted (measured: a 1000-byte datagram
/// into 10 bytes is 10 here, 1000 there). Read **under the caller's peek or
/// receive of that same message** -- see [`recv_msg`]'s `trunc` -- because the
/// head can change between this and the receive on a socket another thread
/// also reads; then the answer is the length of whichever message was taken,
/// as long as nothing else took it first.
pub(crate) fn pending_datagram_len(fd: BorrowedFd<'_>) -> HostResult<usize> {
    let mut n: c_int = 0;
    let mut len = size_of::<c_int>() as libc::socklen_t;
    // SAFETY: `n` is a local `c_int` and `len` says so.
    check(unsafe { libc::getsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_NREAD, (&raw mut n).cast(), &mut len) } as isize)?;
    Ok(n.max(0) as usize)
}

/// Whether something is waiting to be received, without waiting for it.
pub(crate) fn readable_now(fd: BorrowedFd<'_>) -> bool {
    let mut p = [rustix::event::PollFd::new(&fd, rustix::event::PollFlags::IN)];
    rustix::event::poll(&mut p, Some(&rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 })).is_ok_and(|n| n > 0)
}

/// One control message as the host delivered it: Darwin's level and type,
/// and the payload.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HostCmsg {
    pub(crate) level: c_int,
    pub(crate) ty: c_int,
    pub(crate) data: Vec<u8>,
}

/// Darwin's control messages in `buf`, read from bytes: a `cmsghdr` is a
/// 32-bit length, a level and a type, and both the payload and the next
/// header are 4-byte aligned (`__DARWIN_ALIGN32`). A message whose length
/// runs past the buffer ends the walk, as `CMSG_NXTHDR` would.
pub(crate) fn parse_host_cmsgs(buf: &[u8]) -> Vec<HostCmsg> {
    const HDR: usize = 12;
    let word = |at: usize| i32::from_ne_bytes(buf[at..at + 4].try_into().unwrap());
    let mut out = Vec::new();
    let mut at = 0;
    while at + HDR <= buf.len() {
        let len = word(at) as u32 as usize;
        if len < HDR || at + len > buf.len() {
            break;
        }
        out.push(HostCmsg { level: word(at + 4), ty: word(at + 8), data: buf[at + HDR..at + len].to_vec() });
        at += (len + 3) & !3;
    }
    out
}

/// `recvmsg` into `bufs`, asking for the sender only if `want_name` and for
/// control messages only if `want_control`.
///
/// `libc` rather than `rustix` for the reason the module comment gives: the
/// sender is reported as the host wrote it.
pub(crate) fn recv_msg(
    fd: BorrowedFd<'_>,
    bufs: &mut [Vec<u8>],
    want_name: bool,
    want_control: bool,
    flags: c_int,
    datagram_len: bool,
) -> HostResult<Received> {
    // Asked immediately before the receive. The message measured is the one
    // about to be taken unless another reader of this socket takes it in
    // between, which a guest sharing one datagram socket between threads
    // has asked for; the answer is then the next message's length, never
    // less than what was copied (`max` below).
    let pending = if datagram_len { Some(pending_datagram_len(fd)?) } else { None };
    let mut empty = [0u8; 1];
    let mut iov: Vec<libc::iovec> = bufs
        .iter_mut()
        .map(|b| libc::iovec {
            iov_base: b.as_mut_ptr().cast(),
            iov_len: b.len(),
        })
        .collect();
    if iov.is_empty() {
        iov.push(libc::iovec {
            iov_base: empty.as_mut_ptr().cast(),
            iov_len: 0,
        });
    }
    let mut name = AddrBuf::new();
    // Room for every kind a socket here can ask for at once -- pktinfo, TTL,
    // TOS, a timestamp, one descriptor -- with space to spare. It was one
    // descriptor's worth, so Darwin truncated anything else and set
    // MSG_CTRUNC, which reached the guest. `u64`s for a `cmsghdr`'s alignment.
    let mut control = [0u64; 32];

    // SAFETY: every pointer in `msg` is into a local that outlives the call --
    // `iov` and the buffers it points at, `name`, `control` -- and each length
    // is that local's.
    let (bytes, msg_flags, controllen) = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        if want_name {
            let (addr, _) = name.parts();
            msg.msg_name = addr.cast();
            msg.msg_namelen = name.len;
        }
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len() as _;
        if want_control {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = size_of_val(&control) as _;
        }
        let bytes = check(libc::recvmsg(fd.as_raw_fd(), &mut msg, flags))?;
        name.len = if want_name { msg.msg_namelen } else { 0 };
        (bytes, msg.msg_flags, if want_control { msg.msg_controllen as usize } else { 0 })
    };
    let raw: Vec<u8> = control.iter().flat_map(|w| w.to_ne_bytes()).take(controllen).collect();
    let mut control = parse_host_cmsgs(&raw);
    // The descriptors an `SCM_RIGHTS` carried are this process's now and
    // nothing else has their numbers: owned at once, so each closes however
    // the caller ends. The first is the placeholder; a second cannot arrive,
    // and would be closed.
    let mut rights = None;
    control.retain(|m| {
        if m.level != libc::SOL_SOCKET || m.ty != libc::SCM_RIGHTS {
            return true;
        }
        for raw in m.data.as_chunks::<4>().0 {
            // SAFETY: a descriptor the host just installed in this process for
            // this message, which nothing else has seen.
            let fd = unsafe { OwnedFd::from_raw_fd(c_int::from_ne_bytes(*raw)) };
            rights.get_or_insert(fd);
        }
        false
    });
    Ok(Received {
        bytes,
        full_len: pending.map_or(bytes, |p| p.max(bytes)),
        flags: msg_flags,
        name,
        rights,
        control,
    })
}
