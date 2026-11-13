//! Accept and local peer handshake handling.

use std::ffi::c_int;
use std::os::fd::BorrowedFd;

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno as HostErrno;
use sockabi::guest;
use strace::strace;

use crate::{
    Errno, Sock, caller_cred, fd_new, get_u32, host, interrupted_accept, put_u32, rx_err, state_of,
    write_host_addr,
};

// ---------------------------------------------------------------------------
// accept
// ---------------------------------------------------------------------------

/// The `AF_LOCAL` peer handshake.
///
/// Two sockets in this kernel that connect to each other have to find each
/// other's endpoint, and the only channel between them is the host socket. What
/// used to go over it was the *address* of the connecting `struct fd`, which
/// the accepting side then dereferenced and wrote through as given. The host
/// socket lives at `/tmp/iulsock<pid>.<id>`, so on a build where that is a real
/// path, anything on the host that connects to it picks the pointer. It was
/// also read with a single `read()` whose short return was ignored, so a peer
/// that sent fewer than eight bytes had them silently swallowed out of the
/// stream.
///
/// What goes over it now is a magic number and an id. The id names an entry in
/// a table that `connect` adds to for as long as its handshake is outstanding,
/// so an id that is not in the table is a peer that is not one of ours —
/// nothing to dereference. Both fields are fixed-width and little-endian on
/// every platform this builds for.
///
/// A peer that is not in this host process is not asked for one at all -- see
/// [`peer_is_this_process`]. It used to be, and a foreign peer that connected
/// and sent nothing held every later accept on that listener in the read.
pub(super) const UNIX_HANDSHAKE_MAGIC: u64 = 0x2a72_6565_506c_7569; // "iulPeer*"

/// Who is on the other end of an accepted unix socket.
///
/// **Three answers, not two, and treating the third as `Foreign` corrupted the
/// stream.** Every guest socket is in this host process, because one host
/// process runs every guest thread — so `Ours` is the exact test for "a peer
/// that will send the handshake". The host answers it from the connection
/// itself: `LOCAL_PEERPID` on Darwin, `SO_PEERCRED` on Linux.
///
/// The question can fail, and the commonest reason is not a foreign peer: a
/// peer of ours that has **already closed**. Darwin's `LOCAL_PEERPID` answers
/// `ENOTCONN` then, which is what a client that connects, writes and exits
/// produces every time the accept loses the race.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Peer {
    /// This host process: it has sent, or will send, a handshake.
    Ours,
    /// Somebody else on the host: it does not know the protocol.
    Foreign,
    /// The host would not say. **Not the same as `Foreign`** — the usual cause
    /// is that the peer has closed, so whatever it sent is already buffered and
    /// can be looked at without waiting for anything.
    Unknown,
}

fn peer_of(fd: BorrowedFd<'_>) -> Peer {
    match peer_pid(fd) {
        Some(pid) if pid == std::process::id() => Peer::Ours,
        Some(_) => Peer::Foreign,
        None => Peer::Unknown,
    }
}

fn peer_pid(fd: BorrowedFd<'_>) -> Option<u32> {
    // `pid_t` is an `int`, and the helper refuses an answer of any other size.
    const _: () = assert!(size_of::<libc::pid_t>() == size_of::<c_int>());
    host::getsockopt_int(fd, libc::SOL_LOCAL, libc::LOCAL_PEERPID).ok().map(|pid| pid as u32)
}

/// read/write until the whole buffer is done, EOF, or a real error. A stream
/// socket is free to split a sixteen-byte message.
pub(super) fn io_full(fd: BorrowedFd<'_>, buf: &mut [u8], writing: bool) -> Option<usize> {
    let mut done = 0usize;
    while done < buf.len() {
        let rest = &mut buf[done..];
        let n = if writing {
            rustix::io::write(fd, rest)
        } else {
            rustix::io::read(fd, rest)
        };
        match n {
            Err(HostErrno::INTR) => continue,
            Err(_) => return None,
            Ok(0) => break, // EOF; the peer is gone or is not one of ours
            Ok(n) => done += n,
        }
    }
    Some(done)
}

/// Consume the peer handshake, if the peer sent one, and answer its id.
///
/// **The handshake is in band, so failing to consume it does not lose it — it
/// *becomes data*.** That is what happened: a client that connected, wrote its
/// handshake and exited left `LOCAL_PEERPID` answering `ENOTCONN`, the peer was
/// classified foreign, the sixteen bytes stayed in the stream, and the guest's
/// first `read` returned `iulPeer*` where the program had sent `ping`. Two
/// independent test runs caught it about one time in thirty.
///
/// So the decision is made from **what is in the stream**, not from who the
/// host says the peer is, and `MSG_PEEK` is what makes that possible: looking
/// costs nothing and leaves a foreign peer's bytes where they are.
///
/// | peeked | peer | what happens |
/// | --- | --- | --- |
/// | the magic | any | consume 16 bytes. Only this kernel writes those eight bytes, and a foreign peer that reproduces them is claiming an id that is not outstanding, which does nothing |
/// | 8 bytes, not the magic | any | leave it. Somebody else's protocol, or a peer of ours whose `connect` could not send |
/// | fewer than 8 | [`Peer::Ours`] | wait for more: a peer of ours has sent or is about to send |
/// | fewer than 8 | [`Peer::Foreign`] or [`Peer::Unknown`] | leave it. `Unknown` is a peer that has **closed**, so everything it will ever send is already here |
///
/// The wait is bounded, which the old blocking read was not. Its purpose is a
/// peer of ours whose `write` has not landed yet — sixteen bytes into an empty
/// socket buffer, so microseconds — and the only way it does not arrive is that
/// the peer's `connect` failed to send and unpublished the id. That used to
/// park the accept for ever.
fn take_handshake(client: BorrowedFd<'_>) -> Option<u64> {
    /// Long enough that a scheduling hiccup between `connect` returning and its
    /// `write` landing cannot reach it, short enough not to matter when the
    /// peer never writes at all.
    const BUDGET: std::time::Duration = std::time::Duration::from_millis(500);

    let peer = peer_of(client);
    if peer == Peer::Foreign {
        return None;
    }
    let deadline = std::time::Instant::now() + BUDGET;
    let mut hs = [0u8; 16];
    loop {
        match host::recv(client, &mut hs, libc::MSG_PEEK | libc::MSG_DONTWAIT) {
            Err(HostErrno::INTR) => continue,
            // Nothing readable yet. Only a peer of ours is worth waiting for,
            // and only while it is still connected -- `Unknown` means it has
            // closed, so there is nothing more to come.
            Err(HostErrno::AGAIN) if peer == Peer::Ours => {}
            Err(_) => return None,
            Ok(0) => return None, // the peer sent nothing at all and is gone
            Ok(peeked) if peeked >= 8 => {
                if u64::from_le_bytes(hs[..8].try_into().unwrap()) != UNIX_HANDSHAKE_MAGIC {
                    return None;
                }
                if peeked == hs.len() {
                    // Committed: the magic is ours, so the other eight bytes
                    // were written in the same call and are here or imminent.
                    if io_full(client, &mut hs, false) != Some(hs.len()) {
                        return None;
                    }
                    return Some(u64::from_le_bytes(hs[8..].try_into().unwrap()));
                }
                // The magic arrived split. Fall through and wait for the rest.
            }
            // Fewer than eight bytes from a peer that has closed: it never
            // sent a handshake, and what is there is somebody's data.
            Ok(_) if peer != Peer::Ours => return None,
            Ok(_) => {}
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        // A millisecond, so the budget above is a count rather than one long
        // sleep -- the common case returns on the first peek and never gets
        // here at all. Whatever it answers, the peek above asks again.
        let tick = Timespec { tv_sec: 0, tv_nsec: 1_000_000 };
        let _ = rustix::event::poll(&mut [PollFd::new(&client, PollFlags::IN)], Some(&tick));
    }
}

fn accept_common(
    sock_fd: c_int,
    addr: u64,
    len_addr: u64,
    flags: c_int,
) -> Result<c_int, Errno> {
    let sock = Sock::get(sock_fd)?;
    let buffer_len = if addr != 0 { get_u32(len_addr)? } else { 0 };

    let client;
    loop {
        sockrestart::sockrestart_begin_listen_wait(&sock);
        // After the registration, so that a `shutdown` which comes later finds
        // this thread to wake. Only a blocking accept: a non-blocking one on
        // a shut-down listener answers `EAGAIN` on Linux, as the host does.
        if sock.state().read_shut.load(std::sync::atomic::Ordering::Relaxed) && !sock.host_nonblocking() {
            sockrestart::sockrestart_end_listen_wait(&sock);
            return Err(Errno::EINVAL);
        }
        let res = sock.real().map(|h| host::accept(h).map_err(|e| (e, h)));
        sockrestart::sockrestart_end_listen_wait(&sock);
        let (accepted, peer) = match res? {
            Ok(accepted) => accepted,
            Err((HostErrno::INTR, real)) => {
                if sockrestart::sockrestart_should_restart_listen_wait() {
                    continue;
                }
                // Only a guest signal ends the wait: the host EINTR may be
                // the emulator's own SIGUSR1 delivering one, or nothing at
                // all, and a caller told EINTR with no signal to handle has
                // been told a lie. `sock_io` has the same rule. A real
                // interruption says whether the call may be restarted, which
                // is the socket's to know -- see `wait::interrupted_accept`.
                if !taskview::current_signal_pending() {
                    continue;
                }
                return Err(Errno::from_negative_or_eio(interrupted_accept(real)));
            }
            Err((e, _)) => return Err(rx_err(e)),
        };
        if addr != 0 {
            // Reporting the address must not cost the caller the connection: on
            // failure the accepted host socket is closed and the error returned.
            // Returning the descriptor handed a *host* number back as the result
            // of a guest syscall, and leaked it besides.
            let reported = write_host_addr(addr, peer.as_slice(), buffer_len)
                .and_then(|report| put_u32(len_addr, report));
            reported?;
        }
        client = accepted;
        break;
    }

    let client_fd = match fd_new(client, sock.domain(), sock.ty(), sock.protocol()) {
        // it closed `client`; see fd_new
        None => return Err(Errno::ENOMEM),
        Some(fd) => fd,
    };

    if sock.is_unix() {
        // `fd_new` just made this one, so it has a state.
        let handle = state_of(&client_fd).map_or(0, crate::SocketState::peer);
        unixpeer::with_table(|t| {
            t.set_cred(handle, caller_cred());
            // The accepted socket carries the listener's name, as Linux does --
            // unix_stream_connect copies the listening socket's address onto the
            // new one. It is what the *client* gets back from getpeername: the
            // path it connected to. Without it the accepted socket had no name
            // and a client asking who it was talking to was told nobody.
            let name = t.name(sock.peer()).to_vec();
            t.set_name(handle, &name);
        });

        // Nothing happens for an id that is not outstanding -- a peer that is
        // not one of ours, or one whose connect has already given up. The
        // connection still works; it just has no peer credentials and no
        // SCM_RIGHTS. Claiming also moves anything the client sent before this
        // moment into the new socket's receive queue, ahead of anything sent
        // from now on.
        // The number, read back off the description that owns it now.
        if let Some(id) = crate::host_of(&client_fd).ok().and_then(take_handshake) {
            unixpeer::with_table(|t| t.claim(handle, id));
        }
    }

    Errno::split(fs_fdobj::f_install(client_fd, flags) as i64).map(|n| n as c_int)
}

pub fn sys_accept(sock_fd: c_int, addr: u64, len_addr: u64) -> Result<c_int, Errno> {
    strace!("accept({sock_fd}, {addr:#x}, {len_addr:#x})");
    accept_common(sock_fd, addr, len_addr, 0)
}

pub fn sys_accept4(
    sock_fd: c_int,
    addr: u64,
    len_addr: u64,
    flags: c_int,
) -> Result<c_int, Errno> {
    strace!("accept4({sock_fd}, {addr:#x}, {len_addr:#x}, {flags:#x})");
    if flags & !(guest::SOCK_NONBLOCK | guest::SOCK_CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    accept_common(sock_fd, addr, len_addr, flags)
}
