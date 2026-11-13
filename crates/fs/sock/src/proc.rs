//! Socket information exposed to `/proc/net`.

use std::ffi::c_int;
use std::sync::atomic::Ordering;

use crate::{Sock, ffi, host};

// ---------------------------------------------------------------------------
// What /proc/net/{tcp,tcp6,udp,udp6,unix} reports
// ---------------------------------------------------------------------------

/// One socket, as the `/proc/net/*` files describe it.
///
/// Assembled here rather than in `crates/fs/proc` so that the layout of
/// `SocketState` and the rule for a unix socket's name stay in this crate — a
/// reader that reached in for `unix_peer` would be a second place that knows
/// what a handle is.
pub struct NetInfo {
    pub domain: c_int,
    pub type_: c_int,
    pub protocol: c_int,
    /// The host's `sockaddr` for each end, empty when the host has none —
    /// which for a unix socket is always, because the host socket is bound to a
    /// path in `/tmp` and the guest's name is `crates/fs/unixpeer`'s.
    pub local: Vec<u8>,
    pub remote: Vec<u8>,
    /// Whether `listen` has been called: the column every reader looks at
    /// first, and recorded rather than asked because macOS has no
    /// `SO_ACCEPTCONN` to read back.
    pub listening: bool,
    /// The guest's name for a unix socket: a path, or an abstract name with a
    /// leading NUL. Empty for one that bound nothing.
    pub unix_name: Vec<u8>,
    /// Whether a unix socket has a peer.
    pub unix_connected: bool,
    pub inode: u64,
}

/// What `/proc/net/*` needs about a socket descriptor, or `None` for one that
/// is not a socket.
///
/// Safe: a `&ffi::fd` is a live description for as long as it is borrowed,
/// and every read here is of this crate's own state or a host call on the
/// description's socket.
pub fn net_info(fd: &ffi::fd) -> Option<NetInfo> {
    // The driver is the test: `state.socket` is only a `SocketState` for a
    // descriptor this crate made, and reading it for any other is what the
    // check exists to stop. A downcast rather than a comparison of table
    // addresses, which is what it was until 2026-09-11.
    let sock = Sock::of(fd)?;
    let st = sock.state();

    let mut local = Vec::new();
    let mut remote = Vec::new();
    if !sock.is_unix()
        && let Ok(real) = sock.real()
    {
        if let Ok(name) = host::sockname(real) {
            local = name.as_slice().to_vec();
        }
        if let Ok(peer) = host::peername(real) {
            remote = peer.as_slice().to_vec();
        }
    }

    let (unix_name, unix_connected) = if sock.is_unix() {
        let handle = st.peer();
        let name = unixpeer::with_table(|t| t.name(handle).to_vec());
        let connected = unixpeer::with_table(|t| t.peer_of(handle).is_some());
        (name, connected)
    } else {
        (Vec::new(), false)
    };

    Some(NetInfo {
        domain: st.domain,
        type_: st.type_,
        protocol: st.protocol,
        local,
        remote,
        listening: st.listening.load(Ordering::Relaxed),
        unix_name,
        unix_connected,
        inode: fd.stat.inode,
    })
}
