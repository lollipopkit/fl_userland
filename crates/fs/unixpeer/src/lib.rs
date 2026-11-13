//! What one `AF_UNIX` socket knows about the one at the other end.
//!
//! Two iul sockets connected to each other have to find each other's kernel
//! object, and the only channel between them is the host socket underneath.
//! What goes over it is a magic number and an *id*, and the id names an entry
//! here that `connect` publishes and `accept` claims — so an id that is not
//! outstanding is a peer that is not one of ours, and there is nothing to
//! dereference. It used to be the address of the connecting `struct fd`,
//! written through as given.
//!
//! # Why this is a table of ids and not a graph of pointers
//!
//! The C kept the relationship as raw `struct fd *` in both directions, with
//! no reference either way, under one global `peer_lock`. Every question about
//! it — is my peer still there, whose credentials are these, where do these
//! descriptors go — was a pointer dereference whose validity came from holding
//! that lock, and every answer had to be *used* while still holding it. The
//! shape produced the defect the `sendmsg` cleanup path carries a paragraph
//! about: reading `sock->socket.unix_peer` again at cleanup time took the wrong
//! lock if the peer had changed, and skipped the unlink entirely if it had gone
//! — freeing a node that was still in that peer's list.
//!
//! Here an endpoint is a number in a map. A peer that has closed is a number
//! that is not in it; there is no pointer to be stale. The one lock is kept —
//! deliberately, so the ordering against `scm_send_lock` and the descriptor
//! table is exactly what it was — but nothing outside can hold a reference
//! into what it protects.
//!
//! # What is still C's
//!
//! A control message. `ControlMessage` holds retained descriptor addresses, and
//! the descriptor layer owns those; the queue here transports address values
//! and [`Table::drain`] hands them back for `fs-sock` to release. That is the
//! same split `crates/fs/inotify` uses: the registry is Rust's, the thing being
//! registered stays where its lifetime is managed.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// The descriptors one queued `SCM_RIGHTS` control message carries.
///
/// **Owning, since 2026-09-12.** It held `usize` addresses and the comment said
/// "the descriptor layer owns their lifetime; this queue only transports the
/// addresses until `fs-sock` installs or releases them" — which is a lifetime
/// obligation spread over three release paths in another crate, and one of them
/// released a descriptor twice.
///
/// `fs-unixpeer` already depends on `fs-fdobj`, so the queue can hold the
/// handle rather than the address, and a message dropped anywhere — a peer that
/// goes away, a `sendmsg` that fails after queuing, a receiver with no room —
/// releases exactly what it holds.
/// **And in the queue by value, since 2026-09-16.** The queues were
/// `VecDeque<usize>` and `Vec<usize>` holding `Box::into_raw` addresses, so
/// every one of the five entry points below spoke in `*mut ControlMessage`,
/// `crates/fs/sock` had a `scm_into_raw`/`scm_free` pair around them, and the
/// address was doing double duty as the message's *identity* — which is what
/// [`Table::unqueue`] searched the queues for. A `ScmId` is that identity
/// without the dereference, and the message can then live where it is queued.
pub struct ControlMessage {
    id: ScmId,
    pub fds: Vec<fs_fdobj::Owned>,
}

impl ControlMessage {
    /// Which message this is, for [`Table::unqueue`].
    pub fn id(&self) -> ScmId {
        self.id
    }
}

/// Which queued control message.
///
/// Handed out by [`Table::queue`] so that a `sendmsg` failing *after* it has
/// queued can take its message back. Never reused, for the reason
/// [`Table::open`] gives about endpoint handles: an id whose message has been
/// received answers "gone" rather than reaching the next one queued.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ScmId(u64);

/// Where [`Table::queue`] put a control message.
///
/// Three `c_int` constants — `QUEUED_NOWHERE`, `QUEUED_PEER`, `QUEUED_OWN` —
/// until 2026-09-16, of which the only caller outside this crate's tests
/// compared against one. "Nowhere" is the `None`, and it is not a *place*: the
/// message is dropped and its descriptors released, which a third variant
/// carrying an id could not say.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Queued {
    /// To the peer's inbox, to be received.
    Peer(ScmId),
    /// Onto this socket's own outbox: nobody has accepted the connection yet,
    /// and [`Table::claim`] splices these onto the socket `accept` creates.
    Own(ScmId),
}

impl Queued {
    pub fn id(self) -> ScmId {
        match self {
            Queued::Peer(id) | Queued::Own(id) => id,
        }
    }
}

/// The `ucred` a `SO_PEERCRED` reports. Filled at connect and at accept, from
/// the *effective* ids, as Linux's `init_peercred` does.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Ucred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// The greatest length a unix socket name can have, which is `sun_path`'s.
///
/// **Not `NAME_MAX`**: see the note on the same constant in `crates/fs/sockaddr`.
pub const UNIX_NAME_MAX: usize = 108;

/// What a client knows about its peer between `connect` and the server's
/// `accept`: the listener's credentials and the address it connected to.
/// Linux copies both onto the client at connect (`unix_stream_connect`'s
/// `copy_peercred` and its copy of the listener's address), so `SO_PEERCRED`
/// and `getpeername` answer before anyone has accepted. Superseded by the
/// real peer once the handshake is claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Expected {
    cred: Ucred,
    name: Vec<u8>,
}

#[derive(Default)]
struct Endpoint {
    /// The endpoint at the other end, or `None`. Not a pointer: an endpoint
    /// that has closed is simply not in the table, so a stale edge answers
    /// "gone" instead of being followed.
    peer: Option<u64>,
    /// See [`Expected`]. `None` until a connect, and after a claim it is
    /// what the peer answers anyway.
    expected: Option<Expected>,
    /// The socket id `bind` gave this endpoint's name -- the number in the
    /// host path -- which is how a connecting client finds the listener it
    /// is connecting to. `None` for a socket that is not bound.
    socket_id: Option<u64>,
    /// This socket's own name, as `bind` recorded it. `getpeername` reads the
    /// peer's — it is the path the client connected to, which is what Linux
    /// answers from `unix_stream_connect`'s copy of the listener's address.
    name: Vec<u8>,
    /// This socket's own credentials. `SO_PEERCRED` reads the peer's.
    cred: Ucred,
    /// Control messages waiting to be received.
    inbox: VecDeque<ControlMessage>,
    /// Control messages sent before this socket had a peer, which is every one
    /// sent between `connect` and the server's `accept`. The message goes out
    /// on the wire either way, so the descriptors wait here and `accept`
    /// splices them onto the socket it creates, ahead of anything sent from
    /// then on. Their order is the order they went out.
    ///
    /// This used to be a wait: `sendmsg` blocked until a peer appeared, and a
    /// listener that simply stops accepting never ends that — six runs in
    /// eight of the socket race probe hung there.
    outbox: Vec<ControlMessage>,
}

#[derive(Default)]
pub struct Table {
    endpoints: HashMap<u64, Endpoint>,
    /// Handshake id to the endpoint that published it. `connect` adds, and the
    /// `accept` that reads that id off the wire takes it away.
    pending: HashMap<u64, u64>,
    /// Socket id to the bound endpoint, for a client to find the listener
    /// it is connecting to. `bind` adds; the endpoint's close removes.
    bound: HashMap<u64, u64>,
    next_handle: u64,
    next_handshake: u64,
    /// See [`ScmId`]: never reused, like `next_handle`.
    next_scm: u64,
}

impl Table {
    /// A new endpoint, for a socket that has just been created.
    ///
    /// Handles are never reused. That is what lets a stale one — held by a
    /// socket whose peer closed and whose number was handed out again — answer
    /// "gone" rather than reaching a different socket.
    pub fn open(&mut self, cred: Ucred) -> Option<u64> {
        self.endpoints.try_reserve(1).ok()?;
        self.next_handle += 1;
        let h = self.next_handle;
        self.endpoints.insert(
            h,
            Endpoint {
                cred,
                ..Endpoint::default()
            },
        );
        Some(h)
    }

    /// The socket has closed. Its peer is told, its handshake is withdrawn,
    /// and whatever it still holds is left for [`Table::drain`].
    ///
    /// Returns the messages it was holding, in both directions: the ones it
    /// had not received and the ones it sent to a connection nobody accepted.
    /// Nothing will collect either now.
    pub fn close(&mut self, h: u64) -> Vec<ControlMessage> {
        let Some(mut ep) = self.endpoints.remove(&h) else {
            return Vec::new();
        };
        if let Some(peer) = ep.peer
            && let Some(other) = self.endpoints.get_mut(&peer)
            && other.peer == Some(h)
        {
            other.peer = None;
        }
        self.pending.retain(|_, owner| *owner != h);
        if let Some(id) = ep.socket_id {
            self.bound.remove(&id);
        }
        let mut left: Vec<ControlMessage> = ep.inbox.drain(..).collect();
        left.append(&mut ep.outbox);
        left
    }

    /// `bind`: this endpoint's name has socket id `id`, so a client that
    /// resolves a path to that id is connecting to this endpoint.
    pub fn set_socket_id(&mut self, h: u64, id: u64) -> bool {
        if !self.endpoints.contains_key(&h) || self.bound.try_reserve(1).is_err() {
            return false;
        }
        self.bound.insert(id, h);
        if let Some(ep) = self.endpoints.get_mut(&h) {
            ep.socket_id = Some(id);
        }
        true
    }

    /// `connect`: record what this endpoint's peer will be -- the listener
    /// at socket id `id`, whose credentials are copied now, and `name`, the
    /// address connected to -- so that `SO_PEERCRED` and `getpeername`
    /// answer before the server's `accept` links the two. `false` when the
    /// listener is not one of ours, which leaves both unanswered as before.
    pub fn expect_peer(&mut self, h: u64, id: u64, name: &[u8]) -> bool {
        let Some(cred) = self
            .bound
            .get(&id)
            .and_then(|l| self.endpoints.get(l))
            .map(|ep| ep.cred)
        else {
            return false;
        };
        let name = &name[..name.len().min(UNIX_NAME_MAX)];
        let mut owned = Vec::new();
        if owned.try_reserve_exact(name.len()).is_err() {
            return false;
        }
        owned.extend_from_slice(name);
        match self.endpoints.get_mut(&h) {
            Some(ep) => {
                ep.expected = Some(Expected { cred, name: owned });
                true
            }
            None => false,
        }
    }

    /// `connect`: publish an id for this endpoint and hand it back to be sent
    /// on the wire. `accept` on the other side claims it.
    pub fn publish(&mut self, h: u64) -> Option<u64> {
        if !self.endpoints.contains_key(&h) {
            return None;
        }
        self.pending.try_reserve(1).ok()?;
        self.next_handshake += 1;
        let id = self.next_handshake;
        self.pending.insert(id, h);
        Some(id)
    }

    /// Nothing was sent, so nothing can ever claim it.
    pub fn unpublish(&mut self, id: u64) {
        self.pending.remove(&id);
    }

    /// `accept`: claim the handshake `id` and link it to `h`.
    ///
    /// `None` for an id that is not outstanding — a peer that is not one of
    /// ours, or one whose connect has already given up. The connection still
    /// works; it just has no peer credentials and no `SCM_RIGHTS`.
    ///
    /// The claimed endpoint's outbox comes back with it: those messages went
    /// out before there was a socket to receive them, and they belong at the
    /// head of this one's inbox.
    pub fn claim(&mut self, h: u64, id: u64) -> Option<u64> {
        let peer = self.pending.remove(&id)?;
        if !self.endpoints.contains_key(&peer) || !self.endpoints.contains_key(&h) {
            return None;
        }
        self.link(h, peer);
        let waiting = std::mem::take(&mut self.endpoints.get_mut(&peer).expect("checked").outbox);
        self.endpoints.get_mut(&h).expect("checked").inbox.extend(waiting);
        Some(peer)
    }

    /// `socketpair`: two sockets that are each other's peer from the start.
    pub fn link(&mut self, a: u64, b: u64) {
        if let Some(ep) = self.endpoints.get_mut(&a) {
            ep.peer = Some(b);
        }
        if let Some(ep) = self.endpoints.get_mut(&b) {
            ep.peer = Some(a);
        }
    }

    pub fn peer_of(&self, h: u64) -> Option<u64> {
        self.endpoints.get(&h)?.peer
    }

    /// The peer's credentials, for `SO_PEERCRED` -- the linked peer's, or
    /// before the link, the listener's as copied at connect.
    pub fn peer_cred(&self, h: u64) -> Option<Ucred> {
        let ep = self.endpoints.get(&h)?;
        match ep.peer.and_then(|p| self.endpoints.get(&p)) {
            Some(peer) => Some(peer.cred),
            None => ep.expected.as_ref().map(|e| e.cred),
        }
    }

    pub fn set_cred(&mut self, h: u64, cred: Ucred) {
        if let Some(ep) = self.endpoints.get_mut(&h) {
            ep.cred = cred;
        }
    }

    /// `bind` recorded a name for this socket.
    pub fn set_name(&mut self, h: u64, name: &[u8]) -> bool {
        let Some(ep) = self.endpoints.get_mut(&h) else {
            return false;
        };
        let name = &name[..name.len().min(UNIX_NAME_MAX)];
        let mut owned = Vec::new();
        if owned.try_reserve_exact(name.len()).is_err() {
            return false;
        }
        owned.extend_from_slice(name);
        ep.name = owned;
        true
    }

    pub fn name(&self, h: u64) -> &[u8] {
        self.endpoints.get(&h).map_or(&[], |ep| &ep.name)
    }

    /// The peer's name: the path the client connected to. Linux copies the
    /// listening socket's address onto the accepted one for exactly this --
    /// and onto the client at connect, which is what answers before the
    /// accept.
    pub fn peer_name(&self, h: u64) -> &[u8] {
        let Some(ep) = self.endpoints.get(&h) else {
            return &[];
        };
        match ep.peer.and_then(|p| self.endpoints.get(&p)) {
            Some(peer) => &peer.name,
            None => ep.expected.as_ref().map_or(&[], |e| &e.name),
        }
    }

    /// A control message this socket is sending. It goes to the peer's inbox,
    /// or onto this socket's own outbox if there is no peer yet.
    ///
    /// **The descriptors are taken by value**, so `None` — no such endpoint,
    /// no peer's endpoint, or a queue that cannot grow — releases them here
    /// rather than leaving the caller holding a raw pointer it has to
    /// remember to free. That free was written out at three call sites in
    /// `crates/fs/sock`.
    pub fn queue(&mut self, h: u64, fds: Vec<fs_fdobj::Owned>) -> Option<Queued> {
        self.next_scm += 1;
        let scm = ControlMessage {
            id: ScmId(self.next_scm),
            fds,
        };
        let id = scm.id;
        let Some(peer) = self.peer_of(h) else {
            let ep = self.endpoints.get_mut(&h)?;
            ep.outbox.try_reserve(1).ok()?;
            ep.outbox.push(scm);
            return Some(Queued::Own(id));
        };
        let other = self.endpoints.get_mut(&peer)?;
        other.inbox.try_reserve(1).ok()?;
        other.inbox.push_back(scm);
        Some(Queued::Peer(id))
    }

    /// Take a queued message back out, for a send that failed after queueing.
    ///
    /// Every endpoint is searched rather than the one it was put in. The C
    /// read `sock->socket.unix_peer` again at cleanup time to decide where to
    /// unlink from, which took the wrong lock if the peer had changed and
    /// skipped the unlink entirely if it had gone — freeing a node that was
    /// still in that peer's list. There is one lock here and the search is on
    /// a path taken only when a `sendmsg` has already failed.
    pub fn unqueue(&mut self, id: ScmId) -> Option<ControlMessage> {
        for ep in self.endpoints.values_mut() {
            if let Some(i) = ep.inbox.iter().position(|m| m.id == id) {
                return ep.inbox.remove(i);
            }
            if let Some(i) = ep.outbox.iter().position(|m| m.id == id) {
                return Some(ep.outbox.remove(i));
            }
        }
        None
    }

    /// How many descriptors wait in this socket's queue to be received:
    /// `/proc/<pid>/fdinfo`'s `scm_fds:`, Linux's `scm_stat.nr_fds`.
    pub fn queued_fds(&self, h: u64) -> usize {
        self.endpoints
            .get(&h)
            .map_or(0, |ep| ep.inbox.iter().map(|m| m.fds.len()).sum())
    }

    /// The next control message for this socket, or `None`.
    pub fn take(&mut self, h: u64) -> Option<ControlMessage> {
        self.endpoints.get_mut(&h)?.inbox.pop_front()
    }

    /// The next thing this endpoint is holding that has to be freed.
    ///
    /// The inbox first, then the outbox: the order does not matter to a caller
    /// that frees them all, and taking one at a time keeps the interface free
    /// of arrays. Called in a loop before [`Table::close`].
    pub fn drain_one(&mut self, h: u64) -> Option<ControlMessage> {
        if let Some(scm) = self.take(h) {
            return Some(scm);
        }
        self.endpoints.get_mut(&h)?.outbox.pop()
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// For `/proc/iul/objects`: endpoints, and handshakes still outstanding.
    /// Both return to what they were when every socket has closed -- a
    /// `sock_close` that skipped `unixpeer_close` shows up as an endpoint that
    /// never goes.
    pub fn counts(&self) -> (usize, usize) {
        (self.endpoints.len(), self.pending.len())
    }
}

// --------------------------------------------------------------- C binding
//
// One lock, as `peer_lock` was, so the ordering against scm_send_lock and the
// descriptor table is exactly what it was. Nothing outside can hold a
// reference into what it protects: every call takes a handle and returns a
// value.

static TABLE: Mutex<Option<Table>> = Mutex::new(None);

/// The one table, for a Rust caller.
///
/// The C ABI below is the same call with the arguments flattened; a Rust caller
/// takes this instead, so that a socket syscall in `crates/fs/sock` reaches the
/// table without going out through C and back. Nothing may hold a reference
/// into the table across the call -- the closure gets `&mut Table` and the lock
/// is released when it returns.
pub fn with_table<T>(f: impl FnOnce(&mut Table) -> T) -> T {
    with(f)
}

fn with<T>(f: impl FnOnce(&mut Table) -> T) -> T {
    let mut guard = TABLE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(guard.get_or_insert_with(Table::default))
}

/// For `/proc/iul/objects`: live endpoints and outstanding handshakes. A socket
/// closed without `unixpeer_close` is an endpoint that never goes — the way a
/// side table leaks where the fields it replaced could not.
///
/// Rust, not `extern "C"`. It was a C ABI taking two out-pointers until
/// 2026-08-31, when `fs/proc/iul.c` -- its only caller -- became
/// `crates/fs/proc`'s `iul` module.
pub fn counts() -> (u64, u64) {
    let (e, p) = with(|t| t.counts());
    (e as u64, p as u64)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
