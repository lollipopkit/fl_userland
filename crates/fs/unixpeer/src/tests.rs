use super::*;

mod shorthand {
    use super::*;

    /// A new endpoint. 0 if the table cannot grow.
    pub fn unixpeer_open(pid: i32, uid: u32, gid: u32) -> u64 {
        with(|t| t.open(Ucred { pid, uid, gid })).unwrap_or(0)
    }

    /// The socket has closed. Call [`unixpeer_drain`] first for what it held.
    pub fn unixpeer_close(h: u64) {
        // close() returns what was queued; the caller has already drained it,
        // so anything left here is a caller that did not -- and since the
        // queue owns its messages, they are released here rather than leaked.
        // The assertion is about the *caller's* shape, not about safety.
        let left = with(|t| t.close(h));
        debug_assert!(left.is_empty(), "unixpeer_drain before unixpeer_close");
    }

    /// The next thing this endpoint is holding, or `None`. Called in a loop
    /// before [`unixpeer_close`].
    pub fn unixpeer_drain(h: u64) -> Option<ScmId> {
        with(|t| t.drain_one(h)).map(|m| m.id())
    }

    /// `connect`: an id to send on the wire. 0 on failure.
    pub fn unixpeer_publish(h: u64) -> u64 {
        with(|t| t.publish(h)).unwrap_or(0)
    }

    /// `accept`: claim the handshake and link. 0 for an id nothing published.
    pub fn unixpeer_claim(h: u64, id: u64) -> u64 {
        with(|t| t.claim(h, id)).unwrap_or(0)
    }

    pub fn unixpeer_has_peer(h: u64) -> bool {
        with(|t| t.peer_of(h).is_some())
    }

    /// The *peer's* credentials, which is what SO_PEERCRED reports. `None` if
    /// there is no peer.
    pub fn unixpeer_peer_cred(h: u64) -> Option<Ucred> {
        with(|t| t.peer_cred(h))
    }

    pub fn unixpeer_set_name(h: u64, name: &[u8]) -> bool {
        with(|t| t.set_name(h, name))
    }

    /// The peer's name, for `getpeername`.
    pub fn unixpeer_peer_name(h: u64) -> Vec<u8> {
        with(|t| t.peer_name(h).to_vec())
    }

    /// Queue a control message. Reports where it went.
    pub fn unixpeer_queue(h: u64, fds: Vec<fs_fdobj::Owned>) -> Option<Queued> {
        with(|t| t.queue(h, fds))
    }

    /// The next control message for this socket, or `None`.
    pub fn unixpeer_take(h: u64) -> Option<ScmId> {
        with(|t| t.take(h)).map(|m| m.id())
    }
}

use shorthand::*;

/// Between `connect` and `accept` a client already knows who it is
/// talking to: the listener's credentials and the address it connected
/// to, copied at connect. The accept's link then supersedes the copy.
#[test]
fn a_client_knows_its_listener_before_the_accept() {
    let mut t = Table::default();
    let listener = t.open(cred(10)).unwrap();
    assert!(t.set_name(listener, b"/tmp/s"));
    assert!(t.set_socket_id(listener, 7));

    let client = t.open(cred(20)).unwrap();
    assert_eq!(t.peer_cred(client), None, "nothing known yet");
    assert!(t.expect_peer(client, 7, b"/tmp/s"));
    assert_eq!(t.peer_cred(client), Some(cred(10)));
    assert_eq!(t.peer_name(client), b"/tmp/s");

    // A listener that is not one of ours: nothing is recorded, and the
    // client is told nothing rather than something made up.
    let other = t.open(cred(30)).unwrap();
    assert!(!t.expect_peer(other, 99, b"/tmp/x"));
    assert_eq!(t.peer_cred(other), None);

    // The accepted socket is the real peer from the claim on.
    let accepted = t.open(cred(11)).unwrap();
    let id = t.publish(client).unwrap();
    assert_eq!(t.claim(accepted, id), Some(client));
    assert_eq!(t.peer_cred(client), Some(cred(11)));

    // A listener that closed is forgotten under its socket id.
    t.close(listener);
    let late = t.open(cred(40)).unwrap();
    assert!(!t.expect_peer(late, 7, b"/tmp/s"));
}

/// A control message carrying no descriptors.
///
/// It was `n as *mut ControlMessage` -- an integer cast to a pointer, "only
/// ever compared and handed back" -- and the number was how these tests told
/// two messages apart. `Table::queue` hands out a `ScmId` now, so the identity
/// under test is the one the product uses rather than one the test made up.
fn scm() -> Vec<fs_fdobj::Owned> {
    Vec::new()
}

fn cred(pid: i32) -> Ucred {
    Ucred {
        pid,
        uid: 1000,
        gid: 1000,
    }
}

#[test]
fn a_handshake_links_the_two_ends() {
    let mut t = Table::default();
    let client = t.open(cred(10)).unwrap();
    let server = t.open(cred(20)).unwrap();
    let id = t.publish(client).unwrap();
    assert_eq!(t.claim(server, id), Some(client));
    assert_eq!(t.peer_of(server), Some(client));
    assert_eq!(t.peer_of(client), Some(server));
    // SO_PEERCRED reads the other end's.
    assert_eq!(t.peer_cred(server).unwrap().pid, 10);
    assert_eq!(t.peer_cred(client).unwrap().pid, 20);
}

/// An id nothing published is a peer that is not one of ours -- a host
/// process that connected to `/tmp/iulsock<pid>.<n>` and sent something.
/// The connection still works; it has no peer.
#[test]
fn an_id_nothing_published_links_nothing() {
    let mut t = Table::default();
    let server = t.open(cred(20)).unwrap();
    assert_eq!(t.claim(server, 999), None);
    assert_eq!(t.peer_of(server), None);
    assert_eq!(t.peer_cred(server), None);
}

#[test]
fn a_handshake_can_only_be_claimed_once() {
    let mut t = Table::default();
    let client = t.open(cred(10)).unwrap();
    let a = t.open(cred(20)).unwrap();
    let b = t.open(cred(30)).unwrap();
    let id = t.publish(client).unwrap();
    assert_eq!(t.claim(a, id), Some(client));
    assert_eq!(t.claim(b, id), None, "the second accept gets nothing");
}

/// A connect that could not send its handshake takes the id back, or the
/// entry outlives the socket and the accept that finally reads that number
/// off the wire links to something that is gone.
#[test]
fn an_unsent_handshake_can_be_withdrawn() {
    let mut t = Table::default();
    let client = t.open(cred(10)).unwrap();
    let id = t.publish(client).unwrap();
    assert_eq!(t.pending_len(), 1);
    t.unpublish(id);
    assert_eq!(t.pending_len(), 0);
    let server = t.open(cred(20)).unwrap();
    assert_eq!(t.claim(server, id), None);
}

/// The defect the raw-pointer version had: a closed peer left an edge
/// pointing at freed memory. Here it is an id that is no longer in the
/// table, and every question about it answers "gone".
#[test]
fn a_closed_socket_leaves_no_edge_behind() {
    let mut t = Table::default();
    let client = t.open(cred(10)).unwrap();
    let server = t.open(cred(20)).unwrap();
    let id = t.publish(client).unwrap();
    t.claim(server, id);
    assert!(t.close(client).is_empty());
    assert_eq!(t.peer_of(server), None, "the back-edge went with it");
    assert_eq!(t.peer_cred(server), None);
    assert_eq!(t.peer_name(server), b"");
    // And the handle is not reused, so a later socket cannot be mistaken
    // for the one that closed.
    let third = t.open(cred(30)).unwrap();
    assert_ne!(third, client);
}

#[test]
fn a_socket_that_closes_gives_back_what_it_held() {
    let mut t = Table::default();
    let a = t.open(cred(10)).unwrap();
    let b = t.open(cred(20)).unwrap();
    t.link(a, b);
    // Two for b to receive, and one a sent before it had a peer -- which
    // it cannot have here, so send it, unlink, and send again.
    let one = t.queue(a, scm()).unwrap();
    let two = t.queue(a, scm()).unwrap();
    assert!(matches!(one, Queued::Peer(_)));
    assert!(matches!(two, Queued::Peer(_)));
    let left: Vec<_> = t.close(b).iter().map(ControlMessage::id).collect();
    assert_eq!(left, vec![one.id(), two.id()], "in the order they arrived");
    // a's own outbox now, since its peer is gone.
    let three = t.queue(a, scm()).unwrap();
    assert!(matches!(three, Queued::Own(_)));
    let left: Vec<_> = t.close(a).iter().map(ControlMessage::id).collect();
    assert_eq!(left, vec![three.id()]);
}

/// The whole point of the outbox: a message sent between `connect` and the
/// server's `accept` is not lost and is not blocked on. It waits, and it
/// arrives ahead of anything sent afterwards.
#[test]
fn messages_sent_before_a_peer_arrive_first_and_in_order() {
    let mut t = Table::default();
    let client = t.open(cred(10)).unwrap();
    let one = t.queue(client, scm()).unwrap();
    let two = t.queue(client, scm()).unwrap();
    assert!(matches!(one, Queued::Own(_)));
    assert!(matches!(two, Queued::Own(_)));

    let server = t.open(cred(20)).unwrap();
    let id = t.publish(client).unwrap();
    assert_eq!(t.claim(server, id), Some(client));

    // And one after the link.
    let three = t.queue(client, scm()).unwrap();
    assert!(matches!(three, Queued::Peer(_)));
    assert_eq!(t.take(server).map(|m| m.id()), Some(one.id()));
    assert_eq!(t.take(server).map(|m| m.id()), Some(two.id()));
    assert_eq!(t.take(server).map(|m| m.id()), Some(three.id()));
    assert!(t.take(server).is_none());
}

/// A `sendmsg` that queued and then failed takes its message back, from
/// wherever it went -- including from a peer it no longer has.
#[test]
fn a_failed_send_takes_its_message_back_from_wherever_it_went() {
    let mut t = Table::default();
    let a = t.open(cred(10)).unwrap();
    let b = t.open(cred(20)).unwrap();
    t.link(a, b);
    let sent = t.queue(a, scm()).unwrap();
    assert!(matches!(sent, Queued::Peer(_)));
    // The peer changes underneath: a is relinked to c.
    let c = t.open(cred(30)).unwrap();
    t.link(a, c);
    // The message is still in b's inbox, and unqueue finds it there.
    assert_eq!(t.unqueue(sent.id()).map(|m| m.id()), Some(sent.id()));
    assert!(t.take(b).is_none());
    assert!(t.unqueue(sent.id()).is_none(), "and only once");
}

#[test]
fn a_name_is_the_peers_to_read() {
    let mut t = Table::default();
    let server = t.open(cred(10)).unwrap();
    let client = t.open(cred(20)).unwrap();
    assert!(t.set_name(server, b"/tmp/s.sock\0"));
    t.link(server, client);
    assert_eq!(t.peer_name(client), b"/tmp/s.sock\0");
    assert_eq!(t.name(client), b"", "the client never bound one");
    assert_eq!(t.peer_name(server), b"");
}

/// An abstract name is bytes and may contain NULs, so the length is
/// carried rather than inferred -- and it is bounded by `sun_path`.
#[test]
fn a_name_keeps_its_nuls_and_is_bounded() {
    let mut t = Table::default();
    let h = t.open(cred(10)).unwrap();
    assert!(t.set_name(h, b"\0log\0v1"));
    assert_eq!(t.name(h), b"\0log\0v1");
    let long = vec![b'a'; UNIX_NAME_MAX + 50];
    assert!(t.set_name(h, &long));
    assert_eq!(t.name(h).len(), UNIX_NAME_MAX);
}

#[test]
fn a_handle_that_is_not_one_answers_nothing() {
    let mut t = Table::default();
    assert_eq!(t.peer_of(404), None);
    assert_eq!(t.peer_cred(404), None);
    assert_eq!(t.name(404), b"");
    assert!(t.take(404).is_none());
    assert!(t.close(404).is_empty());
    assert_eq!(t.publish(404), None);
    assert!(t.queue(404, scm()).is_none());
    assert!(!t.set_name(404, b"x"));
}

/// Closing one end of a socketpair is the same as closing a connected
/// socket, which the C reached by a different path.
#[test]
fn a_socketpair_unlinks_like_anything_else() {
    let mut t = Table::default();
    let a = t.open(cred(10)).unwrap();
    let b = t.open(cred(20)).unwrap();
    t.link(a, b);
    assert_eq!(t.peer_cred(a).unwrap().pid, 20);
    t.close(a);
    assert_eq!(t.peer_of(b), None);
    assert!(t.close(b).is_empty());
    assert!(t.is_empty());
}

/// The C API's round trip, which is what fs/sock.c calls.
#[test]
fn the_c_api_links_queues_and_closes() {
    let client = unixpeer_open(1, 0, 0);
    let server = unixpeer_open(2, 0, 0);
    assert!(client != 0 && server != 0);
    let id = unixpeer_publish(client);
    assert_ne!(id, 0);
    assert_eq!(unixpeer_claim(server, id), client);
    assert!(unixpeer_has_peer(server));

    assert_eq!(unixpeer_peer_cred(server).map(|c| c.pid), Some(1));

    let name = b"/tmp/x.sock";
    assert!(unixpeer_set_name(client, name));
    assert_eq!(unixpeer_peer_name(server), name);

    let one = unixpeer_queue(client, scm()).unwrap();
    assert!(matches!(one, Queued::Peer(_)));
    assert_eq!(unixpeer_take(server), Some(one.id()));
    assert!(unixpeer_take(server).is_none());

    let two = unixpeer_queue(client, scm()).unwrap();
    assert!(matches!(two, Queued::Peer(_)));
    assert_eq!(unixpeer_drain(server), Some(two.id()));
    assert!(unixpeer_drain(server).is_none());
    unixpeer_close(server);
    assert!(!unixpeer_has_peer(client));
    unixpeer_close(client);
}
