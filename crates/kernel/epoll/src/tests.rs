//! Unit tests for the epoll core and its reverse-edge integration.

use super::*;
use crate::core::Delivery;

impl Core {
    fn add(
        &mut self,
        key: DescriptionKey,
        fd_number: i32,
        events: u32,
        data: u64,
        is_socket: bool,
        graph_target: Option<GraphNode>,
    ) -> Result<AddResult, Error> {
        self.insert(
            key,
            std::sync::Weak::<u8>::new(),
            &Arc::new(Watchers::default()),
            fd_number,
            events,
            data,
            is_socket,
            graph_target,
        )
    }
}

/// Distinct keys from real storage, for both test modules below.
///
/// A key was a `usize` until 2026-09-16 and these tests named members as
/// `0x1000`, which was sound because nothing dereferenced one. `Members` takes
/// `&Self::Member` now and the core borrows what a key names, so a key has to
/// name something. A `static` outlives every registration in a test.
#[cfg(test)]
fn slot(n: usize) -> &'static u8 {
    static SLOTS: [u8; 32] = [0; 32];
    &SLOTS[n]
}

#[cfg(test)]
mod reverse_edge {
    //! The link between a description and the sets watching it, from both
    //! ends. What these pin is that neither end can free what the other is
    //! walking, and that a set which is gone leaves an inert entry rather than
    //! a dangling one — the shape that produced the `sched_yield` retry loops
    //! this replaced.
    use super::*;
    use pollset::{poll_watchers_closed, poll_watchers_notify};

    /// A member that is never ready, has no host descriptor and is not a
    /// socket -- so what these tests exercise is the graph, not readiness.
    struct Quiet;

    impl Members for Quiet {
        type Member = u8;

        fn poll(_: &u8) -> c_int {
            0
        }
        fn host_fd(_: &u8) -> c_int {
            -1
        }
        fn is_socket(_: &u8) -> bool {
            false
        }
    }

    /// Distinct per test: a member is identified to the nesting graph by its
    /// address, and two tests sharing one would share an edge.
    ///
    /// **Real storage.** This was `(0x1000 + n * 0x100) as *mut c_void`, under
    /// "the keys below are not dereferenced by anything" — true while
    /// `Members` took a `usize` key, and the reason the fabrication was
    /// sound. It takes `&Self::Member` since 2026-09-16, so the core borrows
    /// what a key names and an invented address would be undefined behaviour.
    /// A `static` gives distinct addresses that outlive every registration;
    /// an `Arc` since 2026-10-17, because a registration keeps a `Weak`.
    fn member(n: usize) -> &'static Arc<u8> {
        static MEMBERS: std::sync::LazyLock<Vec<Arc<u8>>> =
            std::sync::LazyLock::new(|| (0..32).map(|_| Arc::new(0)).collect());
        &MEMBERS[n]
    }

    fn list_watchers(list: &Watchers) -> usize {
        list.watchers_locked().len()
    }

    fn poll_watchers_new() -> Arc<Watchers> {
        Arc::new(Watchers::default())
    }

    fn registrations(epoll: &Epoll) -> usize {
        lock_core(epoll).registrations_len()
    }

    fn new_epoll() -> Arc<Epoll> {
        epoll_state_new().expect("an epoll state")
    }

    #[test]
    fn adding_a_member_records_the_set_in_its_reverse_edge() {
        let list = poll_watchers_new();
        let epoll = new_epoll();
        let fd = member(1);
        assert_eq!(
            epoll_add::<Quiet>(&epoll, None, &Arc::downgrade(fd), &list, 3, READ, 7),
            1
        );
        assert_eq!(list_watchers(&list), 1);
        // A second registration on the same description is one more
        // registration and still one entry: the entry names the description.
        assert_eq!(
            epoll_add::<Quiet>(&epoll, None, &Arc::downgrade(fd), &list, 4, WRITE, 8),
            0
        );
        assert_eq!(list_watchers(&list), 1);
        assert_eq!(registrations(&epoll), 2);
        drop(epoll);
    }

    #[test]
    fn deleting_the_last_registration_removes_the_entry() {
        let list = poll_watchers_new();
        let epoll = new_epoll();
        let fd = member(2);
        epoll_add::<Quiet>(&epoll, None, &Arc::downgrade(fd), &list, 3, READ, 7);
        epoll_add::<Quiet>(&epoll, None, &Arc::downgrade(fd), &list, 4, READ, 8);
        assert_eq!(
            epoll_delete::<Quiet>(&epoll, None, fd, &list, 3),
            0
        );
        assert_eq!(list_watchers(&list), 1, "one registration still names it");
        assert_eq!(
            epoll_delete::<Quiet>(&epoll, None, fd, &list, 4),
            1
        );
        assert_eq!(list_watchers(&list), 0);
        drop(epoll);
    }

    #[test]
    fn a_set_that_is_dropped_takes_its_entry_with_it() {
        let list = poll_watchers_new();
        let epoll = new_epoll();
        epoll_add::<Quiet>(&epoll, None, &Arc::downgrade(member(3)), &list, 3, READ, 7);
        assert_eq!(list_watchers(&list), 1);
        // The member outlives the set, which is the order the old code needed
        // a retry loop for.
        drop(epoll);
        assert_eq!(list_watchers(&list), 0);
    }

    #[test]
    fn a_description_that_closes_takes_its_registrations_with_it() {
        let list = poll_watchers_new();
        let epoll = new_epoll();
        epoll_add::<Quiet>(&epoll, None, &Arc::downgrade(member(4)), &list, 3, READ, 7);
        epoll_add::<Quiet>(&epoll, None, &Arc::downgrade(member(4)), &list, 4, READ, 8);
        assert_eq!(registrations(&epoll), 2);
        // The other order: the description goes first.
        poll_watchers_closed(&list);
        assert_eq!(registrations(&epoll), 0);
        assert_eq!(list_watchers(&list), 0);
        assert!(!epoll_is_ready(&epoll));
        drop(epoll);
    }

    #[test]
    fn a_wakeup_reaches_the_set_through_the_reverse_edge() {
        let list = poll_watchers_new();
        let epoll = new_epoll();
        epoll_add::<Quiet>(&epoll, None, &Arc::downgrade(member(5)), &list, 3, READ, 7);
        assert!(!epoll_is_ready(&epoll));
        poll_watchers_notify(&list, READ);
        assert!(epoll_is_ready(&epoll));
        drop(epoll);
    }

    /// Always readable, so a wait has to ask it.
    struct Ready;

    impl Members for Ready {
        type Member = u8;

        fn poll(_: &u8) -> c_int {
            READ as c_int
        }
        fn host_fd(_: &u8) -> c_int {
            -1
        }
        fn is_socket(_: &u8) -> bool {
            false
        }
    }

    /// A member whose last reference is gone before its `detach` has run --
    /// the window a description's finalizer is in while it waits for this
    /// set's lock -- is not ready and is not reached. Until 2026-10-17 a wait
    /// borrowed the member from its key's address there.
    #[test]
    fn a_wait_does_not_reach_a_member_whose_last_reference_is_gone() {
        let list = poll_watchers_new();
        let epoll = new_epoll();
        let fd = Arc::new(0u8);
        epoll_add::<Ready>(&epoll, None, &Arc::downgrade(&fd), &list, 3, READ, 7);
        let mut out = [Event { events: 0, _pad: 0, data: 0 }; 1];
        // Level-triggered, so it is queued again after each delivery.
        assert_eq!(epoll_take_ready::<Ready>(&epoll, &mut out, std::time::Duration::ZERO), 1);
        assert_eq!(out[0].data, 7);
        drop(fd);
        assert_eq!(epoll_take_ready::<Ready>(&epoll, &mut out, std::time::Duration::ZERO), 0);
        poll_watchers_closed(&list);
        assert_eq!(registrations(&epoll), 0);
    }

    #[test]
    fn a_wakeup_after_the_set_is_gone_is_inert() {
        let list = poll_watchers_new();
        let epoll = new_epoll();
        epoll_add::<Quiet>(&epoll, None, &Arc::downgrade(member(6)), &list, 3, READ, 7);
        drop(epoll);
        // The entry is already gone here; the point is that a list which
        // outlives every set watching it stays usable.
        poll_watchers_notify(&list, READ);
        poll_watchers_closed(&list);
    }
}

#[cfg(test)]
mod core_tests {
    use super::*;

    /// `Event` is the shape `kernel/epoll.h` declared, which was the other
    /// definition of it.
    ///
    /// **`Ops` was checked here too, and is gone.** It had five fields in the
    /// header and three here until 2026-09-04: `crates/fs/poll` built its
    /// table from the header, so it passed a 24-byte static where this read a
    /// 40-byte struct, and nothing dereferenced the two extra fields — `wake`
    /// and `gone` were declared and read nowhere — which is the only reason it
    /// was harmless. It is a trait since 2026-09-09 and there is no layout for
    /// two renderings to disagree about, which is a better ending than a test
    /// that compares them.
    #[test]
    fn the_c_abi_structs_are_the_shape_the_header_declares() {
        // struct epoll_ready_event: uint32_t, uint32_t pad, uint64_t.
        assert_eq!(size_of::<Event>(), 16);
        assert_eq!(std::mem::offset_of!(Event, events), 0);
        assert_eq!(std::mem::offset_of!(Event, _pad), 4);
        assert_eq!(std::mem::offset_of!(Event, data), 8);
    }

    #[test]
    fn pair_identity_preserves_dup_registrations() {
        let mut core = Core::default();
        let first = core.add(DescriptionKey::of(slot(20)), 4, READ, 40, false, None).unwrap();
        let second = core.add(DescriptionKey::of(slot(20)), 9, WRITE, 90, false, None).unwrap();
        assert_eq!(first.description, second.description);
        assert_eq!(
            core.add(DescriptionKey::of(slot(20)), 4, READ, 0, false, None),
            Err(Error::Exists)
        );
        assert_eq!(core.registrations_len(), 2);
        assert_eq!(
            core.host_interest(first.description),
            Some(HostInterest {
                events: READ | WRITE | ERR | HUP,
                edge: false,
            })
        );

        core.modify(DescriptionKey::of(slot(20)), 4, PRI, 41).unwrap();
        assert_eq!(core.remove(DescriptionKey::of(slot(20)), 9), Ok((first.description, None)));
        assert!(core.registration_for_pair(DescriptionKey::of(slot(20)), 4).is_some());
        assert_eq!(
            core.host_interest(first.description).unwrap().events,
            PRI | ERR | HUP
        );
    }

    #[test]
    fn stale_host_tokens_do_not_name_reused_descriptions() {
        let mut core = Core::default();
        let old = core.add(DescriptionKey::of(slot(1)), 3, READ, 0, false, None).unwrap().description;
        core.remove(DescriptionKey::of(slot(1)), 3).unwrap();
        let new = core.add(DescriptionKey::of(slot(2)), 3, READ, 0, false, None).unwrap().description;
        assert_eq!(old.slot, new.slot, "the test needs slot reuse");
        assert_ne!(old.generation, new.generation);
        assert!(!core.notify(old, READ));
        assert!(!core.is_ready());
        assert!(core.notify(new, READ));
    }

    #[test]
    fn maxevents_does_not_consume_undelivered_edges() {
        let mut core = Core::default();
        let a = core.add(DescriptionKey::of(slot(1)), 1, READ | EDGE, 1, false, None).unwrap();
        let b = core.add(DescriptionKey::of(slot(2)), 2, READ | EDGE, 2, false, None).unwrap();
        core.notify(a.description, READ);
        core.notify(b.description, READ);

        let first = core.take_ready(1, |_| READ).unwrap();
        let second = core.take_ready(1, |_| READ).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_ne!(first[0].event.data, second[0].event.data);
        assert!(core.take_ready(1, |_| READ).unwrap().is_empty());
    }

    /// What fdinfo prints for each item: ERR and HUP added, as `epoll_ctl`
    /// adds them, and a delivered ONESHOT down to its control bits.
    #[test]
    fn the_listing_holds_the_events_linuxs_item_does() {
        let mut core = Core::default();
        let a = core.add(DescriptionKey::of(slot(1)), 7, READ | ONESHOT, 0xa, false, None).unwrap();
        core.add(DescriptionKey::of(slot(2)), 3, WRITE | EDGE, 0xb, false, None).unwrap();
        let shown = |core: &Core| -> Vec<(i32, u32, u64)> {
            core.listing().into_iter().map(|(fd, ev, data, _)| (fd, ev, data)).collect()
        };
        assert_eq!(
            shown(&core),
            [(3, WRITE | EDGE | ERR | HUP, 0xb), (7, READ | ONESHOT | ERR | HUP, 0xa)]
        );
        core.notify(a.description, READ);
        assert_eq!(core.take_ready(4, |_| READ).unwrap().len(), 1);
        assert_eq!(shown(&core)[1], (7, ONESHOT, 0xa));
    }

    #[test]
    fn maxevents_does_not_disarm_undelivered_oneshots() {
        let mut core = Core::default();
        let a = core.add(DescriptionKey::of(slot(1)), 1, READ | ONESHOT, 1, false, None).unwrap();
        let b = core.add(DescriptionKey::of(slot(2)), 2, READ | ONESHOT, 2, false, None).unwrap();
        core.notify(a.description, READ);
        core.notify(b.description, READ);

        let first = core.take_ready(1, |_| READ).unwrap();
        let second = core.take_ready(1, |_| READ).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_ne!(first[0].event.data, second[0].event.data);
        assert!(core.take_ready(2, |_| READ).unwrap().is_empty());
    }

    #[test]
    fn level_ready_queue_rotates_fairly() {
        let mut core = Core::default();
        let a = core.add(DescriptionKey::of(slot(1)), 1, READ, 1, false, None).unwrap();
        let b = core.add(DescriptionKey::of(slot(2)), 2, READ, 2, false, None).unwrap();
        core.notify(a.description, READ);
        core.notify(b.description, READ);

        let first = core.take_ready(1, |_| READ).unwrap();
        let second = core.take_ready(1, |_| READ).unwrap();
        assert_eq!(first[0].event.data, 1);
        assert_eq!(second[0].event.data, 2);
        assert_eq!(core.take_ready(2, |_| READ).unwrap().len(), 2);
    }

    #[test]
    fn modify_rearms_a_fired_oneshot() {
        let mut core = Core::default();
        let added = core.add(DescriptionKey::of(slot(1)), 1, READ | ONESHOT, 1, false, None).unwrap();
        core.notify(added.description, READ);
        assert_eq!(core.take_ready(1, |_| READ).unwrap().len(), 1);
        assert!(core.take_ready(1, |_| READ).unwrap().is_empty());

        let (id, _, _) = core.modify(DescriptionKey::of(slot(1)), 1, READ | ONESHOT, 2).unwrap();
        core.queue_registration(id);
        assert_eq!(
            core.take_ready(1, |_| READ).unwrap(),
            vec![Delivery {
                event: Event {
                    events: READ,
                    _pad: 0,
                    data: 2
                },
                description: added.description,
                refresh_backend: true,
            }]
        );
    }

    #[test]
    fn nested_graph_counts_aliases_and_failed_add_rollbacks() {
        let mut graph = Graph::default();
        let (outer, inner) = (1, 2);
        assert_eq!(graph.add(SetId::raw(outer), SetId::raw(inner)), 0);
        assert_eq!(
            graph.add(SetId::raw(outer), SetId::raw(inner)),
            0,
            "a second alias shares the topology"
        );
        graph.remove(SetId::raw(outer), GraphNode::Epoll(SetId::raw(inner)), 1);
        assert_eq!(
            graph.add(SetId::raw(inner), SetId::raw(outer)),
            ELOOP,
            "one alias still keeps the edge live"
        );
        graph.remove(SetId::raw(outer), GraphNode::Epoll(SetId::raw(inner)), 1);
        assert_eq!(
            graph.add(SetId::raw(inner), SetId::raw(outer)),
            0,
            "the last registration removed the edge"
        );
    }

    #[test]
    fn nested_edge_can_reverse_after_every_alias_is_deleted() {
        let mut graph = Graph::default();
        assert_eq!(graph.add_target(SetId::raw(1), GraphNode::File(FileId::raw(99))), 0);
        assert_eq!(graph.add(SetId::raw(1), SetId::raw(2)), 0);
        assert_eq!(graph.add(SetId::raw(1), SetId::raw(2)), 0);
        graph.remove(SetId::raw(1), GraphNode::Epoll(SetId::raw(2)), 1);
        assert_eq!(graph.add(SetId::raw(2), SetId::raw(1)), ELOOP);
        graph.remove(SetId::raw(1), GraphNode::Epoll(SetId::raw(2)), 1);
        assert_eq!(graph.add(SetId::raw(2), SetId::raw(1)), 0);
    }

    #[test]
    fn nested_graph_enforces_the_linux_depth_limit() {
        let mut graph = Graph::default();
        for outer in 1..=4 {
            assert_eq!(graph.add(SetId::raw(outer), SetId::raw(outer + 1)), 0, "edge {outer}");
        }
        assert_eq!(graph.add(SetId::raw(5), SetId::raw(6)), ELOOP, "a fifth edge is too deep");

        let mut bridged = Graph::default();
        assert_eq!(bridged.add(SetId::raw(1), SetId::raw(2)), 0);
        assert_eq!(bridged.add(SetId::raw(2), SetId::raw(3)), 0);
        assert_eq!(bridged.add(SetId::raw(4), SetId::raw(5)), 0);
        assert_eq!(bridged.add(SetId::raw(5), SetId::raw(6)), 0);
        assert_eq!(
            bridged.add(SetId::raw(3), SetId::raw(4)),
            ELOOP,
            "upstream and downstream depth both count"
        );
    }

    #[test]
    fn nested_graph_enforces_reverse_wakeup_path_limits() {
        let mut graph = Graph::default();
        // At reverse nesting depth four Linux permits ten distinct paths from
        // one leaf. Build ten top-level parents over a shared three-edge tail;
        // the eleventh parent would create the eleventh path for that leaf.
        assert_eq!(graph.add_target(SetId::raw(40), GraphNode::File(FileId::raw(99))), 0);
        assert_eq!(graph.add(SetId::raw(30), SetId::raw(40)), 0);
        assert_eq!(graph.add(SetId::raw(20), SetId::raw(30)), 0);
        assert_eq!(graph.add(SetId::raw(10), SetId::raw(20)), 0);
        for parent in 100..110 {
            assert_eq!(graph.add(SetId::raw(parent), SetId::raw(10)), 0, "depth-four path {parent}");
        }
        assert_eq!(
            graph.add(SetId::raw(110), SetId::raw(10)),
            EINVAL,
            "the eleventh depth-four path exceeds Linux's limit"
        );
    }

    #[test]
    fn every_alias_delete_decrements_its_graph_count() {
        let mut core = Core::default();
        let target = GraphNode::Epoll(SetId::raw(2));
        let first = core.add(DescriptionKey::of(slot(21)), 4, READ, 1, false, Some(target)).unwrap();
        core.add(DescriptionKey::of(slot(21)), 9, READ, 2, false, Some(target)).unwrap();
        assert_eq!(core.remove(DescriptionKey::of(slot(21)), 4), Ok((first.description, Some(target))));
        assert_eq!(core.remove(DescriptionKey::of(slot(21)), 9), Ok((first.description, Some(target))));
    }

    #[test]
    fn one_edge_registration_makes_the_shared_host_watch_edge_triggered() {
        let mut core = Core::default();
        let edge = core.add(DescriptionKey::of(slot(1)), 1, READ | EDGE, 1, false, None).unwrap();
        assert!(core.host_interest(edge.description).unwrap().edge);
        core.add(DescriptionKey::of(slot(1)), 2, WRITE, 2, false, None).unwrap();
        assert!(core.host_interest(edge.description).unwrap().edge);
    }
}

#[cfg(test)]
mod busy_poll {
    use super::*;

    /// Every field reads back as it was set, at both ends of its range, and a
    /// new set starts at zero.
    #[test]
    fn the_parameters_read_back_as_set() {
        let epoll = epoll_state_new().expect("an epoll state");
        assert_eq!(epoll.busy_poll(), BusyPoll::default());
        for params in [
            BusyPoll { usecs: 100, budget: 8, prefer: true },
            BusyPoll { usecs: i32::MAX as u32, budget: u16::MAX, prefer: false },
            BusyPoll { usecs: u32::MAX, budget: 0, prefer: true },
        ] {
            epoll.set_busy_poll(params);
            assert_eq!(epoll.busy_poll(), params);
        }
    }
}
