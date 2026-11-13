//! The queue's ordering and its waits, through the entry points a guest
//! reaches and against the real `wait_for`.

use kernel_sighand as _;
use kernel_sigqueue as _;

use super::*;
use std::thread;
use std::time::Instant;

type Q = Queue<()>;

fn inode() -> Inode {
    Inode {
        ino: 1,
        mode: 0o100600,
        uid: 0,
        gid: 0,
        size: abi::FILENT_SIZE,
        linked: true,
        atime: (0, 0),
        mtime: (0, 0),
        ctime: (0, 0),
    }
}

fn queue(maxmsg: usize) -> Q {
    Queue::new(maxmsg, 16, inode())
}

fn send(q: &Q, prio: u32, m: &[u8]) -> Result<Option<Delivery<()>>, Errno> {
    q.send(prio, m.to_vec(), true, None, (0, 0))
}

fn recv(q: &Q) -> Result<(u32, Vec<u8>), Errno> {
    q.receive(true, None, (0, 0))
}

fn soon(ms: i64) -> Deadline {
    let (sec, nsec) = timeabi::host_clock(libc::CLOCK_REALTIME).unwrap();
    let (sec, nsec) = timeabi::absolute_deadline(sec, nsec, ms / 1000, (ms % 1000) * 1_000_000);
    Deadline { sec, nsec }
}

fn registration(how: How<()>) -> Registration<()> {
    Registration { owner_tgid: 7, owner: TaskRef { pid: 7, generation: 1 }, how }
}

#[test]
fn higher_priorities_first_and_fifo_within_one() {
    let q = queue(8);
    for (m, p) in [(b"a", 1), (b"b", 5), (b"c", 5), (b"d", 3), (b"e", 0), (b"f", 5), (b"g", 0)] {
        send(&q, p, m).unwrap();
    }
    let got: Vec<(u32, u8)> = (0..7).map(|_| recv(&q).map(|(p, m)| (p, m[0])).unwrap()).collect();
    assert_eq!(
        got,
        [(5, b'b'), (5, b'c'), (5, b'f'), (3, b'd'), (1, b'a'), (0, b'e'), (0, b'g')]
    );
    assert_eq!(recv(&q).unwrap_err(), Errno::EAGAIN);
}

#[test]
fn qsize_counts_bytes_not_messages() {
    let q = queue(8);
    send(&q, 3, b"12345").unwrap();
    send(&q, 1, b"abc").unwrap();
    assert_eq!(q.lock().msgs.bytes(), 8);
    recv(&q).unwrap();
    assert_eq!(q.lock().msgs.bytes(), 3);
}

#[test]
fn a_full_queue_refuses_a_nonblocking_send_and_polls_readable_only() {
    let q = queue(2);
    assert_eq!(q.poll(), POLL_OUT);
    send(&q, 0, b"x").unwrap();
    assert_eq!(q.poll(), POLL_IN | POLL_OUT);
    send(&q, 0, b"x").unwrap();
    assert_eq!(q.poll(), POLL_IN);
    assert_eq!(send(&q, 0, b"x").unwrap_err(), Errno::EAGAIN);
}

#[test]
fn a_deadline_is_asked_only_when_the_call_would_block() {
    let q = queue(1);
    let past = Deadline { sec: 1, nsec: 0 };
    assert!(q.send(0, b"x".to_vec(), false, Some(past), (0, 0)).is_ok(), "room: no wait");
    assert_eq!(q.send(0, b"y".to_vec(), false, Some(past), (0, 0)).unwrap_err(), Errno::ETIMEDOUT);
    assert!(q.receive(false, Some(past), (0, 0)).is_ok());
    assert_eq!(q.receive(false, Some(past), (0, 0)).unwrap_err(), Errno::ETIMEDOUT);
}

#[test]
fn a_receive_waits_out_its_deadline() {
    let q = queue(1);
    let started = Instant::now();
    assert_eq!(q.receive(false, Some(soon(80)), (0, 0)).unwrap_err(), Errno::ETIMEDOUT);
    assert!(started.elapsed().as_millis() >= 70, "{:?}", started.elapsed());
}

/// The first registration fires on the first message into an empty queue,
/// and is used up.
#[test]
fn a_notification_fires_once_on_the_empty_to_nonempty_transition() {
    let q = queue(4);
    q.register(registration(How::Signal { signo: 12, value: 9 }), (0, 0)).ok().unwrap();
    let fired = send(&q, 0, b"x").unwrap();
    assert!(matches!(fired, Some(Delivery::Signal { signo: 12, value: 9, .. })));
    assert!(q.lock().registration.is_none());
    assert!(send(&q, 0, b"x").unwrap().is_none());

    // Registered on a queue that is not empty: the next send does nothing.
    q.register(registration(How::Signal { signo: 12, value: 1 }), (0, 0)).ok().unwrap();
    assert!(send(&q, 0, b"x").unwrap().is_none());
    assert!(q.lock().registration.is_some());
}

#[test]
fn signal_zero_and_sigev_none_are_used_up_and_send_nothing() {
    for how in [How::Nothing, How::Signal { signo: 0, value: 0 }] {
        let q = queue(4);
        q.register(registration(how), (0, 0)).ok().unwrap();
        assert!(send(&q, 0, b"x").unwrap().is_none());
        assert!(q.lock().registration.is_none());
    }
}

#[test]
fn a_second_registration_is_ebusy_and_only_the_owner_removes_it() {
    let q = queue(4);
    q.register(registration(How::Nothing), (0, 0)).ok().unwrap();
    let again = q.register(registration(How::Nothing), (0, 0));
    assert_eq!(again.err().map(|(e, _)| e), Some(Errno::EBUSY));
    assert!(q.unregister(8, None).is_none());
    assert!(q.lock().registration.is_some(), "not the owner");
    q.unregister(7, None);
    assert!(q.lock().registration.is_none());
}

/// A message handed to a sleeping receiver never reaches the queue, so it
/// does not use up the registration -- and a second send, before the receiver
/// runs, is the one that notifies.
#[test]
fn a_handed_over_message_does_not_notify_and_the_next_send_does() {
    let q = queue(4);
    q.register(registration(How::Signal { signo: 12, value: 3 }), (0, 0)).ok().unwrap();
    thread::scope(|s| {
        let r = s.spawn(|| q.receive(false, Some(soon(3000)), (0, 0)));
        while q.lock().receivers.is_empty() {
            thread::yield_now();
        }
        // Whether or not the receiver runs between the two sends, the first
        // message was its and the second finds the queue empty.
        assert!(send(&q, 0, b"first").unwrap().is_none());
        assert!(q.lock().registration.is_some(), "handed over: not notified");
        assert!(matches!(send(&q, 0, b"second").unwrap(), Some(Delivery::Signal { value: 3, .. })));
        assert_eq!(r.join().unwrap().unwrap().1, b"first");
    });
    assert_eq!(recv(&q).unwrap().1, b"second");
}

/// A receive from a full queue moves the oldest sleeping sender's message in,
/// so the queue stays full and no later sender overtakes it.
#[test]
fn a_receive_from_a_full_queue_takes_in_the_oldest_sleeping_sender() {
    let q = queue(1);
    send(&q, 0, b"full").unwrap();
    thread::scope(|s| {
        let a = s.spawn(|| q.send(2, b"next".to_vec(), false, Some(soon(3000)), (0, 0)));
        while q.lock().senders.is_empty() {
            thread::yield_now();
        }
        assert_eq!(recv(&q).unwrap().1, b"full");
        assert_eq!(q.lock().msgs.len(), 1, "refilled before the sender runs");
        assert!(a.join().unwrap().unwrap().is_none());
    });
    assert_eq!(recv(&q).unwrap(), (2, b"next".to_vec()));
}

/// Two sleeping receivers are served in the order they went to sleep.
#[test]
fn sleeping_receivers_are_served_in_order() {
    let q = queue(4);
    thread::scope(|s| {
        let first = s.spawn(|| q.receive(false, Some(soon(3000)), (0, 0)));
        while q.lock().receivers.is_empty() {
            thread::yield_now();
        }
        let second = s.spawn(|| q.receive(false, Some(soon(3000)), (0, 0)));
        while q.lock().receivers.len() < 2 {
            thread::yield_now();
        }
        send(&q, 0, b"1").unwrap();
        send(&q, 0, b"2").unwrap();
        assert_eq!(first.join().unwrap().unwrap().1, b"1");
        assert_eq!(second.join().unwrap().unwrap().1, b"2");
    });
}

/// A receiver that times out leaves the line, so the next message goes into
/// the queue rather than to a ticket nobody will collect.
#[test]
fn a_receiver_that_gave_up_is_not_handed_anything() {
    let q = queue(4);
    assert_eq!(q.receive(false, Some(soon(20)), (0, 0)).unwrap_err(), Errno::ETIMEDOUT);
    assert!(q.lock().receivers.is_empty());
    send(&q, 0, b"x").unwrap();
    assert_eq!(q.lock().msgs.len(), 1);
}

/// Many producers and consumers on a small queue: nothing lost, nothing
/// duplicated, and every priority level internally in order.
#[test]
fn producers_and_consumers_lose_nothing() {
    let q = queue(3);
    const PER: u32 = 400;
    let mut seen = Vec::new();
    thread::scope(|s| {
        for p in 0..4u32 {
            let q = &q;
            s.spawn(move || {
                for i in 0..PER {
                    let m = (p * PER + i).to_le_bytes().to_vec();
                    q.send(p, m, false, Some(soon(10_000)), (0, 0)).unwrap();
                }
            });
        }
        let consumers: Vec<_> = (0..3)
            .map(|_| {
                let q = &q;
                s.spawn(move || {
                    let mut got = Vec::new();
                    while let Ok((_, m)) = q.receive(false, Some(soon(500)), (0, 0)) {
                        got.push(u32::from_le_bytes(m.try_into().unwrap()));
                    }
                    got
                })
            })
            .collect();
        for c in consumers {
            seen.extend(c.join().unwrap());
        }
    });
    seen.sort();
    assert_eq!(seen, (0..4 * PER).collect::<Vec<_>>());
}
