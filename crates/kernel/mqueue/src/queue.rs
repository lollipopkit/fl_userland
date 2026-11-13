//! One queue: its messages, who is waiting on it, and who asked to be told.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use guest_errno::Errno;
use pollset::Watchers;
use util_guestlock::{GuestGuard, GuestLock, Woke};
use util_identity::TaskRef;

use crate::abi::{self, Attr};

/// A receiver's condition: a message was handed to someone.
const HANDED: u32 = 0;
/// A sender's condition: someone's message went in.
const TAKEN: u32 = 1;

pub const POLL_IN: u32 = 1;
pub const POLL_OUT: u32 = 4;

/// The messages, highest priority first and in arrival order within one.
///
/// A map of priority to a FIFO rather than a heap of `(prio, seq)`: the two
/// questions asked of it are "the oldest of the highest" and "how many", and
/// most queues use one priority, so this is one `VecDeque`.
#[derive(Default)]
pub struct Messages {
    by_prio: BTreeMap<u32, VecDeque<Vec<u8>>>,
    count: usize,
    /// The bytes held, which is the status line's `QSIZE`.
    bytes: u64,
}

impl Messages {
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn push(&mut self, prio: u32, msg: Vec<u8>) {
        self.bytes += msg.len() as u64;
        self.count += 1;
        self.by_prio.entry(prio).or_default().push_back(msg);
    }

    pub fn pop(&mut self) -> Option<(u32, Vec<u8>)> {
        let mut top = self.by_prio.last_entry()?;
        let prio = *top.key();
        let msg = top.get_mut().pop_front().expect("no empty level is kept");
        if top.get().is_empty() {
            top.remove();
        }
        self.count -= 1;
        self.bytes -= msg.len() as u64;
        Some((prio, msg))
    }
}

/// How a registered process is told.
pub enum How<S> {
    /// Nothing is sent; the registration is used up all the same.
    Nothing,
    Signal { signo: i32, value: u64 },
    /// A netlink socket, held for as long as the registration is, and the
    /// cookie that goes back on it.
    Thread { sock: S, cookie: [u8; abi::COOKIE_LEN] },
}

/// `mq_notify`'s one registration per queue.
pub struct Registration<S> {
    /// The registering process's tgid: what `NOTIFY_PID` shows and what the
    /// "is it the owner" questions compare.
    pub owner_tgid: i32,
    /// The same process, as a reference a reused pid does not match: where a
    /// signal goes.
    pub owner: TaskRef,
    pub how: How<S>,
}

impl<S> Registration<S> {
    fn sigev_notify(&self) -> i32 {
        match self.how {
            How::Nothing => abi::SIGEV_NONE,
            How::Signal { .. } => abi::SIGEV_SIGNAL,
            How::Thread { .. } => abi::SIGEV_THREAD,
        }
    }

    fn signo(&self) -> i32 {
        match self.how {
            How::Signal { signo, .. } => signo,
            _ => 0,
        }
    }

    /// What firing it sends, which is the caller's to send once the queue's
    /// lock is dropped: a signal needs the process table's lock and a cookie
    /// needs a socket's, neither of which nests under this one.
    fn fired(self) -> Option<Delivery<S>> {
        match self.how {
            How::Nothing | How::Signal { signo: 0, .. } => None,
            How::Signal { signo, value } => Some(Delivery::Signal { to: self.owner, signo, value }),
            How::Thread { sock, mut cookie } => {
                cookie[abi::COOKIE_LEN - 1] = abi::NOTIFY_WOKENUP;
                Some(Delivery::Datagram { sock, cookie })
            }
        }
    }

    /// What removing it sends: a `SIGEV_THREAD` registration is told it is
    /// gone, so the thread waiting on the socket can stop.
    fn removed(self) -> Option<Delivery<S>> {
        match self.how {
            How::Thread { sock, mut cookie } => {
                cookie[abi::COOKIE_LEN - 1] = abi::NOTIFY_REMOVED;
                Some(Delivery::Datagram { sock, cookie })
            }
            _ => None,
        }
    }
}

/// What a caller must send after the queue's lock is dropped.
#[derive(Debug)]
pub enum Delivery<S> {
    /// `SI_MESGQ` to the process, from the caller.
    Signal { to: TaskRef, signo: i32, value: u64 },
    Datagram { sock: S, cookie: [u8; abi::COOKIE_LEN] },
}

/// The queue as an inode: what `fstat` reports and `fchmod`, `fchown`,
/// `ftruncate` and `futimens` change. One per queue, so a change through one
/// descriptor is what every other one -- and the next `mq_open` -- sees.
#[derive(Debug, Clone, Copy)]
pub struct Inode {
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// `FILENT_SIZE` until a truncate says otherwise. Nothing reads it but
    /// `fstat`, `lseek(SEEK_END)` and `FIONREAD`; the status line is formatted
    /// into a buffer of its own.
    pub size: i64,
    pub linked: bool,
    pub atime: (i64, i64),
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}

pub struct State<S> {
    pub msgs: Messages,
    pub registration: Option<Registration<S>>,
    pub inode: Inode,
    /// Receivers asleep on an empty queue, oldest first.
    receivers: VecDeque<u64>,
    /// Messages a send handed straight to a sleeping receiver, by its ticket.
    handed: BTreeMap<u64, (u32, Vec<u8>)>,
    /// Senders asleep on a full queue, oldest first, with what they sent.
    senders: VecDeque<(u64, u32, Vec<u8>)>,
    /// Senders whose message a receive moved into the queue.
    taken: Vec<u64>,
    next_ticket: u64,
}

impl<S> State<S> {
    fn ticket(&mut self) -> u64 {
        self.next_ticket += 1;
        self.next_ticket
    }

    /// The status line's three notification fields.
    pub fn notify_fields(&self) -> Option<(i32, i32, i32)> {
        self.registration.as_ref().map(|r| (r.sigev_notify(), r.signo(), r.owner_tgid))
    }
}

/// An absolute `CLOCK_REALTIME` deadline, already checked to be a valid
/// `timespec`.
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    pub sec: i64,
    pub nsec: i64,
}

impl Deadline {
    /// What is left of it, or `None` once it has passed. Asked again on every
    /// pass of a wait, against the clock: the guest's clock is the host's, so
    /// a host clock change moves it the way `clock_settime` moves Linux's.
    fn remaining(&self) -> Option<Duration> {
        let (now_sec, now_nsec) = timeabi::host_clock(libc::CLOCK_REALTIME).unwrap_or((0, 0));
        timeabi::remaining_until(self.sec, self.nsec, now_sec, now_nsec)
            .map(|ns| Duration::from_nanos(ns as u64))
    }
}

/// Why a wait ended without its operation.
enum Ended {
    Interrupted,
    TimedOut,
}

impl From<Ended> for Errno {
    fn from(e: Ended) -> Errno {
        match e {
            Ended::Interrupted => Errno::EINTR,
            Ended::TimedOut => Errno::ETIMEDOUT,
        }
    }
}

/// One wait for `cond`, bounded by what is left of `deadline`. `Ok` to look
/// again, whatever woke it.
fn wait_once<S>(
    s: &mut GuestGuard<'_, State<S>>,
    cond: u32,
    deadline: Option<Deadline>,
) -> Result<(), Ended> {
    let timeout = match deadline {
        None => None,
        Some(d) => Some(d.remaining().ok_or(Ended::TimedOut)?),
    };
    match s.wait(cond, timeout) {
        Woke::Interrupted => Err(Ended::Interrupted),
        // Not an answer by itself: the deadline is asked again above, against
        // the clock, which is the one that decides.
        Woke::TimedOut | Woke::Notified => Ok(()),
    }
}

/// A queue: everything `mq_open` finds by name.
///
/// # Messages are handed over, not raced for
///
/// A send to an empty queue with a receiver asleep gives the message to the
/// oldest sleeping receiver, and a receive from a full queue with a sender
/// asleep moves the oldest sleeping sender's message in. That is Linux's
/// `pipelined_send` and `pipelined_receive`, and the difference from "wake
/// everyone and let them look" is observable twice:
///
/// - `mq_notify` fires on a message reaching an empty queue **with nobody
///   waiting for it**. A handed-over message never reaches the queue, so a
///   second send arriving before the woken receiver runs finds the queue
///   empty and notifies -- where a woken-and-racing design would find the
///   first message still there and stay silent.
/// - Waiters are served in order; nobody who arrives later takes a message
///   an earlier sleeper was woken for.
///
/// A sleeper that is interrupted or times out after its message was handed
/// to it takes the message anyway, which is Linux's `wq_sleep` reading
/// `STATE_READY` before the signal.
pub struct Queue<S> {
    pub maxmsg: usize,
    pub msgsize: usize,
    state: GuestLock<State<S>>,
    /// Every open description's reverse edge. Weak: a description holds its
    /// queue, not the other way round.
    watchers: Mutex<Vec<Weak<Watchers>>>,
}

impl<S> Queue<S> {
    pub fn new(maxmsg: usize, msgsize: usize, inode: Inode) -> Queue<S> {
        Queue {
            maxmsg,
            msgsize,
            state: GuestLock::new(
                State {
                    msgs: Messages::default(),
                    registration: None,
                    inode,
                    receivers: VecDeque::new(),
                    handed: BTreeMap::new(),
                    senders: VecDeque::new(),
                    taken: Vec::new(),
                    next_ticket: 0,
                },
                2,
            ),
            watchers: Mutex::new(Vec::new()),
        }
    }

    pub fn lock(&self) -> GuestGuard<'_, State<S>> {
        self.state.lock()
    }

    pub fn watch(&self, w: &Arc<Watchers>) {
        let mut list = self.watchers.lock().unwrap_or_else(|e| e.into_inner());
        list.retain(|w| w.strong_count() > 0);
        list.push(Arc::downgrade(w));
    }

    /// Publish a readiness change. Never under the queue's lock: a watcher may
    /// ask for the readiness, and that takes it.
    fn wake_pollers(&self, events: u32) {
        let list: Vec<Arc<Watchers>> = {
            let mut list = self.watchers.lock().unwrap_or_else(|e| e.into_inner());
            list.retain(|w| w.strong_count() > 0);
            list.iter().filter_map(Weak::upgrade).collect()
        };
        for w in list {
            pollset::poll_watchers_notify(&w, events);
        }
    }

    /// `mq_getsetattr`'s view, with `mq_flags` the caller's to fill in.
    pub fn attr(&self) -> Attr {
        Attr {
            flags: 0,
            maxmsg: self.maxmsg as i64,
            msgsize: self.msgsize as i64,
            curmsgs: self.lock().msgs.len() as i64,
        }
    }

    /// The readiness bits, for every access mode alike: Linux's
    /// `mqueue_poll_file` does not look at how the queue was opened.
    pub fn poll(&self) -> u32 {
        let s = self.lock();
        let mut bits = 0;
        if !s.msgs.is_empty() {
            bits |= POLL_IN;
        }
        if s.msgs.len() < self.maxmsg {
            bits |= POLL_OUT;
        }
        bits
    }

    /// `mq_timedsend` once its arguments are checked: `msg` fits.
    ///
    /// Answers what the caller must deliver for `mq_notify`.
    pub fn send(
        &self,
        prio: u32,
        msg: Vec<u8>,
        nonblock: bool,
        deadline: Option<Deadline>,
        now: (i64, i64),
    ) -> Result<Option<Delivery<S>>, Errno> {
        let mut s = self.lock();
        if s.msgs.len() < self.maxmsg {
            s.inode.atime = now;
            s.inode.mtime = now;
            s.inode.ctime = now;
            if let Some(receiver) = s.receivers.pop_front() {
                s.handed.insert(receiver, (prio, msg));
                drop(s);
                self.state.notify(HANDED);
                return Ok(None);
            }
            s.msgs.push(prio, msg);
            // The empty-to-not-empty transition, with nobody waiting: the
            // only one that notifies, and it uses the registration up.
            let fired = if s.msgs.len() == 1 {
                s.registration.take().and_then(Registration::fired)
            } else {
                None
            };
            drop(s);
            self.wake_pollers(POLL_IN);
            return Ok(fired);
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        let me = s.ticket();
        s.senders.push_back((me, prio, msg));
        loop {
            if let Some(i) = s.taken.iter().position(|&t| t == me) {
                s.taken.swap_remove(i);
                return Ok(None);
            }
            if let Err(e) = wait_once(&mut s, TAKEN, deadline) {
                if let Some(i) = s.taken.iter().position(|&t| t == me) {
                    s.taken.swap_remove(i);
                    return Ok(None);
                }
                s.senders.retain(|(t, _, _)| *t != me);
                return Err(e.into());
            }
        }
    }

    /// `mq_timedreceive` once its arguments are checked: the caller's buffer
    /// holds `msgsize`.
    pub fn receive(
        &self,
        nonblock: bool,
        deadline: Option<Deadline>,
        now: (i64, i64),
    ) -> Result<(u32, Vec<u8>), Errno> {
        let mut s = self.lock();
        if let Some(got) = s.msgs.pop() {
            s.inode.atime = now;
            s.inode.mtime = now;
            s.inode.ctime = now;
            let refilled = if let Some((sender, prio, msg)) = s.senders.pop_front() {
                s.msgs.push(prio, msg);
                s.taken.push(sender);
                true
            } else {
                false
            };
            drop(s);
            if refilled {
                self.state.notify(TAKEN);
            } else {
                self.wake_pollers(POLL_OUT);
            }
            return Ok(got);
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        let me = s.ticket();
        s.receivers.push_back(me);
        loop {
            if let Some(got) = s.handed.remove(&me) {
                return Ok(got);
            }
            if let Err(e) = wait_once(&mut s, HANDED, deadline) {
                if let Some(got) = s.handed.remove(&me) {
                    return Ok(got);
                }
                s.receivers.retain(|&t| t != me);
                return Err(e.into());
            }
        }
    }

    /// `mq_notify` with a registration. `EBUSY` if there is one already, and
    /// `reg` comes back with the error so a socket it holds is released by
    /// the caller rather than under this lock.
    pub fn register(&self, reg: Registration<S>, now: (i64, i64)) -> Result<(), (Errno, Registration<S>)> {
        let mut s = self.lock();
        if s.registration.is_some() {
            return Err((Errno::EBUSY, reg));
        }
        s.registration = Some(reg);
        s.inode.atime = now;
        s.inode.ctime = now;
        Ok(())
    }

    /// Remove the registration if `tgid` owns it: `mq_notify(NULL)` and a
    /// close by the owner. Anyone else's is left alone, and that is not an
    /// error -- measured: a child's `mq_notify(NULL)` answers 0 and the
    /// parent's registration stays.
    pub fn unregister(&self, tgid: i32, now: Option<(i64, i64)>) -> Option<Delivery<S>> {
        let mut s = self.lock();
        if s.registration.as_ref().is_some_and(|r| r.owner_tgid == tgid) {
            if let Some(now) = now {
                s.inode.atime = now;
                s.inode.ctime = now;
            }
            return s.registration.take().and_then(Registration::removed);
        }
        None
    }
}

#[cfg(test)]
#[path = "queue_tests.rs"]
mod tests;
