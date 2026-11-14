//! One AIO context: its ring, its in-flight count, its pending polls, and the
//! registry that finds it from a guest's context id.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use guest_errno::Errno;
use usercopy::GuestMem;
use util_guestlock::{GuestLock, Woke};

use crate::abi::{self, IoEvent};
use crate::poll::PollReq;
use crate::ring::Ring;
use taskview::ffi;

/// The one condition a context has: an event was published or it died.
const CHANGED: u32 = 0;

pub(crate) struct Context {
    /// The address space this context belongs to, as an identity. Contexts
    /// are `mm->ioctx_table`'s on Linux: a thread of the same process finds
    /// them, a forked child does not.
    mm: usize,
    /// The ring's `id` word, an index unique within `mm`.
    id: u32,
    max_reqs: u32,
    pub(crate) pages: u64,
    ring: Ring,
    /// The ring's file. Its identity is what says a guest page is this ring:
    /// see [`lookup`].
    file: fs_fdobj::Owned,
    state: GuestLock<State>,
    /// Linux's `ring_lock`: one reaper at a time, across the copy to the
    /// guest. Never held with `state`, and never taken under the address
    /// space's lock -- see [`ring_unmapped`].
    reap: Mutex<()>,
}

#[derive(Default)]
struct State {
    /// `io_destroy` ran, or the ring's last mapping went.
    dead: bool,
    /// The kernel's own tail, which a guest scribble on the ring's cannot move.
    tail: u32,
    /// Slots taken and not yet published: transfers in progress and polls
    /// pending.
    in_flight: u32,
    /// The pending `IOCB_CMD_POLL`s, which are what `io_cancel` can find.
    polls: Vec<Arc<PollReq>>,
    /// Polls that have completed, kept so that the reference which holds their
    /// descriptors is let go on a guest thread rather than the poll service's.
    retired: Vec<Arc<PollReq>>,
}

impl Context {
    pub fn nr(&self) -> u32 {
        self.ring.nr()
    }

    /// Events published and not yet reaped, against the guest's `head`.
    fn used(&self, st: &State) -> u32 {
        let nr = self.nr();
        let head = self.ring.head() % nr;
        (st.tail + nr - head) % nr
    }

    /// `aio_get_req`: a slot for one request, or `EAGAIN` when completed
    /// events nobody has reaped and requests in flight fill the ring. Linux
    /// keeps one slot free (`reqs_available` starts at `nr - 1`).
    pub fn reserve(&self) -> Result<Slot<'_>, Errno> {
        let mut st = self.state.lock();
        if st.dead {
            return Err(Errno::EINVAL);
        }
        if st.in_flight + self.used(&st) + 1 >= self.nr() {
            return Err(Errno::EAGAIN);
        }
        st.in_flight += 1;
        Ok(Slot { ctx: self, live: true })
    }

    /// Publish one event into a slot already taken, and wake the reapers.
    fn publish(&self, st: &mut State, ev: &IoEvent) {
        st.in_flight = st.in_flight.saturating_sub(1);
        if !st.dead {
            let at = st.tail;
            st.tail = (at + 1) % self.nr();
            self.ring.push(at, ev, st.tail);
        }
        // Dead or not: `drain` waits on the count as well.
        self.state.notify(CHANGED);
    }

    /// Wait for every slot to come back, as `io_destroy` does for every
    /// request -- uninterruptibly, as Linux's `wait_for_completion` is.
    pub fn drain(&self) {
        let mut st = self.state.lock();
        while st.in_flight > 0 {
            st.wait_ignoring_signals(CHANGED, None);
        }
    }

    /// A poll has finished: out of the pending list, its event published,
    /// and the request kept until a guest thread drops it.
    pub fn poll_done(&self, req: &Arc<PollReq>, ev: &IoEvent) {
        let mut st = self.state.lock();
        if let Some(i) = st.polls.iter().position(|p| Arc::ptr_eq(p, req)) {
            let p = st.polls.swap_remove(i);
            st.retired.push(p);
        }
        self.publish(&mut st, ev);
    }

    /// A poll that is pending now, holding the slot it was submitted with.
    /// False, and the slot given back, if the context died since the slot
    /// was taken: nothing would ever cancel the request.
    pub fn add_poll(&self, slot: Slot<'_>, req: Arc<PollReq>) -> bool {
        let mut st = self.state.lock();
        if st.dead {
            drop(st);
            drop(slot);
            return false;
        }
        st.polls.push(req);
        drop(st);
        slot.keep();
        true
    }

    pub fn find_poll(&self, obj: u64) -> Option<Arc<PollReq>> {
        self.state.lock().polls.iter().find(|p| p.obj == obj).cloned()
    }

    /// The finished polls, for the caller to drop outside every lock.
    pub fn take_retired(&self) -> Vec<Arc<PollReq>> {
        std::mem::take(&mut self.state.lock().retired)
    }

    fn dead(&self) -> bool {
        self.state.lock().dead
    }

    /// `kill_ioctx`: no more submissions, every waiter answered `EINVAL`.
    /// The pending polls are handed back for the caller to cancel outside
    /// the lock.
    pub fn kill(&self) -> Vec<Arc<PollReq>> {
        let mut st = self.state.lock();
        st.dead = true;
        let mut out = std::mem::take(&mut st.polls);
        out.append(&mut st.retired);
        self.state.notify(CHANGED);
        out
    }

    /// `aio_read_events_ring`: copy up to `max` events to `out` and move the
    /// guest's `head` past them. **The guest's `head` and `tail` are read
    /// back**, scribbled or not, which is what Linux does; only a fault leaves
    /// `head` where it was, so nothing is consumed by a copy that failed.
    fn reap(&self, out: u64, max: i64) -> Result<i64, Errno> {
        let _one = self.reap.lock().unwrap_or_else(|e| e.into_inner());
        let nr = self.nr();
        let head = self.ring.head();
        let tail = self.ring.tail();
        if head == tail {
            return Ok(0);
        }
        let (mut head, tail) = (head % nr, tail % nr);
        let mut bytes = Vec::new();
        let mut n = 0i64;
        while n < max && head != tail {
            self.ring.get(head).encode(&mut bytes);
            head = (head + 1) % nr;
            n += 1;
        }
        if n > 0 && GuestMem.write(out, &bytes) != 0 {
            return Err(Errno::EFAULT);
        }
        self.ring.set_head(head);
        Ok(n)
    }

    /// `read_events`: at least `min` events, or fewer when the timeout runs
    /// out or a signal arrives. A wait is the interruptible one, so a signal
    /// or a group exit ends it.
    pub fn get_events(&self, min: i64, nr: i64, out: u64, timeout: abi::Timeout) -> Result<i64, Errno> {
        let deadline = match timeout {
            abi::Timeout::After(ns) => Some(util_timeabi::monotonic_ns().saturating_add(ns)),
            _ => None,
        };
        let mut got = 0i64;
        loop {
            // `aio_read_events`: a fault is the answer only if nothing came
            // before it, and a dead context is `EINVAL` on the same terms.
            match self.reap(out + got as u64 * abi::EVENT_SIZE as u64, nr - got) {
                Ok(n) => got += n,
                Err(e) if got == 0 => return Err(e),
                Err(_) => return Ok(got),
            }
            if self.dead() {
                return if got == 0 { Err(Errno::EINVAL) } else { Ok(got) };
            }
            if got >= min || timeout == abi::Timeout::Poll {
                return Ok(got);
            }
            let mut st = self.state.lock();
            if st.dead || self.ring.head() != self.ring.tail() {
                continue;
            }
            let remaining = match deadline {
                None => None,
                Some(d) => {
                    let now = util_timeabi::monotonic_ns();
                    if now >= d {
                        drop(st);
                        // One last read, as Linux's wait evaluates the
                        // condition again after the timer fires.
                        return match self.reap(out + got as u64 * abi::EVENT_SIZE as u64, nr - got) {
                            Ok(n) => Ok(got + n),
                            Err(e) if got == 0 => Err(e),
                            Err(_) => Ok(got),
                        };
                    }
                    Some(Duration::from_nanos(d - now))
                }
            };
            if st.wait(CHANGED, remaining) == Woke::Interrupted {
                drop(st);
                return if got == 0 { Err(Errno::EINTR) } else { Ok(got) };
            }
        }
    }
}

/// A slot `reserve` took. Dropped unused, it is given back -- every refusal
/// after `aio_get_req` frees the request it allocated.
pub(crate) struct Slot<'a> {
    ctx: &'a Context,
    live: bool,
}

impl Slot<'_> {
    /// The request ran and finished: publish its event.
    pub fn complete(mut self, ev: &IoEvent) {
        self.live = false;
        let mut st = self.ctx.state.lock();
        self.ctx.publish(&mut st, ev);
    }

    /// The slot now belongs to a pending poll, which publishes into it.
    fn keep(mut self) {
        self.live = false;
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        if self.live {
            let mut st = self.ctx.state.lock();
            st.in_flight = st.in_flight.saturating_sub(1);
            self.ctx.state.notify(CHANGED);
        }
    }
}

// ---------------------------------------------------------------- registry

struct Registry {
    contexts: Vec<Arc<Context>>,
    /// `aio_nr`: what every live context charges, against [`abi::AIO_MAX_NR`].
    aio_nr: u64,
}

/// Held only for lookups and edits of the list, **never across a mapping
/// operation**: [`ring_unmapped`] takes it with the address space locked.
static REGISTRY: Mutex<Registry> = Mutex::new(Registry { contexts: Vec::new(), aio_nr: 0 });

fn registry() -> MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// `/proc/sys/fs/aio-nr`.
pub fn aio_nr() -> u64 {
    registry().aio_nr
}

fn current_mm() -> usize {
    taskview::current_mm() as usize
}

/// `ioctx_alloc` up to the point the ring is mapped: charge the budget, make
/// the file, give it an id and publish it. The caller maps it.
pub(crate) fn create(geometry: abi::Geometry) -> Result<Arc<Context>, Errno> {
    let mm = current_mm();
    {
        let mut r = registry();
        let charged = r.aio_nr.checked_add(u64::from(geometry.max_reqs));
        match charged {
            Some(total) if total <= abi::AIO_MAX_NR => r.aio_nr = total,
            _ => return Err(Errno::EAGAIN),
        }
    }
    let refund = |e| {
        registry().aio_nr -= u64::from(geometry.max_reqs);
        e
    };
    let file = memfdcalls::create_internal(b"/[aio]", geometry.pages * abi::PAGE, 0o600, Some(ring_unmapped), None)
        .map_err(|_| refund(Errno::ENOMEM))?;
    let host = file.host().ok_or(Errno::ENOMEM).map_err(refund)?;
    let ring = Ring::map(host, geometry.pages, geometry.nr).map_err(refund)?;
    let mut r = registry();
    // `ioctx_add_table`: the lowest index this address space is not using.
    let mut id = 0u32;
    while r.contexts.iter().any(|c| c.mm == mm && c.id == id) {
        id += 1;
    }
    ring.init(id);
    let ctx = Arc::new(Context {
        mm,
        id,
        max_reqs: geometry.max_reqs,
        pages: geometry.pages,
        ring,
        file,
        state: GuestLock::new(State::default(), 1),
        reap: Mutex::new(()),
    });
    r.contexts.push(Arc::clone(&ctx));
    Ok(ctx)
}

/// The ring's file, for the caller that maps it.
pub(crate) fn file_of(ctx: &Context) -> &fs_fdobj::Owned {
    &ctx.file
}

/// Take a context out of the registry and give back its budget. False if it
/// was not there, which is a second `io_destroy` losing a race.
pub(crate) fn unlink(ctx: &Arc<Context>) -> bool {
    let mut r = registry();
    let Some(i) = r.contexts.iter().position(|c| Arc::ptr_eq(c, ctx)) else {
        return false;
    };
    let gone = r.contexts.swap_remove(i);
    r.aio_nr -= u64::from(gone.max_reqs);
    drop(r);
    drop(gone);
    true
}

/// `lookup_ioctx`. Linux reads the ring's `id` word through the guest's
/// mapping -- so an unmapped or scribbled ring is not found -- indexes the
/// address space's table with it, and checks the context's `user_id` against
/// the address, which `aio_ring_mremap` keeps current.
///
/// The last check is asked of the page table here: the page at `ctx_id` must
/// be the first page of this context's ring file. That is what `user_id`
/// stands for, and it follows an `mremap` without being told, which this
/// kernel's `mremap` could not do.
pub(crate) fn lookup(ctx_id: u64) -> Option<Arc<Context>> {
    if !ctx_id.is_multiple_of(abi::PAGE) {
        return None;
    }
    let mut word = [0u8; 4];
    if GuestMem.read(ctx_id, &mut word) != 0 {
        return None;
    }
    let id = u32::from_le_bytes(word);
    let mm = current_mm();
    let ctx = registry().contexts.iter().find(|c| c.mm == mm && c.id == id).cloned()?;
    let (file, offset) = mmapcalls::share::mapped_at(ctx_id)?;
    (offset == 0 && file.as_ptr() == ctx.file.as_ptr()).then_some(ctx)
}

/// The page table dropped a shared mapping of a ring file. When it was the
/// last -- the guest unmapped the ring, or the address space went with an
/// `exit` or an `execve` -- nothing can reach the context again, and it is
/// released: Linux's `exit_aio`.
///
/// **Runs with the address space locked for writing**, from the mapping's
/// destructor, so it takes the registry and the context's state and nothing
/// that needs that lock.
fn ring_unmapped(fd: &ffi::fd) {
    if memfdcalls::shared_mappings(fd) != Some(0) {
        return;
    }
    let found = registry()
        .contexts
        .iter()
        .find(|c| std::ptr::eq(c.file.as_ptr().cast_const(), fd))
        .cloned();
    if let Some(ctx) = found
        && unlink(&ctx)
    {
        crate::teardown(&ctx, None);
    }
}
