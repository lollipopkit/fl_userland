//! `IOCB_CMD_POLL`: a one-shot wait for a descriptor's readiness that
//! completes on its own, with nobody in a syscall.
//!
//! # Why a service thread
//!
//! Linux completes a poll from the waker's wakeup callback. The equivalent
//! here is [`pollset::Watcher::notify`], and it **cannot ask the descriptor
//! anything**: a pipe notifies with its own lock held, and its `poll` takes
//! that lock. So a notify only kicks one host thread, which asks every armed
//! request's descriptor for its readiness from outside every lock and
//! completes the ready ones -- publishing to the ring through the kernel's own
//! mapping and signalling an `IOCB_FLAG_RESFD` eventfd, so a program that
//! waits on that eventfd with epoll and reaps from the ring itself sees the
//! completion without making an AIO syscall at all.
//!
//! Descriptors whose readiness is the host's (sockets, host files, host
//! terminals) are never notified by anything in this kernel, and neither is
//! an epoll set's own description; while one of those is armed the thread
//! rechecks every [`HOST_RECHECK`].
//!
//! # The result word
//!
//! `vfs_poll(file) & (requested | POLLERR | POLLHUP)`, with `POLLRDNORM` and
//! `POLLWRNORM` added the way `crates/fs/poll` adds them: what Linux answers
//! at submission and whenever a driver wakes without a key. A Linux driver
//! that *does* pass a key gets the key back unfiltered (a pipe write answers
//! `POLLIN|POLLRDNORM`, a socket `POLLIN|POLLPRI|POLLRDNORM|POLLRDBAND`);
//! this kernel's drivers notify with their own words, not Linux's keys, so
//! that half is not reproduced. `aio_probe` carries the two lines.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::Duration;

use pollset::Watcher;
use taskview::ffi;

use crate::abi::IoEvent;
use crate::context::{Context, Slot};

/// How often an armed request on a host-backed descriptor is asked again.
const HOST_RECHECK: Duration = Duration::from_millis(10);

/// `DEFAULT_POLLMASK`: a descriptor with no `poll` is always ready both ways.
const DEFAULT_MASK: u32 = (fs_poll::bits::READ | fs_poll::bits::WRITE | fs_poll::bits::RDNORM | fs_poll::bits::WRNORM) as u32;

/// One pending poll.
pub(crate) struct PollReq {
    ctx: Weak<Context>,
    /// The iocb's guest address: the event's `obj`, and what `io_cancel`
    /// names it by.
    pub obj: u64,
    data: u64,
    /// What was asked for, with `POLLERR | POLLHUP`, which always are.
    events: u32,
    fd: fs_fdobj::Owned,
    resfd: Option<fs_fdobj::Owned>,
    /// Readiness that nothing in this kernel notifies; see the module comment.
    timed: bool,
    done: AtomicBool,
}

/// What a descriptor reports, as Linux's `vfs_poll` would see it.
fn readiness(fd: &ffi::fd) -> u32 {
    match fd.ops.and_then(|ops| ops.poll(fd)) {
        None => DEFAULT_MASK,
        Some(types) => fs_poll::poll_add_aliases(types).max(0) as u32,
    }
}

impl PollReq {
    fn ready(&self) -> u32 {
        readiness(&self.fd) & self.events
    }

    fn as_watcher(self: &Arc<Self>) -> Arc<dyn Watcher> {
        Arc::clone(self) as Arc<dyn Watcher>
    }

    /// Complete with `res`, once: the service thread, `io_cancel` and
    /// teardown can all arrive here, and only the first publishes.
    ///
    /// The watcher goes **first**. Until it has, a notify running on another
    /// thread may hold an upgraded reference; removing it waits that notify
    /// out, and only then can this request's last reference -- and with it a
    /// descriptor whose watcher list that notify holds locked -- be dropped.
    pub fn finish(self: &Arc<Self>, res: u32) {
        if self.done.swap(true, Ordering::AcqRel) {
            return;
        }
        self.fd.poll_watchers.watchers_locked().remove(&self.as_watcher());
        disarm(self);
        if let Some(ctx) = self.ctx.upgrade() {
            ctx.poll_done(self, &IoEvent { data: self.data, obj: self.obj, res: i64::from(res), res2: 0 });
        }
        if let Some(resfd) = &self.resfd {
            crate::signal(resfd);
        }
    }

    /// `aio_poll_cancel` and the work it schedules: the result is whatever is
    /// ready at that moment, 0 when nothing is, which is what a cancelled
    /// poll on an empty pipe was measured to deliver.
    pub fn cancel(self: &Arc<Self>) {
        self.finish(self.ready());
    }
}

impl Watcher for PollReq {
    /// Called with the description's watcher list locked: nothing here may
    /// ask the descriptor anything. A word that names none of the requested
    /// events is not for this request, as Linux's `aio_poll_wake` filters it.
    fn notify(&self, _key: u64, events: u32) {
        if events != 0 && events & self.events == 0 {
            return;
        }
        kick();
    }

    /// The request holds the description, so it cannot close underneath it.
    fn detach(&self, _key: u64) {}
}

/// `aio_poll`. Registered before readiness is asked, so a transition between
/// the two is either seen by the question or notifies the registration.
pub(crate) fn submit(
    ctx: &Arc<Context>,
    slot: Slot<'_>,
    fd: fs_fdobj::Owned,
    resfd: Option<fs_fdobj::Owned>,
    obj: u64,
    data: u64,
    requested: u16,
) {
    let timed = fd.ops.is_some_and(|ops| ops.poll_follows_host_fd() || ops.caps() == ffi::Caps::NONE);
    let req = Arc::new(PollReq {
        ctx: Arc::downgrade(ctx),
        obj,
        data,
        events: u32::from(requested) | (fs_poll::bits::ERR | fs_poll::bits::HUP) as u32,
        fd,
        resfd,
        timed,
        done: AtomicBool::new(false),
    });
    if !ctx.add_poll(slot, Arc::clone(&req)) {
        return;
    }
    {
        let w = req.as_watcher();
        let mut list = req.fd.poll_watchers.watchers_locked();
        // A list that cannot grow leaves the request to the recheck below and
        // the service thread's timer, which is slower and still correct.
        if list.reserve(&w) {
            list.commit(&w, 0);
        }
    }
    arm(&req);
    let ready = req.ready();
    if ready != 0 {
        req.finish(ready);
    }
}

/// Cancel every request a dead context handed back, and drop them -- the
/// caller holds no lock of this crate's.
pub(crate) fn cancel_all(reqs: Vec<Arc<PollReq>>) {
    for req in &reqs {
        req.cancel();
    }
}

// ----------------------------------------------------------- the service

struct Armed {
    reqs: Vec<Arc<PollReq>>,
    kicked: bool,
    started: bool,
}

static ARMED: Mutex<Armed> = Mutex::new(Armed { reqs: Vec::new(), kicked: false, started: false });
static WAKE: Condvar = Condvar::new();

fn armed() -> MutexGuard<'static, Armed> {
    ARMED.lock().unwrap_or_else(|e| e.into_inner())
}

fn arm(req: &Arc<PollReq>) {
    let mut a = armed();
    a.reqs.push(Arc::clone(req));
    if !a.started {
        a.started = true;
        std::thread::Builder::new()
            .name("iul-aio-poll".into())
            .spawn(service)
            .expect("aio poll service thread");
    }
    WAKE.notify_one();
}

fn disarm(req: &Arc<PollReq>) {
    let removed = {
        let mut a = armed();
        a.reqs.iter().position(|r| Arc::ptr_eq(r, req)).map(|i| a.reqs.swap_remove(i))
    };
    drop(removed);
}

fn kick() {
    armed().kicked = true;
    WAKE.notify_one();
}

fn service() {
    loop {
        let snapshot = {
            let mut a = armed();
            while !a.kicked {
                if a.reqs.iter().any(|r| r.timed) {
                    a = WAKE.wait_timeout(a, HOST_RECHECK).unwrap_or_else(|e| e.into_inner()).0;
                    break;
                }
                a = WAKE.wait(a).unwrap_or_else(|e| e.into_inner());
            }
            a.kicked = false;
            a.reqs.clone()
        };
        for req in &snapshot {
            if req.done.load(Ordering::Acquire) {
                continue;
            }
            let ready = req.ready();
            if ready != 0 {
                req.finish(ready);
            }
        }
    }
}
