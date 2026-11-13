//! Public epoll operations exposed to the descriptor and poll layers.

use super::*;
use kernel_errno::guest::{EEXIST, EINVAL, ELOOP, ENOENT, ENOMEM};
use pollset::Watcher;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(crate) fn error_code(error: Error) -> c_int {
    match error {
        Error::Exists => EEXIST,
        Error::Invalid => EINVAL,
        Error::Missing => ENOENT,
        Error::Loop => ELOOP,
        Error::OutOfMemory => ENOMEM,
    }
}

fn ffi_error(f: impl FnOnce() -> Result<c_int, Error>) -> c_int {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => error_code(error),
        Err(_) => EINVAL,
    }
}

/// Allocate an epoll state, or the guest errno for why not.
///
/// An `Arc` because a member's reverse edge holds a `Weak` of it. It was an
/// `Arc::into_raw` pointer and an out-parameter for the errno until
/// 2026-09-29, when the descriptor started owning its state: the
/// description holds this `Arc`, and [`epoll_add`] and [`epoll_delete`] take
/// it as one: a member's reverse edge needs a count of its own.
pub fn epoll_state_new() -> Result<Arc<Epoll>, c_int> {
    let backend = Backend::new()?;
    // `Arc::new` aborts on allocation failure where the C constructor's
    // contract is ENOMEM, but this is one fixed-size allocation: an emulator
    // that cannot make it is not going to answer a syscall either.
    let epoll = Arc::new(Epoll {
        core: Mutex::new(Core::default()),
        backend,
        busy_poll: Default::default(),
    });
    LIVE.fetch_add(1, Ordering::Relaxed);
    Ok(epoll)
}

pub fn epoll_live_count() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

/// Drain immediately available host transitions and report guest readiness.
pub fn epoll_probe_ready(state: &Epoll) -> c_int {
    let epoll = state;
    let Ok(transitions) = epoll.backend.drain(std::time::Duration::ZERO) else {
        return 0;
    };
    let mut core = lock_core(epoll);
    let was_ready = core.is_ready();
    for (description, events) in transitions.iter() {
        core.notify(description, events);
    }
    let ready = core.is_ready();
    if !was_ready && ready {
        epoll.backend.wake();
    }
    ready as c_int
}

/// `state` must be live when non-null.
/// Not `#[unsafe(no_mangle)]` since 2026-09-06. No C source calls it, no
/// `ffi::` reaches it, and no header the embedder example compiles against
/// declares it -- so the export was a second interface with nobody on the
/// other side, and an optimisation barrier: LTO must emit an externally
/// visible function as written and cannot specialise the call.
pub fn epoll_backend_fd(state: &Epoll) -> c_int {
    std::os::fd::AsRawFd::as_raw_fd(&state.backend.fd)
}

/// Add a registration, and record this epoll in the member's reverse edge.
///
/// Returns 1 when the description was not already registered, 0 when it was, or
/// a negative guest errno.
///
/// **Safe since 2026-09-30.** Its `# Safety` section asked that "`state`, `fd`,
/// `watches` and `ops`" stay live, which the three references already say and
/// the fourth no longer existed. What it did need was unwritten: that the
/// `&Epoll` was the inside of an `Arc`, because the reverse edge clones one out
/// of it -- `Arc::from_raw` on a borrowed address. It takes the `Arc` now,
/// which is what every caller had.
///
/// Its one caller outside this crate is `crates/fs/poll`, which calls it
/// directly since 2026-09-06.
///
/// The member comes as a `Weak`, which is what the registration keeps; a
/// member already gone is `EBADF`'s case, answered as `Invalid` -- the caller
/// holds a reference, so it does not arise.
#[allow(clippy::too_many_arguments)]
pub fn epoll_add<M: Members>(
    state: &Arc<Epoll>,
    nested: Option<&Epoll>,
    member: &std::sync::Weak<M::Member>,
    watchers: &Arc<Watchers>,
    fd_number: c_int,
    events: u32,
    data: u64,
) -> c_int {
    // `fd` is a reference, so there is no null to test for -- the check that
    // was here went with the `*mut M::Member` on 2026-09-16.
    ffi_error(|| {
        let epoll: &Epoll = state;
        let strong = member.upgrade().ok_or(Error::Invalid)?;
        let fd: &M::Member = &strong;
        if nested.is_some() && events & EXCLUSIVE != 0 {
            return Err(Error::Invalid);
        }
        // `match` rather than `is_none()` and a `map_or` with a default the
        // other arm cannot reach: the two graph nodes are the two arms of the
        // `Option`, which is what `nested` means.
        let graph_target = match nested {
            None => GraphNode::File(FileId::of(fd)),
            Some(nested) => GraphNode::Epoll(SetId::of(nested)),
        };
        let mut graph_guard = Some(
            GRAPH
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let graph_plan = {
            let graph = graph_guard
                .as_mut()
                .expect("epoll ADD holds the graph mutex")
                .get_or_insert_with(Graph::default);
            Some(graph.prepare_add(SetId::of(state), graph_target)?)
        };
        // The member's reverse edge before this epoll's core: that is the
        // order a wakeup takes them in, and it is the only order anything takes
        // them in. The entry is reserved here and filled in below, because the
        // key it registers under is the description id, which only exists once
        // the core has made it.
        let watcher: Arc<dyn Watcher> = state.clone();
        let mut listed = watchers.watchers_locked();
        if !listed.reserve(&watcher) {
            return Err(Error::OutOfMemory);
        }
        let mut core = lock_core(epoll);
        let added = core.insert(
            DescriptionKey::of(fd),
            member.clone(),
            watchers,
            fd_number,
            events,
            data,
            M::is_socket(fd),
            Some(graph_target),
        )?;
        if let Some(host_fd) = Some(M::host_fd(fd))
            && host_fd >= 0
        {
            let interest = core
                .host_interest(added.description)
                .expect("an added description must be live");
            let error = epoll.backend.update(host_fd, interest, added.description);
            if error < 0 {
                core.remove(DescriptionKey::of(fd), fd_number)
                    .expect("the just-added registration must roll back");
                if added.new_description {
                    epoll.backend.remove(host_fd);
                } else if let Some(previous) = core.host_interest(added.description) {
                    epoll.backend.update(host_fd, previous, added.description);
                }
                return Ok(error);
            }
        }
        listed.commit(&watcher, pack(added.description));
        let ready = M::poll(fd) as u32;
        let became_ready =
            ready & ((events & !CONTROL) | HUP | ERR) != 0 && core.notify(added.description, ready);
        if became_ready {
            epoll.backend.wake();
        }
        if let Some(plan) = graph_plan {
            graph_guard
                .as_mut()
                .expect("nested add holds the graph mutex")
                .as_mut()
                .expect("the graph was initialized during prepare")
                .commit_add(plan, graph_target);
        }
        Ok(added.new_description as c_int)
    })
}

pub fn epoll_modify<M: Members>(
    state: &Epoll,
    fd: &M::Member,
    fd_number: c_int,
    events: u32,
    data: u64,
) -> c_int {
    ffi_error(|| {
        let epoll = state;
        let mut core = lock_core(epoll);
        let (id, description, old) = core.modify(DescriptionKey::of(fd), fd_number, events, data)?;
        if let Some(host_fd) = Some(M::host_fd(fd))
            && host_fd >= 0
        {
            let interest = core
                .host_interest(description)
                .expect("the modified description must be live");
            let error = epoll.backend.update(host_fd, interest, description);
            if error < 0 {
                core.restore_registration(id, old);
                let old_interest = core
                    .host_interest(description)
                    .expect("the restored description must be live");
                epoll.backend.update(host_fd, old_interest, description);
                return Ok(error);
            }
        }
        let ready = M::poll(fd) as u32;
        let became_ready =
            ready & ((events & !CONTROL) | HUP | ERR) != 0 && core.notify(description, ready);
        if became_ready {
            epoll.backend.wake();
        }
        Ok(0)
    })
}

/// Returns 1 when the last registration for the description was removed, which
/// is also when this epoll leaves the member's reverse edge.
///
/// Safe for [`epoll_add`]'s reason.
pub fn epoll_delete<M: Members>(
    state: &Arc<Epoll>,
    _nested: Option<&Epoll>,
    fd: &M::Member,
    watchers: &Arc<Watchers>,
    fd_number: c_int,
) -> c_int {
    // `fd` is a reference, so there is no null to test for -- the check that
    // was here went with the `*mut M::Member` on 2026-09-16.
    ffi_error(|| {
        let epoll: &Epoll = state;
        let mut graph_guard = Some(
            GRAPH
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let watcher: Arc<dyn Watcher> = state.clone();
        let mut listed = watchers.watchers_locked();
        let mut core = lock_core(epoll);
        let was_ready = core.is_ready();
        let (description, graph_target) = core.remove(DescriptionKey::of(fd), fd_number)?;
        let interest = core.host_interest(description);
        if let Some(host_fd) = Some(M::host_fd(fd))
            && host_fd >= 0
        {
            if let Some(interest) = interest {
                let error = epoll.backend.update(host_fd, interest, description);
                if error < 0 {
                    // DEL has already removed the guest registration and Linux
                    // offers no rollback result. A stale host watch can only
                    // cause a discarded wakeup; remove it when no registrations
                    // remain and otherwise log at the C boundary if desired.
                }
            } else {
                epoll.backend.remove(host_fd);
            }
        }
        if was_ready && !core.is_ready() {
            epoll.backend.drain_notify();
        }
        if interest.is_none() {
            listed.remove(&watcher);
        }
        if let Some(target) = graph_target
            && let Some(graph) = graph_guard.as_mut()
        {
            graph
                .get_or_insert_with(Graph::default)
                .remove(SetId::of(state), target, 1);
        }
        Ok(interest.is_none() as c_int)
    })
}

/// Whether a wait would return at once.
pub fn epoll_is_ready(state: &Epoll) -> bool {
    lock_core(state).is_ready()
}

/// Whether any member is a socket, which is what brackets a wait for the iOS
/// resume path.
pub fn epoll_has_socket(state: &Epoll) -> bool {
    lock_core(state).has_socket()
}

/// Copy up to `out.len()` ready events into `out`, answering how many.
///
/// A slice since 2026-09-30. It was an `unsafe fn` over an `*mut Event` and a
/// count, with a null test, from when the buffer was C's; the one caller has
/// a `Vec`.
/// The member a description names, if it is still open.
fn upgrade<M: Members>(member: &crate::core::MemberRef) -> Option<Arc<M::Member>> {
    member.upgrade()?.downcast::<M::Member>().ok()
}

/// One registration as `/proc/<pid>/fdinfo` lists it; see `Core::listing`.
pub struct Listed<T> {
    pub fd: i32,
    pub events: u32,
    pub data: u64,
    /// `None` for a member that is closing.
    pub member: Option<Arc<T>>,
}

/// The set's registrations, ordered by descriptor number.
pub fn epoll_listing<M: Members>(state: &Epoll) -> Vec<Listed<M::Member>> {
    let listing = lock_core(state).listing();
    listing
        .into_iter()
        .map(|(fd, events, data, member)| Listed { fd, events, data, member: upgrade::<M>(&member) })
        .collect()
}

pub fn epoll_take_ready<M: Members>(
    state: &Epoll,
    out: &mut [Event],
    timeout: std::time::Duration,
) -> c_int {
    let max_events = out.len();
    catch_unwind(AssertUnwindSafe(|| {
        let epoll = state;
        // Drain before delivery even when Rust already has a candidate. The host
        // may still hold the transition that caused an ADD-time readiness check;
        // consuming it first prevents that old transition from being mistaken
        // for a new edge on the next wait.
        let transitions = match epoll.backend.drain(timeout) {
            Ok(transitions) => transitions,
            Err(error) => return error,
        };
        let mut core = lock_core(epoll);
        for (description, events) in transitions.iter() {
            core.notify(description, events);
        }
        let was_ready = core.is_ready();
        // A member that cannot be upgraded is closing: not ready, and its
        // `detach` is about to remove it.
        let events = match core.take_ready(max_events, |member| {
            upgrade::<M>(member).map_or(0, |fd| M::poll(&fd) as u32)
        }) {
            Ok(events) => events,
            Err(error) => return error_code(error),
        };
        for delivery in events.iter().filter(|delivery| delivery.refresh_backend) {
            let Some(fd) = core.description_member(delivery.description).and_then(upgrade::<M>) else {
                continue;
            };
            let host_fd = M::host_fd(&fd);
            if host_fd >= 0 {
                let interest = core
                    .host_interest(delivery.description)
                    .expect("a delivered registration's description must be live");
                epoll
                    .backend
                    .update(host_fd, interest, delivery.description);
            }
        }
        if was_ready && !core.is_ready() {
            epoll.backend.drain_notify();
        }
        for (slot, delivery) in out.iter_mut().zip(events.iter()) {
            *slot = delivery.event;
        }
        events.len() as c_int
    }))
    .unwrap_or(EINVAL)
}
