//! Rust-owned state for an epoll open file description.
//!
//! The C descriptor layer still owns `struct fd` and the guest-aware blocking
//! protocol. This crate owns everything whose invariants are local to epoll:
//! registration identity, description sharing, stable host tokens, the ready
//! queue, and edge/oneshot delivery state.
//!
//! # Lock order
//!
//! `GRAPH`, then a member's `Watchers` list, then the epoll's own [`Core`]. A path
//! that has to go the other way — an epoll being dropped, or a description
//! closing — collects what it needs under the inner lock, releases it, and then
//! takes the outer one; there is no path that holds two of these in the wrong
//! order.
//!
//! Code holding the epoll mutex may ask a member for its current readiness,
//! which can acquire that object's own lock. Readiness producers must therefore
//! call `poll_wakeup` only after releasing that lock — the rule is stated on
//! `poll_wakeup` in `fs/poll.h` and is what keeps `member lock -> Core` and
//! `Core -> member lock` from meeting.

#[cfg(test)]
use kernel_errno::guest::{EINVAL, ELOOP};
use libc::c_int;
use pollset::Watchers;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

mod backend;
use backend::Backend;
mod arena;
use arena::Arena;
mod core;
pub use core::{
    AddResult, Core, DescriptionId, DescriptionKey, Error, Event, HostInterest, RegistrationId,
};
mod graph;
#[cfg(test)]
mod tests;
use graph::{FileId, GRAPH, Graph, GraphNode, SetId, graph_remove_node};

mod api;
pub use api::{
    Listed, epoll_add, epoll_backend_fd, epoll_delete, epoll_has_socket, epoll_is_ready,
    epoll_listing, epoll_live_count, epoll_modify, epoll_probe_ready, epoll_state_new,
    epoll_take_ready,
};

pub const READ: u32 = 1;
pub const PRI: u32 = 2;
pub const WRITE: u32 = 4;
pub const ERR: u32 = 8;
pub const HUP: u32 = 16;
pub const NVAL: u32 = 32;
pub const RDNORM: u32 = 1 << 6;
pub const WRNORM: u32 = 1 << 8;
pub const RDHUP: u32 = 1 << 13;
pub const EXCLUSIVE: u32 = 1 << 28;
pub const WAKEUP: u32 = 1 << 29;
pub const ONESHOT: u32 = 1 << 30;
pub const EDGE: u32 = 1 << 31;

const CONTROL: u32 = EXCLUSIVE | WAKEUP | ONESHOT | EDGE;

/// What epoll asks a member descriptor.
///
/// A trait since 2026-09-09, the way `pollset::Members` is and for the same
/// reasons. It was a struct of three `Option<unsafe fn>` before that, and
/// **it had five fields until 2026-09-04**: `wake` and `gone` were declared
/// here and read nowhere, while `kernel/epoll.h` — the C declaration
/// `crates/fs/poll` built its table from — had the three. So the caller passed
/// a 24-byte static and this read a 40-byte struct. Nothing dereferenced the
/// two extra fields, which is the only reason it was harmless. A trait cannot
/// have that defect at all: there is no layout for two renderings to disagree
/// about.
///
/// Safe since 2026-10-17. It was an `unsafe trait` whose contract was that a
/// registered key names a live member; the core keeps a `Weak` of the member
/// now (see `Description::member`), so a wait reaches only one it could
/// upgrade.
pub trait Members {
    /// What a member is.
    ///
    /// The three methods below take one **by reference**. They took a `usize`
    /// until 2026-09-16 and each implementation cast it back to a pointer,
    /// which is what made this associated type documentation rather than a
    /// type: it named the thing the key pointed at and nothing checked that
    /// the cast agreed with it. [`crate::DescriptionKey`] is the address, an
    /// identity only; the core reaches a member through its `Weak`.
    type Member: Send + Sync + 'static;
    /// The descriptor's own readiness, in guest `POLL_*` terms.
    fn poll(member: &Self::Member) -> c_int;
    /// A host descriptor that answers for this one, or -1.
    fn host_fd(member: &Self::Member) -> c_int;
    fn is_socket(member: &Self::Member) -> bool;
}

impl pollset::Watcher for Epoll {
    /// A member became ready. `key` is the description id, packed: this is the
    /// same slot/generation pair the core uses, and a stale one names a
    /// registration that is gone and is simply not found.
    fn notify(&self, key: u64, events: u32) {
        if lock_core(self).notify(unpack(key), events) {
            self.backend.wake();
        }
    }

    /// A member's description is closing.
    fn detach(&self, key: u64) {
        let mut graph = GRAPH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut core = lock_core(self);
        let was_ready = core.is_ready();
        if let Some((target, count)) = core.remove_description(unpack(key)) {
            graph
                .get_or_insert_with(Graph::default)
                .remove(SetId::of(self), target, count);
        }
        if was_ready && !core.is_ready() {
            self.backend.drain_notify();
        }
    }
}

fn pack(id: DescriptionId) -> u64 {
    ((id.slot as u64) << 32) | id.generation as u64
}

fn unpack(key: u64) -> DescriptionId {
    DescriptionId {
        slot: (key >> 32) as u32,
        generation: key as u32,
    }
}

pub struct Epoll {
    core: Mutex<Core>,
    backend: Backend,
    /// `EPIOCSPARAMS`' three values, packed by [`BusyPoll::pack`]. An atomic
    /// rather than a field of `Core`: nothing else reads them, and a set and a
    /// get race only with each other.
    busy_poll: std::sync::atomic::AtomicU64,
}

/// A set's busy-poll parameters (`struct epoll_params`, Linux 6.9).
///
/// **Stored and reported, and nothing more.** Busy polling spins on a NAPI
/// queue of a network device before sleeping; this kernel's sockets are the
/// host's and it has no device queue to spin on, so the values change nothing
/// about a wait. Keeping them means a program that sets them reads back what
/// it set, which is what a kernel whose devices do not support busy polling
/// answers too: Linux stores them per set whatever the members are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BusyPoll {
    pub usecs: u32,
    pub budget: u16,
    pub prefer: bool,
}

impl BusyPoll {
    fn pack(self) -> u64 {
        u64::from(self.usecs) | u64::from(self.budget) << 32 | u64::from(self.prefer) << 48
    }

    fn unpack(v: u64) -> BusyPoll {
        BusyPoll {
            usecs: v as u32,
            budget: (v >> 32) as u16,
            prefer: (v >> 48) & 1 != 0,
        }
    }
}

impl Epoll {
    pub fn busy_poll(&self) -> BusyPoll {
        BusyPoll::unpack(self.busy_poll.load(Ordering::Relaxed))
    }

    pub fn set_busy_poll(&self, params: BusyPoll) {
        self.busy_poll.store(params.pack(), Ordering::Relaxed);
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::Relaxed);
        // Every member this set was still watching loses its entry. The lists
        // are collected under the core lock and touched after it is released,
        // because the other direction — a wakeup — takes them the other way
        // round.
        let lists: Vec<Arc<Watchers>> = self
            .core
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .watcher_lists()
            .map(Arc::clone)
            .collect();
        // `self` is mid-drop, so no `Weak` naming it can upgrade any more; the
        // entries are already inert and this is what reclaims them. A list is
        // asked to drop dead entries rather than this one specifically,
        // because there is no `Arc` left to name it with.
        for list in lists {
            list.drop_dead_watchers();
        }
        graph_remove_node(self);
    }
}

static LIVE: AtomicI64 = AtomicI64::new(0);

fn lock_core(epoll: &Epoll) -> MutexGuard<'_, Core> {
    epoll
        .core
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
