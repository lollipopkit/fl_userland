//! Registration state and ready-queue bookkeeping for one epoll instance.

use super::*;
use std::collections::{HashMap, TryReserveError};

/// The member a registration names, as its address.
///
/// **A `usize` until 2026-09-16**, which is the "integer as a handle" shape:
/// `epoll_add` took a `*mut M::Member` and stored `fd as usize`, and the three
/// [`Members`] methods took that integer back and cast it to a pointer — a
/// conversion the compiler cannot check, in both directions, at nine sites.
///
/// An identity only since 2026-10-17: a `HashMap` key and a node of the
/// nesting graph, never turned back into the member. Reaching the member is
/// [`Description::member`]'s `Weak`. Built only from a reference, so a key
/// cannot be made out of an arbitrary integer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DescriptionKey(usize);

impl DescriptionKey {
    /// The address of a member.
    pub fn of<T>(member: &T) -> DescriptionKey {
        DescriptionKey(std::ptr::from_ref(member).addr())
    }
}

/// A member, as the core holds it: weakly, and with its type erased because
/// [`Core`] is not generic over [`Members`]. `epoll_take_ready` upgrades and
/// downcasts it back to `M::Member`.
pub(crate) type MemberRef = std::sync::Weak<dyn std::any::Any + Send + Sync>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct DescriptionId {
    pub slot: u32,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct RegistrationId {
    pub slot: u32,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Event {
    pub events: u32,
    pub _pad: u32,
    pub data: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Delivery {
    pub(crate) event: Event,
    pub(crate) description: DescriptionId,
    pub(crate) refresh_backend: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostInterest {
    pub events: u32,
    pub edge: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Exists,
    Invalid,
    Missing,
    Loop,
    OutOfMemory,
}

impl From<TryReserveError> for Error {
    fn from(_: TryReserveError) -> Self {
        Error::OutOfMemory
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddResult {
    pub description: DescriptionId,
    pub new_description: bool,
}

struct Description {
    key: DescriptionKey,
    /// The member itself, for the readiness and backend questions a wait asks.
    ///
    /// Weak, because a registration does not keep a file open, and that is
    /// what makes the borrow sound. It was the key turned back into a `&fd`
    /// under an `unsafe trait Members` whose contract was "a registered key
    /// names a live member": the registration is removed by the description's
    /// finalizer, which already holds the `&mut fd` `Drop` made while a wait
    /// on another thread could still be inside `poll` with a `&fd` of it. An
    /// upgrade fails from the moment the strong count reaches zero, so a
    /// closing member is not ready, and its `detach` removes it.
    member: MemberRef,
    /// The member's reverse-edge list. Held so that this epoll can take its own
    /// entry out without going through `struct fd` — which is what the old
    /// `fd_try_retain` retry loop was for.
    watchers: Arc<Watchers>,
    registrations: Option<RegistrationId>,
    is_socket: bool,
    graph_target: Option<GraphNode>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RegistrationState {
    events: u32,
    data: u64,
    triggered: u32,
    oneshot_fired: bool,
}

#[derive(Debug)]
struct Registration {
    description: DescriptionId,
    fd_number: i32,
    state: RegistrationState,
    description_prev: Option<RegistrationId>,
    description_next: Option<RegistrationId>,
    ready_prev: Option<RegistrationId>,
    ready_next: Option<RegistrationId>,
    queued: bool,
}

#[derive(Default)]
pub struct Core {
    descriptions: Arena<Description>,
    registrations: Arena<Registration>,
    description_by_key: HashMap<DescriptionKey, DescriptionId>,
    registration_by_pair: HashMap<(DescriptionKey, i32), RegistrationId>,
    ready_head: Option<RegistrationId>,
    ready_tail: Option<RegistrationId>,
    ready_count: usize,
    socket_descriptions: usize,
}

impl Core {
    pub(crate) fn watcher_lists(&self) -> impl Iterator<Item = &Arc<Watchers>> {
        self.descriptions
            .iter()
            .map(|description| &description.watchers)
    }

    pub(crate) fn description_member(&self, description: DescriptionId) -> Option<&MemberRef> {
        self.descriptions
            .get(description)
            .map(|description| &description.member)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert(
        &mut self,
        key: DescriptionKey,
        member: MemberRef,
        watchers: &Arc<Watchers>,
        fd_number: i32,
        events: u32,
        data: u64,
        is_socket: bool,
        graph_target: Option<GraphNode>,
    ) -> Result<AddResult, Error> {
        if self.registration_by_pair.contains_key(&(key, fd_number)) {
            return Err(Error::Exists);
        }

        let existing_description = self.description_by_key.get(&key).copied();
        self.registration_by_pair.try_reserve(1)?;
        self.registrations.reserve_slot()?;
        if existing_description.is_none() {
            self.description_by_key.try_reserve(1)?;
            self.descriptions.reserve_slot()?;
        }

        let description = match existing_description {
            Some(id) => id,
            None => {
                let id = self.descriptions.insert_reserved(Description {
                    key,
                    member,
                    watchers: Arc::clone(watchers),
                    registrations: None,
                    is_socket,
                    graph_target,
                });
                self.description_by_key.insert(key, id);
                if is_socket {
                    self.socket_descriptions += 1;
                }
                id
            }
        };
        let old_head = self
            .descriptions
            .get(description)
            .expect("a keyed description must be live")
            .registrations;
        let registration = self.registrations.insert_reserved(Registration {
            description,
            fd_number,
            state: RegistrationState {
                events,
                data,
                triggered: 0,
                oneshot_fired: false,
            },
            description_prev: None,
            description_next: old_head,
            ready_prev: None,
            ready_next: None,
            queued: false,
        });
        if let Some(old_head) = old_head {
            self.registrations
                .get_mut(old_head)
                .expect("the description list must contain live registrations")
                .description_prev = Some(registration);
        }
        self.descriptions
            .get_mut(description)
            .expect("the new description must be live")
            .registrations = Some(registration);
        self.registration_by_pair
            .insert((key, fd_number), registration);

        Ok(AddResult {
            description,
            new_description: existing_description.is_none(),
        })
    }

    pub(crate) fn restore_registration(&mut self, id: RegistrationId, state: RegistrationState) {
        let registration = self
            .registrations
            .get_mut(id)
            .expect("the restored registration must be live");
        registration.state = state;
    }

    pub(crate) fn modify(
        &mut self,
        key: DescriptionKey,
        fd_number: i32,
        events: u32,
        data: u64,
    ) -> Result<(RegistrationId, DescriptionId, RegistrationState), Error> {
        let id = self
            .registration_by_pair
            .get(&(key, fd_number))
            .copied()
            .ok_or(Error::Missing)?;
        let registration = self
            .registrations
            .get_mut(id)
            .expect("the pair index must contain a live registration");
        let old = registration.state;
        let description = registration.description;
        registration.state.events = events;
        registration.state.data = data;
        registration.state.triggered &= events & !CONTROL;
        registration.state.oneshot_fired = false;
        Ok((id, description, old))
    }

    pub(crate) fn remove(
        &mut self,
        key: DescriptionKey,
        fd_number: i32,
    ) -> Result<(DescriptionId, Option<GraphNode>), Error> {
        let id = self
            .registration_by_pair
            .remove(&(key, fd_number))
            .ok_or(Error::Missing)?;
        let description = self
            .registrations
            .get(id)
            .expect("the pair index must contain a live registration")
            .description;
        let graph_target = self
            .descriptions
            .get(description)
            .expect("the registration's description must be live")
            .graph_target;
        self.unlink_ready(id);
        let registration = self
            .registrations
            .remove(id)
            .expect("the pair index must contain a live registration");

        if let Some(previous) = registration.description_prev {
            self.registrations
                .get_mut(previous)
                .expect("the previous description link must be live")
                .description_next = registration.description_next;
        } else {
            self.descriptions
                .get_mut(description)
                .expect("the registration's description must be live")
                .registrations = registration.description_next;
        }
        if let Some(next) = registration.description_next {
            self.registrations
                .get_mut(next)
                .expect("the next description link must be live")
                .description_prev = registration.description_prev;
        }

        let mut removed_target = None;
        if self
            .descriptions
            .get(description)
            .expect("the registration's description must be live")
            .registrations
            .is_none()
        {
            let removed = self
                .descriptions
                .remove(description)
                .expect("the empty description must be live");
            self.description_by_key.remove(&removed.key);
            if removed.is_socket {
                self.socket_descriptions -= 1;
            }
            removed_target = removed.graph_target;
        }
        Ok((description, graph_target.or(removed_target)))
    }

    pub(crate) fn remove_description(
        &mut self,
        description: DescriptionId,
    ) -> Option<(GraphNode, usize)> {
        let mut next = self
            .descriptions
            .get(description)
            .map(|description| description.registrations)?;
        let mut removed = None;
        let mut count = 0;
        while let Some(id) = next {
            let registration = self
                .registrations
                .get(id)
                .expect("the description list must contain live registrations");
            next = registration.description_next;
            let key = self
                .descriptions
                .get(description)
                .expect("the description must stay live during removal")
                .key;
            let (_, target) = self
                .remove(key, registration.fd_number)
                .expect("a listed registration must be indexed");
            count += 1;
            if target.is_some() {
                removed = target;
            }
        }
        removed.map(|target| (target, count))
    }

    pub fn has_socket(&self) -> bool {
        self.socket_descriptions != 0
    }

    pub fn registration_for_pair(
        &self,
        key: DescriptionKey,
        fd_number: i32,
    ) -> Option<RegistrationId> {
        self.registration_by_pair.get(&(key, fd_number)).copied()
    }

    pub fn host_interest(&self, description: DescriptionId) -> Option<HostInterest> {
        let description = self.descriptions.get(description)?;
        let mut next = description.registrations;
        let mut interest = HostInterest {
            events: 0,
            edge: false,
        };
        let mut any = false;
        while let Some(id) = next {
            let registration = self
                .registrations
                .get(id)
                .expect("the description list must contain live registrations");
            next = registration.description_next;
            if registration.state.oneshot_fired {
                continue;
            }
            any = true;
            interest.events |= registration.state.events & !CONTROL;
            interest.edge |= registration.state.events & EDGE != 0;
        }
        if !any {
            // Every registration for this description is an already-fired
            // ONESHOT. Remove the host watch until MOD rearms one.
            return Some(HostInterest::default());
        }
        // EPOLLERR and EPOLLHUP are always reported even when the caller did
        // not request them. Keep a host watch with the read/write filters that
        // can expose EOF or error transitions even for events=0.
        interest.events |= ERR | HUP;
        Some(interest)
    }

    pub fn queue_registration(&mut self, registration: RegistrationId) -> bool {
        let Some(entry) = self.registrations.get(registration) else {
            return false;
        };
        if entry.queued || entry.state.oneshot_fired {
            return false;
        }
        let old_tail = self.ready_tail;
        let entry = self
            .registrations
            .get_mut(registration)
            .expect("the registration was just checked");
        entry.ready_prev = old_tail;
        entry.ready_next = None;
        entry.queued = true;
        if let Some(old_tail) = old_tail {
            self.registrations
                .get_mut(old_tail)
                .expect("the ready tail must be live")
                .ready_next = Some(registration);
        } else {
            self.ready_head = Some(registration);
        }
        self.ready_tail = Some(registration);
        self.ready_count += 1;
        true
    }

    pub fn notify(&mut self, description: DescriptionId, events: u32) -> bool {
        let was_empty = self.ready_head.is_none();
        let Some(mut next) = self
            .descriptions
            .get(description)
            .map(|description| description.registrations)
        else {
            return false;
        };
        while let Some(id) = next {
            let registration = self
                .registrations
                .get_mut(id)
                .expect("the description list must contain live registrations");
            next = registration.description_next;
            registration.state.triggered &= !events;
            if !registration.state.oneshot_fired
                && events & ((registration.state.events & !CONTROL) | HUP | ERR) != 0
            {
                self.queue_registration(id);
            }
        }
        was_empty && self.ready_head.is_some()
    }

    pub(crate) fn take_ready<F>(
        &mut self,
        max_events: usize,
        mut readiness: F,
    ) -> Result<Vec<Delivery>, Error>
    where
        F: FnMut(&MemberRef) -> u32,
    {
        let mut events = Vec::new();
        // A level-triggered registration is put back at the tail. Only inspect
        // entries that were queued on entry so one registration is never
        // returned twice by one wait call.
        let mut remaining = self.ready_len();
        events.try_reserve(max_events.min(remaining))?;
        while remaining > 0 && events.len() < max_events {
            remaining -= 1;
            let Some(id) = self.ready_head else {
                break;
            };
            self.unlink_ready(id);
            let Some(registration) = self.registrations.get(id) else {
                continue;
            };
            if registration.state.oneshot_fired {
                continue;
            }
            let description = registration.description;
            let member = &self
                .descriptions
                .get(description)
                .expect("a registration's description must be live")
                .member;
            let wanted = (registration.state.events & !CONTROL) | HUP | ERR;
            let mut ready = readiness(member) & wanted;
            if registration.state.events & EDGE != 0 {
                ready &= !registration.state.triggered;
            }
            if ready == 0 {
                continue;
            }

            let registration = self
                .registrations
                .get_mut(id)
                .expect("the registration stayed live during synchronous readiness");
            let refresh_backend = registration.state.events & ONESHOT != 0;
            events.push(Delivery {
                event: Event {
                    events: ready,
                    _pad: 0,
                    data: registration.state.data,
                },
                description,
                refresh_backend,
            });
            if registration.state.events & ONESHOT != 0 {
                registration.state.oneshot_fired = true;
            } else if registration.state.events & EDGE != 0 {
                registration.state.triggered |= ready;
            } else {
                self.queue_registration(id);
            }
        }
        Ok(events)
    }

    pub fn is_ready(&self) -> bool {
        self.ready_head.is_some()
    }

    /// Every registration, by descriptor number, with the member it names:
    /// `(fd, events, data, member)`. `events` is what Linux's item holds and
    /// `/proc/<pid>/fdinfo` prints -- `EPOLLERR | EPOLLHUP` added, as
    /// `epoll_ctl` adds them, and only the control bits left once a
    /// `EPOLLONESHOT` registration has delivered (`EP_PRIVATE_BITS`).
    ///
    /// The members are `Weak`s, upgraded by the caller after the core's lock
    /// is released: dropping the last reference to one runs its close, which
    /// takes this lock to detach it.
    pub(crate) fn listing(&self) -> Vec<(i32, u32, u64, MemberRef)> {
        let mut out: Vec<_> = self
            .registrations
            .iter()
            .filter_map(|r| {
                let member = self.description_member(r.description)?.clone();
                let events = if r.state.oneshot_fired {
                    r.state.events & CONTROL
                } else {
                    r.state.events | ERR | HUP
                };
                Some((r.fd_number, events, r.state.data, member))
            })
            .collect();
        out.sort_by_key(|&(fd, ..)| fd);
        out
    }

    pub fn registrations_len(&self) -> usize {
        self.registrations.live_len()
    }

    fn ready_len(&self) -> usize {
        self.ready_count
    }

    fn unlink_ready(&mut self, id: RegistrationId) {
        let Some(registration) = self.registrations.get(id) else {
            return;
        };
        if !registration.queued {
            return;
        }
        let previous = registration.ready_prev;
        let next = registration.ready_next;
        if let Some(previous) = previous {
            self.registrations
                .get_mut(previous)
                .expect("the previous ready link must be live")
                .ready_next = next;
        } else {
            self.ready_head = next;
        }
        if let Some(next) = next {
            self.registrations
                .get_mut(next)
                .expect("the next ready link must be live")
                .ready_prev = previous;
        } else {
            self.ready_tail = previous;
        }
        let registration = self
            .registrations
            .get_mut(id)
            .expect("the unlinked registration must be live");
        registration.ready_prev = None;
        registration.ready_next = None;
        registration.queued = false;
        self.ready_count -= 1;
    }
}
