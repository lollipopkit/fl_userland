//! Namespaces: which one of each kind a task is in.
//!
//! Linux's `struct nsproxy`, one per task and shared until one of its tasks
//! asks for a namespace of its own (`clone`, `unshare`) or joins another
//! (`setns`). It is per **thread**: a thread that unshares leaves the rest of
//! its process where they were, measured by `utsns_probe`.
//!
//! The UTS, IPC and mount kinds are built. Every other kind has one
//! namespace, the initial one, and every task is in it: [`Ns::Init`] names
//! it, so `/proc/<pid>/ns/<kind>` and `setns` on its file answer as Linux does
//! for a task that never left it.
//!
//! # What an IPC or mount namespace holds
//!
//! The System V tables, the message queue names and the mount table live in
//! the crates that own them, above this one. A [`Space`] keeps one value of
//! each such type, made on first use ([`Space::part`]). A new namespace
//! starts with each one empty, except a part registered with an `inherit`
//! function ([`Space::inherited`]): the mount table, which a new mount
//! namespace starts as a copy of. A namespace's parts go when its last
//! reference does.
//!
//! # Numbers
//!
//! The initial namespaces have Linux's numbers: the fixed ones in
//! `include/linux/proc_ns.h` and, for the network and mount namespaces, the
//! first two `proc_alloc_inum` hands out. A new namespace takes the next from
//! there, never reused, so two namespaces alive at once never share one -- the
//! number is how a program tells two apart (`readlink /proc/<pid>/ns/uts`).

use std::any::{Any, TypeId};
use std::ffi::CStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

/// A kind of namespace, in the order `/proc/<pid>/ns` lists them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Net,
    Uts,
    Ipc,
    Pid,
    User,
    Mnt,
    Cgroup,
    Time,
}

impl Kind {
    pub const ALL: [Kind; 8] = [Kind::Net, Kind::Uts, Kind::Ipc, Kind::Pid, Kind::User, Kind::Mnt, Kind::Cgroup, Kind::Time];

    /// What `/proc/<pid>/ns/<x>` reads back before the number: `uts:[...]`.
    pub fn name(self) -> &'static CStr {
        match self {
            Kind::Net => c"net",
            Kind::Uts => c"uts",
            Kind::Ipc => c"ipc",
            Kind::Pid => c"pid",
            Kind::User => c"user",
            Kind::Mnt => c"mnt",
            Kind::Cgroup => c"cgroup",
            Kind::Time => c"time",
        }
    }

    /// Its `CLONE_NEW*` flag.
    pub fn flag(self) -> u64 {
        match self {
            Kind::Net => 0x4000_0000,
            Kind::Uts => 0x0400_0000,
            Kind::Ipc => 0x0800_0000,
            Kind::Pid => 0x2000_0000,
            Kind::User => 0x1000_0000,
            Kind::Mnt => 0x0002_0000,
            Kind::Cgroup => 0x0200_0000,
            Kind::Time => 0x80,
        }
    }

    /// The initial namespace's number.
    pub fn init_inum(self) -> u32 {
        match self {
            Kind::Net => 0xF000_0000,
            Kind::Uts => 0xEFFF_FFFE,
            Kind::Ipc => 0xEFFF_FFFF,
            Kind::Pid => 0xEFFF_FFFC,
            Kind::User => 0xEFFF_FFFD,
            Kind::Mnt => 0xF000_0001,
            Kind::Cgroup => 0xEFFF_FFFB,
            Kind::Time => 0xEFFF_FFFA,
        }
    }

    /// Every kind this kernel can make a new namespace of.
    pub const BUILT: u64 = 0x0400_0000 | 0x0800_0000 | 0x0002_0000;
}

/// The next number `proc_alloc_inum` would give, after the network's and the
/// mount namespace's.
fn alloc_inum() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(0xF000_0002);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// The two names `sethostname` and `setdomainname` set. `None` is a name
/// nobody in this namespace has set: the embedder's or the host's node name,
/// and `(none)`, decided where `uname` is answered.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct UtsNames {
    pub hostname: Option<Vec<u8>>,
    pub domainname: Option<Vec<u8>>,
}

/// A UTS namespace.
#[derive(Debug)]
pub struct Uts {
    inum: u32,
    names: Mutex<UtsNames>,
}

impl Uts {
    pub fn inum(&self) -> u32 {
        self.inum
    }

    pub fn names(&self) -> UtsNames {
        self.names.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn update(&self, f: impl FnOnce(&mut UtsNames)) {
        f(&mut self.names.lock().unwrap_or_else(|e| e.into_inner()));
    }

    /// A new namespace starting with this one's names, as `copy_utsname` does.
    fn copy(&self) -> Arc<Uts> {
        Arc::new(Uts { inum: alloc_inum(), names: Mutex::new(self.names()) })
    }
}

/// What a new namespace's part starts as, given its parent's.
type InheritFn = fn(&(dyn Any + Send + Sync)) -> Arc<dyn Any + Send + Sync>;

/// One part of a [`Space`].
struct Part {
    id: TypeId,
    value: Arc<dyn Any + Send + Sync>,
    /// What a new namespace starts with; `None` is empty.
    inherit: Option<InheritFn>,
}

/// An IPC or mount namespace. See the module comment.
pub struct Space {
    inum: u32,
    parts: Mutex<Vec<Part>>,
}

/// The IPC kind's.
pub type Ipc = Space;
/// The mount kind's.
pub type Mnt = Space;

impl std::fmt::Debug for Space {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Space").field("inum", &self.inum).finish_non_exhaustive()
    }
}

/// A part a new namespace starts as a copy of: see [`Space::inherited`].
///
/// Both constructors answer an `Arc` rather than a value so that a part can
/// keep a registry of every instance (the mount table does, for halting).
pub trait Inherit: Send + Sync + 'static {
    /// An empty one, for a namespace that never had one.
    fn fresh() -> Arc<Self>;
    /// A copy of this one, for a namespace made from its own.
    fn inherit(&self) -> Arc<Self>;
}

impl Space {
    fn new(inum: u32) -> Arc<Space> {
        Arc::new(Space { inum, parts: Mutex::new(Vec::new()) })
    }

    pub fn inum(&self) -> u32 {
        self.inum
    }

    fn get<T: Send + Sync + 'static>(
        &self,
        make: impl FnOnce() -> Arc<T>,
        inherit: Option<InheritFn>,
    ) -> Arc<T> {
        let mut parts = self.parts.lock().unwrap_or_else(|e| e.into_inner());
        let id = TypeId::of::<T>();
        let any = match parts.iter().find(|p| p.id == id) {
            Some(p) => Arc::clone(&p.value),
            None => {
                let value: Arc<dyn Any + Send + Sync> = make();
                parts.push(Part { id, value: Arc::clone(&value), inherit });
                value
            }
        };
        any.downcast().expect("stored under its own TypeId")
    }

    /// This namespace's `T`, made empty the first time it is asked for. A new
    /// namespace's starts empty.
    pub fn part<T: Default + Send + Sync + 'static>(&self) -> Arc<T> {
        self.get(|| Arc::new(T::default()), None)
    }

    /// This namespace's `T`, as [`Space::part`] -- except that a namespace
    /// made from this one starts with `T::inherit` of it.
    pub fn inherited<T: Inherit>(&self) -> Arc<T> {
        fn inherit<T: Inherit>(v: &(dyn Any + Send + Sync)) -> Arc<dyn Any + Send + Sync> {
            v.downcast_ref::<T>().expect("stored under its own TypeId").inherit()
        }
        self.get(T::fresh, Some(inherit::<T>))
    }

    /// A new namespace of this kind: the inherited parts copied, the rest
    /// left to be made empty.
    fn fork(&self) -> Arc<Space> {
        // The copies are made outside this lock: a part's `inherit` takes
        // the part's own lock, and nothing should be under two.
        let carried: Vec<_> = {
            let parts = self.parts.lock().unwrap_or_else(|e| e.into_inner());
            parts.iter().filter_map(|p| Some((p.id, Arc::clone(&p.value), p.inherit?))).collect()
        };
        let parts = carried
            .into_iter()
            .map(|(id, value, inherit)| Part { id, value: inherit(&*value), inherit: Some(inherit) })
            .collect();
        Arc::new(Space { inum: alloc_inum(), parts: Mutex::new(parts) })
    }
}

/// One namespace: what a namespace descriptor holds, and keeps alive.
#[derive(Clone, Debug)]
pub enum Ns {
    Uts(Arc<Uts>),
    Ipc(Arc<Ipc>),
    Mnt(Arc<Mnt>),
    /// The initial namespace of a kind this kernel has only that one of.
    Init(Kind),
}

impl Ns {
    pub fn kind(&self) -> Kind {
        match self {
            Ns::Uts(_) => Kind::Uts,
            Ns::Ipc(_) => Kind::Ipc,
            Ns::Mnt(_) => Kind::Mnt,
            Ns::Init(k) => *k,
        }
    }

    pub fn inum(&self) -> u32 {
        match self {
            Ns::Uts(u) => u.inum,
            Ns::Ipc(i) => i.inum,
            Ns::Mnt(m) => m.inum,
            Ns::Init(k) => k.init_inum(),
        }
    }
}

/// The namespaces a task is in.
#[derive(Clone, Debug)]
pub struct NsProxy {
    pub uts: Arc<Uts>,
    pub ipc: Arc<Ipc>,
    pub mnt: Arc<Mnt>,
}

static INITIAL: LazyLock<Arc<NsProxy>> = LazyLock::new(|| {
    Arc::new(NsProxy {
        uts: Arc::new(Uts { inum: Kind::Uts.init_inum(), names: Mutex::new(UtsNames::default()) }),
        ipc: Space::new(Kind::Ipc.init_inum()),
        mnt: Space::new(Kind::Mnt.init_inum()),
    })
});

impl NsProxy {
    /// The first process's.
    pub fn initial() -> Arc<NsProxy> {
        Arc::clone(&INITIAL)
    }

    pub fn get(&self, kind: Kind) -> Ns {
        match kind {
            Kind::Uts => Ns::Uts(Arc::clone(&self.uts)),
            Kind::Ipc => Ns::Ipc(Arc::clone(&self.ipc)),
            Kind::Mnt => Ns::Mnt(Arc::clone(&self.mnt)),
            k => Ns::Init(k),
        }
    }

    /// With a new namespace of each kind in `flags` (`CLONE_NEW*`), copied
    /// from this one's; the same proxy when there are none. Flags of a kind
    /// not in [`Kind::BUILT`] are the caller's to have refused.
    pub fn unshare(self: &Arc<Self>, flags: u64) -> Arc<NsProxy> {
        if flags & Kind::BUILT == 0 {
            return Arc::clone(self);
        }
        let mut new = NsProxy::clone(self);
        if flags & Kind::Uts.flag() != 0 {
            new.uts = self.uts.copy();
        }
        // A new IPC namespace starts empty; a mount namespace with a copy
        // of the mount table.
        if flags & Kind::Ipc.flag() != 0 {
            new.ipc = self.ipc.fork();
        }
        if flags & Kind::Mnt.flag() != 0 {
            new.mnt = self.mnt.fork();
        }
        Arc::new(new)
    }

    /// With `ns` in place of this one's namespace of its kind.
    pub fn with(&self, ns: &Ns) -> Arc<NsProxy> {
        let mut new = self.clone();
        match ns {
            Ns::Uts(u) => new.uts = Arc::clone(u),
            Ns::Ipc(i) => new.ipc = Arc::clone(i),
            Ns::Mnt(m) => new.mnt = Arc::clone(m),
            Ns::Init(_) => {}
        }
        Arc::new(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsharing_copies_the_names_and_keeps_them_apart() {
        let a = NsProxy::initial().unshare(Kind::Uts.flag());
        a.uts.update(|n| n.hostname = Some(b"a".to_vec()));
        let b = a.unshare(Kind::Uts.flag());
        assert_eq!(b.uts.names().hostname.as_deref(), Some(&b"a"[..]));
        assert_ne!(a.uts.inum(), b.uts.inum());
        b.uts.update(|n| n.hostname = Some(b"b".to_vec()));
        assert_eq!(a.uts.names().hostname.as_deref(), Some(&b"a"[..]));
    }

    #[test]
    fn no_built_flag_is_the_same_proxy() {
        let p = NsProxy::initial();
        assert!(Arc::ptr_eq(&p, &p.unshare(Kind::Net.flag())));
    }

    struct Copied(Mutex<Vec<u8>>);

    impl Inherit for Copied {
        fn fresh() -> Arc<Copied> {
            Arc::new(Copied(Mutex::new(Vec::new())))
        }
        fn inherit(&self) -> Arc<Copied> {
            Arc::new(Copied(Mutex::new(self.0.lock().unwrap().clone())))
        }
    }

    #[test]
    fn an_inherited_part_starts_as_a_copy() {
        let a = NsProxy::initial().unshare(Kind::Mnt.flag());
        a.mnt.inherited::<Copied>().0.lock().unwrap().push(7);
        a.mnt.part::<Mutex<Vec<u8>>>().lock().unwrap().push(1);
        let b = a.unshare(Kind::Mnt.flag());
        assert_eq!(*b.mnt.inherited::<Copied>().0.lock().unwrap(), [7]);
        assert!(b.mnt.part::<Mutex<Vec<u8>>>().lock().unwrap().is_empty(), "an uninherited part starts empty");
        b.mnt.inherited::<Copied>().0.lock().unwrap().push(8);
        assert_eq!(*a.mnt.inherited::<Copied>().0.lock().unwrap(), [7], "a copy, not a share");
    }

    #[test]
    fn a_new_ipc_namespace_starts_empty() {
        let a = NsProxy::initial().unshare(Kind::Ipc.flag());
        a.ipc.part::<Mutex<Vec<u8>>>().lock().unwrap().push(1);
        assert_eq!(a.ipc.part::<Mutex<Vec<u8>>>().lock().unwrap().len(), 1, "one value per type");
        let b = a.unshare(Kind::Ipc.flag());
        assert!(b.ipc.part::<Mutex<Vec<u8>>>().lock().unwrap().is_empty());
        assert_ne!(a.ipc.inum(), b.ipc.inum());
        assert!(Arc::ptr_eq(&a.uts, &b.uts), "the other kinds are shared");
    }

    #[test]
    fn joining_replaces_only_that_kind() {
        let a = NsProxy::initial().unshare(Kind::Uts.flag());
        let back = a.with(&NsProxy::initial().get(Kind::Uts));
        assert_eq!(back.uts.inum(), Kind::Uts.init_inum());
    }
}
