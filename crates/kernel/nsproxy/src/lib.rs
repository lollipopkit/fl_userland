//! Namespaces: which one of each kind a task is in.
//!
//! Linux's `struct nsproxy`, one per task and shared until one of its tasks
//! asks for a namespace of its own (`clone`, `unshare`) or joins another
//! (`setns`). It is per **thread**: a thread that unshares leaves the rest of
//! its process where they were, measured by `utsns_probe`.
//!
//! Only the UTS namespace is built. Every other kind has one namespace, the
//! initial one, and every task is in it: [`Ns::Init`] names it, so
//! `/proc/<pid>/ns/<kind>` and `setns` on its file answer as Linux does for a
//! task that never left it.
//!
//! # Numbers
//!
//! The initial namespaces have Linux's numbers: the fixed ones in
//! `include/linux/proc_ns.h` and, for the network and mount namespaces, the
//! first two `proc_alloc_inum` hands out. A new namespace takes the next from
//! there, never reused, so two namespaces alive at once never share one -- the
//! number is how a program tells two apart (`readlink /proc/<pid>/ns/uts`).

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
    pub const BUILT: u64 = 0x0400_0000;
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

/// One namespace: what a namespace descriptor holds, and keeps alive.
#[derive(Clone, Debug)]
pub enum Ns {
    Uts(Arc<Uts>),
    /// The initial namespace of a kind this kernel has only that one of.
    Init(Kind),
}

impl Ns {
    pub fn kind(&self) -> Kind {
        match self {
            Ns::Uts(_) => Kind::Uts,
            Ns::Init(k) => *k,
        }
    }

    pub fn inum(&self) -> u32 {
        match self {
            Ns::Uts(u) => u.inum,
            Ns::Init(k) => k.init_inum(),
        }
    }
}

/// The namespaces a task is in.
#[derive(Clone, Debug)]
pub struct NsProxy {
    pub uts: Arc<Uts>,
}

static INITIAL: LazyLock<Arc<NsProxy>> = LazyLock::new(|| {
    Arc::new(NsProxy {
        uts: Arc::new(Uts { inum: Kind::Uts.init_inum(), names: Mutex::new(UtsNames::default()) }),
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
        Arc::new(new)
    }

    /// With `ns` in place of this one's namespace of its kind.
    pub fn with(&self, ns: &Ns) -> Arc<NsProxy> {
        let mut new = self.clone();
        if let Ns::Uts(u) = ns {
            new.uts = Arc::clone(u);
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
        assert!(Arc::ptr_eq(&p, &p.unshare(Kind::Ipc.flag())));
    }

    #[test]
    fn joining_replaces_only_that_kind() {
        let a = NsProxy::initial().unshare(Kind::Uts.flag());
        let back = a.with(&NsProxy::initial().get(Kind::Uts));
        assert_eq!(back.uts.inum(), Kind::Uts.init_inum());
    }
}
