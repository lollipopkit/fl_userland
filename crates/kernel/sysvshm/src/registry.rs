//! Shared-memory segment registry and mapping lifecycle state.

use super::*;

pub(super) struct Segment {
    pub(super) key: i32,
    pub(super) perm: Perm,
    pub(super) seq: u16,
    pub(super) size: u64,
    pub(super) pages: u64,
    /// The memfd behind the segment: the registry's one reference, **owned**.
    ///
    /// A `usize` until 2026-09-16, with a comment calling it an "opaque memfd
    /// identity" — it was not opaque, it was a `*mut ffi::fd` laundered through
    /// an integer and converted back with
    /// `&*(seg.fd as *mut taskview::ffi::fd)` at five sites. "The registry's
    /// one reference" was a protocol three `memfdcalls::release` calls had to
    /// keep, each of them deliberately *outside* the registry lock because the
    /// release can re-enter through [`segment_unmapped`].
    ///
    /// [`fs_fdobj::Owned`] is that protocol: dropping the `Segment` is the
    /// release, and the ordering requirement survives because a `Segment`
    /// taken out of the registry with `remove` is dropped where it lands.
    pub(super) fd: fs_fdobj::Owned,
    pub(super) cpid: i32,
    pub(super) lpid: i32,
    pub(super) atime: i64,
    pub(super) dtime: i64,
    pub(super) ctime: i64,
    /// `IPC_RMID` while attached: destroyed when the last attach goes.
    pub(super) marked: bool,
}

#[derive(Default)]
pub(super) struct Registry {
    pub(super) slots: Vec<Option<Segment>>,
    pub(super) by_key: HashMap<i32, usize>,
    pub(super) seq: u16,
    pub(super) total_pages: u64,
}

pub(super) static REGISTRY: std::sync::LazyLock<Mutex<Registry>> =
    std::sync::LazyLock::new(|| Mutex::new(Registry::default()));

impl Registry {
    pub(super) fn lookup(&self, id: i32) -> Option<usize> {
        index_of(id, |i| {
            self.slots.get(i).and_then(|s| s.as_ref()).map(|s| s.seq)
        })
    }

    /// Which slot holds the segment backed by `fd`, if any.
    ///
    /// Compared by address: a memfd belongs to exactly one segment, and the
    /// registry's reference keeps it alive, so two live segments cannot share
    /// one.
    pub(super) fn by_fd(&self, fd: &taskview::ffi::fd) -> Option<usize> {
        self.slots.iter().position(|s| {
            s.as_ref()
                .is_some_and(|s| std::ptr::eq(s.fd.as_ptr(), std::ptr::from_ref(fd).cast_mut()))
        })
    }

    pub(super) fn used(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub(super) fn max_index(&self) -> usize {
        self.slots.iter().rposition(|s| s.is_some()).unwrap_or(0)
    }

    /// Take the segment out. Its file is released by the caller, outside
    /// the lock.
    pub(super) fn remove(&mut self, index: usize) -> Option<Segment> {
        let seg = self.slots[index].take()?;
        if seg.key != ipc::PRIVATE {
            self.by_key.remove(&seg.key);
        }
        self.total_pages -= seg.pages;
        Some(seg)
    }
}

pub(super) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The caller's ids and the three capabilities the rules ask, owned so the
/// credentials are not borrowed across the registry's lock.
pub(super) struct Me {
    euid: u32,
    egid: u32,
    groups: Vec<u32>,
    caps: [bool; 3],
}

impl Me {
    pub(super) fn who(&self) -> Who<'_> {
        Who {
            euid: self.euid,
            egid: self.egid,
            groups: &self.groups,
            ipc_owner: self.caps[0],
            sys_admin: self.caps[1],
            ipc_lock: self.caps[2],
        }
    }
}

pub(super) fn who_am_i() -> Me {
    use taskview::caps::{CAP_IPC_LOCK, CAP_IPC_OWNER, CAP_SYS_ADMIN};
    taskview::with_current_creds(|c| Me {
        euid: c.euid(),
        egid: c.egid(),
        groups: c.groups().as_slice().to_vec(),
        caps: [c.capable(CAP_IPC_OWNER), c.capable(CAP_SYS_ADMIN), c.capable(CAP_IPC_LOCK)],
    })
    .unwrap_or(Me { euid: 0, egid: 0, groups: Vec::new(), caps: [false; 3] })
}

pub(super) fn tgid() -> i32 {
    taskview::current_tgid()
}

/// The memfd's notification: a shared mapping of `fd` has gone. If the
/// segment was marked and nothing is attached any more, it goes too.
pub(super) fn segment_unmapped(fd: &taskview::ffi::fd) {
    let gone = {
        let mut r = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        match r.by_fd(fd) {
            Some(i)
                if r.slots[i].as_ref().is_some_and(|s| s.marked)
                    && memfdcalls::shared_mappings(fd) == Some(0) =>
            {
                r.remove(i)
            }
            _ => None,
        }
    };
    // **Dropped here, with the registry lock released.** That is what the
    // hand-written `memfdcalls::release` on this line was, and the ordering is
    // the reason it was ever on its own line: the release reaches
    // `memfdcalls`' unmap notification, which calls back into this function.
    drop(gone);
}
