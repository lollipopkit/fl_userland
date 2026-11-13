//! The controlling terminal a thread group holds, and the reference it holds
//! it by.
//!
//! One field of `struct tgroup` — `struct tty *tty` — with the lock over it.
//! What the terminal *is* has been `crates/fs/tty` since the terminal moved;
//! this is the edge from the process side to it, which is the last thing
//! `tgroup->lock` was guarding for the terminal.
//!
//! # The reference is the point
//!
//! A group that has a controlling terminal holds a reference to it, taken when
//! it claims one and given back when it leaves the session or exits. A `fork`
//! inherits the terminal and takes a reference of its own. Getting that wrong
//! is a use-after-free of an object shared by every process in the session, so
//! the retain and the store are one operation here and cannot be separated:
//! `set_if_none` takes the reference exactly when it takes the terminal, and
//! `take` gives back exactly what it removes.
//!
//! # Lock order
//!
//! This lock is **innermost** and takes nothing while held — in particular it
//! does not call into `crates/fs/tty`, which has a lock of its own that the
//! claim path takes *after* this one is released. Asking the other way round
//! is the cycle in
//! `docs/changelog/2026-08-31-a-terminal-asked-the-process-layer-while-holding-its-own-lock.md`,
//! and `tools/lock-order.py` cannot see either half because both locks are
//! Rust's now.
//!
//! A reference is a [`User`], so it is given back by being dropped, and every
//! method here drops the one it removes **after** the lock is released:
//! `tty::release` takes the terminal table's lock, and the last release tears
//! the terminal down. Until 2026-09-30 this comment said `retain` and `release`
//! "are atomic counter operations on the `Arc` and take no lock", which was true
//! of the retain and had stopped being true of the release, and `clear_if` and
//! the group's drop released with this lock held. Taking a user
//! ([`User::take`]) is still only an atomic increment, so `retain`,
//! `set_if_none` and `from_parent` do that under it. The claim, which takes
//! the terminal's lock, is the caller's to do afterwards -- which is why
//! `set_if_none` answers whether it stored, rather than claiming itself.

use fs_tty::tty::{Tty, User};
use std::sync::{Arc, Mutex};

/// An `Arc<Tty>` identity: an address this crate compares and never reads.
///
/// It was a private `TtyPtr(usize)` with a `tty_ptr(raw: usize) -> *const Tty`
/// to undo it, and the sentinel `0` for "none", until 2026-09-16. Since
/// 2026-09-30 the field holds a [`User`] and this is only what the queries
/// answer.
pub use fs_tty::ops::TtyId;

#[derive(Default)]
pub struct Ctty {
    tty: Mutex<Option<User>>,
}

impl Ctty {
    pub fn new() -> Ctty {
        Ctty::default()
    }

    fn with<T>(&self, f: impl FnOnce(&mut Option<User>) -> T) -> T {
        f(&mut self.tty.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn id(&self) -> Option<TtyId> {
        self.with(|t| t.as_ref().map(|u| TtyId::of(u.tty())))
    }

    /// Whether this group has one at all.
    pub fn has(&self) -> bool {
        self.with(|t| t.is_some())
    }

    /// Whether `tty` is this group's.
    pub fn is(&self, tty: TtyId) -> bool {
        self.id() == Some(tty)
    }

    /// The terminal **with a reference taken**.
    ///
    /// For a caller that is going to keep it -- `/dev/tty` opens whatever the
    /// group has, and the reference has to be taken while the field is still
    /// held or the group can give the terminal up in between -- and for one
    /// that is going to read it. There was a `peek` answering the identity
    /// alone until 2026-09-30, and its one reader, `/proc/<pid>/stat`, turned
    /// it back into a pointer and read through it: sound only because every
    /// path that gives a terminal up holds `pids_lock`, which nothing here
    /// could check. An increment is what reading costs now.
    pub fn retain(&self) -> Option<User> {
        self.with(|t| t.as_ref().map(|u| User::take(u.tty())))
    }

    /// Takes `tty` as this group's controlling terminal if it has none, with a
    /// reference.
    ///
    /// Answers whether it stored — the caller claims the terminal on the other
    /// side only if it did, and does that **after** this returns, because that
    /// call takes the terminal's own lock.
    pub fn set_if_none(&self, tty: &Arc<Tty>) -> bool {
        self.with(|t| {
            if t.is_some() {
                return false;
            }
            *t = Some(User::take(tty));
            true
        })
    }

    /// Gives up `tty` if it is this group's, releasing the reference once the
    /// lock is released.
    ///
    /// Answers whether it was. This is what taking a terminal away from the
    /// session that has it does to each group in that session.
    pub fn clear_if(&self, tty: TtyId) -> bool {
        let removed = self.with(|t| {
            t.take_if(|u| TtyId::of(u.tty()) == tty)
        });
        removed.is_some()
    }

    /// Gives up whatever it has and hands the reference to the caller, which
    /// has more to do with the terminal (a session leaving it disowns it first)
    /// before dropping it.
    pub fn take(&self) -> Option<User> {
        self.with(Option::take)
    }

    /// A new group's, inheriting its parent's with a reference of its own.
    pub fn from_parent(parent: &Ctty) -> Ctty {
        Ctty {
            tty: Mutex::new(parent.retain()),
        }
    }
}

impl std::fmt::Debug for Ctty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctty").field("tty", &self.id()).finish()
    }
}

// A group that is freed without leaving its session still owes the reference
// back, and the field's own drop gives it: nothing else can reach the group by
// then, so no lock is held.

#[cfg(test)]
mod tests {
    use super::*;
    use fs_tty::tty::{Kind, users};
    use std::sync::Weak;

    /// A real terminal: a console the table makes on first use, which is
    /// freed when its last user goes. Each test names its own number, so the
    /// tests do not share one. The counts are the terminal's own, which is
    /// what the reference and the field moving together is about.
    ///
    /// These drove fake pointers through `cfg(test)` doubles of
    /// `tty_retain`/`tty_release` until 2026-09-30, so they checked the
    /// pairing and not that the terminal was given back.
    fn console(num: i32) -> User {
        User::get(Kind::Console, num).expect("a console")
    }

    fn count(u: &User) -> usize {
        users(u.tty())
    }

    fn weak(u: &User) -> Weak<Tty> {
        Arc::downgrade(u.tty())
    }

    #[test]
    fn a_fresh_group_has_none() {
        let t = console(1);
        let c = Ctty::new();
        assert!(!c.has());
        assert_eq!(c.id(), None);
        assert!(!c.is(TtyId::of(t.tty())));
        assert!(c.retain().is_none(), "nothing to retain");
    }

    /// Claiming takes a reference; claiming again takes nothing and changes
    /// nothing.
    ///
    /// `TIOCSCTTY` on a process that already has a controlling terminal is a
    /// no-op, and a second retain there would be a reference nobody gives back.
    #[test]
    fn claiming_takes_one_reference_and_only_one() {
        let (t, other) = (console(11), console(12));
        let c = Ctty::new();
        assert!(c.set_if_none(t.tty()));
        assert_eq!(count(&t), 2);
        assert!(c.has() && c.is(TtyId::of(t.tty())));

        assert!(!c.set_if_none(t.tty()), "the second claim stores nothing");
        assert_eq!(count(&t), 2, "and takes no second reference");
        assert!(!c.set_if_none(other.tty()), "and a different terminal is refused");
        assert!(c.is(TtyId::of(t.tty())));
        assert_eq!(count(&other), 1);
    }

    /// Giving it up gives the reference back, and only for the right terminal.
    #[test]
    fn clearing_matches_the_terminal_it_is_given() {
        let (t, other) = (console(21), console(22));
        let c = Ctty::new();
        c.set_if_none(t.tty());
        assert!(!c.clear_if(TtyId::of(other.tty())), "another terminal is not this one");
        assert_eq!(count(&t), 2, "and nothing was released");
        assert!(c.clear_if(TtyId::of(t.tty())));
        assert_eq!(count(&t), 1, "the reference went back");
        assert!(!c.has());
        assert!(!c.clear_if(TtyId::of(t.tty())), "and a second time does nothing");
        assert_eq!(count(&t), 1);
    }

    /// `take` hands the reference to the caller rather than dropping it: the
    /// session-leaving path disowns the terminal and then releases.
    #[test]
    fn take_hands_the_reference_over() {
        let t = console(31);
        let c = Ctty::new();
        c.set_if_none(t.tty());
        let held = c.take().expect("the terminal");
        assert!(Arc::ptr_eq(held.tty(), t.tty()));
        assert_eq!(count(&t), 2, "still held -- the caller owes it");
        assert!(!c.has());
        assert!(c.take().is_none());
        drop(held);
        assert_eq!(count(&t), 1);
    }

    /// A child inherits the terminal with a reference of its own, so the
    /// parent's exit does not take it from the child.
    #[test]
    fn a_child_inherits_with_its_own_reference() {
        let t = console(41);
        let id = TtyId::of(t.tty());
        let parent = Ctty::new();
        parent.set_if_none(t.tty());
        let child = Ctty::from_parent(&parent);
        assert_eq!(count(&t), 3);
        assert!(child.is(id) && parent.is(id));

        drop(parent);
        assert_eq!(count(&t), 2, "the child still holds one");
        assert!(child.is(id));
        drop(child);
        assert_eq!(count(&t), 1);
    }

    /// `retain` takes a reference where `peek` does not, which is the whole
    /// difference between them: one is for a caller that keeps the terminal.
    #[test]
    fn retain_takes_a_reference_and_peek_does_not() {
        let t = console(61);
        let c = Ctty::new();
        c.set_if_none(t.tty());
        assert_eq!(c.id(), Some(TtyId::of(t.tty())));
        assert_eq!(count(&t), 2, "peek took nothing");
        let kept = c.retain().expect("the terminal");
        assert_eq!(count(&t), 3, "retain took one");
        drop(kept);
        assert_eq!(count(&t), 2);
    }

    /// Inheriting from a parent that has none takes nothing.
    #[test]
    fn a_child_of_a_group_with_no_terminal_gets_none() {
        let parent = Ctty::new();
        let child = Ctty::from_parent(&parent);
        assert!(!child.has());
    }

    /// A group freed without leaving its session still gives the reference
    /// back, and the terminal is freed once nothing else holds it.
    #[test]
    fn dropping_a_group_gives_the_reference_back() {
        let t = console(51);
        let gone = weak(&t);
        let c = Ctty::new();
        c.set_if_none(t.tty());
        drop(t);
        assert!(gone.upgrade().is_some(), "the group's reference keeps it");
        drop(c);
        assert!(gone.upgrade().is_none(), "the group's drop gave the last one back");
    }

    /// The last reference, given back by `clear_if`, frees the terminal.
    #[test]
    fn clearing_the_last_reference_frees_the_terminal() {
        let t = console(7);
        let id = TtyId::of(t.tty());
        let gone = weak(&t);
        let c = Ctty::new();
        c.set_if_none(t.tty());
        drop(t);
        assert!(c.clear_if(id));
        assert!(gone.upgrade().is_none());
    }
}
