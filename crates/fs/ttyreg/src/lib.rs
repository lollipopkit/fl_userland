//! Which terminal is at which number, for one terminal driver.
//!
//! `struct tty_driver` carried a bare `struct tty *ttys[N]` and a `limit`, and
//! three files reached into it: `fs/tty.c` to find or install a terminal,
//! `fs/pty.c` to reserve a number before there is a terminal to put in it, and
//! `crates/fs/devpts` through accessors to list `/dev/pts`. A slot in it meant
//! one of three things, and the third was written as the pointer value 1:
//!
//! ```c
//! // pty_reserve_next stores 1 to avoid races on the same tty
//! if (tty == NULL || tty == (void *) 1 /* ew */) {
//! ```
//!
//! Here it is an enum, so "reserved" is a state rather than an address no
//! allocator would return, and the compiler checks that every read considers
//! it. The comment in the C says `ew`; this is what it was reaching for.
//!
//! Two other things follow from owning the array rather than indexing it:
//!
//! - Reserving a number was a scan from zero on every `ptmx` open, over 4096
//!   slots. A cursor makes it amortised constant.
//! - The ownership and mode of a pty slave's device node live here, beside the
//!   number they describe, instead of inside the terminal. `pty_slave_info`
//!   took `ttys_lock` and then the terminal's own lock to read three integers;
//!   now it takes neither beyond the one the caller already holds.
//!
//! The registry does not own the terminals. It holds an *identity* of one and
//! never dereferences it; lifetime and reference counting stay in
//! `crates/fs/tty`, under the lock that also serialises everything here.
//!
//! # `Registry<T>` is generic, and that is what the identity costs
//!
//! `Slot::Live` held a `usize` until 2026-09-16 — a `*const Tty` with the type
//! taken off, because this crate cannot name `Tty`: `fs-tty` depends on this
//! one, so the edge back is a cycle. The answer is not to erase the type but to
//! **not fix it**: a registry of numbers to identities does not care what the
//! identity is of, so `T` is the caller's and `fs/tty` instantiates
//! `Registry<Tty>`.
//!
//! What that buys over the `usize` is what `crates/util/identity`'s module
//! comment says it buys everywhere: `set(num, some_index)` no longer
//! type-checks, and `get` answers `Option<Identity<T>>` rather than `0` for
//! "nothing there" — a sentinel this crate had to spell out at two call sites
//! and that read the same as a live slot to anything that forgot.

use std::ffi::c_int;
use util_identity::Identity;

/// What a number holds.
///
/// Every impl below is hand-written rather than derived: a `#[derive]` would
/// add a `T: Clone`/`T: PartialEq`/`T: Debug` bound, and `Tty` is none of
/// those. `Identity<T>`'s own impls are hand-written for the same reason, and
/// it says so.
enum Slot<T> {
    /// Nothing, and available.
    Empty,
    /// Claimed by a caller that has not yet built the terminal. `ptmx` open
    /// takes a number first so that two opens cannot pick the same one.
    Reserved,
    /// A terminal identity. It is never dereferenced here.
    Live(Identity<T>),
}

impl<T> Clone for Slot<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Slot<T> {}
impl<T> PartialEq for Slot<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Slot::Empty, Slot::Empty) | (Slot::Reserved, Slot::Reserved) => true,
            (Slot::Live(a), Slot::Live(b)) => a == b,
            _ => false,
        }
    }
}
impl<T> Eq for Slot<T> {}
impl<T> std::fmt::Debug for Slot<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Slot::Empty => write!(f, "Empty"),
            Slot::Reserved => write!(f, "Reserved"),
            Slot::Live(id) => write!(f, "Live({id:?})"),
        }
    }
}

/// The ownership and mode of a pty slave's node in `/dev/pts`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Attrs {
    uid: u32,
    gid: u32,
    perms: u32,
}

impl Default for Attrs {
    fn default() -> Self {
        // What Linux gives a fresh pty: owned by whoever opened it, group
        // tty, and writable by that group so `write` and `wall` work.
        Attrs {
            uid: 0,
            gid: 0,
            perms: 0o620,
        }
    }
}

pub struct Registry<T> {
    slots: Vec<Slot<T>>,
    attrs: Vec<Attrs>,
    /// Where to start looking for a free number. Not a guarantee — the slot it
    /// names may have been taken — just a place that is usually right.
    cursor: usize,
}

impl<T> Registry<T> {
    pub fn new(limit: usize) -> Registry<T> {
        Registry {
            slots: vec![Slot::Empty; limit],
            attrs: vec![Attrs::default(); limit],
            cursor: 0,
        }
    }

    pub fn limit(&self) -> usize {
        self.slots.len()
    }

    fn slot(&self, num: c_int) -> Option<Slot<T>> {
        if num < 0 {
            return None;
        }
        self.slots.get(num as usize).copied()
    }

    /// The terminal at `num`, or `None`. `Reserved` reads as `None`: a number
    /// that is spoken for does not yet have a terminal in it.
    pub fn get(&self, num: c_int) -> Option<Identity<T>> {
        match self.slot(num) {
            Some(Slot::Live(p)) => Some(p),
            _ => None,
        }
    }

    /// Whether a terminal is actually there, which is what `/dev/pts` asks.
    pub fn is_live(&self, num: c_int) -> bool {
        matches!(self.slot(num), Some(Slot::Live(_)))
    }

    /// Whether the number is free to be claimed — neither live nor reserved.
    /// `tty_get` builds a terminal when it finds this, which is why a reserved
    /// number has to be distinguishable from an empty one.
    pub fn is_vacant(&self, num: c_int) -> bool {
        matches!(self.slot(num), Some(Slot::Empty) | Some(Slot::Reserved))
    }

    /// `None` empties the number, which is what [`Self::clear`] does by name.
    /// It was a `usize` with `0` meaning the same thing.
    pub fn set(&mut self, num: c_int, tty: Option<Identity<T>>) -> bool {
        if num < 0 || num as usize >= self.slots.len() {
            return false;
        }
        self.slots[num as usize] = match tty {
            None => Slot::Empty,
            Some(id) => Slot::Live(id),
        };
        true
    }

    /// Empties a number, whatever it held.
    pub fn clear(&mut self, num: c_int) {
        if num >= 0
            && let Some(s) = self.slots.get_mut(num as usize)
        {
            *s = Slot::Empty;
            // A number just freed is the best guess for the next one.
            self.cursor = self.cursor.min(num as usize);
        }
    }

    /// Claims the lowest free number, or `None` when the table is full.
    ///
    /// The C returned `MAX_PTYS` for full, and its own comment records what
    /// happened when a caller forgot to check: the reservation was written at
    /// `ttys[MAX_PTYS]`, one past the end, into whatever the linker had put
    /// next to the array. An `Option` cannot be used without deciding.
    pub fn reserve(&mut self) -> Option<c_int> {
        let n = self.slots.len();
        for step in 0..n {
            let i = (self.cursor + step) % n;
            if self.slots[i] == Slot::Empty {
                self.slots[i] = Slot::Reserved;
                self.attrs[i] = Attrs::default();
                self.cursor = (i + 1) % n;
                return Some(i as c_int);
            }
        }
        None
    }

    /// Gives back a number `reserve` handed out that nothing was put into.
    /// Without it a failed open left the number spoken for until the process
    /// ended, and enough of them exhausted the table.
    pub fn release_reservation(&mut self, num: c_int) {
        if num < 0 {
            return;
        }
        if let Some(s) = self.slots.get_mut(num as usize)
            && *s == Slot::Reserved
        {
            *s = Slot::Empty;
            self.cursor = self.cursor.min(num as usize);
        }
    }

    /// The first live number at or after `from`, for listing `/dev/pts`.
    pub fn next_live(&self, from: c_int) -> Option<c_int> {
        let start = if from < 0 { 0 } else { from as usize };
        (start..self.slots.len())
            .find(|&i| matches!(self.slots[i], Slot::Live(_)))
            .map(|i| i as c_int)
    }

    /// The node's ownership and mode, if a terminal is there.
    pub fn attrs(&self, num: c_int) -> Option<(u32, u32, u32)> {
        if !self.is_live(num) {
            return None;
        }
        let a = self.attrs[num as usize];
        Some((a.uid, a.gid, a.perms))
    }

    pub fn set_attrs(&mut self, num: c_int, uid: u32, gid: u32, perms: u32) -> bool {
        if num < 0 || num as usize >= self.slots.len() {
            return false;
        }
        self.attrs[num as usize] = Attrs { uid, gid, perms };
        true
    }

    pub fn set_attr(&mut self, num: c_int, which: c_int, value: u32) -> bool {
        if !self.is_live(num) {
            return false;
        }
        let a = &mut self.attrs[num as usize];
        match which {
            ATTR_UID => a.uid = value,
            ATTR_GID => a.gid = value,
            ATTR_MODE => a.perms = value,
            _ => return false,
        }
        true
    }
}

pub const ATTR_UID: c_int = 0;
pub const ATTR_GID: c_int = 1;
pub const ATTR_MODE: c_int = 2;

// This had a C ABI -- fourteen `extern "C"` functions from when `fs/tty.c` and
// `fs/pty.c` drove the registry directly. `crates/fs/tty` owns the terminal
// now and uses the Rust API, so nothing crossed it: no C in the tree named one
// of them and no header declared one, which means a C caller could not have
// reached them even by accident. They are gone.
//
// The `reg`/`reg_mut` pointer macros went with them; a `&Registry` needs
// neither.

#[cfg(test)]
mod tests {
    use super::*;

    /// A pointee that does not exist, which is the point: this crate never
    /// dereferences what a slot holds, so its tests never needed a terminal
    /// and could not have built one — `Tty` is `fs-tty`'s, which depends on
    /// this crate.
    enum Fake {}

    type Reg = Registry<Fake>;

    fn tty(n: usize) -> Identity<Fake> {
        // A distinct identity, never 0 or 1 -- which is the value the C used
        // to mean "reserved". `Identity::from_ptr` is safe and `const` for
        // exactly this; see `crates/util/identity`.
        Identity::from_ptr(((n + 2) * 8) as *mut _).expect("a non-zero handle")
    }

    #[test]
    fn a_new_registry_is_empty() {
        let r = Reg::new(4);
        assert_eq!(r.limit(), 4);
        for n in 0..4 {
            assert_eq!(r.get(n), None);
            assert!(!r.is_live(n));
            assert!(r.is_vacant(n));
        }
    }

    #[test]
    fn a_number_outside_the_table_answers_rather_than_indexing() {
        let mut r = Reg::new(4);
        assert_eq!(r.get(4), None);
        assert_eq!(r.get(-1), None);
        assert_eq!(r.get(c_int::MAX), None);
        assert!(!r.is_live(4));
        assert!(!r.is_vacant(4), "outside is not vacant either");
        assert!(!r.set(4, Some(tty(1))));
        assert!(!r.set(-1, Some(tty(1))));
        r.clear(9999); // must not panic
    }

    /// The state the C wrote as the pointer value 1.
    #[test]
    fn a_reserved_number_holds_no_terminal_but_is_not_free() {
        let mut r = Reg::new(4);
        let n = r.reserve().unwrap();
        assert_eq!(r.get(n), None, "nothing to hand out yet");
        assert!(!r.is_live(n), "and /dev/pts must not list it");
        assert!(r.is_vacant(n), "but tty_get may build into it");
        // A second reservation cannot pick the same number.
        assert_ne!(r.reserve().unwrap(), n);
    }

    #[test]
    fn reserving_hands_out_every_number_then_reports_full() {
        let mut r = Reg::new(3);
        let mut seen = Vec::new();
        for _ in 0..3 {
            seen.push(r.reserve().expect("a free number"));
        }
        seen.sort();
        assert_eq!(seen, vec![0, 1, 2]);
        assert_eq!(r.reserve(), None, "full");
    }

    /// The C answered "full" with MAX_PTYS, and its own comment records a
    /// caller writing the reservation at that index -- one past the end.
    #[test]
    fn full_is_not_a_number_that_can_be_indexed() {
        let mut r = Reg::new(2);
        r.reserve();
        r.reserve();
        assert_eq!(r.reserve(), None);
        // Nothing was written past the end: both slots are still reserved.
        assert!(r.is_vacant(0) && r.is_vacant(1));
        assert!(!r.is_live(0) && !r.is_live(1));
    }

    #[test]
    fn a_released_reservation_can_be_taken_again() {
        let mut r = Reg::new(2);
        let a = r.reserve().unwrap();
        r.reserve().unwrap();
        assert_eq!(r.reserve(), None);
        r.release_reservation(a);
        assert_eq!(r.reserve(), Some(a));
    }

    #[test]
    fn releasing_does_not_disturb_a_number_that_holds_a_terminal() {
        let mut r = Reg::new(2);
        let n = r.reserve().unwrap();
        r.set(n, Some(tty(1)));
        r.release_reservation(n);
        assert_eq!(r.get(n), Some(tty(1)), "a live terminal is not a reservation");
    }

    #[test]
    fn setting_and_clearing_a_number() {
        let mut r = Reg::new(4);
        assert!(r.set(2, Some(tty(7))));
        assert_eq!(r.get(2), Some(tty(7)));
        assert!(r.is_live(2));
        assert!(!r.is_vacant(2));
        r.clear(2);
        assert_eq!(r.get(2), None);
        assert!(r.is_vacant(2));
    }

    #[test]
    fn setting_null_empties_the_number() {
        let mut r = Reg::new(4);
        r.set(1, Some(tty(1)));
        r.set(1, None);
        assert!(r.is_vacant(1));
    }

    #[test]
    fn next_live_skips_empty_and_reserved_numbers() {
        let mut r = Reg::new(8);
        r.reserve(); // 0, reserved only
        r.set(3, Some(tty(1)));
        r.set(6, Some(tty(2)));
        assert_eq!(r.next_live(0), Some(3), "a reservation is not a device");
        assert_eq!(r.next_live(4), Some(6));
        assert_eq!(r.next_live(7), None);
        assert_eq!(
            r.next_live(-5),
            Some(3),
            "a negative start means the beginning"
        );
        assert_eq!(r.next_live(100), None);
    }

    /// The C scanned from zero on every open. With a cursor, opening and
    /// closing in a loop does not walk the whole table each time.
    #[test]
    fn reserving_does_not_start_from_zero_every_time() {
        let mut r = Reg::new(64);
        let a = r.reserve().unwrap();
        let b = r.reserve().unwrap();
        assert_eq!((a, b), (0, 1), "lowest first while the table is fresh");
        // Free the lower one; the cursor comes back for it rather than
        // stranding it.
        r.release_reservation(a);
        assert_eq!(r.reserve(), Some(a));
    }

    #[test]
    fn the_cursor_wraps_rather_than_running_off_the_end() {
        let mut r = Reg::new(4);
        for _ in 0..4 {
            r.reserve().unwrap();
        }
        r.release_reservation(3);
        assert_eq!(r.reserve(), Some(3), "found after wrapping");
    }

    // --- the node's ownership and mode ---

    #[test]
    fn a_fresh_pty_has_linux_default_permissions() {
        let mut r = Reg::new(4);
        let n = r.reserve().unwrap();
        r.set(n, Some(tty(1)));
        assert_eq!(r.attrs(n), Some((0, 0, 0o620)));
    }

    #[test]
    fn attributes_belong_to_a_number_that_holds_a_terminal() {
        let mut r = Reg::new(4);
        assert_eq!(r.attrs(1), None, "nothing there");
        let n = r.reserve().unwrap();
        assert_eq!(r.attrs(n), None, "reserved is not there either");
        r.set(n, Some(tty(1)));
        assert!(r.attrs(n).is_some());
    }

    #[test]
    fn each_attribute_can_be_set_on_its_own() {
        let mut r = Reg::new(4);
        r.set(0, Some(tty(1)));
        assert!(r.set_attr(0, ATTR_UID, 501));
        assert!(r.set_attr(0, ATTR_GID, 20));
        assert!(r.set_attr(0, ATTR_MODE, 0o600));
        assert_eq!(r.attrs(0), Some((501, 20, 0o600)));
        assert!(!r.set_attr(0, 99, 1), "an attribute that does not exist");
        assert!(!r.set_attr(3, ATTR_UID, 1), "a number with nothing in it");
    }

    /// A number handed out again must not carry the last owner's permissions.
    #[test]
    fn reserving_a_number_again_resets_its_permissions() {
        let mut r = Reg::new(2);
        let n = r.reserve().unwrap();
        r.set(n, Some(tty(1)));
        r.set_attr(n, ATTR_UID, 1234);
        r.set_attr(n, ATTR_MODE, 0o666);
        r.clear(n);

        let again = r.reserve().unwrap();
        assert_eq!(again, n, "the same number comes back");
        r.set(again, Some(tty(2)));
        assert_eq!(
            r.attrs(again),
            Some((0, 0, 0o620)),
            "with default permissions, not the last owner's"
        );
    }
}
