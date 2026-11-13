//! [`ArcSlot`]: an `Option<Arc<T>>` that another thread may swap out.
//!
//! A task's descriptor table and the cleanup record's handed-over references
//! are written by one thread and taken by another with no lock in common --
//! the group-exit valve hands a stuck thread's objects to its cleanup record
//! while that thread may be draining it. Each was an `AtomicPtr` holding an
//! `Arc::into_raw` count, with `Arc::from_raw` and `into_raw` written out at
//! every site that moved one, in six crates. This is that, once: the slot owns
//! the count it holds, every exchange moves a count rather than adjusting
//! one, and dropping the slot gives back whatever is left in it.

use std::marker::PhantomData;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

/// One strong reference to a `T`, or none, behind an atomic pointer.
pub struct ArcSlot<T> {
    ptr: AtomicPtr<T>,
    /// What the pointer owns, so auto traits and drop check see an `Arc<T>`.
    _owns: PhantomData<Arc<T>>,
}

fn into_raw<T>(v: Option<Arc<T>>) -> *mut T {
    v.map_or(ptr::null_mut(), |a| Arc::into_raw(a).cast_mut())
}

/// # Safety
/// `p` is null or carries a count this call adopts.
unsafe fn from_raw<T>(p: *mut T) -> Option<Arc<T>> {
    // SAFETY: the caller's contract.
    (!p.is_null()).then(|| unsafe { Arc::from_raw(p.cast_const()) })
}

impl<T> ArcSlot<T> {
    pub const fn empty() -> ArcSlot<T> {
        ArcSlot { ptr: AtomicPtr::new(ptr::null_mut()), _owns: PhantomData }
    }

    pub fn new(v: Option<Arc<T>>) -> ArcSlot<T> {
        ArcSlot { ptr: AtomicPtr::new(into_raw(v)), _owns: PhantomData }
    }

    /// Put `v` in and answer what was there. `AcqRel`: the taker sees
    /// everything the putter did to the object before handing it over.
    pub fn swap(&self, v: Option<Arc<T>>) -> Option<Arc<T>> {
        let old = self.ptr.swap(into_raw(v), Ordering::AcqRel);
        // SAFETY: every pointer in the slot came from `into_raw` and its count
        // is the slot's; the swap took it out, so it is this call's.
        unsafe { from_raw(old) }
    }

    /// The object, borrowed through an exclusive borrow of the slot -- one
    /// nothing else can be taking from or replacing, which is what makes this
    /// safe where [`ArcSlot::as_ptr`]'s caller has to argue it.
    pub fn get_mut(&mut self) -> Option<&T> {
        // SAFETY: the slot owns a count on what it holds, and `&mut self`
        // excludes every `take`, `swap` and `set` for the borrow.
        unsafe { self.ptr.get_mut().cast_const().as_ref() }
    }

    /// Empty the slot, answering what was in it. Exactly one of two racing
    /// takers gets the reference.
    pub fn take(&self) -> Option<Arc<T>> {
        self.swap(None)
    }

    /// Replace the contents, dropping what was there.
    pub fn set(&self, v: Option<Arc<T>>) {
        drop(self.swap(v));
    }

    /// Move this slot's reference into `to`, publishing it there **before**
    /// emptying this one, so a reader that looks in both never finds it in
    /// neither. What `to` held is released.
    ///
    /// # Safety
    /// Nothing else writes `self` between the two stores -- the two are not
    /// one atomic step, and a concurrent `take` would leave the same count in
    /// two places.
    pub unsafe fn move_to(&self, to: &ArcSlot<T>) {
        let p = self.ptr.load(Ordering::Acquire);
        let old = to.ptr.swap(p, Ordering::SeqCst);
        self.ptr.store(ptr::null_mut(), Ordering::Release);
        // SAFETY: `old` was `to`'s, and the swap took it out.
        drop(unsafe { from_raw(old) });
    }

    /// The object's address, for identity and for a caller that borrows it
    /// under a rule of its own; null when empty. Owns nothing.
    pub fn as_ptr(&self) -> *const T {
        self.ptr.load(Ordering::Acquire)
    }

    /// Another reference to what is in the slot, leaving it there.
    ///
    /// # Safety
    /// Nothing can take the slot's reference and drop it during this call:
    /// the caller holds whatever lock every taker holds, or is the only
    /// thread that takes from it.
    pub unsafe fn clone_arc(&self) -> Option<Arc<T>> {
        let p = self.as_ptr();
        if p.is_null() {
            return None;
        }
        // SAFETY: live for this call by the caller's contract; the increment
        // is the new reference's count.
        unsafe {
            Arc::increment_strong_count(p);
            Some(Arc::from_raw(p))
        }
    }
}

impl<T> Default for ArcSlot<T> {
    fn default() -> Self {
        ArcSlot::empty()
    }
}

impl<T> Drop for ArcSlot<T> {
    fn drop(&mut self) {
        drop(self.take());
    }
}

impl<T> std::fmt::Debug for ArcSlot<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ArcSlot({:p})", self.as_ptr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slot_owns_one_count_and_gives_it_back() {
        let a = Arc::new(5);
        let slot = ArcSlot::new(Some(Arc::clone(&a)));
        assert_eq!(Arc::strong_count(&a), 2);
        let c = unsafe { slot.clone_arc() }.unwrap();
        assert_eq!(Arc::strong_count(&a), 3);
        drop(c);
        drop(slot);
        assert_eq!(Arc::strong_count(&a), 1, "dropping the slot released its count");
    }

    #[test]
    fn a_swap_moves_counts_rather_than_adjusting_them() {
        let a = Arc::new(1);
        let b = Arc::new(2);
        let slot = ArcSlot::new(Some(Arc::clone(&a)));
        let out = slot.swap(Some(Arc::clone(&b))).unwrap();
        assert!(Arc::ptr_eq(&out, &a));
        assert_eq!((Arc::strong_count(&a), Arc::strong_count(&b)), (2, 2));
        assert!(Arc::ptr_eq(&slot.take().unwrap(), &b));
        assert!(slot.take().is_none() && slot.as_ptr().is_null());
        assert_eq!(Arc::strong_count(&b), 1);
    }

    #[test]
    fn a_move_leaves_the_reference_in_exactly_one_slot() {
        let a = Arc::new(3);
        let from = ArcSlot::new(Some(Arc::clone(&a)));
        let to = ArcSlot::empty();
        unsafe { from.move_to(&to) };
        assert!(from.as_ptr().is_null());
        assert_eq!(to.as_ptr(), Arc::as_ptr(&a));
        assert_eq!(Arc::strong_count(&a), 2, "moved, not cloned or dropped");
        unsafe { from.move_to(&to) };
        assert!(to.as_ptr().is_null(), "moving an empty slot empties the target");
        assert_eq!(Arc::strong_count(&a), 1);
    }

    #[test]
    fn get_mut_lends_what_the_slot_holds() {
        let a = Arc::new(5);
        let mut slot = ArcSlot::new(Some(Arc::clone(&a)));
        assert_eq!(slot.get_mut(), Some(&5));
        assert_eq!(Arc::strong_count(&a), 2, "lent, not cloned");
        assert_eq!(ArcSlot::<u8>::empty().get_mut(), None);
    }

    #[test]
    fn exactly_one_of_two_racing_takers_gets_it() {
        for _ in 0..200 {
            let a = Arc::new(());
            let slot = Arc::new(ArcSlot::new(Some(Arc::clone(&a))));
            let s2 = Arc::clone(&slot);
            let t = std::thread::spawn(move || s2.take().is_some());
            let here = slot.take().is_some();
            let there = t.join().unwrap();
            assert!(here ^ there);
            assert_eq!(Arc::strong_count(&a), 1);
        }
    }
}
