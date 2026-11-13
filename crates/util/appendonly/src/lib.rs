//! A fixed-capacity list that only grows, read without a lock.
//!
//! The two native offload tables (`crates/asbestos/offloadsym` and
//! `offloadprebuilt`) were each a `static mut` array and a published count:
//! a registration wrote a slot through `&raw mut` and then stored the count
//! with `Release`, and a reader made a slice of the first `count` slots with
//! `from_raw_parts`. Sound, given that only one thread ever registered at a
//! time -- which one of them enforced with a `Mutex` and the other with a
//! sentence about constructors. This is the same shape with the slot an
//! `OnceLock`, so the write needs no `unsafe` and two registrations cannot
//! claim one slot.
//!
//! Reading takes no lock: a reader sees the count with `Acquire`, and every
//! slot below it has been set.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

pub struct AppendOnly<T, const N: usize> {
    slots: [OnceLock<T>; N],
    len: AtomicUsize,
    push: Mutex<()>,
}

impl<T, const N: usize> AppendOnly<T, N> {
    pub const fn new() -> Self {
        AppendOnly {
            slots: [const { OnceLock::new() }; N],
            len: AtomicUsize::new(0),
            push: Mutex::new(()),
        }
    }

    /// Appends `value` and answers its index, or gives it back when full.
    pub fn push(&self, value: T) -> Result<usize, T> {
        let _serial = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        let id = self.len.load(Ordering::Relaxed);
        let Some(slot) = self.slots.get(id) else {
            return Err(value);
        };
        // Only a pusher sets a slot, under `push`, and only the one at `len`.
        slot.set(value)?;
        self.len.store(id + 1, Ordering::Release);
        Ok(id)
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every entry published so far, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.slots[..self.len()].iter().filter_map(OnceLock::get)
    }
}

impl<T, const N: usize> Default for AppendOnly<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_fills_in_order_and_refuses_past_capacity() {
        let list: AppendOnly<u32, 2> = AppendOnly::new();
        assert!(list.is_empty());
        assert_eq!(list.push(7), Ok(0));
        assert_eq!(list.push(8), Ok(1));
        assert_eq!(list.push(9), Err(9));
        assert_eq!(list.iter().copied().collect::<Vec<_>>(), [7, 8]);
    }

    #[test]
    fn concurrent_pushes_each_get_their_own_slot() {
        static LIST: AppendOnly<usize, 64> = AppendOnly::new();
        let threads: Vec<_> = (0..8)
            .map(|t| {
                std::thread::spawn(move || {
                    for i in 0..8 {
                        LIST.push(t * 8 + i).unwrap();
                    }
                })
            })
            .collect();
        threads.into_iter().for_each(|h| h.join().unwrap());
        assert_eq!(LIST.len(), 64);
        let mut seen: Vec<usize> = LIST.iter().copied().collect();
        seen.sort_unstable();
        assert_eq!(seen, (0..64).collect::<Vec<_>>());
    }
}
