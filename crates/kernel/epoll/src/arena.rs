//! Generation checked slot storage used by epoll descriptions and registrations.

use super::{DescriptionId, Error, RegistrationId};

struct Slot<T> {
    generation: u32,
    value: Option<T>,
}

pub(super) struct Arena<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
}

impl<T> Default for Arena<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }
}

pub(super) trait ArenaId: Copy {
    fn new(slot: u32, generation: u32) -> Self;
    fn slot(self) -> u32;
    fn generation(self) -> u32;
}

impl ArenaId for DescriptionId {
    fn new(slot: u32, generation: u32) -> Self {
        Self { slot, generation }
    }

    fn slot(self) -> u32 {
        self.slot
    }

    fn generation(self) -> u32 {
        self.generation
    }
}

impl ArenaId for RegistrationId {
    fn new(slot: u32, generation: u32) -> Self {
        Self { slot, generation }
    }

    fn slot(self) -> u32 {
        self.slot
    }

    fn generation(self) -> u32 {
        self.generation
    }
}

impl<T> Arena<T> {
    pub(super) fn reserve_slot(&mut self) -> Result<(), Error> {
        if self.free.is_empty() {
            if self.slots.len() >= u32::MAX as usize {
                return Err(Error::OutOfMemory);
            }
            self.slots.try_reserve(1)?;
            // Every new live slot may eventually be removed. Reserve its future
            // free-list entry now, so removal itself is allocation-free.
            self.free.try_reserve(1)?;
        }
        Ok(())
    }

    pub(super) fn insert_reserved<I: ArenaId>(&mut self, value: T) -> I {
        if let Some(slot) = self.free.pop() {
            let entry = &mut self.slots[slot as usize];
            debug_assert!(entry.value.is_none());
            entry.value = Some(value);
            I::new(slot, entry.generation)
        } else {
            let slot = self.slots.len() as u32;
            self.slots.push(Slot {
                generation: 1,
                value: Some(value),
            });
            I::new(slot, 1)
        }
    }

    pub(super) fn get<I: ArenaId>(&self, id: I) -> Option<&T> {
        let slot = self.slots.get(id.slot() as usize)?;
        (slot.generation == id.generation()).then_some(slot.value.as_ref()?)
    }

    pub(super) fn get_mut<I: ArenaId>(&mut self, id: I) -> Option<&mut T> {
        let slot = self.slots.get_mut(id.slot() as usize)?;
        (slot.generation == id.generation()).then_some(slot.value.as_mut()?)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.slots.iter().filter_map(|slot| slot.value.as_ref())
    }

    pub(super) fn remove<I: ArenaId>(&mut self, id: I) -> Option<T> {
        let slot = self.slots.get_mut(id.slot() as usize)?;
        if slot.generation != id.generation() {
            return None;
        }
        let value = slot.value.take()?;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        self.free.push(id.slot());
        Some(value)
    }

    pub(super) fn live_len(&self) -> usize {
        self.slots.len() - self.free.len()
    }
}
