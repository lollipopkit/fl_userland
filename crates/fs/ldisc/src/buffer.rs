//! The terminal input buffer, as a ring.
//!
//! The C held a flat `char buf[4096]` plus a parallel `bool buf_flag[4096]`,
//! and every read copied the remainder down:
//!
//! ```c
//! memcpy(buf, tty->buf, bufsize);
//! tty->bufsize -= bufsize;
//! memmove(tty->buf, tty->buf + bufsize, tty->bufsize);   // magic!
//! memmove(tty->buf_flag, tty->buf_flag + bufsize, tty->bufsize);
//! ```
//!
//! That is quadratic in what is buffered — reading 4000 bytes one at a time
//! moved about 8 MB. In practice it costs about a millisecond, because the
//! buffer is capped at 4 KB and the moves are microseconds each, so this is
//! not why it was rewritten. A ring has no copy at all, needs one bit per
//! slot rather than a whole byte for the flags, and does not need the comment
//! that says "magic!".

/// Matches `TTY_BUF_SIZE` in `fs/tty.h`. A power of two, so the wrap is a
/// mask rather than a division.
pub const SIZE: usize = 4096;
const MASK: usize = SIZE - 1;

/// A flag marks the end of a line in canonical mode. It is set by the EOL and
/// EOF characters, and erase stops at one: you cannot backspace into a line
/// that has already been made available to a reader.
pub struct LineBuffer {
    data: [u8; SIZE],
    /// One bit per slot, indexed the same way as `data`.
    flags: [u64; SIZE / 64],
    /// Index of the oldest byte.
    head: usize,
    len: usize,
}

impl Default for LineBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl LineBuffer {
    pub fn new() -> LineBuffer {
        LineBuffer {
            data: [0; SIZE],
            flags: [0; SIZE / 64],
            head: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_full(&self) -> bool {
        self.len == SIZE
    }

    fn slot(&self, i: usize) -> usize {
        (self.head + i) & MASK
    }

    fn get_flag(&self, slot: usize) -> bool {
        self.flags[slot / 64] & (1u64 << (slot % 64)) != 0
    }

    fn set_flag(&mut self, slot: usize, value: bool) {
        let word = &mut self.flags[slot / 64];
        let bit = 1u64 << (slot % 64);
        if value {
            *word |= bit;
        } else {
            *word &= !bit;
        }
    }

    /// Append one character. Returns false when the buffer is full.
    pub fn push(&mut self, ch: u8, flag: bool) -> bool {
        if self.is_full() {
            return false;
        }
        let slot = self.slot(self.len);
        self.data[slot] = ch;
        self.set_flag(slot, flag);
        self.len += 1;
        true
    }

    /// The character `i` positions from the read end.
    pub fn at(&self, i: usize) -> Option<u8> {
        (i < self.len).then(|| self.data[self.slot(i)])
    }

    /// Remove the most recent character, unless it carries a flag or the
    /// buffer is empty. Returns what was removed.
    ///
    /// Erase stops at a flag because that character terminated a line a reader
    /// may already have seen.
    pub fn erase(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        let slot = self.slot(self.len - 1);
        if self.get_flag(slot) {
            return None;
        }
        self.len -= 1;
        Some(self.data[slot])
    }

    /// Length of the first complete line, including its terminator, or `None`
    /// when no line has been terminated yet.
    pub fn canon_len(&self) -> Option<usize> {
        (0..self.len)
            .find(|&i| self.get_flag(self.slot(i)))
            .map(|i| i + 1)
    }

    /// Copy out up to `out.len()` bytes and drop them from the buffer.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len);
        for (i, slot) in out.iter_mut().enumerate().take(n) {
            *slot = self.data[self.slot(i)];
        }
        self.head = (self.head + n) & MASK;
        self.len -= n;
        n
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(bytes: &[u8]) -> LineBuffer {
        let mut b = LineBuffer::new();
        for &ch in bytes {
            assert!(b.push(ch, false));
        }
        b
    }

    #[test]
    fn push_and_read_round_trip() {
        let mut b = filled(b"hello");
        let mut out = [0u8; 8];
        assert_eq!(b.read(&mut out), 5);
        assert_eq!(&out[..5], b"hello");
        assert!(b.is_empty());
    }

    #[test]
    fn a_partial_read_leaves_the_rest_in_order() {
        let mut b = filled(b"abcdef");
        let mut out = [0u8; 2];
        assert_eq!(b.read(&mut out), 2);
        assert_eq!(&out, b"ab");
        let mut rest = [0u8; 8];
        assert_eq!(b.read(&mut rest), 4);
        assert_eq!(&rest[..4], b"cdef");
    }

    #[test]
    fn it_wraps_without_moving_anything() {
        // Fill, drain most of it, then fill again: the second fill wraps past
        // the end of the array. The flat buffer needed a memmove for this.
        let mut b = LineBuffer::new();
        for i in 0..SIZE {
            assert!(b.push((i % 251) as u8, false));
        }
        let mut out = vec![0u8; SIZE - 10];
        assert_eq!(b.read(&mut out), SIZE - 10);
        assert_eq!(b.len(), 10);
        for i in 0..100 {
            assert!(b.push(i as u8, false));
        }
        assert_eq!(b.len(), 110);
        // The ten survivors are still first, and still in order.
        for i in 0..10 {
            assert_eq!(b.at(i), Some(((SIZE - 10 + i) % 251) as u8));
        }
        assert_eq!(b.at(10), Some(0));
        assert_eq!(b.at(109), Some(99));
    }

    #[test]
    fn a_full_buffer_refuses_more() {
        let mut b = LineBuffer::new();
        for _ in 0..SIZE {
            assert!(b.push(b'x', false));
        }
        assert!(b.is_full());
        assert!(!b.push(b'y', false));
        assert_eq!(b.len(), SIZE);
    }

    #[test]
    fn erase_removes_the_most_recent_character() {
        let mut b = filled(b"abc");
        assert_eq!(b.erase(), Some(b'c'));
        assert_eq!(b.erase(), Some(b'b'));
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn erase_stops_at_a_flag() {
        // A terminated line is not editable: a reader may already have it.
        let mut b = LineBuffer::new();
        b.push(b'h', false);
        b.push(b'\n', true);
        b.push(b'x', false);
        assert_eq!(b.erase(), Some(b'x'));
        assert_eq!(b.erase(), None, "must not erase past the newline");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn erase_on_an_empty_buffer_is_a_no_op() {
        let mut b = LineBuffer::new();
        assert_eq!(b.erase(), None);
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn canon_len_finds_the_first_terminator() {
        let mut b = LineBuffer::new();
        assert_eq!(b.canon_len(), None);
        for &ch in b"one" {
            b.push(ch, false);
        }
        assert_eq!(b.canon_len(), None, "an unterminated line is not readable");
        b.push(b'\n', true);
        assert_eq!(b.canon_len(), Some(4));
        // A second line does not change the first one's length.
        for &ch in b"two" {
            b.push(ch, false);
        }
        b.push(b'\n', true);
        assert_eq!(b.canon_len(), Some(4));
    }

    #[test]
    fn canon_len_is_correct_across_a_wrap() {
        // The flag bits are indexed by slot, so a line that straddles the end
        // of the array has to be found just the same.
        let mut b = LineBuffer::new();
        for i in 0..SIZE {
            b.push((i % 251) as u8, false);
        }
        let mut out = vec![0u8; SIZE - 2];
        b.read(&mut out);
        // Two stale bytes remain; add a terminated line that wraps.
        for &ch in b"wrapped" {
            b.push(ch, false);
        }
        b.push(b'\n', true);
        assert_eq!(b.canon_len(), Some(2 + 7 + 1));
    }

    #[test]
    fn flags_do_not_survive_the_slot_being_reused() {
        // A slot that held a terminator and was then read and refilled must
        // not still look like one.
        let mut b = LineBuffer::new();
        b.push(b'\n', true);
        let mut out = [0u8; 1];
        b.read(&mut out);
        b.push(b'x', false);
        assert_eq!(b.canon_len(), None, "the reused slot kept its flag");
    }

    #[test]
    fn clear_drops_everything() {
        let mut b = filled(b"abc");
        b.clear();
        assert!(b.is_empty());
        assert_eq!(b.canon_len(), None);
    }
}
