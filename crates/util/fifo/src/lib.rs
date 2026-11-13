//! The kernel log's ring buffer.
//!
//! One caller, `kernel/log.c`, and one job: hold the last megabyte of `printk`
//! output so a guest can read it back with `syslog(2)`. It is here because the
//! C had two indexing mistakes in nineteen lines, and both are inexpressible
//! against a slice.
//!
//! # It read past the end of its own buffer
//!
//! ```c
//! size_t start = fifo->start;
//! if (flags & FIFO_LAST)
//!     start = (start + (fifo->size - size)) % fifo->capacity;
//!
//! size_t first_copy_size = fifo->capacity - fifo->start;   // fifo->start!
//! ...
//! memcpy(buf, &fifo->buf[start], first_copy_size);
//! ```
//!
//! The length of the first copy was measured from `fifo->start` and the copy
//! was made from `start`, which `FIFO_LAST` had moved. With a wrapped buffer —
//! capacity 10, `start` 8, holding 6 bytes, asking for the last 5 — the first
//! copy runs from index 9 for 2 bytes and reads index 10. The bytes that come
//! back are wrong as well as out of bounds.
//!
//! `SYSLOG_ACTION_READ_ALL` is `FIFO_LAST`, and the log wraps after a megabyte
//! of output, so a guest reaches it by producing enough log and then reading
//! it.
//!
//! # A write larger than the whole buffer underflowed its length
//!
//! `fifo_write` with `FIFO_OVERWRITE` computed `excess = size - remaining` and
//! did `fifo->size -= excess`. For a write bigger than the capacity that
//! subtracts more than is there, and `size` is a `size_t`: the length became
//! about 2^64 and the copies that followed were sized from it.
//!
//! # What changed besides
//!
//! [`Fifo::read`] returns **how many bytes it read** rather than all-or-nothing.
//! The C returned 1 and copied nothing when asked for more than it held, and
//! its one caller ignored that and handed the untouched buffer to the guest —
//! A short read cannot be ignored into a disclosure.

use std::os::raw::c_int;

/// `FIFO_OVERWRITE`: drop the oldest bytes rather than refuse.
pub const OVERWRITE: c_int = 1;
/// `FIFO_PEEK`: leave the bytes in place.
pub const PEEK: c_int = 1;
/// `FIFO_LAST`: take from the end rather than the start.
pub const LAST: c_int = 2;

/// A byte ring of fixed capacity.
pub struct Fifo {
    buf: Vec<u8>,
    /// Where the oldest byte is.
    start: usize,
    /// How many bytes are held.
    len: usize,
}

impl Fifo {
    pub fn with_capacity(capacity: usize) -> Fifo {
        Fifo {
            buf: vec![0; capacity],
            start: 0,
            len: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn remaining(&self) -> usize {
        self.capacity() - self.len
    }

    /// Append `data`. `false` if it would not fit and `overwrite` is not set.
    ///
    /// With `overwrite`, a write larger than the whole buffer keeps its **last**
    /// `capacity` bytes, which is what a ring of that size can hold. The C
    /// subtracted the overflow from its length without checking, and a
    /// `size_t` going below zero made the buffer look enormous.
    pub fn write(&mut self, data: &[u8], overwrite: bool) -> bool {
        if self.capacity() == 0 {
            return data.is_empty();
        }
        if data.len() > self.remaining() && !overwrite {
            return false;
        }
        // Only the tail of an oversized write survives; the rest would be
        // overwritten by it anyway.
        let data = if data.len() > self.capacity() {
            &data[data.len() - self.capacity()..]
        } else {
            data
        };
        let excess = data.len().saturating_sub(self.remaining());
        if excess > 0 {
            self.start = (self.start + excess) % self.capacity();
            self.len -= excess;
        }
        for (i, byte) in data.iter().enumerate() {
            let at = (self.start + self.len + i) % self.capacity();
            self.buf[at] = *byte;
        }
        self.len += data.len();
        true
    }

    /// Copy up to `out.len()` bytes into `out` and return how many.
    ///
    /// `last` takes them from the end rather than the start; `peek` leaves them
    /// in place. Taking from the end and then consuming would leave a hole in
    /// the middle, so a non-peeking `last` read drops everything up to what it
    /// returned — which is what "read the tail and clear" means.
    pub fn read(&mut self, out: &mut [u8], last: bool, peek: bool) -> usize {
        let n = out.len().min(self.len);
        if n == 0 {
            return 0;
        }
        let from = if last {
            (self.start + self.len - n) % self.capacity()
        } else {
            self.start
        };
        // The index is computed once, and used for both the length and the
        // offset. The C measured the first copy from one and read from the
        // other.
        for (i, slot) in out[..n].iter_mut().enumerate() {
            *slot = self.buf[(from + i) % self.capacity()];
        }
        if !peek {
            let consumed = if last { self.len } else { n };
            self.start = (self.start + consumed) % self.capacity();
            self.len -= consumed;
        }
        n
    }

    pub fn flush(&mut self) {
        self.start = 0;
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(f: &mut Fifo) -> Vec<u8> {
        let mut out = vec![0u8; f.len()];
        let n = f.read(&mut out, false, false);
        out.truncate(n);
        out
    }

    #[test]
    fn what_goes_in_comes_out() {
        let mut f = Fifo::with_capacity(8);
        assert!(f.write(b"abc", false));
        assert_eq!(f.len(), 3);
        assert_eq!(f.remaining(), 5);
        assert_eq!(drain(&mut f), b"abc");
        assert!(f.is_empty());
    }

    #[test]
    fn a_write_that_does_not_fit_is_refused_unless_told_otherwise() {
        let mut f = Fifo::with_capacity(4);
        assert!(f.write(b"abcd", false));
        assert!(!f.write(b"e", false), "no room and no overwrite");
        assert_eq!(f.len(), 4, "and nothing was disturbed");
        assert!(f.write(b"e", true));
        assert_eq!(drain(&mut f), b"bcde");
    }

    #[test]
    fn a_write_larger_than_the_whole_buffer_keeps_its_tail() {
        // The C computed `excess = size - remaining` and subtracted it from the
        // length without checking, so a write bigger than the capacity took
        // `size` below zero -- and it is a size_t.
        let mut f = Fifo::with_capacity(4);
        assert!(f.write(b"abcdefghij", true));
        assert_eq!(f.len(), 4, "held {} bytes", f.len());
        assert_eq!(drain(&mut f), b"ghij");
    }

    #[test]
    fn reading_the_tail_of_a_wrapped_buffer() {
        // The bug this crate exists for. Capacity 10, start 8, six bytes held
        // and wrapping, asking for the last five: the C measured the first copy
        // from `fifo->start` and read from the moved `start`, so it read index
        // 10 of a ten-byte buffer and returned the wrong bytes with it.
        let mut f = Fifo::with_capacity(10);
        f.write(b"01234567", false); // fill and consume, to move start to 8
        let mut sink = [0u8; 8];
        f.read(&mut sink, false, false);
        assert_eq!(f.len, 0);
        assert_eq!(f.start, 8);

        f.write(b"ABCDEF", false); // occupies 8,9,0,1,2,3
        assert_eq!(f.len(), 6);
        let mut out = [0u8; 5];
        let n = f.read(&mut out, true, true);
        assert_eq!(n, 5);
        assert_eq!(&out[..n], b"BCDEF", "the last five, in order");
    }

    #[test]
    fn reading_the_head_of_a_wrapped_buffer() {
        let mut f = Fifo::with_capacity(10);
        f.write(b"01234567", false);
        let mut sink = [0u8; 8];
        f.read(&mut sink, false, false);
        f.write(b"ABCDEF", false);
        let mut out = [0u8; 4];
        assert_eq!(f.read(&mut out, false, true), 4);
        assert_eq!(&out, b"ABCD");
    }

    #[test]
    fn a_peek_leaves_the_bytes_and_a_read_takes_them() {
        let mut f = Fifo::with_capacity(8);
        f.write(b"abcdef", false);
        let mut out = [0u8; 3];
        assert_eq!(f.read(&mut out, false, true), 3);
        assert_eq!(&out, b"abc");
        assert_eq!(f.len(), 6, "a peek takes nothing");
        assert_eq!(f.read(&mut out, false, false), 3);
        assert_eq!(&out, b"abc");
        assert_eq!(f.len(), 3);
        assert_eq!(drain(&mut f), b"def");
    }

    #[test]
    fn asking_for_more_than_it_holds_is_a_short_read() {
        // The C returned 1 and copied *nothing*, and its one caller ignored
        // that and handed the untouched buffer to the guest.
        let mut f = Fifo::with_capacity(64);
        f.write(b"hello", false);
        let mut out = [0xAAu8; 32];
        let n = f.read(&mut out, false, false);
        assert_eq!(n, 5);
        assert_eq!(&out[..5], b"hello");
        assert!(
            out[5..].iter().all(|b| *b == 0xAA),
            "and nothing past what it read was touched"
        );
    }

    #[test]
    fn an_empty_fifo_reads_nothing() {
        let mut f = Fifo::with_capacity(8);
        let mut out = [0xAAu8; 4];
        assert_eq!(f.read(&mut out, false, false), 0);
        assert_eq!(f.read(&mut out, true, true), 0);
        assert!(out.iter().all(|b| *b == 0xAA));
    }

    #[test]
    fn a_tail_read_that_consumes_leaves_nothing_behind_it() {
        // Taking from the end and keeping what came before would leave a hole,
        // so a consuming tail read drops the lot.
        let mut f = Fifo::with_capacity(8);
        f.write(b"abcdef", false);
        let mut out = [0u8; 2];
        assert_eq!(f.read(&mut out, true, false), 2);
        assert_eq!(&out, b"ef");
        assert!(f.is_empty(), "held {} bytes", f.len());
    }

    #[test]
    fn every_wrap_position_reads_back_what_was_written() {
        // The indexing is the whole subject, so every alignment of start
        // against the capacity gets exercised rather than the two that
        // happened to be tried.
        const CAP: usize = 7;
        for offset in 0..CAP * 2 {
            for take in 1..=CAP {
                let mut f = Fifo::with_capacity(CAP);
                // Move `start` to `offset % CAP`.
                let filler = vec![b'.'; offset % CAP];
                f.write(&filler, false);
                let mut sink = vec![0u8; filler.len()];
                f.read(&mut sink, false, false);

                let body: Vec<u8> = (0..CAP as u8).map(|i| b'a' + i).collect();
                f.write(&body, true);
                assert_eq!(f.len(), CAP);

                let mut head = vec![0u8; take];
                assert_eq!(f.read(&mut head, false, true), take);
                assert_eq!(head, body[..take], "head, offset {offset} take {take}");

                let mut tail = vec![0u8; take];
                assert_eq!(f.read(&mut tail, true, true), take);
                assert_eq!(
                    tail,
                    body[CAP - take..],
                    "tail, offset {offset} take {take}"
                );
            }
        }
    }

    #[test]
    fn a_zero_capacity_fifo_holds_nothing_and_does_not_divide_by_zero() {
        let mut f = Fifo::with_capacity(0);
        assert!(f.write(b"", false));
        assert!(!f.write(b"a", true), "nothing fits");
        let mut out = [0u8; 4];
        assert_eq!(f.read(&mut out, false, false), 0);
        assert_eq!(f.read(&mut out, true, false), 0);
    }
}
