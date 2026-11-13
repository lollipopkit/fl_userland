//! The bookkeeping behind `sendfile`, `splice` and `copy_file_range`.
//!
//! All three move bytes through a bounce buffer, and what they have to get
//! right is not the copying — it is where each side is left. A short write into
//! a pipe means the output took less than the input gave, and the difference
//! must not be consumed:
//!
//! ```text
//! splice(file, NULL, pipe, NULL, 200000)  ->  65536
//! lseek(file, 0, SEEK_CUR)                ->  69632
//! ```
//!
//! 4096 too far, one block, and a caller resuming from what it was told skips
//! it. The return value is right, the bytes that arrived are right and in
//! order, and nothing reports the difference.
//!
//! That was found twice on 2026-08-23, an hour apart, in two copies of the same
//! loop — `sendfile` had its own. The loops were merged into one, and this is
//! the arithmetic out of it: no descriptors, no buffers, no errno, just what
//! each cursor does given what the read and the write returned.
//!
//! # The asymmetry that makes it worth a type
//!
//! A side reading from an **explicit offset** never moves anything: the offset
//! advances by what was *transferred*, and there is nothing to undo. A side
//! reading from the descriptor's **own position** has already moved by what was
//! *read*, because the read did it, so the difference has to be seeked back.
//!
//! Two cases that look alike and are not. [`Step::put_back`] is zero for the
//! first and non-zero for the second, and the caller does not have to know
//! which it is holding.

use std::ffi::c_int;

/// Where one side of a transfer reads or writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cursor {
    /// The descriptor's own position, which the read or write moves itself.
    Position,
    /// An explicit offset, which the descriptor never sees.
    Offset(i64),
}

/// What to do after one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Go round again.
    Continue,
    /// Stop, and put this many bytes back on the input first.
    Stop { put_back: u32 },
    /// Stop with this errno. Nothing was transferred at all, so the caller has
    /// nothing better to report.
    Fail { errno: c_int, put_back: u32 },
}

/// One transfer in progress.
#[derive(Debug, Clone, Copy)]
pub struct Copier {
    input: Cursor,
    output: Cursor,
    remaining: u32,
    total: u32,
}

impl Copier {
    pub fn new(input: Cursor, output: Cursor, len: u32) -> Copier {
        Copier {
            input,
            output,
            remaining: len,
            total: 0,
        }
    }

    /// How many bytes to ask for next, or `None` when there is nothing left to
    /// do. `buf` is the bounce buffer's size.
    pub fn next_chunk(&self, buf: u32) -> Option<u32> {
        if self.remaining == 0 {
            return None;
        }
        Some(self.remaining.min(buf))
    }

    /// Where to read from, or `None` for the descriptor's own position.
    pub fn read_at(&self) -> Option<i64> {
        match self.input {
            Cursor::Position => None,
            Cursor::Offset(o) => Some(o),
        }
    }

    /// Where to write to, or `None` for the descriptor's own position.
    pub fn write_at(&self) -> Option<i64> {
        match self.output {
            Cursor::Position => None,
            Cursor::Offset(o) => Some(o),
        }
    }

    /// How much has been transferred.
    pub fn total(&self) -> u32 {
        self.total
    }

    /// The input offset, for writing back to the caller. Unchanged from what it
    /// was constructed with when the input used its own position.
    pub fn in_offset(&self) -> Option<i64> {
        match self.input {
            Cursor::Position => None,
            Cursor::Offset(o) => Some(o),
        }
    }

    pub fn out_offset(&self) -> Option<i64> {
        match self.output {
            Cursor::Position => None,
            Cursor::Offset(o) => Some(o),
        }
    }

    /// Records what one read and one write returned, and says what happens
    /// next.
    ///
    /// `nread` and `nwritten` are what the descriptors answered: negative is an
    /// errno, and `nwritten` is only meaningful when `nread` was positive —
    /// pass anything when it was not.
    ///
    /// The rules, and each is a row in the tests:
    ///
    /// - the read failed: stop. Nothing was consumed, so nothing goes back.
    /// - the read hit end of file: stop.
    /// - the write failed, or took nothing: the whole block goes back.
    /// - the write took some: the rest goes back, and this is the last round.
    /// - the write took it all: go round again.
    ///
    /// An error is only reported when nothing at all has been transferred.
    /// Once a byte has moved, the count is the answer and the errno is lost —
    /// which is what `sendfile(2)` documents and what the other two do too.
    pub fn after(&mut self, nread: i64, nwritten: i64) -> Step {
        if nread < 0 {
            return self.fail_or_stop(nread as c_int, 0);
        }
        if nread == 0 {
            return Step::Stop { put_back: 0 };
        }
        if nwritten <= 0 {
            let back = self.put_back(nread as u32);
            if nwritten < 0 {
                return self.fail_or_stop(nwritten as c_int, back);
            }
            return Step::Stop { put_back: back };
        }

        let moved = nwritten.min(nread) as u32;
        self.advance(moved);
        if nwritten < nread {
            return Step::Stop {
                put_back: self.put_back((nread - nwritten) as u32),
            };
        }
        if self.remaining == 0 {
            return Step::Stop { put_back: 0 };
        }
        Step::Continue
    }

    /// Bytes the input has to give back.
    ///
    /// Zero when it reads from an explicit offset: that offset only ever
    /// advances by what was transferred, so there is nothing to undo. The
    /// descriptor case has already moved by what was *read*.
    fn put_back(&self, unused: u32) -> u32 {
        match self.input {
            Cursor::Position => unused,
            Cursor::Offset(_) => 0,
        }
    }

    fn advance(&mut self, n: u32) {
        if let Cursor::Offset(o) = &mut self.input {
            *o += n as i64;
        }
        if let Cursor::Offset(o) = &mut self.output {
            *o += n as i64;
        }
        self.total += n;
        self.remaining -= n;
    }

    fn fail_or_stop(&self, errno: c_int, put_back: u32) -> Step {
        if self.total == 0 {
            Step::Fail { errno, put_back }
        } else {
            Step::Stop { put_back }
        }
    }
}

// The C ABI was here until 2026-09-09: `NO_OFFSET`, a `#[repr(C)] CStep`, six
// `copyloop_*` entry points over a `*mut Copier`, a test that round-tripped
// them and a second test asserting `struct copyloop` in `kernel/copyloop.h`
// reserved enough bytes. That header went with the rest on 2026-09-08 and the
// only caller of any of it was those two tests -- `crates/kernel/rwcalls` uses
// `Copier::new`, `Step` and `Cursor`, which is what this crate is.

#[cfg(test)]
mod tests {
    use super::*;

    const BUF: u32 = 4096;

    fn positions(len: u32) -> Copier {
        Copier::new(Cursor::Position, Cursor::Position, len)
    }

    #[test]
    fn a_transfer_that_all_goes_through() {
        let mut c = positions(BUF * 2);
        assert_eq!(c.next_chunk(BUF), Some(BUF));
        assert_eq!(c.after(BUF as i64, BUF as i64), Step::Continue);
        assert_eq!(c.total(), BUF);
        assert_eq!(c.next_chunk(BUF), Some(BUF));
        // The last block ends it without another round.
        assert_eq!(c.after(BUF as i64, BUF as i64), Step::Stop { put_back: 0 });
        assert_eq!(c.total(), BUF * 2);
        assert_eq!(c.next_chunk(BUF), None);
    }

    #[test]
    fn the_last_chunk_is_what_is_left() {
        let c = positions(100);
        assert_eq!(c.next_chunk(BUF), Some(100), "less than the buffer");
        let c = positions(0);
        assert_eq!(c.next_chunk(BUF), None, "a length of zero asks for nothing");
    }

    #[test]
    fn a_short_write_puts_the_rest_back() {
        // The defect this crate exists for.
        let mut c = positions(200000);
        assert_eq!(c.after(4096, 1000), Step::Stop { put_back: 3096 });
        assert_eq!(c.total(), 1000, "and only what went out is counted");
    }

    #[test]
    fn a_short_write_from_an_offset_puts_nothing_back() {
        // The asymmetry. An explicit offset only ever advances by what was
        // transferred, so there is nothing to undo -- and undoing it would move
        // the offset backwards past bytes that did go out.
        let mut c = Copier::new(Cursor::Offset(5000), Cursor::Position, 200000);
        assert_eq!(c.after(4096, 1000), Step::Stop { put_back: 0 });
        assert_eq!(c.in_offset(), Some(6000), "advanced by what was written");
        assert_eq!(c.total(), 1000);
    }

    #[test]
    fn a_write_that_takes_nothing_puts_the_whole_block_back() {
        let mut c = positions(200000);
        assert_eq!(c.after(4096, 0), Step::Stop { put_back: 4096 });
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn a_failed_write_puts_the_whole_block_back() {
        let mut c = positions(200000);
        assert_eq!(
            c.after(4096, -11),
            Step::Fail {
                errno: -11,
                put_back: 4096
            }
        );
    }

    #[test]
    fn an_error_after_something_moved_is_lost() {
        // sendfile(2) says so, and the other two do the same: once a byte has
        // moved, the count is the answer.
        let mut c = positions(200000);
        assert_eq!(c.after(4096, 4096), Step::Continue);
        assert_eq!(c.after(4096, -11), Step::Stop { put_back: 4096 });
        assert_eq!(c.total(), 4096);
    }

    #[test]
    fn a_failed_read_reports_the_errno_and_consumes_nothing() {
        let mut c = positions(200000);
        assert_eq!(
            c.after(-5, 0),
            Step::Fail {
                errno: -5,
                put_back: 0
            }
        );
        let mut c = positions(200000);
        c.after(4096, 4096);
        assert_eq!(
            c.after(-5, 0),
            Step::Stop { put_back: 0 },
            "unless something moved"
        );
    }

    #[test]
    fn end_of_file_stops_without_an_error() {
        let mut c = positions(200000);
        assert_eq!(c.after(0, 0), Step::Stop { put_back: 0 });
        assert_eq!(c.total(), 0);
    }

    #[test]
    fn a_short_read_is_not_a_short_write() {
        // The file had less than the buffer, and the output took all of it.
        // Nothing goes back and the transfer carries on.
        let mut c = positions(200000);
        assert_eq!(c.after(100, 100), Step::Continue);
        assert_eq!(c.total(), 100);
        assert_eq!(
            c.next_chunk(BUF),
            Some(BUF),
            "and asks for a full block next"
        );
    }

    #[test]
    fn both_offsets_advance_together() {
        let mut c = Copier::new(Cursor::Offset(1000), Cursor::Offset(50), 8192);
        assert_eq!(c.after(4096, 4096), Step::Continue);
        assert_eq!(c.in_offset(), Some(1000 + 4096));
        assert_eq!(c.out_offset(), Some(50 + 4096));
        assert_eq!(c.read_at(), Some(1000 + 4096));
        assert_eq!(c.write_at(), Some(50 + 4096));
    }

    #[test]
    fn a_position_has_no_offset_to_report() {
        let c = positions(10);
        assert_eq!(c.in_offset(), None);
        assert_eq!(c.out_offset(), None);
        assert_eq!(c.read_at(), None);
        assert_eq!(c.write_at(), None);
    }

    #[test]
    fn a_write_longer_than_the_read_is_not_believed() {
        // Nothing should answer this, and if something does, counting it would
        // report more transferred than was ever read.
        let mut c = positions(200000);
        assert_eq!(c.after(100, 4096), Step::Continue);
        assert_eq!(c.total(), 100);
    }

    #[test]
    fn the_whole_thing_is_never_over_delivered() {
        // Every path out, run to exhaustion: the total can never exceed the
        // length asked for, and remaining can never go negative -- which
        // `remaining -= nwritten` on an unclamped write would do.
        for written in [0i64, 1, 100, 4095, 4096, 8192] {
            let mut c = positions(4096);
            let _ = c.after(4096, written);
            assert!(
                c.total() <= 4096,
                "total {} for a write of {written}",
                c.total()
            );
        }
    }
}
