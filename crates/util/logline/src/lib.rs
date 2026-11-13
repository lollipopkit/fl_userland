//! Turning a stream of `printk` fragments into whole lines.
//!
//! `printk` is called with whatever a caller has to say, which is often not a
//! whole line: `crates/kernel/offloadexec` prints a guest's entire `argv` one
//! argument at a time and only then a newline. So the fragments accumulate in a
//! per-thread buffer until a `\n` arrives, and everything up to the last one is
//! handed to the output handler.
//!
//! Per **thread**, because two threads printing halves of two lines into one
//! buffer would interleave them into nonsense. The lock in `kernel/log.c`
//! covers the *output*, which is a different thing: it stops two finished lines
//! interleaving inside one `fprintf`.
//!
//! # The bound is the whole point
//!
//! The C this replaces had `static __thread char buf[16384]` and, until
//! 2026-09-02, an **unbounded `vsprintf`** into it. A guest chooses both the
//! number of its `execve` arguments and their contents, so an `execve` with
//! enough of them wrote past the end of that buffer — from a log statement.
//!
//! The rule when a fragment does not fit is not "drop it". A full buffer that
//! never drains silently swallows every line after it, which is a worse failure
//! than a wrong one: keep what fits, **end the line**, and let it drain. A
//! truncated log line is a visible failure.
//!
//! There is a second bound the C did not have. A caller that prints megabytes
//! with no newline at all fills the buffer, and the C then truncated *every*
//! subsequent fragment for ever — the buffer stayed full because nothing ended
//! the line. Ending it is what makes the next fragment start from empty.

/// The ring every line is appended to and `syslog(2)` reads.
pub mod klog;
pub mod printk;
pub mod sink;

/// The two a caller with a Rust string wants. At the root because that is what
/// nine call sites across nine crates say `logline::printk` and `logline::die`
/// for; `sink` is where they live and is an implementation detail of where the
/// bytes go.
pub use sink::{die, printk};

/// How much of a line is kept. The C's number, and it is the size of one
/// `execve`'s worth of arguments rather than of any line anybody writes.
pub const CAPACITY: usize = 16384;

/// A partial line, per thread.
pub struct LineBuffer {
    buf: Vec<u8>,
}

impl Default for LineBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl LineBuffer {
    pub fn new() -> LineBuffer {
        LineBuffer { buf: Vec::new() }
    }

    /// Add `bytes`, and hand each **complete** line to `out` without its
    /// newline. What follows the last newline stays here.
    ///
    /// A NUL in the middle of `bytes` is kept: this counts bytes, and a log
    /// line that contains one is a log line that contains one. The C used
    /// `strchr`, which would have ended the line there and dropped the rest.
    pub fn append(&mut self, bytes: &[u8], mut out: impl FnMut(&[u8])) {
        let room = CAPACITY - 1 - self.buf.len();
        if bytes.len() > room {
            // Keep what fits and end the line, so the buffer drains. Without
            // this a single over-long message wedges the buffer full and every
            // later line is lost with no sign of it.
            self.buf.extend_from_slice(&bytes[..room]);
            self.buf.push(b'\n');
        } else {
            self.buf.extend_from_slice(bytes);
        }

        let mut start = 0;
        while let Some(i) = self.buf[start..].iter().position(|&b| b == b'\n') {
            let end = start + i;
            out(&self.buf[start..end]);
            start = end + 1;
        }
        self.buf.drain(..start);
    }

    /// What is held, for a test. Never a whole line: a newline would have
    /// drained it.
    pub fn pending(&self) -> &[u8] {
        &self.buf
    }
}

// ----------------------------------------------------- the per-thread buffer

use std::cell::RefCell;

thread_local! {
    /// One partial line per thread; see the module comment for why per thread.
    static PENDING: RefCell<LineBuffer> = RefCell::new(LineBuffer::new());
}

/// Run `f` on this thread's partial line.
///
/// A reentrant call — a `printk` from inside an output handler — finds the
/// buffer borrowed and does nothing. Dropping the fragment is better than a
/// panic on a path that cannot unwind, and nothing in this tree does it.
pub(crate) fn with_pending(f: impl FnOnce(&mut LineBuffer)) {
    PENDING.with(|p| {
        if let Ok(mut buf) = p.try_borrow_mut() {
            f(&mut buf);
        }
    });
}

/* `logline_append` was here: a `#[no_mangle]` entry point taking a C callback,
 * because `kernel/log.c` drove the line assembly. The C hands whole messages to
 * `sink::log_emit` now and the callback is a Rust closure, so there is nothing
 * left for an `extern "C"` to be an interface *to*. Removed 2026-09-06. */

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(b: &mut LineBuffer, s: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        b.append(s, |l| out.push(l.to_vec()));
        out
    }

    #[test]
    fn a_fragment_without_a_newline_is_held() {
        let mut b = LineBuffer::new();
        assert!(lines(&mut b, b"hello ").is_empty());
        assert!(lines(&mut b, b"world").is_empty());
        assert_eq!(b.pending(), b"hello world");
        assert_eq!(lines(&mut b, b"\n"), vec![b"hello world".to_vec()]);
        assert!(b.pending().is_empty());
    }

    /// The case `offloadexec` produces: one argument per call, a newline at the
    /// end. Nothing is emitted until the newline and then exactly one line is.
    #[test]
    fn many_fragments_make_one_line() {
        let mut b = LineBuffer::new();
        for arg in ["exec", " /bin/sh", " -c", " true"] {
            assert!(lines(&mut b, arg.as_bytes()).is_empty());
        }
        assert_eq!(lines(&mut b, b"\n"), vec![b"exec /bin/sh -c true".to_vec()]);
    }

    #[test]
    fn several_newlines_in_one_fragment_are_several_lines() {
        let mut b = LineBuffer::new();
        assert_eq!(
            lines(&mut b, b"one\ntwo\nthree"),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
        assert_eq!(b.pending(), b"three");
    }

    /// An empty line is a line. `printk("\n")` prints one.
    #[test]
    fn an_empty_line_is_emitted() {
        let mut b = LineBuffer::new();
        assert_eq!(lines(&mut b, b"\n\n"), vec![Vec::new(), Vec::new()]);
    }

    /// The overflow the C had. Nothing may be written past `CAPACITY`, and the
    /// line has to *end* so the buffer drains — which is the part that is easy
    /// to get wrong, because dropping the fragment also stops the overflow and
    /// then loses every line after it for ever.
    #[test]
    fn an_over_long_fragment_is_truncated_and_ended() {
        let mut b = LineBuffer::new();
        let huge = vec![b'x'; CAPACITY * 4];
        let got = lines(&mut b, &huge);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].len(), CAPACITY - 1);
        assert!(got[0].iter().all(|&c| c == b'x'));
        assert!(b.pending().is_empty(), "the buffer drained");

        // And the next line is unaffected, which is what "drains" has to mean.
        assert_eq!(lines(&mut b, b"after\n"), vec![b"after".to_vec()]);
    }

    /// Filling it a fragment at a time reaches the same rule. The C truncated
    /// against the *remaining* room, so this is the path its `room` arithmetic
    /// was for.
    #[test]
    fn accumulating_to_the_bound_ends_the_line_too() {
        let mut b = LineBuffer::new();
        let chunk = vec![b'y'; 4096];
        let mut emitted = Vec::new();
        for _ in 0..5 {
            b.append(&chunk, |l| emitted.push(l.to_vec()));
        }
        assert_eq!(emitted.len(), 1, "one truncated line, not five");
        assert_eq!(emitted[0].len(), CAPACITY - 1);
        assert!(b.pending().len() < CAPACITY);
    }

    /// A NUL is a byte. The C split on `strchr` and would have lost whatever
    /// followed one in the same fragment.
    #[test]
    fn a_nul_does_not_end_a_line() {
        let mut b = LineBuffer::new();
        assert_eq!(lines(&mut b, b"a\0b\n"), vec![b"a\0b".to_vec()]);
    }

    /// And the path seven crates reached this through **dropped the whole
    /// line** rather than the tail: each had its own
    /// `if let Ok(s) = CString::new(msg) { iul_printk("%s\n", s) }`, so a
    /// message with an interior NUL went nowhere at all. The two answers are
    /// asserted side by side because that is the difference — `printk` takes a
    /// `&str` and hands the sink bytes, which cannot fail on a NUL.
    #[test]
    fn the_cstring_route_dropped_a_line_this_one_keeps() {
        assert!(
            std::ffi::CString::new("a\0b").is_err(),
            "the old route's guard: CString::new fails, the `if let Ok` does not run, \
             and the line is gone"
        );
        let mut b = LineBuffer::new();
        assert_eq!(lines(&mut b, "a\0b".as_bytes()), Vec::<Vec<u8>>::new());
        assert_eq!(lines(&mut b, b"\n"), vec![b"a\0b".to_vec()]);
    }
}
