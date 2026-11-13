//! The kernel log ring: what every `printk` line is appended to, and what
//! `syslog(2)` reads.
//!
//! **Here and not in `crates/kernel/syslogcalls`** since 2026-09-29. The ring
//! was that crate's, so this one -- which every other crate prints through --
//! depended on a *syscall* crate to append a line, and through it on
//! `kernel-usercopy` and `kernel-taskview`. The log is below the syscall that
//! reads it; `syslogcalls` keeps the argument rules and the copy into guest
//! memory and asks this for the bytes.
//!
//! One consuming cursor rather than Linux's per-reader sequence, and a `CLEAR`
//! that moves a boundary rather than draining: `syslogcalls`' module comment
//! says why and what `SIZE_UNREAD` reports because of it.

use std::sync::Mutex;

use fifo::Fifo;

/// A megabyte, as the C had.
const LOG_CAPACITY: usize = 1 << 20;

/// How many bytes a read of `len` may return, given what the log holds.
///
/// The clamp is against the **contents**, not the capacity. Clamping to the
/// capacity is what handed a guest a megabyte of the emulator's heap: the ring
/// copied nothing when asked for more than it held, and the caller reported the
/// length it had asked for.
///
/// `max_since_clear` bounds the tail-reading commands only: a `CLEAR` moves that
/// boundary, and bytes before it are not part of what `READ_ALL` reports.
pub fn readable(len: i32, held: usize, max_since_clear: usize, tail: bool) -> usize {
    if len <= 0 {
        return 0;
    }
    let available = if tail {
        held.min(max_since_clear)
    } else {
        held
    };
    (len as usize).min(available)
}

/// The ring and the boundary a `CLEAR` moves.
struct Klog {
    ring: Fifo,
    /// How much of the ring the tail-reading commands may see. Capped at the
    /// capacity, because a ring that has wrapped holds no more than that
    /// however much has been written through it.
    max_since_clear: usize,
}

/// Created on first use. `Fifo::with_capacity` allocates a megabyte and
/// `Mutex::new` is the only const part, so there is nothing to build at load
/// time — which is also what the C did, for the same reason.
static KLOG: Mutex<Option<Klog>> = Mutex::new(None);

impl Klog {
    fn append(&mut self, bytes: &[u8]) {
        self.ring.write(bytes, true);
        self.max_since_clear = self
            .max_since_clear
            .saturating_add(bytes.len())
            .min(self.ring.capacity());
    }
}

/// Runs `f` over the log, creating it if this is the first use.
fn with_log<T>(f: impl FnOnce(&mut Klog) -> T) -> T {
    let mut guard = KLOG.lock().unwrap_or_else(|e| e.into_inner());
    let log = guard.get_or_insert_with(|| Klog {
        ring: Fifo::with_capacity(LOG_CAPACITY),
        max_since_clear: 0,
    });
    f(log)
}

/// Append a line to the kernel log, which `sys_syslog` reads.
///
/// Called by this crate's sink with the output lock held, once per
/// line. It was `#[unsafe(no_mangle)] extern "C"` taking a pointer and a length
/// until 2026-09-06, because `kernel/log.c` called it; with the caller in Rust
/// there is nothing on the other side of that boundary, and an export no C can
/// reach is an optimisation barrier rather than an interface.
pub fn append(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    with_log(|log| log.append(bytes));
}

/// Take at most `len` bytes out of the ring, and optionally clear.
///
/// **One acquisition.** The clamp and the read have to see the same log, or a
/// concurrent `printk` between them makes the count describe a ring that is no
/// longer there — which is how the disclosure this replaces worked in the first
/// place. The copy into guest memory is deliberately *outside* it: `user_write`
/// takes the address space's lock, and holding the log across that would put
/// two global locks in an order nothing else here uses.
///
/// The buffer is the **clamped** length, so a caller that asks for more than
/// the log holds allocates nothing extra — `syslog(READ, buf, 1 << 20)` against
/// an empty log allocates nothing at all.
pub fn take(len: i32, tail: bool, peek: bool, clear: bool) -> Vec<u8> {
    with_log(|log| {
        let want = readable(len, log.ring.len(), log.max_since_clear, tail);
        let mut out = vec![0u8; want];
        // The count, not a status: a short read reported as a long one is how
        // the guest got a megabyte of heap.
        let got = log.ring.read(&mut out, tail, peek);
        out.truncate(got);
        if clear {
            log.max_since_clear = 0;
        }
        out
    })
}

/// Move the boundary the tail-reading commands stop at: `SYSLOG_ACTION_CLEAR`.
pub fn clear() {
    with_log(|log| log.max_since_clear = 0);
}

/// Bytes in the ring: `SYSLOG_ACTION_SIZE_UNREAD`.
pub fn len() -> usize {
    with_log(|log| log.ring.len())
}

/// The ring's size: `SYSLOG_ACTION_SIZE_BUFFER`.
pub fn capacity() -> usize {
    with_log(|log| log.ring.capacity())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The clamp is against the contents. Asking for a megabyte of an empty log
    /// is zero bytes, not a megabyte of whatever the allocator handed over.
    #[test]
    fn a_read_is_bounded_by_what_the_log_holds() {
        assert_eq!(readable(1 << 20, 0, 0, false), 0);
        assert_eq!(readable(1 << 20, 40, 40, false), 40);
        assert_eq!(readable(10, 40, 40, false), 10);
        assert_eq!(readable(0, 40, 40, false), 0);
        assert_eq!(readable(-1, 40, 40, false), 0);
    }

    /// A clear moves the boundary the tail-reading commands stop at, and does
    /// not affect the consuming one.
    #[test]
    fn a_clear_bounds_the_tail_reads_only() {
        assert_eq!(readable(100, 40, 0, true), 0);
        assert_eq!(readable(100, 40, 0, false), 40);
        assert_eq!(readable(100, 40, 10, true), 10);
    }

    #[test]
    fn the_boundary_never_exceeds_the_ring() {
        let mut log = Klog {
            ring: Fifo::with_capacity(8),
            max_since_clear: 0,
        };
        for _ in 0..10 {
            log.append(b"abcd");
        }
        assert_eq!(log.max_since_clear, 8);
        assert_eq!(log.ring.len(), 8);
    }

    /// What `READ_CLEAR` answers. The value it used to answer was the clear
    /// arm's, which it reached by falling through.
    #[test]
    fn read_clear_answers_the_count_and_then_clears() {
        let mut log = Klog {
            ring: Fifo::with_capacity(64),
            max_since_clear: 0,
        };
        log.append(b"hello\n");
        let want = readable(64, log.ring.len(), log.max_since_clear, true);
        assert_eq!(want, 6, "the count a READ_CLEAR has to return");
        log.max_since_clear = 0;
        assert_eq!(
            readable(64, log.ring.len(), log.max_since_clear, true),
            0,
            "and a second one has nothing left to report"
        );
    }
}
