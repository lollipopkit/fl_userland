//! A pipe: a bounded queue of bytes with a reader end and a writer end.
//!
//! `fs/pipe.c` used to be 81 lines that called the host's `pipe(2)` and handed
//! each end to `realfs_fdops`, so every question a guest asked about a pipe was
//! answered by macOS. `pipe_probe` found nineteen places where macOS and Linux
//! disagree, and four of them cannot be fixed from outside:
//!
//! - **`F_GETPIPE_SZ` and `F_SETPIPE_SZ` do not exist on macOS.** Linux reports
//!   65536, rounds a request up to a power of two, floors it at one page,
//!   answers `EPERM` above the sysctl maximum and `EBUSY` when asked to shrink
//!   below what is already queued.
//! - **`O_DIRECT` packet mode does not exist on macOS.** Each write is one
//!   record; each read returns one record and discards whatever it had no room
//!   for.
//! - **`PIPE_BUF` is 512 on macOS and 4096 on Linux.** A write up to `PIPE_BUF`
//!   is guaranteed not to interleave with another writer's, and every log
//!   writer in existence relies on the Linux number. Measured: a 4096-byte
//!   write into a pipe with 100 bytes of room put 100 bytes in here, where a
//!   real kernel answers `EAGAIN` and leaves the record whole.
//! - **`tee(2)` copies bytes out of a pipe without consuming them**, which
//!   cannot be expressed against a host pipe at all. It was `ENOSYS`.
//!
//! # The shape
//!
//! One [`Pipe`] and two [`End`]s, each held by a `struct fd`. The buffer, the
//! capacity and the two open counts live behind one [`GuestLock`] — C's, because
//! `wait_for` is the only wait a guest signal can interrupt and a reader parked
//! on a Rust condvar could not be killed.
//!
//! Waking is two-way and asymmetric, which is the part worth reading twice: a
//! *write* has to wake readers, and a *close* of the last writer has to wake
//! them too — with end-of-file rather than data. Each end therefore holds the
//! **other** end's poll list as well as its own condition.

use std::collections::VecDeque;
use std::sync::{Arc, PoisonError, RwLock};

use pollset::Watchers;
use util_guestlock::{GuestLock, Woke};

mod end;

pub use guest_errno::isize_::{EAGAIN, EBADF, EBUSY, EFAULT, EINTR, EINVAL, EPERM, EPIPE};

pub const POLL_READ: i32 = 1;
pub const POLL_WRITE: i32 = 4;
pub const POLL_ERR: i32 = 8;
pub const POLL_HUP: i32 = 16;

/// The most bytes a write is promised not to interleave. **4096, not the
/// host's 512** — this is the number `write(2)` documents and the reason a
/// pipe cannot simply be the host's.
pub const PIPE_BUF: usize = 4096;

/// What a pipe holds before a write has to wait: Linux's default, sixteen
/// pages.
pub const DEFAULT_CAPACITY: usize = 65536;

/// The floor `F_SETPIPE_SZ` rounds up to.
pub const MIN_CAPACITY: usize = 4096;

/// `/proc/sys/fs/pipe-max-size`. A request above it is `EPERM` for a caller
/// without `CAP_SYS_RESOURCE`, which is what a real kernel answered for
/// `0x7fffffff` — measured, rather than derived from the capability rules,
/// because the container runs as root and still said `EPERM`. A caller *with*
/// it may go to [`LARGEST_CAPACITY`].
pub const MAX_CAPACITY: usize = 1024 * 1024;

/// The most `round_pipe_size` can express: a request above 2^31 rounds to
/// nothing and is `EINVAL` whoever asks.
pub const LARGEST_CAPACITY: usize = 1 << 31;

/// Conditions on the lock. Two, because a reader and a writer wait for
/// opposite things and waking both for either is how a full pipe turns into a
/// spin.
const READABLE: u32 = 0;
const WRITABLE: u32 = 1;

/// A run of queued bytes and whether it is a **packet**: one record from one
/// write made in `O_DIRECT` mode, which a read takes at most one of and
/// discards the rest of. Linux keeps this per buffer (`PIPE_BUF_FLAG_PACKET`),
/// and so a pipe can hold packets and plain bytes at once -- the mode is the
/// writing description's and `F_SETFL` can change it between writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Segment {
    len: usize,
    packet: bool,
}

/// The queue itself.
struct Inner {
    /// A byte queue, and how it is divided. Two structures rather than a
    /// `VecDeque<Vec<u8>>` because the byte mode is the one that matters for
    /// throughput, and it must not pay for the other: byte-mode writes merge
    /// into one segment, so a pipe nobody put in packet mode has at most one.
    /// The segment lengths sum to `buf.len()`.
    buf: VecDeque<u8>,
    segments: VecDeque<Segment>,
    capacity: usize,
    /// How many descriptors are open on each end. A read with no writers is
    /// end-of-file; a write with no readers is `EPIPE`.
    readers: u32,
    writers: u32,
    /// Whether the write end is in `O_DIRECT` mode: set by `pipe2(O_DIRECT)`
    /// and changed by `F_SETFL` on the write end. Linux reads it from the
    /// writing *file* at each write; this object knows one write end, so the
    /// flag lives here and is read at each write all the same.
    packet_mode: bool,
}

impl Inner {
    fn room(&self) -> usize {
        self.capacity.saturating_sub(self.buf.len())
    }

    /// Queues `bytes` as one packet, or as plain bytes merged into the plain
    /// run before them.
    fn push(&mut self, bytes: &[u8], packet: bool) {
        self.buf.extend(bytes.iter().copied());
        match self.segments.back_mut() {
            Some(last) if !last.packet && !packet => last.len += bytes.len(),
            _ => self.segments.push_back(Segment {
                len: bytes.len(),
                packet,
            }),
        }
    }

    /// What a read of up to `want` bytes gets: how many reach the caller and
    /// how many leave the queue. **They are not the same number**, and only
    /// because of packets: a short read of a record discards the rest of it,
    /// which is what makes reading 5 bytes of a 30-byte record answer 5 and
    /// then move to the next record. Plain bytes are never discarded, and a
    /// read runs across plain runs and into the packet after them -- but never
    /// past a packet, which is `pipe_read`'s `total_len = chars` on a packet
    /// buffer. The first version of this used one variable for both numbers,
    /// so an ordinary short read threw away everything it had not asked for.
    fn take(&mut self, want: usize) -> (usize, usize) {
        let (mut give, mut consume) = (0, 0);
        while give < want {
            let Some(seg) = self.segments.front_mut() else {
                break;
            };
            let n = seg.len.min(want - give);
            give += n;
            if seg.packet {
                consume += seg.len;
                self.segments.pop_front();
                break;
            }
            consume += n;
            seg.len -= n;
            if seg.len == 0 {
                self.segments.pop_front();
            }
        }
        (give, consume)
    }
}

/// The object both descriptors share.
pub struct Pipe {
    inner: GuestLock<Inner>,
    /// The poll lists of the descriptions open for reading and for writing. A
    /// write notifies the readers'; a close notifies the other side's.
    ///
    /// One raw pointer per side until 2026-10-18, set by an `unsafe fn` whose
    /// caller promised to clear it before the list was freed -- and one per
    /// side meant one description per side, so a second one (reopening
    /// `/proc/<pid>/fd/<n>`) would have overwritten the first's and its
    /// pollers never woken. A description's list is an `Arc`, so holding it
    /// here needs no promise.
    read_watchers: RwLock<Vec<Arc<Watchers>>>,
    write_watchers: RwLock<Vec<Arc<Watchers>>>,
}

impl Pipe {
    fn notify(&self, which: &RwLock<Vec<Arc<Watchers>>>, events: u32) {
        for w in which.read().unwrap_or_else(PoisonError::into_inner).iter() {
            w.notify(events);
        }
    }
}

/// What one description of a pipe holds: the pipe, and which way it is open.
/// `O_RDWR` is both, which only a reopen through `/proc/<pid>/fd` makes.
pub struct End {
    pipe: Arc<Pipe>,
    reading: bool,
    writing: bool,
}

/// Creates a pipe and both its ends.
pub fn new(packet_mode: bool) -> (Box<End>, Box<End>) {
    let inner = Inner {
        buf: VecDeque::new(),
        segments: VecDeque::new(),
        capacity: DEFAULT_CAPACITY,
        readers: 1,
        writers: 1,
        packet_mode,
    };
    let pipe = Arc::new(Pipe {
        inner: GuestLock::new(inner, 2),
        read_watchers: RwLock::new(Vec::new()),
        write_watchers: RwLock::new(Vec::new()),
    });
    (
        Box::new(End {
            pipe: pipe.clone(),
            reading: true,
            writing: false,
        }),
        Box::new(End {
            pipe,
            reading: false,
            writing: true,
        }),
    )
}

/// A second descriptor on the same end: `dup`, or a `fork` that inherits it.
///
/// Not the same as cloning the `Arc`. The counts are what `EPIPE` and
/// end-of-file are decided by, so a duplicate has to be counted.
impl Clone for End {
    fn clone(&self) -> End {
        self.reopen(self.reading, self.writing)
    }
}

impl Drop for End {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests;
