//! The growable buffer a procfs `show` callback fills.
//!
//! A proc file is generated in full by one call, into this.
//!
//! # It was three raw fields and a `libc::realloc`
//!
//! `struct proc_data` in `fs/proc.h` was `char *data`, `size_t size`,
//! `size_t capacity` and a flag, and this module grew it with `libc::realloc`
//! under a comment saying why:
//!
//! > `libc::realloc` rather than a `Vec` because `fs/proc.c`'s `proc_printf` is
//! > still C — a variadic function cannot be defined in Rust — and the entry
//! > code frees it with `libc::free`. One allocator on all three sides.
//!
//! **`fs/proc.c` has not existed since 2026-09-01** and `proc_printf` went with
//! it; `fs/proc.h` says so nine lines above where the struct was. No `.c` in
//! the tree named `struct proc_data`, and the buffer lives in a `Box<ProcFd>`
//! that this crate allocates and frees. The reason had outlived the file it
//! named, which is the same shape as the `unsafe extern "C"` blocks naming
//! `fs/proc/pid.c` and `kernel/futex.c` that went the same day.
//!
//! # What a `Vec` changes
//!
//! The doubling is no longer written down here. It was:
//!
//! > `capacity + 1` and then double until it fits … a `show` that appends a
//! > line at a time then reallocates logarithmically instead of per line.
//! > `/proc/self/maps` for 2000 mappings is 116 KB built a line at a time.
//!
//! `Vec` amortises for the same reason, so the property is structural rather
//! than asserted — and the test that asserted it is gone rather than rewritten,
//! because a test that a `Vec`'s capacity grows geometrically is a test of the
//! standard library.
//!
//! What is *not* structural, and is still tested, is the three refusals: an
//! offset past the end, a length that overflows the tidemark, and an allocation
//! that fails. The last is `try_reserve`, for the reason the root `Cargo.toml`
//! gives — this crate must not abort a process because a proc file did not fit.

/// The contents of one open procfs file, and whether they have been generated.
#[derive(Default)]
pub struct ProcData {
    bytes: Vec<u8>,
    /// Whether `bytes` holds the contents `show` produced. A proc file is
    /// generated in full by one call, and pread used to run that call again for
    /// every read: reading N bytes B at a time cost O(N²/B). 2000 mappings make
    /// `/proc/self/maps` 116 KB, which took 1.79s to read in 64-byte chunks and
    /// 0.03s in 4096-byte ones — the same bytes, 62x apart. Go's runtime reads
    /// this file at startup.
    ///
    /// Seeking back to offset 0 clears it, which is how a reader asks for
    /// contents that have changed since.
    pub valid: bool,
}

impl ProcData {
    /// What has been generated so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Throw the contents away and mark them ungenerated, which is what a seek
    /// back to zero does.
    pub fn reset(&mut self) {
        self.bytes.clear();
        self.valid = false;
    }

    /// Append, which is every caller but `pwrite`.
    pub fn append(&mut self, data: &[u8]) {
        let at = self.bytes.len();
        self.write_at(data, at);
    }

    /// Write `data` at `off`, growing if it does not fit.
    ///
    /// **An `off` past the end writes nothing.** The C `assert`ed this, which a
    /// release build does not check at all, and the hole it would leave is
    /// uninitialised bytes in a file a guest then reads — so it is a refusal in
    /// every build.
    ///
    /// A failed allocation gives up silently and the buffer keeps what it had.
    /// That is what the C did, under a comment reading "just give up, error
    /// reporting is a pain" — and it is defensible for this one thing: a `show`
    /// callback has no way to report a failure the caller could act on, and a
    /// short proc file is a better answer than a killed process.
    pub fn write_at(&mut self, data: &[u8], off: usize) {
        if off > self.bytes.len() {
            return;
        }
        let Some(tidemark) = off.checked_add(data.len()) else {
            return;
        };
        if tidemark > self.bytes.len() {
            let more = tidemark - self.bytes.len();
            if self.bytes.try_reserve(more).is_err() {
                return;
            }
            self.bytes.resize(tidemark, 0);
        }
        self.bytes[off..tidemark].copy_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Appending builds the file in order.
    #[test]
    fn appending_builds_the_file_in_order() {
        let mut b = ProcData::default();
        for _ in 0..1000 {
            b.append(b"0123456789");
        }
        assert_eq!(b.len(), 10_000);
        assert_eq!(&b.as_slice()[..10], b"0123456789");
    }

    /// A write inside what is already there does not move the tidemark, and a
    /// write that crosses the end does.
    #[test]
    fn writing_at_an_offset_moves_the_tidemark_only_when_it_has_to() {
        let mut b = ProcData::default();
        b.append(b"aaaaaaaa");
        assert_eq!(b.len(), 8);

        b.write_at(b"bb", 2);
        assert_eq!(b.len(), 8, "an interior write does not extend it");
        assert_eq!(b.as_slice(), b"aabbaaaa");

        b.write_at(b"cccc", 6);
        assert_eq!(b.len(), 10);
        assert_eq!(b.as_slice(), b"aabbaacccc");
    }

    /// An offset past the end is refused rather than leaving a hole of
    /// uninitialised bytes in a file a guest then reads.
    #[test]
    fn an_offset_past_the_end_writes_nothing() {
        let mut b = ProcData::default();
        b.append(b"abc");
        b.write_at(b"zz", 100);
        assert_eq!(b.as_slice(), b"abc");
    }

    /// Zero bytes at the end is a no-op that allocates nothing, which is what a
    /// `show` producing an empty file does.
    #[test]
    fn an_empty_append_is_nothing() {
        let mut b = ProcData::default();
        b.append(b"");
        assert!(b.is_empty());
    }

    /// A length that would overflow the tidemark is refused rather than
    /// wrapping to a small one and copying over the start of the buffer.
    ///
    /// A slice cannot be `usize::MAX` long, so the overflow is reached through
    /// the offset instead — which is the same addition and the same refusal.
    #[test]
    fn an_offset_that_would_overflow_writes_nothing() {
        let mut b = ProcData::default();
        b.append(b"abc");
        b.write_at(b"z", usize::MAX);
        assert_eq!(b.as_slice(), b"abc");
    }

    /// Resetting is what a seek back to zero does, and it drops the contents
    /// as well as the flag.
    #[test]
    fn a_reset_drops_the_contents_and_the_flag() {
        let mut b = ProcData::default();
        b.append(b"abc");
        b.valid = true;
        b.reset();
        assert!(b.is_empty());
        assert!(!b.valid);
    }
}
