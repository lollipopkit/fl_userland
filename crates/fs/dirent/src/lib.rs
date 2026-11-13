//! The `getdents64` wire format.
//!
//! One `getdents64` answer is a run of variable-length records:
//!
//! ```text
//! offset  0   d_ino     u64
//!         8   d_off     i64
//!        16   d_reclen  u16
//!        18   d_type    u8
//!        19   d_name    NUL-terminated, then padding to a multiple of 8
//! ```
//!
//! The caller walks it by `d_reclen`, so a record whose length disagrees with
//! its contents corrupts every record after it. Two things went wrong in the C
//! this replaces, and both are structural rather than careless:
//!
//! - Records were not rounded up to eight, so `d_ino` and `d_off` inside the
//!   second and later records were unaligned.
//! - Once the rounding was added, the length was computed in two places — once
//!   to size a stack buffer and once to fill it — and only one of them
//!   accounted for it. A name whose length was 5, 6, 7 or 8 modulo 8 wrote past
//!   the end of the buffer. `ls` of a directory holding a five-character name
//!   did it, and ASan was the only thing that noticed.
//!
//! Here the buffer owns its own length. `push` appends a whole record or
//! reports that it did not fit; there is no second expression to disagree with
//! the first, and no fixed-size buffer to run off the end of.

/// Byte offset of `d_name` — the size of the fixed header.
const NAME_OFFSET: usize = 19;
/// Linux rounds each record up to eight so that every record, and so every
/// `d_ino` and `d_off` inside one, starts aligned.
const ALIGN: usize = 8;

/// The bytes one record occupies, rounding included.
fn reclen(name_len: usize) -> usize {
    (NAME_OFFSET + name_len + 1).next_multiple_of(ALIGN)
}

/// A `getdents64` answer under construction.
///
/// `limit` is the guest's buffer size, which the guest chooses, so the backing
/// store grows towards it rather than being allocated up front — a `getdents64`
/// naming a four-gigabyte buffer must not become a four-gigabyte allocation
/// before a single entry has been read.
pub struct DirentBuf {
    bytes: Vec<u8>,
    limit: usize,
}

impl DirentBuf {
    pub fn new(limit: usize) -> Self {
        DirentBuf {
            bytes: Vec::new(),
            limit,
        }
    }

    /// Appends one record. Answers `false` if it does not fit in what is left
    /// of the guest's buffer, having appended nothing — the caller seeks the
    /// directory back and returns what it has.
    pub fn push(&mut self, ino: u64, off: i64, d_type: u8, name: &[u8]) -> bool {
        let len = reclen(name.len());
        if len > self.limit - self.bytes.len() {
            return false;
        }
        let start = self.bytes.len();
        // try_reserve rather than reserve: the size is the guest's to choose,
        // and a mount that fails is better than an abort. See the panic note in
        // CLAUDE.md's Rust section.
        if self.bytes.try_reserve(len).is_err() {
            return false;
        }
        // The padding the rounding adds is handed to the guest, so it is zero
        // rather than whatever was here before.
        self.bytes.resize(start + len, 0);
        let rec = &mut self.bytes[start..start + len];
        rec[0..8].copy_from_slice(&ino.to_le_bytes());
        rec[8..16].copy_from_slice(&off.to_le_bytes());
        rec[16..18].copy_from_slice(&(len as u16).to_le_bytes());
        rec[18] = d_type;
        rec[NAME_OFFSET..NAME_OFFSET + name.len()].copy_from_slice(name);
        true
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

// The C ABI was here: five functions so that fs/dir.c could build a record
// buffer through an opaque pointer. `getdents64` is crates/fs/dircalls now and
// uses `DirentBuf` directly, so no C can reach them -- which is what
// tools/dead-exports.py reported the moment the C went. The split it existed
// for is unchanged: the loop holds the descriptor and does the one write into
// guest memory, and only the record format is here.

#[cfg(test)]
mod tests {
    use super::*;

    /// The rounding, at every length across three turns of it. This is the
    /// arithmetic the C got wrong in two different ways.
    #[test]
    fn record_lengths_are_aligned_and_fit_the_name() {
        for name_len in 0..=24usize {
            let len = reclen(name_len);
            assert_eq!(len % ALIGN, 0, "length {name_len} gave an unaligned {len}");
            let needed = NAME_OFFSET + name_len + 1;
            assert!(
                len >= needed,
                "length {name_len} gave {len}, too small for the name and its NUL"
            );
            assert!(
                len < needed + ALIGN,
                "length {name_len} gave {len}, more than one round of padding"
            );
        }
    }

    #[test]
    fn a_record_reads_back_the_way_a_caller_walks_it() {
        let mut buf = DirentBuf::new(4096);
        assert!(buf.push(42, 7, 4, b"hello"));
        let b = buf.as_slice();
        assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), 42);
        assert_eq!(i64::from_le_bytes(b[8..16].try_into().unwrap()), 7);
        let len = u16::from_le_bytes(b[16..18].try_into().unwrap()) as usize;
        assert_eq!(len, 32); // 19 + 5 + 1 = 25, rounded to 32
        assert_eq!(len, b.len());
        assert_eq!(b[18], 4);
        assert_eq!(&b[19..24], b"hello");
        assert_eq!(b[24], 0, "the name is NUL-terminated");
        assert!(b[25..].iter().all(|&x| x == 0), "the padding is zeroed");
    }

    #[test]
    fn records_follow_one_another_by_reclen() {
        let mut buf = DirentBuf::new(4096);
        for (i, name) in ["a", "bb", "ccccc", "dddddddd"].iter().enumerate() {
            assert!(buf.push(i as u64, i as i64, 8, name.as_bytes()));
        }
        // Walk it the way the guest does.
        let b = buf.as_slice();
        let mut at = 0usize;
        let mut names = Vec::new();
        while at < b.len() {
            let len = u16::from_le_bytes(b[at + 16..at + 18].try_into().unwrap()) as usize;
            assert_eq!(at % ALIGN, 0, "record at {at} is not aligned");
            let name = &b[at + 19..at + len];
            let end = name.iter().position(|&c| c == 0).unwrap();
            names.push(String::from_utf8_lossy(&name[..end]).into_owned());
            at += len;
        }
        assert_eq!(names, ["a", "bb", "ccccc", "dddddddd"]);
        assert_eq!(at, b.len(), "the last record ends exactly at the end");
    }

    #[test]
    fn a_record_that_does_not_fit_appends_nothing() {
        let mut buf = DirentBuf::new(32);
        assert!(buf.push(1, 1, 8, b"aaaaa")); // exactly 32
        assert_eq!(buf.as_slice().len(), 32);
        assert!(!buf.push(2, 2, 8, b"b"), "a full buffer refuses");
        assert_eq!(buf.as_slice().len(), 32, "and is left as it was");
    }

    #[test]
    fn a_buffer_too_small_for_one_record_stays_empty() {
        let mut buf = DirentBuf::new(8);
        assert!(!buf.push(1, 1, 8, b"name"));
        assert!(buf.as_slice().is_empty());
    }

    /// The guest picks `limit`, so it must not become an allocation before an
    /// entry has been read.
    #[test]
    fn a_huge_limit_allocates_nothing_up_front() {
        let buf = DirentBuf::new(usize::MAX / 2);
        assert_eq!(buf.as_slice().len(), 0);
    }
}
