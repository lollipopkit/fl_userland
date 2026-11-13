//! Inode numbers for procfs entries.
//!
//! Two requirements, and only two: `stat` of one file twice has to agree with
//! itself, and no two files may agree with each other.
//!
//! The C composed a number out of three fields:
//!
//! ```c
//! if (next_entry.meta->inode == 0)
//!     next_entry.meta->inode = index + 1;
//! ...
//! stat->inode = entry->meta->inode | entry->pid << 16 | (uint64_t) entry->fd << 48;
//! ```
//!
//! Composing is the right shape. Two things about that one were not. The write
//! is to a `static` table shared by every thread resolving a proc path, with no
//! lock. And the value written is the entry's index *within its own directory*,
//! so entries at the same index in different directories collide —
//! `/proc/cpuinfo` and the first entry of `/proc/net` both landed on 2.
//!
//! This crate's first answer was a `HashMap<(meta, pid, fd), u64>` and a
//! counter, which satisfies both requirements and never writes the tables. It
//! also never forgets: the key holds a pid, so every process that has ever been
//! looked at leaves an entry per file in `/proc/<pid>` behind it, plus one per
//! descriptor. `ps` looks at all of them. Bounded only by `MAX_PID` — 32768 —
//! times the size of the per-pid table, which is hundreds of thousands of live
//! entries on a machine that churns processes, none of which can ever be used
//! again.
//!
//! So: composed, like the C, but with a *global* index per table entry rather
//! than a per-directory one. The map that assigns those holds one entry per
//! `proc_dir_entry` in the tables — around fifty, all of them `static`, so it
//! stops growing once each has been seen once.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// bits 0..15 identify the table entry, 16..47 the pid, 48..63 the descriptor.
const INDEX_BITS: u32 = 16;
const PID_BITS: u32 = 32;

fn table() -> &'static Mutex<(HashMap<usize, u64>, u64)> {
    static TABLE: OnceLock<Mutex<(HashMap<usize, u64>, u64)>> = OnceLock::new();
    // Starts at 2: 1 is conventionally the root, and 0 means "no inode" to
    // enough callers that handing it out invites trouble.
    TABLE.get_or_init(|| Mutex::new((HashMap::new(), 2)))
}

/// A small number identifying one entry of the static tables.
///
/// Keyed on the entry's address, which is stable and unique: they live in
/// `static`s for the life of the process. The key is a `usize` and is
/// **compared, never dereferenced**, which is what lets the tests below name
/// entries as addresses that are not entries.
fn index_of(key: usize) -> u64 {
    let mut guard = table().lock().unwrap_or_else(|e| e.into_inner());
    let (map, next) = &mut *guard;
    if let Some(&index) = map.get(&key) {
        return index;
    }
    let index = *next;
    *next += 1;
    map.insert(key, index);
    index
}

/// Pack the three parts into one number.
///
/// Each field is masked to its width rather than asserted, so an `fd` of -1 —
/// which is what a non-descriptor entry carries in some tables — packs to the
/// same value every time instead of spilling into the fields above it.
fn compose(index: u64, pid: i32, fd: i32) -> u64 {
    let index = index & ((1 << INDEX_BITS) - 1);
    let pid = (pid as u32 as u64) & ((1u64 << PID_BITS) - 1);
    let fd = (fd as u32 as u64) & ((1 << (64 - INDEX_BITS - PID_BITS)) - 1);
    index | (pid << INDEX_BITS) | (fd << (INDEX_BITS + PID_BITS))
}

/// The inode number for an entry.
///
/// An entry with no table row -- the default-constructed one -- takes key 0,
/// which no `static` can be at, so it is its own index rather than sharing one.
pub(crate) fn for_entry(meta: Option<&'static crate::ffi::proc_dir_entry>, pid: i32, fd: i32) -> u64 {
    let key = meta.map_or(0, |m| std::ptr::from_ref(m) as usize);
    compose(index_of(key), pid, fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Distinct addresses standing in for table entries: the key is compared
    /// and never dereferenced, so these need not be entries.
    fn meta(n: usize) -> usize {
        0x1000 + n * 64
    }

    /// What `for_entry` is over a key that is already a `usize`.
    fn keyed(key: usize, pid: i32, fd: i32) -> u64 {
        compose(index_of(key), pid, fd)
    }

    #[test]
    fn the_same_entry_always_gets_the_same_number() {
        let a = keyed(meta(1), 0, 0);
        assert_eq!(keyed(meta(1), 0, 0), a);
        assert_eq!(keyed(meta(1), 0, 0), a);
    }

    #[test]
    fn entries_in_different_directories_do_not_collide() {
        // The bug in the C: both of these were the first entry of their own
        // directory and both got 2.
        assert_ne!(keyed(meta(2), 0, 0), keyed(meta(3), 0, 0));
    }

    #[test]
    fn the_same_file_under_different_processes_differs() {
        assert_ne!(keyed(meta(4), 100, 0), keyed(meta(4), 101, 0));
    }

    #[test]
    fn descriptors_of_one_process_differ() {
        assert_ne!(keyed(meta(5), 100, 1), keyed(meta(5), 100, 2));
    }

    #[test]
    fn nothing_collides_across_the_whole_space_we_can_reach() {
        // Every combination a real /proc can produce: fifty table entries,
        // pids up to MAX_PID, and a spread of descriptors.
        let mut seen = HashSet::new();
        for m in 0..50 {
            for &pid in &[0, 1, 2, 1000, 32767] {
                for &fd in &[0, 1, 2, 255, 1024] {
                    let ino = keyed(meta(100 + m), pid, fd);
                    assert!(
                        seen.insert(ino),
                        "collision at meta {m} pid {pid} fd {fd}: {ino:#x}"
                    );
                    assert_ne!(ino, 0, "0 means \"no inode\" to too many callers");
                }
            }
        }
    }

    #[test]
    fn a_negative_fd_packs_the_same_way_every_time() {
        // Some tables leave fd at -1 rather than 0. It has to be stable and it
        // has to stay out of the fields above it.
        let a = keyed(meta(200), 7, -1);
        assert_eq!(keyed(meta(200), 7, -1), a);
        assert_ne!(a, keyed(meta(200), 7, 0));
    }

    #[test]
    fn a_thousand_processes_share_one_table_entry() {
        // The whole point of composing rather than remembering: the only thing
        // the map holds is the per-entry index, so a thousand pids against one
        // table entry allocate one index between them.
        //
        // Asserted on the numbers rather than on the map's size, because these
        // tests run in one process and share the table — a size delta would be
        // measuring the other tests too.
        let index = keyed(meta(300), 0, 0) & ((1 << INDEX_BITS) - 1);
        for pid in 1..1000 {
            let ino = keyed(meta(300), pid, 0);
            assert_eq!(
                ino & ((1 << INDEX_BITS) - 1),
                index,
                "pid {pid} allocated a second index for one table entry"
            );
        }
    }
}
