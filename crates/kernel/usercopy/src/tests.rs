//! Tests for guest range checks, page chunking, copying, and string reads.

use super::*;
use std::collections::BTreeMap;

/// An address space made of whichever pages a test asks for. Absent pages
/// are absent, which is what makes "the copy stopped at the hole" a thing
/// the tests can see.
struct Fake {
    pages: BTreeMap<u64, Box<[u8; PAGE_SIZE as usize]>>,
    read_only: Vec<u64>,
    /// Every (addr, len) `map` was asked for, so a test can assert that a
    /// copy did one lookup per page rather than one per byte.
    lookups: Vec<(u64, usize)>,
}

impl Fake {
    fn new(pages: &[u64]) -> Fake {
        let mut map = BTreeMap::new();
        for &p in pages {
            map.insert(p, Box::new([0u8; PAGE_SIZE as usize]));
        }
        Fake {
            pages: map,
            read_only: Vec::new(),
            lookups: Vec::new(),
        }
    }

    fn put(&mut self, addr: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            let at = addr + i as u64;
            self.pages.get_mut(&(at >> PAGE_BITS)).expect("mapped")[(at & (PAGE_SIZE - 1)) as usize] = b;
        }
    }

    fn get(&self, addr: u64, len: usize) -> Vec<u8> {
        (0..len as u64)
            .map(|i| {
                let at = addr + i;
                self.pages[&(at >> PAGE_BITS)][(at & (PAGE_SIZE - 1)) as usize]
            })
            .collect()
    }

    fn lookups(&self) -> Vec<(u64, usize)> {
        self.lookups.clone()
    }
}

impl Pages for Fake {
    fn map(&mut self, addr: u64, len: usize, access: Access) -> Option<*mut u8> {
        self.lookups.push((addr, len));
        let page = addr >> PAGE_BITS;
        if access == Access::Write && self.read_only.contains(&page) {
            return None;
        }
        let bytes = self.pages.get_mut(&page)?;
        Some(bytes[(addr & (PAGE_SIZE - 1)) as usize..].as_mut_ptr())
    }
}

const MAX_PAGE: u64 = 0xFFFFFFFFF; // 48-bit address space, as the guest has

#[test]
fn a_range_that_wraps_is_refused() {
    assert!(
        !range_ok(u64::MAX, 4, MAX_PAGE),
        "four bytes at the very top"
    );
    assert!(!range_ok(u64::MAX - 2, 8, MAX_PAGE));
    // The last byte is exactly the last one: no wrap, but above the space.
    assert!(!range_ok(u64::MAX, 1, MAX_PAGE));
    // A zero count is not a range and cannot wrap.
    assert!(range_ok(u64::MAX, 0, MAX_PAGE));
}

#[test]
fn a_range_above_the_address_space_is_refused() {
    let top = (MAX_PAGE + 1) << PAGE_BITS; // the first byte that is not there
    assert!(range_ok(top - 1, 1, MAX_PAGE), "the last byte that is");
    assert!(!range_ok(top, 1, MAX_PAGE));
    // And one that starts inside and runs out.
    assert!(!range_ok(top - 2, 4, MAX_PAGE));
    assert!(range_ok(top - 4, 4, MAX_PAGE));
}

/// The aliasing this exists to stop: `p` and `p + 2^48` are the same page
/// as far as the page table is concerned, so the second has to be refused
/// before it ever reaches one.
#[test]
fn an_address_that_aliases_onto_a_low_page_is_refused() {
    let p = 0x1000u64;
    assert!(range_ok(p, 8, MAX_PAGE));
    assert!(!range_ok(p + (1 << 48), 8, MAX_PAGE));
}

#[test]
fn chunks_never_cross_a_page_and_cover_the_range() {
    // Wholly inside one page: one chunk.
    assert_eq!(chunks(0x1010, 16).collect::<Vec<_>>(), vec![(0x1010, 16)]);
    // Straddling: two.
    assert_eq!(
        chunks(0x1FF8, 16).collect::<Vec<_>>(),
        vec![(0x1FF8, 8), (0x2000, 8)]
    );
    // Exactly a page, page-aligned: one.
    assert_eq!(
        chunks(0x2000, 4096).collect::<Vec<_>>(),
        vec![(0x2000, 4096)]
    );
    // Several pages from an unaligned start.
    assert_eq!(
        chunks(0x1FFF, 4098).collect::<Vec<_>>(),
        vec![(0x1FFF, 1), (0x2000, 4096), (0x3000, 1)]
    );
    assert_eq!(chunks(0x1000, 0).count(), 0);

    // Whatever the shape: no chunk crosses a page, and they add up.
    for start in [0u64, 1, 0xFFF, 0x1000, 0x1001, 0x2FFF] {
        for count in [0usize, 1, 7, 4095, 4096, 4097, 9000] {
            let cs: Vec<_> = chunks(start, count).collect();
            assert_eq!(cs.iter().map(|c| c.1).sum::<usize>(), count);
            let mut at = start;
            for (a, l) in cs {
                assert_eq!(a, at);
                assert_eq!(a >> PAGE_BITS, (a + l as u64 - 1) >> PAGE_BITS);
                at += l as u64;
            }
        }
    }
}

#[test]
fn a_copy_spans_pages_and_does_one_lookup_per_page() {
    let mut mem = Fake::new(&[1, 2, 3]);
    let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    mem.put(0x1000, &payload);

    let mut out = vec![0u8; 8192];
    assert_eq!(read(&mut mem, 0x1000, &mut out, MAX_PAGE), 0);
    assert_eq!(out, payload);
    // Two pages, two lookups -- not eight thousand.
    assert_eq!(mem.lookups(), vec![(0x1000, 4096), (0x2000, 4096)]);
}

#[test]
fn a_copy_that_reaches_a_hole_stops_there() {
    // Page 1 and page 3 exist; page 2 does not.
    let mut mem = Fake::new(&[1, 3]);
    let mut out = vec![0u8; 8192];
    assert_eq!(read(&mut mem, 0x1000, &mut out, MAX_PAGE), EFAULT);
    // It found the hole on the second lookup rather than reading past it.
    assert_eq!(mem.lookups(), vec![(0x1000, 4096), (0x2000, 4096)]);
}

#[test]
fn a_write_to_a_read_only_page_is_refused() {
    let mut mem = Fake::new(&[1]);
    mem.read_only.push(1);
    assert_eq!(
        write(&mut mem, 0x1000, b"hello", Access::Write, MAX_PAGE),
        EFAULT
    );
    // A debugger's write is a different question and this fake answers it
    // the way mem_ptr does: MEM_WRITE_PTRACE is not MEM_WRITE.
    assert_eq!(
        write(&mut mem, 0x1000, b"hello", Access::WritePtrace, MAX_PAGE),
        0
    );
    assert_eq!(mem.get(0x1000, 5), b"hello");
}

#[test]
fn the_writable_prefix_stops_at_the_first_page_that_is_not() {
    // Pages 1 and 2 mapped, 3 absent: a read offered three pages may take
    // two. That is a short read rather than a refusal, which is what makes
    // it match Linux -- the copy stops where the mapping does, and a caller
    // asking for more than a pipe holds never notices.
    let mut mem = Fake::new(&[1, 2]);
    assert_eq!(
        writable_prefix(&mut mem, 0x1000, 3 * 4096, Access::Write, MAX_PAGE),
        2 * 4096
    );
    // Not from a page boundary: the first chunk is short by the offset.
    assert_eq!(
        writable_prefix(&mut mem, 0x1800, 3 * 4096, Access::Write, MAX_PAGE),
        2 * 4096 - 0x800
    );
    // Nothing at all, which is the answer that means the driver must not be
    // called.
    assert_eq!(
        writable_prefix(&mut mem, 0x3000, 64, Access::Write, MAX_PAGE),
        0
    );
}

#[test]
fn a_read_only_page_is_not_a_writable_prefix() {
    // The direction is half the question. A check that only asked "is this
    // mapped" would pass a `read` into the caller's own text segment, and
    // the copy would then fail after the driver had consumed. Backing the
    // `access` argument out to `Access::Read` is what makes this fail.
    let mut mem = Fake::new(&[1, 2]);
    mem.read_only.push(2);
    assert_eq!(
        writable_prefix(&mut mem, 0x1000, 8192, Access::Write, MAX_PAGE),
        4096
    );
    assert_eq!(
        writable_prefix(&mut mem, 0x2000, 4096, Access::Write, MAX_PAGE),
        0
    );
}

#[test]
fn a_writable_prefix_of_a_range_no_guest_could_name_is_none() {
    // Before any page is looked at, because an address above the address
    // space *aliases* rather than faulting -- a walk would answer about some
    // other page and report it writable. It is also why a caller can tell
    // this apart from an unmapped page: `access_ok` is checked before Linux
    // waits for data, and a missing mapping is found during the copy.
    let mut mem = Fake::new(&[1]);
    assert_eq!(
        writable_prefix(&mut mem, 0x1000 + (1 << 48), 64, Access::Write, MAX_PAGE),
        0
    );
    assert_eq!(
        writable_prefix(&mut mem, u64::MAX, 64, Access::Write, MAX_PAGE),
        0
    );
    // And a zero-length question touches nothing.
    assert_eq!(
        writable_prefix(&mut mem, 0x9999_0000, 0, Access::Write, MAX_PAGE),
        0
    );
}

#[test]
fn a_string_stops_at_its_terminator() {
    let mut mem = Fake::new(&[1]);
    mem.put(0x1000, b"/etc/passwd\0and then some");
    let mut buf = [0u8; 64];
    assert_eq!(read_string(&mut mem, 0x1000, &mut buf, MAX_PAGE), Ok(11));
    assert_eq!(&buf[..12], b"/etc/passwd\0");
    // One lookup, not eleven.
    assert_eq!(mem.lookups().len(), 1);
}

#[test]
fn a_string_spanning_a_page_is_joined() {
    let mut mem = Fake::new(&[1, 2]);
    let name = b"/a/very/long/path/that/crosses\0";
    let start = 0x2000 - 15;
    mem.put(start, name);
    let mut buf = [0u8; 64];
    assert_eq!(
        read_string(&mut mem, start, &mut buf, MAX_PAGE),
        Ok(name.len() - 1)
    );
    assert_eq!(&buf[..name.len()], name);
    assert_eq!(mem.lookups().len(), 2);
}

/// The defect: with no terminator in the space given, this used to report
/// success with the buffer full and unterminated, and the caller read past
/// it.
#[test]
fn a_string_with_no_terminator_is_refused() {
    let mut mem = Fake::new(&[1]);
    mem.put(0x1000, &[b'a'; 64]);
    let mut buf = [0u8; 32];
    assert_eq!(
        read_string(&mut mem, 0x1000, &mut buf, MAX_PAGE),
        Err(ENAMETOOLONG)
    );
}

/// And the boundary either side of it: a name that exactly fills the
/// buffer including its NUL is fine, one byte longer is not.
#[test]
fn a_string_may_fill_the_buffer_including_its_terminator() {
    let mut mem = Fake::new(&[1]);
    mem.put(0x1000, b"abcdefg\0");
    let mut buf = [0u8; 8];
    assert_eq!(read_string(&mut mem, 0x1000, &mut buf, MAX_PAGE), Ok(7));
    let mut buf = [0u8; 7];
    assert_eq!(
        read_string(&mut mem, 0x1000, &mut buf, MAX_PAGE),
        Err(ENAMETOOLONG)
    );
}

/// A string that ends before a hole must not fault on the page after it --
/// which is what bounding each chunk to its own page buys.
#[test]
fn a_string_ending_before_a_hole_does_not_touch_it() {
    // Page 1 exists, page 2 does not.
    let mut mem = Fake::new(&[1]);
    mem.put(0x1FF0, b"short\0");
    let mut buf = [0u8; 4096];
    assert_eq!(read_string(&mut mem, 0x1FF0, &mut buf, MAX_PAGE), Ok(5));
    assert_eq!(
        mem.lookups(),
        vec![(0x1FF0, 16)],
        "asked for the rest of the page, no more"
    );
}

/// And one that runs into the hole does fault.
#[test]
fn a_string_running_into_a_hole_faults() {
    let mut mem = Fake::new(&[1]);
    mem.put(0x1FF0, b"aaaaaaaaaaaaaaaa"); // fills to the page end, no NUL
    let mut buf = [0u8; 4096];
    assert_eq!(read_string(&mut mem, 0x1FF0, &mut buf, MAX_PAGE), Err(EFAULT));
}

#[test]
fn a_string_at_an_address_that_is_not_one_is_refused() {
    let mut mem = Fake::new(&[1]);
    let mut buf = [0u8; 64];
    assert_eq!(read_string(&mut mem, u64::MAX, &mut buf, MAX_PAGE), Err(EFAULT));
    assert_eq!(
        read_string(&mut mem, 0x1000 + (1 << 48), &mut buf, MAX_PAGE),
        Err(EFAULT)
    );
    // A zero-length buffer has nowhere to put even a terminator.
    assert_eq!(read_string(&mut mem, 0x1000, &mut [], MAX_PAGE), Err(EFAULT));
}

#[test]
fn a_zero_length_copy_touches_nothing() {
    let mut mem = Fake::new(&[1]);
    assert_eq!(read(&mut mem, 0x1000, &mut [], MAX_PAGE), 0);
    assert_eq!(write(&mut mem, 0x1000, &[], Access::Write, MAX_PAGE), 0);
    assert!(mem.lookups().is_empty());
    // Even at an address that is not one: nothing is touched, so there is
    // nothing to fault on. Linux agrees -- read(fd, anything, 0) is 0.
    assert_eq!(read(&mut mem, u64::MAX, &mut [], MAX_PAGE), 0);
}
