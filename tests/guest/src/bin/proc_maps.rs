//! What `/proc/<pid>/maps` says, and whether it says it in the layout readers
//! parse.
//!
//! Nothing covered this file before. Its format is not self-describing —
//! every reader of it (pmap, a JIT looking for its own code region, a leak
//! checker) indexes by column and by field position — so the checks here are
//! about the columns as much as about the contents.
//!
//! The regions are made deliberately: a file-backed read-only mapping, a
//! file-backed read-write one, and an anonymous one, all of a file whose path
//! is known. A mapping that the dump merges with its neighbour would not be
//! findable, so the protections alternate.

use guest_tests::{Harness, check};

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// One parsed line.
struct Region {
    start: u64,
    end: u64,
    perms: String,
    offset: u64,
    path: String,
}

/// Parse one line of `<start>-<end> <perms> <pgoff> <maj>:<min> <inode> <name>`.
///
/// Two things this got wrong when it was written against this emulator alone,
/// both found by running the same binary on a real kernel
/// (tests/integration/differential.sh):
///
///   - **The addresses are not a fixed twelve digits.** Linux zero-pads them
///     to a minimum of eight and prints as many more as the address needs, so
///     the fields after them shift. Requiring twelve rejected ten of a real
///     kernel's seventeen lines.
///   - **The name is padded to a column, not to a field width.** Taking a
///     fixed offset past the inode captured the padding, so every path
///     compared unequal to the path it was.
///
/// So: split on whitespace for the five fixed fields, and take the name as
/// whatever follows the inode with the padding trimmed. A name containing
/// spaces survives that, because only the leading padding is removed; a name
/// that *begins* with a space would not, and Linux does not emit one.
fn parse(line: &str) -> Option<Region> {
    let (range, rest) = line.split_once(' ')?;
    let (start, end) = range.split_once('-')?;
    if start.len() < 8 || end.len() < 8 {
        return None;
    }
    let mut f = rest.splitn(4, ' ');
    let perms = f.next()?.to_string();
    let offset = f.next()?;
    let _dev = f.next()?;
    let tail = f.next()?;
    // The inode, then one space, then padding out to the name column. An
    // unnamed region ends at that first space and there is nothing after it.
    let (_inode, padded) = tail.split_once(' ')?;
    Some(Region {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        perms,
        offset: u64::from_str_radix(offset, 16).ok()?,
        path: padded.trim_start().to_string(),
    })
}

/// Where Linux's `seq_pad` puts the name: `25 + sizeof(void *) * 6`.
const NAME_COLUMN: usize = 25 + 8 * 6;

/// The index the pathname starts at, or `None` when the region has no name.
///
/// Found by walking past the five fixed fields and the run of spaces after the
/// last of them, so it does not care how wide any of them came out — which is
/// the whole point of a padded column.
fn name_start(line: &str) -> Option<usize> {
    let b = line.as_bytes();
    let mut i = 0;
    for _ in 0..5 {
        // range, perms, offset, dev, inode
        while i < b.len() && b[i] != b' ' {
            i += 1;
        }
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
    }
    (i < b.len()).then_some(i)
}

fn read_maps() -> Vec<String> {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    let mut h = Harness::new();

    let path = format!("{dir}/maps-probe");
    std::fs::write(&path, vec![0u8; 4096 * 4]).ok();
    let fd = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        check!(h, false, "opening {path}");
        std::process::exit(h.finish());
    }

    // Three mappings of the same file, at three offsets, with three
    // protections, so none of them can be merged into another.
    let map = |off: i64, prot: i32| unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            prot,
            libc::MAP_PRIVATE,
            fd,
            off,
        )
    };
    let ro = map(0, libc::PROT_READ);
    let rw = map(4096, libc::PROT_READ | libc::PROT_WRITE);
    let anon = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    let lines = read_maps();
    h.group("format");
    check!(h, !lines.is_empty(), "/proc/self/maps is not empty");
    let parsed: Vec<Region> = lines.iter().filter_map(|l| parse(l)).collect();
    check!(
        h,
        parsed.len() == lines.len(),
        "every line parses by column: {} of {} did",
        parsed.len(),
        lines.len()
    );
    check!(
        h,
        parsed.iter().all(|r| r.end > r.start),
        "every region ends after it starts"
    );
    check!(
        h,
        parsed.iter().all(|r| r.perms.len() == 4),
        "the permission column is four characters"
    );
    // 'p' or 's'. It was 'p' or '-', which no kernel emits -- this dump
    // printed '-' for a mapping it thought was shared, and decided that by
    // reading the copy-on-write bit.
    check!(
        h,
        parsed
            .iter()
            .all(|r| r.perms.ends_with('p') || r.perms.ends_with('s')),
        "and its last character is the sharing flag, p or s: {:?}",
        parsed.iter().find(|r| !r.perms.ends_with('p') && !r.perms.ends_with('s')).map(|r| &r.perms)
    );
    // Linux pads the name out to `25 + sizeof(void *) * 6`, and readers that
    // index by column depend on it landing there.
    //
    // The first version of this check was `every line longer than 73
    // characters has a space at 72`, which is vacuously true whenever no line
    // is that long -- and under this emulator none is, because the paths in
    // this process's own address space are short. It passed with the column
    // set to 49. Hence `named`, and hence the check below it that `named` is
    // not empty: a column assertion that survives every column is not one.
    let named: Vec<(usize, &String)> = lines
        .iter()
        .filter_map(|l| name_start(l).map(|c| (c, l)))
        .collect();
    check!(h, !named.is_empty(), "some region has a name at all");
    check!(
        h,
        named.iter().all(|(c, _)| *c == NAME_COLUMN),
        "a named region starts its name at column {NAME_COLUMN}: {:?}",
        named.iter().find(|(c, _)| *c != NAME_COLUMN)
    );
    // Something in this address space is executable: the binary's own text, at
    // the very least. This dump reported nothing executable at all, because
    // the ELF loader never translated the segment's PH_X into a page flag.
    check!(
        h,
        parsed.iter().any(|r| r.perms.contains('x')),
        "at least one mapping is executable"
    );
    // Sorted by address is not promised by Linux, but every reader assumes it
    // and this dump walks the page table in order.
    check!(
        h,
        parsed.windows(2).all(|w| w[0].start <= w[1].start),
        "the regions are in address order"
    );

    h.group("contents");
    let find = |addr: *mut libc::c_void| -> Option<&Region> {
        let a = addr as u64;
        parsed.iter().find(|r| r.start <= a && a < r.end)
    };

    match find(ro) {
        Some(r) => {
            check!(h, r.perms.starts_with("r--"), "the read-only mapping is r--, got {}", r.perms);
            check!(h, r.path == path, "and names the file: {:?}", r.path);
            check!(h, r.offset == 0, "at offset 0, got {:#x}", r.offset);
        }
        None => check!(h, false, "the read-only mapping is in the dump"),
    }
    match find(rw) {
        Some(r) => {
            check!(h, r.perms.starts_with("rw-"), "the read-write mapping is rw-, got {}", r.perms);
            check!(h, r.path == path, "and names the file: {:?}", r.path);
            check!(
                h,
                r.offset == 4096,
                "at the offset it was mapped from, want 0x1000 got {:#x}",
                r.offset
            );
        }
        None => check!(h, false, "the read-write mapping is in the dump"),
    }
    match find(anon) {
        Some(r) => {
            check!(h, r.perms.starts_with("rw-"), "the anonymous mapping is rw-, got {}", r.perms);
            check!(h, r.path.is_empty(), "and has no path, got {:?}", r.path);
        }
        None => check!(h, false, "the anonymous mapping is in the dump"),
    }

    h.group("lifetime");
    // Unmapping removes it. This is the check that a dump built from a
    // snapshot has to keep passing: the snapshot must be of the address space
    // as it is when it is read, not one left over from a previous read.
    unsafe { libc::munmap(anon, 4096) };
    let after: Vec<Region> = read_maps().iter().filter_map(|l| parse(l)).collect();
    let a = anon as u64;
    check!(
        h,
        !after.iter().any(|r| r.start <= a && a < r.end),
        "an unmapped region is gone from the next read"
    );
    check!(
        h,
        after.iter().any(|r| r.path == path),
        "and the ones still mapped are still there"
    );

    // Two reads agree about the mappings that did not change. Only those:
    // reading the file allocates a buffer to hold it, which moves the heap, so
    // comparing the whole dump would be comparing the probe against itself.
    // The collect-then-format split allocates and frees an array per read, and
    // a stale pointer or a double free there would show up here.
    let ours = |ls: &[String]| -> Vec<String> {
        ls.iter().filter(|l| l.ends_with(&path)).cloned().collect()
    };
    let again = ours(&read_maps());
    let once_more = ours(&read_maps());
    check!(h, !again.is_empty(), "the file-backed lines are findable");
    check!(
        h,
        again == once_more,
        "two reads agree about the mappings that did not change:\n{again:#?}\n{once_more:#?}"
    );

    h.group("System V shared memory");
    // Named `SYSV<key as %08x>` and unlinked from birth, as Linux's `newseg`
    // names the file; `IPC_PRIVATE` is key 0. Every segment was
    // `/memfd:SYSV (deleted)` until 2026-11-11 (`shm_probe`).
    for key in [0x5348_0002u32 as i32, libc::IPC_PRIVATE, 0x8765_4322u32 as i32] {
        let id = unsafe { libc::shmget(key, 8192, libc::IPC_CREAT | libc::IPC_EXCL | 0o600) };
        let p = if id >= 0 { unsafe { libc::shmat(id, std::ptr::null(), 0) } } else { usize::MAX as *mut _ };
        let want = format!("/SYSV{:08x} (deleted)", key as u32);
        let found = read_maps().iter().filter_map(|l| parse(l)).find(|r| r.start == p as u64);
        check!(
            h,
            found.as_ref().is_some_and(|r| r.path == want && r.perms == "rw-s"),
            "key {key:#x}: the segment's line is rw-s {want:?}: {:?}",
            found.map(|r| (r.perms, r.path))
        );
        unsafe {
            if p as isize != -1 {
                libc::shmdt(p);
            }
            libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut());
        }
    }

    h.group("device and inode");
    // What `fstat` on the mapped file says, as `major:minor` in hex and the
    // inode in decimal; `00:00 0` for memory with no file. Every region read
    // `00:00 0` until 2026-11-12 (`mapsdev_probe`).
    // The line whose range holds `p`: an anonymous region merges with its
    // neighbours, so it need not start there.
    let columns = |p: *mut libc::c_void| -> Option<(String, String)> {
        let at = p as u64;
        let l = read_maps().into_iter().find(|l| parse(l).is_some_and(|r| r.start <= at && at < r.end))?;
        let mut f = l.split_whitespace().skip(3);
        Some((f.next()?.to_string(), f.next()?.to_string()))
    };
    let expect = |fd: i32| {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        unsafe { libc::fstat(fd, &mut st) };
        (format!("{:02x}:{:02x}", libc::major(st.st_dev), libc::minor(st.st_dev)), st.st_ino.to_string())
    };
    let got = columns(ro);
    check!(h, got == Some(expect(fd)), "a file in {dir}: {got:?} vs fstat {:?}", expect(fd));
    let shm_path = "/dev/shm/maps-probe";
    let shm = unsafe { libc::open(cstr(shm_path).as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) };
    unsafe { libc::ftruncate(shm, 4096) };
    let shm_map = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ, libc::MAP_SHARED, shm, 0) };
    let got = columns(shm_map);
    check!(h, got == Some(expect(shm)), "a file in /dev/shm: {got:?} vs fstat {:?}", expect(shm));
    let mfd = unsafe { libc::memfd_create(c"maps-probe".as_ptr(), 0) };
    unsafe { libc::ftruncate(mfd, 4096) };
    let mfd_map = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ, libc::MAP_SHARED, mfd, 0) };
    let got = columns(mfd_map);
    check!(h, got == Some(expect(mfd)), "a memfd: {got:?} vs fstat {:?}", expect(mfd));
    let got = columns(anon);
    check!(h, got == Some(("00:00".into(), "0".into())), "anonymous memory: {got:?}");
    unsafe {
        libc::munmap(shm_map, 4096);
        libc::munmap(mfd_map, 4096);
        libc::close(shm);
        libc::close(mfd);
        libc::unlink(cstr(shm_path).as_ptr());
    }

    unsafe {
        libc::munmap(ro, 4096);
        libc::munmap(rw, 4096);
        libc::close(fd);
        libc::unlink(cstr(&path).as_ptr());
    }
    std::process::exit(h.finish());
}
