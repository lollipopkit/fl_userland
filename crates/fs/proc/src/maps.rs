//! `/proc/<pid>/maps`.
//!
//! `fs/proc/pid.c` walks the page table and resolves each region's path,
//! because both need `struct mem` and the VFS. What it hands over is an array
//! of regions the caller owns, and the line-per-region formatting is here.
//!
//! The split is the same one `pid.rs` describes and it is for the same reason:
//! the walk used to format as it went, one `proc_printf` per region — each of
//! which can realloc the output buffer — plus a `generic_getpath` for every
//! file-backed region, all with `mem->lock` held. That lock is what every
//! `mmap`, `munmap`, `mprotect` and `brk` needs to write.

use std::fmt::Write as _;
use std::os::raw::c_int;

use crate::ffi;

/// Page protection bits, from `kernel/memory.h`. Mirrored rather than
/// bindgen'd: they are `#define`s, and the four this file reads are the ones
/// the format's permission column is made of.
///
/// `P_SHARED` was `1 << 4` here, which is `P_COW` -- so the sharing column
/// answered a question about copy-on-write. `tests/proc_maps_flags.c` reads
/// the header and fails if any of these four drift again, which is the only
/// thing that makes a mirrored `#define` safe.
pub(crate) const P_READ: u32 = 1 << 0;
pub(crate) const P_WRITE: u32 = 1 << 1;
pub(crate) const P_EXEC: u32 = 1 << 2;
pub(crate) const P_SHARED: u32 = 1 << 7;

/// Linux pads the pathname to `25 + sizeof(void *) * 6` (`seq_setwidth` in
/// `show_map_vma`), which on a 64-bit kernel is 73. Readers that index by
/// column -- and the format exists to be indexed by column -- expect the name
/// there.
const NAME_COLUMN: usize = 25 + 8 * 6;

/// `/proc/<pid>/maps`.
pub(crate) fn proc_pid_maps_show(
    entry: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    let regions = crate::pidmem::collect(entry);
    format(&regions, buf);
    0
}

/// The same, from the Rust regions `crates/fs/proc`'s own walk produces.
///
/// One formatter of this layout, which is the point: the emulator's fatal-fault
/// dump had a second copy written out as a `proc_printf`, the two disagreed
/// about which bit the sharing column reads, and neither was Linux's layout.
pub fn format(regions: &[crate::pidmem::Region], buf: &mut ffi::proc_data) {
    if regions.is_empty() {
        return;
    }
    // One string for the whole dump rather than one append per region: the
    // buffer this goes into grows by reallocating, and a process with a few
    // thousand mappings made a few thousand of them.
    let mut text = String::with_capacity(regions.len() * (NAME_COLUMN + 24));
    for r in regions {
        write_region(&mut text, r);
    }
    buf.append(text.as_bytes());
}

/// One line, in the layout every reader of this file parses by column.
///
/// This is `show_map_vma` in `fs/proc/task_mmu.c`, field for field:
///
/// ```text
/// <start>-<end> <perms> <pgoff> <major>:<minor> <inode> <padding><name>
/// ```
///
/// with the addresses and the offset in hex zero-padded to *at least* eight
/// digits, the inode in decimal followed by one space, and the name -- when
/// there is one -- padded out to [`NAME_COLUMN`]. A region with no name ends
/// after that space, trailing, which is what Linux emits and what a parser
/// written against Linux expects to see.
///
/// The device and inode are what `fstat` on the mapped file answers, so a
/// reader that correlates a region to a file by (dev, inode) -- `lsof`, a
/// debugger matching a mapping to the binary it loaded -- finds the same file
/// `stat` does. They were `00:00 0` for every region until 2026-11-12.
pub(crate) fn write_region(out: &mut String, r: &crate::pidmem::Region) {
    let (flags, path) = (r.flags, r.path.as_str());
    let bit = |set: u32, c: char| if flags & set != 0 { c } else { '-' };
    let before = out.len();
    let _ = write!(
        out,
        "{:08x}-{:08x} {}{}{}{} {:08x} {:02x}:{:02x} {} ",
        r.start,
        r.end,
        bit(P_READ, 'r'),
        bit(P_WRITE, 'w'),
        bit(P_EXEC, 'x'),
        // 'p' or 's', never '-'. This printed '-' for a shared mapping, which
        // no kernel does, and it read the wrong bit to decide (see P_SHARED).
        if flags & P_SHARED != 0 { 's' } else { 'p' },
        r.file_offset,
        fs_devices::dev_major(r.dev as u32),
        fs_devices::dev_minor(r.dev as u32),
        r.inode,
    );
    if !path.is_empty() {
        // Pad, but never *back up*: a line already past the column gets a
        // single separating space, which is what seq_pad does when the fields
        // have overrun the width.
        let width = out.len() - before;
        for _ in width..NAME_COLUMN {
            out.push(' ');
        }
        out.push_str(path);
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(start: u64, end: u64, offset: u64, flags: u32, path: &str) -> String {
        located(start, end, offset, flags, 0, 0, path)
    }

    fn located(start: u64, end: u64, offset: u64, flags: u32, dev: u64, inode: u64, path: &str) -> String {
        let mut s = String::new();
        let r = crate::pidmem::Region {
            start,
            end,
            file_offset: offset,
            flags,
            dev,
            inode,
            path: path.into(),
            counts: Default::default(),
        };
        write_region(&mut s, &r);
        s
    }

    /// A line captured from a real aarch64 Linux kernel, reproduced field for
    /// field. This is the assertion the rest of the file exists to keep true:
    /// the addresses are hex zero-padded to at least eight digits, the offset
    /// to exactly eight, the device is `major:minor` two digits each, the
    /// inode is decimal, and the name begins at column 73.
    ///
    /// The device is the packed `dev_t` a guest `stat` answers, printed as
    /// `major:minor`; `0xb4` is minor 0xb4 of major 0.
    #[test]
    fn matches_a_line_from_a_real_kernel() {
        // aab50f8e0000-aab50f9b9000 r-xp 00000000 00:b4 32771240      /bin/busybox
        let got = located(
            0xaab5_0f8e_0000,
            0xaab5_0f9b_9000,
            0,
            P_READ | P_EXEC,
            0xb4,
            32771240,
            "/bin/busybox",
        );
        let want = "aab50f8e0000-aab50f9b9000 r-xp 00000000 00:b4 32771240                   /bin/busybox\n";
        assert_eq!(got, want);
        assert_eq!(got.find("/bin/busybox"), Some(NAME_COLUMN));
    }

    /// Both halves of a device number, including a minor past 255, which the
    /// packed encoding splits in two.
    #[test]
    fn the_device_column_is_major_and_minor_of_st_dev() {
        // makedev(8, 0x1234): major in bits 8..20, minor's low byte in 0..8
        // and the rest from bit 20 up.
        let dev = (8u64 << 8) | 0x34 | (0x12u64 << 20);
        let l = located(0x1000, 0x2000, 0, P_READ, dev, 7, "/x");
        assert!(l.starts_with("00001000-00002000 r--p 00000000 08:1234 7 "), "{l}");
    }

    /// Whatever the fields' widths come to, the name lands on the same column.
    /// A reader that indexes by column rather than by whitespace -- and the
    /// format is padded precisely so it can -- depends on that holding for a
    /// short address as much as for a long one.
    #[test]
    fn the_name_column_does_not_move() {
        for (start, end) in [(0x1000u64, 0x2000u64), (0xffff_ffff_f000, 0xffff_ffff_ffff)] {
            let l = line(start, end, 0, P_READ, "[heap]");
            assert_eq!(l.find("[heap]"), Some(NAME_COLUMN), "{l}");
        }
    }

    /// An unnamed region ends after the space that follows the inode, with no
    /// padding at all. Linux emits exactly that -- `rw-p 00000000 00:00 0 ` --
    /// and a parser written against Linux treats the trailing space as the
    /// empty name field.
    #[test]
    fn an_unnamed_region_is_not_padded() {
        let l = line(0x1000, 0x2000, 0, P_READ | P_WRITE, "");
        assert_eq!(l, "00001000-00002000 rw-p 00000000 00:00 0 \n");
    }

    /// Eight hex digits is the *minimum*, not the width: an address that needs
    /// more gets more, and the fields after it shift, which is why the name is
    /// padded rather than placed.
    #[test]
    fn an_address_wider_than_eight_digits_is_not_truncated() {
        let l = line(0x7fff_0000, 0xaab5_0f9b_9000, 0x2000, P_READ | P_WRITE, "");
        assert!(l.starts_with("7fff0000-aab50f9b9000 rw-p 00002000 "), "{l}");
    }

    #[test]
    fn every_permission_bit_shows_in_its_own_column() {
        let perms = |flags| {
            let l = line(0x1000, 0x2000, 0, flags, "");
            l[18..22].to_string()
        };
        assert_eq!(perms(0), "---p");
        assert_eq!(perms(P_READ), "r--p");
        assert_eq!(perms(P_WRITE), "-w-p");
        assert_eq!(perms(P_EXEC), "--xp");
        // 's', not '-'. A shared mapping printed '-' here, which is a
        // character the sharing column does not take on any kernel.
        assert_eq!(perms(P_SHARED), "---s");
        assert_eq!(perms(P_READ | P_WRITE | P_SHARED), "rw-s");
    }

    /// The bit the sharing column reads is P_SHARED and not P_COW. It read
    /// `1 << 4` -- P_COW -- so a private file mapping, which is every one of
    /// them, answered the wrong question.
    #[test]
    fn copy_on_write_is_not_sharing() {
        const P_COW: u32 = 1 << 4;
        assert_eq!(&line(0x1000, 0x2000, 0, P_READ | P_COW, "")[18..22], "r--p");
    }
}
