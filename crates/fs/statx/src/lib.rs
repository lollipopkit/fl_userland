//! `statx`'s 256 bytes, and the two rules about them that are easy to break.
//!
//! Every modern libc reaches `stat` through this syscall — glibc, musl and
//! Rust's `std::fs::metadata` all do — so a wrong answer is wrong for every
//! program that looks at a file.
//!
//! # The mask is a promise
//!
//! `stx_mask` says which fields were filled. A caller reads a field *only* if
//! its bit is set, so setting a bit for a field left at zero does not report
//! "unknown"; it reports the epoch as a birth time, or no links, as fact.
//!
//! The C set `stx_mask = STATX_BASIC_STATS` unconditionally. That happened to
//! be honest, because `struct statbuf` carries exactly those fields — but it
//! was a constant standing next to eleven assignments, and nothing tied the
//! two together. Here the bit and the value are the same thing: a field that
//! might not be known is an [`Option`], and its bit is set by the code that
//! writes it. Claiming a field this does not have is not something you can
//! spell.
//!
//! # The arguments are checked
//!
//! `flags` and `mask` both have reserved ranges, and the C checked neither, so
//! a program probing for a field or a sync mode this kernel does not implement
//! was told it had it. Four checks; `statx(2)` documents none of the values,
//! which is why they were established by running
//! `tests/guest/src/bin/statx_abi.rs` against a real arm64 kernel.

#![no_std]

use core::ffi::c_int;

/// The buffer `statx` fills. Fixed by the ABI: a guest's libc allocates this
/// many bytes and reads fields out of it by offset.
pub const STATX_BYTES: usize = 256;

// The mask bits, from include/uapi/linux/stat.h.
pub const STATX_TYPE: u32 = 1 << 0;
pub const STATX_MODE: u32 = 1 << 1;
pub const STATX_NLINK: u32 = 1 << 2;
pub const STATX_UID: u32 = 1 << 3;
pub const STATX_GID: u32 = 1 << 4;
pub const STATX_ATIME: u32 = 1 << 5;
pub const STATX_MTIME: u32 = 1 << 6;
pub const STATX_CTIME: u32 = 1 << 7;
pub const STATX_INO: u32 = 1 << 8;
pub const STATX_SIZE: u32 = 1 << 9;
pub const STATX_BLOCKS: u32 = 1 << 10;
pub const STATX_BASIC_STATS: u32 = 0x7ff;
pub const STATX_BTIME: u32 = 1 << 11;
pub const STATX_MNT_ID: u32 = 1 << 12;
/// A mount id that is not reused after the mount goes away. Linux 6.10.
///
/// The same *field* as [`STATX_MNT_ID`] — a caller asks for one or the other
/// and reads `stx_mnt_id` either way, and the kernel says which it gave in
/// `stx_mask`. The *number* is a different one: Linux's unique ids start above
/// `1 << 31` so that the two kinds cannot be confused, and `statmount` and
/// `listmount` take only the unique kind -- a smaller one is EINVAL there. So
/// the unique id is the one those two answer, which is
/// `ffi::unique_mount_id`, and it answered the old one here until 2026-11-11.
pub const STATX_MNT_ID_UNIQUE: u32 = 1 << 14;
/// The `stx_attributes` bits the VFS answers itself, from
/// include/uapi/linux/stat.h.
pub const STATX_ATTR_AUTOMOUNT: u64 = 0x1000;
pub const STATX_ATTR_MOUNT_ROOT: u64 = 0x2000;
pub const STATX_ATTR_DAX: u64 = 0x0020_0000;
/// The bit no caller may set. `statx(2)` does not name it.
pub const STATX_RESERVED: u32 = 0x8000_0000;

// The flags statx accepts, from fcntl.h.
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const AT_NO_AUTOMOUNT: c_int = 0x800;
const AT_EMPTY_PATH: c_int = 0x1000;
const AT_STATX_SYNC_TYPE: c_int = 0x6000;
const AT_STATX_KNOWN: c_int =
    AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE;

use guest_errno::Errno;

// Field offsets, from include/uapi/linux/stat.h. Written out because a struct
// cannot be asked to justify one; the tests state each.
const OFF_MASK: usize = 0;
const OFF_BLKSIZE: usize = 4;
const OFF_ATTRIBUTES: usize = 8;
const OFF_NLINK: usize = 16;
const OFF_UID: usize = 20;
const OFF_GID: usize = 24;
const OFF_MODE: usize = 28;
const OFF_INO: usize = 32;
const OFF_SIZE: usize = 40;
const OFF_BLOCKS: usize = 48;
const OFF_ATTRIBUTES_MASK: usize = 56;
const OFF_ATIME: usize = 64;
const OFF_BTIME: usize = 80;
const OFF_CTIME: usize = 96;
const OFF_MTIME: usize = 112;
const OFF_RDEV_MAJOR: usize = 128;
const OFF_RDEV_MINOR: usize = 132;
const OFF_DEV_MAJOR: usize = 136;
const OFF_DEV_MINOR: usize = 140;
const OFF_MNT_ID: usize = 144;

/// A timestamp, or nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timestamp {
    pub sec: i64,
    pub nsec: u32,
}

/// What is known about a file.
///
/// The fields that may be unknown are `Option`, and that is the whole design:
/// [`encode`] sets a mask bit exactly where it writes a value, so the mask
/// cannot claim a field nobody filled.
#[derive(Clone, Copy, Debug, Default)]
pub struct FileInfo {
    pub blksize: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    /// Creation time. `struct statbuf` does not carry one and no mount here
    /// reports one, so this is `None` and `STATX_BTIME` stays clear — which is
    /// the difference between "we do not know" and "the epoch".
    pub btime: Option<Timestamp>,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    /// The mount this file is on, as `/proc/self/mountinfo` numbers it.
    pub mnt_id: Option<u64>,
    /// The same mount's unique id, for `STATX_MNT_ID_UNIQUE`.
    pub mnt_id_unique: Option<u64>,
    /// Whether this is the root of its mount: `STATX_ATTR_MOUNT_ROOT`.
    pub mount_root: bool,
}

/// Whether `statx` will accept these arguments.
///
/// Linux's `SYSCALL_DEFINE5(statx)` and `vfs_statx` between them reject four
/// things, and this rejected none of them:
///
/// - a `mask` with [`STATX_RESERVED`] set,
/// - a `flags` outside the set `statx` defines,
/// - both bits of the sync-type field at once — the field has three legal
///   values and that is not one of them.
///
/// Returns `Ok(())` or the guest errno.
pub fn validate(flags: c_int, mask: u32) -> Result<(), Errno> {
    if mask & STATX_RESERVED != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & !AT_STATX_KNOWN != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

fn put_u16(out: &mut [u8], at: usize, v: u16) {
    out[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(out: &mut [u8], at: usize, v: u32) {
    out[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(out: &mut [u8], at: usize, v: u64) {
    out[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// `struct statx_timestamp` is `{ __s64 tv_sec; __u32 tv_nsec; __s32 __pad; }`.
fn put_time(out: &mut [u8], at: usize, t: Timestamp) {
    put_u64(out, at, t.sec as u64);
    put_u32(out, at + 8, t.nsec);
    put_u32(out, at + 12, 0);
}

/// Fill the buffer, and return the mask that describes what was filled.
///
/// All [`STATX_BYTES`] are written. A kernel that writes fewer leaves whatever
/// the caller had in the tail, and the caller reads it as a field.
///
/// `requested` is not used to *withhold* anything: Linux says a kernel may
/// return more than was asked for, and every field here is free to compute. It
/// is taken so that the signature says what a caller passed and so a future
/// field that costs something has somewhere to look.
///
/// # Panics
/// If `out` is shorter than [`STATX_BYTES`].
pub fn encode(out: &mut [u8], info: &FileInfo, requested: u32) -> u32 {
    assert!(out.len() >= STATX_BYTES, "statx buffer too small");
    out[..STATX_BYTES].fill(0);

    // A bit is set by the line that writes its field, so the two cannot drift.
    let mut mask = 0;

    put_u32(out, OFF_BLKSIZE, info.blksize);
    put_u32(out, OFF_NLINK, info.nlink);
    mask |= STATX_NLINK;
    put_u32(out, OFF_UID, info.uid);
    mask |= STATX_UID;
    put_u32(out, OFF_GID, info.gid);
    mask |= STATX_GID;
    put_u16(out, OFF_MODE, info.mode);
    mask |= STATX_MODE | STATX_TYPE;
    put_u64(out, OFF_INO, info.ino);
    mask |= STATX_INO;
    put_u64(out, OFF_SIZE, info.size);
    mask |= STATX_SIZE;
    put_u64(out, OFF_BLOCKS, info.blocks);
    mask |= STATX_BLOCKS;

    put_time(out, OFF_ATIME, info.atime);
    mask |= STATX_ATIME;
    put_time(out, OFF_MTIME, info.mtime);
    mask |= STATX_MTIME;
    put_time(out, OFF_CTIME, info.ctime);
    mask |= STATX_CTIME;
    if let Some(btime) = info.btime {
        put_time(out, OFF_BTIME, btime);
        mask |= STATX_BTIME;
    }

    put_u32(out, OFF_RDEV_MAJOR, info.rdev_major);
    put_u32(out, OFF_RDEV_MINOR, info.rdev_minor);
    put_u32(out, OFF_DEV_MAJOR, info.dev_major);
    put_u32(out, OFF_DEV_MINOR, info.dev_minor);

    // Which of the two bits to set is the caller's choice, as on Linux: one
    // field, two names for it, and `stx_mask` says which was answered.
    match (info.mnt_id, info.mnt_id_unique) {
        (_, Some(unique)) if requested & STATX_MNT_ID_UNIQUE != 0 => {
            put_u64(out, OFF_MNT_ID, unique);
            mask |= STATX_MNT_ID_UNIQUE;
        }
        (Some(id), _) => {
            put_u64(out, OFF_MNT_ID, id);
            mask |= STATX_MNT_ID;
        }
        _ => {}
    }

    // `attributes_mask` says which bits of `attributes` this kernel knows
    // about, and the three the VFS answers for every filesystem are the ones
    // it does: Linux's `vfs_getattr_nosec` and `vfs_statx` claim these
    // whatever the disk is. A filesystem's own -- compressed, immutable,
    // append, encrypted, verity -- are not claimed, because nothing here
    // stores them.
    //
    // It was zero until 2026-11-11, so `STATX_ATTR_MOUNT_ROOT` -- which
    // systemd's `fd_is_mount_point` asks before anything else -- read as "not
    // known" for every file. `AUTOMOUNT` and `DAX` are known and never set:
    // there is no automounter and no DAX.
    put_u64(out, OFF_ATTRIBUTES_MASK, STATX_ATTR_AUTOMOUNT | STATX_ATTR_MOUNT_ROOT | STATX_ATTR_DAX);
    if info.mount_root {
        put_u64(out, OFF_ATTRIBUTES, STATX_ATTR_MOUNT_ROOT);
    }

    put_u32(out, OFF_MASK, mask);
    mask
}

// ---------------------------------------------------------------------------
// The C ABI
// ---------------------------------------------------------------------------

/// The fields the C side has, in the order `fs/stat.c` reads them off a
/// `struct statbuf`. Mirrored rather than bindgen'd because `struct statbuf`
/// is the *internal* shape and this is the crate's own input; the C fills it
/// field by field, which is where the widening of the 32-bit times happens.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CFileInfo {
    pub blksize: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime_sec: i64,
    pub atime_nsec: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FileInfo {
        FileInfo {
            blksize: 4096,
            nlink: 2,
            uid: 1000,
            gid: 1000,
            mode: 0o100644,
            ino: 0x1234_5678,
            size: 10,
            blocks: 8,
            atime: Timestamp {
                sec: 1_700_000_000,
                nsec: 111,
            },
            mtime: Timestamp {
                sec: 1_700_000_001,
                nsec: 222,
            },
            ctime: Timestamp {
                sec: 1_700_000_002,
                nsec: 333,
            },
            btime: None,
            rdev_major: 0,
            rdev_minor: 0,
            dev_major: 8,
            dev_minor: 1,
            mnt_id: None,
            mnt_id_unique: None,
            mount_root: false,
        }
    }

    fn get_u32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }
    fn get_u64(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
    }

    /// The offsets, stated rather than derived from a struct.
    #[test]
    fn the_offsets_are_the_ones_linux_fixes() {
        assert_eq!(STATX_BYTES, 256);
        assert_eq!(OFF_MASK, 0);
        assert_eq!(OFF_BLKSIZE, 4);
        assert_eq!(OFF_NLINK, 16);
        assert_eq!(
            OFF_MODE, 28,
            "stx_mode is a u16 after three u32s and stx_attributes"
        );
        assert_eq!(OFF_INO, 32);
        assert_eq!(OFF_SIZE, 40);
        assert_eq!(OFF_BLOCKS, 48);
        assert_eq!(OFF_ATIME, 64);
        assert_eq!(OFF_BTIME, 80, "btime comes second, between atime and ctime");
        assert_eq!(OFF_CTIME, 96);
        assert_eq!(OFF_MTIME, 112);
        assert_eq!(OFF_MNT_ID, 144);
    }

    #[test]
    fn the_fields_land_where_a_caller_reads_them() {
        let mut b = [0xABu8; STATX_BYTES];
        let info = sample();
        encode(&mut b, &info, STATX_BASIC_STATS);
        assert_eq!(get_u32(&b, OFF_BLKSIZE), 4096);
        assert_eq!(get_u32(&b, OFF_NLINK), 2);
        assert_eq!(get_u32(&b, OFF_UID), 1000);
        assert_eq!(u16::from_le_bytes([b[OFF_MODE], b[OFF_MODE + 1]]), 0o100644);
        assert_eq!(get_u64(&b, OFF_INO), 0x1234_5678);
        assert_eq!(get_u64(&b, OFF_SIZE), 10);
        assert_eq!(get_u64(&b, OFF_ATIME), 1_700_000_000);
        assert_eq!(get_u32(&b, OFF_ATIME + 8), 111);
        assert_eq!(get_u64(&b, OFF_MTIME), 1_700_000_001);
        assert_eq!(get_u64(&b, OFF_CTIME), 1_700_000_002);
    }

    /// The whole buffer is written. A kernel that fills only the fields it
    /// knows leaves the caller's own bytes in the tail, and a caller reads
    /// them as fields — `abi_structs` fills the buffer with 0xAB and checks.
    #[test]
    fn all_two_hundred_and_fifty_six_bytes_are_written() {
        let mut b = [0xABu8; STATX_BYTES];
        encode(&mut b, &sample(), STATX_BASIC_STATS);
        assert!(
            !b.contains(&0xAB),
            "some of the buffer was left as the caller had it"
        );
    }

    /// The point of the `Option`s. An unknown birth time leaves its bit clear
    /// and its field zero, and a caller that checks the bit never reads the
    /// zero as a date.
    #[test]
    fn an_unknown_field_is_not_claimed() {
        let mut b = [0u8; STATX_BYTES];
        let mask = encode(&mut b, &sample(), u32::MAX);
        assert_eq!(mask & STATX_BTIME, 0, "btime was claimed without a value");
        assert_eq!(mask & STATX_MNT_ID, 0, "mnt_id was claimed without a value");
        assert_eq!(
            mask & STATX_MNT_ID_UNIQUE,
            0,
            "nor the unique spelling of it"
        );
        assert_eq!(get_u64(&b, OFF_BTIME), 0);
        assert_eq!(
            get_u32(&b, OFF_MASK),
            mask,
            "the mask in the buffer is the one returned"
        );
    }

    /// And a known one is claimed, by the same line that writes it.
    #[test]
    fn a_known_field_is_claimed() {
        let mut info = sample();
        info.btime = Some(Timestamp {
            sec: 1_600_000_000,
            nsec: 7,
        });
        let mut b = [0u8; STATX_BYTES];
        let mask = encode(&mut b, &info, u32::MAX);
        assert_ne!(mask & STATX_BTIME, 0);
        assert_eq!(get_u64(&b, OFF_BTIME), 1_600_000_000);
        assert_eq!(get_u32(&b, OFF_BTIME + 8), 7);
    }

    /// Everything `struct statbuf` carries is claimed, so a caller asking for
    /// the basic set gets all of it. This is what the C's unconditional
    /// `stx_mask = STATX_BASIC_STATS` asserted by hand.
    #[test]
    fn the_basic_set_is_complete() {
        let mut b = [0u8; STATX_BYTES];
        let mask = encode(&mut b, &sample(), STATX_BASIC_STATS);
        assert_eq!(mask & STATX_BASIC_STATS, STATX_BASIC_STATS, "{mask:#x}");
        assert_eq!(mask & STATX_RESERVED, 0);
    }

    /// A time before the epoch is negative and stays negative. The field is an
    /// `__s64` for that reason, and the C side reads it out of a `dword_t`,
    /// which is where a negative one is lost — see the note in `fs/stat.c`.
    #[test]
    fn a_time_before_the_epoch_survives_the_format() {
        let mut info = sample();
        info.mtime = Timestamp {
            sec: -86_400,
            nsec: 5,
        };
        let mut b = [0u8; STATX_BYTES];
        encode(&mut b, &info, STATX_BASIC_STATS);
        assert_eq!(get_u64(&b, OFF_MTIME) as i64, -86_400);
    }

    #[test]
    fn the_reserved_mask_bit_is_refused() {
        assert_eq!(validate(0, STATX_RESERVED), Err(Errno::EINVAL));
        assert_eq!(validate(0, STATX_BASIC_STATS | STATX_RESERVED), Err(Errno::EINVAL));
        assert_eq!(validate(0, STATX_BASIC_STATS), Ok(()));
        assert_eq!(validate(0, 0), Ok(()), "asking for nothing is not an error");
        assert_eq!(validate(0, !STATX_RESERVED), Ok(()));
    }

    #[test]
    fn an_undefined_flag_is_refused() {
        assert_eq!(validate(0x8000, STATX_BASIC_STATS), Err(Errno::EINVAL));
        assert_eq!(validate(AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS), Ok(()));
        assert_eq!(validate(AT_EMPTY_PATH, STATX_BASIC_STATS), Ok(()));
        assert_eq!(validate(AT_NO_AUTOMOUNT, STATX_BASIC_STATS), Ok(()));
    }

    /// The sync-type field has three legal values out of four. Both bits at
    /// once is the fourth, and Linux refuses it.
    #[test]
    fn both_sync_bits_at_once_are_refused() {
        assert_eq!(validate(AT_STATX_SYNC_TYPE, 0), Err(Errno::EINVAL));
        assert_eq!(validate(0x0000, 0), Ok(()), "SYNC_AS_STAT");
        assert_eq!(validate(0x2000, 0), Ok(()), "FORCE_SYNC");
        assert_eq!(validate(0x4000, 0), Ok(()), "DONT_SYNC");
    }

    #[test]
    fn one_field_two_names_and_the_caller_picks() {
        // `stx_mnt_id` is one field. Linux answers `STATX_MNT_ID_UNIQUE` when
        // that is what was asked for and `STATX_MNT_ID` otherwise, and a caller
        // reads the same offset either way. Both must never be set at once:
        // that would tell a program its kernel promises something it did not
        // ask about.
        let mut info = sample();
        info.mnt_id = Some(7);
        info.mnt_id_unique = Some((1 << 31) + 7);
        let mut out = [0u8; STATX_BYTES];

        let mask = encode(&mut out, &info, STATX_BASIC_STATS | STATX_MNT_ID);
        assert_eq!(mask & STATX_MNT_ID, STATX_MNT_ID);
        assert_eq!(mask & STATX_MNT_ID_UNIQUE, 0);
        assert_eq!(
            u64::from_le_bytes(out[OFF_MNT_ID..OFF_MNT_ID + 8].try_into().unwrap()),
            7
        );

        let mask = encode(&mut out, &info, STATX_MNT_ID_UNIQUE);
        assert_eq!(mask & STATX_MNT_ID_UNIQUE, STATX_MNT_ID_UNIQUE);
        assert_eq!(mask & STATX_MNT_ID, 0, "not both");
        assert_eq!(
            u64::from_le_bytes(out[OFF_MNT_ID..OFF_MNT_ID + 8].try_into().unwrap()),
            (1 << 31) + 7,
            "the unique kind, which statmount takes"
        );

        // Asking for neither still answers the plain one, which is what Linux
        // does: the field is filled whether or not it was requested.
        let mask = encode(&mut out, &info, 0);
        assert_eq!(mask & STATX_MNT_ID, STATX_MNT_ID);
    }

    /// The three the VFS knows about are claimed for every file, and the one
    /// that can be set is set exactly on a mount's root.
    #[test]
    fn mount_root_is_known_about_and_set_on_a_root() {
        let get = |b: &[u8], at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        let mut out = [0u8; STATX_BYTES];
        let mut info = sample();
        encode(&mut out, &info, STATX_BASIC_STATS);
        assert_eq!(get(&out, OFF_ATTRIBUTES_MASK), 0x20_3000);
        assert_eq!(get(&out, OFF_ATTRIBUTES), 0);
        info.mount_root = true;
        encode(&mut out, &info, STATX_BASIC_STATS);
        assert_eq!(get(&out, OFF_ATTRIBUTES), STATX_ATTR_MOUNT_ROOT);
    }
}
