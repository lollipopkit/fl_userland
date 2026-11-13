//! `openat2(2)`: `openat` with an extensible argument struct whose `resolve`
//! word confines the walk.
//!
//! The confinement is `crates/fs/path`'s (`Scope`): a syscall that accepted
//! the flags and walked as usual would hand back a descriptor the caller
//! believes cannot be outside its root, which is worse than the `ENOSYS` this
//! number answered until 2026-11-11 -- glibc falls back to `openat` on that,
//! and Go to an `O_PATH` walk that checks each component. What is here is the
//! argument protocol, which is strict where `openat`'s is lax: an unknown
//! flag, a mode without a create, or a resolve bit nobody defines is `EINVAL`
//! rather than ignored. Every rule and its order was measured with
//! `tests/guest/src/bin/openat2_probe.rs` against an arm64 7.2 kernel.

use super::*;

use fs_generic::O_EMPTYPATH;

/// `struct open_how`'s first published size; anything shorter is `EINVAL`.
const OPEN_HOW_SIZE_VER0: usize = 24;

/// `OPENAT2_REGULAR`: bit 32, so `open(2)`'s 32-bit word cannot spell it.
const OPENAT2_REGULAR: u64 = 1 << 32;
/// `__O_TMPFILE`, the half of `O_TMPFILE` that is not `O_DIRECTORY`.
const O_TMPFILE_BIT: u64 = (ffi::O_TMPFILE_ & !ffi::O_DIRECTORY_) as u64;

/// Linux's `VALID_OPEN_FLAGS`, plus the two 7.x added.
///
/// Measured bit by bit: the access mode, bits 6 to 22, `O_EMPTYPATH` (26) and
/// `OPENAT2_REGULAR` (32). Bits 2 to 5, 23 to 25, 27 to 31 and above 32 are
/// `EINVAL`, where `openat` ignores every one of them.
const VALID_OPEN_FLAGS: u64 = 0o3
    | (ffi::O_CREAT_
        | ffi::O_EXCL_
        | ffi::O_NOCTTY_
        | ffi::O_TRUNC_
        | ffi::O_APPEND_
        | ffi::O_NONBLOCK_
        | ffi::O_DSYNC_
        | ffi::O_ASYNC_
        | ffi::O_DIRECTORY_
        | ffi::O_NOFOLLOW_
        | ffi::O_DIRECT_
        | ffi::O_LARGEFILE_
        | ffi::O_NOATIME_
        | ffi::O_CLOEXEC_
        | ffi::O_SYNC_
        | ffi::O_PATH_
        | ffi::O_TMPFILE_) as u64
    | O_EMPTYPATH as u64
    | OPENAT2_REGULAR;

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;
const VALID_RESOLVE_FLAGS: u64 = 0x3f;

/// `struct open_how`, decoded from the bytes the guest passed -- not yet
/// judged, which is what [`Raw::validate`] does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Raw {
    flags: u64,
    mode: u64,
    resolve: u64,
}

impl Raw {
    fn decode(raw: &[u8; OPEN_HOW_SIZE_VER0]) -> Raw {
        let word = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().expect("eight bytes"));
        Raw {
            flags: word(0),
            mode: word(1),
            resolve: word(2),
        }
    }

    /// Linux's `build_open_flags`, in its order: what `openat` would have
    /// done with these flags, or the errno `openat2` refuses them with.
    fn validate(self) -> Result<(c_int, c_uint, fs_generic::OpenHow), Errno> {
        let flags = self.flags;
        if flags & !VALID_OPEN_FLAGS != 0 || self.resolve & !VALID_RESOLVE_FLAGS != 0 {
            return Err(Errno::EINVAL);
        }
        let r = |bit: u64| self.resolve & bit != 0;
        // The two scoping flags are two answers to one question.
        if r(RESOLVE_BENEATH) && r(RESOLVE_IN_ROOT) {
            return Err(Errno::EINVAL);
        }
        // A mode means something only to a call that makes a file, and then
        // only its permission bits do.
        let will_create = flags & (ffi::O_CREAT_ as u64 | O_TMPFILE_BIT) != 0;
        if will_create {
            if self.mode & !0o7777 != 0 {
                return Err(Errno::EINVAL);
            }
        } else if self.mode != 0 {
            return Err(Errno::EINVAL);
        }
        let dir_and_create = (ffi::O_DIRECTORY_ | ffi::O_CREAT_) as u64;
        if flags & dir_and_create == dir_and_create {
            return Err(Errno::EINVAL);
        }
        if flags & O_TMPFILE_BIT != 0 {
            // `O_TMPFILE` is the bit and `O_DIRECTORY`, so that a kernel that
            // does not know it opens a directory -- and a file nobody can
            // write is a temporary file nobody can use.
            if flags & ffi::O_DIRECTORY_ as u64 == 0 || flags & 0o3 == 0 {
                return Err(Errno::EINVAL);
            }
        }
        if flags & ffi::O_PATH_ as u64 != 0 && flags & !(fs_generic::O_PATH_FLAGS as u64) != 0 {
            return Err(Errno::EINVAL);
        }
        let regular_only = flags & OPENAT2_REGULAR != 0;
        // A regular file is not a directory, and a reference opens nothing
        // to check the type of. Measured: both are `EINVAL`.
        if regular_only && flags & (ffi::O_DIRECTORY_ | ffi::O_PATH_) as u64 != 0 {
            return Err(Errno::EINVAL);
        }
        if r(RESOLVE_CACHED) && flags & (ffi::O_TRUNC_ as u64 | ffi::O_CREAT_ as u64 | O_TMPFILE_BIT) != 0 {
            // A create or a truncation always does I/O, so there is nothing
            // to try.
            return Err(Errno::EAGAIN);
        }
        let scope = path::Scope {
            no_xdev: r(RESOLVE_NO_XDEV),
            no_magiclinks: r(RESOLVE_NO_MAGICLINKS),
            no_symlinks: r(RESOLVE_NO_SYMLINKS),
            beneath: r(RESOLVE_BENEATH),
            in_root: r(RESOLVE_IN_ROOT),
            cached: r(RESOLVE_CACHED),
        };
        // The low 32 bits are `openat`'s word; `OPENAT2_REGULAR` travels as
        // its own field.
        Ok((
            flags as u32 as c_int,
            self.mode as c_uint,
            fs_generic::OpenHow { scope, regular_only, ..Default::default() },
        ))
    }
}

pub fn sys_openat2(at_f: c_int, path_addr: u64, how_addr: u64, size: u64) -> Result<i64, Errno> {
    strace!("openat2({at_f}, {path_addr:#x}, {how_addr:#x}, {size})");
    // The size first, then the struct, then the path: a NULL `how` with a
    // size above a page is `E2BIG`, and a bad flag beats a NULL path.
    if (size as usize) < OPEN_HOW_SIZE_VER0 {
        return Err(Errno::EINVAL);
    }
    if size > ffi::PAGE_SIZE as u64 {
        return Err(Errno::E2BIG);
    }
    let mut raw = [0u8; OPEN_HOW_SIZE_VER0];
    usercopy::read_extensible(&GuestMem, how_addr, size as usize, &mut raw)?;
    let how = Raw::decode(&raw);
    let (flags, mode, open_how) = how.validate()?;

    let path = Path::read(path_addr)?;
    strace!(" {:?} {how:?}", path.as_str());
    // An empty name is ENOENT before the descriptor is looked at, unless
    // `O_EMPTYPATH` says it means the descriptor.
    if path.0[0] == 0 && flags & O_EMPTYPATH == 0 {
        return Err(Errno::ENOENT);
    }
    // `RESOLVE_IN_ROOT` starts an absolute path at the descriptor too, so it
    // has to be looked up whatever the path says: a closed one is `EBADF`.
    let at = if open_how.scope.in_root {
        fs_fdobj::at_fd(at_f, c".").ok_or(Errno::EBADF)?
    } else {
        at_of(at_f, &path)?
    };
    let mode = if flags & (ffi::O_CREAT_ | ffi::O_TMPFILE_) as c_int != 0 {
        apply_umask(mode)
    } else {
        mode
    };
    let fd = fs_generic::generic_openat2(at.at(), path.as_cstr(), flags, mode as c_int, open_how)?;
    Errno::split(fs_fdobj::f_install(fd, flags) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn how(flags: u64, mode: u64, resolve: u64) -> Result<(c_int, c_uint, fs_generic::OpenHow), Errno> {
        Raw { flags, mode, resolve }.validate()
    }

    #[test]
    fn the_struct_is_three_little_endian_words() {
        let mut raw = [0u8; 24];
        raw[0] = 0x41;
        raw[8..10].copy_from_slice(&0o644u16.to_le_bytes());
        raw[16] = 0x08;
        assert_eq!(Raw::decode(&raw), Raw { flags: 0x41, mode: 0o644, resolve: 8 });
    }

    /// The bits a real kernel accepts, and nothing else.
    #[test]
    fn unknown_bits_are_refused_where_openat_ignores_them() {
        for bit in [2, 3, 4, 5, 23, 24, 25, 27, 28, 29, 30, 31, 33, 63] {
            assert_eq!(how(1 << bit, 0, 0).err(), Some(Errno::EINVAL), "bit {bit}");
        }
        for bit in [0, 1, 7, 13, 16, 17, 18, 19, 20, 26, 32] {
            assert!(how(1 << bit, 0, 0).is_ok(), "bit {bit}");
        }
        assert_eq!(how(0, 0, 0x40).err(), Some(Errno::EINVAL));
        assert_eq!(how(0, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT).err(), Some(Errno::EINVAL));
    }

    #[test]
    fn mode_and_the_create_flags() {
        let creat = ffi::O_CREAT_ as u64;
        assert_eq!(how(0, 0o644, 0).err(), Some(Errno::EINVAL));
        assert!(how(creat, 0o7777, 0).is_ok());
        assert_eq!(how(creat, 0o10000, 0).err(), Some(Errno::EINVAL));
        assert_eq!(how(creat | ffi::O_DIRECTORY_ as u64, 0, 0).err(), Some(Errno::EINVAL));
        let tmpfile = ffi::O_TMPFILE_ as u64;
        assert_eq!(how(tmpfile, 0o600, 0).err(), Some(Errno::EINVAL), "read-only O_TMPFILE");
        assert_eq!(how(O_TMPFILE_BIT | 2, 0o600, 0).err(), Some(Errno::EINVAL), "without O_DIRECTORY");
        assert!(how(tmpfile | 2, 0o600, 0).is_ok());
    }

    #[test]
    fn o_path_keeps_only_its_four() {
        let path = ffi::O_PATH_ as u64;
        assert!(how(path | (ffi::O_DIRECTORY_ | ffi::O_NOFOLLOW_ | ffi::O_CLOEXEC_) as u64, 0, 0).is_ok());
        for extra in [2, ffi::O_LARGEFILE_ as u64, ffi::O_NONBLOCK_ as u64, ffi::O_CREAT_ as u64, OPENAT2_REGULAR] {
            assert_eq!(how(path | extra, 0, 0).err(), Some(Errno::EINVAL), "{extra:#o}");
        }
        assert_eq!(how(OPENAT2_REGULAR | ffi::O_DIRECTORY_ as u64, 0, 0).err(), Some(Errno::EINVAL));
    }

    #[test]
    fn resolve_cached_refuses_what_always_does_io() {
        for f in [ffi::O_CREAT_ as u64, ffi::O_TRUNC_ as u64, ffi::O_TMPFILE_ as u64 | 2] {
            let mode = if f & ffi::O_TRUNC_ as u64 != 0 { 0 } else { 0o600 };
            assert_eq!(how(f, mode, RESOLVE_CACHED).err(), Some(Errno::EAGAIN), "{f:#o}");
        }
        let (_, _, h) = how(0, 0, RESOLVE_CACHED | RESOLVE_NO_XDEV).unwrap();
        assert!(h.scope.cached && h.scope.no_xdev && !h.scope.beneath);
    }

    #[test]
    fn regular_only_travels_beside_the_low_word() {
        let (flags, _, h) = how(OPENAT2_REGULAR | 2, 0, 0).unwrap();
        assert_eq!(flags, 2);
        assert!(h.regular_only);
    }
}
