//! Linux's extensible argument structs: `copy_struct_from_user`.
//!
//! `openat2`'s `open_how`, the `*xattrat` calls' `xattr_args`, `file_setattr`'s
//! `file_attr` and `statmount`'s `mnt_id_req` are passed with their size, and
//! the size is the version: a caller built against an older kernel passes a
//! shorter struct and the missing fields read as zero, one built against a
//! newer kernel passes a longer one. The longer one is accepted only if every
//! byte this kernel has no field for is zero, and is `E2BIG` otherwise --
//! silently dropping a field a caller set is the failure the protocol exists
//! to prevent, because the caller would go on believing it got what it asked
//! for.
//!
//! What a struct's *minimum* and *maximum* sizes are, and which errno a size
//! outside them is, differs per syscall and is checked by each caller before
//! it gets here: `openat2` answers `EINVAL` below `OPEN_HOW_SIZE_VER0` and
//! `E2BIG` above a page, `file_getattr` checks the page bound first.

use guest_errno::Errno;

use crate::GuestIo;

/// Fill `out` from the `size` bytes at `addr`.
///
/// A short struct leaves the rest of `out` zero; a long one has its tail
/// checked a chunk at a time, so a size the caller has not bounded costs no
/// allocation. `EFAULT` for any byte that cannot be read, `E2BIG` for a
/// nonzero byte past `out.len()`.
pub fn read_extensible(mem: &impl GuestIo, addr: u64, size: usize, out: &mut [u8]) -> Result<(), Errno> {
    out.fill(0);
    let known = size.min(out.len());
    if mem.read(addr, &mut out[..known]) != 0 {
        return Err(Errno::EFAULT);
    }
    let mut at = known;
    let mut chunk = [0u8; 256];
    while at < size {
        let n = (size - at).min(chunk.len());
        let tail = addr.checked_add(at as u64).ok_or(Errno::EFAULT)?;
        if mem.read(tail, &mut chunk[..n]) != 0 {
            return Err(Errno::EFAULT);
        }
        if chunk[..n].iter().any(|&b| b != 0) {
            return Err(Errno::E2BIG);
        }
        at += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_int;

    /// Guest memory as a `Vec` mapped at `base`.
    struct Mem {
        base: u64,
        bytes: Vec<u8>,
    }

    impl GuestIo for Mem {
        fn read_u64(&self, _addr: u64) -> Result<u64, c_int> {
            unimplemented!()
        }
        fn write_u64(&self, _addr: u64, _value: u64) -> c_int {
            unimplemented!()
        }
        fn write(&self, _addr: u64, _bytes: &[u8]) -> c_int {
            unimplemented!()
        }
        fn read(&self, addr: u64, out: &mut [u8]) -> c_int {
            let Some(off) = addr.checked_sub(self.base) else {
                return Errno::EFAULT.as_c_int();
            };
            let off = off as usize;
            match self.bytes.get(off..off + out.len()) {
                Some(src) => {
                    out.copy_from_slice(src);
                    0
                }
                None => Errno::EFAULT.as_c_int(),
            }
        }
        fn read_string(&self, _addr: u64, _buf: &mut [u8]) -> Result<usize, c_int> {
            unimplemented!()
        }
    }

    fn mem(bytes: Vec<u8>) -> Mem {
        Mem { base: 0x1000, bytes }
    }

    #[test]
    fn a_short_struct_reads_as_zero_past_its_end() {
        let m = mem(vec![1, 2, 3, 4]);
        let mut out = [0xffu8; 8];
        read_extensible(&m, 0x1000, 4, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn a_long_struct_with_a_zero_tail_is_accepted() {
        let mut bytes = vec![7u8; 8];
        bytes.extend(std::iter::repeat_n(0, 1000));
        let m = mem(bytes);
        let mut out = [0u8; 8];
        read_extensible(&m, 0x1000, 1008, &mut out).unwrap();
        assert_eq!(out, [7; 8]);
    }

    /// The protocol's whole point: a field this kernel does not know about,
    /// set, is refused rather than dropped -- including in the last byte of a
    /// tail longer than one chunk.
    #[test]
    fn a_nonzero_byte_in_the_tail_is_e2big() {
        let mut bytes = vec![0u8; 8 + 600];
        *bytes.last_mut().unwrap() = 1;
        let m = mem(bytes);
        let mut out = [0u8; 8];
        assert_eq!(read_extensible(&m, 0x1000, 608, &mut out), Err(Errno::E2BIG));
    }

    #[test]
    fn an_unreadable_tail_is_efault() {
        let m = mem(vec![0u8; 16]);
        let mut out = [0u8; 8];
        assert_eq!(read_extensible(&m, 0x1000, 32, &mut out), Err(Errno::EFAULT));
        assert_eq!(read_extensible(&m, 0, 8, &mut out), Err(Errno::EFAULT));
    }
}
