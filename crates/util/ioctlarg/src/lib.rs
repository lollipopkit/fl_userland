//! An ioctl's argument, as a driver sees it.
//!
//! The kernel asks a driver how large a command's argument is, copies that
//! many bytes in from the guest, and hands the driver the buffer; a size of
//! zero means the argument is the value itself. Until 2026-09-30 the buffer
//! arrived as a `*mut c_void` and `FdOps::ioctl` was an `unsafe fn`, so eight
//! drivers each cast it to the type the command names -- and four of them did
//! it with an **aligned** access or a reference into a `[u8; 128]` on the
//! stack, whose alignment is one. It happened to be aligned, because the array
//! followed a word-sized field. Nothing said it had to be.
//!
//! Here the buffer is a `&mut [u8]` whose length is the size the driver
//! answered, and a typed read or write is a checked, unaligned copy.

/// A type an ioctl argument may be read as or written from.
pub use plain::Plain;

use std::mem::size_of;

/// The argument of one ioctl.
pub enum IoctlArg<'a> {
    /// The driver answered a size of zero: the guest's argument register.
    Value(usize),
    /// The driver answered a size: exactly that many bytes, copied in from
    /// the guest and copied back out when the driver succeeds.
    Buf(&'a mut [u8]),
}

impl IoctlArg<'_> {
    /// The argument as a `T`, or `None` for a value, or a buffer that is not
    /// exactly a `T` -- which is the driver's size table disagreeing with
    /// its handler.
    pub fn read<T: Plain>(&self) -> Option<T> {
        match self {
            IoctlArg::Buf(buf) => plain::from_bytes(buf),
            IoctlArg::Value(_) => None,
        }
    }

    /// Store `value` as the argument. False when [`IoctlArg::read`] would
    /// answer `None` for a `T`.
    pub fn write<T: Plain>(&mut self, value: T) -> bool {
        match self {
            IoctlArg::Buf(buf) if buf.len() == size_of::<T>() => {
                buf.copy_from_slice(plain::bytes_of(&value));
                true
            }
            _ => false,
        }
    }

    /// Run `f` over the argument as a `T` and store what it leaves, or `None`
    /// when the buffer is not a `T`. The shape of a command that reads its
    /// argument, writes it, or both.
    pub fn with<T: Plain, R>(&mut self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut value = self.read::<T>()?;
        let out = f(&mut value);
        self.write(value);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_word_goes_in_and_comes_out_at_any_alignment() {
        let mut backing = [0u8; 9];
        // Offset one, so a `u32` access through the pointer would be
        // misaligned; the copies do not care.
        let mut arg = IoctlArg::Buf(&mut backing[1..5]);
        assert!(arg.write(0x0102_0304u32));
        assert_eq!(arg.read::<u32>(), Some(0x0102_0304));
        assert_eq!(arg.with(|w: &mut u32| *w += 1), Some(()));
        assert_eq!(backing[1..5], 0x0102_0305u32.to_ne_bytes());
    }

    #[test]
    fn a_buffer_of_the_wrong_size_is_not_a_t() {
        let mut backing = [0u8; 8];
        let mut arg = IoctlArg::Buf(&mut backing);
        assert_eq!(arg.read::<u32>(), None);
        assert!(!arg.write(1u32));
        assert_eq!(arg.with(|_: &mut u32| ()), None);
        assert_eq!(backing, [0; 8], "a refused write writes nothing");
    }

    #[test]
    fn a_value_is_not_a_buffer() {
        let mut arg = IoctlArg::Value(7);
        assert_eq!(arg.read::<u32>(), None);
        assert!(!arg.write(1u32));
    }
}
