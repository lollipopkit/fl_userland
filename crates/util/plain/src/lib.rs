//! Types whose bytes are their value: a guest wire format, viewed as bytes.
//!
//! A syscall that hands the guest a `struct stat` used to build it, take its
//! address and `from_raw_parts` it into a `&[u8]` -- an `unsafe` block at each
//! of nine copies, each sound only if the struct had **no padding**, which none
//! of them checked. Padding is not part of a value: no construction
//! initialises it and any move may leave it as whatever the stack held. That is
//! not hypothetical here: `siginfo_` had four bytes of it until 2026-09-30, and
//! every `sigtimedwait` handed them to the guest.
//!
//! [`plain!`] is where that is checked, at compile time: it lists the fields,
//! asserts each is itself [`Plain`], and asserts their sizes add up to the
//! struct's. A field added to the struct and not to the list, or a hole the
//! compiler inserted, fails the build. The one `unsafe impl` is in the macro.

use std::mem::size_of;

/// A type every bit pattern of whose `size_of::<Self>()` bytes is a valid
/// value, and none of whose bytes is padding.
///
/// Implement it with [`plain!`], which checks the second half.
///
/// # Safety
///
/// No padding, and no invalid bit patterns: integers and arrays of them, and
/// structs of those with nothing between the fields.
pub unsafe trait Plain: Copy {}

macro_rules! integers {
    ($($t:ty)*) => {$(
        // SAFETY: an integer has neither padding nor invalid bit patterns.
        unsafe impl Plain for $t {}
    )*};
}
integers!(u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize);

// SAFETY: an array has no padding between elements; its size is `N` times the
// element's, and the element has none.
unsafe impl<T: Plain, const N: usize> Plain for [T; N] {}

/// Implement [`Plain`] for structs whose every field is listed and `Plain`.
///
/// ```ignore
/// plain::plain!(Winsize { row, col, xpixel, ypixel });
/// ```
///
/// Fails to compile when a field is not `Plain`, or when the listed fields'
/// sizes do not add up to the struct's: padding, or a field missing from the
/// list.
#[macro_export]
macro_rules! plain {
    ($($t:ty { $($f:ident),* $(,)? })*) => {$(
        // SAFETY: every field is `Plain` and the assertion below proves the
        // fields fill the struct, so it has no padding.
        unsafe impl $crate::Plain for $t {}
        const _: () = assert!(
            ::core::mem::size_of::<$t>() == 0 $(+ $crate::field_size(|s: &$t| &s.$f))*,
            concat!(stringify!($t), " has padding, or a field `plain!` does not list"),
        );
    )*};
}

/// The size of the field `f` names, which must be `Plain`. For [`plain!`].
#[doc(hidden)]
pub const fn field_size<T, F: Plain>(_f: fn(&T) -> &F) -> usize {
    size_of::<F>()
}

/// `value`'s bytes, in memory order.
pub fn bytes_of<T: Plain>(value: &T) -> &[u8] {
    // SAFETY: `size_of::<T>()` bytes behind a live reference, and `Plain` says
    // none of them is padding, so every one is initialised.
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
}

/// `value`'s bytes, writable.
pub fn bytes_of_mut<T: Plain>(value: &mut T) -> &mut [u8] {
    // SAFETY: as `bytes_of`, and `Plain` says any bytes written are a valid
    // `T`.
    unsafe { std::slice::from_raw_parts_mut((value as *mut T).cast::<u8>(), size_of::<T>()) }
}

/// The bytes of a slice of `T`, in memory order.
pub fn slice_bytes<T: Plain>(values: &[T]) -> &[u8] {
    // SAFETY: as `bytes_of`; a slice has no padding between elements.
    unsafe { std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), size_of_val(values)) }
}

/// [`slice_bytes`], writable.
pub fn slice_bytes_mut<T: Plain>(values: &mut [T]) -> &mut [u8] {
    let len = size_of_val(values);
    // SAFETY: as `bytes_of_mut`.
    unsafe { std::slice::from_raw_parts_mut(values.as_mut_ptr().cast::<u8>(), len) }
}

/// A `T` read from `bytes`, which must be exactly its size. At any alignment.
pub fn from_bytes<T: Plain>(bytes: &[u8]) -> Option<T> {
    if bytes.len() != size_of::<T>() {
        return None;
    }
    // SAFETY: `size_of::<T>()` readable bytes, read unaligned, and `Plain`
    // says any bytes are a valid `T`.
    Some(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq)]
    struct Pair {
        a: u32,
        b: [u8; 4],
    }
    plain!(Pair { a, b });

    #[test]
    fn a_struct_round_trips_through_its_bytes() {
        let p = Pair { a: 0x0102_0304, b: *b"wxyz" };
        let bytes = bytes_of(&p).to_vec();
        assert_eq!(bytes[..4], 0x0102_0304u32.to_ne_bytes());
        assert_eq!(&bytes[4..], b"wxyz");
        assert_eq!(from_bytes::<Pair>(&bytes), Some(p));

        let mut q = Pair::default();
        bytes_of_mut(&mut q).copy_from_slice(&bytes);
        assert_eq!(q, p);
    }

    #[test]
    fn the_wrong_length_is_not_a_t() {
        assert_eq!(from_bytes::<Pair>(&[0; 7]), None);
        assert_eq!(from_bytes::<Pair>(&[0; 9]), None);
    }

    #[test]
    fn a_slice_is_its_elements_back_to_back() {
        let mut words = [1u32, 2, 3];
        assert_eq!(slice_bytes(&words).len(), 12);
        slice_bytes_mut(&mut words[1..])[..4].copy_from_slice(&9u32.to_ne_bytes());
        assert_eq!(words, [1, 9, 3]);
    }

    /// The check itself, which is the point of the crate: a struct with a
    /// hole sums to less than its size.
    #[test]
    fn padding_makes_the_sizes_disagree() {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Holed {
            a: u8,
            b: u32,
        }
        let sum = field_size(|s: &Holed| &s.a) + field_size(|s: &Holed| &s.b);
        assert_eq!(sum, 5);
        assert_eq!(size_of::<Holed>(), 8);
    }
}
