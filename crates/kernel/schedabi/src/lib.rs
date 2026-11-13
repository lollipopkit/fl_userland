//! `sched_getaffinity`'s and `sched_setaffinity`'s argument: a `cpu_set_t`.
//!
//! The mask is a **wire format with a length rule**, which is the combination
//! this tree keeps finding defects in. Both of the ones here were length rules:
//! `sched_getaffinity` answered `3` for a machine with 20 processors, where
//! Linux answers `8`, and it accepted a `cpusetsize` of 3, 7 or 9 and wrote
//! whatever it felt like into them.
//!
//! What is *not* here is the scheduling. The host does that and is not told;
//! an affinity is stored and reported so that a program which pins itself and
//! reads the mask back is not contradicted, which is the part it can observe.
//! `crates/kernel/rlimit` has the priority rules, which are about *who may*
//! rather than about a layout.

use std::ffi::c_int;

/// Guest errnos, negated as everywhere else in the tree.
pub use guest_errno::c_int_::EINVAL;

/// How many processors a mask can name here.
///
/// A `u64`, so 64. Linux's is `NR_CPUS` and can be thousands; a guest asking
/// about a processor above this is asking about one the emulator does not
/// report, and the answer is the same as for one that does not exist.
pub const MASK_BITS: u32 = 64;

/// The width of the array element a `cpu_set_t` is made of: `unsigned long`,
/// which is eight bytes on every target this builds for.
///
/// It is not `size_of::<usize>()` by accident — the guest's `unsigned long` is
/// what decides this, not the host's, and they agree here only because both are
/// 64-bit. Written as a constant so that a 32-bit guest would fail the
/// assertion below rather than silently answer in the host's units.
pub const LONG_BYTES: u32 = 8;

const _: () = assert!(MASK_BITS.is_multiple_of(8 * LONG_BYTES));

/// Linux's `cpumask_size()`: the bytes `sched_getaffinity` writes and returns.
///
/// **A whole number of `unsigned long`s**, because that is what the mask is an
/// array of. The C computed `(cpus + 7) / 8` and returned it, so a machine with
/// 20 processors answered `3` — and a caller cannot tell that from a kernel
/// that wrote a partial word.
pub fn mask_bytes(cpus: u32) -> u32 {
    let bytes = cpus.div_ceil(8);
    bytes.div_ceil(LONG_BYTES) * LONG_BYTES
}

/// Whether `sched_getaffinity` accepts this `cpusetsize`.
///
/// Two rules, both `EINVAL` and both from Linux's `sys_sched_getaffinity`:
///
/// - it must be big enough to hold every processor there is, and
/// - it must be **a whole number of `unsigned long`s**.
///
/// The second was missing. A partial word is a request the mask has no way to
/// answer, and 3, 7 and 9 were all accepted.
pub fn getaffinity_len_ok(cpusetsize: u64, cpus: u32) -> bool {
    cpusetsize.saturating_mul(8) >= cpus as u64 && cpusetsize.is_multiple_of(LONG_BYTES as u64)
}

/// A mask as the bytes a guest reads, little-endian by bit index: processor `n`
/// is bit `n % 8` of byte `n / 8`.
///
/// Writes `out.len()` bytes, so the caller decides how much of its buffer the
/// guest asked for. Bits above `cpus` are zero — a processor that does not
/// exist is not in anyone's mask.
pub fn encode(mask: u64, cpus: u32, out: &mut [u8]) {
    out.fill(0);
    for cpu in 0..cpus.min(MASK_BITS) {
        if mask & (1u64 << cpu) != 0 {
            let byte = (cpu / 8) as usize;
            if byte < out.len() {
                out[byte] |= 1 << (cpu % 8);
            }
        }
    }
}

/// The reverse. Bytes beyond the first eight are ignored, which is what Linux
/// does with bits above the processors it has — and a caller's `cpu_set_t` is
/// usually 128 bytes of which all but the first few are zero.
pub fn decode(bytes: &[u8]) -> u64 {
    let mut mask = 0u64;
    for cpu in 0..MASK_BITS {
        let byte = (cpu / 8) as usize;
        if byte < bytes.len() && bytes[byte] & (1 << (cpu % 8)) != 0 {
            mask |= 1u64 << cpu;
        }
    }
    mask
}

/// What `sched_setaffinity` stores, or `EINVAL`.
///
/// A mask naming no processor this kernel has is refused rather than stored: a
/// thread that may run nowhere is not a thing to be, and Linux says the same.
/// `online` is the mask of processors that exist.
pub fn setaffinity_mask(requested: u64, online: u64) -> Result<u64, c_int> {
    let mask = requested & online;
    if mask == 0 { Err(EINVAL) } else { Ok(mask) }
}

#[cfg(test)]
/// Every processor there is, as a mask. `cpus` above [`MASK_BITS`] is clamped,
/// because a mask cannot name more.
pub(crate) fn online_mask(cpus: u32) -> u64 {
    match cpus.min(MASK_BITS) {
        0 => 1, // there is always at least one
        MASK_BITS => u64::MAX,
        n => (1u64 << n) - 1,
    }
}

#[cfg(test)]
/// The mask to store, or 0 for `EINVAL` — a mask naming no processor that
/// exists.
pub(crate) fn schedabi_setaffinity_mask(requested: u64, online: u64) -> u64 {
    setaffinity_mask(requested, online).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------ the length

    /// The defect: 20 processors need 3 bytes and Linux answers 8, because the
    /// mask is an array of `unsigned long`.
    #[test]
    fn the_size_is_a_whole_number_of_longs() {
        assert_eq!(mask_bytes(1), 8);
        assert_eq!(mask_bytes(8), 8);
        assert_eq!(mask_bytes(20), 8, "not 3");
        assert_eq!(mask_bytes(64), 8);
        assert_eq!(mask_bytes(65), 16);
        assert_eq!(mask_bytes(128), 16);
    }

    #[test]
    fn a_length_must_hold_every_processor() {
        assert!(!getaffinity_len_ok(0, 8));
        assert!(getaffinity_len_ok(8, 8));
        assert!(getaffinity_len_ok(8, 64));
        assert!(!getaffinity_len_ok(8, 65), "65 processors need two words");
        assert!(getaffinity_len_ok(16, 65));
    }

    /// The rule that was missing: 3, 7 and 9 were all accepted, and a partial
    /// `unsigned long` is a request the mask has no way to answer.
    #[test]
    fn a_length_must_be_a_whole_number_of_longs() {
        for bad in [1u64, 2, 3, 4, 5, 6, 7, 9, 15, 17] {
            assert!(!getaffinity_len_ok(bad, 1), "size {bad}");
        }
        for ok in [8u64, 16, 24, 128] {
            assert!(getaffinity_len_ok(ok, 1), "size {ok}");
        }
    }

    #[test]
    fn an_absurd_length_does_not_overflow() {
        assert!(getaffinity_len_ok(!7, 64));
    }

    // ------------------------------------------------------- the wire format

    #[test]
    fn processor_n_is_bit_n() {
        let mut out = [0u8; 8];
        encode(0b1, 64, &mut out);
        assert_eq!(out[0], 0b1, "cpu 0 is bit 0 of byte 0");

        encode(1 << 7, 64, &mut out);
        assert_eq!(out[0], 0x80, "cpu 7 is the top bit of byte 0");

        encode(1 << 8, 64, &mut out);
        assert_eq!(out[0], 0, "cpu 8 is not in byte 0");
        assert_eq!(out[1], 1, "it is bit 0 of byte 1");

        encode(1 << 63, 64, &mut out);
        assert_eq!(out[7], 0x80);
    }

    #[test]
    fn a_processor_that_does_not_exist_is_not_in_the_mask() {
        let mut out = [0u8; 8];
        // Four processors, and a mask claiming eight.
        encode(0xff, 4, &mut out);
        assert_eq!(out[0], 0x0f, "only the four that exist");
    }

    #[test]
    fn a_short_buffer_is_filled_as_far_as_it_goes() {
        let mut out = [0u8; 1];
        encode(!0, 64, &mut out);
        assert_eq!(out[0], 0xff, "and does not write past it");
    }

    #[test]
    fn encode_and_decode_round_trip() {
        for mask in [1u64, 0xff, 0x8000_0000_0000_0000, 0x0f0f_0f0f_0f0f_0f0f, !0] {
            let mut out = [0u8; 8];
            encode(mask, 64, &mut out);
            assert_eq!(decode(&out), mask, "mask {mask:#x}");
        }
    }

    /// A caller's `cpu_set_t` is usually 128 bytes, of which all but the first
    /// few are zero.
    #[test]
    fn bytes_beyond_the_mask_are_ignored() {
        let mut big = [0u8; 128];
        big[0] = 0b101;
        big[100] = 0xff; // a processor 800, which does not exist
        assert_eq!(decode(&big), 0b101);
    }

    #[test]
    fn decoding_a_short_buffer_reads_what_is_there() {
        assert_eq!(decode(&[0xff]), 0xff);
        assert_eq!(decode(&[]), 0);
    }

    // ------------------------------------------------------------- setting

    #[test]
    fn a_mask_is_narrowed_to_what_exists() {
        assert_eq!(setaffinity_mask(!0, 0b1111), Ok(0b1111));
        assert_eq!(setaffinity_mask(0b0110, 0b1111), Ok(0b0110));
    }

    /// A thread that may run nowhere is not a thing to be.
    #[test]
    fn a_mask_naming_nothing_that_exists_is_einval() {
        assert_eq!(setaffinity_mask(0, 0b1111), Err(EINVAL));
        assert_eq!(setaffinity_mask(0b1_0000, 0b1111), Err(EINVAL));
        assert_eq!(schedabi_setaffinity_mask(0, 0b1111), 0);
    }

    // --------------------------------------------------------- online mask

    #[test]
    fn the_online_mask_has_one_bit_per_processor() {
        assert_eq!(online_mask(1), 0b1);
        assert_eq!(online_mask(4), 0b1111);
        assert_eq!(online_mask(64), u64::MAX);
    }

    #[test]
    fn more_processors_than_bits_is_all_of_them() {
        assert_eq!(online_mask(65), u64::MAX);
        assert_eq!(online_mask(u32::MAX), u64::MAX);
    }

    /// Not reachable — the caller clamps to at least one — but a mask of zero
    /// processors would make every `setaffinity` `EINVAL` and every
    /// `getaffinity` empty.
    #[test]
    fn zero_processors_is_still_one() {
        assert_eq!(online_mask(0), 1);
    }
}
