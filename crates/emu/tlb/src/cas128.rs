//! A sixteen-byte compare-exchange, which stable Rust has no type for.
//!
//! # Why this is not a call into C any more
//!
//! `emu/tlb.c` held four lines around `__atomic_compare_exchange_n` on a
//! `__uint128_t`, and the reason written beside it was that **the compiler
//! chooses**: `CASP` is FEAT_LSE and an illegal instruction on an aarch64 host
//! without it, so a hand-written `asm!` block would have to pick one form and
//! would pick wrong on some target.
//!
//! That reason was true and is answered rather than ignored. The choice clang
//! makes is `target_feature`, and `cfg(target_feature = "lse")` is the same
//! judgement from the same table. Measured on 2026-09-06, per target, against
//! `clang -O2` on the body this replaces:
//!
//! | target | clang | `cfg(target_feature = "lse")` |
//! | --- | --- | --- |
//! | `aarch64-apple-darwin` | `caspal` | set |
//! | `aarch64-apple-ios` | `ldaxp`/`stlxp` | not set |
//! | `aarch64-apple-ios-sim` | `caspal` | set |
//!
//! Three targets, three agreements. So the decision is not being taken away
//! from the compiler — it is being read off the same input.
//!
//! # The arm that ships is the one this machine does not compile
//!
//! A development host is `aarch64-apple-darwin`, so `cargo test -p emu-tlb`
//! builds the `caspal` arm and **never** the `ldaxp`/`stlxp` one — which is the
//! arm an `iphoneos` build uses, and therefore the one that ships. Breaking it
//! leaves all thirteen tests green.
//!
//! `tools/checks.sh cas128_no_lse` runs the same thirteen with
//! `-C target-feature=-lse`, so the loop below is executed rather than only
//! read. Checked by breaking it: the ordinary run stayed green and the gate
//! failed. See `tools/cas128-no-lse.sh`.
//!
//! # The non-LSE loop is clang's, instruction for instruction
//!
//! The failure arm is the part that would have been written wrong. The obvious
//! shape is `clrex`, and clang does not do that: on a mismatch it `stlxp`s back
//! **the value it just read**, so the failure path is a complete
//! exclusive sequence with a store-release in it rather than an abandoned one.
//! That is what `__ATOMIC_SEQ_CST` as the *failure* ordering costs, and it is
//! not something review would have produced.
//!
//! The sequence below is a transcription of `clang -O2 -target
//! arm64-apple-ios15.0`, kept in that order for that reason.
//!
//! # What it is for
//!
//! A torn update breaks any lock-free algorithm that relies on the pair moving
//! together, and libpas's `pas_versioned_field` is `{value, version}` and is
//! exactly that. Sixteen bytes must move as one operation and not as two of
//! eight.

/// Compare-exchange the sixteen bytes at `ptr`.
///
/// Returns `(old_lo, old_hi, swapped)`. The old pair comes back whether or not
/// it swapped, because that is what `CASP` writes into `Rs` and what the guest
/// instruction being emulated hands back.
///
/// # Safety
/// `ptr` must be writable, 16-byte aligned, and not straddle a page — the
/// caller checks the last two with `pair16_ok`. An unaligned sixteen-byte
/// compare-exchange is not lock-free on this hardware; it raises an alignment
/// fault, which is why refusing is the caller's job and not this function's.
#[inline]
pub unsafe fn cas128(
    ptr: *mut u8,
    exp_lo: u64,
    exp_hi: u64,
    des_lo: u64,
    des_hi: u64,
) -> (u64, u64, bool) {
    #[cfg(target_feature = "lse")]
    {
        let (mut old_lo, mut old_hi) = (exp_lo, exp_hi);
        // CASPAL Xs, Xs+1, Xt, Xt+1, [Xn]: Xs/Xs+1 and Xt/Xt+1 must each be a
        // consecutive pair starting at an even register, which is why these are
        // pinned to x0-x3 rather than left to the allocator.
        unsafe {
            core::arch::asm!(
                "caspal x0, x1, x2, x3, [{ptr}]",
                ptr = in(reg) ptr,
                inout("x0") old_lo,
                inout("x1") old_hi,
                in("x2") des_lo,
                in("x3") des_hi,
            );
        }
        (old_lo, old_hi, old_lo == exp_lo && old_hi == exp_hi)
    }

    #[cfg(not(target_feature = "lse"))]
    {
        let (mut old_lo, mut old_hi): (u64, u64);
        // Transcribed from clang -O2 for arm64-apple-ios15.0. The mismatch arm
        // stores back what it read rather than issuing `clrex`; see the module
        // comment.
        unsafe {
            core::arch::asm!(
                "2:",
                "ldaxp {old_lo}, {old_hi}, [{ptr}]",
                "cmp {old_lo}, {exp_lo}",
                "cset {t:w}, ne",
                "cmp {old_hi}, {exp_hi}",
                "cinc {t:w}, {t:w}, ne",
                "cbz {t:w}, 3f",
                "stlxp {t:w}, {old_lo}, {old_hi}, [{ptr}]",
                "cbnz {t:w}, 2b",
                "b 4f",
                "3:",
                "stlxp {t:w}, {des_lo}, {des_hi}, [{ptr}]",
                "cbnz {t:w}, 2b",
                "4:",
                ptr = in(reg) ptr,
                exp_lo = in(reg) exp_lo,
                exp_hi = in(reg) exp_hi,
                des_lo = in(reg) des_lo,
                des_hi = in(reg) des_hi,
                old_lo = out(reg) old_lo,
                old_hi = out(reg) old_hi,
                t = out(reg) _,
                options(nostack),
            );
        }
        (old_lo, old_hi, old_lo == exp_lo && old_hi == exp_hi)
    }
}

#[cfg(test)]
mod tests {
    use super::cas128;

    /// 16-byte aligned storage, which is the precondition `cas128` is given.
    #[repr(align(16))]
    struct Pair([u64; 2]);

    #[test]
    fn a_matching_pair_swaps_and_reports_the_old_value() {
        let mut p = Pair([0xaaaa_aaaa_aaaa_aaaa, 0xbbbb_bbbb_bbbb_bbbb]);
        let ptr = p.0.as_mut_ptr().cast::<u8>();
        let (lo, hi, swapped) =
            unsafe { cas128(ptr, 0xaaaa_aaaa_aaaa_aaaa, 0xbbbb_bbbb_bbbb_bbbb, 1, 2) };
        assert!(swapped);
        assert_eq!((lo, hi), (0xaaaa_aaaa_aaaa_aaaa, 0xbbbb_bbbb_bbbb_bbbb));
        assert_eq!(p.0, [1, 2]);
    }

    /// The half that a two-of-eight implementation gets wrong: only the low
    /// word matches, so nothing may move.
    #[test]
    fn a_mismatch_in_the_high_half_alone_leaves_both_words() {
        let mut p = Pair([7, 8]);
        let ptr = p.0.as_mut_ptr().cast::<u8>();
        let (lo, hi, swapped) = unsafe { cas128(ptr, 7, 999, 100, 200) };
        assert!(!swapped);
        assert_eq!((lo, hi), (7, 8));
        assert_eq!(p.0, [7, 8], "a failed compare-exchange must not store");
    }

    #[test]
    fn a_mismatch_in_the_low_half_alone_leaves_both_words() {
        let mut p = Pair([7, 8]);
        let ptr = p.0.as_mut_ptr().cast::<u8>();
        let (lo, hi, swapped) = unsafe { cas128(ptr, 999, 8, 100, 200) };
        assert!(!swapped);
        assert_eq!((lo, hi), (7, 8));
        assert_eq!(p.0, [7, 8], "a failed compare-exchange must not store");
    }

    /// The property the whole thing exists for, in the shape libpas relies on:
    /// `{value, version}` where `value == version * 2` is the invariant. Two of
    /// eight bytes would let a reader see one word from before an update and
    /// one from after it, and the invariant would not hold.
    ///
    /// Failing this needs a real race, so it runs long enough to get one: on
    /// this machine a torn build (two `AtomicU64` compare-exchanges) fails it
    /// within a few thousand iterations.
    #[test]
    fn the_pair_never_tears_under_contention() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        #[repr(align(16))]
        struct Shared([u64; 2]);

        // The cell is written only through cas128 and read only through the
        // same instruction's load half, which is what makes the raw pointer
        // sound to share.
        struct Cell(std::cell::UnsafeCell<Shared>);
        unsafe impl Sync for Cell {}

        let cell = Arc::new(Cell(std::cell::UnsafeCell::new(Shared([0, 0]))));
        let stop = Arc::new(AtomicBool::new(false));
        let torn = Arc::new(AtomicBool::new(false));

        let writers: Vec<_> = (0..4)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let ptr = cell.0.get().cast::<u8>();
                    while !stop.load(Ordering::Relaxed) {
                        // Read the current pair with a compare-exchange that
                        // cannot succeed, then try to advance it by one.
                        let (lo, hi, _) = unsafe { cas128(ptr, u64::MAX, u64::MAX, 0, 0) };
                        let next = hi.wrapping_add(1);
                        unsafe { cas128(ptr, lo, hi, next.wrapping_mul(2), next) };
                    }
                })
            })
            .collect();

        let reader = {
            let cell = Arc::clone(&cell);
            let stop = Arc::clone(&stop);
            let torn = Arc::clone(&torn);
            std::thread::spawn(move || {
                let ptr = cell.0.get().cast::<u8>();
                while !stop.load(Ordering::Relaxed) {
                    let (lo, hi, _) = unsafe { cas128(ptr, u64::MAX, u64::MAX, 0, 0) };
                    if lo != hi.wrapping_mul(2) {
                        torn.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            })
        };

        std::thread::sleep(std::time::Duration::from_millis(300));
        stop.store(true, Ordering::Relaxed);
        for w in writers {
            w.join().unwrap();
        }
        reader.join().unwrap();

        assert!(!torn.load(Ordering::Relaxed), "the pair was observed torn");
        let final_pair = unsafe { &*cell.0.get() };
        assert_eq!(final_pair.0[0], final_pair.0[1].wrapping_mul(2));
        assert!(
            final_pair.0[1] > 0,
            "no writer made progress; the test proved nothing"
        );
    }
}
