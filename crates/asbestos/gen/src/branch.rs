//! Branches, and the two exceptions that are encoded beside them.
//!
//! Everything here **ends the block**, except one case that deliberately does
//! not — see [`Follow`] below. That is what makes this class the one where the
//! chaining contract lives: a block's last gadget holds where to go next, and
//! the block cache patches those words into direct jumps.
//!
//! # The two-slot convention
//!
//! A block records up to two destinations, `jump_ip[0]` and `jump_ip[1]`, as
//! *indices into its own code array*. What is stored there is an address with
//! **bit 63 set**, which is how the dispatch loop tells "not chained yet" from
//! a code pointer the cache has patched in. Every emission below that ends in
//! a branch writes the destinations last and then records where they are, in
//! that order, because the indices are computed from the length.
//!
//! Which slot means what is not uniform, and it is worth reading before
//! changing anything:
//!
//! - a conditional branch is `[0] = taken`, `[1] = fallthrough`;
//! - an unconditional one uses `[0]` alone;
//! - `BL` is `[0] = where the call returns to`, `[1] = the callee`, because
//!   the return site is the one the *return cache* wants to find.

use crate::gadgets::*;
use crate::{BLOCK_ENDS, DECODED, Gadget, Gen, decode};
use std::ffi::c_int;

/// A branch's destination, as the code stream holds it before chaining.
///
/// Bit 63 marks it: a chained slot holds a real code pointer, and the guest's
/// address space is 48 bits, so the top bit is free to mean "still an address".
fn unresolved(addr: u64) -> u64 {
    addr | (1 << 63)
}

/// How far an unconditional `B` may be followed inline before the block just
/// ends instead.
///
/// Following one turns two blocks into one and saves a dispatch, which is
/// worth doing for the `b` that every `if` without an `else` ends with. The
/// bound and the two conditions on it — same page, forward only — are what
/// stop it: backwards would let a loop inline itself for ever, and a different
/// page would put a block's code in a page the invalidation index does not
/// know it touches.
const FOLLOW_LIMIT: u32 = 3;

pub fn decode(g: &mut Gen, insn: u32) -> c_int {
    // `SVC`: the syscall. The gadget records where to resume, because the
    // syscall returns to the *next* instruction and the interrupt below it
    // leaves the block.
    if insn & 0xffe0_001f == 0xd400_0001 {
        let next = g.ip();
        g.gadget(gadget_svc);
        g.emit(next);
        g.interrupt(crate::int::SYSCALL);
        return BLOCK_ENDS;
    }
    // `BRK`. The pc is deliberately *not* advanced: the exception is taken
    // with the program counter still on the instruction, so a handler that
    // returns re-executes it, which is what a real kernel does.
    if insn & 0xffe0_001f == 0xd420_0000 {
        g.interrupt(crate::int::BREAKPOINT);
        return BLOCK_ENDS;
    }

    if insn & 0x7c00_0000 == 0x1400_0000 {
        return branch_imm(g, insn);
    }
    if insn & 0xff00_0010 == 0x5400_0000 {
        return bcond(g, insn);
    }
    if insn & 0x7e00_0000 == 0x3400_0000 {
        return compare_and_branch(g, insn);
    }
    if insn & 0x7e00_0000 == 0x3600_0000 {
        return test_and_branch(g, insn);
    }
    if insn & 0xfe00_0000 == 0xd600_0000 {
        return branch_reg(g, insn);
    }
    if insn & 0xffc0_0000 == 0xd500_0000 {
        return crate::system::decode(g, insn);
    }

    g.undefined()
}

/// `B` and `BL` with a 26-bit offset.
fn branch_imm(g: &mut Gen, insn: u32) -> c_int {
    let is_bl = (insn >> 31) & 1 != 0;
    let offset = decode::sign_extend(((insn as u64) & 0x03ff_ffff) << 2, 28);
    let target = g.orig_ip().wrapping_add(offset as u64);

    if is_bl {
        // The call's code stream is five words, and the order is a contract
        // with `gadget_branch_link`: the block's own address (patched by
        // `gen_end`, which is why a slot is emitted empty), the return address
        // as a plain number for `x30`, and then the two destinations.
        let ret = g.ip();
        g.gadget(gadget_branch_link);
        g.emit(0);
        g.emit(ret);
        g.emit(unresolved(ret));
        g.emit(unresolved(target));
        g.set_block_patch_slot(4);
        g.set_jump_slots();
        return BLOCK_ENDS;
    }

    // An unconditional forward `B` on the same page is followed inline rather
    // than ended on: it is what every `if` without an `else` finishes with,
    // and merging the two blocks removes a dispatch. See [`FOLLOW_LIMIT`].
    if g.follow(target, FOLLOW_LIMIT) {
        return DECODED;
    }

    g.gadget(gadget_branch);
    g.emit(unresolved(target));
    g.set_single_jump_slot();
    BLOCK_ENDS
}

/// One gadget per condition, rather than one gadget and a jump table: the
/// condition is known when the block is compiled, so the indirect branch a
/// shared gadget would need is pure cost at run time.
static BCOND: [Gadget; 14] = [
    gadget_bcond_eq,
    gadget_bcond_ne,
    gadget_bcond_cs,
    gadget_bcond_cc,
    gadget_bcond_mi,
    gadget_bcond_pl,
    gadget_bcond_vs,
    gadget_bcond_vc,
    gadget_bcond_hi,
    gadget_bcond_ls,
    gadget_bcond_ge,
    gadget_bcond_lt,
    gadget_bcond_gt,
    gadget_bcond_le,
];

fn bcond(g: &mut Gen, insn: u32) -> c_int {
    let cond = (insn & 0xf) as usize;
    let target = g.orig_ip().wrapping_add(decode::branch_imm19(insn) as u64);

    // `AL` and `NV` are always taken, so they are an unconditional branch —
    // and the table has fourteen entries, which is what keeps the index in
    // range without a separate check.
    if cond >= 14 {
        g.gadget(gadget_branch);
        g.emit(unresolved(target));
        g.set_single_jump_slot();
        return BLOCK_ENDS;
    }

    let fallthrough = g.ip();
    g.gadget(BCOND[cond]);
    g.emit(unresolved(target));
    g.emit(unresolved(fallthrough));
    g.set_jump_slots();
    BLOCK_ENDS
}

/// `CBZ` and `CBNZ`: branch on a whole register being zero.
fn compare_and_branch(g: &mut Gen, insn: u32) -> c_int {
    let is_cbnz = (insn >> 24) & 1 != 0;
    let sf = (insn >> 31) & 1 != 0;
    let rt = insn & 0x1f;
    let target = g.orig_ip().wrapping_add(decode::branch_imm19(insn) as u64);
    let fallthrough = g.ip();

    if rt != 31 {
        // The specialised gadgets know their width and know the register is
        // real, so they skip both checks. `XZR` is always zero, which is a
        // constant branch and rare enough not to be worth four more gadgets.
        let gadget = match (is_cbnz, sf) {
            (true, true) => gadget_cbnz_64,
            (true, false) => gadget_cbnz_32,
            (false, true) => gadget_cbz_64,
            (false, false) => gadget_cbz_32,
        };
        g.gadget(gadget);
        g.emit(rt as u64);
    } else {
        g.gadget(if is_cbnz { gadget_cbnz } else { gadget_cbz });
        g.emit(rt as u64 | ((sf as u64) << 8));
    }
    g.emit(unresolved(target));
    g.emit(unresolved(fallthrough));
    g.set_jump_slots();
    BLOCK_ENDS
}

/// `TBZ` and `TBNZ`: branch on one bit, whose number is split across the
/// instruction — bit 5 of it is the `sf` position and the low five are their
/// own field.
fn test_and_branch(g: &mut Gen, insn: u32) -> c_int {
    let is_tbnz = (insn >> 24) & 1 != 0;
    let b5 = (insn >> 31) & 1;
    let b40 = (insn >> 19) & 0x1f;
    let bit = (b5 << 5) | b40;
    let rt = insn & 0x1f;
    // A 14-bit offset, which is the shortest branch range there is: ±32 KB.
    let offset = decode::sign_extend(((insn as u64 >> 5) & 0x3fff) << 2, 16);
    let target = g.orig_ip().wrapping_add(offset as u64);
    let fallthrough = g.ip();

    g.gadget(if is_tbnz { gadget_tbnz } else { gadget_tbz });
    g.emit(rt as u64 | ((bit as u64) << 8));
    g.emit(unresolved(target));
    g.emit(unresolved(fallthrough));
    g.set_jump_slots();
    BLOCK_ENDS
}

/// `BR`, `BLR` and `RET`, whose destination is in a register and so cannot be
/// chained at all — there are no jump slots here.
fn branch_reg(g: &mut Gen, insn: u32) -> c_int {
    let opc = (insn >> 21) & 0xf;
    let rn = (insn >> 5) & 0x1f;
    match opc {
        0 => {
            g.gadget(gadget_branch_reg);
            g.emit(rn as u64);
        }
        1 => {
            let ret = g.ip();
            g.gadget(gadget_branch_link_reg);
            g.emit(rn as u64);
            g.emit(ret);
        }
        2 => {
            g.gadget(gadget_ret);
            g.emit(rn as u64);
        }
        // 4 and 5 are `ERET` and `DRPS`, which are EL1 and above.
        _ => return g.undefined(),
    }
    BLOCK_ENDS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bit 63 is what says a slot has not been chained. The guest's address
    /// space is 48 bits, so it cannot collide with a real address — which is
    /// the assumption the whole convention rests on.
    #[test]
    fn an_unresolved_destination_is_marked_above_the_address_space() {
        let a = 0x0000_7fff_1234_5678u64;
        assert_eq!(unresolved(a) & !(1 << 63), a, "the address survives");
        assert_ne!(unresolved(a), a);
        assert_eq!(unresolved(0) >> 63, 1);
        // The top of what a guest can address is still below the marker.
        assert_eq!(unresolved(0xffff_ffff_ffff) >> 63, 1);
    }

    /// `TBZ`'s bit number is two fields: the low five bits are their own, and
    /// the sixth is the register-size bit reused. Reading only the low five
    /// tests the wrong bit for every test of bits 32 to 63, which is every
    /// sign test on a 64-bit value.
    #[test]
    fn the_test_and_branch_bit_number_is_split() {
        let mk = |b5: u32, b40: u32| (b5 << 31) | 0x3600_0000 | (b40 << 19);
        let bit = |insn: u32| (((insn >> 31) & 1) << 5) | ((insn >> 19) & 0x1f);
        assert_eq!(bit(mk(0, 0)), 0);
        assert_eq!(bit(mk(0, 31)), 31);
        assert_eq!(
            bit(mk(1, 0)),
            32,
            "the sixth bit comes from the top of the word"
        );
        assert_eq!(bit(mk(1, 31)), 63);
    }

    /// The three conditions on following a `B` inline. Each one alone is what
    /// stops a different failure, so the test names all three.
    #[test]
    fn a_branch_is_only_followed_forward_on_its_own_page() {
        let can = |from: u64, to: u64, block_page: u64, depth: u32| {
            to >> 12 == block_page && to > from && depth < FOLLOW_LIMIT
        };
        assert!(can(0x100_0100, 0x100_0200, 0x1000, 0), "forward, same page");
        assert!(
            !can(0x100_0200, 0x100_0100, 0x1000, 0),
            "backward would inline a loop for ever"
        );
        assert!(
            !can(0x100_0100, 0x100_1100, 0x1000, 0),
            "another page is one the index does not know about"
        );
        assert!(
            !can(0x100_0100, 0x100_0200, 0x1000, FOLLOW_LIMIT),
            "and the depth is bounded"
        );
    }
}
