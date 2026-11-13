//! `_PyToken_TwoChars` from libpython 3.12: which token a pair of characters
//! makes, or `OP` (55) if the pair is not one.
//!
//! The one real libpython leaf that was translated and kept. **Bit-identical
//! and 1.67x on its hot path**, which is the number this PoC records; the
//! full-libpython experiment beside it concluded the opposite for the library
//! as a whole.
//!
//! # Why it writes `x1`
//!
//! The generated C sets `regs[1]` to the candidate token before selecting
//! between it and 55, and a spec_fn has to leave the CPU exactly as the guest's
//! own instructions would — a `csel` reads both operands out of registers, so
//! the register holding the loser is written whether or not it wins. Cleaning
//! that up would make this *not* bit-identical, which is the only property it
//! has.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Cpu, Tlb};

/// The library's load base. It is a PIE, so nothing is registered without
/// `IUL_TWOCHARS_BASE`; kept because the registration needs it and the body
/// does not.
static BASE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn set_base(base: u64) {
    BASE.store(base, Ordering::Relaxed);
}

/// `OP`, which is what any pair that is not a token answers.
const OP: u64 = 55;

/// # Safety
/// `cpu` is the running guest's; the TLB is not touched.
pub unsafe extern "C" fn two_chars(cpu: *mut Cpu, _tlb: *mut Tlb) {
    // SAFETY: the caller's contract.
    let regs = unsafe { &mut (*cpu).regs };

    // `c1 - '!'`, as a 32-bit value: anything below '!' wraps above the table
    // and takes the same exit as anything above '['.
    let first = (regs[0] as u32).wrapping_sub(33);
    regs[0] = u64::from(first);
    let second = regs[1] as u32;

    if first > 91 {
        regs[0] = OP;
        return;
    }

    // Answer `t` when the second character is `c`, and `OP` otherwise —
    // writing `regs[1]` as the guest's `csel` does. `None` for an arm that
    // returns before reaching one, which leaves `regs[1]` alone.
    let mut sel = |c: u32, t: u64| {
        regs[0] = OP;
        regs[1] = t;
        regs[0] = if second != c { OP } else { t };
    };

    match first {
        // '!' '='  ->  NOTEQUAL
        0 => sel(61, 28),
        // '%' '='  ->  PERCENTEQUAL
        4 => sel(61, 40),
        // '&' '='  ->  AMPEREQUAL
        5 => sel(61, 41),
        // '*' '*'  ->  DOUBLESTAR, '*' '='  ->  STAREQUAL
        9 => {
            if second == 42 {
                regs[0] = 35;
            } else {
                sel(61, 38);
            }
        }
        // '+' '='  ->  PLUSEQUAL
        10 => sel(61, 36),
        // '-' '='  ->  MINEQUAL, '-' '>'  ->  RARROW
        12 => {
            if second == 61 {
                regs[0] = 37;
            } else {
                sel(62, 51);
            }
        }
        // '/' '/'  ->  DOUBLESLASH, '/' '='  ->  SLASHEQUAL
        14 => {
            if second == 47 {
                regs[0] = regs[1];
            } else {
                sel(61, 39);
            }
        }
        // ':' '='  ->  COLONEQUAL
        25 => sel(61, 53),
        // '<' '='  ->  LESSEQUAL, '<' '>'  ->  NOTEQUAL, '<' '<'  ->  LEFTSHIFT
        27 => {
            if second == 61 {
                regs[0] = 29;
            } else if second == 62 {
                regs[0] = 28;
            } else {
                sel(60, 33);
            }
        }
        // '=' '='  ->  EQEQUAL
        28 => sel(61, 27),
        // '>' '='  ->  GREATEREQUAL, '>' '>'  ->  RIGHTSHIFT
        29 => {
            if second == 61 {
                regs[0] = 30;
            } else {
                sel(62, 34);
            }
        }
        // '@' '='  ->  ATEQUAL
        31 => sel(61, 50),
        // '^' '='  ->  CIRCUMFLEXEQUAL
        61 => sel(61, 43),
        // '|' '='  ->  VBAREQUAL
        91 => sel(61, 42),
        _ => regs[0] = OP,
    }
}
