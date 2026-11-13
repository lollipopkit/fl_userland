//! That the constructor runs and the registry takes what it offers.
//!
//! An integration test rather than a `#[cfg(test)] mod`, because a `--lib` test
//! compiles the crate twice -- once under `cfg(test)` and once as a dependency
//! -- and this crate is full of `link_section` statics, so the two copies would
//! both register.

// The gadget symbols and `iul_printk`. An `--extern` nothing names is not
// loaded, so this has to be a `use`.
use iul as _;

/// Three, not five: `bbjit` and `twochars` are in PIE binaries and register
/// only when the environment supplies a load base.
#[test]
fn the_unconditional_fixtures_register() {
    assert_eq!(offloadtestprebuilt::registered(), 3);
}

/// And the registry can find one of them, which is what says `add` reached it
/// rather than only that the constructor ran.
#[test]
fn the_registry_has_mix() {
    let addr = std::env::var("IUL_MIXBENCH_MIX").ok();
    assert!(addr.is_none(), "unset in a cargo run; the script sets it");
    assert!(offloadprebuilt::native_offload_prebuilt_lookup(0x223dc4).is_some());
}

/// `two_chars` against CPython's own table, written from the *characters*
/// rather than from the translated body's `c - '!'` indices.
///
/// It is not a restatement of its subject: the subject is a machine
/// translation of one binary's instructions, and this is what the function is
/// supposed to mean. A case number off by one would pass any check written
/// from the translation and fails this one.
#[test]
fn two_chars_answers_cpythons_table() {
    // (first, second, token), from Parser/token.c's `_PyToken_TwoChars`.
    const TABLE: &[(u8, u8, u64)] = &[
        (b'!', b'=', 28), // NOTEQUAL
        (b'%', b'=', 40), // PERCENTEQUAL
        (b'&', b'=', 41), // AMPEREQUAL
        (b'*', b'*', 35), // DOUBLESTAR
        (b'*', b'=', 38), // STAREQUAL
        (b'+', b'=', 36), // PLUSEQUAL
        (b'-', b'=', 37), // MINEQUAL
        (b'-', b'>', 51), // RARROW
        (b'/', b'/', 47), // DOUBLESLASH
        (b'/', b'=', 39), // SLASHEQUAL
        (b':', b'=', 53), // COLONEQUAL
        (b'<', b'<', 33), // LEFTSHIFT
        (b'<', b'=', 29), // LESSEQUAL
        (b'<', b'>', 28), // NOTEQUAL
        (b'=', b'=', 27), // EQEQUAL
        (b'>', b'=', 30), // GREATEREQUAL
        (b'>', b'>', 34), // RIGHTSHIFT
        (b'@', b'=', 50), // ATEQUAL
        (b'^', b'=', 43), // CIRCUMFLEXEQUAL
        (b'|', b'=', 42), // VBAREQUAL
    ];

    // Every pair of printable characters, so the answer for the ones *not* in
    // the table is checked too -- OP (55), which is the whole point of the
    // function and is what a mistranscribed case number would break.
    for a in 0u8..=127 {
        for b in 0u8..=127 {
            let want = TABLE
                .iter()
                .find(|&&(x, y, _)| x == a && y == b)
                .map_or(55, |&(_, _, t)| t);
            assert_eq!(run(a, b), want, "{:?} {:?}", a as char, b as char);
        }
    }
}

/// Call the fixture with `regs[0]`/`regs[1]` set and read `regs[0]` back.
fn run(a: u8, b: u8) -> u64 {
    let mut cpu = offloadtestprebuilt::Cpu::default();
    cpu.regs[0] = u64::from(a);
    cpu.regs[1] = u64::from(b);
    // SAFETY: a zeroed `cpu_state` on the stack; `two_chars` touches `regs`
    // only, and is passed a null TLB it does not read.
    unsafe { offloadtestprebuilt::two_chars(&raw mut cpu, std::ptr::null_mut()) };
    cpu.regs[0]
}
