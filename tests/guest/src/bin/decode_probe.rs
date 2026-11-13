//! Which encodings this kernel decodes, swept rather than listed.
//!
//! # Why this exists
//!
//! `simd_probe` and its siblings are hand-written: somebody thought of an
//! instruction and wrote a case for it. That found nine defects, and its blind
//! spot is exactly the one that matters — **an instruction nobody thought of**.
//! Seven of those nine were "no decoder at all", found only because a case
//! happened to name them.
//!
//! This is the other shape. It walks whole encoding groups, executes each
//! encoding, and reports whether the machine ran it. The host is the ground
//! truth: an encoding an arm64 Linux container runs and this kernel refuses is
//! a missing decoder, and one this kernel runs and the container refuses is a
//! decoder for something that does not exist.
//!
//! Forty-five groups: nine of Advanced SIMD, which is where 46 missing decoders
//! were found in a day; seven of the **scalar integer core**, which is the
//! opposite prior; seven of **loads and stores**, which is the largest decoder
//! in the tree after the SIMD tables and had no sweep at all; six of the
//! **immediate** space; and the **hint** and **barrier** corners of the system
//! space.
//!
//! # What makes a blind sweep safe
//!
//! For the first sixteen groups, that no encoding in them touches memory or
//! takes a branch and every register field is zero — so one that turns out to be
//! allocated cannot corrupt anything.
//!
//! For the load and store groups it is that **the sweep chooses the register
//! fields**: `Rn` is 0, and `x0` is where the first argument of the function
//! this probe calls arrives, so an unknown load reads a scratch page rather than
//! wherever a register happened to point. The other fields are 1 to 4, because
//! naming one register twice is CONSTRAINED UNPREDICTABLE for anything with a
//! pair or a writeback and this CPU takes it as UNDEFINED — which read as 111
//! missing decoders before it read as a mistake.
//!
//! The rest of the branch and system space is still not swept and cannot be by
//! this method: a branch to an arbitrary offset does not come back, and an
//! `SVC` makes whatever syscall is in `x8`.
//!
//! # What is checked
//!
//! Nothing is asserted. One line per encoding, tagged with the group it belongs
//! to — `vec3s`, `sc2r`, `dp2s` and so on — so that a `KNOWN` entry in
//! `tests/integration/probe_diff.sh` can name one group without matching the
//! identical field values in another. The finding is the difference against a
//! container.
//!
//! Each case runs in a **forked child**, because an undecoded instruction
//! raises `SIGILL` whose default action ends the process — without that the
//! first gap would hide every one after it.

use std::arch::asm;

/// A page shared with each child, where it says it got there.
static mut SLOT: *mut u8 = std::ptr::null_mut();

/// Run one 32-bit encoding, in a child, and answer what happened to it.
///
/// The word is written into a small buffer, the instruction cache is cleaned
/// for it, and it is called. That is what makes a *swept* encoding runnable at
/// all: an `asm!` block can only hold a constant.
/// The register-to-register groups, which need nothing in a register.
///
/// `x0`–`x4` are passed as **zero** rather than left to whatever the caller
/// happened to have there, so a case answers the same thing every run.
fn execute(word: u32) -> &'static str {
    run(word, false)
}

/// The load and store groups, with a scratch page in `x0` and zero in `x1`–`x4`.
///
/// Unlike the register-to-register groups, these do **not** use register zero
/// everywhere: `Rn` is 0 so the base is the scratch page, and `Rt`, `Rt2`, `Rm`
/// and `Rs` are 1, 2, 3 and 4. Naming one register twice is CONSTRAINED
/// UNPREDICTABLE for anything with writeback or a pair, and this CPU takes it as
/// UNDEFINED — so the first version of this sweep reported 103 differences that
/// were all `LDP w0, w0, [x0]` and its neighbours, which is the probe's mistake
/// and not a decoder's.
fn execute_addressing(word: u32) -> &'static str {
    run(word, true)
}

fn run(word: u32, with_memory: bool) -> &'static str {
    unsafe {
        *SLOT = 0;
        let pid = libc::fork();
        if pid == 0 {
            // Two instructions: the one under test, then `ret`.
            let mut code: [u32; 2] = [word, 0xd65f_03c0];
            let p = code.as_mut_ptr();
            // Make it executable. `mprotect` on the stack is refused, so the
            // code goes in a fresh anonymous mapping.
            let page = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if page == libc::MAP_FAILED {
                libc::_exit(3);
            }
            std::ptr::copy_nonoverlapping(p.cast::<u8>(), page.cast::<u8>(), 8);
            if libc::mprotect(page, 4096, libc::PROT_READ | libc::PROT_EXEC) != 0 {
                libc::_exit(3);
            }
            // The data cache has the words and the instruction cache does not.
            asm!(
                "dc cvau, {p}",
                "dsb ish",
                "ic ivau, {p}",
                "dsb ish",
                "isb",
                p = in(reg) page,
                options(nostack)
            );
            // A page for the addressing groups to reach. Private to this child,
            // so a store cannot carry anything to the next case, and mapped
            // read *and* write because the sweep contains both directions.
            let scratch = if with_memory {
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if p == libc::MAP_FAILED {
                    libc::_exit(3);
                }
                // Halfway in, so a negative offset and a writeback that goes
                // backwards both stay inside it.
                p.cast::<u8>().add(2048)
            } else {
                std::ptr::null_mut()
            };
            *SLOT = 1;
            // x0 is the base and x1..x4 are zero, so an offset register adds
            // nothing and a store writes a known value.
            let f: extern "C" fn(*mut u8, u64, u64, u64, u64) = std::mem::transmute(page);
            f(scratch, 0, 0, 0, 0);
            *SLOT = 2;
            libc::_exit(0);
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        if libc::WIFEXITED(status) {
            match libc::WEXITSTATUS(status) {
                0 => "ran",
                3 => "the probe could not map",
                _ => "exited oddly",
            }
        } else if libc::WIFSIGNALED(status) {
            match libc::WTERMSIG(status) {
                libc::SIGILL => "SIGILL",
                libc::SIGSEGV => "SIGSEGV",
                libc::SIGBUS => "SIGBUS",
                libc::SIGFPE => "SIGFPE",
                libc::SIGTRAP => "SIGTRAP",
                s => return leak(format!("signal {s}")),
            }
        } else {
            "neither"
        }
    }
}

/// A description that outlives the call, for the signals with no name above.
/// One allocation per case at most, and only in the rare case.
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn main() {
    unsafe {
        SLOT = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
        .cast();
        assert!(!SLOT.is_null());
    }

    three_same();
    two_reg_misc();
    three_different();
    across_lanes();
    shift_by_immediate();
    scalar_three_same();
    scalar_two_reg_misc();
    scalar_shift_by_immediate();
    vector_by_element();
    scalar_by_element();
    dp_one_source();
    dp_two_source();
    dp_three_source();
    cond_select();
    cond_compare();
    add_with_carry();
    move_wide();
    logical_shifted();
    add_sub_shifted();
    add_sub_extended();
    unsigned_immediate();
    unscaled_immediate();
    register_offset();
    load_store_pair();
    exclusive();
    atomic_memory_ops();
    literal_load();
    simd_structures();
    simd_single_lane();
    pc_relative();
    add_sub_immediate();
    add_sub_immediate_tags();
    logical_immediate();
    bitfield();
    extract();
    fp_int_conversion();
    fp_one_source();
    fp_two_source();
    fp_three_source();
    fp_compare();
    fp_cond_compare();
    fp_cond_select();
    fp_immediate();
    hints();
    barriers();
    system_register_reads();
}

/// `0 Q U 01110 size 1 Rm opcode 1 Rn Rd`, every `(U, size, opcode)` with
/// `Q = 1` and every register zero.
///
/// `Q = 1` because it is the form that exists for every operation that exists
/// at all: several are `128-bit only`, and none is `64-bit only`.
fn three_same() {
    println!("## advanced simd three same");
    for u in 0..2u32 {
        for size in 0..4u32 {
            for opcode in 0..32u32 {
                let word = 0x0e20_0400 | (1 << 30) | (u << 29) | (size << 22) | (opcode << 11);
                println!("  vec3s U{u} size{size} op{opcode:02} -> {}", execute(word));
            }
        }
    }
}

/// `0 Q U 01110 size 10000 opcode 10 Rn Rd`, likewise.
fn two_reg_misc() {
    println!("## advanced simd two-register misc");
    for u in 0..2u32 {
        for size in 0..4u32 {
            for opcode in 0..32u32 {
                let word = 0x0e20_0800 | (1 << 30) | (u << 29) | (size << 22) | (opcode << 12);
                println!("  vec2r U{u} size{size} op{opcode:02} -> {}", execute(word));
            }
        }
    }
}

/// `0 Q U 01110 size 1 Rm opcode 00 Rn Rd` — the widening and narrowing pairs.
///
/// `opcode` is four bits here, not five, and the three saturating doubling
/// forms in it are the ones `crates/asbestos/gen` has no gadget for.
fn three_different() {
    println!("## advanced simd three different");
    for u in 0..2u32 {
        for size in 0..4u32 {
            for opcode in 0..16u32 {
                let word = 0x0e20_0000 | (1 << 30) | (u << 29) | (size << 22) | (opcode << 12);
                println!("  vec3d U{u} size{size} op{opcode:02} -> {}", execute(word));
            }
        }
    }
}

/// `0 Q U 01110 size 11000 opcode 10 Rn Rd` — one vector reduced to a scalar.
///
/// The same shape as two-register misc one bit up, which is why the two are
/// easy to confuse in a mask: bit 20 is the whole difference.
fn across_lanes() {
    println!("## advanced simd across lanes");
    for u in 0..2u32 {
        for size in 0..4u32 {
            for opcode in 0..32u32 {
                let word = 0x0e30_0800 | (1 << 30) | (u << 29) | (size << 22) | (opcode << 12);
                println!("  across U{u} size{size} op{opcode:02} -> {}", execute(word));
            }
        }
    }
}

/// `0 Q U 011110 immh immb opcode 1 Rn Rd` — the shifts by an immediate.
///
/// `immh` is swept because it is the *width*, and `immh = 0` is `MOVI` in the
/// same encoding space: the one place in this class where two instructions
/// share a mask and the decoder has to fall through. `immb` is fixed at 1, so
/// every case names a shift the width allows.
fn shift_by_immediate() {
    println!("## advanced simd shift by immediate");
    for u in 0..2u32 {
        for immh in 0..16u32 {
            for opcode in 0..32u32 {
                let word = 0x0f00_0400
                    | (1 << 30)
                    | (u << 29)
                    | (immh << 19)
                    | (1 << 16)
                    | (opcode << 11);
                println!("  vecshift U{u} immh{immh:02} op{opcode:02} -> {}", execute(word));
            }
        }
    }
}

/// `01 U 11110 size 1 Rm opcode 1 Rn Rd` — the scalar forms of the three-same
/// group, which operate on one element of a vector register.
///
/// A separate encoding from the vector three-same group above, with a separate
/// table in `crates/asbestos/gen/src/simd/scalar.rs` — and one that has always
/// been the thinner of the two.
fn scalar_three_same() {
    println!("## advanced simd scalar three same");
    for u in 0..2u32 {
        for size in 0..4u32 {
            for opcode in 0..32u32 {
                let word = 0x5e20_0400 | (u << 29) | (size << 22) | (opcode << 11);
                println!("  sc3s U{u} size{size} op{opcode:02} -> {}", execute(word));
            }
        }
    }
}

/// `01 U 11110 size 10000 opcode 10 Rn Rd` — the scalar two-register misc.
fn scalar_two_reg_misc() {
    println!("## advanced simd scalar two-register misc");
    for u in 0..2u32 {
        for size in 0..4u32 {
            for opcode in 0..32u32 {
                let word = 0x5e20_0800 | (u << 29) | (size << 22) | (opcode << 12);
                println!("  sc2r U{u} size{size} op{opcode:02} -> {}", execute(word));
            }
        }
    }
}

/// `01 U 111110 immh immb opcode 1 Rn Rd` — the scalar shifts by an immediate.
fn scalar_shift_by_immediate() {
    println!("## advanced simd scalar shift by immediate");
    for u in 0..2u32 {
        for immh in 0..16u32 {
            for opcode in 0..32u32 {
                let word =
                    0x5f00_0400 | (u << 29) | (immh << 19) | (1 << 16) | (opcode << 11);
                println!("  scshift U{u} immh{immh:02} op{opcode:02} -> {}", execute(word));
            }
        }
    }
}

/// `0 Q U 01111 size L M Rm opcode H 0 Rn Rd` — multiply by one lane of a
/// second vector.
///
/// `L`, `M` and `H` are the lane index and are left at zero: what is swept is
/// which `(U, size, opcode)` combinations exist at all.
fn vector_by_element() {
    println!("## advanced simd vector by element");
    for u in 0..2u32 {
        for size in 0..4u32 {
            for opcode in 0..16u32 {
                let word = 0x0f00_0000 | (1 << 30) | (u << 29) | (size << 22) | (opcode << 12);
                println!("  byelem U{u} size{size} op{opcode:02} -> {}", execute(word));
            }
        }
    }
}

/// `01 U 11111 size L M Rm opcode H 0 Rn Rd` — the scalar by-element forms.
///
/// Swept because the vector group's mask and this one's differ in exactly one
/// bit, and getting that bit wrong makes half a table unreachable rather than
/// wrong: `U` is bit 29 here and was *checked* until 2026-09-03, so every
/// `U = 1` entry was dead. Nothing in a hand-written probe had named one.
fn scalar_by_element() {
    println!("## advanced simd scalar by element");
    for u in 0..2u32 {
        for size in 0..4u32 {
            for opcode in 0..16u32 {
                let word = 0x5f00_0000 | (u << 29) | (size << 22) | (opcode << 12);
                println!("  scbyelem U{u} size{size} op{opcode:02} -> {}", execute(word));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The scalar integer core
// ---------------------------------------------------------------------------
//
// Everything above is SIMD, because that is where the gaps were: 46 missing
// decoders in one day. The scalar integer groups are the opposite prior --
// every guest program executes millions of them and `scalar_probe`, which is
// hand-written, found nothing at all. That is exactly why a *sweep* of them is
// worth having: what a hand-written probe cannot find is an instruction nobody
// thought of, and the ones nobody thinks of here are the rare ones. `RBIT`,
// `CRC32`, the pointer-authentication family, the memory-tagging family and the
// flag-manipulation instructions are all in these groups, and none of them is
// what a C compiler emits from ordinary code.
//
// They qualify under the same safety rule as the SIMD groups and for the same
// reason: **data-processing register and immediate encodings touch no memory and
// take no branch**, so executing one that turns out to be allocated cannot
// corrupt anything. The load/store and branch spaces do not qualify and are not
// swept.
//
// Every register field is zero, so each writes `x0` at most and reads `x0`.

/// `sf 1 S 11010110 opcode2 opcode Rn Rd` — data-processing (1 source).
///
/// `RBIT`, `REV16`, `REV32`, `REV`, `CLZ`, `CLS`, and with `opcode2 = 1` the
/// whole `PACIA`/`AUTDZB` pointer-authentication family. `opcode2` is swept over
/// its first two values only: everything above them is unallocated in every
/// revision, and 32 of them would be 16,000 cases to say so.
fn dp_one_source() {
    println!("## data-processing (1 source)");
    for sf in 0..2u32 {
        for s in 0..2u32 {
            for opcode2 in 0..2u32 {
                for opcode in 0..64u32 {
                    let word =
                        0x5ac0_0000 | (sf << 31) | (s << 29) | (opcode2 << 16) | (opcode << 10);
                    println!(
                        "  dp1s sf{sf} S{s} op2_{opcode2} op{opcode:02} -> {}",
                        execute(word)
                    );
                }
            }
        }
    }
}

/// `sf 0 S 11010110 Rm opcode Rn Rd` — data-processing (2 source).
///
/// `UDIV`, `SDIV`, the four variable shifts, `CRC32`, `PACGA`, and the
/// memory-tagging `SUBP`, `IRG` and `GMI`. `CRC32` is the interesting one:
/// `AT_HWCAP` claims it, and a claim the decoder cannot back is what
/// `crypto_probe` found four of.
fn dp_two_source() {
    println!("## data-processing (2 source)");
    for sf in 0..2u32 {
        for s in 0..2u32 {
            for opcode in 0..64u32 {
                let word = 0x1ac0_0000 | (sf << 31) | (s << 29) | (opcode << 10);
                println!("  dp2s sf{sf} S{s} op{opcode:02} -> {}", execute(word));
            }
        }
    }
}

/// `sf op54 11011 op31 Rm o0 Ra Rn Rd` — data-processing (3 source).
///
/// `MADD`, `MSUB` and the six widening multiplies. Small, and swept because
/// `op54` and `op31` between them have far more unallocated combinations than
/// allocated ones — which is the shape that produced a decoder for something
/// that does not exist elsewhere in this file.
fn dp_three_source() {
    println!("## data-processing (3 source)");
    for sf in 0..2u32 {
        for op54 in 0..4u32 {
            for op31 in 0..8u32 {
                for o0 in 0..2u32 {
                    let word =
                        0x1b00_0000 | (sf << 31) | (op54 << 29) | (op31 << 21) | (o0 << 15);
                    println!(
                        "  dp3s sf{sf} op54_{op54} op31_{op31} o0_{o0} -> {}",
                        execute(word)
                    );
                }
            }
        }
    }
}

/// `sf op S 11010100 Rm cond op2 Rn Rd` — conditional select.
///
/// `CSEL`, `CSINC`, `CSINV`, `CSNEG`, over all sixteen conditions. The
/// conditions are the point: a decoder that reads `cond` with the wrong width or
/// forgets that `1111` is `NV` gets fifteen right.
fn cond_select() {
    println!("## conditional select");
    for sf in 0..2u32 {
        for op in 0..2u32 {
            for s in 0..2u32 {
                for cond in 0..16u32 {
                    for op2 in 0..4u32 {
                        let word = 0x1a80_0000
                            | (sf << 31)
                            | (op << 30)
                            | (s << 29)
                            | (cond << 12)
                            | (op2 << 10);
                        println!(
                            "  csel sf{sf} op{op} S{s} cond{cond:02} op2_{op2} -> {}",
                            execute(word)
                        );
                    }
                }
            }
        }
    }
}

/// `sf op S 11010010 Rm/imm5 cond i o2 Rn o3 nzcv` — conditional compare.
///
/// Both forms, register and immediate, which differ only in bit 11 — the same
/// one-bit distinction that made `shift::lengthening` decode every scalar
/// encoding as a vector one.
fn cond_compare() {
    println!("## conditional compare");
    for sf in 0..2u32 {
        for op in 0..2u32 {
            for s in 0..2u32 {
                for imm_form in 0..2u32 {
                    for o2 in 0..2u32 {
                        for cond in 0..16u32 {
                            let word = 0x1a40_0000
                                | (sf << 31)
                                | (op << 30)
                                | (s << 29)
                                | (cond << 12)
                                | (imm_form << 11)
                                | (o2 << 10);
                            println!(
                                "  ccmp sf{sf} op{op} S{s} imm{imm_form} o2_{o2} cond{cond:02} -> {}",
                                execute(word)
                            );
                        }
                    }
                }
            }
        }
    }
}

/// `sf op S 11010000 Rm opcode2 Rn Rd` — add/subtract with carry, and the two
/// groups that share its encoding space.
///
/// `ADC`, `ADCS`, `SBC`, `SBCS` at `opcode2 = 0`, and above them `RMIF`,
/// `SETF8` and `SETF16` — FEAT_FlagM, which a compiler emits for some
/// floating-point comparisons and which nothing in this tree had ever named.
/// The whole six-bit field is swept because that is what distinguishes them.
fn add_with_carry() {
    println!("## add/subtract with carry");
    for sf in 0..2u32 {
        for op in 0..2u32 {
            for s in 0..2u32 {
                for opcode2 in 0..64u32 {
                    let word =
                        0x1a00_0000 | (sf << 31) | (op << 30) | (s << 29) | (opcode2 << 10);
                    println!(
                        "  adc sf{sf} op{op} S{s} op2_{opcode2:02} -> {}",
                        execute(word)
                    );
                }
            }
        }
    }
}

/// `sf opc 100101 hw imm16 Rd` — move wide (immediate).
///
/// Thirty-two cases, of which eight are unallocated: `opc = 01` in every
/// combination, and `hw >= 2` when `sf = 0`, because a 32-bit move cannot name a
/// shift of 32 or 48. Cheap, and the second of those is a width rule of exactly
/// the kind the SIMD sweep found four of.
fn move_wide() {
    println!("## move wide (immediate)");
    for sf in 0..2u32 {
        for opc in 0..4u32 {
            for hw in 0..4u32 {
                let word = 0x1280_0000 | (sf << 31) | (opc << 29) | (hw << 21);
                println!("  movw sf{sf} opc{opc} hw{hw} -> {}", execute(word));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Loads and stores
// ---------------------------------------------------------------------------
//
// These are the groups the safety rule above excludes — they touch memory —
// and they can be swept anyway, for one reason: **every register field is zero,
// so `x0` is the base register of every address any of them forms**, and `x0`
// is where the first argument of the function the probe calls arrives. Give it
// a scratch page and an unknown load reads from a page this process owns rather
// than from wherever the register happened to point.
//
// `ldst.rs` is 1203 lines, the largest decoder here after the SIMD tables, and
// it had no sweep at all. What a hand-written probe covers is the addressing
// modes somebody thought of.
//
// Three consequences worth stating, because they shape what the output means:
//
// - A register-offset form computes `x0 + x0`, which is not a mapped address.
//   That is `SIGSEGV` on both sides, and it still answers the question: an
//   encoding with no decoder is `SIGILL`, one with a decoder is `SIGSEGV`.
// - The scratch pointer is 2048 bytes into its page, so a negative offset and a
//   writeback that goes backwards both stay inside it.
// - The **branch** group is still not swept, and cannot be by this method: a
//   branch to an arbitrary offset does not come back.

/// `Rt = 1`, `Rn = 0`: the transfer register and the base are different
/// registers, and the base is the one holding the scratch page.
const RT_RN: u32 = 1;
/// ...with `Rt2 = 2`, for the pair forms.
const RT_RN_RT2: u32 = RT_RN | (2 << 10);
/// ...with `Rm = 3`, for the register-offset form. `x3` is zero, so the address
/// is the scratch page and not twice it.
const RT_RN_RM: u32 = RT_RN | (3 << 16);
/// ...with `Rt = 2`, `Rs = 4` and `Rt2 = 31`, for the exclusive forms.
///
/// `Rt2` is the second transfer register only for `STXP`/`LDXP`; every other
/// encoding in the group requires `11111`, and zero would make most of them
/// unpredictable. `Rt` is **2 and not 1** because `CASP` shares this space and
/// takes register *pairs*: an odd `Rs` or `Rt` there is unpredictable, and this
/// CPU takes it as undefined, which read as eight missing decoders.
const RT_RN_RS_RT2: u32 = 2 | (4 << 16) | (0x1f << 10);
/// ...with `Rs = 4`, for the atomics.
const RT_RN_RS: u32 = RT_RN | (4 << 16);

/// `size 111 V 01 opc imm12 Rn Rt` — the scaled unsigned-offset form, which is
/// the one a compiler emits for a struct field.
fn unsigned_immediate() {
    println!("## load/store register (unsigned immediate)");
    for size in 0..4u32 {
        for v in 0..2u32 {
            for opc in 0..4u32 {
                let word = 0x3900_0000 | RT_RN | (size << 30) | (v << 26) | (opc << 22);
                println!(
                    "  ldstui size{size} V{v} opc{opc} -> {}",
                    execute_addressing(word)
                );
            }
        }
    }
}

/// `size 111 V 00 opc 0 imm9 op2 Rn Rt` — the four unscaled forms told apart by
/// bits 11:10: unscaled, post-indexed, unprivileged, pre-indexed.
///
/// `op2` is the interesting field. Unprivileged (`10`) is a distinct
/// instruction — `LDTR` — that behaves as an ordinary load at EL0 and is easy
/// to leave undecoded because nothing emits it.
fn unscaled_immediate() {
    println!("## load/store register (unscaled immediate)");
    for size in 0..4u32 {
        for v in 0..2u32 {
            for opc in 0..4u32 {
                for op2 in 0..4u32 {
                    let word = 0x3800_0000
                        | RT_RN
                        | (size << 30)
                        | (v << 26)
                        | (opc << 22)
                        | (op2 << 10);
                    println!(
                        "  ldstun size{size} V{v} opc{opc} op2_{op2} -> {}",
                        execute_addressing(word)
                    );
                }
            }
        }
    }
}

/// `size 111 V 00 opc 1 Rm option S 10 Rn Rt` — the register-offset form.
///
/// `option` is swept over all eight, and only four of them name an extend that
/// exists: `010` (UXTW), `011` (LSL), `110` (SXTW) and `111` (SXTX). The other
/// four are unallocated, which is the shape three defects above this line were.
fn register_offset() {
    println!("## load/store register (register offset)");
    for size in 0..4u32 {
        for v in 0..2u32 {
            for opc in 0..4u32 {
                for option in 0..8u32 {
                    let word = 0x3820_0800
                        | RT_RN_RM
                        | (size << 30)
                        | (v << 26)
                        | (opc << 22)
                        | (option << 13);
                    println!(
                        "  ldstro size{size} V{v} opc{opc} opt{option} -> {}",
                        execute_addressing(word)
                    );
                }
            }
        }
    }
}

/// `opc 101 V op L imm7 Rt2 Rn Rt` — load/store pair, all four addressing forms
/// (no-allocate, post-indexed, offset, pre-indexed) at every width.
fn load_store_pair() {
    println!("## load/store pair");
    for opc in 0..4u32 {
        for v in 0..2u32 {
            for op in 0..4u32 {
                for l in 0..2u32 {
                    let word = 0x2800_0000
                        | RT_RN_RT2
                        | (opc << 30)
                        | (v << 26)
                        | (op << 23)
                        | (l << 22);
                    println!(
                        "  ldstp opc{opc} V{v} op{op} L{l} -> {}",
                        execute_addressing(word)
                    );
                }
            }
        }
    }
}

/// `size 001000 o2 L o1 Rs o0 Rt2 Rn Rt` — the exclusive and load-acquire forms.
///
fn exclusive() {
    println!("## load/store exclusive");
    for size in 0..4u32 {
        for o2 in 0..2u32 {
            for l in 0..2u32 {
                for o1 in 0..2u32 {
                    for o0 in 0..2u32 {
                        let word = 0x0800_0000
                            | RT_RN_RS_RT2
                            | (size << 30)
                            | (o2 << 23)
                            | (l << 22)
                            | (o1 << 21)
                            | (o0 << 15);
                        println!(
                            "  ldstx size{size} o2_{o2} L{l} o1_{o1} o0_{o0} -> {}",
                            execute_addressing(word)
                        );
                    }
                }
            }
        }
    }
}

/// `size 111 0 00 A R 1 Rs o3 opc 00 Rn Rt` — the LSE atomics.
///
/// `atomics_probe` covers these by hand and found one defect in 81 cases; this
/// asks the whole space, including the `opc` values that name nothing.
fn atomic_memory_ops() {
    println!("## atomic memory operations");
    for size in 0..4u32 {
        for a in 0..2u32 {
            for r in 0..2u32 {
                for o3 in 0..2u32 {
                    for opc in 0..8u32 {
                        let word = 0x3820_0000
                            | RT_RN_RS
                            | (size << 30)
                            | (a << 23)
                            | (r << 22)
                            | (o3 << 15)
                            | (opc << 12);
                        println!(
                            "  ldstat size{size} A{a} R{r} o3_{o3} opc{opc} -> {}",
                            execute_addressing(word)
                        );
                    }
                }
            }
        }
    }
}

/// `opc 011 V 00 imm19 Rt` — the PC-relative literal load.
///
/// `imm19 = 0` reads the instruction itself, which is on a page the probe
/// mapped, so this one needs no scratch at all. `opc = 11` is `PRFM` and
/// `opc = 10` is the sign-extending word load.
fn literal_load() {
    println!("## load register (literal)");
    for opc in 0..4u32 {
        for v in 0..2u32 {
            let word = 0x1800_0000 | RT_RN | (opc << 30) | (v << 26);
            println!("  ldlit opc{opc} V{v} -> {}", execute_addressing(word));
        }
    }
}

// ---------------------------------------------------------------------------
// The hints and barriers
// ---------------------------------------------------------------------------
//
// The branch and system space is not sweepable as a whole — a branch to an
// arbitrary offset does not come back, and an `SVC` makes a syscall chosen by
// whatever is in `x8`. These two corners of it are, because every encoding in
// them either does nothing or orders memory, and both are one instruction long.
//
// They matter more than their size suggests. **`PACIASP` and `AUTIASP` are
// hints**, and a toolchain built with `-mbranch-protection=standard` puts one at
// the top and one at the bottom of every function it compiles. A CPU without
// FEAT_PAuth executes them as no-ops, which is the whole point of putting them
// in the hint space; a decoder that refuses them instead cannot run a single
// function of such a build. `BTI`, `CSDB`, `SB` and `PSB CSYNC` are the same
// argument one step down.

/// `1101 0101 0000 0011 0010 CRm op2 11111` — the hint space.
///
/// `NOP`, `YIELD`, `WFE`, `WFI`, `SEV`, `SEVL`, the `BTI` variants, the
/// pointer-authentication prologue and epilogue pairs, `PSB CSYNC`, `CSDB` and
/// everything unallocated between them. All 128, because an unallocated hint is
/// architecturally a `NOP` and telling that from a missing decoder is the
/// question.
fn hints() {
    println!("## hints");
    for crm in 0..16u32 {
        for op2 in 0..8u32 {
            let word = 0xd503_201f | (crm << 8) | (op2 << 5);
            println!("  hint CRm{crm:02} op2_{op2} -> {}", execute(word));
        }
    }
}

/// `1101 0101 0000 0011 0011 CRm op2 11111` — the barrier space.
///
/// `DSB`, `DMB`, `ISB`, `SB`, `CLREX` and `TCOMMIT`, at every domain and
/// ordering. `CLREX` is here, which is worth noting: it was a no-op with a
/// comment saying the monitor is cleared by `STXR` anyway — true, and not the
/// same thing, because the point of `CLREX` is to make a *later* `STXR` fail.
fn barriers() {
    println!("## barriers");
    for crm in 0..16u32 {
        for op2 in 0..8u32 {
            let word = 0xd503_301f | (crm << 8) | (op2 << 5);
            println!("  barrier CRm{crm:02} op2_{op2} -> {}", execute(word));
        }
    }
}

// ---------------------------------------------------------------------------
// Data processing (immediate)
// ---------------------------------------------------------------------------
//
// The rest of the immediate space, which `move_wide` above started. Pure
// register operations again, so the first safety rule applies unchanged.
//
// The two large ones are worth the cases they cost. **Logical immediate** and
// **bitfield** both carry an `N:imms` encoding whose validity is a real rule
// rather than a field to read — `decode_bitmask_imm` implements it, and there
// are more `(N, imms)` pairs that name no mask than pairs that name one. An
// encoding accepted there is a mask computed from a number that means nothing.

/// `op immlo 10000 immhi Rd` — `ADR` and `ADRP`.
fn pc_relative() {
    println!("## pc-relative addressing");
    for op in 0..2u32 {
        let word = 0x1000_0000 | (op << 31);
        println!("  pcrel op{op} -> {}", execute(word));
    }
}

/// `sf op S 100010 sh imm12 Rn Rd` — add and subtract an immediate, with the
/// shift that makes the 12-bit field cover 24 bits.
fn add_sub_immediate() {
    println!("## add/subtract (immediate)");
    for sf in 0..2u32 {
        for op in 0..2u32 {
            for s in 0..2u32 {
                for sh in 0..2u32 {
                    let word = 0x1100_0000 | (sf << 31) | (op << 30) | (s << 29) | (sh << 22);
                    println!("  addsubi sf{sf} op{op} S{s} sh{sh} -> {}", execute(word));
                }
            }
        }
    }
}

/// `sf op S 100011 o2 uimm6 op3 uimm4 Xn Xd` — `ADDG` and `SUBG`, FEAT_MTE.
///
/// Swept for the same reason the memory-tagging two-source forms are: they are
/// one bit away from the group above and nothing else asks whether that bit is
/// read.
fn add_sub_immediate_tags() {
    println!("## add/subtract (immediate, with tags)");
    for sf in 0..2u32 {
        for op in 0..2u32 {
            for s in 0..2u32 {
                for o2 in 0..2u32 {
                    let word = 0x1180_0000 | (sf << 31) | (op << 30) | (s << 29) | (o2 << 22);
                    println!("  addsubg sf{sf} op{op} S{s} o2_{o2} -> {}", execute(word));
                }
            }
        }
    }
}

/// `sf opc 100100 N immr imms Rn Rd` — `AND`, `ORR`, `EOR` and `ANDS` of a
/// bitmask immediate.
///
/// `immr` is swept over the one bit that decides validity and `imms` over all
/// of its, because the pair is what decides whether the encoding names a mask at
/// all: `N = 1` needs a 64-bit operation, and a run of ones in `imms` that
/// reaches the element size names nothing.
fn logical_immediate() {
    println!("## logical (immediate)");
    for sf in 0..2u32 {
        for opc in 0..4u32 {
            for n in 0..2u32 {
                for immr in [0u32, 32] {
                    for imms in 0..64u32 {
                        let word = 0x1200_0000
                            | (sf << 31)
                            | (opc << 29)
                            | (n << 22)
                            | (immr << 16)
                            | (imms << 10);
                        println!(
                            "  logimm sf{sf} opc{opc} N{n} immr{immr:02} imms{imms:02} -> {}",
                            execute(word)
                        );
                    }
                }
            }
        }
    }
}

/// `sf opc 100110 N immr imms Rn Rd` — `SBFM`, `BFM`, `UBFM` and everything
/// spelled on top of them: `LSL`, `LSR`, `ASR`, `SXTB`, `UBFX` and the rest.
///
/// `N` has to equal `sf`, and a 32-bit operation cannot name a bit at 32 or
/// above — in `imms` *or* in `immr`, so both are swept over the bit that decides
/// it. Three width rules, which is where this sweep keeps finding things.
fn bitfield() {
    println!("## bitfield");
    for sf in 0..2u32 {
        for opc in 0..4u32 {
            for n in 0..2u32 {
                for immr in [0u32, 32] {
                    for imms in 0..64u32 {
                        let word = 0x1300_0000
                            | (sf << 31)
                            | (opc << 29)
                            | (n << 22)
                            | (immr << 16)
                            | (imms << 10);
                        println!(
                            "  bitfield sf{sf} opc{opc} N{n} immr{immr:02} imms{imms:02} -> {}",
                            execute(word)
                        );
                    }
                }
            }
        }
    }
}

/// `sf op21 100111 N o0 Rm imms Rn Rd` — `EXTR`, which is how `ROR` by an
/// immediate is spelled.
fn extract() {
    println!("## extract");
    for sf in 0..2u32 {
        for op21 in 0..4u32 {
            for n in 0..2u32 {
                for o0 in 0..2u32 {
                    for imms in [0u32, 31, 32, 63] {
                        let word = 0x1380_0000
                            | (sf << 31)
                            | (op21 << 29)
                            | (n << 22)
                            | (o0 << 21)
                            | (imms << 10);
                        println!(
                            "  extr sf{sf} op21_{op21} N{n} o0_{o0} imms{imms:02} -> {}",
                            execute(word)
                        );
                    }
                }
            }
        }
    }
}

/// `sf opc 01010 shift N Rm imm6 Rn Rd` — the logical operations with a shifted
/// second operand.
///
/// `ROR` *is* an allocated shift here, which is the one place it differs from
/// the arithmetic group below, and a 32-bit operation cannot shift by 32 or
/// more — the field is six bits wide for both widths.
fn logical_shifted() {
    println!("## logical (shifted register)");
    for sf in 0..2u32 {
        for opc in 0..4u32 {
            for shift in 0..4u32 {
                for n in 0..2u32 {
                    for imm6 in [0u32, 31, 32, 63] {
                        let word = 0x0a00_0000
                            | (sf << 31)
                            | (opc << 29)
                            | (shift << 22)
                            | (n << 21)
                            | (imm6 << 10);
                        println!(
                            "  logsh sf{sf} opc{opc} sh{shift} N{n} imm{imm6:02} -> {}",
                            execute(word)
                        );
                    }
                }
            }
        }
    }
}

/// `sf op S 01011 shift 0 Rm imm6 Rn Rd` — add and subtract with a shifted
/// second operand, where `shift = 3` (`ROR`) names nothing.
fn add_sub_shifted() {
    println!("## add/subtract (shifted register)");
    for sf in 0..2u32 {
        for op in 0..2u32 {
            for s in 0..2u32 {
                for shift in 0..4u32 {
                    for imm6 in [0u32, 31, 32, 63] {
                        let word = 0x0b00_0000
                            | (sf << 31)
                            | (op << 30)
                            | (s << 29)
                            | (shift << 22)
                            | (imm6 << 10);
                        println!(
                            "  addsubsh sf{sf} op{op} S{s} sh{shift} imm{imm6:02} -> {}",
                            execute(word)
                        );
                    }
                }
            }
        }
    }
}

/// `sf op S 01011 00 1 Rm option imm3 Rn Rd` — the extended-register form, where
/// the second operand is widened from a byte, halfword or word first.
///
/// `imm3` is the left shift applied after the extend and is **0 to 4**: the
/// three values above that name nothing. All eight `option` values do name an
/// extend, which is what makes this group's rule different from the
/// register-offset load's.
fn add_sub_extended() {
    println!("## add/subtract (extended register)");
    for sf in 0..2u32 {
        for op in 0..2u32 {
            for s in 0..2u32 {
                for option in 0..8u32 {
                    for imm3 in 0..8u32 {
                        let word = 0x0b20_0000
                            | (sf << 31)
                            | (op << 30)
                            | (s << 29)
                            | (option << 13)
                            | (imm3 << 10);
                        println!(
                            "  addsubex sf{sf} op{op} S{s} opt{option} imm3_{imm3} -> {}",
                            execute(word)
                        );
                    }
                }
            }
        }
    }
}

/// `1101 0101 0 0 1 1 11 000 0000 CRm op2 Rt` — the ID register block.
///
/// # Why only this corner, and why the rest is off limits
///
/// Linux **traps and emulates** `op0 = 3, op1 = 0, CRn = 0` for EL0 and fills in
/// a sanitised value, precisely so a library can ask what the CPU implements.
/// One this kernel has no arm for is an illegal instruction instead and the
/// program dies — which is what happened to `MIDR_EL1`, `MPIDR_EL1` and
/// `TPIDRRO_EL0` until 2026-09-02, found only because a hand-written probe
/// happened to name them.
///
/// The rest of the system-register space is **not swept, and that is a
/// measurement rather than caution**. A sweep of `op1` 0 and 3 across every
/// `CRn` took the *host's* Docker VM down twice, deterministically, about 537
/// cases in — at `op0 = 3, op1 = 0, CRn = 4`, which is `SPSel`, `CurrentEL`,
/// `PAN` and their neighbours. Reading one of those from EL0 is a trap on real
/// hardware; under a hypervisor it evidently is not only that.
///
/// So the blind-sweep safety argument that holds for every other group here does
/// **not** extend to this one: those groups are safe because of what the
/// instruction does to *this* process, and an `MRS` can reach past it.
fn system_register_reads() {
    println!("## system register reads (the ID block)");
    for crm in 0..16u32 {
        for op2 in 0..8u32 {
            let word = 0xd538_0000 | (crm << 8) | (op2 << 5);
            println!("  mrs id CRm{crm:02} op2_{op2} -> {}", execute(word));
        }
    }
}

/// `0 Q 0011000 L 000000 opcode size Rn Rt` and its post-indexed form — the
/// `LD1`–`LD4` and `ST1`–`ST4` structure loads.
///
/// These are what a NEON `memcpy` and every vectorised loop are made of, and
/// they were the one corner of the load/store space the first sweep missed:
/// `ldst.rs` routes them to a decoder of their own before any of the groups
/// above, so none of those cases reached them.
///
/// `opcode` is the interesting field. Eight of its sixteen values are allocated
/// and the pattern is not obvious — `LD1` is at 7, 10, 6 and 2 depending on how
/// many registers it names — so an unallocated one decoded as its neighbour
/// loads a different number of registers.
fn simd_structures() {
    println!("## advanced simd load/store structures");
    for post in 0..2u32 {
        for q in 0..2u32 {
            for l in 0..2u32 {
                for opcode in 0..16u32 {
                    for size in 0..4u32 {
                        let base = if post != 0 { 0x0c80_0000 } else { 0x0c00_0000 };
                        // Rn = 0 is the scratch page; Rm = 3 holds zero, which
                        // is the register form of the post-index.
                        let word = base
                            | (q << 30)
                            | (l << 22)
                            | (opcode << 12)
                            | (size << 10)
                            | if post != 0 { 3 << 16 } else { 0 };
                        println!(
                            "  ldstst post{post} Q{q} L{l} op{opcode:02} size{size} -> {}",
                            execute_addressing(word)
                        );
                    }
                }
            }
        }
    }
}

/// `0 Q 0011010 L R 00000 opcode S size Rn Rt` and its post-indexed form — the
/// single-lane structure loads, including the replicating `LD1R`–`LD4R`.
fn simd_single_lane() {
    println!("## advanced simd load/store single structure");
    for post in 0..2u32 {
        for q in 0..2u32 {
            for l in 0..2u32 {
                for r in 0..2u32 {
                    for opcode in 0..8u32 {
                        for sbit in 0..2u32 {
                            for size in 0..4u32 {
                                let base =
                                    if post != 0 { 0x0d80_0000 } else { 0x0d00_0000 };
                                let word = base
                                    | (q << 30)
                                    | (l << 22)
                                    | (r << 21)
                                    | (opcode << 13)
                                    | (sbit << 12)
                                    | (size << 10)
                                    | if post != 0 { 3 << 16 } else { 0 };
                                println!(
                                    "  ldst1s post{post} Q{q} L{l} R{r} op{opcode} S{sbit} size{size} -> {}",
                                    execute_addressing(word)
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scalar floating point
// ---------------------------------------------------------------------------
//
// Eight groups, all of them register-to-register, so the first safety rule
// applies. `fp_probe` covers them by hand and found four defects that way,
// including two conversion gadgets that did the work at 64 bits and narrowed —
// which saturates at the wrong boundary and sign-extends where a `W`
// destination zeroes.
//
// The field to watch across all eight is `type`, which names the precision: 00
// single, 01 double, **11 half** (FEAT_FP16) and 10 nothing at all. A decoder
// that reads it as a width without asking whether the width exists accepts a
// quarter of every group.

/// `sf 0 S 11110 type 1 rmode opcode 000000 Rn Rd` — between a floating-point
/// register and a general one, in both directions and at every rounding mode.
fn fp_int_conversion() {
    println!("## fp/integer conversion");
    for sf in 0..2u32 {
        for s in 0..2u32 {
            for ty in 0..4u32 {
                for rmode in 0..4u32 {
                    for opcode in 0..8u32 {
                        let word = 0x1e20_0000
                            | (sf << 31)
                            | (s << 29)
                            | (ty << 22)
                            | (rmode << 19)
                            | (opcode << 16);
                        println!(
                            "  fpcvt sf{sf} S{s} ty{ty} rm{rmode} op{opcode} -> {}",
                            execute(word)
                        );
                    }
                }
            }
        }
    }
}

/// `M 0 S 11110 type 1 opcode 10000 Rn Rd` — `FMOV`, `FABS`, `FNEG`, `FSQRT`,
/// the rounding family and the precision conversions.
fn fp_one_source() {
    println!("## fp data-processing (1 source)");
    for m in 0..2u32 {
        for s in 0..2u32 {
            for ty in 0..4u32 {
                for opcode in 0..64u32 {
                    let word =
                        0x1e20_4000 | (m << 31) | (s << 29) | (ty << 22) | (opcode << 15);
                    println!(
                        "  fp1s M{m} S{s} ty{ty} op{opcode:02} -> {}",
                        execute(word)
                    );
                }
            }
        }
    }
}

/// `M 0 S 11110 type 1 Rm opcode 10 Rn Rd` — the arithmetic.
fn fp_two_source() {
    println!("## fp data-processing (2 source)");
    for m in 0..2u32 {
        for s in 0..2u32 {
            for ty in 0..4u32 {
                for opcode in 0..16u32 {
                    let word =
                        0x1e20_0800 | (m << 31) | (s << 29) | (ty << 22) | (opcode << 12);
                    println!("  fp2s M{m} S{s} ty{ty} op{opcode:02} -> {}", execute(word));
                }
            }
        }
    }
}

/// `M 0 S 11111 type o1 Rm o0 Ra Rn Rd` — the four fused multiply-adds.
fn fp_three_source() {
    println!("## fp data-processing (3 source)");
    for m in 0..2u32 {
        for s in 0..2u32 {
            for ty in 0..4u32 {
                for o1 in 0..2u32 {
                    for o0 in 0..2u32 {
                        let word = 0x1f00_0000
                            | (m << 31)
                            | (s << 29)
                            | (ty << 22)
                            | (o1 << 21)
                            | (o0 << 15);
                        println!(
                            "  fp3s M{m} S{s} ty{ty} o1_{o1} o0_{o0} -> {}",
                            execute(word)
                        );
                    }
                }
            }
        }
    }
}

/// `M 0 S 11110 type 1 Rm op 1000 Rn opcode2` — `FCMP` and `FCMPE`, against a
/// register and against zero.
///
/// `opcode2` is five bits of which only four values are allocated, and its low
/// three bits must be zero — the shape this sweep keeps finding read as a
/// selector.
fn fp_compare() {
    println!("## fp compare");
    for m in 0..2u32 {
        for s in 0..2u32 {
            for ty in 0..4u32 {
                for op in 0..4u32 {
                    for opcode2 in 0..32u32 {
                        let word = 0x1e20_2000
                            | (m << 31)
                            | (s << 29)
                            | (ty << 22)
                            | (op << 14)
                            | opcode2;
                        println!(
                            "  fpcmp M{m} S{s} ty{ty} op{op} o2_{opcode2:02} -> {}",
                            execute(word)
                        );
                    }
                }
            }
        }
    }
}

/// `M 0 S 11110 type 1 Rm cond 01 Rn op nzcv` — `FCCMP` and `FCCMPE`.
fn fp_cond_compare() {
    println!("## fp conditional compare");
    for m in 0..2u32 {
        for s in 0..2u32 {
            for ty in 0..4u32 {
                for cond in 0..16u32 {
                    for op in 0..2u32 {
                        let word = 0x1e20_0400
                            | (m << 31)
                            | (s << 29)
                            | (ty << 22)
                            | (cond << 12)
                            | (op << 4);
                        println!(
                            "  fpccmp M{m} S{s} ty{ty} cond{cond:02} op{op} -> {}",
                            execute(word)
                        );
                    }
                }
            }
        }
    }
}

/// `M 0 S 11110 type 1 Rm cond 11 Rn Rd` — `FCSEL`.
fn fp_cond_select() {
    println!("## fp conditional select");
    for m in 0..2u32 {
        for s in 0..2u32 {
            for ty in 0..4u32 {
                for cond in 0..16u32 {
                    let word =
                        0x1e20_0c00 | (m << 31) | (s << 29) | (ty << 22) | (cond << 12);
                    println!(
                        "  fpcsel M{m} S{s} ty{ty} cond{cond:02} -> {}",
                        execute(word)
                    );
                }
            }
        }
    }
}

/// `M 0 S 11110 type 1 imm8 100 imm5 Rd` — `FMOV` of one of the 256 constants
/// the eight-bit field can name. `imm5` must be zero.
fn fp_immediate() {
    println!("## fp immediate");
    for m in 0..2u32 {
        for s in 0..2u32 {
            for ty in 0..4u32 {
                for imm5 in 0..32u32 {
                    let word =
                        0x1e20_1000 | (m << 31) | (s << 29) | (ty << 22) | (imm5 << 5);
                    println!(
                        "  fpimm M{m} S{s} ty{ty} imm5_{imm5:02} -> {}",
                        execute(word)
                    );
                }
            }
        }
    }
}
