//! That `tools/prebuilt_gadget_gen` still produces a correct spec_fn.
//!
//! It had no test at all. `crates/kernel/offloadtestprebuilt/src/mixgen.rs` is
//! its output for `mixbench:mix`, checked in and registered by nothing; this
//! runs it and the hand-written `mixbench::mix` over the same inputs and
//! requires the **whole** `cpu_state` to match afterwards.
//!
//! Comparing the whole state rather than `regs[0]` is the point:
//! `docs/changelog/2026-09-09-the-offload-benchmarks-needed-docker-to-build-forty-lines.md`
//! records that `run.sh`'s bit-identical check does *not* catch a spec_fn that
//! writes the wrong scratch register, because it compares the program's output.
//! Here both sides are in this process, so there is nothing stopping it.

use iul as _;

use offloadtestprebuilt::{Cpu, mixgen};

/// The two implementations, run against the same starting registers.
fn both(seed: u64, count: u64) -> (Cpu, Cpu) {
    let start = |cpu: &mut Cpu| {
        cpu.regs[0] = seed;
        cpu.regs[1] = count;
    };
    let (mut hand, mut generated) = (Cpu::default(), Cpu::default());
    start(&mut hand);
    start(&mut generated);

    // SAFETY: two zeroed `cpu_state`s on the stack. `mix` has no frame and
    // never reaches memory, so the null TLB is never touched -- which is
    // exactly why it is the shape the offload mechanism wins on.
    unsafe {
        offloadtestprebuilt::mix(&raw mut hand, std::ptr::null_mut());
        mixgen::spec(&raw mut generated, std::ptr::null_mut());
    }
    (hand, generated)
}

fn same(a: &Cpu, b: &Cpu) -> Result<(), String> {
    for i in 0..a.regs.len() {
        if a.regs[i] != b.regs[i] {
            return Err(format!(
                "x{i}: hand {:#x}, generated {:#x}",
                a.regs[i], b.regs[i]
            ));
        }
    }
    if a.sp != b.sp {
        return Err(format!("sp: hand {:#x}, generated {:#x}", a.sp, b.sp));
    }
    Ok(())
}

#[test]
fn the_generated_spec_fn_matches_the_hand_written_one() {
    // A spread rather than a sweep: the interesting ones are the boundaries of
    // the loop count, since the early exit and the `subs`/`b.ne` edge are the
    // control flow the state machine had to reproduce.
    let counts = [0u64, 1, 2, 3, 63, 64, 65, 1000];
    let seeds = [
        0u64,
        1,
        u64::MAX,
        0x0123_4567_89ab_cdef,
        0x8000_0000_0000_0000,
    ];

    let mut cases = 0;
    for &count in &counts {
        for &seed in &seeds {
            let (hand, generated) = both(seed, count);
            if let Err(what) = same(&hand, &generated) {
                panic!("mix({seed:#x}, {count}): {what}");
            }
            cases += 1;
        }
    }
    assert_eq!(cases, 40, "the loops ran");
}

/// And that it is not both of them answering the same wrong thing: the result
/// against an independent evaluation of what `mix` is supposed to compute.
#[test]
fn and_both_compute_what_mixbench_does() {
    // Written the way `tests/offload/prebuilt/guest/src/bin/mixbench.rs`
    // writes it, shifts and all, because the point is that this is a *separate*
    // rendering of the same arithmetic rather than a call to the same helper.
    #[allow(clippy::manual_rotate)]
    fn reference(seed: u64, count: u64) -> u64 {
        let mut h = seed ^ 0x736f_6d65_7073_6575;
        let mut i = 0u64;
        while i < count {
            h ^= i + 1;
            h = (h << 13) | (h >> 51);
            h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
            h = h.wrapping_add(0x9e37_79b9_7f4a_7c15);
            i += 1;
        }
        h
    }

    for count in [0u64, 1, 7, 64] {
        for seed in [0u64, 1, 0x0123_4567_89ab_cdef] {
            let (hand, generated) = both(seed, count);
            let want = reference(seed, count);
            assert_eq!(hand.regs[0], want, "hand-written, mix({seed:#x}, {count})");
            assert_eq!(
                generated.regs[0], want,
                "generated, mix({seed:#x}, {count})"
            );
        }
    }
}

/// The other half of the pair, `outer`, is **compiled and not run**.
///
/// `crates/kernel/offloadtestprebuilt/src/outergen.rs` is checked in and is a
/// member of this crate, so the generator's output for a function with guest
/// memory, a stack-pointer writeback and a `bl` has to type-check -- which is
/// what catches an emission that names the wrong helper or the wrong arity.
///
/// It is not *executed* here because it reaches the TLB, and a test binary has
/// neither a mapped guest nor a dispatch loop for the call to fall back into.
/// What covers that is `tests/offload/prebuilt/run.sh`, which runs the
/// hand-written `callbench::outer` against threaded execution and requires the
/// results to be identical -- and the two files were compared by reading them
/// when the generator was ported on 2026-09-09.
///
/// Saying so rather than writing a test that stands up a fake TLB: a stub whose
/// behaviour nobody has checked would make this pass without establishing
/// anything, which is the shape `CLAUDE.md` opens with.
#[test]
fn the_generated_outer_compiles() {
    // Naming it is what keeps the module from being dead code, which is the
    // whole of the check -- and it has to be through the shape the registry
    // takes, so a generated body with the wrong signature fails here.
    //
    // `SpecFn`, not the signature written out again. It *was* written out here,
    // as `unsafe extern "C" fn(*mut Cpu, *mut c_void)`, which made this a
    // fourth rendering of one type -- and it is the rendering that decides
    // whether "the shape the registry takes" means anything, because a test
    // that spells the shape itself agrees with itself. Merging the registry's
    // alias with the fixture's on 2026-09-12 is what found it: this line
    // stopped compiling.
    let f: offloadtestprebuilt::SpecFn = offloadtestprebuilt::outergen::spec;
    assert_ne!(
        f as *const (),
        offloadtestprebuilt::mixgen::spec as *const (),
        "two distinct generated bodies"
    );
}
