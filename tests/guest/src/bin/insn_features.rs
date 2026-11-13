//! The instructions of the CPU features beyond ARMv8.0 (LRCPC, JSCVT, DotProd,
//! RDM, FCMA, FlagM, FRINTTS, I8MM, BF16, DIT, DCPOP), one hash per group.
//!
//! Every expected value is a hash of the whole register state (and, for the
//! memory groups, the buffer) after one instruction, folded over a few hundred
//! cases per group, **recorded from a real arm64 kernel**:
//!
//!   insn_features                    check against `insn_features.expect`
//!   insn_features record             print `name hash` lines (run on a real kernel)
//!   insn_features detail <group> <n>...   the states before and after case n
//!
//! A hash says only that a case differs; `detail` on both sides finds which
//! lane. A group whose expectation is missing fails: a new group is recorded
//! before it is trusted.
//!
//! The states are built to reach the edges: NaNs of both kinds, infinities,
//! denormals, saturation boundaries, all four FPCR rounding modes, FZ and DN,
//! and a non-zero starting FPSR so that the sticky flags are observed to stay
//! set.

use guest_tests::insn::{State, run, setup};
use guest_tests::{Harness, check};

const EXPECT: &str = include_str!("insn_features.expect");

/// Where the memory groups' buffer is: three pages, so a cross-page access can
/// land on the seam.
const BUF: u64 = 0x3200_0000;
const BUF_LEN: usize = 0x3000;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len() as u64) as usize]
    }
    fn reg(&mut self) -> u32 {
        self.below(32) as u32
    }
    /// Rd, Rn, Rm, with the overlaps an implementation gets wrong.
    fn regs3(&mut self) -> (u32, u32, u32) {
        let (mut d, mut n, mut m) = (self.reg(), self.reg(), self.reg());
        match self.below(8) {
            0 => d = n,
            1 => d = m,
            2 => n = m,
            3 => {
                d = n;
                m = n;
            }
            _ => {}
        }
        (d, n, m)
    }
}

/// What the vector registers hold: the lane values that sit on the edges of the
/// element type under test.
#[derive(Clone, Copy)]
enum Kind {
    /// Bytes: the extremes and random, for the integer dot products.
    Bytes,
    /// 16-bit lanes at the saturation boundaries.
    Half,
    /// 32-bit lanes at the saturation boundaries.
    Word,
    F32,
    F64,
    Bf16,
    /// Half-precision lanes: the edges and random exponents.
    F16,
    /// A mix: any of the above per register.
    Any,
}

const F32_EDGES: [u32; 20] = [
    0, 0x8000_0000, 0x3f80_0000, 0xbf80_0000, 0x7f80_0000, 0xff80_0000, 0x7fc0_0000, 0xffc0_0000,
    0x7f80_0001, 0xff80_0001, 0x0000_0001, 0x807f_ffff, 0x007f_ffff, 0x7f7f_ffff, 0xff7f_ffff,
    0x4b00_0000, 0x0080_0000, 0x3f00_0000, 0x4f00_0000, 0xcf00_0000,
];
const F64_EDGES: [u64; 20] = [
    0, 0x8000_0000_0000_0000, 0x3ff0_0000_0000_0000, 0xbff0_0000_0000_0000, 0x7ff0_0000_0000_0000,
    0xfff0_0000_0000_0000, 0x7ff8_0000_0000_0000, 0xfff8_0000_0000_0000, 0x7ff0_0000_0000_0001,
    0x0000_0000_0000_0001, 0x000f_ffff_ffff_ffff, 0x7fef_ffff_ffff_ffff, 0x4330_0000_0000_0000,
    0x41e0_0000_0000_0000, 0xc1e0_0000_0000_0000, 0x41df_ffff_ffc0_0000, 0x43e0_0000_0000_0000,
    0xc3e0_0000_0000_0000, 0x3fe0_0000_0000_0000, 0x0010_0000_0000_0000,
];
const F16_EDGES: [u16; 26] = [
    0, 0x8000, 0x3c00, 0xbc00, 0x7c00, 0xfc00, 0x7e00, 0xfe00, 0x7c01, 0xfd00, 0x0001, 0x8001, 0x03ff,
    0x83ff, 0x0400, 0x7bff, 0xfbff, 0x5800, 0x3555, 0x4000, 0x3800, 0x7fff, 0x6400, 0x5bff, 0x4400, 0x0200,
];
const BF16_EDGES: [u16; 14] = [
    0, 0x8000, 0x3f80, 0xbf80, 0x7f80, 0xff80, 0x7fc0, 0x7f81, 0x0001, 0x007f, 0x7f7f, 0x0080,
    0x8080, 0x4000,
];

fn f32_lane(r: &mut Rng) -> u32 {
    match r.below(5) {
        0 | 1 => r.pick(&F32_EDGES),
        // A whole number or a half up to 2^63: where a round-to-integer that
        // checks its range changes behaviour.
        4 => {
            let i = (r.next() as i64) >> (1 + r.below(63));
            let f = i as f32 + if r.below(3) == 0 { 0.5 } else { 0.0 };
            f.to_bits()
        }
        // A normal with a modest exponent, so sums and products neither
        // overflow nor vanish every time.
        2 => ((r.next() as u32) & 0x807f_ffff) | ((100 + r.below(50) as u32) << 23),
        _ => r.next() as u32,
    }
}

fn f64_lane(r: &mut Rng) -> u64 {
    match r.below(5) {
        0 | 1 => r.pick(&F64_EDGES),
        2 => (r.next() & 0x800f_ffff_ffff_ffff) | ((1000 + r.below(100)) << 52),
        // A whole number, or a half, of any magnitude up to 2^63: the values
        // where a float-to-integer conversion changes behaviour.
        3 => {
            let i = (r.next() as i64) >> (1 + r.below(63));
            let f = i as f64 + if r.below(3) == 0 { 0.5 } else { 0.0 };
            f.to_bits()
        }
        _ => r.next(),
    }
}

fn fill(r: &mut Rng, kind: Kind) -> [u64; 2] {
    let kind = match kind {
        Kind::Any => *[Kind::Bytes, Kind::Half, Kind::Word, Kind::F32, Kind::F64, Kind::Bf16, Kind::F16]
            .get(r.below(7) as usize)
            .unwrap(),
        k => k,
    };
    // One time in eight, plain random bits.
    if r.below(8) == 0 {
        return [r.next(), r.next()];
    }
    let mut out = [0u64; 2];
    for lane in &mut out {
        *lane = match kind {
            Kind::Bytes => {
                let mut v = 0u64;
                for i in 0..8 {
                    let b = match r.below(4) {
                        0 => r.pick(&[0u64, 1, 0x7f, 0x80, 0xff, 0xfe, 0x81]),
                        _ => r.next() & 0xff,
                    };
                    v |= b << (8 * i);
                }
                v
            }
            Kind::Half => {
                let mut v = 0u64;
                for i in 0..4 {
                    let h = match r.below(3) {
                        0 => r.pick(&[0u64, 1, 0x7fff, 0x8000, 0x8001, 0xffff, 0x4000, 0xc000, 0x2000]),
                        _ => r.next() & 0xffff,
                    };
                    v |= h << (16 * i);
                }
                v
            }
            Kind::Word => {
                let mut v = 0u64;
                for i in 0..2 {
                    let w = match r.below(3) {
                        0 => r.pick(&[0u64, 1, 0x7fff_ffff, 0x8000_0000, 0x8000_0001, 0xffff_ffff, 0x4000_0000, 0xc000_0000]),
                        _ => r.next() & 0xffff_ffff,
                    };
                    v |= w << (32 * i);
                }
                v
            }
            Kind::F32 => f32_lane(r) as u64 | (f32_lane(r) as u64) << 32,
            Kind::F64 => f64_lane(r),
            Kind::Bf16 => {
                let mut v = 0u64;
                for i in 0..4 {
                    let h = match r.below(3) {
                        0 => r.pick(&BF16_EDGES) as u64,
                        1 => (f32_lane(r) >> 16) as u64,
                        _ => r.next() & 0xffff,
                    };
                    v |= h << (16 * i);
                }
                v
            }
            Kind::F16 => {
                let mut v = 0u64;
                for i in 0..4 {
                    let h = match r.below(4) {
                        0 | 1 => r.pick(&F16_EDGES) as u64,
                        // A normal with a modest exponent, so arithmetic neither
                        // overflows nor vanishes every time.
                        2 => ((r.next() & 0x83ff) | (8 + r.below(14)) << 10) & 0xffff,
                        _ => r.next() & 0xffff,
                    };
                    v |= h << (16 * i);
                }
                v
            }
            Kind::Any => unreachable!(),
        };
    }
    out
}

fn int_value(r: &mut Rng) -> u64 {
    match r.below(4) {
        0 => r.pick(&[0u64, 1, u64::MAX, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0xffff_ffff, 0x8000_0000]),
        1 => r.below(256),
        2 => r.next() & 0xffff_ffff,
        _ => r.next(),
    }
}

/// FPCR values: the rounding modes, FZ, DN and AHP, mostly the default.
const FPCRS: [u64; 16] = [
    0, 0, 0, 1 << 22, 2 << 22, 3 << 22, 1 << 24, 1 << 25, 1 << 24 | 1 << 25, 3 << 22 | 1 << 24 | 1 << 25,
    // FZ16, with the rounding modes and DN.
    1 << 19, 1 << 19, 1 << 19 | 1 << 22, 1 << 19 | 2 << 22, 1 << 19 | 3 << 22, 1 << 19 | 1 << 25,
];

fn fresh_state(r: &mut Rng, kind: Kind, fp: bool) -> State {
    let mut st = State::zeroed();
    for x in &mut st.x {
        *x = int_value(r);
    }
    st.nzcv = r.below(16) << 28;
    for q in &mut st.q {
        *q = fill(r, kind);
    }
    if fp {
        st.fpcr = r.pick(&FPCRS);
    }
    // Sticky flags: the six exception bits and QC. Mostly clear.
    st.fpsr = if r.below(4) == 0 { r.next() & (0x9f | 1 << 27) } else { 0 };
    st
}

struct Group {
    name: &'static str,
    kind: Kind,
    /// Vary FPCR.
    fp: bool,
    /// Give the instruction a buffer: `x[rn]` (bits 9:5) is set so that the
    /// access lands in it. The function answers the instruction's offset from
    /// Rn, its size in bytes, and whether it must be naturally aligned.
    ///
    /// The access never crosses a 16-byte granule, because an ordered access
    /// that does raises SIGBUS on hardware with FEAT_LSE2 and the process dies.
    mem: Option<fn(u32) -> (i64, u64, bool)>,
    /// Put the case number's eight consecutive halfwords in Vn (register 1):
    /// with 8192 cases every one of the 65536 half-precision values is an
    /// operand once.
    sweep: bool,
    cases: u32,
    gen_insn: Box<dyn Fn(&mut Rng) -> u32>,
}

fn group(name: &'static str, kind: Kind, cases: u32, f: impl Fn(&mut Rng) -> u32 + 'static) -> Group {
    Group { name, kind, fp: false, mem: None, sweep: false, cases, gen_insn: Box::new(f) }
}
impl Group {
    fn fp(mut self) -> Group {
        self.fp = true;
        self
    }
    fn sweep(mut self) -> Group {
        self.sweep = true;
        self
    }
    fn mem(mut self, access: fn(u32) -> (i64, u64, bool)) -> Group {
        self.mem = Some(access);
        self
    }
}

fn fnv(h: &mut u64, v: u64) {
    for b in v.to_le_bytes() {
        *h ^= b as u64;
        *h = h.wrapping_mul(0x100_0000_01b3);
    }
}

/// The hash of one case's outcome.
fn hash_case(h: &mut u64, st: &State, ill: bool, mem: bool) {
    st.x.iter().for_each(|&v| fnv(h, v));
    fnv(h, st.nzcv);
    st.q.iter().for_each(|q| {
        fnv(h, q[0]);
        fnv(h, q[1]);
    });
    fnv(h, st.fpsr);
    fnv(h, ill as u64);
    if mem {
        let b = unsafe { std::slice::from_raw_parts(BUF as *const u8, BUF_LEN) };
        b.chunks_exact(8).for_each(|c| fnv(h, u64::from_le_bytes(c.try_into().unwrap())));
    }
}

/// One case of a group: the instruction and the state it runs on. The buffer is
/// filled and `x[rn]` set here, so `detail` sees the same.
fn make_case(g: &Group, r: &mut Rng, index: u32) -> (u32, State) {
    let insn = (g.gen_insn)(r);
    let mut st = fresh_state(r, g.kind, g.fp);
    if g.sweep {
        let base = (index % 8192) as u64 * 8;
        let h = |k: u64| (base + k) & 0xffff;
        st.q[1] = [h(0) | h(1) << 16 | h(2) << 32 | h(3) << 48, h(4) | h(5) << 16 | h(6) << 32 | h(7) << 48];
        // The second pass over the values runs in another FPCR mode.
        st.fpcr = if index >= 8192 { (1 << 19) | 1 << 22 | 1 << 25 } else { 0 };
    }
    if let Some(access) = g.mem {
        let rn = ((insn >> 5) & 31) as usize;
        let (offset, size, aligned) = access(insn);
        // Near the seam between the first two pages a quarter of the time.
        let mut a = match r.below(4) {
            0 => 0x1000 - 16 + r.below(32),
            _ => 0x800 + r.below(0x100),
        };
        if aligned {
            a &= !(size - 1);
        } else if (a & 15) + size > 16 {
            a = (a & !15) + 16 - size;
        }
        if rn < 31 {
            st.x[rn] = (BUF + a).wrapping_sub(offset as u64);
        }
        let buf = unsafe { std::slice::from_raw_parts_mut(BUF as *mut u8, BUF_LEN) };
        for c in buf.chunks_exact_mut(8) {
            c.copy_from_slice(&r.next().to_le_bytes());
        }
    }
    (insn, st)
}

fn seed_of(name: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    name.bytes().for_each(|b| fnv(&mut h, b as u64));
    h | 1
}

fn run_group(g: &Group) -> u64 {
    let mut r = Rng(seed_of(g.name));
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for index in 0..g.cases {
        let (insn, st) = make_case(g, &mut r, index);
        let (after, ill) = unsafe { run(insn, &st) };
        hash_case(&mut h, &after, ill, g.mem.is_some());
    }
    h
}

fn dump(label: &str, before: &State, st: &State, all: bool) {
    println!("  {label}:");
    for n in 0..31 {
        if all || st.x[n] != before.x[n] {
            println!("    x{n}={:#018x}", st.x[n]);
        }
    }
    println!("    nzcv={:#x} fpsr={:#x} fpcr={:#x}", st.nzcv, st.fpsr, st.fpcr);
    for n in 0..32 {
        if all || st.q[n] != before.q[n] {
            println!("    q{n}={:016x}{:016x}", st.q[n][1], st.q[n][0]);
        }
    }
}

fn detail(g: &Group, want: &[u32]) {
    let mut r = Rng(seed_of(g.name));
    for i in 0..g.cases {
        let (insn, st) = make_case(g, &mut r, i);
        if want.is_empty() || want.contains(&i) {
            println!("case {i} insn {insn:08x} fpcr={:#x}", st.fpcr);
            dump("before", &st, &st, true);
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let (after, ill) = unsafe { run(insn, &st) };
            println!("  ill={ill}");
            dump("after (changed)", &st, &after, false);
        }
    }
}

// ---------------------------------------------------------------------------
// The groups, by feature.
// ---------------------------------------------------------------------------

fn groups() -> Vec<Group> {
    let mut v = Vec::new();
    lrcpc(&mut v);
    jscvt(&mut v);
    dotprod(&mut v);
    rdm(&mut v);
    fcma(&mut v);
    flagm(&mut v);
    frintts(&mut v);
    i8mm(&mut v);
    bf16(&mut v);
    fp16(&mut v);
    v.push(group("sb", Kind::Any, 20, |_| 0xd503_30ff));
    v
}

/// The imm9 of an unscaled-offset access, sign-extended.
fn simm9(insn: u32) -> i64 {
    ((insn as i64 >> 12) & 0x1ff) << 55 >> 55
}

/// LRCPC and LRCPC2: `ldapr`, `ldapur`, `stlur`, every size and sign-extension.
fn lrcpc(v: &mut Vec<Group>) {
    // Rn is never 31: the stub runs on SP.
    let rn = |r: &mut Rng| r.below(31) as u32;
    v.push(
        group("lrcpc-ldapr", Kind::Any, 400, move |r| {
            let size = r.below(4) as u32;
            0x38bf_c000 | size << 30 | rn(r) << 5 | r.reg()
        })
        .mem(|insn| (0, 1 << (insn >> 30), true)),
    );
    // LDAPUR/STLUR: (size, opc) pairs that are allocated.
    const PAIRS: [(u32, u32); 12] = [
        (0, 0), (0, 1), (0, 2), (0, 3), (1, 0), (1, 1), (1, 2), (1, 3), (2, 0), (2, 1), (2, 2), (3, 0),
    ];
    v.push(
        group("lrcpc-ldapur-stlur", Kind::Any, 1200, move |r| {
            let (size, opc) = if r.below(12) == 0 { (3, 1) } else { r.pick(&PAIRS) };
            let imm9 = r.below(512) as u32;
            0x1900_0000 | size << 30 | opc << 22 | imm9 << 12 | rn(r) << 5 | r.reg()
        })
        .mem(|insn| (simm9(insn), 1 << (insn >> 30), false)),
    );
    // The encodings next to them that are not allocated.
    v.push(group("lrcpc-unallocated", Kind::Any, 200, move |r| {
        let (size, opc) = r.pick(&[(2u32, 3u32), (3, 2), (3, 3)]);
        0x1900_0000 | size << 30 | opc << 22 | (r.below(512) as u32) << 12 | rn(r) << 5 | r.reg()
    }));
}

/// JSCVT: `fjcvtzs Wd, Dn`, under every rounding mode, FZ and DN.
fn jscvt(v: &mut Vec<Group>) {
    v.push(
        group("jscvt-fjcvtzs", Kind::F64, 2000, |r| {
            let (d, n, _) = r.regs3();
            0x1e7e_0000 | n << 5 | d
        })
        .fp(),
    );
    // The 64-bit form and the other type are not allocated.
    v.push(group("jscvt-unallocated", Kind::F64, 100, |r| {
        let (d, n, _) = r.regs3();
        r.pick(&[0x9e7e_0000u32, 0x1e3e_0000, 0x1e7f_0000, 0x1e7e_8000]) | n << 5 | d
    }));
}

/// DotProd: `sdot`/`udot`, vector and by element, both vector lengths.
fn dotprod(v: &mut Vec<Group>) {
    for (name, u) in [("dotprod-sdot-vec", 0u32), ("dotprod-udot-vec", 1)] {
        v.push(group(name, Kind::Any, 600, move |r| {
            let (d, n, m) = r.regs3();
            0x0e80_9400 | (r.below(2) as u32) << 30 | u << 29 | m << 16 | n << 5 | d
        }));
    }
    for (name, u) in [("dotprod-sdot-elem", 0u32), ("dotprod-udot-elem", 1)] {
        v.push(group(name, Kind::Any, 600, move |r| {
            let (d, n, m) = r.regs3();
            let (l, h) = (r.below(2) as u32, r.below(2) as u32);
            0x0f80_e000 | (r.below(2) as u32) << 30 | u << 29 | l << 21 | h << 11 | m << 16 | n << 5 | d
        }));
    }
    // The size fields next to it name other instructions (MLA, say) or nothing.
    v.push(group("dotprod-neighbours", Kind::Any, 200, |r| {
        let (d, n, m) = r.regs3();
        let size = r.pick(&[0u32, 1, 3]);
        r.pick(&[0x0e00_9400u32, 0x0f00_e000]) | size << 22 | (r.below(2) as u32) << 30
            | (r.below(2) as u32) << 29 | m << 16 | n << 5 | d
    }));
}

/// RDM: `sqrdmlah` and `sqrdmlsh`, vector, scalar and by element, halfwords and
/// words, with operands at the saturation boundaries (-2^15 * -2^15 is the one
/// product that overflows the doubled form).
fn rdm(v: &mut Vec<Group>) {
    for (name, kind, sub) in [
        ("rdm-sqrdmlah-vec-h", Kind::Half, 0u32),
        ("rdm-sqrdmlsh-vec-h", Kind::Half, 1),
        ("rdm-sqrdmlah-vec-s", Kind::Word, 0),
        ("rdm-sqrdmlsh-vec-s", Kind::Word, 1),
    ] {
        let size = if name.ends_with('h') { 1u32 } else { 2 };
        v.push(group(name, kind, 600, move |r| {
            let (d, n, m) = r.regs3();
            0x2e00_8400 | (r.below(2) as u32) << 30 | size << 22 | sub << 11 | m << 16 | n << 5 | d
        }));
    }
    for (name, kind, sub) in [
        ("rdm-sqrdmlah-scalar-h", Kind::Half, 0u32),
        ("rdm-sqrdmlsh-scalar-h", Kind::Half, 1),
        ("rdm-sqrdmlah-scalar-s", Kind::Word, 0),
        ("rdm-sqrdmlsh-scalar-s", Kind::Word, 1),
    ] {
        let size = if name.ends_with('h') { 1u32 } else { 2 };
        v.push(group(name, kind, 300, move |r| {
            let (d, n, m) = r.regs3();
            0x7e00_8400 | size << 22 | sub << 11 | m << 16 | n << 5 | d
        }));
    }
    for (name, kind, sub, scalar) in [
        ("rdm-sqrdmlah-elem-h", Kind::Half, 0u32, 0u32),
        ("rdm-sqrdmlsh-elem-h", Kind::Half, 1, 0),
        ("rdm-sqrdmlah-elem-s", Kind::Word, 0, 0),
        ("rdm-sqrdmlsh-elem-s", Kind::Word, 1, 0),
        ("rdm-sqrdmlah-scalar-elem-h", Kind::Half, 0, 1),
        ("rdm-sqrdmlsh-scalar-elem-s", Kind::Word, 1, 1),
    ] {
        let size = if name.ends_with('h') { 1u32 } else { 2 };
        v.push(group(name, kind, 600, move |r| {
            let (d, n, m) = r.regs3();
            let (l, h) = (r.below(2) as u32, r.below(2) as u32);
            // A half's Rm is four bits and bit 20 is M, part of the index.
            let base = if scalar == 1 { 0x7f00_d000u32 } else { 0x2f00_d000 | (r.below(2) as u32) << 30 };
            base | size << 22 | sub << 13 | l << 21 | h << 11 | m << 16 | n << 5 | d
        }));
    }
    // The sizes that name nothing, in all three forms.
    v.push(group("rdm-unallocated", Kind::Any, 200, |r| {
        let (d, n, m) = r.regs3();
        let size = r.pick(&[0u32, 3]);
        r.pick(&[0x2e00_8400u32, 0x2e00_8c00, 0x7e00_8400, 0x2f00_d000, 0x2f00_f000, 0x7f00_d000])
            | size << 22 | m << 16 | n << 5 | d
    }));
}

/// FCMA: `fcmla` (all four rotations, vector and by element) and `fcadd`, single
/// and double precision, under every rounding mode, FZ and DN. The half-precision
/// forms are FP16's.
fn fcma(v: &mut Vec<Group>) {
    for (name, kind, size) in [("fcma-fcmla-vec-s", Kind::F32, 2u32), ("fcma-fcmla-vec-d", Kind::F64, 3)] {
        v.push(
            group(name, kind, 800, move |r| {
                let (d, n, m) = r.regs3();
                let q = if size == 3 { 1 } else { r.below(2) as u32 };
                0x2e00_c400 | q << 30 | size << 22 | (r.below(4) as u32) << 11 | m << 16 | n << 5 | d
            })
            .fp(),
        );
    }
    for (name, kind, size) in [("fcma-fcadd-s", Kind::F32, 2u32), ("fcma-fcadd-d", Kind::F64, 3)] {
        v.push(
            group(name, kind, 600, move |r| {
                let (d, n, m) = r.regs3();
                let q = if size == 3 { 1 } else { r.below(2) as u32 };
                0x2e00_e400 | q << 30 | size << 22 | (r.below(2) as u32) << 12 | m << 16 | n << 5 | d
            })
            .fp(),
        );
    }
    v.push(
        group("fcma-fcmla-elem-s", Kind::F32, 800, |r| {
            let (d, n, m) = r.regs3();
            0x2f80_1000 | 1 << 30 | (r.below(4) as u32) << 13 | (r.below(2) as u32) << 11 | m << 16 | n << 5 | d
        })
        .fp(),
    );
    // Reserved: `.2s` by element, L=1 by element, the .1d vector form, size 0.
    v.push(group("fcma-unallocated", Kind::F32, 200, |r| {
        let (d, n, m) = r.regs3();
        let rot = r.below(4) as u32;
        match r.below(5) {
            0 => 0x2f80_1000 | rot << 13 | m << 16 | n << 5 | d,
            1 => 0x2f80_1000 | 1 << 30 | rot << 13 | 1 << 21 | m << 16 | n << 5 | d,
            2 => 0x2ec0_c400 | rot << 11 | m << 16 | n << 5 | d,
            3 => 0x6e00_c400 | rot << 11 | m << 16 | n << 5 | d,
            _ => 0x6e00_e400 | (rot & 1) << 12 | m << 16 | n << 5 | d,
        }
    }));
}

/// FlagM and FlagM2: `cfinv`, `axflag`, `xaflag`, `setf8`, `setf16`, `rmif`.
fn flagm(v: &mut Vec<Group>) {
    // NZCV takes all sixteen values in 40 cases with high probability.
    for (name, insn) in [
        ("flagm-cfinv", 0xd500_401fu32),
        ("flagm-xaflag", 0xd500_403f),
        ("flagm-axflag", 0xd500_405f),
    ] {
        v.push(group(name, Kind::Any, 64, move |_| insn));
    }
    v.push(group("flagm-setf", Kind::Any, 400, |r| {
        0x3a00_080d | (r.below(2) as u32) << 14 | r.reg() << 5
    }));
    v.push(group("flagm-rmif", Kind::Any, 600, |r| {
        0xba00_0400 | (r.below(64) as u32) << 15 | r.reg() << 5 | r.below(16) as u32
    }));
    // The neighbours: RMIF with bit 4 set, SETF with other opcode bits, and the
    // MSR-immediate encodings around CFINV.
    v.push(group("flagm-neighbours", Kind::Any, 200, |r| {
        match r.below(6) {
            0 => 0xba00_0410 | (r.below(64) as u32) << 15 | r.reg() << 5 | r.below(16) as u32,
            1 => 0x3a00_081d | r.reg() << 5,
            2 => 0x3a00_0c0d | r.reg() << 5,
            3 => 0xd500_407f,
            4 => 0xd500_401e,
            _ => 0xd500_409f,
        }
    }));
}

/// FRINTTS: `frint32z/x`, `frint64z/x`, scalar and vector, all rounding modes.
fn frintts(v: &mut Vec<Group>) {
    for (name, op) in [
        ("frint-32z", 0u32),
        ("frint-32x", 1),
        ("frint-64z", 2),
        ("frint-64x", 3),
    ] {
        // Scalar, single and double.
        v.push(
            group(Box::leak(format!("{name}-scalar").into_boxed_str()), Kind::Any, 500, move |r| {
                let (d, n, _) = r.regs3();
                0x1e28_4000 | (r.below(2) as u32) << 22 | op << 15 | n << 5 | d
            })
            .fp(),
        );
        // Vector: .2s, .4s, .2d. U picks X, bit 12 picks 64-bit.
        v.push(
            group(Box::leak(format!("{name}-vec").into_boxed_str()), Kind::Any, 700, move |r| {
                let (d, n, _) = r.regs3();
                let dbl = r.below(2) as u32;
                let q = if dbl == 1 { 1 } else { r.below(2) as u32 };
                0x0e21_e800 | q << 30 | (op & 1) << 29 | dbl << 22 | (op >> 1) << 12 | n << 5 | d
            })
            .fp(),
        );
    }
    // Reserved: the vector .1d form, and the half-precision scalar type.
    v.push(group("frint-unallocated", Kind::Any, 100, |r| {
        let (d, n, _) = r.regs3();
        r.pick(&[0x0e61_e800u32, 0x0e61_f800, 0x2e61_e800, 0x1ee8_4000]) | n << 5 | d
    }));
}

/// I8MM: `usdot`, `sudot`, `smmla`, `ummla`, `usmmla`.
fn i8mm(v: &mut Vec<Group>) {
    v.push(group("i8mm-usdot-vec", Kind::Any, 600, |r| {
        let (d, n, m) = r.regs3();
        0x0e80_9c00 | (r.below(2) as u32) << 30 | m << 16 | n << 5 | d
    }));
    for (name, base) in [("i8mm-usdot-elem", 0x0f80_f000u32), ("i8mm-sudot-elem", 0x0f00_f000)] {
        v.push(group(name, Kind::Any, 600, move |r| {
            let (d, n, m) = r.regs3();
            base | (r.below(2) as u32) << 30 | (r.below(2) as u32) << 21 | (r.below(2) as u32) << 11
                | m << 16 | n << 5 | d
        }));
    }
    for (name, base) in [("i8mm-smmla", 0x4e80_a400u32), ("i8mm-ummla", 0x6e80_a400), ("i8mm-usmmla", 0x4e80_ac00)] {
        v.push(group(name, Kind::Any, 600, move |r| {
            let (d, n, m) = r.regs3();
            base | m << 16 | n << 5 | d
        }));
    }
    // Reserved: the 64-bit MMLA forms and the sizes around USDOT. (Size 01 by
    // element is BFDOT, which is BF16's.)
    v.push(group("i8mm-neighbours", Kind::Any, 200, |r| {
        let (d, n, m) = r.regs3();
        r.pick(&[0x0e80_a400u32, 0x2e80_a400, 0x0e80_ac00, 0x0e00_9c00, 0x0ec0_9c00])
            | m << 16 | n << 5 | d
    }));
}

/// BF16: `bfdot`, `bfmmla`, `bfmlalb/t`, `bfcvt`, `bfcvtn/n2`, with bfloat16 and
/// single-precision edge values in every register and every FPCR mode.
fn bf16(v: &mut Vec<Group>) {
    v.push(
        group("bf16-bfdot-vec", Kind::Bf16, 800, |r| {
            let (d, n, m) = r.regs3();
            0x2e40_fc00 | (r.below(2) as u32) << 30 | m << 16 | n << 5 | d
        })
        .fp(),
    );
    v.push(
        group("bf16-bfdot-elem", Kind::Bf16, 800, |r| {
            let (d, n, m) = r.regs3();
            0x0f40_f000 | (r.below(2) as u32) << 30 | (r.below(2) as u32) << 21 | (r.below(2) as u32) << 11
                | m << 16 | n << 5 | d
        })
        .fp(),
    );
    v.push(
        group("bf16-bfmmla", Kind::Bf16, 800, |r| {
            let (d, n, m) = r.regs3();
            0x6e40_ec00 | m << 16 | n << 5 | d
        })
        .fp(),
    );
    for (name, q) in [("bf16-bfmlalb-vec", 0u32), ("bf16-bfmlalt-vec", 1)] {
        v.push(
            group(name, Kind::Bf16, 600, move |r| {
                let (d, n, m) = r.regs3();
                0x2ec0_fc00 | q << 30 | m << 16 | n << 5 | d
            })
            .fp(),
        );
    }
    for (name, q) in [("bf16-bfmlalb-elem", 0u32), ("bf16-bfmlalt-elem", 1)] {
        v.push(
            group(name, Kind::Bf16, 600, move |r| {
                let (d, n, m) = r.regs3();
                0x0fc0_f000 | q << 30 | (r.below(2) as u32) << 21 | (r.below(2) as u32) << 11
                    | (m & 0x1f) << 16 | n << 5 | d
            })
            .fp(),
        );
    }
    v.push(
        group("bf16-bfcvt", Kind::Any, 600, |r| {
            let (d, n, _) = r.regs3();
            0x1e63_4000 | n << 5 | d
        })
        .fp(),
    );
    v.push(
        group("bf16-bfcvtn", Kind::Any, 800, |r| {
            let (d, n, _) = r.regs3();
            0x0ea1_6800 | (r.below(2) as u32) << 30 | n << 5 | d
        })
        .fp(),
    );
    // Reserved: BFMMLA on 64 bits, and bfcvt of the single type.
    v.push(group("bf16-neighbours", Kind::Any, 100, |r| {
        let (d, n, m) = r.regs3();
        r.pick(&[0x2e40_ec00u32, 0x1e23_4000]) | m << 16 | n << 5 | d
    }));
}

/// FP16: the half-precision scalar and AdvSIMD instructions, group by group of
/// encoding class, every FPCR mode including FZ16.
fn fp16(v: &mut Vec<Group>) {
    let regs = |r: &mut Rng| r.regs3();
    // Scalar data processing.
    v.push(group("fp16-s-1src", Kind::F16, 1200, move |r| {
        let (d, n, _) = regs(r);
        let op = r.pick(&[0u32, 1, 2, 3, 8, 9, 10, 11, 12, 14, 15]);
        0x1ee0_4000 | op << 15 | n << 5 | d
    }).fp());
    v.push(group("fp16-s-2src", Kind::F16, 1600, move |r| {
        let (d, n, m) = regs(r);
        0x1ee0_0800 | m << 16 | (r.below(9) as u32) << 12 | n << 5 | d
    }).fp());
    v.push(group("fp16-s-3src", Kind::F16, 1200, move |r| {
        let (d, n, m) = regs(r);
        0x1fc0_0000 | (r.below(2) as u32) << 21 | m << 16 | (r.below(2) as u32) << 15 | r.reg() << 10 | n << 5 | d
    }).fp());
    v.push(group("fp16-s-cmp", Kind::F16, 800, move |r| {
        let (_, n, m) = regs(r);
        let z = r.below(2) as u32;
        0x1ee0_2000 | if z == 1 { 0 } else { m << 16 } | n << 5 | (r.below(2) as u32) << 4 | z << 3
    }).fp());
    v.push(group("fp16-s-ccmp", Kind::F16, 800, move |r| {
        let (_, n, m) = regs(r);
        0x1ee0_0400 | m << 16 | (r.below(16) as u32) << 12 | n << 5 | (r.below(2) as u32) << 4 | r.below(16) as u32
    }).fp());
    v.push(group("fp16-s-csel", Kind::F16, 600, move |r| {
        let (d, n, m) = regs(r);
        0x1ee0_0c00 | m << 16 | (r.below(16) as u32) << 12 | n << 5 | d
    }).fp());
    v.push(group("fp16-s-fmov-imm", Kind::F16, 300, move |r| {
        0x1ee0_1000 | (r.below(256) as u32) << 13 | r.reg()
    }));
    // Float <-> integer: sf, rmode, opcode all vary, and the fixed-point forms.
    v.push(group("fp16-s-int", Kind::Any, 2400, move |r| {
        let (d, n, _) = regs(r);
        0x1ee0_0000 | (r.below(2) as u32) << 31 | (r.below(4) as u32) << 19 | (r.below(8) as u32) << 16 | n << 5 | d
    }).fp());
    v.push(group("fp16-s-fixed", Kind::Any, 1600, move |r| {
        let (d, n, _) = regs(r);
        let sf = r.below(2) as u32;
        let scale = if sf == 1 { r.below(64) as u32 } else { 32 + r.below(32) as u32 };
        let (rmode, opcode) = r.pick(&[(0u32, 2u32), (0, 3), (3, 0), (3, 1)]);
        0x1ec0_0000 | sf << 31 | rmode << 19 | opcode << 16 | scale << 10 | n << 5 | d
    }).fp());
    // AdvSIMD three same, vector and scalar.
    const THREE: [(u32, u32, u32); 24] = [
        (0, 0, 0), (0, 0, 1), (0, 0, 2), (0, 0, 3), (0, 0, 4), (0, 0, 6), (0, 0, 7), (0, 1, 0), (0, 1, 1),
        (0, 1, 2), (0, 1, 6), (0, 1, 7), (1, 0, 0), (1, 0, 2), (1, 0, 3), (1, 0, 4), (1, 0, 5), (1, 0, 6),
        (1, 0, 7), (1, 1, 0), (1, 1, 2), (1, 1, 4), (1, 1, 5), (1, 1, 6),
    ];
    v.push(group("fp16-v-3same", Kind::F16, 4000, move |r| {
        let (d, n, m) = regs(r);
        let (u, a, op) = r.pick(&THREE);
        0x0e40_0400 | (r.below(2) as u32) << 30 | u << 29 | a << 23 | m << 16 | op << 11 | n << 5 | d
    }).fp());
    const THREE_S: [(u32, u32, u32); 9] = [
        (0, 0, 3), (0, 0, 4), (0, 0, 7), (0, 1, 7), (1, 0, 4), (1, 0, 5), (1, 1, 2), (1, 1, 4), (1, 1, 5),
    ];
    v.push(group("fp16-s-3same", Kind::F16, 1600, move |r| {
        let (d, n, m) = regs(r);
        let (u, a, op) = r.pick(&THREE_S);
        0x5e40_0400 | u << 29 | a << 23 | m << 16 | op << 11 | n << 5 | d
    }).fp());
    // Two-register miscellaneous.
    const MISC: [(u32, u32, u32); 30] = [
        (0, 0, 0b11000), (0, 0, 0b11001), (0, 0, 0b11010), (0, 0, 0b11011), (0, 0, 0b11100), (0, 0, 0b11101),
        (0, 1, 0b01100), (0, 1, 0b01101), (0, 1, 0b01110), (0, 1, 0b01111), (0, 1, 0b11000), (0, 1, 0b11001),
        (0, 1, 0b11010), (0, 1, 0b11011), (0, 1, 0b11101), (1, 0, 0b11000), (1, 0, 0b11001), (1, 0, 0b11010),
        (1, 0, 0b11011), (1, 0, 0b11100), (1, 0, 0b11101), (1, 1, 0b01100), (1, 1, 0b01101), (1, 1, 0b01111),
        (1, 1, 0b11001), (1, 1, 0b11010), (1, 1, 0b11011), (1, 1, 0b11101), (1, 1, 0b11111), (0, 1, 0b11111),
    ];
    v.push(group("fp16-v-misc", Kind::F16, 5000, move |r| {
        let (d, n, _) = regs(r);
        let (u, a, op) = loop {
            let c = r.pick(&MISC);
            // FRECPX has no vector form.
            if c != (0, 1, 0b11111) {
                break c;
            }
        };
        0x0e78_0800 | (r.below(2) as u32) << 30 | u << 29 | a << 23 | op << 12 | n << 5 | d
    }).fp());
    const MISC_S: [(u32, u32, u32); 20] = [
        (0, 0, 0b11010), (0, 0, 0b11011), (0, 0, 0b11100), (0, 0, 0b11101), (0, 1, 0b01100), (0, 1, 0b01101),
        (0, 1, 0b01110), (0, 1, 0b11010), (0, 1, 0b11011), (0, 1, 0b11101), (0, 1, 0b11111), (1, 0, 0b11010),
        (1, 0, 0b11011), (1, 0, 0b11100), (1, 0, 0b11101), (1, 1, 0b01100), (1, 1, 0b01101), (1, 1, 0b11010),
        (1, 1, 0b11011), (1, 1, 0b11101),
    ];
    v.push(group("fp16-s-misc", Kind::F16, 3000, move |r| {
        let (d, n, _) = regs(r);
        let (u, a, op) = r.pick(&MISC_S);
        0x5e78_0800 | u << 29 | a << 23 | op << 12 | n << 5 | d
    }).fp());
    // By element, vector and scalar.
    v.push(group("fp16-elem", Kind::F16, 3000, move |r| {
        let (d, n, m) = regs(r);
        let (u, op) = r.pick(&[(0u32, 1u32), (0, 5), (0, 9), (1, 9)]);
        let scalar = r.below(3) == 0;
        let base = if scalar { 0x5f00_0000 } else { 0x0f00_0000 | (r.below(2) as u32) << 30 };
        base | u << 29 | (r.below(2) as u32) << 21 | (r.below(2) as u32) << 20 | (m & 0xf) << 16 | op << 12
            | (r.below(2) as u32) << 11 | n << 5 | d
    }).fp());
    // Across lanes and scalar pairwise.
    v.push(group("fp16-across", Kind::F16, 1600, move |r| {
        let (d, n, _) = regs(r);
        let (a, op) = r.pick(&[(0u32, 0b01100u32), (1, 0b01100), (0, 0b01111), (1, 0b01111)]);
        0x0e30_0800 | (r.below(2) as u32) << 30 | a << 23 | op << 12 | n << 5 | d
    }).fp());
    v.push(group("fp16-pair-scalar", Kind::F16, 1200, move |r| {
        let (d, n, _) = regs(r);
        let (a, op) = r.pick(&[(0u32, 0b01101u32), (0, 0b01100), (1, 0b01100), (0, 0b01111), (1, 0b01111)]);
        0x5e30_0800 | a << 23 | op << 12 | n << 5 | d
    }).fp());
    // Fixed-point conversions, vector and scalar.
    v.push(group("fp16-shift-fixed", Kind::Any, 2000, move |r| {
        let (d, n, _) = regs(r);
        let (u, op) = r.pick(&[(0u32, 0b11100u32), (1, 0b11100), (0, 0b11111), (1, 0b11111)]);
        let base = if r.below(3) == 0 { 0x5f00_0400 } else { 0x0f00_0400 | (r.below(2) as u32) << 30 };
        base | u << 29 | (16 + r.below(16) as u32) << 16 | op << 11 | n << 5 | d
    }).fp());
    v.push(group("fp16-fmov-vec-imm", Kind::F16, 300, move |r| {
        0x0f00_fc00 | (r.below(2) as u32) << 30 | (r.below(8) as u32) << 16 | (r.below(32) as u32) << 5 | r.reg()
    }));
    // Complex numbers.
    v.push(group("fp16-fcmla-vec", Kind::F16, 1200, move |r| {
        let (d, n, m) = regs(r);
        0x2e40_c400 | (r.below(2) as u32) << 30 | m << 16 | (r.below(4) as u32) << 11 | n << 5 | d
    }).fp());
    v.push(group("fp16-fcadd", Kind::F16, 800, move |r| {
        let (d, n, m) = regs(r);
        0x2e40_e400 | (r.below(2) as u32) << 30 | m << 16 | (r.below(2) as u32) << 12 | n << 5 | d
    }).fp());
    v.push(group("fp16-fcmla-elem", Kind::F16, 1200, move |r| {
        let (d, n, m) = regs(r);
        0x2f40_1000 | (r.below(2) as u32) << 30 | (r.below(4) as u32) << 13 | (r.below(2) as u32) << 21
            | (r.below(2) as u32) << 11 | m << 16 | n << 5 | d
    }).fp());
    // Every half-precision value through the one-operand estimates and the
    // classifiers, in the default mode and in FZ16 + round-up + DN.
    for (name, insn) in [
        ("fp16-sweep-frecpe", 0x0ef9_d820u32),
        ("fp16-sweep-frsqrte", 0x2ef9_d820),
        ("fp16-sweep-frecpx", 0x5ef9_f820),
        ("fp16-sweep-fsqrt", 0x2ef9_f820),
        ("fp16-sweep-frinta", 0x2e79_8820),
        ("fp16-sweep-fcvtzs", 0x0ef9_b820),
        ("fp16-sweep-scvtf", 0x0e79_d820),
    ] {
        v.push(group(name, Kind::F16, 16384, move |_| insn).sweep());
    }
}

fn main() {
    unsafe {
        setup();
        let p = libc::mmap(BUF as *mut _, BUF_LEN, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED, -1, 0);
        assert!(p as u64 == BUF, "buffer mapping");
    }
    let args: Vec<String> = std::env::args().collect();
    let all = groups();
    match args.get(1).map(String::as_str) {
        Some("record") => {
            for g in &all {
                println!("{} {:016x}", g.name, run_group(g));
            }
        }
        // One line per case: index, instruction, hash of its outcome. Diff the
        // output of two machines to find the cases that differ.
        Some("dump") => {
            let g = all.iter().find(|g| g.name == args[2]).expect("group name");
            let mut r = Rng(seed_of(g.name));
            for i in 0..g.cases {
                let (insn, st) = make_case(g, &mut r, i);
                let (after, ill) = unsafe { run(insn, &st) };
                let mut h = 0xcbf2_9ce4_8422_2325u64;
                hash_case(&mut h, &after, ill, g.mem.is_some());
                println!("{i} {insn:08x} {h:016x}");
            }
        }
        Some("detail") => {
            let g = all.iter().find(|g| g.name == args[2]).expect("group name");
            let want: Vec<u32> = args[3..].iter().map(|a| a.parse().expect("case")).collect();
            detail(g, &want);
        }
        _ => {
            let mut h = Harness::new();
            for g in &all {
                h.group(g.name);
                let want = EXPECT
                    .lines()
                    .find_map(|l| l.strip_prefix(g.name).and_then(|r| r.strip_prefix(' ')))
                    .and_then(|x| u64::from_str_radix(x.trim(), 16).ok());
                let got = run_group(g);
                check!(h, want == Some(got), "{}: {:016x}, recorded {}", g.name, got,
                    want.map_or("nothing".to_string(), |w| format!("{w:016x}")));
            }
            std::process::exit(h.finish());
        }
    }
}
