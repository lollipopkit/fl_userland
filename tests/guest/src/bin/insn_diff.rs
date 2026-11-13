//! Random data-processing instructions on random state, one line per case.
//!
//! Run it here and on a real arm64 kernel and diff the output: a line that
//! differs is an instruction the emulator gets wrong. Nothing is asserted.
//!
//!   insn_diff [<cases per class> [<seed>]]    one `index insn hash` line per case
//!   insn_diff detail <seed> <index>...        full state before and after
//!   insn_diff words <seed> <n> <hex|@file>... each encoding on n random states
//!
//! Each case copies a stub into a fixed code page, patches one instruction
//! into its slot, loads x0-x30, NZCV, q0-q31, FPSR and FPCR from a state block,
//! runs the instruction, and stores them all back. Fixed addresses keep ADR,
//! ADRP and reads of SP identical on both sides. An instruction that raises
//! SIGILL is skipped by the handler and reported as `ill`.
//!
//! Only four encoding classes are generated -- data processing (immediate and
//! register) and SIMD & FP data processing -- because none of them touches
//! memory or branches; encodings that would write SP are rejected, since the
//! stub runs on SP.

use guest_tests::insn::{State, run, setup};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Values that sit on the edges integer and flag logic get wrong.
fn int_value(r: &mut Rng) -> u64 {
    const EDGES: [u64; 12] = [
        0, 1, 2, u64::MAX, u64::MAX - 1, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000,
        0xffff_ffff, 0x7fff_ffff, 0x8000_0000, 0x1_0000_0000, 0xffff_ffff_0000_0000,
    ];
    match r.below(4) {
        0 => EDGES[r.below(EDGES.len() as u64) as usize],
        1 => r.below(256),
        2 => r.next() & 0xffff_ffff,
        _ => r.next(),
    }
}

/// A 64-bit lane: a float edge in either width, or random bits.
fn fp_lane(r: &mut Rng) -> u64 {
    const D: [u64; 12] = [
        0, 0x8000_0000_0000_0000, 0x3ff0_0000_0000_0000, 0xbff0_0000_0000_0000,
        0x7ff0_0000_0000_0000, 0xfff0_0000_0000_0000, 0x7ff8_0000_0000_0000,
        0x7ff0_0000_0000_0001, 0x0000_0000_0000_0001, 0x000f_ffff_ffff_ffff,
        0x7fef_ffff_ffff_ffff, 0x4330_0000_0000_0000,
    ];
    const S: [u32; 12] = [
        0, 0x8000_0000, 0x3f80_0000, 0xbf80_0000, 0x7f80_0000, 0xff80_0000, 0x7fc0_0000,
        0x7f80_0001, 0x0000_0001, 0x007f_ffff, 0x7f7f_ffff, 0x4b00_0000,
    ];
    let s = |r: &mut Rng| S[r.below(S.len() as u64) as usize] as u64;
    match r.below(4) {
        0 => D[r.below(D.len() as u64) as usize],
        1 => s(r) | s(r) << 32,
        2 => r.next() & 0x00ff_00ff_00ff_00ff,
        _ => r.next(),
    }
}

/// One encoding of a class, or `None` for one this harness must not run.
fn encoding(r: &mut Rng, class: u64) -> Option<u32> {
    let w = r.next() as u32;
    let w = match class {
        0 => (w & !(0b111 << 26)) | (0b100 << 26),
        1 => (w & !(0b111 << 25)) | (0b101 << 25),
        2 => (w & !(0b1111 << 25)) | (0b0111 << 25),
        _ => (w & !(0b1111 << 25)) | (0b1111 << 25),
    };
    let rd = w & 31;
    let s = (w >> 29) & 1;
    if class == 0 && rd == 31 {
        match (w >> 23) & 0b111 {
            // Add/subtract immediate, with or without tags: Rd 31 is SP unless S.
            0b010 | 0b011 if s == 0 => return None,
            // Logical immediate: SP unless ANDS.
            0b100 if (w >> 29) & 0b11 != 0b11 => return None,
            _ => {}
        }
    }
    // Add/subtract, extended register: Rd 31 is SP unless S.
    if class == 1 && rd == 31 && (w >> 24) & 0b11111 == 0b01011 && (w >> 21) & 1 == 1 && s == 0 {
        return None;
    }
    // EXT with Q=0 and imm4 >= 8 is UNDEFINED, and an emulator that decodes it
    // may index an eight-entry jump table with it and spin in the gadget for
    // ever (no signal reaches a host thread there). Fixed in the emulator;
    // `INSN_DIFF_SKIP_HANG=1` skips these to run against one that still has it.
    if std::env::var_os("INSN_DIFF_SKIP_HANG").is_some()
        && w & 0xbfe0_8400 == 0x2e00_0000
        && (w >> 30) & 1 == 0
        && (w >> 14) & 1 == 1
    {
        return None;
    }
    Some(w)
}

fn fresh_state(r: &mut Rng) -> State {
    let mut st: State = unsafe { std::mem::zeroed() };
    for x in &mut st.x {
        *x = int_value(r);
    }
    st.nzcv = r.below(16) << 28;
    for q in &mut st.q {
        *q = [fp_lane(r), fp_lane(r)];
    }
    // RMode, FZ, DN; AHP and FZ16 too. Mostly the default.
    st.fpcr = if r.below(2) == 0 { 0 } else { r.next() & (0b11 << 22 | 1 << 24 | 1 << 25 | 1 << 26 | 1 << 19) };
    st
}

fn hash(st: &State, ill: bool) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |v: u64| {
        for b in v.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100_0000_01b3);
        }
    };
    st.x.iter().for_each(|&v| eat(v));
    eat(st.nzcv);
    st.q.iter().for_each(|q| { eat(q[0]); eat(q[1]); });
    eat(st.fpsr);
    eat(ill as u64);
    h
}

/// Every case of a seed, in order, so `detail` regenerates the same ones.
fn cases(seed: u64, per_class: u64) -> impl Iterator<Item = (u64, u32, State)> {
    let mut r = Rng(seed | 1);
    let mut i = 0;
    std::iter::from_fn(move || {
        if i >= 4 * per_class {
            return None;
        }
        let class = i / per_class;
        let insn = loop {
            if let Some(w) = encoding(&mut r, class) {
                break w;
            }
        };
        let st = fresh_state(&mut r);
        i += 1;
        Some((i - 1, insn, st))
    })
}

fn dump(label: &str, st: &State) {
    println!("  {label}:");
    for (n, v) in st.x.iter().enumerate() {
        print!("    x{n}={v:#018x}{}", if n % 4 == 3 { "\n" } else { "" });
    }
    println!("\n    nzcv={:#x} fpsr={:#x} fpcr={:#x}", st.nzcv, st.fpsr, st.fpcr);
    for (n, q) in st.q.iter().enumerate() {
        print!("    q{n}={:016x}{:016x}{}", q[1], q[0], if n % 2 == 1 { "\n" } else { "" });
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    unsafe { setup() };
    // `insn_diff try <hex>...`: whether each encoding executes or raises SIGILL.
    if args.get(1).map(String::as_str) == Some("try") {
        let st: State = unsafe { std::mem::zeroed() };
        for a in &args[2..] {
            let w = u32::from_str_radix(a, 16).expect("hex encoding");
            let (_, ill) = unsafe { run(w, &st) };
            println!("{a} {}", if ill { "ill" } else { "ok" });
        }
        return;
    }
    // `insn_diff words <seed> <n> <hex>...`: each encoding on `n` random
    // states, one `hex i hash` line per case, for targeting a family the random
    // classes reach too rarely. (An argument is passed rather than an
    // environment variable: the emulator's guest does not inherit the host's.)
    if args.get(1).map(String::as_str) == Some("words") {
        let seed: u64 = args[2].parse().expect("seed");
        let n: u64 = args[3].parse().expect("states per word");
        let mut r = Rng(seed | 1);
        // An argument `@path` names a file of one hex word per line.
        let words: Vec<String> = args[4..]
            .iter()
            .flat_map(|a| match a.strip_prefix('@') {
                Some(path) => std::fs::read_to_string(path)
                    .expect("word file")
                    .split_whitespace()
                    .map(String::from)
                    .collect::<Vec<_>>(),
                None => vec![a.clone()],
            })
            .collect();
        for a in &words {
            let w = u32::from_str_radix(a, 16).expect("hex encoding");
            for i in 0..n {
                let st = fresh_state(&mut r);
                let (after, ill) = unsafe { run(w, &st) };
                if ill {
                    println!("{a} {i} ill");
                } else {
                    println!("{a} {i} {:016x}", hash(&after, ill));
                }
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) == Some("detail") {
        let seed: u64 = args[2].parse().expect("seed");
        let want: Vec<u64> = args[3..].iter().map(|a| a.parse().expect("index")).collect();
        let max = *want.iter().max().expect("an index");
        let per_class: u64 = std::env::var("PER_CLASS").ok().and_then(|v| v.parse().ok()).unwrap_or(20000);
        for (i, insn, st) in cases(seed, per_class).take(max as usize + 1) {
            if want.contains(&i) {
                let (out, ill) = unsafe { run(insn, &st) };
                println!("case {i} insn {insn:08x} ill={ill}");
                dump("before", &st);
                dump("after", &out);
            }
        }
        return;
    }
    let per_class: u64 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(20000);
    let seed: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(1);
    // A case that kills the process (one that wrote SP, say) is reported as
    // `died` and the run resumes after it, in a fresh child: the progress
    // counter lives in a shared page the parent reads.
    let progress = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0) as *mut u64
    };
    let all: Vec<(u64, u32, State)> = cases(seed, per_class).collect();
    let mut from: usize = std::env::var("FROM").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let to: usize = std::env::var("TO").ok().and_then(|v| v.parse().ok()).unwrap_or(usize::MAX);
    let all: Vec<_> = all.into_iter().take(to).collect();
    while from < all.len() {
        use std::io::Write;
        std::io::stdout().flush().ok();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let mut out = std::io::stdout().lock();
            for (i, insn, st) in &all[from..] {
                unsafe { progress.write_volatile(*i) };
                let (after, ill) = unsafe { run(*insn, st) };
                if ill {
                    writeln!(out, "{i} {insn:08x} ill").ok();
                } else {
                    writeln!(out, "{i} {insn:08x} {:016x}", hash(&after, ill)).ok();
                }
                out.flush().ok();
            }
            unsafe { libc::_exit(0) };
        }
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0 {
            break;
        }
        let at = unsafe { progress.read_volatile() } as usize;
        let sig = if libc::WIFSIGNALED(st) { libc::WTERMSIG(st) } else { -1 };
        println!("{at} {:08x} died {sig}", all[at].1);
        from = at + 1;
    }
}
