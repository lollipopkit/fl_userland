//! Pure instruction decoding and repeated-fault tracking.

// ---------------------------------------------------------------------------
// Decoding, which is pure and is where the defects were
// ---------------------------------------------------------------------------

/// A load, as [`recover_read`] needs to see one: which registers it writes and
/// what it does to its base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Load {
    /// The destination. 31 is the zero register and is not written.
    pub rt: u32,
    /// The second destination of an `LDP`.
    pub rt2: Option<u32>,
    /// The base register, when the addressing mode writes it back, with the
    /// signed displacement to add.
    pub writeback: Option<(u32, i64)>,
}

/// Does this instruction end a basic block? The forward scan for the faulting
/// load must not step past one, because it cannot assume the fall-through.
pub(crate) fn is_branch(insn: u32) -> bool {
    insn & 0xfc00_0000 == 0x1400_0000        // B
        || insn & 0xfc00_0000 == 0x9400_0000 // BL
        || insn & 0xffff_fc1f == 0xd61f_0000 // BR
        || insn & 0xffff_fc1f == 0xd63f_0000 // BLR
        || insn == 0xd65f_03c0               // RET
        || insn & 0xff00_0010 == 0x5400_0000 // B.cond
        || insn & 0x7e00_0000 == 0x3400_0000 // CBZ/CBNZ
        || insn & 0x7e00_0000 == 0x3600_0000 // TBZ/TBNZ
}

/// The load `insn` is, or `None` for anything else.
///
/// The `LDP` mask is `0xffc00000` and not `0x7fc00000`: the old one cleared
/// bit 31, so the 64-bit `LDP` test could never be true — the compiler said so
/// — and an `LDP x` matched the `LDP w` arm instead. Both arms do the same
/// thing here, so it changed no behaviour; it makes the code mean what it says.
pub(crate) fn decode_load(insn: u32) -> Option<Load> {
    let rt = insn & 0x1f;
    let rn = (insn >> 5) & 0x1f;

    // LDP/STP, signed offset. Two destinations.
    if insn & 0xffc0_0000 == 0xa940_0000 || insn & 0xffc0_0000 == 0x2940_0000 {
        return Some(Load {
            rt,
            rt2: Some((insn >> 10) & 0x1f),
            writeback: None,
        });
    }

    // LDR/STR with an unsigned immediate offset: opc bit 22 is the direction.
    if insn & 0x3b40_0000 == 0x3940_0000 {
        return Some(Load {
            rt,
            rt2: None,
            writeback: None,
        });
    }

    // LDR/STR, register offset.
    if insn & 0x3b20_0c00 == 0x3820_0800 {
        return ((insn >> 22) & 3 != 0).then_some(Load {
            rt,
            rt2: None,
            writeback: None,
        });
    }

    // LDR/STR, unscaled or pre/post-indexed immediate. `opc == 0` is a store.
    let indexed = insn & 0x3b20_0c00;
    if indexed == 0x3800_0400 || indexed == 0x3800_0c00 || indexed == 0x3800_0000 {
        if (insn >> 22) & 3 == 0 {
            return None;
        }
        // Index type 01 is post-indexed and 11 is pre-indexed; both write the
        // base back. 00 is unscaled, which does not.
        let writeback = matches!((insn >> 10) & 3, 1 | 3).then(|| {
            let imm9 = ((insn >> 12) & 0x1ff) as i64;
            // Nine bits, signed.
            let imm9 = if imm9 & 0x100 != 0 {
                imm9 - 0x200
            } else {
                imm9
            };
            (rn, imm9)
        });
        return Some(Load {
            rt,
            rt2: None,
            writeback,
        });
    }
    None
}

// ---------------------------------------------------------------------------
// Refusing to spin
// ---------------------------------------------------------------------------

/// One fault, as the rate limiter compares them.
///
/// A legitimate recovery cycle — a stack growing down, a heap demand-mapped —
/// changes the address every time round, so counting *identical* faults
/// separates progress from a loop. The read/write direction is part of it
/// because a page can be readable and not writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fault {
    pub pid: i32,
    pub pc: u64,
    pub addr: u64,
    pub write: bool,
}

/// How many identical faults are allowed before the process is killed.
///
/// Lower below `0x1000`, which is null-dereference territory: no recovery ever
/// loops there, so a fault that repeats is stuck by definition.
pub(crate) fn stuck_limit(pc: u64) -> u32 {
    if pc < 0x1000 { 16 } else { 256 }
}

/// The per-thread count of consecutive identical faults.
#[derive(Default)]
pub(crate) struct Stuck {
    at: Option<Fault>,
    count: u32,
}

impl Stuck {
    /// Record a fault and answer how many times this exact one has arrived in
    /// a row, counting this one.
    pub(crate) fn saw(&mut self, f: Fault) -> u32 {
        if self.at == Some(f) {
            self.count += 1;
        } else {
            self.at = Some(f);
            self.count = 1;
        }
        self.count
    }
}

thread_local! {
    pub(crate) static STUCK: std::cell::RefCell<Stuck> = std::cell::RefCell::new(Stuck::default());
}
