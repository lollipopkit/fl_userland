//! The block `execve` leaves at the top of a new process's stack.
//!
//! ```text
//! sp -> argc
//!       argv[0] .. argv[argc-1]
//!       NULL
//!       envp[0] .. envp[n-1]
//!       NULL
//!       auxv[0].type, auxv[0].value, ...
//!       AT_NULL, 0
//! ```
//!
//! Every process that has ever run starts by reading this, and libc reads it
//! with no length: it walks to the `NULL`s and then to `AT_NULL`. So a layout
//! that is one word out is not a smaller answer, it is a different one — the
//! environment read as the auxiliary vector, or an `argv` that runs off into
//! whatever is above it.
//!
//! ## Why it is here
//!
//! The C **computed the size in one place and wrote the contents in another**:
//!
//! ```c
//! sp -= ((argv.count + 1) + (envp.count + 1) + 1) * ELF_PTR_SIZE;
//! sp -= sizeof(aux);
//! sp &= ~0xf;
//! ...
//! {uint64_t argc64 = argv.count; if (user_put(p, argc64)) ...}
//! p += ELF_PTR_SIZE;
//! while (argc-- > 0) { ...; p += ELF_PTR_SIZE; }
//! p += ELF_PTR_SIZE; // null terminator
//! ```
//!
//! Two independent pieces of arithmetic over the same layout, which is exactly
//! the shape that overflowed a stack buffer in `crates/fs/dirent`: a record
//! length worked out twice, and the two disagreed. Here they are one
//! [`Layout`], which knows its own size because it is the thing that fills it.

/// A pointer on this target. The guest is aarch64.
pub const PTR: usize = 8;

/// Auxiliary vector types, from `kernel/elf.h`.
pub mod at {
    pub const NULL: u64 = 0;
    pub const PHDR: u64 = 3;
    pub const PHENT: u64 = 4;
    pub const PHNUM: u64 = 5;
    pub const PAGESZ: u64 = 6;
    pub const BASE: u64 = 7;
    pub const FLAGS: u64 = 8;
    pub const ENTRY: u64 = 9;
    pub const UID: u64 = 11;
    pub const EUID: u64 = 12;
    pub const GID: u64 = 13;
    pub const EGID: u64 = 14;
    pub const PLATFORM: u64 = 15;
    pub const HWCAP: u64 = 16;
    pub const CLKTCK: u64 = 17;
    pub const SECURE: u64 = 23;
    pub const RANDOM: u64 = 25;
    pub const HWCAP2: u64 = 26;
    pub const EXECFN: u64 = 31;
    pub const SYSINFO_EHDR: u64 = 33;
}

/// The auxiliary vector keys this kernel puts on a new process's stack.
///
/// `kernel/elf.h` has the same numbers, so `tools/guessed-constants.py`
/// compares them by name.
pub const AX_PHDR: u64 = 3;
pub const AX_PHENT: u64 = 4;
pub const AX_PHNUM: u64 = 5;
pub const AX_PAGESZ: u64 = 6;
pub const AX_BASE: u64 = 7;
pub const AX_FLAGS: u64 = 8;
pub const AX_ENTRY: u64 = 9;
pub const AX_UID: u64 = 11;
pub const AX_EUID: u64 = 12;
pub const AX_GID: u64 = 13;
pub const AX_EGID: u64 = 14;
pub const AX_PLATFORM: u64 = 15;
pub const AX_HWCAP: u64 = 16;
pub const AX_CLKTCK: u64 = 17;
pub const AX_SECURE: u64 = 23;
pub const AX_RANDOM: u64 = 25;
pub const AX_HWCAP2: u64 = 26;
pub const AX_HWCAP3: u64 = 29;
pub const AX_EXECFN: u64 = 31;
pub const AX_SYSINFO_EHDR: u64 = 33;
pub const AX_MINSIGSTKSZ: u64 = 51;

/// Two keys that are **deliberately absent**, and stay absent.
///
/// glibc reads `AT_RSEQ_FEATURE_SIZE` and `AT_RSEQ_ALIGN` to decide whether to
/// register a restartable sequence, and `rseq(2)` is not implemented here.
/// Advertising the feature would make every glibc program issue a syscall that
/// fails at startup; a missing pair is the answer that means "no".
///
/// They are named so the omission is a thing a test can check. A comment saying
/// "deliberately not here" is reversed by the next person to add a key.
pub const AX_RSEQ_FEATURE_SIZE: u64 = 27;
pub const AX_RSEQ_ALIGN: u64 = 28;

/// What the auxiliary vector is built from.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AuxParams {
    pub vdso: u64,
    pub page_size: u64,
    /// Where the program header table landed in the new image.
    pub phdr: u64,
    pub phnum: u64,
    /// The interpreter's load address, or 0 when there is none.
    pub interp_base: u64,
    pub entry: u64,
    pub ruid: u32,
    pub euid: u32,
    pub rgid: u32,
    pub egid: u32,
    /// `bprm->secureexec`, `crates/kernel/creds`' `Exec::secure`: the exec
    /// changed an id or gave a capability. libc reads it and, when it is set,
    /// **ignores `LD_PRELOAD`, `LD_LIBRARY_PATH` and the rest of the
    /// environment that can redirect a load** -- the entire defence against
    /// handing a setuid binary a library of your choosing. It was hard-coded
    /// to 0 here once, and computed from the ids alone until 2026-11-13, which
    /// missed every file-capability exec.
    pub secure: bool,
    /// Guest addresses of the three strings already on the stack.
    pub random: u64,
    pub execfn: u64,
    pub platform: u64,
    /// The largest signal frame this kernel writes, for `AT_MINSIGSTKSZ`.
    pub sigframe_max: u64,
}

/// What the guest is told its CPU can do, and why each bit is set.
///
/// A crypto library on aarch64 branches on this and nothing else: OpenSSL,
/// BoringSSL, Go's `crypto`, the Rust `sha2` and `sha3` crates all read it and
/// pick between an instruction sequence and a table-driven fallback several
/// times slower. A bit that is clear is a fast path nobody takes.
///
/// Until 2026-09-02 this was the bare `0x11f` — FP, ASIMD, EVTSTRM, AES, PMULL
/// and ATOMICS — while `asbestos/guest-arm64/gen.c` decoded SHA-1, SHA-256,
/// SHA-512 and all eight CRC32 instructions as well. Those four extensions
/// were implemented, correct, and **never executed by anything**, which is why
/// nothing had ever tested them.
///
/// # The rule for adding one
///
/// A bit may be set only when **every** instruction the extension defines is
/// decoded, because a library that sees the bit emits all of them and an
/// undecoded one is an illegal instruction that kills the process.
/// `tests/guest/src/bin/crypto_probe.rs` runs each of them and is compared
/// against a real arm64 kernel by `tests/integration/probe_diff.sh`.
///
/// That rule is why **SM3 and SM4 are not here**: only `sm3partw1` and `sm4e`
/// are decoded, of eight and two. Apple Silicon implements neither, so there
/// is no hardware to check the software against either.
///
/// The bits, the ID register fields and `/proc/cpuinfo`'s `Features` line are
/// one table, `asbestos_features::caps`, so the three cannot disagree.
const HWCAP: u64 = asbestos_features::caps::hwcap();
const HWCAP2: u64 = asbestos_features::caps::hwcap2();

/// The standard set, in the order this kernel writes it.
///
/// One place rather than a table in `kernel/exec.c`, because what is *in* it is
/// the part that has been wrong: `AT_UID`, `AT_EUID`, `AT_GID` and `AT_EGID`
/// were hard-coded to 0, so `getauxval(AT_UID)` told a process running as 1000
/// that it was root — and `AT_SECURE` beside them, which is the one that
/// matters. libc reads it and, when it is set, ignores `LD_PRELOAD` and
/// everything else in the environment that can redirect a load; hard-coded to
/// 0, a setuid binary could be handed a library of the caller's choosing.
pub fn standard_aux(p: &AuxParams) -> Vec<(u64, u64)> {
    let round_up = |n: u64| (n + p.page_size - 1) & !(p.page_size - 1);
    vec![
        (AX_SYSINFO_EHDR, p.vdso),
        (AX_HWCAP, HWCAP),
        (AX_PAGESZ, p.page_size),
        (AX_CLKTCK, 0x64),
        (AX_PHDR, p.phdr),
        // The ELF64 program header size, from the one place that knows it.
        (AX_PHENT, elf::PHDR_SIZE as u64),
        (AX_PHNUM, p.phnum),
        (AX_BASE, p.interp_base),
        (AX_FLAGS, 0),
        (AX_ENTRY, p.entry),
        (AX_UID, p.ruid as u64),
        (AX_EUID, p.euid as u64),
        (AX_GID, p.rgid as u64),
        (AX_EGID, p.egid as u64),
        (AX_SECURE, p.secure as u64),
        (AX_RANDOM, p.random),
        (AX_HWCAP2, HWCAP2),
        (AX_HWCAP3, 0),
        (AX_EXECFN, p.execfn),
        (AX_PLATFORM, p.platform),
        // glibc reads this for sysconf(_SC_MINSIGSTKSZ) and to size SIGSTKSZ at
        // run time. Absent, it falls back to a compile-time constant that may
        // be smaller than the frame this kernel writes -- and a program that
        // sizes a sigaltstack from that constant would have its stack overrun.
        (AX_MINSIGSTKSZ, round_up(p.sigframe_max)),
    ]
}

/// One auxiliary vector entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Aux {
    pub kind: u64,
    pub value: u64,
}

/// What goes at the top of the stack, and where.
///
/// The pointers are absolute guest addresses of strings already copied higher
/// up the stack; this arranges them, it does not copy them.
pub struct Layout {
    argv: Vec<u64>,
    envp: Vec<u64>,
    aux: Vec<Aux>,
}

impl Layout {
    /// `aux` must **not** include the terminating `AT_NULL`; it is added here,
    /// so it cannot be forgotten and cannot be counted twice.
    pub fn new(argv: Vec<u64>, envp: Vec<u64>, mut aux: Vec<Aux>) -> Layout {
        aux.push(Aux {
            kind: at::NULL,
            value: 0,
        });
        Layout { argv, envp, aux }
    }

    /// How many bytes the block takes.
    ///
    /// `argc`, the pointers, their two `NULL`s, and the auxiliary vector
    /// including its terminator.
    pub fn size(&self) -> usize {
        (1 + self.argv.len() + 1 + self.envp.len() + 1) * PTR + self.aux.len() * 2 * PTR
    }

    /// Where `sp` goes, given the lowest address the block may start at.
    ///
    /// **Sixteen-byte aligned downwards**, which the aarch64 procedure call
    /// standard requires of `sp` at every instruction — and which is the reason
    /// the block is measured before it is placed rather than built upwards from
    /// a chosen `sp`.
    pub fn sp_for(&self, below: u64) -> u64 {
        below.saturating_sub(self.size() as u64) & !0xf
    }

    /// Offset of the auxiliary vector within the block, for `/proc/<pid>/auxv`.
    pub fn auxv_offset(&self) -> usize {
        (1 + self.argv.len() + 1 + self.envp.len() + 1) * PTR
    }

    pub fn auxv_bytes(&self) -> usize {
        self.aux.len() * 2 * PTR
    }

    /// Fill `out`, which must be [`Self::size`] bytes.
    ///
    /// Little-endian, as the guest is. Returns whether it fit — a caller that
    /// sized the buffer from `size()` cannot fail this, which is the point of
    /// the two being the same object.
    pub fn encode(&self, out: &mut [u8]) -> bool {
        if out.len() < self.size() {
            return false;
        }
        let mut at = 0usize;
        let mut put = |v: u64, at: &mut usize| {
            out[*at..*at + PTR].copy_from_slice(&v.to_le_bytes());
            *at += PTR;
        };
        put(self.argv.len() as u64, &mut at);
        for &p in &self.argv {
            put(p, &mut at);
        }
        put(0, &mut at); // argv's terminator
        for &p in &self.envp {
            put(p, &mut at);
        }
        put(0, &mut at); // envp's terminator
        for a in &self.aux {
            put(a.kind, &mut at);
            put(a.value, &mut at);
        }
        debug_assert_eq!(at, self.size());
        true
    }
}

#[cfg(test)]
mod tests;
