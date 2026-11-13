//! Turning guest instructions into a gadget program.
//!
//! `asbestos/guest-arm64/gen.c` decodes one AArch64 instruction at a time and
//! appends to a `struct fiber_block`: a pointer to a pre-compiled assembly
//! gadget, then whatever operands that gadget reads out of the code stream.
//! This is that, in Rust, one instruction class at a time.
//!
//! # Why a class at a time, and why it costs nothing
//!
//! `gen_step` already dispatches on `arm64_classify_insn`, so a class that
//! moves replaces a static call with an extern one — **once per instruction of
//! that class**, and only while it is being compiled. Everything underneath
//! that made a finer cut impossible is duplicated here instead of exported:
//!
//! - [`Gen::emit`] is the ten-line `gen()` from `gen.c`, so a Rust decoder
//!   does not make a cross-language call per operand. That was the thing that
//!   would have cost: a block is a few dozen instructions and each emits two
//!   to five words.
//! - The peephole fusions and the immediate decoders were `static` and
//!   `static inline`, so there was nothing to link to. [`decode`] has the
//!   second set, with tests; [`fuse`] has the first.
//!
//! `struct gen_state`, which C declared, is [`Builder`]'s private state since
//! the last class moved.
//!
//! # What checks it
//!
//! `tests/guest/src/bin/scalar_probe.rs` covers every instruction in the class
//! moved so far — the flag-setting arithmetic, the bitfield aliases, the
//! logical immediates, `adr`/`adrp`, `extr` and the moves — against a real
//! arm64 CPU through `tests/integration/probe_diff.sh`. It was written before
//! this crate existed, which is the order that makes a rewrite safe.


use std::ffi::c_int;

// `struct gen_state`, `struct fiber_block` and the FIBER_*/INT_*/PAGE_SIZE
// constants, all `crates/kernel/taskview`'s. This crate's own bindgen also
// asked for `enum iul_sp_cat`, which **no header defines** -- the comment
// beside it named an `IUL_SP_CAT_JIT` that does not exist either, and the
// generated file never had them.
use emu_abi as ffi;

mod block;
mod branch;
mod classify;
pub mod compile;
pub mod decode;
mod dpimm;
mod dpreg;
mod features;
mod fuse;
mod gadgets;
mod ldst;
mod simd;
mod step;
mod system;

/// The interrupt numbers a decoder can end a block with. `emu/interrupt.h`,
/// generated rather than written down.
pub mod int {
    use super::ffi;
    use std::ffi::c_int;
    pub const UNDEFINED: c_int = ffi::INT_UNDEFINED as c_int;
    pub const SYSCALL: c_int = ffi::INT_SYSCALL as c_int;
    pub const BREAKPOINT: c_int = ffi::INT_BREAKPOINT as c_int;
}

/// A gadget, as the code stream holds it: an address the dispatch loop jumps
/// to. The gadgets are assembly and take no arguments a caller passes — they
/// read the words after themselves — so the type says nothing about a
/// signature.
pub type Gadget = unsafe extern "C" fn();

/// What a class decoder answers.
///
/// The C spelling is `int`: 1 for "decoded, keep going", 0 for "the block ends
/// here", and the caller of `gen_step` treats them as `continue` and `stop`.
/// A separate type would have to be converted at the boundary and there is one
/// boundary, so it is the same two integers with names.
pub const DECODED: c_int = 1;
pub const BLOCK_ENDS: c_int = 0;

/// A block being compiled: the decoder's state and the code emitted so far.
///
/// The code is a `Vec` until [`Builder::finish`] makes the block, one
/// allocation of exactly the size it needs. Until 2026-10-17 the block was
/// `malloc`ed at the start and `realloc`ed as it grew, so every append was a
/// raw write into it under an invariant only the private field kept, a `Drop`
/// freed it by hand, and `used` recorded the doubled capacity rather than the
/// code -- which `crates/asbestos/dispatch`'s prebuilt fault path takes as the
/// bound of the code array, so an offset into the unwritten tail passed it.
pub struct Builder(State);

/// `struct gen_state`, which C declared until the decoder was all Rust. Its
/// `block`, `size` and `capacity` are `code`.
struct State {
    ip: ffi::addr_t,
    orig_ip: ffi::addr_t,
    orig_ip_extra: u64,
    /// Where the block starts.
    addr: ffi::addr_t,
    code: Vec<u64>,
    jump_ip: [u32; 2],
    block_patch_ip: u32,
    last_insn: u32,
    tlb: *mut ffi::tlb,
    b_follow_depth: u32,
}

impl Builder {
    /// Start a block at `addr`.
    pub fn start(addr: ffi::addr_t) -> Builder {
        Builder(State {
            ip: addr,
            orig_ip: 0,
            orig_ip_extra: 0,
            addr,
            code: SCRATCH.take(),
            jump_ip: [0, 0],
            block_patch_ip: 0,
            last_insn: 0,
            tlb: std::ptr::null_mut(),
            b_follow_depth: 0,
        })
    }

    /// The decoder over this block.
    pub fn decoder(&mut self) -> Gen<'_> {
        Gen { st: &mut self.0 }
    }

    /// Where the next instruction is.
    pub fn ip(&self) -> u64 {
        self.0.ip
    }

    /// Where the instruction last compiled is.
    pub fn orig_ip(&self) -> u64 {
        self.0.orig_ip
    }

    /// The words emitted so far.
    pub fn code(&self) -> &[u64] {
        &self.0.code
    }

    /// Start the code array again, for a test that decodes one instruction
    /// at a time.
    #[cfg(test)]
    fn clear(&mut self) {
        self.0.code.clear();
    }

    /// Make the block and hand it over: resolve the jump slots, fill in the
    /// block's own address where a call gadget needs it, record the range it
    /// covers and how much code it holds. The caller owns the result, which
    /// `fiber_block_free` frees. `None` if the allocation failed.
    pub fn finish(self) -> Option<std::ptr::NonNull<ffi::fiber_block>> {
        block::gen_end(&self.0)
    }
}

thread_local! {
    /// The code array, kept between compiles on this thread: a block is
    /// copied out of it by `finish`, so a fresh `Vec` per block would be an
    /// allocation and its regrowth on every compile, which exec churn
    /// measured at 2.5% against the `realloc`ed block this replaced.
    static SCRATCH: std::cell::Cell<Vec<u64>> = const { std::cell::Cell::new(Vec::new()) };
}

/// A block is at most a page of guest code; a buffer grown past this by some
/// pathological one is not worth keeping.
const SCRATCH_KEEP: usize = 16 * 1024;

impl Drop for Builder {
    fn drop(&mut self) {
        let mut code = std::mem::take(&mut self.0.code);
        if code.capacity() <= SCRATCH_KEEP {
            code.clear();
            SCRATCH.set(code);
        }
    }
}

/// The block being built, and the cursor into the guest's instruction stream.
/// Made by [`Builder::decoder`].
pub struct Gen<'a> {
    st: &'a mut State,
}

impl Gen<'_> {
    fn s(&self) -> &State {
        self.st
    }
    fn m(&mut self) -> &mut State {
        self.st
    }

    /// Start on a new instruction: record where it is, so a fault reports its
    /// address rather than the next one's, and bind this thread's TLB so the
    /// peepholes can read ahead.
    ///
    /// # Safety
    /// `tlb` is this thread's, live for as long as this decoder reads through
    /// it -- [`Gen::peek`] does. It was a safe function storing a raw pointer
    /// another safe function dereferenced until 2026-10-16.
    pub unsafe fn begin(&mut self, tlb: *mut ffi::tlb) {
        let st = self.m();
        st.orig_ip = st.ip;
        st.orig_ip_extra = 0;
        st.tlb = tlb;
    }

    /// Record the word being compiled. `asbestos/asbestos.c` reads it when a
    /// block ends in something it has to report.
    pub fn set_last_insn(&mut self, insn: u32) {
        self.m().last_insn = insn;
    }

    /// Where the *next* instruction is. `gen_step` has already advanced this
    /// past the one being decoded, which is why a peephole that consumes a
    /// second instruction adds four to it.
    pub fn ip(&self) -> u64 {
        self.s().ip
    }

    /// Where the instruction being decoded is — what a fault must report and
    /// what `adr` is relative to.
    pub fn orig_ip(&self) -> u64 {
        self.s().orig_ip
    }

    /// Consume `n` more instructions, for a peephole that fused them.
    pub fn consume(&mut self, n: u64) {
        self.m().ip += 4 * n;
    }

    /// How many words are in the block so far. The two jump slots are recorded
    /// as indices into it.
    pub fn len(&self) -> u32 {
        self.s().code.len() as u32
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append one word — a gadget address or an operand.
    ///
    /// This is `gen()` from `gen.c`, duplicated rather than called: it runs two
    /// to five times per instruction compiled, and a cross-language call there
    /// is what would have made moving a class at a time cost anything.
    pub fn emit(&mut self, word: u64) {
        self.m().code.push(word);
    }

    /// A slow path, through the one gadget that calls Rust: the function and
    /// its operand word. See `emu_tlb::access::SlowFn`; the signature is
    /// checked here, where the function becomes a code-stream word.
    pub fn slow_call(&mut self, f: emu_tlb::access::SlowFn, arg: u64) {
        self.gadget(gadgets::gadget_slow_call);
        self.emit(f as usize as u64);
        self.emit(arg);
    }

    /// A gadget address, which is the common case of [`Gen::emit`].
    pub fn gadget(&mut self, g: Gadget) {
        self.emit(g as usize as u64);
    }

    /// End the block with an interrupt, pointing the guest's pc at the
    /// instruction that caused it so a signal handler sees the right address.
    pub fn interrupt(&mut self, which: c_int) {
        let pc = self.orig_ip();
        self.gadget(gadgets::gadget_set_pc);
        self.emit(pc);
        self.gadget(gadgets::gadget_interrupt);
        self.emit(which as u64);
    }

    /// An instruction this decoder does not know. Ends the block.
    pub fn undefined(&mut self) -> c_int {
        self.interrupt(ffi::INT_UNDEFINED as c_int);
        BLOCK_ENDS
    }

    /// The next instruction word, without consuming it. `None` if it is not
    /// readable, which is a block that ends at a page boundary.
    pub fn peek(&self) -> Option<u32> {
        self.peek_at(self.ip())
    }

    /// The word at `addr`, for a peephole looking two instructions ahead.
    ///
    pub fn peek_at(&self, addr: u64) -> Option<u32> {
        // SAFETY: `begin`'s contract: the TLB is this thread's.
        unsafe { fetch(self.s().tlb, addr) }
    }

    /// Record that the *last* word emitted is the block's one destination.
    pub fn set_single_jump_slot(&mut self) {
        let n = self.len();
        self.m().jump_ip[0] = n - 1;
    }

    /// Record where the block's own address goes, `back` words from the end.
    ///
    /// `gadget_branch_link` needs a pointer to the block it is in, and the
    /// block does not exist as an object until `gen_end` — so a slot is
    /// emitted empty and filled in there.
    pub fn set_block_patch_slot(&mut self, back: u32) {
        let n = self.len();
        self.m().block_patch_ip = n - back;
    }

    /// Follow an unconditional branch inline instead of ending the block, if
    /// the three conditions hold: it is forward, it lands on the page the
    /// block started on, and this has not already been done too often.
    ///
    /// Backward would let a loop inline itself for ever. A different page
    /// would put the block's code in a page the invalidation index does not
    /// know it touches, so a write there would not throw the block away.
    pub fn follow(&mut self, target: u64, limit: u32) -> bool {
        // SAFETY: the builder's own block, whose header `start` wrote.
        let block_page = self.s().addr >> 12;
        if target >> 12 != block_page
            || target <= self.orig_ip()
            || self.s().b_follow_depth >= limit
        {
            return false;
        }
        let st = self.m();
        st.ip = target;
        st.b_follow_depth += 1;
        true
    }

    /// Record that the last two words emitted are a branch's target and its
    /// fallthrough, so the block cache can patch them into a direct jump.
    ///
    /// The indices are into the code array and are what `gen_end` turns into
    /// pointers; getting them one out patches the wrong word, which is a jump
    /// into the middle of an operand.
    pub fn set_jump_slots(&mut self) {
        let n = self.len();
        let st = self.m();
        st.jump_ip[0] = n - 2;
        st.jump_ip[1] = n - 1;
    }
}

/// An instruction word read through the software TLB, which is
/// `crates/emu/tlb`'s.
///
/// A thin wrapper rather than a direct call, because the `#[cfg(test)]` twin
/// below is what lets a decoder test give the block its own memory. It was an
/// `unsafe extern "C"` declaration until 2026-09-05; the C ABI is gone and the
/// shape it made possible is not.
///
/// # Safety
/// `tlb` is this thread's.
#[cfg(not(test))]
unsafe fn fetch(tlb: *mut ffi::tlb, addr: u64) -> Option<u32> {
    unsafe { emu_tlb::access::Tlb::new(tlb) }.read_array(addr).map(u32::from_le_bytes)
}

/// The stand-in a test binary links instead, in the shape `gadgets!` already
/// uses for the 742 gadget symbols.
///
/// It answers **not readable** by default, which is what a block ending at a
/// page boundary looks like: `peek` gives `None` and no peephole fuses. That is
/// what a test of a class decoder wants — one instruction in, one decision out —
/// and without it a test could not link at all, which is why `dpimm::decode` had
/// no test before.
///
/// A test that needs a *block* rather than an instruction gives it memory with
/// [`harness::with_guest_memory`]. Defaulting to empty rather than to zeroes
/// matters: a page of zeroes decodes as `udf #0`, which ends the block, so the
/// two are not interchangeable.
///
/// # Safety
/// None: `unsafe` only to match the real one's signature.
#[cfg(test)]
unsafe fn fetch(_tlb: *mut ffi::tlb, addr: u64) -> Option<u32> {
    harness::GUEST.with(|g| {
        let g = g.borrow();
        let (base, bytes) = g.as_ref()?;
        let at = addr.checked_sub(*base)? as usize;
        let word = bytes.get(at..at + 4)?;
        Some(u32::from_le_bytes(word.try_into().expect("four bytes")))
    })
}

/* The five class decoders were `extern "C"` here while `asbestos/gen.c` still
 * held `gen_step` and dispatched to them one at a time. It does not: `gen_step`
 * is `step.rs` and calls them as Rust, so the four exports went with the C. */

/// Driving a real decoder from a test.
///
/// # Why this exists
///
/// The tests in these modules restated the rule they were about rather than
/// calling the code — a closure that says which `(sf, op31)` pairs are allocated,
/// beside a decoder that says the same thing again. Two statements of one rule
/// is two chances to disagree, and on 2026-09-03 they did:
/// `the_widening_multiplies_are_64_bit_only` passed while the decoder ran
/// `SMULH` for `o0 = 1`, which is not an allocated encoding. The test could not
/// have failed, because it never asked the decoder anything.
///
/// A `Gen` needs a `struct gen_state` with a block behind it, which is all this
/// is: the block is `malloc`ed the way `gen.c` does it and grown by `emit`, and
/// the gadget symbols are the `cfg(test)` stand-ins `gadgets!` already declares.
#[cfg(test)]
pub(crate) mod harness {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        /// The bytes `fetch` serves, and the guest address they start at.
        pub(crate) static GUEST: RefCell<Option<(u64, Vec<u8>)>> = const { RefCell::new(None) };
    }

    /// Run `f` with `words` readable at `base`, and nothing else readable.
    ///
    /// For a test that needs a whole *block*: without it the decoder cannot read
    /// a second instruction, so every block is one instruction long.
    pub(crate) fn with_guest_memory<R>(base: u64, words: &[u32], f: impl FnOnce() -> R) -> R {
        let bytes = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        GUEST.with(|g| *g.borrow_mut() = Some((base, bytes)));
        let out = f();
        GUEST.with(|g| *g.borrow_mut() = None);
        out
    }

    pub(crate) struct Decoder {
        b: crate::Builder,
    }

    impl Decoder {
        pub(crate) fn new() -> Decoder {
            Decoder { b: crate::Builder::start(0) }
        }

        /// Hand `insn` to `f` and answer whether it was **decoded** — that is,
        /// whether it produced anything other than the undefined-instruction
        /// interrupt.
        ///
        /// The test is on what was emitted rather than on the return value,
        /// because `undefined()` answers `BLOCK_ENDS`, which is also what a
        /// branch answers.
        pub(crate) fn decodes(&mut self, f: fn(&mut Gen, u32) -> c_int, insn: u32) -> bool {
            self.b.clear();
            f(&mut self.b.decoder(), insn);
            match self.b.code() {
                [.., before, last] => {
                    !(*before == gadgets::gadget_interrupt as *const () as usize as u64
                        && *last == ffi::INT_UNDEFINED as u64)
                }
                _ => true,
            }
        }

        /// The last two words emitted: a gadget and its operand.
        ///
        /// For a test that cares *what* was decoded and not only that something
        /// was — `decodes` answers the second question and they are different
        /// claims.
        pub(crate) fn last_pair(&self) -> (u64, u64) {
            match self.b.code() {
                [.., a, b] => (*a, *b),
                _ => panic!("nothing was emitted"),
            }
        }
    }
}
