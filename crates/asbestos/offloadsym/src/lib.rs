//! Symbol-level native offload: running a *host* implementation of one guest
//! function instead of translating it.
//!
//! The companion to `crates/kernel/offloadexec`, which intercepts a whole guest
//! command at `execve`. This intercepts one function at its entry pc, in the
//! JIT's dispatch loop. Binary-level is for "run this whole tool natively"
//! (curl, ffmpeg); this is for "run this hot function natively" (`memcpy`, a
//! Python compile step).
//!
//! # What a handler gets
//!
//! A context wrapping the guest CPU and its TLB. Arguments follow AAPCS64 —
//! integers in `x0`..`x7`, the return value in `x0` — and **every memory access
//! is a value copy**, which is what makes it fork- and copy-on-write-safe and
//! is the same discipline the `mem*` bypass follows. A read or a write that
//! faults answers false rather than trapping.
//!
//! A registration names a binary basename and a symbol. `addr_hint` is a fixed
//! guest entry address for the no-ASLR case; zero means "resolve by name
//! later", which the loader does through `native_offload_bind_symbol` when a
//! matching binary maps a matching symbol. Binding is idempotent.
//!
//! The dispatch hook is called from the dispatch loop with the current guest
//! pc and answers whether a handler fired — cheap on the common miss, which is
//! a few address compares. `native_offload_sym_any` is what lets the loop skip
//! the scan entirely when nothing is registered.
//!
//! # Lossless, which is what makes the gate "registered" and nothing else
//!
//! Nothing is registered unless an embedder registers it, a registration that
//! has not been bound to an address matches nothing, and a handler may answer
//! [`Result::Declined`] after looking at the arguments — in which case the
//! guest's own code runs, unchanged. There is no environment variable and no
//! build flag, because there is no case where being on is worse than being off.
//!
//! # An entry is never removed, and the table is fixed
//!
//! `struct task` does not hold one of these, so the reason is different from
//! `crates/kernel/offloadreg`'s: the *dispatch* runs on every block the JIT
//! enters, from every thread, with no lock. A `Vec` that could reallocate under
//! a reader is the thing to avoid; 64 entries written once at registration and
//! read for ever is not. Registration happens before any guest thread exists,
//! or from a loader callback on the thread doing the load.


use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};
use util_appendonly::AppendOnly;

#[allow(non_upper_case_globals, non_camel_case_types, dead_code)]
/// The offload ABI, public so a handler crate can name `nsym_ctx` without
/// generating a second copy of it. `crates/kernel/offloadtest` is the one.
// The CPU/TLB and offload context types belong to the emulator ABI layer. This
// crate used to import them through `taskview`, which also exposed unrelated
// task accessors and forced this interpreter component into the kernel layer.
pub use emu_abi as ffi;

/// What a handler answers.
pub mod result {
    use std::ffi::c_int;
    /// The handler did the work; resume as `ctx.resume` says.
    pub const HANDLED: c_int = 0;
    /// The handler looked and opted out; run the guest's own code.
    pub const DECLINED: c_int = 1;
}

/// Where to resume after a handler.
mod resume {
    use std::ffi::c_uint;
    /// Return to the link register, which is what a call does.
    pub const RET: c_uint = 0;
    /// Jump to `ctx.resume_pc`, which the handler set.
    pub const PC: c_uint = 1;
}

/// The most symbols an embedder may register.
const MAX: usize = 64;

/// What a symbol-level handler looks like. Public so a handler crate names
/// this rather than rebuilding it from the generated enum — the return is
/// `c_int` and bindgen renders `nsym_result` as `c_uint`, which is a
/// disagreement the compiler catches only if both sides use one type.
pub type Handler = unsafe extern "C" fn(*mut ffi::nsym_ctx, *mut c_void) -> c_int;

/// One registration.
///
/// `addr` is the resolved entry pc, or zero for one waiting to be bound: a
/// symbol's address depends on where its binary maps, so a registration made
/// before the load is bound afterwards by [`native_offload_bind_symbol`].
struct Target {
    /// `""` for none. `&'static` because the C contract says the strings
    /// outlive the process; read once, at registration, where that contract
    /// is the caller's -- it was a `usize` re-read through `CStr::from_ptr` in
    /// an `unsafe` block at every comparison and report until 2026-10-01.
    binary: &'static str,
    symbol: &'static str,
    handler: Handler,
    user: usize,
    addr: AtomicU64,
    hits: AtomicU64,
}

/// The registrations. Read by the dispatch without a lock; see
/// `util_appendonly`, which replaced a `static mut` array, a published count
/// and a registration `Mutex` written out here by hand.
static TABLE: AppendOnly<Target, MAX> = AppendOnly::new();

/// A registered symbol's C string as a `&str`, or `""`.
///
/// # Safety
/// `p` is null or a NUL-terminated string that outlives the call.
unsafe fn name<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        return "";
    }
    unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("")
}

// ---------------------------------------------------------------------------
// What a handler is given
// ---------------------------------------------------------------------------

/// An integer argument, AAPCS64: `x0`..`x7`. Zero for anything else, because a
/// handler asking for `nsym_arg(ctx, 9)` has misread the ABI and a wrong answer
/// is better than a read off the end of the register file.
///
/// # Safety
/// `ctx` is one the dispatch built.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nsym_arg(ctx: *mut ffi::nsym_ctx, n: c_int) -> u64 {
    if !(0..=7).contains(&n) {
        return 0;
    }
    unsafe { (*(*ctx).cpu).regs[n as usize] }
}

/// The return value, which AAPCS64 puts in `x0`.
///
/// # Safety
/// As [`nsym_arg`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nsym_set_ret(ctx: *mut ffi::nsym_ctx, v: u64) {
    unsafe { (*(*ctx).cpu).regs[0] = v };
}

/// Guest memory into `buf`. False on a fault.
///
/// A **value copy**, in page-sized bites, which is the discipline the whole
/// offload interface is built on: a handler never holds a host pointer into
/// guest memory, so a copy-on-write or a `fork` between two of its reads cannot
/// leave it pointing at the wrong page.
///
/// # Safety
/// `buf` addresses `len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nsym_read(
    ctx: *mut ffi::nsym_ctx,
    gaddr: u64,
    buf: *mut c_void,
    len: usize,
) -> bool {
    unsafe { chunked(ctx, gaddr, buf.cast::<u8>(), len, true) }
}

/// `buf` into guest memory. False on a fault.
///
/// # Safety
/// `buf` addresses `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nsym_write(
    ctx: *mut ffi::nsym_ctx,
    gaddr: u64,
    buf: *const c_void,
    len: usize,
) -> bool {
    unsafe { chunked(ctx, gaddr, buf as *mut u8, len, false) }
}

/// Add a byte offset to a guest address without wrapping into a different page.
fn guest_address_at(base: u64, offset: usize) -> Option<u64> {
    base.checked_add(offset as u64)
}

/// One page at a time, because that is the largest the TLB will answer for in
/// one go.
///
/// # Safety
/// As the two above.
unsafe fn chunked(
    ctx: *mut ffi::nsym_ctx,
    gaddr: u64,
    buf: *mut u8,
    len: usize,
    read: bool,
) -> bool {
    // SAFETY: the caller's contract: `ctx` is the running guest's.
    let tlb = unsafe { emu_tlb::access::Tlb::new((*ctx).tlb) };
    let mut done = 0usize;
    while done < len {
        let chunk = (len - done).min(4096);
        let Some(at) = guest_address_at(gaddr, done) else {
            return false;
        };
        // SAFETY: `buf` is `len` bytes, the caller's contract.
        let here = unsafe { std::slice::from_raw_parts_mut(buf.add(done), chunk) };
        let ok = if read { tlb.read(at, here) } else { tlb.write(at, here) };
        if !ok {
            return false;
        }
        done += chunk;
    }
    true
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// Register `(binary, symbol) -> handler`. The id, or -1 if the table is full.
///
/// The strings are **not copied**: they belong to the caller and must outlive
/// the process, which is what the header says and what an embedder registering
/// literals does.
///
/// # Safety
/// `binary` and `symbol` are NUL-terminated and static.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_offload_add_symbol(
    binary: *const c_char,
    symbol: *const c_char,
    handler: Option<Handler>,
    user: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract -- NUL-terminated and static.
    add(unsafe { name(binary) }, unsafe { name(symbol) }, 0, handler, user)
}

/// The same, with the entry address already known — which it is when the guest
/// is loaded without ASLR.
///
/// # Safety
/// As [`native_offload_add_symbol`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_offload_add_symbol_hinted(
    binary: *const c_char,
    symbol: *const c_char,
    addr_hint: u64,
    handler: Option<Handler>,
    user: *mut c_void,
) -> c_int {
    // SAFETY: as above.
    add(unsafe { name(binary) }, unsafe { name(symbol) }, addr_hint, handler, user)
}

fn add(
    binary: &'static str,
    symbol: &'static str,
    addr: u64,
    handler: Option<Handler>,
    user: *mut c_void,
) -> c_int {
    let Some(handler) = handler else {
        return -1;
    };
    let target = Target {
        binary,
        symbol,
        handler,
        user: user as usize,
        addr: AtomicU64::new(addr),
        hits: AtomicU64::new(0),
    };
    TABLE.push(target).map_or(-1, |id| id as c_int)
}

/// Bind every unbound registration of `symbol` to the address the loader found
/// it at. Idempotent: an entry that already has an address is left alone.
///
/// A null `binary` matches any, which is how a caller that knows only the
/// symbol name binds it.
///
/// # Safety
/// `symbol` is NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_offload_bind_symbol(
    binary: *const c_char,
    symbol: *const c_char,
    addr: u64,
) {
    let want = unsafe { name(symbol) };
    let want_binary = unsafe { name(binary) };
    for t in TABLE.iter() {
        if t.addr.load(Ordering::Relaxed) != 0 {
            continue;
        }
        if !want_binary.is_empty()
            && !t.binary.is_empty()
            && t.binary != want_binary
        {
            continue;
        }
        if t.symbol != want {
            continue;
        }
        t.addr.store(addr, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Is any symbol offload registered? The JIT's loop asks first, so a build
/// nobody has registered anything in skips the scan entirely.
///
/// **There are no built-ins.** `kernel/native_offload_sym_builtins.c` was called
/// from here on the first call, and it is gone as of 2026-09-03: its whole body
/// was an `#ifdef IUL_OFFLOAD_PYCOMPILE` block naming a backend file that does
/// not exist in this tree, so no build could compile it and a build that defined
/// the flag would not link. The offload *tests* never came through it either --
/// `kernel/offload_tests/symbol/register.c` self-registers with a constructor,
/// which is what `-Doffload_test_symbol=true` `link_whole`s it for.
///
/// So this is a load and a comparison, which is what it has to be: it is asked
/// on every block the JIT dispatches.
pub fn native_offload_sym_active() -> bool {
    !TABLE.is_empty()
}

/// Run a handler if one is registered at `pc`. True when the guest state has
/// been advanced and the block must not run.
///
/// A linear scan over a table that is almost always empty and never more than
/// 64 entries, on a path that almost always misses — which branch-predicts
/// well and is why there is no index.
///
/// # Safety
/// `cpu` and `tlb` belong to the calling guest thread.
pub unsafe fn native_offload_sym_dispatch(
    pc: u64,
    cpu: *mut ffi::cpu_state,
    tlb: *mut ffi::tlb,
) -> bool {
    for t in TABLE.iter() {
        if t.addr.load(Ordering::Acquire) != pc {
            continue;
        }
        let handler = t.handler;
        let mut ctx = ffi::nsym_ctx {
            cpu,
            tlb,
            resume: resume::RET,
            resume_pc: 0,
        };
        if unsafe { handler(&raw mut ctx, t.user as *mut c_void) } == result::DECLINED {
            // Lossless: fall through to the guest's own code.
            return false;
        }
        if t.hits.fetch_add(1, Ordering::Relaxed) == 0 && util_iulenv::env().offload_stats {
            eprintln!(
                "[offload:sym] first hit: {}:{} @ {pc:x}",
                match t.binary {
                    "" => "?",
                    b => b,
                },
                t.symbol,
            );
        }
        unsafe {
            (*cpu).pc = if ctx.resume == resume::PC {
                ctx.resume_pc
            } else {
                (*cpu).regs[30]
            };
        }
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_registered_by_default() {
        // The gate is "registered", with no environment variable and no build
        // flag, because there is no case where being on is worse than being
        // off: an unmatched pc runs the guest's code and so does a handler
        // that declines.
        assert!(TABLE.is_empty());
    }

    #[test]
    fn a_guest_address_offset_does_not_wrap() {
        assert_eq!(guest_address_at(0x1000, 0x20), Some(0x1020));
        assert_eq!(guest_address_at(u64::MAX, 1), None);
        assert_eq!(guest_address_at(u64::MAX - 7, 7), Some(u64::MAX));
        assert_eq!(guest_address_at(u64::MAX - 7, 8), None);
    }

    #[test]
    fn an_argument_past_the_seventh_is_zero_rather_than_a_read() {
        // AAPCS64 puts eight integer arguments in registers. A handler asking
        // for a ninth has misread the ABI, and answering zero is better than
        // indexing off the end of the register file.
        assert_eq!(unsafe { nsym_arg(std::ptr::null_mut(), 8) }, 0);
        assert_eq!(unsafe { nsym_arg(std::ptr::null_mut(), -1) }, 0);
    }

    #[test]
    fn the_two_answers_are_the_headers_numbering() {
        // An embedder's handler returns these, so they are the C enum's values
        // and not this crate's choice.
        assert_eq!(result::HANDLED, ffi::nsym_result_NSYM_HANDLED as c_int);
        assert_eq!(result::DECLINED, ffi::nsym_result_NSYM_DECLINED as c_int);
        assert_eq!(resume::RET, ffi::nsym_resume_NSYM_RESUME_RET);
        assert_eq!(resume::PC, ffi::nsym_resume_NSYM_RESUME_PC);
    }
}
