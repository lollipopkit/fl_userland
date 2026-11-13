//! Hand-written native handlers for known guest functions, so the symbol-level
//! offload path can be A/B tested against threaded code.
//!
//! `kernel/offload_tests/symbol/register.c` until 2026-09-06. It was compiled
//! only under `-Doffload_test_symbol=true` and `link_whole`d, because it
//! self-registers from a constructor and the product core has no test hook.
//!
//! # Why this is a cargo feature and not a second staticlib
//!
//! The C was its own `static_library`, and the Rust equivalent would be a
//! second `staticlib` — which `CLAUDE.md` forbids, and for a real reason: two
//! Rust staticlibs in one link are two standard libraries, and under the
//! release profile's LTO their symbols are strong globals. Sixteen of them once
//! made `libiul.a` 206 MB and impossible to link.
//!
//! An `rlib` behind a cargo feature has none of that. `crates/iul` depends on
//! this optionally, a build asks for it with
//! `--features offload-test-symbol`, and a default build compiles nothing here
//! at all. It was `-Doffload_test_symbol=true` until 2026-09-11, and a feature
//! is an *argument* rather than a setting — so a test that wants both a plain
//! and an instrumented binary builds two rather than reconfiguring one
//! directory and having to put it back.
//!
//! # The targets are addresses, so it stays inert
//!
//! A handler only replaces a guest function if `IUL_OFFLOAD_MEMCPY` or
//! `IUL_OFFLOAD_HASH` names its address, which is specific to one rootfs and
//! one binary. A build with this compiled in and no variable set behaves
//! exactly like one without it.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{CStr, c_void};
use std::mem::MaybeUninit;

// **The ABI comes from `crates/asbestos/offloadsym`**, which owns it. Generating
// it again here would be a second rendering of `nsym_ctx` -- the defect
// `crates/kernel/taskview` exists to prevent -- and calling through it would be
// a dependency edge cargo cannot check.
use offloadsym::ffi;
use offloadsym::result::{DECLINED, HANDLED};

/// The block a copy moves at a time.
///
/// `MaybeUninit`, not `[0u8; N]`: every byte is written by `nsym_read` before
/// anything reads it, and zeroing four kilobytes per block on a `memcpy` fast
/// path is exactly the kind of cost a Rust translation adds without meaning to.
/// The C's `char buf[4096]` was not initialised either.
const CHUNK: usize = 4096;

/// musl's `memcpy(dst, src, len)`, as a value copy through the TLB.
///
/// Through the TLB rather than a host `memcpy` because the guest's pages are
/// not contiguous in the host and may be copy-on-write; `nsym_read`/`nsym_write`
/// are what resolve that, which is also what makes this fork-safe.
///
/// # Safety
/// Called by the offload dispatcher with a live context.
unsafe extern "C" fn h_memcpy(ctx: *mut ffi::nsym_ctx, _user: *mut c_void) -> std::ffi::c_int {
    // SAFETY: the dispatcher's contract.
    let (dst, src, len) = unsafe {
        (
            offloadsym::nsym_arg(ctx, 0),
            offloadsym::nsym_arg(ctx, 1),
            offloadsym::nsym_arg(ctx, 2),
        )
    };
    // A length this large is not a `memcpy` the guest meant; decline rather
    // than spend the time finding out.
    if len == 0 || len >= 0x1000_0000 {
        return DECLINED;
    }

    let mut buf = MaybeUninit::<[u8; CHUNK]>::uninit();
    let mut done: u64 = 0;
    while done < len {
        let chunk = (len - done).min(CHUNK as u64);
        // SAFETY: `nsym_read` writes `chunk` bytes or answers false, and
        // `nsym_write` only reads what it wrote.
        unsafe {
            if !offloadsym::nsym_read(ctx, src + done, buf.as_mut_ptr().cast(), chunk as _) {
                return DECLINED;
            }
            if !offloadsym::nsym_write(ctx, dst + done, buf.as_ptr().cast(), chunk as _) {
                return DECLINED;
            }
        }
        done += chunk;
    }
    // SAFETY: as above. `memcpy` answers its destination.
    unsafe { offloadsym::nsym_set_ret(ctx, dst) };
    HANDLED
}

/// `pyc_bench`'s `hash_bytes(data, len)`, a siphash-shaped byte mix.
///
/// # Safety
/// As [`h_memcpy`].
unsafe extern "C" fn h_hash_bytes(ctx: *mut ffi::nsym_ctx, _user: *mut c_void) -> std::ffi::c_int {
    // SAFETY: the dispatcher's contract.
    let (ptr, len) = unsafe {
        (
            offloadsym::nsym_arg(ctx, 0),
            offloadsym::nsym_arg(ctx, 1) as u32 as i32,
        )
    };
    let mut h: u64 = 0x736f_6d65_7073_6575;
    if len > 0 && len as usize <= CHUNK {
        let mut buf = MaybeUninit::<[u8; CHUNK]>::uninit();
        // SAFETY: as above; `len` is bounded by CHUNK.
        let ok = unsafe { offloadsym::nsym_read(ctx, ptr, buf.as_mut_ptr().cast(), len as _) };
        if ok {
            // SAFETY: `nsym_read` answered true, so `len` bytes are written.
            let bytes = unsafe { &buf.assume_init_ref()[..len as usize] };
            for &b in bytes {
                h = (u64::from(b) ^ h)
                    .rotate_right(51)
                    .wrapping_mul(0xff51_afd7_ed55_8ccd);
            }
        }
    }
    // SAFETY: the dispatcher's contract.
    unsafe { offloadsym::nsym_set_ret(ctx, h) };
    HANDLED
}

/// Register the handlers whose address the environment names.
///
/// A constructor, because the product core has no test hook to call — the same
/// mechanism `crates/util/iulenv` and `crates/kernel/pids` use, and for the
/// same reason it must sit beside what it registers.
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static REGISTER_CTOR: extern "C" fn() = register;

/// One target: the environment variable that names its address, the library and
/// symbol it stands for, and the handler.
struct Target {
    env: &'static str,
    library: &'static CStr,
    symbol: &'static CStr,
    handler: offloadsym::Handler,
}

/// The table, so adding a target is one row rather than a copied `if`.
const TARGETS: &[Target] = &[
    Target {
        env: "IUL_OFFLOAD_MEMCPY",
        library: c"libc.musl-aarch64.so.1",
        symbol: c"memcpy",
        handler: h_memcpy,
    },
    Target {
        env: "IUL_OFFLOAD_HASH",
        library: c"pyc_bench_arm64",
        symbol: c"hash_bytes",
        handler: h_hash_bytes,
    },
];

extern "C" fn register() {
    for t in TARGETS {
        let Some(addr) = std::env::var(t.env).ok().and_then(|v| parse_addr(&v)) else {
            continue;
        };
        // SAFETY: before `main`, and the two strings are 'static.
        unsafe {
            offloadsym::native_offload_add_symbol_hinted(
                t.library.as_ptr(),
                t.symbol.as_ptr(),
                addr,
                Some(t.handler),
                std::ptr::null_mut(),
            );
        }
        REGISTERED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// `0x...` or decimal, which is what `strtoull(s, NULL, 0)` accepted.
fn parse_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// How many targets the constructor registered.
///
/// Exists so that something references this crate: its only other content is
/// a `__mod_init_func` entry, and an object defining no referenced symbol is one
/// the linker may drop. It is also the check — a build with the feature on and
/// `IUL_OFFLOAD_MEMCPY` set should answer 1.
pub fn registered_targets() -> usize {
    REGISTERED.load(std::sync::atomic::Ordering::Relaxed)
}

static REGISTERED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
mod tests {
    use super::parse_addr;

    /// The C used `strtoull(s, NULL, 0)`, which takes the base from the prefix.
    /// A target address is written in hex in every note about this, so getting
    /// the prefix wrong would silently register a handler at address 0.
    #[test]
    fn an_address_is_read_the_way_strtoull_read_it() {
        assert_eq!(parse_addr("0x400000"), Some(0x400000));
        assert_eq!(parse_addr("0X400000"), Some(0x400000));
        assert_eq!(parse_addr("4194304"), Some(4194304));
        assert_eq!(parse_addr(" 0x10 "), Some(0x10));
    }

    /// Anything unparseable leaves the target unregistered, which is the safe
    /// answer: the guest runs its own code.
    #[test]
    fn nonsense_registers_nothing() {
        assert_eq!(parse_addr(""), None);
        assert_eq!(parse_addr("zzz"), None);
        assert_eq!(parse_addr("0x"), None);
    }
}
