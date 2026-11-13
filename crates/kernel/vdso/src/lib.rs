//! What is in the built-in VDSO image, and the image itself.
//!
//! `kernel/vdso.c` was five lines of `__asm__(".incbin ...")` until 2026-09-06,
//! and which file got embedded was a contract with meson — which is what knew
//! the path. `build.rs` **builds the image itself** since 2026-09-09, by
//! running `vdso/arm64/build.sh`, so there is one image and this crate made it;
//! there is no path for anything to tell it and no second build-time channel.
//! The argument for reading the path out of `TMPFS_RS_CLANG_ARGS` instead is
//! written out there, and is moot.
//!
//! # One symbol is looked up, and it has to be
//!
//! `__kernel_rt_sigreturn` is where a signal frame's return address points, so
//! a handler that returns lands in the VDSO and executes the `rt_sigreturn`
//! trampoline. Its offset is not a constant anyone may write down: it moves
//! whenever `vdso/arm64/vdso.c` is recompiled.
//!
//! The C parsed the ELF by casting four structs over the image — a trusted
//! input, so nothing checked anything, and a failure aborted the process with
//! "this should never happen". `crates/kernel/elf`'s `dynsym` decodes it from a
//! slice instead, for the reason that crate exists: every defect it was written
//! for was an offset, and a trusted input is one nobody has looked at since it
//! last changed.

/// The image, page-aligned.
///
/// The alignment is not decoration: `crates/kernel/pagetable` maps this into
/// the guest's address space by address, and a guest page has to begin at one.
/// The C got it from being the only thing in its `__data` section, which is a
/// property of that file rather than a statement about the object.
#[repr(C, align(4096))]
struct Image([u8; VDSO_PAGES * PAGE]);

const VDSO_PAGES: usize = 2;
const PAGE: usize = 4096;

/// The same number as `crates/kernel/taskview`'s, which is what
/// `crates/kernel/execcalls` sizes the guest's mapping from.
///
/// It is a **second rendering of one number**, and until 2026-09-08 what kept
/// the two in step was `build.rs` parsing `#define VDSO_PAGES` out of
/// `kernel/vdso.h` — because `execcalls` read the header through bindgen. It
/// does not; no crate reads a header. So the check is the compiler's, which is
/// where it should have been: a disagreement is a build error rather than a
/// guest shown a different number of pages than the image has.
const _: () = assert!(VDSO_PAGES == taskview::ffi::VDSO_PAGES as usize);

/// The image, embedded.
///
/// The explicit assembler name matters: on Mach-O a Rust `static` would be
/// `_vdso_data`, and `\u{1}` is how it asks for the symbol verbatim.
/// `crates/kernel/pagetable` and `crates/kernel/execcalls` declare the same
/// name to map it, and `crates/fs/proc`'s test stub defines a zeroed one.
///
/// `static` and not `static mut`: the guest maps it read-only, and the C
/// declared it `const char[]`.
#[unsafe(export_name = "\u{1}vdso_data")]
static VDSO_DATA_IMAGE: Image = Image(*include_bytes!(concat!(env!("OUT_DIR"), "/vdso_image.bin")));

/// The image, for the two crates that map it into a guest.
///
/// A Rust call rather than each of them re-declaring `vdso_data` as an
/// `extern "C"` static. That declaration is a dependency edge cargo cannot see,
/// which is the shape `CLAUDE.md` records for C ABI calls between crates -- and
/// here it had the concrete cost the general argument predicts: nothing pulled
/// `kernel-vdso` into a test link, so `cargo test -p kernel-usercopy` failed
/// with `Undefined symbols: vdso_data` and that crate had no runnable tests at
/// all. It also gets the `\u{1}` spelling wrong for free, which is what the two
/// long comments beside those declarations existed to warn about.
pub fn image() -> &'static [u8] {
    &VDSO_DATA_IMAGE.0
}

/// The offset of a dynamic symbol in the VDSO, or 0 if it is not there.
///
/// Zero rather than an error because that is what the C answered and what the
/// one caller checks: `crates/kernel/signaldeliver` refuses to deliver a signal
/// it cannot build a return trampoline for.
///
/// This is a Rust-only helper: no C source, `ffi::` declaration, or embedder
/// header reaches it, so keeping a C-shaped interface here would only add an
/// unnecessary optimization barrier.
pub fn vdso_symbol(name: &[u8]) -> i32 {
    // No `unsafe` to reach the image any more: it is this crate's `static`
    // rather than a symbol from C, so a plain borrow is the whole of it.
    elf::dynsym::value(&VDSO_DATA_IMAGE.0, name).unwrap_or(0) as i32
}

#[cfg(test)]
mod tests {
    use super::vdso_symbol;

    #[test]
    fn a_missing_symbol_answers_zero() {
        assert_eq!(vdso_symbol(b"__shellbox_missing_symbol__"), 0);
    }
}
