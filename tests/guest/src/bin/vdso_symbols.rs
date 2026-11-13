//! That the vDSO the kernel mapped is a real ELF with the four symbols a libc
//! looks for, and that calling one of them works.
//!
//! # Why this exists
//!
//! Nothing checked. The vDSO image was built by whichever clang the machine had
//! that could target `aarch64-linux-gnu`, and when there was none the build
//! **`touch`ed an empty file** and carried on. Replacing
//! `build/vdso/arm64/libvdso.so.elf` with zero bytes and rebuilding changed
//! nothing any test could see: `auxv_abi` still passed 26 checks and the shell
//! still ran, because every binary in the rootfs is statically linked musl and
//! never asks.
//!
//! A dynamically linked glibc program does ask, and a process whose
//! `__kernel_rt_sigreturn` is missing cannot return from a signal handler. So
//! this walks the mapped image the way a libc does — `AT_SYSINFO_EHDR`, program
//! headers, `PT_DYNAMIC`, `DT_HASH`, `DT_SYMTAB` — and calls what it finds.
//!
//! It runs against a real kernel in `differential.sh` too, where it is checking
//! Linux's own vDSO. That is the point: the same four symbols, looked up the
//! same way.

use guest_tests::{check, Harness};

/// `AT_SYSINFO_EHDR`, where the kernel says it put the image.
const AT_SYSINFO_EHDR: libc::c_ulong = 33;

const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;

/// Read a `T` out of the mapped image.
///
/// # Safety
/// `at` is inside the vDSO mapping, which is `PROT_READ`.
unsafe fn peek<T: Copy>(at: usize) -> T {
    // SAFETY: the caller's contract; unaligned because a program header's
    // fields are only guaranteed 8-byte aligned relative to the file.
    unsafe { (at as *const T).read_unaligned() }
}

/// The NUL-terminated name at `strtab + offset`.
///
/// # Safety
/// As [`peek`], and the string is NUL-terminated inside the mapping.
unsafe fn name_at(strtab: usize, offset: u32) -> &'static [u8] {
    // SAFETY: the caller's contract.
    unsafe {
        let p = (strtab + offset as usize) as *const u8;
        let mut n = 0;
        while *p.add(n) != 0 && n < 256 {
            n += 1;
        }
        core::slice::from_raw_parts(p, n)
    }
}

/// Every dynamic symbol in the image, as `(name, address)`.
///
/// # Safety
/// `base` is a mapped ELF image.
unsafe fn dynamic_symbols(base: usize) -> Vec<(Vec<u8>, usize)> {
    // SAFETY: the caller's contract, for the whole body.
    unsafe {
        // Ehdr: e_phoff at 0x20, e_phentsize at 0x36, e_phnum at 0x38.
        let phoff: u64 = peek(base + 0x20);
        let phentsize: u16 = peek(base + 0x36);
        let phnum: u16 = peek(base + 0x38);

        let mut dynamic = 0usize;
        for i in 0..phnum as usize {
            let ph = base + phoff as usize + i * phentsize as usize;
            let p_type: u32 = peek(ph);
            if p_type == PT_DYNAMIC {
                // p_vaddr at 0x10, relative to the load base.
                let vaddr: u64 = peek(ph + 0x10);
                dynamic = base + vaddr as usize;
                break;
            }
        }
        if dynamic == 0 {
            return Vec::new();
        }

        let (mut strtab, mut symtab, mut hash) = (0usize, 0usize, 0usize);
        let mut at = dynamic;
        loop {
            let tag: i64 = peek(at);
            let val: u64 = peek(at + 8);
            match tag {
                DT_NULL => break,
                // The three are already absolute for a vDSO, which is mapped at
                // the address the linker laid it out relative to -- so add the
                // base only when the value is smaller than it.
                DT_STRTAB => strtab = absolute(base, val),
                DT_SYMTAB => symtab = absolute(base, val),
                DT_HASH => hash = absolute(base, val),
                _ => {}
            }
            at += 16;
        }
        if strtab == 0 || symtab == 0 || hash == 0 {
            return Vec::new();
        }

        // A SysV hash table's second word is `nchain`, which is the number of
        // entries in the symbol table -- the one place that count is written
        // down. `--hash-style=sysv` in the link is what puts it there.
        let nchain: u32 = peek(hash + 4);

        let mut out = Vec::new();
        for i in 1..nchain as usize {
            // Sym64: st_name u32 at 0, st_value u64 at 8.
            let sym = symtab + i * 24;
            let st_name: u32 = peek(sym);
            let st_value: u64 = peek(sym + 8);
            if st_name == 0 {
                continue;
            }
            out.push((name_at(strtab, st_name).to_vec(), base + st_value as usize));
        }
        out
    }
}

/// A `DT_*` address, which is a link-time virtual address and so already has
/// the base in it when the image was laid out at a nonzero one.
fn absolute(base: usize, value: u64) -> usize {
    let value = value as usize;
    if value < base { base + value } else { value }
}

type ClockGettime = unsafe extern "C" fn(i32, *mut libc::timespec) -> i32;

fn main() {
    let mut h = Harness::new();
    h.group("vdso");

    // SAFETY: no arguments.
    let base = unsafe { libc::getauxval(AT_SYSINFO_EHDR) } as usize;
    check!(h, base != 0, "AT_SYSINFO_EHDR names a mapping: {base:#x}");
    if base == 0 {
        std::process::exit(h.finish());
    }

    // SAFETY: `base` is what the kernel says it mapped.
    let magic: [u8; 4] = unsafe { peek(base) };
    check!(
        h,
        magic == *b"\x7fELF",
        "and it starts with an ELF header: {magic:?}"
    );
    if magic != *b"\x7fELF" {
        // An empty image reads as four zero bytes here, which is exactly the
        // failure this test exists for. Stop rather than walk it.
        std::process::exit(h.finish());
    }

    // SAFETY: as above.
    let symbols = unsafe { dynamic_symbols(base) };
    check!(h, !symbols.is_empty(), "the image has a dynamic symbol table");

    let find = |want: &str| {
        symbols
            .iter()
            .find(|(n, _)| n == want.as_bytes())
            .map(|(_, a)| *a)
    };

    for want in [
        "__kernel_rt_sigreturn",
        "__kernel_clock_gettime",
        "__kernel_gettimeofday",
        "__kernel_clock_getres",
    ] {
        check!(h, find(want).is_some(), "the vDSO exports {want}");
    }

    // And one of them actually runs. `CLOCK_MONOTONIC` rather than
    // `CLOCK_REALTIME`, so the comparison below cannot be crossed by the wall
    // clock moving.
    if let Some(addr) = find("__kernel_clock_gettime") {
        // SAFETY: the address of a function in an executable mapping, with the
        // signature the ABI gives it.
        let f: ClockGettime = unsafe { std::mem::transmute::<usize, ClockGettime>(addr) };
        let mut via_vdso: libc::timespec = unsafe { std::mem::zeroed() };
        let mut via_syscall: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: two live `timespec`s.
        let r = unsafe { f(libc::CLOCK_MONOTONIC, &mut via_vdso) };
        // SAFETY: as above.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut via_syscall) };

        check!(h, r == 0, "__kernel_clock_gettime returns 0: {r}");
        check!(
            h,
            via_vdso.tv_sec > 0 || via_vdso.tv_nsec > 0,
            "and fills the timespec: {}.{:09}",
            via_vdso.tv_sec,
            via_vdso.tv_nsec
        );
        // Read before the syscall, so it must not be later than it. A minute of
        // slack, because the two are not required to be the same clock source
        // on a host and this is checking that both are *a* monotonic clock.
        let vdso_ns = via_vdso.tv_sec as i128 * 1_000_000_000 + i128::from(via_vdso.tv_nsec);
        let sys_ns = via_syscall.tv_sec as i128 * 1_000_000_000 + i128::from(via_syscall.tv_nsec);
        check!(
            h,
            vdso_ns <= sys_ns && sys_ns - vdso_ns < 60_000_000_000,
            "and agrees with the syscall: vdso {vdso_ns} vs syscall {sys_ns}"
        );
    }

    std::process::exit(h.finish());
}
