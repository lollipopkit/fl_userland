//! Guest image placement and initial stack construction.

use super::*;
use crate::initstack;
use pagetable::memlock::Held;

/// Where the image ended up, for the auxiliary vector.
pub(super) struct Placed {
    /// `AT_PHDR`'s base: the address the file's byte 0 would be at.
    load_addr: u64,
    bias: u64,
    entry: u64,
    interp_base: u64,
}

/// Everything that happens under `mem->lock`: the segments, the vdso, the vvar
/// pages and the two stack pages.
pub(super) fn place_image(
    file: &File,
    path: &CStr,
    image: &Image,
    interp: Option<&(CString, File, Image)>,
) -> Result<Placed, Failed> {
    // `mut`: `load_entry` gives the lock up around its zero-fill, which is
    // `WriteGuard::without` and takes `&mut`.
    let mut held = MemWrite::current().expect("execve runs in an address space");
    let fatal = |e: c_int| Failed::Fatal(e);

    // A reference of the space's own, released with it.
    held.image_mut().exefile = Some(file.share());

    let mut load_addr = 0u64;
    let mut load_addr_set = false;
    let mut bias = 0u64;
    let (mut start_code, mut end_code, mut start_data, mut end_data) = (u64::MAX, 0u64, 0u64, 0u64);

    for seg in &image.segments {
        if seg.kind != elf::PT_LOAD {
            continue;
        }
        if !load_addr_set && image.header.dynamic != 0 {
            // See the giant comment in linux/fs/binfmt_elf.c, around line 950.
            // ARM64: always use dynamic placement, to avoid conflicts with
            // V8's CodeRange hint at 0x574c0000 -- the x86 bias 0x56555000
            // places large binaries like node right on top of it.
            bias = image.find_hole(&mut held);
        }
        load_entry(seg, bias, file, &mut held).map_err(fatal)?;

        let exec = seg.flags & elf::PH_X != 0;
        let end = seg.vaddr.wrapping_add(seg.filesize);
        if exec {
            start_code = start_code.min(seg.vaddr);
            end_code = end_code.max(end);
        }
        start_data = start_data.max(seg.vaddr);
        end_data = end_data.max(end);

        if !load_addr_set {
            load_addr = bias.wrapping_add(seg.vaddr).wrapping_sub(seg.offset);
            load_addr_set = true;
        }
        // We have to know where the brk starts.
        let brk = bias.wrapping_add(seg.vaddr).wrapping_add(seg.memsize);
        let placed = held.image_mut();
        if brk > placed.start_brk {
            let rounded = (brk + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            placed.start_brk = rounded;
            placed.brk = rounded;
        }
    }

    let mut entry = bias.wrapping_add(image.header.entry);
    let at = |v: u64| bias.wrapping_add(v);
    held.image_mut().code = (at(start_code), at(end_code));
    held.image_mut().data = (at(start_data), at(end_data));
    held.image_mut().exe_bias = bias;
    held.image_mut().exe_entry = entry;

    let mut interp_base = 0u64;
    if let Some((_, interp_file, interp_image)) = interp {
        interp_base = interp_image.find_hole(&mut held);
        for seg in interp_image.segments.iter().rev() {
            if seg.kind != elf::PT_LOAD {
                continue;
            }
            load_entry(seg, interp_base, interp_file, &mut held).map_err(fatal)?;
        }
        entry = interp_base.wrapping_add(interp_image.header.entry);
    }

    map_vdso(&mut held)?;
    map_stack(&mut held)?;
    drop(held);

    // The V8 guard pages want the lock again, and want it after the stack: see
    // the function's own comment.
    guard_low_pages(path);

    Ok(Placed {
        load_addr,
        bias,
        entry,
        interp_base,
    })
}

fn map_vdso(held: &mut MemWrite) -> Result<(), Failed> {
    // `crates/kernel/vdso` owns the image; a Rust call rather than a second
    // `extern "C"` declaration of its assembler name, which is a dependency
    // edge cargo cannot see.
    let vdso = kernel_vdso::image();
    let vdso_bytes = vdso.as_ptr();
    let vdso_pages = (vdso.len() as u64) >> ffi::PAGE_BITS;
    debug_assert_eq!(vdso_pages, ffi::VDSO_PAGES as u64);
    // FIXME disgusting hack: musl's dynamic linker has a one-page hole, and I'd
    // rather not put the vdso in that hole. So find a two-page hole and add one.
    let page = held.find_hole(vdso_pages + 1);
    if page == ffi::BAD_PAGE {
        return Err(Failed::Fatal(ENOMEM));
    }
    let page = page + 1;
    // r-x, as Linux maps it. Mapped with no permission bits at all before,
    // which printed `---p` in /proc/<pid>/maps for a region the guest both
    // reads and calls into -- and made the one mapping every process has that
    // is definitely executable look like it was not.
    // SAFETY: the image is this binary's own data and lives for ever; the
    // page table knows not to `munmap` it.
    unsafe { held.map(page, vdso_pages, vdso_bytes.cast_mut().cast(), 0, ffi::P_READ | ffi::P_EXEC) }.map_err(|e| Failed::Fatal(e.as_c_int()))?;
    held.name_region(page, c"[vdso]");
    held.image_mut().vdso = page << ffi::PAGE_BITS;

    // Three empty "vvar" pages, to satisfy ptraceomatic. r--, as Linux maps
    // them, for the same reason as the vdso above.
    let vvar = held.find_hole(ffi::VVAR_PAGES as u64);
    if vvar == ffi::BAD_PAGE {
        return Err(Failed::Fatal(ENOMEM));
    }
    held.map_nothing(vvar, ffi::VVAR_PAGES as u64, ffi::P_READ).map_err(|e| Failed::Fatal(e.as_c_int()))?;
    held.name_region(vvar, c"[vvar]");
    Ok(())
}

fn map_stack(held: &mut MemWrite) -> Result<(), Failed> {
    // ARM64: the stack sits near the top of the 48-bit address space.
    //
    // P_READ too: the stack is rw-p on Linux and this printed `-w-p`, a
    // combination no real kernel produces. The bits are recorded rather than
    // enforced, so this is about what the guest is told.
    held.map_nothing(
        ffi::STACK_INIT_PAGE as u64,
        1,
        ffi::P_READ | ffi::P_WRITE | ffi::P_GROWSDOWN,
    ).map_err(|e| Failed::Fatal(e.as_c_int()))?;
    held.map_nothing(ffi::STACK_TOP_PAGE as u64, 1, ffi::P_READ).map_err(|e| Failed::Fatal(e.as_c_int()))?;
    Ok(())
}

/// The first megabyte, mapped as readable zeros — for `node` only.
///
/// V8's Zone allocator reuses memory without zeroing. Stale data containing V8
/// compressed pointers (small integers like `0x9xxxx`) can leak into real
/// pointer fields; mapping these low pages with zeros means an accidental
/// dereference reads zero instead of faulting. Covers V8 cage offsets
/// 0x80000-0x100000, which are the common stale values.
///
/// Best-effort: a failure here is not a failure of the exec.
fn guard_low_pages(path: &CStr) {
    if basename(path.to_bytes()) != b"node" {
        return;
    }
    let mut held = MemWrite::current().expect("execve runs in an address space");
    let _ = held.map_nothing(0, 0x100000 / PAGE_SIZE, ffi::P_READ | ffi::P_WRITE);
}

/// Everything the guest's stack starts with, written with `mem->lock` released.
pub(super) fn finish_stack(
    path: &CStr,
    argv: &Args,
    envp: &Args,
    image: &Image,
    at: &Placed,
    exec: &kernel_creds::Exec,
) -> Loaded {
    let fatal = |e: c_int| Failed::Fatal(e);
    let mut sp = ffi::STACK_TOP_ADDR as u64;
    // On 32-bit Linux there are 4 empty bytes at the very bottom of the stack;
    // on 64-bit, 8. Make ptraceomatic happy (a major theme in this file).
    sp -= 8;

    // First the strings the pointers will point at: the filename, then the
    // environment, then the arguments.
    let file_addr = push_bytes(&mut sp, path.to_bytes_with_nul()).map_err(fatal)?;
    let envp_addr = push_bytes(&mut sp, envp.bytes()).map_err(fatal)?;
    // The environment block runs from where the copy left the stack pointer up
    // to where it started, which is just below the filename. Recorded because
    // /proc/<pid>/environ is that range and nothing else knows where it is --
    // these two fields existed in `struct mm` and were never written, so the
    // file read back empty. Stored below, with the rest, under the lock.
    let env = (sp, file_addr);
    let argv_addr = push_bytes(&mut sp, argv.bytes()).map_err(fatal)?;
    let argv_range = (sp, env.0);
    sp &= !0xf;

    let platform_addr = push_bytes(&mut sp, b"aarch64\0").map_err(fatal)?;
    // Sixteen random bytes, so no system call is needed to seed a userspace RNG.
    let mut random = [0u8; 16];
    kernel_random::fill(&mut random);
    let random_addr = push_bytes(&mut sp, &random).map_err(fatal)?;

    // The block at the top of the stack -- argc, argv, envp and the auxiliary
    // vector -- is crates/kernel/initstack. It was two independent pieces of
    // arithmetic over one layout: a size computed from the counts, and a
    // pointer walked forward as the contents went in. That is the shape that
    // overflowed a stack buffer in crates/fs/dirent, where a record length was
    // worked out twice and the two disagreed.
    //
    // The pointers are the addresses of the strings just copied: each list is
    // laid out on the stack exactly as it is in the flat buffer, so walking the
    // buffer and the stack together gives one address per string. The C walked
    // *guest* memory with a per-byte user_get to find each terminator.
    let argv_ptrs = string_addrs(argv, argv_addr);
    let envp_ptrs = string_addrs(envp, envp_addr);

    // Which keys the vector has and what each value is: crates/kernel/initstack.
    // It was a table here, and what is *in* it is the part that has been wrong
    // -- AT_UID, AT_EUID, AT_GID and AT_EGID were hard-coded to 0, so
    // getauxval(AT_UID) told a process running as 1000 that it was root, and
    // AT_SECURE beside them, which is the one that matters: libc reads it and,
    // when it is set, ignores LD_PRELOAD and everything else that can redirect
    // a load. Hard-coded to 0, a setuid binary could be handed a library of the
    // caller's choosing.
    // The ids the **new** image runs with, which are committed after this:
    // Linux writes the vector from `bprm->cred`. Read from the task until
    // 2026-11-13, so a set-uid program was told `AT_EUID` was its caller's.
    let c = &exec.creds;
    let (ruid, euid, rgid, egid) = (c.uid(), c.euid(), c.gid(), c.egid());
    let aux = initstack::standard_aux(&initstack::AuxParams {
        // The stack is written with `mem->lock` released; `map_vdso` set this
        // under the write lock, and it is read back under the read lock.
        vdso: pagetable::memlock::ReadGuard::current().map_or(0, |held| held.image().vdso),
        page_size: PAGE_SIZE,
        phdr: at.load_addr.wrapping_add(image.header.phoff),
        phnum: image.header.phnum as u64,
        interp_base: at.interp_base,
        entry: at.bias.wrapping_add(image.header.entry),
        ruid,
        euid,
        rgid,
        egid,
        secure: exec.secure,
        random: random_addr,
        execfn: file_addr,
        platform: platform_addr,
        // The one definition, in crates/kernel/sigframe. This was
        // `SIGFRAME_MAX` in kernel/signal.h with a static_assert pinning it to
        // the crate's three parts -- glibc sizes SIGSTKSZ from AT_MINSIGSTKSZ
        // at run time, so a program sizing a sigaltstack from it would have
        // had it overrun by the frame if the two ever drifted apart. They
        // cannot now.
        sigframe_max: kernel_sigframe::FRAME_SIZE as u64,
    });
    // AT_NULL is the crate's: it cannot be forgotten and cannot be counted
    // twice.
    let aux = aux
        .into_iter()
        .map(|(kind, value)| initstack::Aux { kind, value })
        .collect();
    let layout = initstack::Layout::new(argv_ptrs, envp_ptrs, aux);

    // One size, and the buffer is that size, so the encode cannot fail for want
    // of room.
    sp = layout.sp_for(sp);
    let mut bytes = Vec::new();
    bytes
        .try_reserve(layout.size())
        .map_err(|_| fatal(ENOMEM))?;
    bytes.resize(layout.size(), 0);
    if !layout.encode(&mut bytes) {
        return Err(fatal(ENOMEM));
    }
    if usercopy::GuestMem.write(sp, &bytes) != 0 {
        return Err(fatal(EFAULT));
    }
    mmapcalls::mm::record_stack_ranges(mmapcalls::mm::StackRanges {
        argv: argv_range,
        env,
        auxv: (
            sp + layout.auxv_offset() as u64,
            sp + (layout.auxv_offset() + layout.auxv_bytes()) as u64,
        ),
        stack_start: sp,
    });

    // The CPU. Every general-purpose register is zeroed: a new image inherits
    // nothing, and what was in them belonged to the program that is gone.
    // Field writes through the pointer, not a `&mut cpu_state`: a signal
    // sender on another thread stores to `_poked` through `poked_ptr`.
    let cpu = taskview::current_cpu();
    unsafe {
        (*cpu).sp = sp;
        (*cpu).pc = at.entry;
        (*cpu).regs = [0; 31];
        (*cpu).nzcv = 0;
        (*cpu).dit = false;
        (*cpu).nf = 0;
        (*cpu).zf = 0;
        (*cpu).cf = 0;
        (*cpu).vf = 0;
        // The default rounding mode, in the hardware as well as in cpu_state.
        taskview::cpu::fp_reset(cpu);
    }
    Ok(())
}

/// Copies bytes onto the stack below `sp` and answers where they landed.
fn push_bytes(sp: &mut u64, bytes: &[u8]) -> Result<u64, c_int> {
    *sp -= bytes.len() as u64;
    if usercopy::GuestMem.write(*sp, bytes) != 0 {
        return Err(EFAULT);
    }
    Ok(*sp)
}

/// One guest address per string in a flat list just copied to `base`.
///
/// The strings are contiguous in both places and in the same order, so the
/// offsets within the buffer are the offsets on the stack. The C read them back
/// out of guest memory one byte at a time to find each terminator.
pub(super) fn string_addrs(args: &Args, base: u64) -> Vec<u64> {
    let mut out = Vec::with_capacity(args.count);
    let mut at = 0usize;
    for _ in 0..args.count {
        out.push(base + at as u64);
        match args.bytes()[at..].iter().position(|&b| b == 0) {
            Some(end) => at += end + 1,
            None => break,
        }
    }
    out
}

pub(super) fn basename(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}
