//! An ELF whose segments land outside the guest address space must be refused.
//!
//! `load_entry` calls `fd->ops->mmap` directly rather than going through
//! `do_mmap`, so `do_mmap`'s bound check never runs -- and `mem_pt` *masks* the
//! page number, so a `p_vaddr` above 2^48 does not fail, it aliases onto a
//! lower page. The loader then silently maps the segment somewhere other than
//! where the file asked, over whatever is already there.

use guest_tests::{Harness, check, cpath};

const EM_AARCH64: u16 = 183;
const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;
const PF_R: u32 = 4;
const PF_X: u32 = 1;
const PT_INTERP: u32 = 3;

fn make_elf(vaddr: u64, memsize: u64) -> Vec<u8> {
    make_elf_interp(vaddr, memsize, None)
}

/// A minimal aarch64 ELF with one PT_LOAD at `vaddr` of `memsize` bytes, and
/// optionally a PT_INTERP naming `interp`.
fn make_elf_interp(vaddr: u64, memsize: u64, interp: Option<&str>) -> Vec<u8> {
    let phoff: u64 = 64;
    let phentsize: u16 = 56;
    let mut e = Vec::new();
    e.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    e.extend_from_slice(&ET_EXEC.to_le_bytes());      // e_type
    e.extend_from_slice(&EM_AARCH64.to_le_bytes());   // e_machine
    e.extend_from_slice(&1u32.to_le_bytes());         // e_version
    e.extend_from_slice(&vaddr.to_le_bytes());        // e_entry
    e.extend_from_slice(&phoff.to_le_bytes());        // e_phoff
    e.extend_from_slice(&0u64.to_le_bytes());         // e_shoff
    e.extend_from_slice(&0u32.to_le_bytes());         // e_flags
    e.extend_from_slice(&64u16.to_le_bytes());        // e_ehsize
    e.extend_from_slice(&phentsize.to_le_bytes());    // e_phentsize
    e.extend_from_slice(&(if interp.is_some() { 2u16 } else { 1u16 }).to_le_bytes()); // e_phnum
    e.extend_from_slice(&0u16.to_le_bytes());         // e_shentsize
    e.extend_from_slice(&0u16.to_le_bytes());         // e_shnum
    e.extend_from_slice(&0u16.to_le_bytes());         // e_shstrndx
    assert_eq!(e.len(), 64);

    // One PT_LOAD, file offset 0, so the header itself is the content.
    e.extend_from_slice(&PT_LOAD.to_le_bytes());
    e.extend_from_slice(&(PF_R | PF_X).to_le_bytes());
    e.extend_from_slice(&0u64.to_le_bytes());         // p_offset
    e.extend_from_slice(&vaddr.to_le_bytes());        // p_vaddr
    e.extend_from_slice(&vaddr.to_le_bytes());        // p_paddr
    e.extend_from_slice(&0x1000u64.to_le_bytes());    // p_filesz
    e.extend_from_slice(&memsize.to_le_bytes());      // p_memsz
    e.extend_from_slice(&0x1000u64.to_le_bytes());    // p_align
    assert_eq!(e.len(), 120);

    if let Some(path) = interp {
        const INTERP_OFF: u64 = 0x200;
        e.extend_from_slice(&PT_INTERP.to_le_bytes());
        e.extend_from_slice(&PF_R.to_le_bytes());
        e.extend_from_slice(&INTERP_OFF.to_le_bytes());          // p_offset
        e.extend_from_slice(&0u64.to_le_bytes());                // p_vaddr
        e.extend_from_slice(&0u64.to_le_bytes());                // p_paddr
        let n = path.len() as u64 + 1;
        e.extend_from_slice(&n.to_le_bytes());                   // p_filesz
        e.extend_from_slice(&n.to_le_bytes());                   // p_memsz
        e.extend_from_slice(&1u64.to_le_bytes());                // p_align
        e.resize(INTERP_OFF as usize, 0);
        e.extend_from_slice(path.as_bytes());
        e.push(0);
    }
    e.resize(0x1000, 0);
    e
}

/// Writes `bytes` as an executable and execs it in a child. Returns
/// (exited, status, signal). A child that reaches `_exit(99)` means execve
/// refused the file, which is the outcome under test.
fn try_exec(h: &mut Harness, name: &str, bytes: &[u8]) -> (bool, i32, i32) {
    let path = format!("/tmp/{name}");
    std::fs::write(&path, bytes).expect("write the elf");
    let cpath = cpath(&path);
    unsafe { libc::chmod(cpath.as_ptr(), 0o755) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            // Bound, not a temporary. `[cpath(&path).as_ptr(), null()]` drops
            // the CString at the end of that statement, so execv read argv[0]
            // out of freed memory -- which held the right bytes often enough
            // that the test passed.
            let argv = [cpath.as_ptr(), std::ptr::null()];
            libc::execv(cpath.as_ptr(), argv.as_ptr());
            libc::_exit(99);
        }
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    let _ = h;
    (
        libc::WIFEXITED(st),
        if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 },
        if libc::WIFSIGNALED(st) { libc::WTERMSIG(st) } else { 0 },
    )
}

fn main() {
    let mut h = Harness::new();

    h.group("vaddr-outside-the-address-space");
    // Page numbers are 36 bits here, so this is above every address a guest
    // has, and masking turns it into page 0x10 -- somewhere quite real.
    let (exited, status, sig) = try_exec(&mut h, "elf_high_vaddr",
        &make_elf(1u64 << 48 | 0x10000, 0x1000));
    check!(h, exited && status == 99,
        "an ELF loaded above the address space is refused: exited={exited} status={status} sig={sig}");

    h.group("memsize-runs-off-the-end");
    // A vaddr inside the space whose bss carries it out of the top.
    let (exited, status, sig) = try_exec(&mut h, "elf_big_memsz",
        &make_elf(0x400000, u64::MAX - 0x400000 - 0x1000));
    check!(h, exited && status == 99,
        "an ELF whose bss leaves the address space is refused: exited={exited} status={status} sig={sig}");

    // The other side of the same check: 4 GiB of bss at a low vaddr is *inside*
    // the address space, so it must be loaded rather than refused. The image
    // then dies on its garbage entry point, which is the program's problem and
    // not the loader's -- what matters is that execve committed to it.
    //
    // This began as a third "must be refused" case and was wrong: a bss that
    // large is legal. It is worth more as the control, because a bounds check
    // written slightly too tight would pass all of the above and fail here.
    let (exited, status, sig) = try_exec(&mut h, "elf_4g_bss",
        &make_elf(0x400000, (1u64 << 32) + 0x2000));
    check!(h, !(exited && status == 99),
        "a 4GiB bss inside the address space is not refused: exited={exited} status={status} sig={sig}");

    h.group("interpreter-is-checked-too");
    // The interpreter is named *by the executable*, so a crafted image chooses
    // it -- and its segments are loaded through the same load_entry, after the
    // point of no return. The pre-commit check covers it because its program
    // headers are read before the mm is replaced.
    let bad_interp = "/tmp/elf_bad_interp";
    std::fs::write(bad_interp, make_elf(1u64 << 48 | 0x20000, 0x1000)).expect("write interp");
    unsafe { libc::chmod(cpath(bad_interp).as_ptr(), 0o755) };
    let (exited, status, sig) = try_exec(&mut h, "elf_uses_bad_interp",
        &make_elf_interp(0x400000, 0x1000, Some(bad_interp)));
    check!(h, exited && status == 99,
        "an image whose interpreter does not fit is refused: exited={exited} status={status} sig={sig}");
    let _ = std::fs::remove_file(bad_interp);

    h.group("a-real-binary-still-runs");
    // The control. All of the above are satisfied by an execve that refuses
    // every file.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            let p = cpath("/bin/true");
            let argv = [p.as_ptr(), std::ptr::null()];
            libc::execv(p.as_ptr(), argv.as_ptr());
            libc::_exit(99);
        }
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
        "/bin/true still execs and exits 0: status={:?}", libc::WEXITSTATUS(st));

    for n in ["elf_high_vaddr", "elf_big_memsz", "elf_4g_bss"] {
        let _ = std::fs::remove_file(format!("/tmp/{n}"));
    }
    std::process::exit(h.finish());
}
