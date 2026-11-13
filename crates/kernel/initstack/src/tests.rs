//! Tests for auxiliary vectors and initial process stack layout.

use super::*;

fn params() -> AuxParams {
    AuxParams {
        vdso: 0x7000,
        page_size: 0x1000,
        phdr: 0x400040,
        phnum: 9,
        interp_base: 0x800000,
        entry: 0x401000,
        ruid: 1000,
        euid: 1000,
        rgid: 1000,
        egid: 1000,
        secure: false,
        random: 0xffff_0000,
        execfn: 0xffff_0100,
        platform: 0xffff_0200,
        sigframe_max: 4672,
    }
}

fn value_of(v: &[(u64, u64)], key: u64) -> Option<u64> {
    v.iter().find(|(k, _)| *k == key).map(|(_, val)| *val)
}

/// The ids are the caller's, not zero.
///
/// `AT_UID`, `AT_EUID`, `AT_GID` and `AT_EGID` were hard-coded, so
/// `getauxval(AT_UID)` told a process running as 1000 that it was root.
#[test]
fn the_ids_are_the_ones_the_image_runs_with() {
    let mut p = params();
    p.ruid = 1000;
    p.euid = 0;
    p.rgid = 1000;
    p.egid = 50;
    let v = standard_aux(&p);
    assert_eq!(value_of(&v, AX_UID), Some(1000));
    assert_eq!(value_of(&v, AX_EUID), Some(0));
    assert_eq!(value_of(&v, AX_GID), Some(1000));
    assert_eq!(value_of(&v, AX_EGID), Some(50));
}

/// `AT_SECURE` is the exec's answer rather than a constant, and not the ids'
/// alone: a file-capability exec changes no id and is secure (`caps_probe`).
/// The rule is `crates/kernel/creds`' `Creds::exec`.
#[test]
fn at_secure_is_what_the_exec_says() {
    let mut p = params();
    assert_eq!(value_of(&standard_aux(&p), AX_SECURE), Some(0));
    p.secure = true;
    assert_eq!(value_of(&standard_aux(&p), AX_SECURE), Some(1));
}

/// The two keys that are deliberately absent stay absent.
///
/// A comment saying "deliberately not here" is reversed by the next person
/// to add a key; this is not.
#[test]
fn the_rseq_keys_are_not_advertised() {
    let v = standard_aux(&params());
    assert_eq!(value_of(&v, AX_RSEQ_FEATURE_SIZE), None);
    assert_eq!(value_of(&v, AX_RSEQ_ALIGN), None);
}

/// Every key appears once, and `AT_NULL` is not among them — the builder
/// puts that on, so a table carrying one would end the vector early.
#[test]
fn no_key_is_written_twice_and_none_is_at_null() {
    let v = standard_aux(&params());
    let mut keys: Vec<u64> = v.iter().map(|(k, _)| *k).collect();
    let before = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), before, "a key is written twice");
    assert!(!keys.contains(&0), "AT_NULL is the builder's");
}

/// `AT_PHENT` is the ELF program header size, from the crate that reads it
/// out of the file — not a 56 written out beside the vector.
#[test]
fn at_phent_is_the_size_the_parser_checks() {
    assert_eq!(value_of(&standard_aux(&params()), AX_PHENT), Some(56));
    assert_eq!(elf::PHDR_SIZE, 56);
}

/// `AT_MINSIGSTKSZ` is the signal frame rounded **up** to a page.
///
/// glibc sizes `SIGSTKSZ` from it; a value below the frame this kernel
/// writes means a program's `sigaltstack` is overrun by the frame.
#[test]
fn at_minsigstksz_covers_the_frame() {
    let mut p = params();
    p.sigframe_max = 4672;
    assert_eq!(value_of(&standard_aux(&p), AX_MINSIGSTKSZ), Some(8192));
    p.sigframe_max = 4096;
    assert_eq!(
        value_of(&standard_aux(&p), AX_MINSIGSTKSZ),
        Some(4096),
        "an exact page is not rounded to the next one"
    );
    assert!(value_of(&standard_aux(&p), AX_MINSIGSTKSZ).unwrap() >= p.sigframe_max);
}

fn read(out: &[u8], word: usize) -> u64 {
    u64::from_le_bytes(out[word * PTR..(word + 1) * PTR].try_into().unwrap())
}

#[test]
fn the_size_is_what_the_encode_writes() {
    // The property the two-places arithmetic did not have. `encode`'s
    // debug_assert says the same from the inside.
    for (argc, envc, auxc) in [(0, 0, 0), (1, 0, 0), (0, 1, 0), (3, 5, 7), (100, 100, 20)] {
        let l = Layout::new(
            vec![0x1000; argc],
            vec![0x2000; envc],
            vec![
                Aux {
                    kind: at::PAGESZ,
                    value: 4096
                };
                auxc
            ],
        );
        let mut out = vec![0u8; l.size()];
        assert!(l.encode(&mut out), "{argc}/{envc}/{auxc}");
    }
}

#[test]
fn a_buffer_one_byte_short_is_refused() {
    let l = Layout::new(vec![1], vec![2], vec![]);
    let mut out = vec![0u8; l.size() - 1];
    assert!(!l.encode(&mut out));
}

#[test]
fn the_order_is_argc_argv_null_envp_null_auxv() {
    let l = Layout::new(
        vec![0xa1, 0xa2],
        vec![0xe1],
        vec![Aux {
            kind: at::PAGESZ,
            value: 4096,
        }],
    );
    let mut out = vec![0u8; l.size()];
    assert!(l.encode(&mut out));

    assert_eq!(read(&out, 0), 2, "argc");
    assert_eq!(read(&out, 1), 0xa1);
    assert_eq!(read(&out, 2), 0xa2);
    assert_eq!(read(&out, 3), 0, "argv's terminator");
    assert_eq!(read(&out, 4), 0xe1);
    assert_eq!(read(&out, 5), 0, "envp's terminator");
    assert_eq!(read(&out, 6), at::PAGESZ);
    assert_eq!(read(&out, 7), 4096);
    assert_eq!(read(&out, 8), at::NULL, "and AT_NULL closes it");
    assert_eq!(read(&out, 9), 0);
}

/// `argc` of zero is a thing a guest can ask for — `execve(path, {NULL},
/// env)` — and it crashed the emulator once. The layout for it is the same
/// shape with nothing between `argc` and its terminator.
#[test]
fn an_empty_argv_is_a_layout() {
    let l = Layout::new(vec![], vec![], vec![]);
    let mut out = vec![0u8; l.size()];
    assert!(l.encode(&mut out));
    assert_eq!(read(&out, 0), 0, "argc");
    assert_eq!(read(&out, 1), 0, "argv's terminator");
    assert_eq!(read(&out, 2), 0, "envp's");
    assert_eq!(read(&out, 3), at::NULL);
    assert_eq!(l.size(), 5 * PTR);
}

#[test]
fn at_null_is_added_and_not_counted_twice() {
    let one = Layout::new(vec![], vec![], vec![]);
    let two = Layout::new(
        vec![],
        vec![],
        vec![Aux {
            kind: at::PAGESZ,
            value: 4096,
        }],
    );
    assert_eq!(two.size() - one.size(), 2 * PTR, "one entry, two words");
}

// ------------------------------------------------------------ alignment

#[test]
fn sp_is_sixteen_byte_aligned() {
    for argc in 0..8 {
        for below in [0x8000_0000u64, 0x8000_0001, 0x8000_000f, 0x7fff_fff9] {
            let l = Layout::new(vec![0; argc], vec![], vec![]);
            let sp = l.sp_for(below);
            assert_eq!(sp % 16, 0, "argc {argc}, below {below:#x}");
            assert!(sp + l.size() as u64 <= below || below < l.size() as u64);
        }
    }
}

#[test]
fn sp_does_not_wrap_below_zero() {
    let l = Layout::new(vec![0; 100], vec![], vec![]);
    assert_eq!(l.sp_for(8), 0);
}

#[test]
fn the_auxv_range_is_where_encode_puts_it() {
    let l = Layout::new(
        vec![1, 2, 3],
        vec![4, 5],
        vec![Aux {
            kind: at::ENTRY,
            value: 0xdead,
        }],
    );
    let mut out = vec![0u8; l.size()];
    l.encode(&mut out);
    let off = l.auxv_offset();
    assert_eq!(off % PTR, 0);
    assert_eq!(
        u64::from_le_bytes(out[off..off + PTR].try_into().unwrap()),
        at::ENTRY,
        "the offset lands on the first auxv type"
    );
    assert_eq!(
        off + l.auxv_bytes(),
        l.size(),
        "and the range ends the block"
    );
}
