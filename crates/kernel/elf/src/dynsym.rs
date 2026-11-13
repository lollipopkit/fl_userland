//! Finding a symbol in a dynamic ELF object, from its bytes.
//!
//! One caller: the built-in VDSO, whose `__kernel_rt_sigreturn` the signal
//! frame's return trampoline points at. That is a *trusted* input — the image
//! is compiled in — which is why the C that did this cast four structs straight
//! over the bytes and read them.
//!
//! It is decoded from a slice here for the reason the rest of this crate
//! exists: the parse is the same parse, the checks cost nothing on an image
//! this size, and a trusted input is one nobody has thought about since the
//! last time it changed. Every defect this crate was written for was an offset.
//!
//! # `d_val` is read as a file offset
//!
//! `DT_STRTAB`, `DT_SYMTAB` and `DT_HASH` hold *virtual addresses*. Treating one
//! as an offset into the file is right only when the object is linked so that
//! the two agree, which a VDSO is — it is one `PT_LOAD` at vaddr 0. The C did
//! the same without saying so; this says so, and answers `None` rather than
//! reading out of bounds when it does not hold.

use crate::{PHDR_SIZE, parse_header, u32_at, u64_at};

/// `PT_DYNAMIC`.
const PT_DYNAMIC: u32 = 2;

const DT_NULL: u64 = 0;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;

/// One `Elf64_Dyn`: a tag and a value, both 64 bits.
const DYN_SIZE: usize = 16;
/// One `Elf64_Sym`: `st_name` (4), `st_info` (1), `st_other` (1), `st_shndx`
/// (2), `st_value` (8), `st_size` (8).
const SYM_SIZE: usize = 24;
const SYM_NAME: usize = 0;
const SYM_VALUE: usize = 8;

/// A slice of `len` bytes at `at`, or `None` if the object does not have them.
fn at(bytes: &[u8], offset: u64, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    bytes.get(start..start.checked_add(len)?)
}

/// The value of the dynamic symbol called `name`, or `None`.
///
/// `name` is compared as bytes and must not contain a NUL.
pub fn value(bytes: &[u8], name: &[u8]) -> Option<u64> {
    let header = parse_header(bytes).ok()?;

    // The one `PT_DYNAMIC` program header.
    let mut dynamic = None;
    for i in 0..header.phnum as usize {
        let ph = at(bytes, header.phoff + (i * PHDR_SIZE) as u64, PHDR_SIZE)?;
        if u32_at(ph, 0) == PT_DYNAMIC {
            dynamic = Some(u64_at(ph, 8));
            break;
        }
    }
    let dynamic = dynamic?;

    // Its entries, until `DT_NULL`. Bounded by the object's length as well:
    // a table with no terminator would otherwise walk off the end.
    let (mut strtab, mut symtab, mut hash) = (None, None, None);
    let mut off = dynamic;
    loop {
        let ent = at(bytes, off, DYN_SIZE)?;
        let tag = u64_at(ent, 0);
        let val = u64_at(ent, 8);
        match tag {
            DT_NULL => break,
            DT_STRTAB => strtab = Some(val),
            DT_SYMTAB => symtab = Some(val),
            DT_HASH => hash = Some(val),
            _ => {}
        }
        off += DYN_SIZE as u64;
    }
    let (strtab, symtab, hash) = (strtab?, symtab?, hash?);

    // The hash table's second word is `nchain`, which is the number of symbol
    // table entries — the one place the count is written down at all. See
    // <https://flapenguin.me/elf-dt-hash>.
    let nsyms = u32_at(at(bytes, hash + 4, 4)?, 0);

    for i in 0..nsyms as usize {
        let sym = at(bytes, symtab + (i * SYM_SIZE) as u64, SYM_SIZE)?;
        let name_off = u32_at(sym, SYM_NAME);
        let start = usize::try_from(strtab).ok()? + name_off as usize;
        let tail = bytes.get(start..)?;
        let len = tail.iter().position(|&b| b == 0)?;
        if &tail[..len] == name {
            return Some(u64_at(sym, SYM_VALUE));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal `ET_DYN` aarch64 object with one `PT_DYNAMIC`, a hash table,
    /// a string table and two symbols. Built by hand so the test does not need
    /// a linker, and so that every offset in it is written down once.
    fn object(symbols: &[(&str, u64)]) -> Vec<u8> {
        const EHDR: usize = 64;
        let phoff = EHDR;
        let dynoff = phoff + PHDR_SIZE;
        let hashoff = dynoff + 4 * DYN_SIZE;
        let symoff = hashoff + 8;
        let stroff = symoff + (symbols.len() + 1) * SYM_SIZE;

        let mut strings = vec![0u8];
        let mut name_offsets = Vec::new();
        for (name, _) in symbols {
            name_offsets.push(strings.len() as u32);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }

        let mut b = vec![0u8; stroff + strings.len()];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // ELFCLASS64
        b[5] = 1; // little endian
        b[6] = 1; // version
        b[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        b[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
        b[32..40].copy_from_slice(&(phoff as u64).to_le_bytes()); // e_phoff
        b[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

        b[phoff..phoff + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        b[phoff + 8..phoff + 16].copy_from_slice(&(dynoff as u64).to_le_bytes());

        let mut put_dyn = |i: usize, tag: u64, val: u64| {
            let o = dynoff + i * DYN_SIZE;
            b[o..o + 8].copy_from_slice(&tag.to_le_bytes());
            b[o + 8..o + 16].copy_from_slice(&val.to_le_bytes());
        };
        put_dyn(0, DT_STRTAB, stroff as u64);
        put_dyn(1, DT_SYMTAB, symoff as u64);
        put_dyn(2, DT_HASH, hashoff as u64);
        put_dyn(3, DT_NULL, 0);

        // nbucket, then nchain -- which is the symbol count, including the
        // reserved entry zero.
        b[hashoff..hashoff + 4].copy_from_slice(&1u32.to_le_bytes());
        b[hashoff + 4..hashoff + 8].copy_from_slice(&((symbols.len() + 1) as u32).to_le_bytes());

        for (i, ((_, value), name_off)) in symbols.iter().zip(&name_offsets).enumerate() {
            let o = symoff + (i + 1) * SYM_SIZE;
            b[o..o + 4].copy_from_slice(&name_off.to_le_bytes());
            b[o + 8..o + 16].copy_from_slice(&value.to_le_bytes());
        }
        b[stroff..].copy_from_slice(&strings);
        b
    }

    /// The one thing this is for, and a name that is not there.
    #[test]
    fn a_symbol_is_found_by_name() {
        let o = object(&[
            ("__kernel_rt_sigreturn", 0x7c0),
            ("__kernel_clock_gettime", 0x800),
        ]);
        assert_eq!(value(&o, b"__kernel_rt_sigreturn"), Some(0x7c0));
        assert_eq!(value(&o, b"__kernel_clock_gettime"), Some(0x800));
        assert_eq!(value(&o, b"__kernel_nothing"), None);
        // A prefix is not a match: the comparison is over the whole name, and
        // the C's `strcmp` was too. A `starts_with` here would answer the first
        // symbol for every shorter name.
        assert_eq!(value(&o, b"__kernel_rt_sig"), None);
    }

    /// Every way the object can be wrong answers `None` rather than reading
    /// past its end. The C aborted the process for the first of these and
    /// dereferenced for the rest.
    #[test]
    fn a_malformed_object_is_refused_rather_than_read_past() {
        let good = object(&[("x", 1)]);
        assert_eq!(value(&good, b"x"), Some(1));

        // No PT_DYNAMIC: the program header becomes a PT_LOAD.
        let mut o = good.clone();
        o[64..68].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(value(&o, b"x"), None);

        // A dynamic table pointing past the end.
        let mut o = good.clone();
        o[72..80].copy_from_slice(&0xffff_ffffu64.to_le_bytes());
        assert_eq!(value(&o, b"x"), None);

        // Truncated: everything after the header is gone.
        assert_eq!(value(&good[..70], b"x"), None);
        assert_eq!(value(&[], b"x"), None);

        // A symbol count larger than the table.
        let mut o = good.clone();
        let hashoff = 64 + PHDR_SIZE + 4 * DYN_SIZE;
        o[hashoff + 4..hashoff + 8].copy_from_slice(&9999u32.to_le_bytes());
        assert_eq!(value(&o, b"not-there"), None);
    }
}
