//! The three interrupt arms that are not dispatch: a memory fault, a
//! breakpoint, and an encoding the JIT had no gadget for.
//!
//! These were the last of `kernel/calls.c`. They were left in C on the grounds
//! that they read `struct cpu_state` and so belonged with `emu/` in step 6;
//! `crates/kernel/signaldeliver::receive` disposed of that argument on
//! 2026-09-02, because the struct is *generated* and what its layout is a
//! contract with is the gadgets, not this.
//!
//! # A recovery is a decision, and every one of them is off by default
//!
//! A fault this emulator can resolve is one it caused: `mmap` leaves unmapped
//! gaps where a native heap is contiguous, so an access one past an allocation
//! faults here and would not on Linux. A fault it cannot resolve belongs to the
//! guest, and answering it with anything but `SIGSEGV` breaks every program
//! that relies on the signal — a garbage collector's write barrier, an
//! allocator's use-after-free check, a runtime's guard page.
//!
//! Three recoveries were written for node and all three are behind a switch
//! now, so the default path is: fix up the fault address for an
//! instruction-fetch fault, refuse to spin, and deliver the signal.
//!
//! - [`recover_read`] answers a *read* of an unmapped page by zeroing the
//!   load's destination and stepping over it. `IUL_READ_FAULT_RECOVERY`.
//! - [`demand_map`] answers a fault on an unmapped page by mapping one.
//!   `IUL_READ_FAULT_RECOVERY` for a read, `IUL_V8_FAULT_RECOVERY` for a write.
//!
//! **A third was deleted rather than moved.** `handle_int_gpf` carried some
//! three hundred lines that unwound the guest's frame-pointer chain on a
//! sentinel-pointer fault, scanned backwards from a return address for `STP`
//! instructions to recover callee-saved registers, forged `x0`, `x19`–`x22`,
//! `sp`, `x29` and `pc`, and returned into a frame it had chosen. Every gate on
//! it was a *hardcoded address* from one node build — `0xee270000`,
//! `0xee3ef000`, `0xeee00000` — which is not an identity: any binary that lands
//! there gets its faults recovered the same way. It was off by default from
//! 2026-08-23, was never demonstrated to succeed at anything, and porting it
//! would have been the line-by-line translation this migration exists not to
//! do.

use std::ffi::c_int;

use pagetable::memlock::{Held, ReadGuard, WriteGuard};
use usercopy::GuestMem;

use crate::{current, ffi};

#[path = "decode.rs"]
mod decode;
#[path = "diagnostics.rs"]
mod diagnostics;
use decode::STUCK;
#[cfg(test)]
use decode::Stuck;
use decode::{Fault, decode_load, is_branch, stuck_limit};
use diagnostics::{dump_maps, dump_stack};

// ---------------------------------------------------------------------------
// Where the guest's memory is
// ---------------------------------------------------------------------------

/// Four bytes of guest memory as an instruction, or `None` if they cannot be
/// read. Little-endian, which is what the guest is.
fn insn_at(pc: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    (GuestMem::current().read(pc, &mut bytes) == 0).then(|| u32::from_le_bytes(bytes))
}

/// A guest word, for the frame-pointer walk.
fn u64_at(addr: u64) -> Option<u64> {
    let mut bytes = [0u8; 8];
    (GuestMem::current().read(addr, &mut bytes) == 0).then(|| u64::from_le_bytes(bytes))
}


// ---------------------------------------------------------------------------
// The recoveries
// ---------------------------------------------------------------------------

/// Is the faulting page one a lazy reservation or the mmap region covers?
///
/// **`0xb0000000..0xf0000000` is the mmap region**, not a cage: `MMAP_HOLE_START`
/// is `0xefffd000` and every anonymous mapping a guest gets is placed below it.
/// The name is the C's and is kept so that the next reader recognises the
/// condition; what it actually says is "somewhere a guest allocation could be".
/// That is why the write half of [`demand_map`] is behind a switch.
fn in_v8_cage(addr: u64, reserved: bool) -> bool {
    reserved || (0xb000_0000..0xf000_0000).contains(&addr) || addr >= 0x1_0000_0000
}

/// How far to look for a mapped neighbour before believing this is a wild
/// pointer rather than the edge of an allocation.
///
/// V8 allocates its heap in many ~256 KB chunks at random high addresses, so a
/// legitimate store can land a chunk-width from the last mapped page; a low
/// address keeps the tight window, where the same slack would mistake a wild
/// pointer for heap growth.
fn neighbour_radius(addr: u64) -> u64 {
    if addr >= 0x1_0000_0000 { 256 } else { 16 }
}

/// Whether [`demand_map`] may run at all, given the two switches.
///
/// Split out so that the rule is one expression with a test rather than four
/// booleans assigned across thirty lines.
pub(crate) fn demand_map_allowed(
    write: bool,
    cage: bool,
    read_recovery: bool,
    v8_recovery: bool,
) -> bool {
    if write {
        cage && v8_recovery
    } else {
        read_recovery
    }
}

/// Answer a fault on an unmapped page by mapping a fresh one, if a mapped page
/// is close enough that this looks like the edge of an allocation.
///
/// Answers whether the guest may be resumed.
///
/// Called on the guest thread, with `mem->lock` **not** held -- the guards it
/// takes would deadlock. `pc` is the faulting block's; it took the whole
/// `*mut cpu_state` for that one read until 2026-10-01.
fn demand_map(pc: u64, addr: u64, write: bool) -> bool {
    let page = addr >> ffi::PAGE_BITS;
    let env = *util_iulenv::env();

    let reserved = ReadGuard::current().expect("a guest fault is taken in an address space").find_reservation(page).is_some();
    if !demand_map_allowed(
        write,
        in_v8_cage(addr, reserved),
        env.read_fault_recovery,
        env.v8_fault_recovery,
    ) {
        return false;
    }

    // A page inside an explicit reservation is one the guest asked for and
    // has not committed, so it needs no neighbour: the reservation is the
    // evidence. Everything else does.
    let explicit = reserved || (0xb000_0000..0xf000_0000).contains(&addr);
    let mut neighbour = write && explicit;
    if !neighbour {
        let radius = neighbour_radius(addr);
        let mem_pages = ffi::MEM_PAGES;
        let held = ReadGuard::current().expect("a guest fault is taken in an address space");
        neighbour = (page + 1..=page + radius)
            .take_while(|&p| p < mem_pages)
            .chain((page.saturating_sub(radius)..page).rev())
            .any(|p| held.pt(p).is_some());
    }
    // A write barrier in V8's own code may reach a fresh cage region farther
    // than the radius from anything mapped. Two pc ranges, which are addresses
    // rather than identities and so are inside the switch above with the rest.
    if !neighbour && write && addr >= 0x1_0000_0000 {
        neighbour =
            (0xeee0_0000..0xeee2_0000).contains(&pc) || (0xee3e_f000..0xee3f_1000).contains(&pc);
    }
    if !neighbour {
        return false;
    }

    let flags = if write {
        ffi::P_READ | ffi::P_WRITE
    } else {
        ffi::P_READ
    };
    let mut held = WriteGuard::current().expect("a guest fault is taken in an address space");
    held.pt(page).is_some() || held.map_nothing(page, 1, flags).is_ok()
}

/// Answer a *read* of an unmapped page by zeroing the load's destination and
/// stepping over the instruction.
///
/// Answers whether the guest may be resumed.
///
/// The JIT reports `cpu->pc` as the **start of the block**, not the faulting
/// instruction, so this scans forward for the first load: the ops between
/// cannot fault. It stops at a branch, because past one there is no
/// fall-through to assume.
///
/// **`fault_page_exists` is what keeps it honest.** Without that check this
/// fires for every read fault, so a `PROT_NONE` page reads back as 4096 zero
/// bytes — one recovered fault per byte, because the rate limit resets whenever
/// the address changes. A guard page that answers reads is not a guard page.
///
/// Safe since 2026-10-01: it took a `*mut cpu_state`, and the caller has this
/// thread's own, which nothing else writes while it handles the fault.
///
/// Takes the pc and the general registers rather than the whole `cpu_state`,
/// and answers the pc to resume at: a `&mut cpu_state` asserts that nothing
/// else writes the struct, and a signal sender on another thread stores to its
/// `_poked` through `poked_ptr`. It took one until 2026-10-16.
fn recover_read(pc: u64, regs: &mut [u64; 31]) -> Option<u64> {
    for step in 0..8u64 {
        let at = pc + step * 4;
        let insn = insn_at(at)?;
        if is_branch(insn) {
            return None;
        }
        let Some(load) = decode_load(insn) else {
            continue;
        };
        if load.rt >= 31 {
            return None;
        }
        regs[load.rt as usize] = 0;
        if let Some(rt2) = load.rt2.filter(|&r| r < 31) {
            regs[rt2 as usize] = 0;
        }
        if let Some((rn, imm)) = load.writeback.filter(|&(rn, _)| rn < 31) {
            // The whole address, as the instruction's writeback keeps it: a
            // register write is not an access, and the top byte is a tag.
            regs[rn as usize] = regs[rn as usize].wrapping_add(imm as u64);
        }
        return Some(at + 4);
    }
    None
}

// ---------------------------------------------------------------------------
// The arms
// ---------------------------------------------------------------------------

/// A memory fault the JIT could not resolve.
///
/// # Safety
/// Called on the guest thread, from `handle_interrupt`.
pub unsafe fn handle_int_gpf() {
    let task = current();
    let cpu = unsafe { (*task).cpu.get() };
    let env = *util_iulenv::env();
    let (mut addr, mut write) = unsafe { ((*cpu).segfault_addr, (*cpu).segfault_was_write) };
    let pc = unsafe { (*cpu).pc };

    if env.exec_trace {
        eprintln!(
            "INT_GPF pid={} pc={pc:#x} fault={addr:#x} write={}",
            taskview::current_pid(),
            write as i32
        );
    }

    // An instruction-fetch fault: the guest's own pc points at unmapped
    // memory, so the JIT could not read an instruction to compile and
    // `segfault_addr` is stale from an earlier data fault. Rewrite it, so that
    // the signal names an address the guest can act on and no recovery retries
    // a fault something else has already resolved.
    let fetchable = !ReadGuard::current()
        .expect("a guest fault is taken in an address space")
        .resolve(pc, ffi::MEM_READ as c_int)
        .is_null();
    if !fetchable && pc != 0 {
        addr = pc;
        write = false;
        // SAFETY: this thread's own CPU state, which only it writes.
        unsafe {
            (*cpu).segfault_addr = addr;
            (*cpu).segfault_was_write = false;
        }
    }

    // Repeating the same fault at the same pc with the same direction is not
    // progress. Every legitimate recovery moves the address.
    let seen = STUCK.with(|s| {
        s.borrow_mut().saw(Fault {
            pid: taskview::current_pid(),
            pc,
            addr,
            write,
        })
    });
    if seen > stuck_limit(pc) {
        if env.exec_trace {
            let regs = unsafe { (*cpu).regs };
            eprintln!(
                "FORCE_EXIT_STUCK_PC: pid={} exits 139 after {seen} GPFs at pc={pc:#x} fault={addr:#x}",
                taskview::current_pid()
            );
            eprintln!(
                "  x30={:#x} sp={:#x} x29={:#x}",
                regs[30],
                unsafe { (*cpu).sp },
                regs[29]
            );
        }
        unsafe { exitcalls::do_exit_group(ffi::SIGSEGV_ as c_int) };
    }

    // Can the access be satisfied as things stand? `mem_ptr` grows a stack and
    // breaks a copy-on-write, so a NULL here means it truly cannot.
    let (resolved, page_exists) = {
        let mut held = ReadGuard::current().expect("a guest fault is taken in an address space");
        let kind = if write { ffi::MEM_WRITE } else { ffi::MEM_READ };
        let p = !held.resolve(addr, kind as c_int).is_null();
        // Whether the page is *there*. Every recovery below exists for pages
        // that are absent -- gaps this emulator leaves where Linux would have
        // mapped something. A page that exists and refuses the access is not a
        // gap: the guest asked for the fault, by mapping PROT_NONE or by
        // mprotecting it away, and answering it would mean a guard page that
        // does not guard.
        let exists = held.pt(addr >> ffi::PAGE_BITS).is_some();
        (p, exists)
    };

    if !resolved && !page_exists && demand_map(pc, addr, write) {
        return;
    }
    if !resolved
        && !write
        && !page_exists
        && env.read_fault_recovery
        // SAFETY: this thread's own registers -- one field, borrowed while the
        // JIT is not running.
        && let Some(next) = recover_read(pc, unsafe { &mut (*cpu).regs })
    {
        // SAFETY: as above.
        unsafe { (*cpu).pc = next };
        return;
    }

    if env.gpf_bt {
        // SAFETY: as above.
        backtrace(unsafe { (*cpu).regs[29] });
    }

    // An **alignment** fault is a different signal. An atomic that crosses a
    // sixteen-byte granule cannot be one operation, and real hardware answers
    // `SIGBUS`/`BUS_ADRALN` rather than `SIGSEGV` — the guest's pointer is
    // mapped, it is just not aligned, and telling it otherwise sends a program
    // looking for the wrong bug. Set by the atomic helpers in
    // `crates/emu/tlb`; cleared here, because the flag must not outlive the
    // fault that set it.
    let align = unsafe { std::mem::replace(&mut (*cpu).segfault_was_align, false) };
    // And a page of a file mapping wholly past the end of its file is
    // `SIGBUS`/`BUS_ADRERR`, which is what Linux's fault handler answers when
    // there is no page of the file to map there.
    let bus = !align
        && page_exists
        && ReadGuard::current().expect("a guest fault is taken in an address space").space().bus_error(addr, write);

    // `mut`: the union member below is bindgen's and cannot be named in a
    // struct literal.
    let mut info = ffi::siginfo_ {
        // Under the read lock, which this read the page table without --
        // as the C did -- while another thread of the process could be
        // mapping or unmapping.
        code: if align {
            BUS_ADRALN
        } else if bus {
            BUS_ADRERR
        } else {
            ReadGuard::current().expect("a guest fault is taken in an address space").segv_reason(addr)
        },
        ..Default::default()
    };
    info.__bindgen_anon_1.fault.addr = addr;
    if env.exec_trace {
        dump_stack(8);
        dump_maps();
    }
    let sig = if align || bus {
        SIGBUS_
    } else {
        ffi::SIGSEGV_ as c_int
    };
    signaldeliver::deliver_signal(signaldeliver::Target::Me, sig, info);
}

/// `SIGBUS`, and the `si_code`s that say why: the address was not aligned, or
/// it had no backing to map.
///
/// Written down rather than generated because neither has a definition in this
/// tree's headers to generate *from* — `SIGBUS_` is in `kernel/signal.h` as
/// part of the guest's signal set and `BUS_ADRALN` is not defined at all. Both
/// are the same on every Linux architecture, which is what makes writing them
/// down safe here where `tools/guessed-constants.py` would otherwise object.
const SIGBUS_: c_int = 7;
const BUS_ADRALN: c_int = 1;
const BUS_ADRERR: c_int = 2;
#[path = "handlers.rs"]
mod handlers;
use handlers::backtrace;
pub use handlers::{handle_int_breakpoint, handle_int_undefined};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_branch_is_where_the_forward_scan_stops() {
        // The scan walks forward from the block start looking for the load
        // that faulted, and past a branch there is no fall-through to assume.
        for insn in [
            0x1400_0004u32, // b .+16
            0x9400_0004,    // bl .+16
            0xd61f_0000,    // br x0
            0xd63f_0000,    // blr x0
            0xd65f_03c0,    // ret
            0x5400_0040,    // b.eq .+8
            0x3400_0040,    // cbz x0, .+8
            0x3600_0040,    // tbz w0, #0, .+8
        ] {
            assert!(is_branch(insn), "{insn:#010x}");
        }
        // And these are not branches.
        for insn in [
            0xf940_0000u32, // ldr x0, [x0]
            0xd503_201f,    // nop
            0x9100_0000,    // add x0, x0, #0
        ] {
            assert!(!is_branch(insn), "{insn:#010x}");
        }
    }

    #[test]
    fn a_store_is_not_a_load() {
        // The whole recovery is "zero what the load would have written", so a
        // store decoded as a load zeroes a register the guest still wants.
        assert_eq!(decode_load(0xf900_0020), None, "str x0, [x1]");
        assert_eq!(decode_load(0x3800_0020), None, "sturb w0, [x1]");
        assert!(decode_load(0xf940_0020).is_some(), "ldr x0, [x1]");
    }

    #[test]
    fn an_ldp_names_both_of_its_destinations() {
        // 0xffc00000 and not 0x7fc00000: the old mask cleared bit 31, so this
        // arm could never be reached for a 64-bit LDP.
        let ldp = 0xa941_0c41u32; // ldp x1, x3, [x2, #16]
        let load = decode_load(ldp).expect("an LDP is a load");
        assert_eq!(load.rt, 1);
        assert_eq!(load.rt2, Some(3));
        assert_eq!(
            load.writeback, None,
            "a signed-offset LDP does not write back"
        );
    }

    #[test]
    fn a_pre_or_post_indexed_load_writes_its_base_back() {
        // ldr x0, [x1], #8   -- post-indexed
        let post = decode_load(0xf840_8420).expect("post-indexed is a load");
        assert_eq!(post.writeback, Some((1, 8)));
        // ldr x0, [x1, #-8]! -- pre-indexed, and the displacement is signed.
        let pre = decode_load(0xf85f_8c20).expect("pre-indexed is a load");
        assert_eq!(pre.writeback, Some((1, -8)));
        // ldur x0, [x1, #8]  -- unscaled, no writeback.
        let unscaled = decode_load(0xf840_8020).expect("unscaled is a load");
        assert_eq!(unscaled.writeback, None);
    }

    #[test]
    fn identical_faults_count_and_a_different_one_resets() {
        let mut s = Stuck::default();
        let f = Fault {
            pid: 1,
            pc: 0x1000,
            addr: 0x2000,
            write: false,
        };
        assert_eq!(s.saw(f), 1);
        assert_eq!(s.saw(f), 2);
        // A stack growing down moves the address every time round, which is
        // what tells progress from a loop.
        assert_eq!(s.saw(Fault { addr: 0x1fff, ..f }), 1);
        assert_eq!(s.saw(f), 1, "and back again is still a change");
        // The direction is part of it: a page can be readable and not writable.
        assert_eq!(s.saw(Fault { write: true, ..f }), 1);
        // So is the task: two threads faulting alternately are not one loop.
        assert_eq!(
            s.saw(Fault {
                pid: 2,
                write: true,
                ..f
            }),
            1
        );
    }

    #[test]
    fn the_null_page_gets_a_shorter_leash() {
        assert_eq!(stuck_limit(0), 16);
        assert_eq!(stuck_limit(0xfff), 16);
        assert_eq!(stuck_limit(0x1000), 256);
    }

    #[test]
    fn every_demand_map_needs_a_switch() {
        // The default is that a fault on an unmapped page is a SIGSEGV. Before
        // 2026-09-02 the write half had no switch at all, and its range is the
        // mmap region -- so every store through a dangling pointer was handed a
        // page.
        assert!(!demand_map_allowed(false, false, false, false));
        assert!(!demand_map_allowed(true, true, false, false));
        // A read needs the read switch, and asks nothing about the cage.
        assert!(demand_map_allowed(false, false, true, false));
        assert!(!demand_map_allowed(false, false, false, true));
        // A write needs the V8 switch *and* the cage.
        assert!(demand_map_allowed(true, true, false, true));
        assert!(!demand_map_allowed(true, false, true, true));
    }

    #[test]
    fn what_counts_as_the_cage() {
        // A reservation is the guest saying it wants the range.
        assert!(in_v8_cage(0x1000, true));
        // The rest is address arithmetic, and the middle range is the mmap
        // region rather than anything V8 owns.
        assert!(in_v8_cage(0xb000_0000, false));
        assert!(!in_v8_cage(0xf000_0000, false), "just past it");
        assert!(
            in_v8_cage(0x1_0000_0000, false),
            "and everything above 4 GB"
        );
        assert!(
            !in_v8_cage(0x400_000, false),
            "but not where a program is loaded"
        );
    }

    #[test]
    fn the_neighbour_window_is_wider_above_four_gigabytes() {
        assert_eq!(neighbour_radius(0xffff_ffff), 16);
        assert_eq!(neighbour_radius(0x1_0000_0000), 256);
    }
}
