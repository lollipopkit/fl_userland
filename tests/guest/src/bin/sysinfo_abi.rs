//! `sysinfo` fills the whole structure, whatever was in it.
//!
//! It writes into a buffer the caller supplies, and callers do not zero it —
//! `struct sysinfo` is a stack local and every field is about to be
//! overwritten. So whatever the stack happened to hold is what is there when
//! the call starts, and a kernel that looks at that and decides to skip a field
//! leaves the caller reading its own leftovers as an answer.
//!
//! The field this is about is the first one, `uptime`, and the leftovers most
//! likely to be sitting there are a pointer: aligned, so its low byte is zero.

use guest_tests::{Harness, check};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Overwrites the whole structure with `fill` bytes, then calls `sysinfo`.
fn sysinfo_over(fill: u64) -> (i32, libc::sysinfo, i32) {
    let mut si: libc::sysinfo = unsafe { std::mem::zeroed() };
    // Byte for byte, so the first eight are exactly `fill`.
    unsafe {
        let p = (&raw mut si) as *mut u64;
        let words = std::mem::size_of::<libc::sysinfo>() / 8;
        for i in 0..words {
            p.add(i).write(fill);
        }
    }
    let r = unsafe { libc::sysinfo(&mut si) };
    (r, si, errno())
}

fn main() {
    let mut h = Harness::new();

    h.group("a-zeroed-buffer");
    let (r, si, e) = sysinfo_over(0);
    check!(h, r == 0, "sysinfo: r={r} errno={e}");
    check!(h, si.uptime > 0, "uptime is filled in: {}", si.uptime);
    check!(h, si.totalram > 0, "and totalram: {}", si.totalram);
    let baseline = si.uptime;

    h.group("a-buffer-holding-what-a-stack-holds");
    // An aligned address is the commonest thing to find in an uninitialised
    // stack local, and its low byte is zero. A kernel that treats "non-zero
    // with a zero low byte" as a reason not to write the first field leaves the
    // caller reading that address as its uptime.
    for fill in [0x0000_ffff_dead_be00u64, 0x0000_0000_0061_3870, 0xffff_ffff_ffff_ff00] {
        let (r, si, e) = sysinfo_over(fill);
        check!(h, r == 0, "sysinfo over {fill:#x}: r={r} errno={e}");
        check!(h, si.uptime as u64 != fill,
            "uptime is not what was already there: {} vs {fill:#x}", si.uptime);
        check!(h, si.uptime.abs_diff(baseline) < 60,
            "and is the real uptime: {} vs {baseline}", si.uptime);
        check!(h, si.totalram > 0, "the rest is filled in too: totalram={}", si.totalram);
    }

    h.group("a-buffer-holding-anything-else");
    // The control: filling with a value whose low byte is *not* zero must work
    // as well, so the group above cannot pass because sysinfo refuses
    // everything.
    for fill in [0x1111_1111_1111_1111u64, 0xdead_beef_dead_beef] {
        let (r, si, e) = sysinfo_over(fill);
        check!(h, r == 0, "sysinfo over {fill:#x}: r={r} errno={e}");
        check!(h, si.uptime.abs_diff(baseline) < 60,
            "uptime is the real one: {} vs {baseline}", si.uptime);
    }

    h.group("the-fields-are-consistent");
    let (_, si, _) = sysinfo_over(0);
    check!(h, si.freeram <= si.totalram, "freeram is within totalram: {} of {}",
        si.freeram, si.totalram);
    check!(h, si.mem_unit >= 1, "mem_unit is a unit: {}", si.mem_unit);
    check!(h, si.procs >= 1, "there is at least one process: {}", si.procs);

    h.group("a-bad-address");
    let r = unsafe { libc::syscall(libc::SYS_sysinfo, 1usize) };
    let e = errno();
    check!(h, r == -1 && e == libc::EFAULT, "an unmapped buffer is EFAULT: r={r} errno={e}");

    std::process::exit(h.finish());
}
