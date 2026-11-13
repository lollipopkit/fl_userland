//! How long does it take to find out that a range is empty?
//!
//! `pt_is_hole` decides whether a mapping can go where it was asked for, and
//! `brk` and `mmap` both call it before they map anything, with `mem->lock`
//! held for **writing** — so every other thread in the process is stopped for
//! the length of the answer.
//!
//! It walked the range one page at a time, doing a four-level page-table walk
//! per page whether or not anything was there. The page table skips empty
//! subtrees (`mem_next_page`) and the walk did not use that.
//!
//! Two measurements:
//!
//!   * a `mmap` with a hint, of a size a runtime really reserves — Go's page
//!     summaries are about 1.1 GB of PROT_NONE, V8's heap cage 128 MB;
//!   * `brk` to an address near the top of the address space, which asks the
//!     same function about 2^36 pages.
//!
//! Not in the gate: it is a measurement, and the numbers depend on the machine.
//! The brk case has a watchdog, because "did not finish" is the result it is
//! looking for.

use std::time::Instant;

const PAGE: usize = 4096;

fn main() {
    let which = std::env::args().nth(1).unwrap_or_else(|| "all".into());

    if which == "all" || which == "mmap" {
        // A hint high enough to be empty, so the hole check walks the whole
        // range and finds nothing — the case that costs the most.
        for mb in [16usize, 128, 1024] {
            let len = mb * 1024 * 1024;
            let mut times = Vec::new();
            let mut keep = Vec::new();
            for i in 0..20 {
                let hint = (0x2000_0000_0000usize + i * (2 * len)) as *mut libc::c_void;
                let t = Instant::now();
                let p = unsafe {
                    libc::mmap(
                        hint,
                        len,
                        libc::PROT_NONE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                        -1,
                        0,
                    )
                };
                times.push(t.elapsed().as_micros());
                if p != libc::MAP_FAILED {
                    keep.push((p, len));
                }
            }
            times.sort_unstable();
            println!(
                "mmap hint {mb}MB: median {}us worst {}us ({} of 20 placed)",
                times[times.len() / 2],
                times[times.len() - 1],
                keep.len()
            );
            for (p, l) in keep {
                unsafe { libc::munmap(p, l) };
            }
        }
    }

    if which == "all" || which == "churn" {
        // mprotect and munmap in a tight loop. Both used to call getenv() --
        // a linear scan of the environment, one strcmp per variable -- on
        // every call, to decide whether a diagnostic that is off should print.
        let pages = 64;
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                pages * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p != libc::MAP_FAILED {
            let rounds = 20000;
            let t = Instant::now();
            for i in 0..rounds {
                let prot = if i % 2 == 0 {
                    libc::PROT_READ
                } else {
                    libc::PROT_READ | libc::PROT_WRITE
                };
                unsafe { libc::mprotect(p, PAGE, prot) };
            }
            let each = t.elapsed().as_nanos() / rounds as u128;
            println!("mprotect: {each}ns each over {rounds}");
            unsafe { libc::munmap(p, pages * PAGE) };
        }
    }

    if which == "all" || which == "brk" {
        // brk near the top of the address space. The request is absurd and is
        // expected to be refused; what is being measured is how long the
        // refusal takes.
        let start = unsafe { libc::syscall(libc::SYS_brk, 0usize) } as usize;
        println!("brk starts at {start:#x}");
        for shift in [32u32, 36, 44, 47] {
            let target = 1usize << shift;
            if target <= start {
                continue;
            }
            let t = Instant::now();
            let got = unsafe { libc::syscall(libc::SYS_brk, target) } as usize;
            let took = t.elapsed();
            println!(
                "brk(1<<{shift}) -> {got:#x} in {}ms",
                took.as_millis()
            );
            // Put it back if it somehow succeeded, and stop if one of these
            // takes long enough that the next would not finish.
            if got >= target {
                unsafe { libc::syscall(libc::SYS_brk, start) };
            }
            if took.as_secs() >= 10 {
                println!("stopping: that took {}s", took.as_secs());
                break;
            }
        }
    }

    // A page still works afterwards, so a run that mangled the address space
    // says so rather than looking like a clean set of numbers.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        println!("LOST: cannot map a page afterwards");
    } else {
        unsafe { std::ptr::write_volatile(p.cast::<u8>(), 1) };
        unsafe { libc::munmap(p, PAGE) };
    }
    println!("survived");
}
