//! The address space, rearranged from several threads at once.
//!
//! Every call in the mmap family mutates one page table that every thread of
//! the process shares, and `mem->lock` is what serialises them —
//! `sys_mmap64`, `sys_munmap`, `sys_mprotect` and `sys_brk` all take it for
//! writing. `sys_mremap` took nothing at all: it called `mem_pt`, `pt_unmap`,
//! `pt_is_hole` and `pt_map_nothing` with no lock held, and none of those take
//! one themselves.
//!
//! Threads here grow and shrink their own mappings with `mremap` while others
//! map, unmap and reprotect theirs, and another walks `/proc/self/maps` over
//! the top — which is the reader that has to cope with the page table changing
//! under it.
//!
//! Each thread owns its own mappings, so nothing here is a race the *guest*
//! program has: every finding is the emulator's. Run it under ThreadSanitizer
//! for the rest.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const PAGE: usize = 4096;

static BAD_CONTENT: AtomicU64 = AtomicU64::new(0);

fn anon(pages: usize) -> *mut libc::c_void {
    unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            pages * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    }
}

fn mremap(addr: *mut libc::c_void, old: usize, new: usize) -> *mut libc::c_void {
    unsafe { libc::syscall(libc::SYS_mremap, addr, old, new, 0, 0usize) as *mut libc::c_void }
}

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();

    // Grow and shrink one mapping, checking its contents survive.
    for t in 0..3u8 {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let p = anon(4);
                if p == libc::MAP_FAILED {
                    continue;
                }
                let mark = 0xa0 | t;
                unsafe { std::ptr::write_bytes(p.cast::<u8>(), mark, PAGE) };

                // Shrink, then try to grow back. The grow may legitimately
                // fail with ENOMEM if another thread took the space; what may
                // not happen is the first page changing.
                let mut pages = 4;
                if mremap(p, 4 * PAGE, 2 * PAGE) == p {
                    pages = 2;
                    if mremap(p, 2 * PAGE, 3 * PAGE) == p {
                        pages = 3;
                    }
                }
                if unsafe { *p.cast::<u8>() } != mark {
                    BAD_CONTENT.fetch_add(1, Ordering::Relaxed);
                }
                unsafe { libc::munmap(p, pages * PAGE) };
                n += 1;
            }
            n
        }));
    }

    // Map, reprotect and unmap, so the page table is being rewritten from
    // somewhere other than mremap at the same time.
    for _ in 0..2 {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let p = anon(8);
                if p == libc::MAP_FAILED {
                    continue;
                }
                unsafe {
                    libc::mprotect(p.byte_add(2 * PAGE), 2 * PAGE, libc::PROT_READ);
                    libc::munmap(p.byte_add(4 * PAGE), 2 * PAGE);
                    libc::mprotect(p, PAGE, libc::PROT_READ | libc::PROT_WRITE);
                    libc::munmap(p, 4 * PAGE);
                    libc::munmap(p.byte_add(6 * PAGE), 2 * PAGE);
                }
                n += 1;
            }
            n
        }));
    }

    // Read the page table while it is being rewritten.
    {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let _ = std::fs::read_to_string("/proc/self/maps");
                let _ = std::fs::read_to_string("/proc/self/statm");
                n += 1;
            }
            n
        }));
    }

    std::thread::sleep(std::time::Duration::from_secs(seconds));
    stop.store(true, Ordering::Relaxed);
    let counts: Vec<u64> = threads.into_iter().map(|t| t.join().unwrap_or(0)).collect();

    println!("iterations: {counts:?}");
    let bad = BAD_CONTENT.load(Ordering::Relaxed);
    if bad != 0 {
        println!("LOST: {bad} mappings changed contents across an mremap");
    }
    println!("survived");
}
