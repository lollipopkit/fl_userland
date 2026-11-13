//! Code that rewrites itself, which is what the W^X machinery exists for.
//!
//! The interpreter compiles a guest page into an array of gadget pointers and
//! marks the page `P_CODE`. A later store to that page has to invalidate what
//! was compiled from it and clear the mark, or the next call runs the old
//! code. The mark lives in `pt_entry->flags`, which is set and cleared by
//! threads holding only the address-space *read* lock — so it is the field a
//! lost read-modify-write costs the most.
//!
//! Each round writes a different constant-returning function into the same
//! page and calls it. The compiled block from the previous round is still in
//! the cache, so a round that returns the previous round's value is the
//! failure: the invalidation did not happen.
//!
//! Also runs it from several threads at once on separate pages, because the
//! mark is per page and cleared while other threads are reading and setting
//! marks of their own.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use guest_tests::{Harness, check};

const PAGE: usize = 4096;

/// `mov w0, #imm; ret`, aarch64, little-endian.
///
/// MOVZ w0, #imm16 is 0x52800000 | (imm << 5); RET is 0xd65f03c0.
fn returns(imm: u16) -> [u32; 2] {
    [0x5280_0000 | ((imm as u32) << 5), 0xd65f_03c0]
}

/// One page, mapped rwx, that can be rewritten and called.
struct CodePage(*mut libc::c_void);

impl CodePage {
    fn new() -> Option<CodePage> {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            None
        } else {
            Some(CodePage(p))
        }
    }

    fn write(&self, code: [u32; 2]) {
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), self.0.cast::<u32>(), 2) };
        // The instruction cache has to be told, on any real aarch64 and here
        // too: this is the barrier a JIT emits, and leaving it out would be
        // testing the emulator against a program that is already wrong.
        unsafe {
            std::arch::asm!(
                "dc cvau, {p}",
                "dsb ish",
                "ic ivau, {p}",
                "dsb ish",
                "isb",
                p = in(reg) self.0,
            );
        }
    }

    fn call(&self) -> u32 {
        let f: extern "C" fn() -> u32 = unsafe { std::mem::transmute(self.0) };
        f()
    }
}

impl Drop for CodePage {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.0, PAGE) };
    }
}

// SAFETY: each thread gets its own page; nothing is shared.
unsafe impl Send for CodePage {}

fn main() {
    let rounds: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let mut h = Harness::new();

    h.group("rewrite");
    match CodePage::new() {
        None => check!(h, false, "mapping a page rwx"),
        Some(page) => {
            let mut wrong = 0;
            for i in 1..=rounds {
                page.write(returns(i));
                let got = page.call();
                if got != i as u32 {
                    wrong += 1;
                    if wrong <= 3 {
                        println!("  round {i}: called it and got {got}");
                    }
                }
            }
            check!(
                h,
                wrong == 0,
                "{rounds} rewrites of one page each ran the code just written ({wrong} did not)"
            );
        }
    }

    h.group("rewrite-threaded");
    let wrong = Arc::new(AtomicU64::new(0));
    let made = Arc::new(AtomicU64::new(0));
    let threads: Vec<_> = (0..4u16)
        .map(|t| {
            let wrong = wrong.clone();
            let made = made.clone();
            std::thread::spawn(move || {
                let Some(page) = CodePage::new() else { return };
                made.fetch_add(1, Ordering::Relaxed);
                for i in 1..=rounds {
                    // A value each thread can be told apart by, so a page that
                    // ran another thread's code would show as its number.
                    let v = i.wrapping_mul(4).wrapping_add(t);
                    page.write(returns(v));
                    if page.call() != v as u32 {
                        wrong.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    for t in threads {
        let _ = t.join();
    }
    check!(
        h,
        made.load(Ordering::Relaxed) == 4,
        "four threads each got a page"
    );
    check!(
        h,
        wrong.load(Ordering::Relaxed) == 0,
        "and every rewrite ran what was written ({} did not)",
        wrong.load(Ordering::Relaxed)
    );

    std::process::exit(h.finish());
}
