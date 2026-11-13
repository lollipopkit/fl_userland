//! Cost of a mapping change as the guest sees it: a one-page `mprotect`
//! followed by a touch of another page. Every change bumps the address space's
//! generation, so this measures what a generation change costs the TLB.
//!
//! A measurement, not a check. Compare builds interleaved, with
//! `compute_bench` as the control.
use std::time::Instant;

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20_000);
    const PAGE: usize = 4096;
    // SAFETY: a fresh private mapping this program owns.
    let base = unsafe {
        libc::mmap(std::ptr::null_mut(), 64 * PAGE, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    } as *mut u8;
    assert!(!base.is_null());
    let start = Instant::now();
    for i in 0..n {
        let prot = if i % 2 == 0 { libc::PROT_READ } else { libc::PROT_READ | libc::PROT_WRITE };
        // SAFETY: the first page of the mapping above; the touch is page 32,
        // which stays writable.
        unsafe {
            libc::mprotect(base.cast(), PAGE, prot);
            base.add(32 * PAGE + (i % PAGE)).write_volatile(i as u8);
        }
    }
    println!("mprotect+touch: {:.2} us/iter", start.elapsed().as_secs_f64() * 1e6 / n as f64);
}
