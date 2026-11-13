//! Grows `/proc/self/maps`, then reads it back at several chunk sizes.
//!
//! A proc file has no stored contents: a `show` callback generates the whole
//! thing. `proc_pread` used to run that callback on every read, so reading N
//! bytes in B-byte chunks cost O(N²/B). With 2000 mappings that was 1.79s in
//! 64-byte chunks against 0.03s in 4096-byte ones — the same bytes, 62x apart
//! — and Go reads this file at startup.
//!
//! The contents are generated once per descriptor now and reused until a seek
//! back to 0, so every chunk size should come out at roughly the same time.

use std::time::Instant;

use guest_tests::sys;

fn read_all(chunk: usize) -> usize {
    let fd = sys::open("/proc/self/maps", libc::O_RDONLY, 0);
    if fd < 0 {
        return 0;
    }
    let mut buf = vec![0u8; chunk];
    let mut total = 0;
    loop {
        let n = sys::read(fd, &mut buf);
        if n <= 0 {
            break;
        }
        total += n as usize;
    }
    sys::close(fd);
    total
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(200);

    // Separate mappings, so they cannot be coalesced into one vma.
    for i in 0..n {
        // SAFETY: an anonymous private mapping, never dereferenced.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            break;
        }
        // Alternate the protection so adjacent mappings stay distinct.
        if i % 2 == 0 {
            unsafe { libc::mprotect(p, 4096, libc::PROT_READ | libc::PROT_WRITE) };
        }
    }

    println!("maps size: {} bytes", read_all(65536));
    for chunk in [64usize, 512, 4096] {
        let start = Instant::now();
        let got = read_all(chunk);
        let dt = start.elapsed();
        println!(
            "  chunk {chunk:5}: {got} bytes in {:.3}s  ({} reads)",
            dt.as_secs_f64(),
            got.div_ceil(chunk)
        );
    }
}
