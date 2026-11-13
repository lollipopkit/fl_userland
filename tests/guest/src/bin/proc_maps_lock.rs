//! How long does reading /proc/<pid>/maps hold the address-space lock?
//!
//! `proc_mem_maps_dump` takes `mem->lock` for reading and holds it for the
//! whole dump: one walk of the page table, one `proc_printf` per region — each
//! of which can realloc the output buffer — and, for every file-backed region,
//! a call to `generic_getpath`, which goes out to the VFS and takes whatever
//! locks the mount it lands on uses.
//!
//! `mem->lock` is what every `mmap`, `munmap`, `mprotect` and `brk` needs to
//! write, so anything holding it for reading stalls all of them.
//!
//! Measures mmap/munmap latency on its own, then again while another thread
//! reads /proc/self/maps in a loop. The mappings are file-backed and
//! alternately protected so they cannot be coalesced, which is what puts one
//! `generic_getpath` under the lock per region.
//!
//! Not in the gate: it is a measurement, and the number depends on the
//! machine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// A file to map, big enough for `n` distinct pages.
fn backing_file(path: &str, pages: usize) -> i32 {
    let fd = unsafe { libc::open(cstr(path).as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o644) };
    if fd < 0 {
        return fd;
    }
    let zeros = vec![0u8; 4096];
    for _ in 0..pages {
        unsafe { libc::write(fd, zeros.as_ptr().cast(), zeros.len()) };
    }
    fd
}

/// File-backed mappings, alternately protected so the dump cannot merge them.
/// Every one of them makes the dump call generic_getpath.
fn make_mappings(fd: i32, n: usize) -> Vec<*mut libc::c_void> {
    let mut v = Vec::new();
    for i in 0..n {
        let prot = if i % 2 == 0 {
            libc::PROT_READ
        } else {
            libc::PROT_READ | libc::PROT_WRITE
        };
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                prot,
                libc::MAP_PRIVATE,
                fd,
                (i * 4096) as libc::off_t,
            )
        };
        if p == libc::MAP_FAILED {
            break;
        }
        v.push(p);
    }
    v
}

/// Worst and median latency of `rounds` mmap+munmap pairs, in microseconds.
/// The pair is what needs `mem->lock` for writing.
fn measure_mmap(rounds: usize) -> (u128, u128) {
    let mut times = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t = Instant::now();
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p != libc::MAP_FAILED {
            unsafe { libc::munmap(p, 4096) };
        }
        times.push(t.elapsed().as_micros());
        // Long enough that the pairs do not simply queue behind each other.
        unsafe { libc::usleep(2000) };
    }
    times.sort_unstable();
    (times[times.len() - 1], times[times.len() / 2])
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1500);
    let rounds: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let dir = std::env::args().nth(3).unwrap_or_else(|| "/tmp".into());

    let path = format!("{dir}/maps-backing");
    let fd = backing_file(&path, n);
    if fd < 0 {
        println!("could not create {path}");
        return;
    }
    let maps = make_mappings(fd, n);
    println!("mappings: {}", maps.len());

    // The reader on its own, so the change can be judged from both sides: it
    // does the same work, in a different order, and the count of reads in the
    // contended run below is not comparable across builds -- that window is
    // however long the mmap measurement takes, which is the thing being fixed.
    let t = Instant::now();
    for _ in 0..50 {
        let _ = std::fs::read_to_string("/proc/self/maps");
    }
    println!("reader:   50 reads in {}us", t.elapsed().as_micros());

    let (worst_idle, median_idle) = measure_mmap(rounds);
    println!("idle:     worst {worst_idle}us  median {median_idle}us");

    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                // Reads its own maps, which is the case a real program has:
                // every runtime that reports its own memory use does this.
                let _ = std::fs::read_to_string("/proc/self/maps");
                n += 1;
            }
            n
        })
    };

    let (worst_busy, median_busy) = measure_mmap(rounds);
    stop.store(true, Ordering::Relaxed);
    let reads = reader.join().unwrap_or(0);
    println!("contended: worst {worst_busy}us  median {median_busy}us  ({reads} reads)");

    for p in maps {
        unsafe { libc::munmap(p, 4096) };
    }
    unsafe {
        libc::close(fd);
        libc::unlink(cstr(&path).as_ptr());
    }
}
