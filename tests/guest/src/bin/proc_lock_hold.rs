//! How long does reading /proc/<pid>/maps stall the rest of the system?
//!
//! Every `/proc/<pid>/*` callback runs with `pids_lock` held — `proc_get_task`
//! takes it and hands the task back still holding it, and `proc_put_task`
//! drops it after the callback has finished formatting. `pids_lock` is the
//! global pid table lock, which fork, exit, wait and kill all need.
//!
//! Measures fork latency on its own, then again while another thread reads
//! /proc/self/maps in a loop.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Make the map big enough to be worth dumping, the way a real program's is.
fn make_mappings(n: usize) -> Vec<*mut libc::c_void> {
    let mut v = Vec::new();
    for _ in 0..n {
        // Separate mappings with alternating protections so they cannot be
        // coalesced into one region by the dump.
        let prot = if v.len() % 2 == 0 {
            libc::PROT_READ
        } else {
            libc::PROT_READ | libc::PROT_WRITE
        };
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            break;
        }
        v.push(p);
    }
    v
}

/// Median and worst of `n` fork+wait round trips, in microseconds.
fn fork_latency(n: usize) -> (u128, u128) {
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                libc::_exit(0);
            }
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
        samples.push(t.elapsed().as_micros());
    }
    samples.sort_unstable();
    (samples[samples.len() / 2], *samples.last().unwrap())
}

fn main() {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let regions_before = maps.lines().count();
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(400);
    let _keep = make_mappings(n);
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    println!(
        "/proc/self/maps: {} regions, {} bytes (was {regions_before} regions)",
        maps.lines().count(),
        maps.len()
    );

    let (idle_med, idle_max) = fork_latency(40);
    println!("fork+wait, quiet:            median {idle_med}us  worst {idle_max}us");

    // The reader has to read *another* process's maps. Reading our own means
    // the dump and fork's mm_copy both want this process's mem->lock, so the
    // two serialise on that whatever pids_lock does — and the measurement says
    // nothing about pids_lock at all.
    let victim = unsafe { libc::fork() };
    if victim == 0 {
        // A child with a large map of its own, sitting still.
        let _keep = make_mappings(n);
        loop {
            unsafe { libc::pause() };
        }
    }
    let file = std::env::args().nth(2).unwrap_or_else(|| "maps".into());
    let victim_maps = format!("/proc/{victim}/{file}");
    std::thread::sleep(std::time::Duration::from_millis(200));
    println!(
        "reading {victim_maps}: {} bytes",
        std::fs::read_to_string(&victim_maps).unwrap_or_default().len()
    );

    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let stop = stop.clone();
        let path = victim_maps.clone();
        std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let _ = std::fs::read_to_string(&path);
                n += 1;
            }
            n
        })
    };
    // Let the reader get going.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let (busy_med, busy_max) = fork_latency(40);
    stop.store(true, Ordering::Relaxed);
    let reads = reader.join().unwrap_or(0);
    unsafe {
        libc::kill(victim, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(victim, &mut st, 0);
    }

    println!("fork+wait, maps being read:  median {busy_med}us  worst {busy_max}us  ({reads} reads)");
    let ratio = if idle_med > 0 {
        busy_med as f64 / idle_med as f64
    } else {
        0.0
    };
    println!("median fork latency ratio: {ratio:.1}x");
}
