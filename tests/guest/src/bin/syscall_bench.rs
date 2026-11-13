//! How long the small-syscall paths take.
//!
//! `kernel/calls.c` carries three shortcuts — `fast_read`, `fast_write` and
//! `fast_fstat64` — that answer a syscall on a realfs descriptor without going
//! through the syscall implementation. They exist for speed, and the question
//! this answers is how much.
//!
//! A measurement, not a check. It reports numbers and never fails, so it is
//! not in the gate.
//!
//! ## What it said on 2026-08-22, and why nothing was changed
//!
//! Run it against a **release** build; a debug one is about 1.6x slower and
//! says nothing useful about shipped performance.
//!
//! Three runs each, release, against the same file on APFS:
//!
//! | | host, native | through the emulator | overhead |
//! | --- | --- | --- | --- |
//! | read 64B (lseek + read) | ~665 ns | ~1030 ns | ~365 ns |
//! | write 64B (lseek + write) | ~1700 ns | ~2100 ns | ~400 ns |
//!
//! Two things follow, both of which stopped an optimisation that looked
//! obvious before the numbers existed.
//!
//! A write costing twice a read is **the host's filesystem**, not this
//! emulator: native writes are already 2.5x native reads here. The per-syscall
//! overhead is the same ~370-400 ns either way. Nothing in the write path
//! needs looking at, which is not what the emulator-only numbers suggested.
//!
//! `sample` on a tight lseek+read loop puts 1407 of 2514 samples in the host's
//! `read` and 783 in the host's `lseek` — the emulator's own share is the
//! remainder, under 2%. There is no fat in the syscall path to cut. The one
//! real opportunity is that a guest `lseek` costs a host `lseek`, which
//! tracking the offset in `struct fd` and using `pread`/`pwrite` would remove:
//! about 30% of a seek-and-read pair, and nothing at all for sequential I/O.
//! It is not done, because it moves ownership of the file offset in the
//! hottest path in the system and O_APPEND, pipes sharing `realfs_fdops`, and
//! descriptors handed to native offload all read that offset differently.
//! Recorded rather than attempted.
//!
//! Guest `pread`/`pwrite` are already one host call each — `realfs_fdops` maps
//! them straight through — so there is nothing to win there.

use std::time::Instant;

/// How long `n` threads take to make `iters` calls each, and what one call
/// costs when they are all doing it.
///
/// The number that matters for a lock is the *concurrent* one: a lock nobody
/// contends costs an uncontended atomic, and a single-threaded loop cannot
/// tell a lock held across a blocking syscall from one that is not.
fn bench_threads(name: &str, threads: usize, iters: u32, f: impl Fn() + Send + Sync + Copy) {
    for _ in 0..iters / 10 + 1 {
        f();
    }
    // Every thread is up and warm *before* the clock starts.
    //
    // Timing from the spawn measured thread creation, and thread creation is
    // its own problem: each one mmaps a stack, `mmap` takes the write lock on
    // the address space, and the JIT holds that lock for reading in every
    // running thread. Two seconds into an eight-thread run, five of the eight
    // existed. That is worth knowing and is not what this is trying to measure.
    let gate = std::sync::Barrier::new(threads + 1);
    let mut start = None;
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let gate = &gate;
            scope.spawn(move || {
                f();
                gate.wait();
                for _ in 0..iters {
                    f();
                }
            });
        }
        gate.wait();
        start = Some(Instant::now());
        // The scope joins them here, so `elapsed` below covers exactly the
        // loops and nothing before them.
    });
    let elapsed = start.expect("the barrier released").elapsed();
    let total = threads as u32 * iters;
    let per = elapsed.as_nanos() as f64 / total as f64;
    println!("  {name:<28} {per:>9.0} ns/call   ({threads} threads x {iters})");
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn bench(name: &str, iters: u32, mut f: impl FnMut()) {
    // A warm-up, so the first block's translation is not in the number.
    for _ in 0..iters / 10 + 1 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let per = elapsed.as_nanos() as f64 / iters as f64;
    println!("  {name:<28} {per:>9.0} ns/call   ({iters} calls in {elapsed:?})");
}

/// Concurrent `stat` on a fakefs path, against a control that does not touch
/// the filesystem at all.
///
/// `fakefs_stat` used to hold the `meta.db` transaction — a process-wide mutex
/// — across `realfs.stat`, which is a blocking host syscall. Every stat in the
/// process therefore serialised behind whichever one was in the host, and
/// `stat` is the operation a fakefs sees most: an `npm` run makes millions.
///
/// The control is `getpid`, which takes no lock and touches no host file. If
/// both move together the machine was busy; only the first moving is the lock.
fn bench_concurrent_stat(dir: &str) {
    let path = format!("{dir}/bench-target");
    let cpath = cstr(&path);
    // Where a stat's time goes, as a function of how many components the path
    // has. Every component of a path is resolved, and on fakefs resolving one
    // means asking meta.db what it is -- so a cost that grows with depth is
    // the walk, and a flat one is the last component's own lookup.
    println!();
    println!("stat by path depth:");
    for (label, p) in [
        ("/", "/".to_string()),
        ("/tmp", "/tmp".to_string()),
        ("/tmp/d1", "/tmp/d1".to_string()),
        ("/tmp/d1/d2", "/tmp/d1/d2".to_string()),
        ("/tmp/d1/d2/d3", "/tmp/d1/d2/d3".to_string()),
        ("/tmp/d1/d2/d3/d4", "/tmp/d1/d2/d3/d4".to_string()),
    ] {
        let _ = std::fs::create_dir_all(&p);
        let c = cstr(&p);
        bench(&format!("stat {label}"), 20000, || {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            unsafe { libc::stat(c.as_ptr() as *const libc::c_char, &mut st) };
        });
    }

    // Does anything here run in parallel at all?
    //
    // `bench_threads` divides by the total number of calls, so a perfectly
    // parallel operation shows a per-call cost that *falls* with the thread
    // count and a perfectly serialised one shows a flat line. Pure arithmetic
    // touches no kernel state and must fall; if it does not, the guest's
    // threads are not running at the same time and every other number in this
    // section is about something else.
    println!();
    println!("parallelism, on arithmetic that touches nothing:");
    for threads in [1usize, 2, 4] {
        bench_threads(&format!("spin x{threads}"), threads, 2000, || {
            let mut acc = 0u64;
            for i in 0..2000u64 {
                acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
            }
            std::hint::black_box(acc);
        });
    }

    println!();
    println!("concurrent stat, and a control that should not move:");
    for threads in [1usize, 2, 4, 8] {
        bench_threads(&format!("stat x{threads}"), threads, 20000, || {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            unsafe { libc::stat(cpath.as_ptr() as *const libc::c_char, &mut st) };
        });
        bench_threads(&format!("getpid x{threads} (control)"), threads, 20000, || {
            unsafe { libc::syscall(libc::SYS_getpid) };
        });
    }
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    // `syscall_bench <dir> spin` runs only the parallelism section, for long
    // enough to sample. Separated because the question it answers -- whether
    // guest threads run at the same time at all -- is about the emulator rather
    // than about any syscall, and mixing it with the rest makes a profile of it
    // impossible to read.
    if std::env::args().nth(2).as_deref() == Some("spin") {
        fn work() {
            let mut acc = 0u64;
            for i in 0..2000u64 {
                acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
            }
            std::hint::black_box(acc);
        }
        const ITERS: u32 = 60000;

        println!("parallelism, on arithmetic that touches nothing:");
        println!("  (per-call cost should FALL with the count if they run at once)");
        for threads in [1usize, 2, 4, 8] {
            bench_threads(&format!("threads x{threads}"), threads, ITERS, work);
        }

        // The same work in forked processes rather than threads. A process has
        // an address space of its own; a thread shares one. If these scale and
        // the threads above do not, that difference is the whole answer.
        println!();
        for procs in [1usize, 2, 4, 8] {
            work();
            let start = Instant::now();
            let mut kids = Vec::new();
            for _ in 0..procs {
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    for _ in 0..ITERS {
                        work();
                    }
                    unsafe { libc::_exit(0) };
                }
                kids.push(pid);
            }
            for pid in kids {
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
            }
            let elapsed = start.elapsed();
            let total = procs as u32 * ITERS;
            println!(
                "  {:<28} {:>9.0} ns/call   ({procs} processes x {ITERS})",
                format!("processes x{procs}"),
                elapsed.as_nanos() as f64 / total as f64
            );
        }
        return;
    }
    // `syscall_bench <dir> getpid [n]`: the dispatch path alone, for timing a
    // change to it against `compute_bench`.
    if std::env::args().nth(2).as_deref() == Some("getpid") {
        let n = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
        bench("getpid", n, || {
            unsafe { libc::syscall(libc::SYS_getpid) };
        });
        return;
    }
    let path = format!("{dir}/bench-target");
    let _ = std::fs::write(&path, vec![0u8; 65536]);

    let rd = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDONLY, 0) };
    let wr = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_WRONLY, 0) };
    if rd < 0 || wr < 0 {
        println!("could not open {path}");
        return;
    }

    println!("small syscalls on a realfs descriptor:");

    let mut buf = [0u8; 64];
    bench("read 64B", 20000, || {
        unsafe {
            libc::lseek(rd, 0, libc::SEEK_SET);
            libc::read(rd, buf.as_mut_ptr().cast(), 64);
        };
    });

    let out = [0u8; 64];
    bench("write 64B", 20000, || {
        unsafe {
            libc::lseek(wr, 0, libc::SEEK_SET);
            libc::write(wr, out.as_ptr().cast(), 64);
        };
    });

    let mut big = vec![0u8; 8192];
    bench("read 8KB (no shortcut)", 5000, || {
        unsafe {
            libc::lseek(rd, 0, libc::SEEK_SET);
            libc::read(rd, big.as_mut_ptr().cast(), 8192);
        };
    });

    bench("write 8KB (no shortcut)", 5000, || {
        unsafe {
            libc::lseek(wr, 0, libc::SEEK_SET);
            libc::write(wr, big.as_ptr().cast(), 8192);
        };
    });

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    bench("fstat", 20000, || {
        unsafe { libc::fstat(rd, &mut st) };
    });

    // How much a syscall pays for the *path* it was given, with fstat above as
    // the control: it does the same work minus the path, so a difference
    // between these three that fstat does not share is the path's cost.
    //
    // user_read_string used to call __user_read_mem for one character at a
    // time, and each of those walks the page table -- so a path cost one walk
    // per character rather than one per page.
    //
    // The long path is the *same path* padded with redundant slashes, which
    // normalisation collapses: the same components, the same lookups, the same
    // file. Padding with "./" instead would have added 96 components for
    // path_normalize to walk and measured that as well.
    let short = cstr(&path);
    let long_path = format!("{dir}/{}bench-target", "/".repeat(190));
    let long = cstr(&long_path);
    bench("stat, 20-byte path", 20000, || {
        unsafe { libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, short.as_ptr(), &raw mut st, 0) };
    });
    bench("stat, 210-byte path", 20000, || {
        unsafe { libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, long.as_ptr(), &raw mut st, 0) };
    });

    // A descriptor with no shortcut at all, for scale.
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    bench("write 64B to a pipe", 20000, || {
        unsafe {
            libc::write(fds[1], out.as_ptr().cast(), 64);
            let mut sink = [0u8; 64];
            libc::read(fds[0], sink.as_mut_ptr().cast(), 64);
        };
    });

    // poll's cost against the number of descriptors. sys_poll merges duplicate
    // descriptors with a nested loop over the whole array -- "FIXME this is
    // quadratic" -- so doubling the count should quadruple the time if that
    // dominates.
    println!("poll, by descriptor count:");
    let mut pipes = Vec::new();
    for _ in 0..1024 {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            break;
        }
        pipes.push(fds);
    }
    for n in [16usize, 64, 256, 512, 1024] {
        if pipes.len() < n {
            continue;
        }
        let mut set: Vec<libc::pollfd> = pipes[..n]
            .iter()
            .map(|p| libc::pollfd { fd: p[0], events: libc::POLLIN, revents: 0 })
            .collect();
        let iters = 2000u32;
        bench(&format!("poll {n} fds"), iters, || {
            unsafe { libc::poll(set.as_mut_ptr(), n as _, 0) };
        });
    }
    // The same descriptor named 256 times. sys_poll merges duplicates into one
    // host registration, so this separates the per-descriptor registration cost
    // from the per-entry bookkeeping: if registration dominates, this is far
    // cheaper than 256 distinct descriptors.
    if let Some(first) = pipes.first() {
        let mut same: Vec<libc::pollfd> = (0..256)
            .map(|_| libc::pollfd { fd: first[0], events: libc::POLLIN, revents: 0 })
            .collect();
        bench("poll 256 x the same fd", 2000, || {
            unsafe { libc::poll(same.as_mut_ptr(), 256, 0) };
        });
    }

    for p in &pipes {
        unsafe {
            libc::close(p[0]);
            libc::close(p[1]);
        }
    }

    unsafe {
        libc::close(rd);
        libc::close(wr);
        libc::close(fds[0]);
        libc::close(fds[1]);
    }

    bench_concurrent_stat(&dir);
}