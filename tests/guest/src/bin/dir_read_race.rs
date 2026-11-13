//! Two threads listing one directory descriptor.
//!
//! `sys_getdents64` takes no `fd->lock` — only the *positional* read and write
//! calls do. Linux serialises it: `getdents64` enters through `fdget_pos`,
//! which takes `f_pos_lock` whenever the description is shared, and
//! `iterate_dir` takes the inode's `i_rwsem` on top of that. Sharing a
//! descriptor is ordinary — `dup`, or `CLONE_FILES`, which every pthread is.
//!
//! Without a lock the loop in `crates/fs/dircalls` is `telldir`, `readdir`,
//! `telldir`, and at the end `seekdir` back to the entry that did not fit.
//! Interleaving two of those on one stream gives duplicated and skipped
//! entries, which is a wrong answer. Two things underneath it are worse, and
//! both are **lazy installs of per-descriptor state on the first listing**:
//!
//! - **`crates/fs/realfs`'s `open_stream`.** Two threads that both find
//!   `fd->dir` null both `dup` the descriptor, both `fdopendir`, and both
//!   store — so one `DIR *` and the **host descriptor inside it** are leaked
//!   with nothing left pointing at them. A guest that repeats it drives the
//!   emulator out of host descriptors. Afterwards both threads read through
//!   the surviving stream, and `readdir` answers a pointer into that stream's
//!   own buffer, which `seekdir` on the other thread can reallocate.
//! - **`crates/fs/fake`'s `dir_path`**, which installs its `DirCache` the same
//!   way: four kilobytes leaked a time, and two threads writing one cache.
//!
//! The window is the *first* listing of each descriptor, so hammering one fd
//! does not reach it — the first phase below opens a descriptor per round and
//! releases both threads into it at once.
//!
//! The check is that listings still work: a leaked stream is invisible until
//! the emulator runs out of descriptors, at which point every `open_stream`
//! answers `EIO` and nothing can be listed at all.
//!
//! # What this covers and what it does not
//!
//! Both installs are a **compare-exchange** as of 2026-09-14, so they are
//! correct on their own and this test passes with `sys_getdents64`'s
//! `fd->lock` backed out — measured, three runs of three. The lock is still
//! right and still there: it is what makes the `telldir`, `readdir`,
//! `seekdir` *sequence* one operation, which is a different property and is
//! what Linux's `f_pos_lock` is for.
//!
//! **That property has no test.** [`records_are_sane`] was added to look for
//! it — a name read out of a stream buffer another thread reallocated would
//! come back malformed — and it does not fire with the lock removed, so it
//! does not distinguish the two. It stays because it asserts something real
//! about the wire format under concurrency and costs nothing; it is not
//! evidence about the lock. Saying so is the point: a gate that covers the
//! install reads exactly like one that covers both.
//!
//! Run against both mounts. `./build/iul -r <dir>` is realfs and `-f <dir>` is
//! fakefs, and the two keep different state behind the same descriptor.

use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

fn getdents(fd: i32, buf: &mut [u8]) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            fd as libc::c_long,
            buf.as_mut_ptr() as libc::c_long,
            buf.len() as libc::c_long,
        )
    }
}

/// Whether every record in `n` bytes of a `getdents64` answer is well-formed.
///
/// This is the half of the test that covers the **sequence** rather than the
/// install. `readdir` on the host answers a pointer into the directory
/// stream's own buffer, and another thread's `seekdir` can reallocate it — so a
/// listing built without a lock can carry a name read out of freed memory.
/// That shows up here as a `d_reclen` outside the record's own bounds or a name
/// with no terminator inside it, neither of which a "did it survive" check
/// sees.
///
/// The layout is `struct linux_dirent64`: `u64 d_ino`, `i64 d_off`,
/// `u16 d_reclen`, `u8 d_type`, then the name and its NUL.
fn records_are_sane(buf: &[u8], n: usize) -> Result<usize, String> {
    const HEAD: usize = 8 + 8 + 2 + 1;
    let mut at = 0usize;
    let mut count = 0usize;
    while at < n {
        if n - at < HEAD {
            return Err(format!("{} bytes left, less than a header", n - at));
        }
        let reclen = u16::from_ne_bytes([buf[at + 16], buf[at + 17]]) as usize;
        if reclen < HEAD + 1 || reclen > n - at {
            return Err(format!("record at {at} has d_reclen {reclen}, {n} answered"));
        }
        let name = &buf[at + HEAD..at + reclen];
        let end = name
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| format!("record at {at} has no terminator in {reclen} bytes"))?;
        if end == 0 {
            return Err(format!("record at {at} has an empty name"));
        }
        if name[..end].iter().any(|&b| b < 0x20) {
            return Err(format!("record at {at} has a control byte in its name"));
        }
        at += reclen;
        count += 1;
    }
    Ok(count)
}

/// One listing of `dir` through a descriptor of its own, start to finish.
fn lists(dir: &str) -> bool {
    let Ok(f) = std::fs::File::open(dir) else {
        return false;
    };
    let mut buf = [0u8; 8192];
    getdents(f.as_raw_fd(), &mut buf) > 0
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().unwrap_or_else(|| "/usr/bin".into());
    let rounds: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(2000);

    println!("{rounds} rounds of two threads racing the first listing of {dir}");

    // Three parties: the two readers and the thread that opens and closes.
    let gate = Arc::new(Barrier::new(3));
    let shared = Arc::new(AtomicI32::new(-1));
    let stop = Arc::new(AtomicBool::new(false));
    let refused = Arc::new(AtomicUsize::new(0));
    // The first malformed record any thread saw, kept rather than counted: one
    // is the finding and the rest are the same finding.
    let bad: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));

    let readers: Vec<_> = (0..2)
        .map(|_| {
            let (gate, shared, stop, refused, bad) = (
                gate.clone(),
                shared.clone(),
                stop.clone(),
                refused.clone(),
                bad.clone(),
            );
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    gate.wait();
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let fd = shared.load(Ordering::Relaxed);
                    // The *first* listing of this descriptor, from both
                    // threads, which is the window the lazy installs have.
                    let n = getdents(fd, &mut buf);
                    if n < 0 {
                        refused.fetch_add(1, Ordering::Relaxed);
                    } else if let Err(why) = records_are_sane(&buf, n as usize) {
                        bad.lock().unwrap().get_or_insert(why);
                    }
                    gate.wait();
                }
            })
        })
        .collect();

    for _ in 0..rounds {
        let Ok(f) = std::fs::File::open(&dir) else {
            println!("could not open {dir}: out of descriptors already");
            std::process::exit(1);
        };
        shared.store(f.as_raw_fd(), Ordering::Relaxed);
        gate.wait();
        gate.wait();
        drop(f);
    }
    stop.store(true, Ordering::Relaxed);
    gate.wait();
    for t in readers {
        t.join().expect("thread");
    }

    let refused = refused.load(Ordering::Relaxed);
    println!("{refused} of {} listings answered an error", rounds * 2);
    if let Some(why) = bad.lock().unwrap().take() {
        println!("a listing came back malformed: {why}");
        std::process::exit(1);
    }

    // A descriptor that was closed while a leaked stream still held a dup of
    // it leaves the host descriptor behind, and nothing will ever close it.
    // Sixty-four fresh listings is what asks whether that has happened: the
    // emulator opens one host descriptor per directory it lists.
    for i in 0..64 {
        if !lists(&dir) {
            println!("a fresh listing of {dir} failed after {i} tries");
            std::process::exit(1);
        }
    }

    // And the sustained case, which is the data race rather than the leak:
    // both threads inside one already-installed stream.
    let f = std::fs::File::open(&dir).expect("reopen");
    let fd = f.as_raw_fd();
    let hammer: Vec<_> = (0..2)
        .map(|_| {
            let bad = bad.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                for _ in 0..rounds {
                    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
                    let n = getdents(fd, &mut buf);
                    if n > 0
                        && let Err(why) = records_are_sane(&buf, n as usize)
                    {
                        bad.lock().unwrap().get_or_insert(why);
                    }
                }
            })
        })
        .collect();
    for t in hammer {
        t.join().expect("thread");
    }

    if !lists(&dir) {
        println!("a fresh listing of {dir} failed after the sustained phase");
        std::process::exit(1);
    }
    if let Some(why) = bad.lock().unwrap().take() {
        println!("a listing came back malformed: {why}");
        std::process::exit(1);
    }

    println!("survived");
}
