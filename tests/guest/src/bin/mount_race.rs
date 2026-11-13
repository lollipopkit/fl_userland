//! Does traversing the mount list without `mounts_lock` come apart?
//!
//! `kernel/fs.h` states the rule beside the lock: "must hold mounts_lock while
//! calling these, or traversing mounts". Two traversals did not — the one
//! behind `/proc/mounts`, and `contains_mount_point`, which `rename` and
//! `rmdir` reach on every call.
//!
//! One thread mounts and unmounts a tmpfs in a loop while others read
//! `/proc/mounts` and rmdir a directory. Prints "survived" if the emulator is
//! still alive at the end; a crash is the finding.
//!
//! Also exercises the lock order between the pid table and the filesystem
//! locks. `/proc/<pid>/exe`, `/cwd` and `/fd/N` all resolve a descriptor to a
//! path, and `generic_getpath` takes the mount table and the real filesystem's
//! locks — so a procfs callback that still held `pids_lock` across it would be
//! taking them in the opposite order from everything that locks a mount first
//! and looks up a task second. That inversion was found in the field, as an
//! intermittent hang with twenty-odd workers scanning `/proc/self/fd`; a hang
//! here shows as the harness having to kill this program.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let stop = Arc::new(AtomicBool::new(false));

    unsafe {
        libc::mkdir(cstr("/mnt/race").as_ptr(), 0o755);
        libc::mkdir(cstr("/mnt/racedir").as_ptr(), 0o755);
    }

    let mut threads = Vec::new();

    // Churn the list.
    {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    let src = cstr("none");
                    let dst = cstr("/mnt/race");
                    let fs = cstr("tmpfs");
                    libc::mount(src.as_ptr(), dst.as_ptr(), fs.as_ptr(), 0, std::ptr::null());
                    libc::umount(dst.as_ptr());
                }
                n += 1;
            }
            n
        }));
    }

    // Read it.
    for _ in 0..2 {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            let mut buf = String::new();
            while !stop.load(Ordering::Relaxed) {
                buf.clear();
                if let Ok(mut f) = std::fs::File::open("/proc/mounts") {
                    let _ = f.read_to_string(&mut buf);
                }
                n += 1;
            }
            n
        }));
    }

    // Resolve descriptors to paths, which is what takes the filesystem locks.
    for _ in 0..2 {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            let mut buf = [0u8; 4096];
            while !stop.load(Ordering::Relaxed) {
                for p in ["/proc/self/exe", "/proc/self/cwd", "/proc/self/fd/0"] {
                    unsafe {
                        libc::readlink(cstr(p).as_ptr(), buf.as_mut_ptr().cast(), buf.len());
                    }
                }
                // And a whole directory of them.
                if let Ok(d) = std::fs::read_dir("/proc/self/fd") {
                    for e in d.flatten() {
                        let _ = std::fs::read_link(e.path());
                    }
                }
                n += 1;
            }
            n
        }));
    }

    // And walk it from the other direction: rmdir calls contains_mount_point.
    {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    libc::rmdir(cstr("/mnt/racedir").as_ptr());
                    libc::mkdir(cstr("/mnt/racedir").as_ptr(), 0o755);
                }
                n += 1;
            }
            n
        }));
    }

    std::thread::sleep(std::time::Duration::from_secs(seconds));
    stop.store(true, Ordering::Relaxed);
    let counts: Vec<u64> = threads.into_iter().map(|t| t.join().unwrap_or(0)).collect();
    println!("iterations: {counts:?}");
    println!("survived");
}
