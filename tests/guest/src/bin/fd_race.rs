//! The descriptor table, from several threads at once.
//!
//! `mount_race` is TSan-clean, but it never duplicates a descriptor — which is
//! why two suspected races in `fs/fd.c` went unreported there and were recorded
//! rather than fixed. This exercises what that one does not: `dup`, `dup2`,
//! `dup3`, `fcntl(F_DUPFD)` and `fcntl(F_DUPFD_CLOEXEC)` racing each other and
//! racing `open` and `close` on one shared table, plus the close-on-exec bit
//! being set and read throughout.
//!
//! The check is that the emulator is still alive and the table is still
//! coherent at the end. Run it under ThreadSanitizer for the rest.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn open_something() -> i32 {
    unsafe { libc::open(cstr("/etc/passwd").as_ptr(), libc::O_RDONLY) }
}

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();

    // Open and close, so the table is churning underneath everything else.
    for _ in 0..2 {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let fd = open_something();
                if fd >= 0 {
                    unsafe { libc::close(fd) };
                }
                n += 1;
            }
            n
        }));
    }

    // Duplicate, every way there is to.
    for which in 0..3u32 {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let fd = open_something();
                if fd < 0 {
                    continue;
                }
                unsafe {
                    let dup = match which {
                        0 => libc::dup(fd),
                        1 => libc::fcntl(fd, libc::F_DUPFD, 100),
                        _ => libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 200),
                    };
                    if dup >= 0 {
                        // dup3 onto a descriptor this thread owns. This is
                        // the thread that mattered: with it removed the
                        // close-on-exec check below never fired, and with it
                        // present it fired about a hundred times in three
                        // seconds before sys_dup3 became one critical section.
                        let target = libc::dup(fd);
                        if target >= 0 {
                            libc::dup3(fd, target, libc::O_CLOEXEC);
                            libc::close(target);
                        }
                        libc::close(dup);
                    }
                    libc::close(fd);
                }
                n += 1;
            }
            n
        }));
    }

    // Set and read the close-on-exec bit, by both routes.
    for _ in 0..2 {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let fd = open_something();
                if fd < 0 {
                    continue;
                }
                unsafe {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                    let got = libc::fcntl(fd, libc::F_GETFD);
                    // The bit this thread just set on its own descriptor has
                    // to read back: another thread's write to a neighbouring
                    // bit in the same byte must not clear it.
                    // The bit this thread just set on its own descriptor has
                    // to read back. It did not when dup3 could close a slot,
                    // let another thread's open win it, and then install over
                    // the top — the descriptor number was no longer this
                    // thread's file at all.
                    if got >= 0 && got & libc::FD_CLOEXEC == 0 {
                        println!("LOST: F_SETFD on fd {fd} read back as {got}");
                    }
                    libc::ioctl(fd, libc::FIOCLEX);
                    libc::close(fd);
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
