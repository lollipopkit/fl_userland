//! Two threads reading one procfs descriptor.
//!
//! `sys_read` takes no `fd->lock` — only the *positional* calls do, and
//! `crates/kernel/rwcalls`' `FdGuard` says why: they hold it across a
//! seek-read-seek sequence. procfs declares `read: false` and `read_at: true`,
//! so a plain `read()` on a procfs file falls through `fd_read`'s capability
//! fallback into `FdOps::pread`, which reaches `proc_pread` with **no lock
//! held at all**.
//!
//! `proc_pread` calls `state(fd)`, which hands out a `&mut ProcFd` from
//! `fd->fs_data`, and `ProcFd` holds the generated file contents as a `Vec`
//! that `refresh` clears and refills. Two threads therefore hold two live
//! `&mut` to one object and mutate one `Vec` — which is the aliasing UB
//! `docs/changelog/2026-08-31-a-release-build-hung-closing-a-descriptor.md` records,
//! with a heap allocation in the middle of it.
//!
//! A rewind is what makes both threads regenerate: `proc_seek` sets
//! `data.valid = false` for an offset of zero, which is what `refresh` tests.
//!
//! Reproduced three times out of three on 2026-09-14, before the fix:
//!
//! ```text
//! panicked at crates/fs/proc/src/data.rs:109:
//!   range end index 2166 out of range for slice of length 1083
//! panic in a function that cannot unwind
//! ```
//!
//! 2166 is twice 1083: two `show` callbacks appending into one buffer, and one
//! of them reading a length the other had already reset. The panic is inside a
//! syscall shim, so it aborts — a guest thread takes the emulator down.
//!
//! **`crates/fs/tmpfs` has the same shape and got it right**: its `FdState`
//! holds `dir_pos: Mutex<DirPos>`. Three unrelated implementations of one
//! interface, which is what `fs_conformance` exists to compare — except this
//! one is a race, and that suite asks each mount the same questions from one
//! thread.
//!
//! The check is that the emulator is still alive: it prints `survived`.

use std::os::unix::io::AsRawFd;

fn main() {
    let rounds: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);

    // A file with a `show` callback, so that a rewind makes the next read
    // regenerate it. `status` is several hundred bytes, which is enough for
    // the two appends to overlap.
    let f = std::fs::File::open("/proc/self/status").expect("/proc/self/status");
    let fd = f.as_raw_fd();
    println!("two threads, {rounds} rewind-and-read rounds each on fd {fd}");

    let threads: Vec<_> = (0..2)
        .map(|_| {
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut refused = 0usize;
                for _ in 0..rounds {
                    // The rewind invalidates the cached contents, so the read
                    // below regenerates them. Both threads do it.
                    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
                    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                    if n < 0 {
                        refused += 1;
                    }
                }
                refused
            })
        })
        .collect();

    // The counts are not the check and are not asserted: two threads sharing
    // one file position get short reads by construction, and how many is a
    // scheduling question. What is being asked is whether the emulator is
    // still here.
    let refused: usize = threads.into_iter().map(|t| t.join().expect("thread")).sum();
    println!("{refused} reads answered an error");
    println!("survived");
}
