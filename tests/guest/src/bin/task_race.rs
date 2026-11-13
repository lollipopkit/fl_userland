//! Task lifetime, from several threads at once.
//!
//! The most delicate area in this tree, by its own changelog: `task_destroy`
//! zeroes a task to poison stale `current` references from leaked pthreads,
//! the group-exit safety valve force-releases a stuck thread's files and mm,
//! and a blocking syscall can return to find its own task already torn down.
//! None of the existing probes create or destroy a task.
//!
//! Threads here fork and reap, exec and reap, spawn threads that exit
//! immediately, exit a group from a non-leader thread, and signal each other
//! throughout — while another reads `/proc` over the top, which is the reader
//! that has to cope with a task disappearing mid-walk.
//!
//! The check is that the emulator is still alive and every child is accounted
//! for. Run it under the sanitizers for the rest.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

static LOST: AtomicU64 = AtomicU64::new(0);
/// How many `/proc/<pid>/mem` reads reached the kernel, so a clean run is
/// known to have exercised the path rather than skipped it.
static MEM_READS: AtomicU64 = AtomicU64::new(0);

/// fork, and reap what we forked. A child that comes back with the wrong
/// status, or does not come back, is the finding.
fn fork_and_reap(body: impl FnOnce()) {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            body();
            libc::_exit(42);
        }
        if pid < 0 {
            return;
        }
        let mut status = 0;
        let got = libc::waitpid(pid, &mut status, 0);
        if got != pid {
            println!("LOST: waitpid({pid}) returned {got} errno {}", guest_tests::sys::errno());
            LOST.fetch_add(1, Ordering::Relaxed);
        } else if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) != 42 {
            println!("LOST: child {pid} exited {}", libc::WEXITSTATUS(status));
            LOST.fetch_add(1, Ordering::Relaxed);
        }
    }
}

extern "C" fn ignore(_: libc::c_int) {}

/// What the `group` child becomes after it execs: several threads, joined, and
/// then the exit code `fork_and_reap` expects.
///
/// **It has to be after an exec.** POSIX allows a child of `fork` in a
/// multithreaded process only async-signal-safe calls until it execs, and
/// `std::thread::spawn` is not one: it allocates, and Rust's `std` takes a lock
/// of its own. The child used to spawn directly, and inherited that lock
/// *already held* by a thread that did not come across the fork -- so its three
/// new threads blocked on it for ever while the forked thread joined them.
///
/// That is the `task_race` deadlock this file's own changelog chased for ten
/// days. The evidence is in
/// `docs/changelog/2026-08-22-a-deadlock-seen-once-in-task-race.md`: the hung
/// process had never written the futex word it was waiting on, which only a
/// fork child can manage.
fn group_child() -> ! {
    let hs: Vec<_> = (0..3)
        .map(|_| {
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(1));
            })
        })
        .collect();
    for h in hs {
        let _ = h.join();
    }
    unsafe { libc::_exit(42) }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--group-child") {
        group_child();
    }
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = ignore as *const () as usize;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }

    // Which threads to run, so the probe can be bisected: any subset of
    // "fork", "exec", "group", "signal", "proc".
    let only: Vec<String> = std::env::args().skip(2).collect();
    let want = |n: &str| only.is_empty() || only.iter().any(|s| s == n);

    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();

    // Plain fork and exit.
    for _ in 0..(if want("fork") { 2 } else { 0 }) {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                fork_and_reap(|| {});
                n += 1;
            }
            n
        }));
    }

    // fork then exec, so a whole address space is replaced and torn down.
    if want("exec") {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    let pid = libc::fork();
                    if pid == 0 {
                        let sh = cstr("/bin/busybox");
                        let a0 = cstr("busybox");
                        let a1 = cstr("true");
                        libc::execl(
                            sh.as_ptr() as *const libc::c_char,
                            a0.as_ptr() as *const libc::c_char,
                            a1.as_ptr() as *const libc::c_char,
                            std::ptr::null::<libc::c_char>(),
                        );
                        libc::_exit(1);
                    }
                    if pid > 0 {
                        let mut status = 0;
                        libc::waitpid(pid, &mut status, 0);
                    }
                }
                n += 1;
            }
            n
        }));
    }

    // A child that execs, spawns threads and lets the group exit from one of
    // them — the path the group-exit safety valve exists for.
    if want("group") {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                // The child execs *before* it spawns anything; see group_child.
                fork_and_reap(|| unsafe {
                    let exe = cstr("/proc/self/exe");
                    let a0 = cstr("task_race");
                    let a1 = cstr("--group-child");
                    libc::execl(
                        exe.as_ptr() as *const libc::c_char,
                        a0.as_ptr() as *const libc::c_char,
                        a1.as_ptr() as *const libc::c_char,
                        std::ptr::null::<libc::c_char>(),
                    );
                    // An exec that fails must still exit the way the reaper
                    // expects, or the failure reads as a lost child.
                    libc::_exit(42);
                });
                n += 1;
            }
            n
        }));
    }

    // Sessions and process groups, from forked children: setsid and setpgid
    // rewrite tgroup->sid, ->pgid and ->tty, which /proc/<pid>/stat reads and
    // which a tty open reads and writes when it takes a controlling terminal.
    if want("session") {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                fork_and_reap(|| unsafe {
                    libc::setsid();
                    libc::setpgid(0, 0);
                    // Take a controlling terminal, which is the other writer
                    // of the same fields.
                    // O_NOCTTY: see the note in poll_events.rs.
                    let fd = libc::open(c"/dev/ptmx".as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
                    if fd >= 0 {
                        libc::grantpt(fd);
                        libc::unlockpt(fd);
                        let name = libc::ptsname(fd);
                        if !name.is_null() {
                            let s = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
                            if s >= 0 {
                                libc::ioctl(s, libc::TIOCSCTTY, 0);
                                libc::close(s);
                            }
                        }
                        libc::close(fd);
                    }
                    libc::setpgid(0, 0);
                });
                n += 1;
            }
            n
        }));
    }

    // Signals at whatever is running, including ourselves.
    if want("signal") {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                unsafe { libc::raise(libc::SIGUSR1) };
                n += 1;
            }
            n
        }));
    }

    // Read /proc over the top: the reader that has to cope with a task
    // vanishing between being listed and being described.
    if want("proc") || only.iter().any(|s| ["stat","statm","exe","maps","mem"].contains(&s.as_str())) {
        let stop = stop.clone();
        let only2 = only.clone();
        let want2 = move |n: &str| only2.is_empty() || only2.iter().any(|s| s == n)
            || only2.iter().any(|s| s == "proc");
        threads.push(std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                if let Ok(d) = std::fs::read_dir("/proc") {
                    for e in d.flatten() {
                        if want2("stat") {
                            let _ = std::fs::read_to_string(e.path().join("stat"));
                        }
                        if want2("statm") {
                            let _ = std::fs::read_to_string(e.path().join("statm"));
                        }
                        if want2("maps") {
                            let _ = std::fs::read_to_string(e.path().join("maps"));
                        }
                        if want2("exe") {
                            let _ = std::fs::read_link(e.path().join("exe"));
                        }
                        // A read through another task's address space, which
                        // an exec in the `exec` thread replaces under it. The
                        // address need not be mapped: the lock is taken first.
                        if want2("mem") {
                            use std::os::unix::fs::FileExt;
                            if let Ok(f) = std::fs::File::open(e.path().join("mem")) {
                                let mut word = [0u8; 8];
                                let _ = f.read_at(&mut word, 0x40_0000);
                                MEM_READS.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
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
    println!("lost: {}", LOST.load(Ordering::Relaxed));
    println!("mem reads: {}", MEM_READS.load(Ordering::Relaxed));
    println!("survived");
}
