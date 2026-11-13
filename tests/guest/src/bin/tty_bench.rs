//! What a terminal read and write cost, and what a global lock adds to them.
//!
//! Every `read` and every `write` on a terminal takes `pids_lock` — the
//! kernel-wide lock that every fork, exit, wait and kill also takes — to decide
//! whether the caller is in the foreground process group, and to ask whether
//! that group is orphaned. Both facts are needed only when the caller is *not*
//! in the foreground, which for an interactive terminal is never.
//!
//! A pipe is the control. It carries the same bytes through the same syscall
//! entry and the same emulator, and its read path takes no process lock at all,
//! so whatever the background threads cost a pipe is scheduling. Whatever they
//! cost a pty *beyond* that is the lock. Without the control the number says
//! only that three more emulated threads make everything slower, which is true
//! and useless.

use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

fn open_pty() -> Option<(i32, i32)> {
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        return None;
    }
    if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
        unsafe { libc::close(master) };
        return None;
    }
    let mut name = [0u8; 128];
    if unsafe { libc::ptsname_r(master, name.as_mut_ptr().cast(), name.len()) } != 0 {
        unsafe { libc::close(master) };
        return None;
    }
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let path = CString::new(&name[..end]).ok()?;
    let slave = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave < 0 {
        unsafe { libc::close(master) };
        return None;
    }
    // Raw mode: this is about the syscall's fixed cost, not about the line
    // discipline deciding where a line ends.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(slave, &mut t) == 0 {
            libc::cfmakeraw(&mut t);
            libc::tcsetattr(slave, libc::TCSANOW, &t);
        }
    }
    Some((master, slave))
}

/// One write into the master and one read out of the slave, `rounds` times.
/// Returns microseconds per round trip.
fn round_trips(master: i32, slave: i32, rounds: usize) -> f64 {
    let payload = [b'x'; 64];
    let mut buf = [0u8; 256];
    // One untimed pass: the first one through any path pays for what it
    // allocates, and that is not what this measures.
    unsafe {
        libc::write(master, payload.as_ptr().cast(), payload.len());
        libc::read(slave, buf.as_mut_ptr().cast(), buf.len());
    }
    let t = Instant::now();
    let mut moved = 0i64;
    for _ in 0..rounds {
        let w = unsafe { libc::write(master, payload.as_ptr().cast(), payload.len()) };
        let r = unsafe { libc::read(slave, buf.as_mut_ptr().cast(), buf.len()) };
        moved += (w.max(0) + r.max(0)) as i64;
    }
    let secs = t.elapsed().as_secs_f64();
    // Asserted rather than reported: a terminal that refuses everything is very
    // fast, and a benchmark that measured the refusal has happened twice in
    // this tree.
    assert!(
        moved >= (rounds * payload.len()) as i64,
        "only {moved} bytes moved in {rounds} rounds -- the pty was not carrying data"
    );
    secs / rounds as f64 * 1e6
}

/// Threads doing process bookkeeping. Every one of these calls takes
/// `pids_lock`, the kernel-wide lock the terminal path also took.
fn background(stop: Arc<AtomicBool>, n: usize) -> Vec<std::thread::JoinHandle<()>> {
    (0..n)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    unsafe {
                        libc::getpgid(0);
                        libc::getsid(0);
                        libc::getppid();
                    }
                }
            })
        })
        .collect()
}

fn main() {
    let Some((master, slave)) = open_pty() else {
        println!("no pty available");
        return;
    };
    // A pipe is the control, and it is what makes the number mean something.
    // It carries the same bytes through the same syscall entry and the same
    // emulator, and its read path takes no process lock at all. So whatever the
    // background threads cost a pipe is scheduling; whatever they cost a pty
    // *beyond* that is the lock.
    let mut pipefd = [0i32; 2];
    if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
        println!("no pipe");
        return;
    }
    const ROUNDS: usize = 20000;

    let pty_quiet = round_trips(master, slave, ROUNDS);
    let pipe_quiet = round_trips(pipefd[1], pipefd[0], ROUNDS);

    let stop = Arc::new(AtomicBool::new(false));
    let threads = background(stop.clone(), 3);
    let pty_busy = round_trips(master, slave, ROUNDS);
    let pipe_busy = round_trips(pipefd[1], pipefd[0], ROUNDS);
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        t.join().ok();
    }

    println!("{:<8}{:>12}{:>12}{:>10}", "", "quiet", "+3 pids", "ratio");
    println!("{:<8}{pty_quiet:>12.3}{pty_busy:>12.3}{:>10.2}", "pty", pty_busy / pty_quiet);
    println!("{:<8}{pipe_quiet:>12.3}{pipe_busy:>12.3}{:>10.2}", "pipe", pipe_busy / pipe_quiet);
    // Above 1 means the terminal loses more to process bookkeeping than a pipe
    // carrying the same bytes does, which is the lock and nothing else.
    println!("pty/pipe under load = {:.2}x",
             (pty_busy / pty_quiet) / (pipe_busy / pipe_quiet));

    unsafe { libc::close(slave) };
    unsafe { libc::close(master) };
    unsafe { libc::close(pipefd[0]) };
    unsafe { libc::close(pipefd[1]) };
}
