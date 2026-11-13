//! A pty, driven from both ends at once.
//!
//! `struct tty` has a lock each, and a pty is two of them wired together, so
//! every path that touches both is a chance to take them in a different order:
//!
//!   * a termios or winsize ioctl naming the **master** operates on the
//!     **slave** (`tty_mode_ioctl`), so it holds the master's lock and takes
//!     the slave's;
//!   * a write to the master is the slave's *input*, and echoing it sends the
//!     characters back to the master — which used to happen with the slave's
//!     lock held, taking the master's.
//!
//! Those two are a cycle, and it is not an exotic one: it is a terminal
//! emulator setting the window size while the user types. Both threads here do
//! only what such a program does.
//!
//! The check is progress. A deadlock is not a crash and not a wrong answer —
//! it is both threads stopping — so the probe watches its own counters and
//! says so.

use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

static IOCTLS: AtomicU64 = AtomicU64::new(0);
static WRITES: AtomicU64 = AtomicU64::new(0);
static READS: AtomicU64 = AtomicU64::new(0);

fn open_pair() -> Option<(i32, i32)> {
    // O_NOCTTY: see the note in poll_events.rs.
    let master = unsafe { libc::open(c"/dev/ptmx".as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        return None;
    }
    unsafe {
        libc::grantpt(master);
        libc::unlockpt(master);
    }
    let name = unsafe { libc::ptsname(master) };
    if name.is_null() {
        unsafe { libc::close(master) };
        return None;
    }
    let name = unsafe { CStr::from_ptr(name) }.to_owned();
    let slave = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave < 0 {
        unsafe { libc::close(master) };
        return None;
    }
    // Echo on, which is the default and is what sends a write to the master
    // back out of the master.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    unsafe {
        libc::tcgetattr(slave, &mut t);
        t.c_lflag |= libc::ECHO | libc::ICANON;
        libc::tcsetattr(slave, libc::TCSANOW, &t);
        // Non-blocking, so a full buffer is not mistaken for the hang.
        libc::fcntl(master, libc::F_SETFL, libc::O_NONBLOCK);
        libc::fcntl(slave, libc::F_SETFL, libc::O_NONBLOCK);
    }
    Some((master, slave))
}

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    let Some((master, slave)) = open_pair() else {
        println!("LOST: could not open a pty");
        println!("survived");
        return;
    };

    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();

    // What a terminal emulator does on a resize, and on any stty.
    {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    if libc::tcgetattr(master, &mut t) == 0 {
                        libc::tcsetattr(master, libc::TCSANOW, &t);
                    }
                    ws.ws_row = 24 + (n % 8) as u16;
                    ws.ws_col = 80;
                    libc::ioctl(master, libc::TIOCSWINSZ, &ws);
                    libc::ioctl(master, libc::TIOCGWINSZ, &mut ws);
                }
                n += 1;
                IOCTLS.fetch_add(1, Ordering::Relaxed);
            }
            n
        }));
    }

    // What it does with keystrokes: write to the master, and the slave's echo
    // comes back out of the master.
    {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut drain = [0u8; 4096];
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    libc::write(master, b"abcdefghij\n".as_ptr().cast(), 11);
                    libc::read(master, drain.as_mut_ptr().cast(), drain.len());
                }
                n += 1;
                WRITES.fetch_add(1, Ordering::Relaxed);
            }
            n
        }));
    }

    // And the program on the other side, reading its input and writing output.
    {
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    libc::read(slave, buf.as_mut_ptr().cast(), buf.len());
                    libc::write(slave, b"output\n".as_ptr().cast(), 7);
                }
                n += 1;
                READS.fetch_add(1, Ordering::Relaxed);
            }
            n
        }));
    }

    // Watch for a stall rather than waiting the whole time and finding out at
    // the end: a deadlock stops both counters, and if it happens the run must
    // say so rather than hanging until the harness gives up.
    let mut stalls = 0;
    let slices = seconds * 5;
    for _ in 0..slices {
        let before = (
            IOCTLS.load(Ordering::Relaxed),
            WRITES.load(Ordering::Relaxed),
            READS.load(Ordering::Relaxed),
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
        let after = (
            IOCTLS.load(Ordering::Relaxed),
            WRITES.load(Ordering::Relaxed),
            READS.load(Ordering::Relaxed),
        );
        if before == after {
            stalls += 1;
            // Two in a row is a stall, not a scheduling hiccup.
            if stalls >= 2 {
                println!("LOST: no thread made progress for 400ms: {after:?}");
                println!("survived");
                std::process::exit(0);
            }
        } else {
            stalls = 0;
        }
    }
    stop.store(true, Ordering::Relaxed);

    let counts: Vec<u64> = threads.into_iter().map(|t| t.join().unwrap_or(0)).collect();
    println!("iterations: {counts:?}");
    unsafe {
        libc::close(slave);
        libc::close(master);
    }
    println!("survived");
}
