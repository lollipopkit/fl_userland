//! A POSIX timer aimed at a thread by tid, after that thread has gone and its
//! number has been handed to another.
//!
//! `timer_create(SIGEV_THREAD_ID)` names a thread by number, and the timer
//! outlives the thread. Linux keeps a `struct pid` in the timer, so a thread
//! that exits takes the timer's target with it: the timer fires and delivers
//! nowhere, however many times the number is handed out again. This kernel
//! stored the bare number, under a TODO saying pids get reused, and looked it
//! up when the timer fired -- so once the numbers wrapped, the timer signalled
//! whatever thread had been given the dead one's tid.
//!
//! Numbers wrap at `MAX_PID`, 32768, so making the reuse happen means creating
//! that many threads. They are cheap here -- a small stack, created and joined,
//! about five seconds for the table -- and the loop stops the moment a thread
//! gets the number it is waiting for, or gives up after twice the table.
//!
//! The control is the same timer aimed at a thread that is still alive.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Which thread the `SIGALRM` handler ran on, or 0 for none.
static RECEIVED_BY: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_alarm(_sig: i32) {
    RECEIVED_BY.store(gettid(), Ordering::SeqCst);
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

const SIGEV_THREAD_ID: i32 = 4;
const NR_TIMER_CREATE: i64 = 107;
const NR_TIMER_SETTIME: i64 = 110;
const NR_TIMER_DELETE: i64 = 111;

/// `timer_create(CLOCK_MONOTONIC, SIGEV_THREAD_ID -> tid, SIGALRM)`, raw:
/// libc's `sigevent` spells the tid field differently per libc, and the
/// kernel's layout is the one under test -- `sigev_value` at 0, `sigev_signo`
/// at 8, `sigev_notify` at 12, the tid at 16.
fn timer_for_thread(tid: i32) -> Result<i32, i32> {
    let mut sigev = [0u8; 64];
    sigev[8..12].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    sigev[12..16].copy_from_slice(&SIGEV_THREAD_ID.to_ne_bytes());
    sigev[16..20].copy_from_slice(&tid.to_ne_bytes());
    let mut id: i32 = -1;
    let r = unsafe {
        libc::syscall(
            NR_TIMER_CREATE,
            libc::CLOCK_MONOTONIC,
            sigev.as_ptr(),
            &mut id as *mut i32,
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(id)
    }
}

/// Arm for 10 ms, once.
fn arm(id: i32) -> i64 {
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec { tv_sec: 0, tv_nsec: 10_000_000 },
    };
    unsafe {
        libc::syscall(
            NR_TIMER_SETTIME,
            id,
            0,
            &spec as *const libc::itimerspec,
            std::ptr::null_mut::<libc::itimerspec>(),
        )
    }
}

/// A thread that reports its tid and then waits to be released.
fn parked() -> (i32, mpsc::Sender<()>, thread::JoinHandle<()>) {
    let (tid_tx, tid_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let handle = thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || {
            tid_tx.send(gettid()).unwrap();
            let _ = go_rx.recv();
        })
        .unwrap();
    (tid_rx.recv().unwrap(), go_tx, handle)
}

fn main() {
    let mut h = Harness::new();
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = on_alarm as *const () as usize;
        libc::sigemptyset(&mut act.sa_mask);
        libc::sigaction(libc::SIGALRM, &act, std::ptr::null_mut());
    }

    // The control: a timer aimed at a living thread reaches it.
    {
        let (tid, release, handle) = parked();
        let id = timer_for_thread(tid).expect("timer_create for a live thread");
        RECEIVED_BY.store(0, Ordering::SeqCst);
        check!(h, arm(id) == 0, "the timer arms");
        thread::sleep(Duration::from_millis(200));
        check!(
            h,
            RECEIVED_BY.load(Ordering::SeqCst) == tid,
            "a living thread gets the signal"
        );
        unsafe { libc::syscall(NR_TIMER_DELETE, id) };
        release.send(()).unwrap();
        handle.join().unwrap();
    }

    // The case: the thread exits, its number comes round again, and the
    // timer must not follow the number.
    {
        let (dead_tid, release, handle) = parked();
        let id = timer_for_thread(dead_tid).expect("timer_create for the thread that will exit");
        release.send(()).unwrap();
        handle.join().unwrap();

        // Cycle through the table until a thread is handed the dead one's
        // number, keeping that one alive.
        //
        // How many that takes is the allocator's range. This kernel's `MAX_PID`
        // is 32768 and it wraps in a second; Linux's `pid_max` defaults to
        // 4194304 on a 64-bit machine, so the number does not come round inside
        // any budget a test can spend. The loop is sized from what the kernel
        // says, and **not reaching it is a skip rather than a failure** --
        // `check!(reused.is_some())` asserted a property of the allocator's
        // range, which is not what this test is about, and reported the
        // emulator and Linux as disagreeing about POSIX timers when they were
        // disagreeing about how quickly a tid comes round.
        let pid_max: u64 = std::fs::read_to_string("/proc/sys/kernel/pid_max")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(32768);
        let budget = if pid_max > 65536 { 0 } else { 2 * pid_max };
        let mut reused = None;
        for _ in 0..budget {
            let (tid, release, handle) = parked();
            if tid == dead_tid {
                reused = Some((release, handle));
                break;
            }
            release.send(()).unwrap();
            handle.join().unwrap();
        }
        if reused.is_none() {
            println!(
                "skipped: pid_max is {pid_max}, so a tid does not come round \
                 inside a budget a test can spend"
            );
        }
        if let Some((release, handle)) = reused {
            RECEIVED_BY.store(0, Ordering::SeqCst);
            check!(h, arm(id) == 0, "the timer still arms");
            thread::sleep(Duration::from_millis(200));
            check!(
                h,
                RECEIVED_BY.load(Ordering::SeqCst) == 0,
                "the thread that inherited the number is not signalled"
            );
            release.send(()).unwrap();
            handle.join().unwrap();
        }
        unsafe { libc::syscall(NR_TIMER_DELETE, id) };
    }

    std::process::exit(h.finish());
}
