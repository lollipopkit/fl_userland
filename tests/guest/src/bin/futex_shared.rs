//! A futex on a page two processes share.
//!
//! `MAP_SHARED|MAP_ANONYMOUS` survives `fork` uncopied — that is what
//! `P_SHARED` means to `pt_copy_on_write` — so a word on such a page is one
//! word seen by two processes. A futex on it is the shape every
//! `PTHREAD_PROCESS_SHARED` mutex, every `sem_t` in shared memory and every
//! inter-process condition variable is built from.
//!
//! `FUTEX_PRIVATE_FLAG` is what tells the two cases apart. Without it a futex
//! is keyed on **what the page is**, so the same page reached from two address
//! spaces is the same futex; with it, the kernel is allowed to key on the
//! address space and skip the lookup, which is why libc sets it whenever it
//! can.
//!
//! Nothing here tested it. Every futex test in this tree is within one process,
//! where the two keyings are indistinguishable.
//!
//! # Every wait has a timeout
//!
//! A lost wake is a hang, and a hang in a test is a suite that never finishes
//! rather than a failure anyone can read. So the parent waits with a deadline
//! and the finding is `ETIMEDOUT` where Linux answers 0.

use std::time::Instant;

use guest_tests::{Harness, check};

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;
const FUTEX_PRIVATE_FLAG: i32 = 128;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `futex(uaddr, op, val, timeout)`. Answers the raw return, or `-errno`.
fn futex(uaddr: *mut u32, op: i32, val: u32, timeout: Option<libc::timespec>) -> i64 {
    // The timespec has to outlive the call, so it is a local rather than a
    // temporary inside the argument list.
    let ts = timeout.unwrap_or(libc::timespec { tv_sec: 0, tv_nsec: 0 });
    let tp = if timeout.is_some() {
        &ts as *const libc::timespec
    } else {
        std::ptr::null()
    };
    let r = unsafe { libc::syscall(libc::SYS_futex, uaddr, op, val, tp, 0, 0) };
    if r < 0 { -(errno() as i64) } else { r }
}

fn shared_page() -> *mut u32 {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(p, libc::MAP_FAILED, "MAP_SHARED|MAP_ANONYMOUS");
    p.cast()
}

fn secs(n: i64) -> libc::timespec {
    libc::timespec {
        tv_sec: n as _,
        tv_nsec: 0,
    }
}

fn main() {
    let mut h = Harness::new();

    h.group("the-page-itself");
    let p = shared_page();
    unsafe { *p = 0 };
    // Before any futex question: is the page shared at all? A kernel that
    // copies it on fork fails everything below for a reason that has nothing
    // to do with futexes, and this is the check that says so.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { *p = 0xabcd };
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let seen = unsafe { std::ptr::read_volatile(p) };
    check!(h, seen == 0xabcd, "a child's write to a MAP_SHARED page is seen by the parent: {seen:#x}");

    h.group("shared-wake");
    unsafe { *p = 0 };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Long enough that the parent is certainly parked.
        unsafe { libc::usleep(200_000) };
        unsafe { std::ptr::write_volatile(p, 1) };
        futex(p, FUTEX_WAKE, 1, None);
        unsafe { libc::_exit(0) };
    }
    let start = Instant::now();
    let r = futex(p, FUTEX_WAIT, 0, Some(secs(3)));
    let ms = start.elapsed().as_millis();
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    check!(h, r == 0, "a FUTEX_WAKE from another process wakes the waiter: r={r}");
    check!(h, ms < 2000, "and it does not wait out the deadline: {ms}ms");
    let seen = unsafe { std::ptr::read_volatile(p) };
    check!(h, seen == 1, "and the word the child wrote is the one the parent sees: {seen}");

    h.group("private-wake");
    // The same thing within one process, which is what every other futex test
    // in this tree does and which the address-space keying answers correctly.
    // It is here as the control: if this fails too, the finding is not about
    // sharing.
    unsafe { *p = 0 };
    let word = p as usize;
    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let p = word as *mut u32;
        unsafe { std::ptr::write_volatile(p, 1) };
        futex(p, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, None);
    });
    let start = Instant::now();
    let r = futex(p, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, Some(secs(3)));
    let ms = start.elapsed().as_millis();
    t.join().ok();
    check!(h, r == 0, "a private FUTEX_WAKE wakes a thread of the same process: r={r}");
    check!(h, ms < 2000, "and promptly: {ms}ms");

    h.group("unflagged-on-a-private-page");
    // A futex *without* FUTEX_PRIVATE_FLAG on a mapping that is not shared.
    // Linux's get_futex_key falls back to the address-space key when the
    // mapping is not VM_MAYSHARE, whatever the flag said, and it has to: a
    // private page is copy-on-write, so its host address is the original
    // before the first write and the copy after it -- and a futex word is
    // being written by definition.
    //
    // Keying it on the host address anyway made every wake miss. This is that
    // case, and it is what `futex_pingpong` hung on.
    let priv_page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    check!(h, priv_page != libc::MAP_FAILED, "a MAP_PRIVATE page");
    let q: *mut u32 = priv_page.cast();
    // Written first, so the page is certainly its own copy by the time the
    // wait enqueues -- and then written again by the waker, which is the move
    // that changes a copy-on-write page's host address.
    unsafe { std::ptr::write_volatile(q, 0) };
    let word = q as usize;
    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let q = word as *mut u32;
        unsafe { std::ptr::write_volatile(q, 1) };
        futex(q, FUTEX_WAKE, 1, None);
    });
    let start = Instant::now();
    let r = futex(q, FUTEX_WAIT, 0, Some(secs(3)));
    let ms = start.elapsed().as_millis();
    t.join().ok();
    check!(h, r == 0, "an unflagged wake on a private page still arrives: r={r}");
    check!(h, ms < 2000, "and promptly: {ms}ms");
    unsafe { libc::munmap(priv_page, 4096) };

    h.group("value-check");
    // A wait whose word does not hold the expected value is EAGAIN, not a
    // wait -- across processes as within one.
    unsafe { *p = 7 };
    let r = futex(p, FUTEX_WAIT, 0, Some(secs(1)));
    check!(h, r == -(libc::EAGAIN as i64),
        "a shared FUTEX_WAIT on a word that already moved is EAGAIN: r={r}");

    h.group("no-waiter");
    // A wake with nobody parked answers 0 rather than an error.
    unsafe { *p = 0 };
    let r = futex(p, FUTEX_WAKE, 1, None);
    check!(h, r == 0, "a shared FUTEX_WAKE with no waiter wakes none: r={r}");

    unsafe { libc::munmap(p.cast(), 4096) };
    std::process::exit(h.finish());
}
