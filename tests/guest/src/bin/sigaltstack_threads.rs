//! `sigaltstack` is per **thread**, and a handler runs on the stack of the
//! thread it was delivered to.
//!
//! Linux keeps `sas_ss_sp` in `task_struct`. This kernel kept it in the
//! disposition table -- one per *process* -- until 2026-09-04, so every
//! thread's `sigaltstack` overwrote the one before it, and a signal delivered
//! to thread A ran A's handler on whichever stack was registered last. Go
//! gives every `M` its own `gsignal` stack and takes `SIGURG` on many threads
//! at once; two of them in a handler in the same instant wrote their frames
//! onto one stack, and `go build` died of `SIGSEGV` about one run in two.
//!
//! Four things, and the first three fail against the shared implementation:
//!
//! 1. A thread queries its stack and gets its own -- none, until it sets one,
//!    whatever the thread that made it had; then what it set; and the main
//!    thread's is untouched by any of that.
//! 2. A handler runs on the stack of the thread it was delivered to. The
//!    handler records where its own frame is; that address is inside the
//!    stack the receiving thread registered and no other.
//! 3. Eight threads, each with its own stack, each taking two hundred signals
//!    while the others do the same. Every handler frame on its own thread's
//!    stack, and the process alive at the end -- which is the Go shape. On the
//!    shared implementation this group ended the process with the pc inside
//!    a stack.
//! 4. A fork child inherits the calling thread's.
//!
//! **The "starts with none" thread is made with `pthread_create`, not
//! `std::thread`.** Rust's `std` gives every thread it spawns an alternate
//! stack of its own for its overflow handler -- and installs one on the main
//! thread at startup -- so a `std::thread` never starts with none, on any
//! kernel, and an exec'd Rust binary always reports one. The first version of
//! this test used `std::thread` for that check and exec'd itself for an
//! "exec drops it" check; both failed against the fixed kernel *and* against
//! Linux. The exec rule is a unit test in `crates/kernel/sigqueue` instead.

use guest_tests::{Harness, check};
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::Barrier;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

/// What a thread made by `pthread_create` and nothing else sees when it asks.
extern "C" fn query_from_bare_thread(out: *mut c_void) -> *mut c_void {
    let (sp, _, flags) = query();
    unsafe { *(out as *mut (usize, i32)) = (sp, flags) };
    std::ptr::null_mut()
}

fn bare_thread_query() -> (usize, i32) {
    let mut out = (0usize, 0i32);
    let mut tid: libc::pthread_t = std::ptr::null_mut();
    let r = unsafe {
        libc::pthread_create(
            &mut tid,
            std::ptr::null(),
            query_from_bare_thread,
            &mut out as *mut (usize, i32) as *mut c_void,
        )
    };
    assert_eq!(r, 0, "pthread_create: {r}");
    assert_eq!(unsafe { libc::pthread_join(tid, std::ptr::null_mut()) }, 0);
    out
}

const STACK: usize = 64 * 1024;
const SIG: i32 = libc::SIGUSR1;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// An `mmap`ed region to register as an alternate stack. Leaked on purpose:
/// a stack a thread has registered must outlive every signal it takes.
fn stack() -> usize {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            STACK,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(p != libc::MAP_FAILED, "mmap: {}", errno());
    p as usize
}

fn set(sp: usize) -> i32 {
    let ss = libc::stack_t {
        ss_sp: sp as *mut c_void,
        ss_flags: 0,
        ss_size: STACK,
    };
    if unsafe { libc::sigaltstack(&ss, std::ptr::null_mut()) } == 0 { 0 } else { -errno() }
}

/// `(ss_sp, ss_size, ss_flags)` as the kernel reports them.
fn query() -> (usize, usize, i32) {
    let mut old: libc::stack_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::sigaltstack(std::ptr::null(), &mut old) };
    assert_eq!(r, 0, "sigaltstack(NULL, &old): {}", errno());
    (old.ss_sp as usize, old.ss_size, old.ss_flags)
}

thread_local! {
    /// Where the last handler on this thread found its own frame.
    static FRAME: Cell<usize> = const { Cell::new(0) };
}

/// How many handlers have run, process-wide.
static RAN: AtomicUsize = AtomicUsize::new(0);

extern "C" fn handler(_sig: i32, _info: *mut libc::siginfo_t, _ctx: *mut c_void) {
    // The address of a local is inside whatever stack this frame is on.
    let marker = 0u8;
    let here = &marker as *const u8 as usize;
    FRAME.with(|f| f.set(here));
    RAN.fetch_add(1, Ordering::SeqCst);
}

fn install() {
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = handler as *const () as usize;
    act.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
    unsafe { libc::sigemptyset(&mut act.sa_mask) };
    let r = unsafe { libc::sigaction(SIG, &act, std::ptr::null_mut()) };
    assert_eq!(r, 0, "sigaction: {}", errno());
}

/// Raise `SIG` at the calling thread and answer where the handler's frame was.
fn take_one() -> usize {
    FRAME.with(|f| f.set(0));
    // musl's raise is tkill on the calling thread, which is what this wants.
    let r = unsafe { libc::raise(SIG) };
    assert_eq!(r, 0, "raise: {}", errno());
    FRAME.with(|f| f.get())
}

fn within(addr: usize, stack: usize) -> bool {
    addr > stack && addr <= stack + STACK
}

fn main() {
    let mut h = Harness::new();
    install();

    // --- 1. per thread ----------------------------------------------------
    h.group("per thread");
    let main_stack = stack();
    check!(h, set(main_stack) == 0, "main thread sets its own");
    check!(h, query().0 == main_stack, "and reads it back");

    // A bare thread: std would install one of its own before this could ask.
    let (before_sp, before_flags) = bare_thread_query();
    check!(
        h,
        before_flags & libc::SS_DISABLE != 0 && before_sp == 0,
        "a new thread starts with none, not the creator's: got sp={before_sp:#x} flags={before_flags:#x}"
    );

    let (mine, set_rc, after) = thread::spawn(move || {
        let mine = stack();
        let set_rc = set(mine);
        (mine, set_rc, query())
    })
    .join()
    .unwrap();
    check!(h, set_rc == 0, "the thread sets its own");
    check!(h, after.0 == mine, "and reads back what it set");
    check!(
        h,
        query().0 == main_stack,
        "the main thread's is untouched by the thread's: got {:#x}, want {:#x}",
        query().0,
        main_stack
    );

    // --- 2. delivery ------------------------------------------------------
    h.group("delivery");
    let frame = take_one();
    check!(
        h,
        within(frame, main_stack),
        "main's handler ran on main's stack: frame {:#x}, stack {:#x}..{:#x}",
        frame,
        main_stack,
        main_stack + STACK
    );
    let (thread_stack, thread_frame) = thread::spawn(|| {
        let mine = stack();
        assert_eq!(set(mine), 0);
        (mine, take_one())
    })
    .join()
    .unwrap();
    check!(
        h,
        within(thread_frame, thread_stack),
        "the thread's handler ran on the thread's stack: frame {:#x}, stack {:#x}..{:#x}",
        thread_frame,
        thread_stack,
        thread_stack + STACK
    );
    check!(
        h,
        !within(thread_frame, main_stack),
        "and not on main's"
    );
    let frame = take_one();
    check!(
        h,
        within(frame, main_stack),
        "main's handler still runs on main's after the thread set its own"
    );

    // --- 3. concurrently --------------------------------------------------
    h.group("concurrently");
    const THREADS: usize = 8;
    const SIGNALS: usize = 200;
    RAN.store(0, Ordering::SeqCst);
    let start = std::sync::Arc::new(Barrier::new(THREADS));
    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let start = start.clone();
            thread::spawn(move || {
                let mine = stack();
                assert_eq!(set(mine), 0);
                start.wait();
                let mut wrong = 0;
                for _ in 0..SIGNALS {
                    if !within(take_one(), mine) {
                        wrong += 1;
                    }
                }
                wrong
            })
        })
        .collect();
    let wrong: usize = workers.into_iter().map(|w| w.join().unwrap()).sum();
    check!(
        h,
        wrong == 0,
        "{THREADS} threads x {SIGNALS} signals: {wrong} handler frames landed on another thread's stack"
    );
    check!(
        h,
        RAN.load(Ordering::SeqCst) == THREADS * SIGNALS,
        "every signal was handled: {} of {}",
        RAN.load(Ordering::SeqCst),
        THREADS * SIGNALS
    );

    // --- 4. fork -----------------------------------------------------------
    h.group("fork");
    let inherited = unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork: {}", errno());
        if pid == 0 {
            let (sp, _, _) = query();
            libc::_exit(if sp == main_stack { 0 } else { 1 });
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    };
    check!(h, inherited, "a fork child inherits the calling thread's");

    std::process::exit(h.finish());
}
