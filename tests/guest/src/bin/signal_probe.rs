//! What the signal calls answer at their edges, and what a handler is told.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Signals are where this tree has found the most defects, and every one was a
//! value nobody had asserted: the frame's `siginfo_` union ended at 48 so two
//! thirds of it was never written, `si_utime` and `si_stime` were four bytes
//! apart instead of eight, the ignore set had five entries where Linux's has
//! four, and `/proc/<pid>/status` reported dispositions one bit high. A probe
//! is the instrument for that class — it asks what the values *are* rather than
//! what someone thought to assert about them.
//!
//! # Every case restores what it changed
//!
//! Dispositions and the blocked mask are process-wide and sticky, so a case
//! that left one set would decide the next one's answer. Each saves and puts
//! back; the ones that cannot — a `SA_RESETHAND` that has already fired — say so
//! in their own line.

use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> &'static str {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::ESRCH => "ESRCH",
        libc::EFAULT => "EFAULT",
        libc::EAGAIN => "EAGAIN",
        libc::EINTR => "EINTR",
        0 => "ok",
        _ => "other",
    }
}

/// What the last handler saw.
static SEEN_SIG: AtomicI32 = AtomicI32::new(0);
static SEEN_CODE: AtomicI32 = AtomicI32::new(0);
static SEEN_PID: AtomicI32 = AtomicI32::new(-1);
static SEEN_UID: AtomicU32 = AtomicU32::new(0xffff_ffff);
static SEEN_VALUE: AtomicU64 = AtomicU64::new(0);
static SEEN_MASK: AtomicU64 = AtomicU64::new(0);
static RAN: AtomicI32 = AtomicI32::new(0);

/// What the last *fault* handler saw, and how it made the access succeed.
static FAULT_CODE: AtomicI32 = AtomicI32::new(0);
static FAULT_ADDR: AtomicU64 = AtomicU64::new(0);
/// The page the next fault is expected on, and the repair: 1 for `mprotect`
/// (the page is mapped and refuses), 2 for `mmap(MAP_FIXED)` (it is not).
static FAULT_PAGE: AtomicU64 = AtomicU64::new(0);
static FAULT_REPAIR: AtomicI32 = AtomicI32::new(0);
/// How many times `fault` ran: a store that "landed" with this at zero was
/// made to succeed by the kernel without a signal, which is a different
/// answer from a signal carrying a wrong si_code.
static FAULT_RAN: AtomicI32 = AtomicI32::new(0);

/// The store that faults, in a function of its own so that the instruction is
/// the first thing in its JIT block. The emulator resumes a handled fault at
/// the **start of the block** rather than at the faulting instruction, so any
/// store before it in the same block runs twice -- and the first version of
/// this probe reset its counters right before the store and read them back as
/// zero after a handler that had run. A call is a block boundary on both
/// sides, which is what keeps the resets out of the retry.
#[inline(never)]
fn poke(at: *mut u8, value: u8) {
    unsafe { std::ptr::write_volatile(std::hint::black_box(at), value) };
}

/// How many times the store *before* the faulting one in [`count_then_poke`]
/// ran. Plain loads and stores rather than an atomic add: an atomic
/// read-modify-write is a loop or an out-of-line call on aarch64, and either
/// is a block boundary, which is the thing being measured.
static BEFORE: AtomicI32 = AtomicI32::new(0);

/// A store, and a store before it with no branch between them -- one JIT block.
/// Linux resumes a handled fault at the faulting instruction, so `BEFORE` goes
/// up once; an emulator that resumes at the start of the block runs the first
/// store twice.
#[inline(never)]
fn count_then_poke(at: *mut u8, value: u8) {
    BEFORE.store(BEFORE.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
    unsafe { std::ptr::write_volatile(std::hint::black_box(at), value) };
}

/// Record the fault's `si_code` and `si_addr`, then make the page accessible
/// and return, so the instruction that faulted runs again and succeeds. That is
/// what a garbage collector's write barrier does, and it keeps the probe to one
/// process: a handler that cannot return would need a fork per case.
///
/// `mmap` and `mprotect` are async-signal-safe; nothing else here is called.
extern "C" fn fault(_sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    FAULT_RAN.fetch_add(1, Ordering::SeqCst);
    if !info.is_null() {
        // si_code at 8, and for a fault si_addr at 16 -- where si_pid is for
        // a signal that was sent. Raw offsets, as in `record`: the layout is
        // the thing under test.
        let raw = unsafe { std::slice::from_raw_parts(info.cast::<u8>(), 24) };
        FAULT_CODE.store(
            i32::from_ne_bytes(raw[8..12].try_into().unwrap()),
            Ordering::SeqCst,
        );
        FAULT_ADDR.store(
            u64::from_ne_bytes(raw[16..24].try_into().unwrap()),
            Ordering::SeqCst,
        );
    }
    let page = FAULT_PAGE.load(Ordering::SeqCst) as *mut libc::c_void;
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    unsafe {
        match FAULT_REPAIR.load(Ordering::SeqCst) {
            1 => {
                libc::mprotect(page, 4096, prot);
            }
            _ => {
                libc::mmap(
                    page,
                    4096,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                    -1,
                    0,
                );
            }
        }
    }
}

extern "C" fn record(sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    RAN.fetch_add(1, Ordering::SeqCst);
    SEEN_SIG.store(sig, Ordering::SeqCst);
    if !info.is_null() {
        // Read through the raw bytes rather than libc's accessors: the union's
        // shape is the thing under test, and an accessor would hide which
        // offset the value came from.
        let raw = unsafe { std::slice::from_raw_parts(info.cast::<u8>(), 128) };
        let word = |at: usize| i32::from_ne_bytes(raw[at..at + 4].try_into().unwrap());
        SEEN_CODE.store(word(8), Ordering::SeqCst);
        SEEN_PID.store(word(16), Ordering::SeqCst);
        SEEN_UID.store(word(20) as u32, Ordering::SeqCst);
        SEEN_VALUE.store(
            u64::from_ne_bytes(raw[24..32].try_into().unwrap()),
            Ordering::SeqCst,
        );
    }
    // The mask *during* the handler: what SA_NODEFER and sa_mask decide.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut set) };
    let mut bits = 0u64;
    for s in 1..=64 {
        if unsafe { libc::sigismember(&set, s) } == 1 {
            bits |= 1u64 << (s - 1);
        }
    }
    SEEN_MASK.store(bits, Ordering::SeqCst);
}

fn reset() {
    RAN.store(0, Ordering::SeqCst);
    SEEN_SIG.store(0, Ordering::SeqCst);
    SEEN_CODE.store(0, Ordering::SeqCst);
    SEEN_PID.store(-1, Ordering::SeqCst);
    SEEN_UID.store(0xffff_ffff, Ordering::SeqCst);
    SEEN_VALUE.store(0, Ordering::SeqCst);
    SEEN_MASK.store(0, Ordering::SeqCst);
}

/// Install `record` for `sig` with `flags` and `mask`, answering the old action.
fn install(sig: i32, flags: i32, mask: &[i32]) -> (i32, libc::sigaction) {
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = record as *const () as usize;
    act.sa_flags = flags | libc::SA_SIGINFO;
    unsafe { libc::sigemptyset(&mut act.sa_mask) };
    for m in mask {
        unsafe { libc::sigaddset(&mut act.sa_mask, *m) };
    }
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::sigaction(sig, &act, &mut old) };
    (r, old)
}

fn restore(sig: i32, old: &libc::sigaction) {
    unsafe { libc::sigaction(sig, old, std::ptr::null_mut()) };
}

fn main() {
    println!("## which signals take a handler");
    for (name, sig) in [
        ("SIGUSR1", libc::SIGUSR1),
        ("SIGKILL", libc::SIGKILL),
        ("SIGSTOP", libc::SIGSTOP),
        ("32 (the first real-time-ish)", 32),
        ("33", 33),
        ("34", 34),
        ("64", 64),
        ("65", 65),
        ("0", 0),
        ("-1", -1),
    ] {
        let (r, old) = install(sig, 0, &[]);
        line(
            &format!("sigaction({name})"),
            if r == 0 { "ok".to_string() } else { named(errno()).to_string() },
        );
        if r == 0 {
            restore(sig, &old);
        }
    }

    println!("## what sa_flags and sa_mask read back");
    {
        let (_, old) = install(
            libc::SIGUSR1,
            libc::SA_RESTART | libc::SA_NODEFER | libc::SA_RESETHAND,
            &[libc::SIGUSR2],
        );
        let mut back: libc::sigaction = unsafe { std::mem::zeroed() };
        unsafe { libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut back) };
        // Printed as the four bits asked for, not as the whole word: libc adds
        // its own (SA_RESTORER on some ports) and that is not the question.
        let asked = libc::SA_RESTART | libc::SA_NODEFER | libc::SA_RESETHAND | libc::SA_SIGINFO;
        line("the four flags set come back", back.sa_flags & asked == asked);
        line(
            "SA_ONSTACK, which was not set",
            back.sa_flags & libc::SA_ONSTACK != 0,
        );
        line("sa_mask has SIGUSR2", unsafe {
            libc::sigismember(&back.sa_mask, libc::SIGUSR2)
        });
        line("sa_mask has SIGUSR1", unsafe {
            libc::sigismember(&back.sa_mask, libc::SIGUSR1)
        });
        restore(libc::SIGUSR1, &old);
    }

    println!("## what a handler is told about who sent it");
    {
        let (_, old) = install(libc::SIGUSR1, 0, &[]);
        reset();
        unsafe { libc::kill(libc::getpid(), libc::SIGUSR1) };
        line("kill: si_code", SEEN_CODE.load(Ordering::SeqCst));
        line(
            "kill: si_pid is ours",
            SEEN_PID.load(Ordering::SeqCst) == unsafe { libc::getpid() },
        );
        line(
            "kill: si_uid is ours",
            SEEN_UID.load(Ordering::SeqCst) == unsafe { libc::getuid() },
        );

        reset();
        unsafe { libc::raise(libc::SIGUSR1) };
        line("raise: si_code", SEEN_CODE.load(Ordering::SeqCst));

        reset();
        let value = libc::sigval {
            sival_ptr: 0xdead_beef_usize as *mut libc::c_void,
        };
        let r = unsafe { libc::sigqueue(libc::getpid(), libc::SIGUSR1, value) };
        line("sigqueue", if r == 0 { "ok" } else { named(errno()) });
        line("sigqueue: si_code", SEEN_CODE.load(Ordering::SeqCst));
        line(
            "sigqueue: si_value",
            format!("{:#x}", SEEN_VALUE.load(Ordering::SeqCst)),
        );
        restore(libc::SIGUSR1, &old);
    }

    println!("## what is blocked while a handler runs");
    {
        let (_, old) = install(libc::SIGUSR1, 0, &[libc::SIGUSR2]);
        reset();
        unsafe { libc::raise(libc::SIGUSR1) };
        let mask = SEEN_MASK.load(Ordering::SeqCst);
        line(
            "the signal itself is blocked",
            mask & (1 << (libc::SIGUSR1 - 1)) != 0,
        );
        line(
            "and so is sa_mask's SIGUSR2",
            mask & (1 << (libc::SIGUSR2 - 1)) != 0,
        );
        line(
            "SIGTERM, which is in neither",
            mask & (1 << (libc::SIGTERM - 1)) != 0,
        );
        restore(libc::SIGUSR1, &old);

        let (_, old) = install(libc::SIGUSR1, libc::SA_NODEFER, &[]);
        reset();
        unsafe { libc::raise(libc::SIGUSR1) };
        line(
            "SA_NODEFER: the signal itself",
            SEEN_MASK.load(Ordering::SeqCst) & (1 << (libc::SIGUSR1 - 1)) != 0,
        );
        restore(libc::SIGUSR1, &old);
    }

    println!("## SA_RESETHAND");
    {
        let (_, old) = install(libc::SIGUSR2, libc::SA_RESETHAND, &[]);
        reset();
        // Blocked first, so the reset-to-default cannot kill this process when
        // the second raise arrives.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR2);
            libc::raise(libc::SIGUSR2);
        }
        line("the handler ran", RAN.load(Ordering::SeqCst));
        let mut back: libc::sigaction = unsafe { std::mem::zeroed() };
        unsafe { libc::sigaction(libc::SIGUSR2, std::ptr::null(), &mut back) };
        line("and the disposition is now", if back.sa_sigaction == libc::SIG_DFL {
            "SIG_DFL"
        } else if back.sa_sigaction == libc::SIG_IGN {
            "SIG_IGN"
        } else {
            "still a handler"
        });
        restore(libc::SIGUSR2, &old);
    }

    println!("## the mask");
    {
        let mut saved: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut saved) };

        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGKILL);
            libc::sigaddset(&mut set, libc::SIGSTOP);
            libc::sigaddset(&mut set, libc::SIGUSR1);
        }
        let r = unsafe { libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
        line("blocking SIGKILL and SIGSTOP", if r == 0 { "ok" } else { named(errno()) });
        let mut now: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut now) };
        line("SIGKILL reads back as blocked", unsafe {
            libc::sigismember(&now, libc::SIGKILL)
        });
        line("SIGSTOP reads back as blocked", unsafe {
            libc::sigismember(&now, libc::SIGSTOP)
        });
        line("SIGUSR1 reads back as blocked", unsafe {
            libc::sigismember(&now, libc::SIGUSR1)
        });

        // A pending blocked signal, and what sigpending says about it.
        unsafe { libc::raise(libc::SIGUSR1) };
        let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigpending(&mut pending) };
        line("after raising it, sigpending", unsafe {
            libc::sigismember(&pending, libc::SIGUSR1)
        });
        line("and something else is not", unsafe {
            libc::sigismember(&pending, libc::SIGTERM)
        });

        // Taken back out, so the rest of the run starts clean.
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let mut only: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut only);
            libc::sigaddset(&mut only, libc::SIGUSR1);
        }
        let got = unsafe { libc::sigtimedwait(&only, std::ptr::null_mut(), &ts) };
        line("sigtimedwait takes it", got);
        let got = unsafe { libc::sigtimedwait(&only, std::ptr::null_mut(), &ts) };
        line("and a second one finds nothing", named(if got < 0 { errno() } else { 0 }));

        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &saved, std::ptr::null_mut()) };
    }

    println!("## sigaltstack");
    {
        let mut before: libc::stack_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigaltstack(std::ptr::null(), &mut before) };
        line("ss_flags before anything sets one", before.ss_flags);

        let mut mem = vec![0u8; 64 * 1024];
        let want = libc::stack_t {
            ss_sp: mem.as_mut_ptr().cast(),
            ss_flags: 0,
            ss_size: mem.len(),
        };
        let mut old: libc::stack_t = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::sigaltstack(&want, &mut old) };
        line("setting one", if r == 0 { "ok" } else { named(errno()) });

        let mut back: libc::stack_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigaltstack(std::ptr::null(), &mut back) };
        line("ss_size comes back", back.ss_size == mem.len());
        line("ss_flags after setting", back.ss_flags);

        // A stack smaller than the minimum: the one argument rule this call has.
        let tiny = libc::stack_t {
            ss_sp: mem.as_mut_ptr().cast(),
            ss_flags: 0,
            ss_size: 1,
        };
        let r = unsafe { libc::sigaltstack(&tiny, std::ptr::null_mut()) };
        line("a one-byte stack", if r == 0 { "ok" } else { named(errno()) });

        // SS_DISABLE, and what the size reads as afterwards.
        let off = libc::stack_t {
            ss_sp: std::ptr::null_mut(),
            ss_flags: libc::SS_DISABLE,
            ss_size: 0,
        };
        let r = unsafe { libc::sigaltstack(&off, std::ptr::null_mut()) };
        line("SS_DISABLE", if r == 0 { "ok" } else { named(errno()) });
        unsafe { libc::sigaltstack(std::ptr::null(), &mut back) };
        line("ss_flags after disabling", back.ss_flags);

        unsafe { libc::sigaltstack(&old, std::ptr::null_mut()) };
    }

    println!("## what a handler is told about a fault");
    {
        // Two faults, two reasons. Linux tells them apart in si_code --
        // SEGV_MAPERR for an address nothing is mapped at, SEGV_ACCERR for a
        // mapping whose protection refused the access -- and a runtime that
        // installs a handler reads it: a GC's write barrier repairs an ACCERR
        // and dies on a MAPERR. Nothing in this tree observed either value
        // until 2026-09-02, when a rewrite of the page table returned 0 and 1
        // for them -- SI_USER and SEGV_MAPERR.
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = fault as *const () as usize;
        act.sa_flags = libc::SA_SIGINFO;
        unsafe { libc::sigemptyset(&mut act.sa_mask) };
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        unsafe { libc::sigaction(libc::SIGSEGV, &act, &mut old) };

        // A page that is mapped and refuses: PROT_NONE.
        let none = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        let target = unsafe { none.cast::<u8>().add(0x123) };
        FAULT_PAGE.store(none as u64, Ordering::SeqCst);
        FAULT_REPAIR.store(1, Ordering::SeqCst);
        FAULT_CODE.store(0, Ordering::SeqCst);
        FAULT_ADDR.store(0, Ordering::SeqCst);
        FAULT_RAN.store(0, Ordering::SeqCst);
        poke(target, 1);
        line("store to PROT_NONE: handler ran", FAULT_RAN.load(Ordering::SeqCst));
        line("store to PROT_NONE: si_code", FAULT_CODE.load(Ordering::SeqCst));
        line(
            "store to PROT_NONE: si_addr is the address",
            FAULT_ADDR.load(Ordering::SeqCst) == target as u64,
        );
        line("store to PROT_NONE: the store landed after repair", unsafe {
            std::ptr::read_volatile(target)
        });
        unsafe { libc::munmap(none, 4096) };

        // A page nothing is mapped at: one that was, and was unmapped. Nothing
        // else in this process maps between the munmap and the store.
        let gone = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        unsafe { libc::munmap(gone, 4096) };
        let target = unsafe { gone.cast::<u8>().add(0x456) };
        FAULT_PAGE.store(gone as u64, Ordering::SeqCst);
        FAULT_REPAIR.store(2, Ordering::SeqCst);
        FAULT_CODE.store(0, Ordering::SeqCst);
        FAULT_ADDR.store(0, Ordering::SeqCst);
        FAULT_RAN.store(0, Ordering::SeqCst);
        poke(target, 2);
        line("store to an unmapped page: handler ran", FAULT_RAN.load(Ordering::SeqCst));
        line("store to an unmapped page: si_code", FAULT_CODE.load(Ordering::SeqCst));
        line(
            "store to an unmapped page: si_addr is the address",
            FAULT_ADDR.load(Ordering::SeqCst) == target as u64,
        );
        line("store to an unmapped page: the store landed after repair", unsafe {
            std::ptr::read_volatile(target)
        });
        unsafe { libc::munmap(gone, 4096) };

        // Where execution resumes after the handler. A store before the
        // faulting one, in the same block, runs once on Linux.
        let none = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        FAULT_PAGE.store(none as u64, Ordering::SeqCst);
        FAULT_REPAIR.store(1, Ordering::SeqCst);
        FAULT_RAN.store(0, Ordering::SeqCst);
        BEFORE.store(0, Ordering::SeqCst);
        count_then_poke(none.cast(), 3);
        line("a handled fault: handler ran", FAULT_RAN.load(Ordering::SeqCst));
        line(
            "a handled fault: the store before it in its block ran",
            BEFORE.load(Ordering::SeqCst),
        );
        unsafe { libc::munmap(none, 4096) };

        restore(libc::SIGSEGV, &old);
    }

    println!("## what the calls refuse");
    {
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut act) };
        line("sigaction with only an old", if r == 0 { "ok" } else { named(errno()) });

        let r = unsafe { libc::sigprocmask(99, std::ptr::null(), std::ptr::null_mut()) };
        line("sigprocmask with a bad how", if r == 0 { "ok" } else { named(errno()) });

        let r = unsafe { libc::kill(libc::getpid(), 0) };
        line("kill(self, 0)", if r == 0 { "ok" } else { named(errno()) });

        let r = unsafe { libc::kill(libc::getpid(), 65) };
        line("kill(self, 65)", if r == 0 { "ok" } else { named(errno()) });

        let r = unsafe { libc::kill(0x7fff_ffff, 0) };
        line("kill(a pid nothing has, 0)", if r == 0 { "ok" } else { named(errno()) });

        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: -1,
        };
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut set) };
        let r = unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &ts) };
        line(
            "sigtimedwait with a negative tv_nsec",
            if r < 0 { named(errno()) } else { "ok" },
        );
    }
}
