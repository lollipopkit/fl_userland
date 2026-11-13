//! `struct iul_env` — Rust's, since 2026-09-08.
//!
//! # Why it moved
//!
//! `util/ish_env.h` was the definition and **two crates generated it**:
//! this one and `crates/asbestos/diag`, which is the two-renderings-of-one-type
//! shape `crates/kernel/taskview` exists to stop. No C reads a field of it —
//! `misc.h` includes the header because every header does, and the only other
//! mention is the `extern` declaration of the global itself. A definition
//! nothing in C reads is not a C definition; it is a Rust one written in C,
//! and every crate that touched it paid a bindgen run for the privilege.
//!
//! # What the generation was buying, and what replaces it
//!
//! The `build.rs` that is gone said it: "a field added to the header without
//! being added here would be silently left at whatever the C global started
//! as. bindgen makes a new field a compile error in the filler below instead,
//! because the struct literal has to name all of them."
//!
//! The struct literal still has to name all of them. What changes is that the
//! field is added *here*, so there is nowhere for the two to disagree.
//!
//! # Not `#[repr(C)]` since 2026-10-17
//!
//! The global was `#[no_mangle]` for `util/ish_env.h`, which had no reader
//! left, and the layout was kept for that published symbol. Neither is: the
//! three paths are `Option<&'static str>` where they were `getenv` pointers
//! every reader turned back into a string under `unsafe`.

#![allow(non_camel_case_types)]

use std::ffi::c_int;

/// The runtime diagnostics, read once before any thread exists.
///
/// They used to be read where they were used, in two shapes and both wrong: a
/// `getenv()` on every call — ``IUL_PROT_TRACE`` scanned the environment on every
/// `munmap` — and a function-local `static int` filled in on first use, which
/// is a data race between whichever threads get there together.
/// ThreadSanitizer found it in `futex_wait`, and there were ten more of the
/// same shape, five in the interpreter's dispatch loop.
///
/// A constructor runs before `main` and before any guest thread, so this is
/// written once and only ever read. Nothing here is a knob a running program
/// turns: they are all "how was this process started".
///
/// It also puts the set in one place. `grep getenv("IUL_` was the documented
/// way to find out what exists, which only worked while every one of them was
/// spelled out at its use site.
///
/// The per-field notes were `util/ish_env.h`'s until 2026-09-09, when that
/// header lost its last reader. Each says which `IUL_*` variable fills it and,
/// for the ones that are off by default, which changelog entry turned them
/// off — several of them record a diagnostic that *shipped* and what it cost.
#[derive(Copy, Clone, Default)]
pub struct iul_env {
    /// Tracing.
    ///
    /// `IUL_EXEC_TRACE`. Read on every `sys_write` and every `INT_GPF`
    /// diagnostic, which is why a `getenv` here was worth removing: it walks
    /// the whole environment table. `misc.h` had a cached `static inline` over
    /// it for that reason, with no caller in C, in the gadgets or in any crate.
    pub exec_trace: bool,
    /// `IUL_SYSTRACE`
    pub systrace: bool,
    /// `IUL_PROT_TRACE`
    pub prot_trace: bool,
    /// `IUL_VMA_TRACE`
    pub vma_trace: bool,
    /// `IUL_READ_FAULT_RECOVERY`=1 restores a workaround that answered every
    /// guest read fault with zero instead of SIGSEGV. Off by default: it made a
    /// null-pointer dereference return 0 and continue.
    /// Since 2026-09-02 also the demand-map that answered a *read* fault on an
    /// unmapped page with a mapped neighbour by mapping a fresh zero page.
    pub read_fault_recovery: bool,
    /// `IUL_V8_FAULT_RECOVERY`=1 restores the V8 zone-corruption recovery: a
    /// ~300-line block that unwinds the guest's frame-pointer chain, zeroes
    /// registers and forces returns, gated on hardcoded PC ranges taken from one
    /// node build. Off by default — those ranges are addresses, not identities,
    /// and any binary mapped there gets the same treatment.
    /// Since 2026-09-02 also the demand-map that answered a *write* fault in
    /// 0xb0000000..0xf0000000 — the mmap region -- or above 4 GB with a fresh
    /// zero page, so a store through a dangling pointer succeeded.
    pub v8_fault_recovery: bool,
    /// `IUL_IDLE_EXIT`=<seconds> restores a safety valve that *killed* a process
    /// which had been waiting in poll()/select() for that long. Off by default,
    /// and 0 is off.
    ///
    /// It was on, at 60 seconds, and it exits the group with status **0** — so
    /// a daemon waiting for a connection, a worker waiting on a socket, or any
    /// program in a long select() was killed and reported success. The exempt
    /// cases were pid 1, a controlling terminal, and having a live child, none
    /// of which a background process has.
    ///
    /// What it was for is narrower than what it did: "V8/libuv exit cleanup
    /// hangs where the event loop spins idle forever". Waiting is not a hang,
    /// and there is no reproducer here to narrow it with.
    pub idle_exit_secs: c_int,
    /// `IUL_WAIT_POLL`=<milliseconds> is how long do_wait sleeps before rescanning
    /// its children anyway. Default 1000; 0 means "do not rescan, wait to be
    /// told".
    ///
    /// The rescan is a backstop, not the mechanism: every event a wait can
    /// report — an exit, a stop, a continue, a ptrace stop -- notifies the
    /// parent's `child_exit`, and the wait wakes on that. What the timeout buys
    /// is that a *missing* notify costs latency rather than a hang.
    ///
    /// Which is exactly why it is worth being able to turn off. A continue was
    /// not reported to the parent at all, in any revision, and the only symptom
    /// was that waitpid(WCONTINUED) took a poll tick — 704 ms against a real
    /// kernel's microseconds, and nothing tests latency. With this at 0 that
    /// same defect is a hang, which a test suite does notice.
    ///
    /// The default stays 1000 because the comment it inherited claims
    /// pthread_cond_wait can block for ever on Darwin under contention, and
    /// that claim has not been tested either way. A backstop whose cost is one
    /// wakeup per second per waiting process is worth keeping until it has.
    pub wait_poll_ms: c_int,
    /// `IUL_BRK_FORCE_DEFAULT`=1 restores a workaround that forced SIGTRAP's
    /// disposition back to the default before delivering it, so no handler ran.
    /// It was on, and it was for V8: its crash reporter returns normally, which
    /// re-executes the BRK for ever because the exception is taken with the pc
    /// still on it. But `brk` is what every Rust panic in a panic=abort build
    /// reaches, what __builtin_trap() compiles to, and what every sanitizer
    /// check and debugger breakpoint is — so silencing every handler to stop
    /// one program looping is the same trade the V8 zone unwind was turned off
    /// for. Off by default since 2026-09-02.
    pub brk_force_default: bool,
    /// `IUL_MEMBARRIER_TRACE`
    pub membarrier_trace: bool,
    /// `IUL_PIDFD_TRACE`
    pub pidfd_trace: bool,
    /// `IUL_GPF_BT`
    pub gpf_bt: bool,
    /// `IUL_NULLPC_DBG`
    pub nullpc_dbg: bool,
    /// The processor count sched_getaffinity and _SC_NPROCESSORS_ONLN report,
    /// when the host's is not what a test wants. 0 means use the host's. Read
    /// once at startup, like everything else here — it used to be a getenv on
    /// every sched_getaffinity.
    ///
    /// `IUL_FAKE_NCPU`
    pub fake_ncpu: c_int,
    /// `IUL_V8_NO_MUTE`
    pub v8_no_mute: bool,
    /// The three profiling gates asbestos/asbestos.c's dispatch loop reads.
    ///
    /// They were `static _Atomic int` set to -1 and filled in lazily by the
    /// first thread to reach them, which put **three sequentially-consistent
    /// loads in the hottest loop in the emulator** — an `ldar` each, per block
    /// dispatched, in a build with none of them set. The lazy fill was also a
    /// race: two threads could both see -1, both call getenv, and both write
    /// the range globals a third was reading.
    ///
    /// Here they are read once at startup, before any guest thread, and the
    /// gate is a plain load the compiler can hoist out of the loop.
    ///
    /// `IUL_PC_HIST`
    pub pc_hist: bool,
    /// `IUL_PC_HIST_FINE`
    pub pc_hist_fine: bool,
    /// `IUL_PC_TRACE_FILE`
    pub pc_trace_file: Option<&'static str>,
    /// `IUL_PC_HIST_DIR`
    pub pc_hist_dir: Option<&'static str>,
    /// `IUL_BLOCK_PROF_FILE`
    pub block_prof_file: Option<&'static str>,
    /// `IUL_PC_TRACE_RANGE`=&lt;lo&gt;-&lt;hi&gt;, the guest pc window the trace
    /// records. Zero means the default, which is a range from one node build
    /// and is written where it is used.
    pub pc_trace_lo: u64,
    /// The other end of [`iul_env::pc_trace_lo`]'s range.
    pub pc_trace_hi: u64,
    /// Counters and statistics.
    ///
    /// `IUL_OFFLOAD_STATS`
    pub offload_stats: bool,
    /// `IUL_WX_STATS`
    pub wx_stats: bool,
    /// `IUL_DISPATCH_COUNT`
    pub dispatch_count: bool,
    /// Behaviour switches, for bisecting a fault to a mechanism.
    ///
    /// `IUL_NO_DONTNEED`
    pub no_dontneed: bool,
    /// `IUL_NO_CHAIN`
    pub no_chain: bool,
    /// `IUL_NO_RETCACHE`
    pub no_retcache: bool,
    /// `IUL_NO_JIT_REUSE`
    pub no_jit_reuse: bool,
    /// `IUL_NO_BLOCK_CACHE`, a level rather than a flag
    pub no_block_cache: c_int,
    /// Watchpoints, as guest addresses. Zero means unset.
    ///
    /// `IUL_FUTEX_WATCH`
    pub futex_watch: u64,
    /// `IUL_EPOLL_WATCH_MUTEX`
    pub epoll_watch_mutex: u64,
    /// The gadget store watchpoint. These were seven getenv+strtoull calls in
    /// main() until 2026-09-03 — the only IUL_* variables read anywhere but
    /// here, which meant they followed none of the rules this file's readers
    /// apply and nothing could test the page mask.
    ///
    /// The two pages are what the assembly compares against; the sub-page
    /// windows narrow which hits get *recorded*, and watch_field is a guest u32
    /// to snapshot at every one. See crates/asbestos/diag.
    ///
    /// `IUL_WATCH_PAGE`, masked to a page
    pub watch_page: u64,
    /// `IUL_WATCH_PAGE2`, likewise
    pub watch_page2: u64,
    pub watch_lo: u64,
    pub watch_hi: u64,
    pub watch_lo2: u64,
    pub watch_hi2: u64,
    /// `IUL_WATCH_FIELD`
    pub watch_field: u64,
    /// The host-side poller: a guest u32 sampled every millisecond and logged
    /// when it changes, which perturbs nothing because it makes no guest store
    /// slower. Zero is off.
    ///
    /// `IUL_POLL_ADDR`
    pub poll_addr: u64,
    /// Dump the pc histogram and trace on SIGTERM/SIGINT and _exit, for a
    /// microbenchmark killed from outside rather than left to halt_system.
    ///
    /// `IUL_DUMP_ON_SIGTERM`
    pub dump_on_sigterm: bool,
    /// `IUL_FUTEX_DBG`: seconds a futex may stall before the thread states are
    /// dumped. Zero is off.
    pub futex_dbg_secs: c_int,
}
