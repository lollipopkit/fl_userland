//! Reading the `IUL_*` environment variables, once, before any guest thread.
//!
//! The struct they fill is `struct iul_env`, generated from `util/ish_env.h`,
//! and **the global and its constructor are this crate's** as of 2026-09-06.
//!
//! # The constructor, and why the link argument stopped applying
//!
//! `util/ish_env.c` kept ten lines of C, and the reason had already been
//! narrowed once: stable Rust *can* write the constructor —
//! `#[link_section = "__DATA,__mod_init_func"]` on Apple, `.init_array`
//! elsewhere, both stable, measured end to end. What kept it was the **link**:
//! an `.init_array` entry only runs if the linker pulls its object out of the
//! archive, the object was pulled in because it defined `iul_env`, and moving
//! the constructor without the global would be silent — every diagnostic off
//! and `wait_poll_ms` 0, which means "never rescan" and turns a missing wakeup
//! into a hang.
//!
//! That argument is about moving *one of the two*. Both are here now, in one
//! module, and the global is what every reader references — so the object that
//! defines it is the object that carries the constructor, which is exactly the
//! property the C relied on. What is new is that it is checked:
//! [`assert_initialised`] is called from `crates/kernel/boot`, and a build
//! where the constructor did not run fails loudly at startup instead of
//! hanging later.
//!
//! # Why it is read once
//!
//! Everything that reads this struct does so without synchronising, which is
//! only sound because nothing writes it after the constructor returns. The two
//! shapes it replaced were both wrong:
//!
//! - `getenv()` at the use site, on every call. `IUL_PROT_TRACE` and
//!   `IUL_VMA_TRACE` ran a linear scan of the environment on every `munmap`,
//!   `mprotect` and `madvise`.
//! - a function-local `static int` filled on first use, which is a data race
//!   between whichever threads reach it together. ThreadSanitizer found one in
//!   `futex_wait` and there were ten more, five of them in the dispatch loop.
//!
//! # The rules, which is why this is worth testing
//!
//! Three of them, and each was a decision:
//!
//! - A flag is **on unless the value is exactly `0`**. Most of these were
//!   tested with `getenv(...) != NULL` and a few with `e[0] == '1'`; taking
//!   the looser rule everywhere means `IUL_NO_CHAIN=0` no longer reads as
//!   "on", which is what anyone typing it meant. Present-and-empty is still
//!   on, which is what `IUL_NO_CHAIN=` has always done.
//! - A number whose default is not zero needs "unset" and "`0`" to differ,
//!   because zero is a value a caller may ask for — `IUL_WAIT_POLL=0` means
//!   "do not rescan" and its default is 1000.
//! - `IUL_PC_TRACE_RANGE` is two hex numbers with a dash. A malformed one
//!   leaves both bounds zero rather than half-filling them, because the reader
//!   supplies the default and a half-parsed range is a window nothing falls in.


use std::ffi::c_int;

mod env_struct;

/// The struct, which is this crate's own Rust since 2026-09-08. `ffi` is the
/// name every use site already had.
mod ffi {
    pub use crate::env_struct::iul_env;
}

/// What the environment says, as a `String`: `None` for unset and for a value
/// that is not UTF-8, as the `getenv` and `to_str` this was answered.
///
/// `std::env::var` since 2026-09-30. `libc::getenv` read the environment
/// without the lock `std::env` takes around every read and write of it.
fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The same, kept for the life of the process: read once, before `main`.
fn var_static(name: &str) -> Option<&'static str> {
    var(name).map(|v| &*Box::leak(v.into_boxed_str()))
}

/// Set unless the value is exactly `0`. See the module comment.
pub fn flag(value: Option<&str>) -> bool {
    match value {
        None => false,
        Some(v) => v != "0",
    }
}

/// A number, or zero when unset. `atoi`'s rule: leading digits, no error.
pub fn number(value: Option<&str>) -> c_int {
    number_or(value, 0)
}

/// A number whose default is not zero, so "unset" and "`0`" differ.
pub(crate) fn number_or(value: Option<&str>, fallback: c_int) -> c_int {
    match value {
        None => fallback,
        Some(v) => atoi(v),
    }
}

/// `atoi`: optional sign, then digits, stopping at the first thing that is not
/// one. Anything else is zero. Written out rather than `parse()` because
/// `parse()` refuses a trailing character and `atoi` does not, and the
/// difference is what `IUL_WAIT_POLL=1000ms` does.
fn atoi(s: &str) -> c_int {
    let s = s.trim_start();
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let n: i64 = digits.parse().unwrap_or(0);
    let n = if neg { -n } else { n };
    n.clamp(c_int::MIN as i64, c_int::MAX as i64) as c_int
}

/// A guest address, in hex. Zero when unset or unparseable.
pub fn address(value: Option<&str>) -> u64 {
    match value {
        None => 0,
        Some(v) => {
            let v = v
                .trim_start()
                .trim_start_matches("0x")
                .trim_start_matches("0X");
            let digits: String = v.chars().take_while(char::is_ascii_hexdigit).collect();
            u64::from_str_radix(&digits, 16).unwrap_or(0)
        }
    }
}

/// `<lo>-<hi>`, both hex. `None` unless *both* parse, because a half-filled
/// range is a window nothing falls in and the reader has a default for the
/// whole thing.
pub fn range(value: Option<&str>) -> Option<(u64, u64)> {
    let v = value?;
    let (lo, hi) = v.split_once('-')?;
    let lo = u64::from_str_radix(lo.trim(), 16).ok()?;
    let hi = u64::from_str_radix(hi.trim(), 16).ok()?;
    Some((lo, hi))
}

/// The settings, filled before `main` by `settings::IUL_ENV_CTOR`.
///
/// `static mut` rather than a `OnceLock`: every reader is on a hot path — the
/// dispatch loop tests `pc_hist` once per block — and a `OnceLock` read is an
/// acquire load and a branch where this is a plain load. What makes that sound
/// is the constructor, which runs before any thread exists; see the module
/// comment.
pub static mut IUL_ENV: ffi::iul_env = ZEROED;

/// Every field false or zero, which is what the C global started as before its
/// constructor ran.
const ZEROED: ffi::iul_env = ffi::iul_env {
    exec_trace: false,
    systrace: false,
    prot_trace: false,
    vma_trace: false,
    read_fault_recovery: false,
    v8_fault_recovery: false,
    idle_exit_secs: 0,
    wait_poll_ms: 0,
    brk_force_default: false,
    membarrier_trace: false,
    pidfd_trace: false,
    gpf_bt: false,
    nullpc_dbg: false,
    fake_ncpu: 0,
    v8_no_mute: false,
    pc_hist: false,
    pc_hist_fine: false,
    pc_trace_file: None,
    pc_hist_dir: None,
    block_prof_file: None,
    pc_trace_lo: 0,
    pc_trace_hi: 0,
    offload_stats: false,
    wx_stats: false,
    dispatch_count: false,
    no_dontneed: false,
    no_chain: false,
    no_retcache: false,
    no_jit_reuse: false,
    no_block_cache: 0,
    futex_watch: 0,
    epoll_watch_mutex: 0,
    watch_page: 0,
    watch_page2: 0,
    watch_lo: 0,
    watch_hi: 0,
    watch_lo2: 0,
    watch_hi2: 0,
    watch_field: 0,
    poll_addr: 0,
    dump_on_sigterm: false,
    futex_dbg_secs: 0,
};

/// Fill the global. Called from the constructor, before `main` and so before
/// any guest thread.
///
/// Plain Rust since 2026-09-06: `util/ish_env.c`'s constructor called it
/// through the C ABI, and with the constructor here too there is nothing on
/// the other side of that boundary.
///
/// # Safety
/// `out` is the `iul_env` global and nothing else is running.
unsafe fn iul_env_fill(out: *mut ffi::iul_env) {
    let f = |n: &str| flag(var(n).as_deref());
    let i = |n: &str| number(var(n).as_deref());

    let (lo, hi) = range(var("IUL_PC_TRACE_RANGE").as_deref()).unwrap_or((0, 0));

    // A struct literal rather than field assignments: a field added to the
    // header and not to this list is a compile error, where an assignment list
    // would silently leave it at whatever the global started as.
    let env = ffi::iul_env {
        exec_trace: f("IUL_EXEC_TRACE"),
        systrace: f("IUL_SYSTRACE"),
        prot_trace: f("IUL_PROT_TRACE"),
        vma_trace: f("IUL_VMA_TRACE"),
        read_fault_recovery: f("IUL_READ_FAULT_RECOVERY"),
        v8_fault_recovery: f("IUL_V8_FAULT_RECOVERY"),
        brk_force_default: f("IUL_BRK_FORCE_DEFAULT"),
        idle_exit_secs: i("IUL_IDLE_EXIT"),
        // 1000 by default, and 0 is a value a caller may ask for.
        wait_poll_ms: number_or(var("IUL_WAIT_POLL").as_deref(), 1000),
        membarrier_trace: f("IUL_MEMBARRIER_TRACE"),
        pidfd_trace: f("IUL_PIDFD_TRACE"),
        gpf_bt: f("IUL_GPF_BT"),
        nullpc_dbg: f("IUL_NULLPC_DBG"),
        fake_ncpu: i("IUL_FAKE_NCPU"),
        v8_no_mute: f("IUL_V8_NO_MUTE"),
        pc_hist: f("IUL_PC_HIST"),
        pc_hist_fine: f("IUL_PC_HIST_FINE"),
        pc_trace_file: var_static("IUL_PC_TRACE_FILE"),
        pc_hist_dir: var_static("IUL_PC_HIST_DIR"),
        block_prof_file: var_static("IUL_BLOCK_PROF_FILE"),
        pc_trace_lo: lo,
        pc_trace_hi: hi,
        offload_stats: f("IUL_OFFLOAD_STATS"),
        wx_stats: f("IUL_WX_STATS"),
        dispatch_count: f("IUL_DISPATCH_COUNT"),
        no_dontneed: f("IUL_NO_DONTNEED"),
        no_chain: f("IUL_NO_CHAIN"),
        no_retcache: f("IUL_NO_RETCACHE"),
        no_jit_reuse: f("IUL_NO_JIT_REUSE"),
        no_block_cache: i("IUL_NO_BLOCK_CACHE"),
        futex_watch: address(var("IUL_FUTEX_WATCH").as_deref()),
        // Masked to a page here rather than at the reader: the assembly
        // compares a store's page against this value, so a low bit left in it
        // would make every comparison fail and the watchpoint record nothing,
        // silently. The C did the mask in `main()` and nothing could test it.
        watch_page: address(var("IUL_WATCH_PAGE").as_deref()) & !0xfff,
        watch_page2: address(var("IUL_WATCH_PAGE2").as_deref()) & !0xfff,
        watch_lo: address(var("IUL_WATCH_LO").as_deref()),
        watch_hi: address(var("IUL_WATCH_HI").as_deref()),
        watch_lo2: address(var("IUL_WATCH_LO2").as_deref()),
        watch_hi2: address(var("IUL_WATCH_HI2").as_deref()),
        watch_field: address(var("IUL_WATCH_FIELD").as_deref()),
        poll_addr: address(var("IUL_POLL_ADDR").as_deref()),
        dump_on_sigterm: f("IUL_DUMP_ON_SIGTERM"),
        epoll_watch_mutex: address(var("IUL_EPOLL_WATCH_MUTEX").as_deref()),
        futex_dbg_secs: i("IUL_FUTEX_DBG"),
    };
    unsafe { *out = env };
}

/// The settings, for a **Rust** reader.
///
/// A crate that wants one flag has three ways to get it and two of them are
/// worse: bindgen over `util/ish_env.h`, which makes it recompile on any change
/// to a 40-field struct it uses one field of, and a C accessor per field, which
/// is the shape `crates/kernel/taskview` exists to stop. This is the third —
/// one narrow question per flag, answered from the same global the C reads.
///
/// The global is written once, by the constructor in `util/ish_env.c`, before
/// `main` and so before any guest thread; every read after that is a read of a
/// value nothing changes.
mod settings {
    use super::ffi;

    use super::IUL_ENV;

    /// The constructor, which runs before `main`.
    ///
    /// `#[used]` so the optimiser keeps a `static` nothing references, and the
    /// section is the platform's: Mach-O calls it `__mod_init_func`, ELF calls
    /// it `.init_array`. Both are stable Rust.
    ///
    /// **It is in the same module as the global on purpose.** An entry here
    /// only runs if the linker pulls this object out of the archive, and what
    /// pulls it in is `iul_env` — which every reader references. That is
    /// exactly the property `util/ish_env.c` relied on, and it is why the two
    /// had to move together rather than one at a time.
    #[used]
    #[unsafe(link_section = "__DATA,__mod_init_func")]
    pub(super) static IUL_ENV_CTOR: extern "C" fn() = init;

    /// Set by [`init`], read by [`assert_initialised`].
    ///
    /// A separate flag rather than a sentinel field, because every field of
    /// `iul_env` has a legitimate zero: `IUL_WAIT_POLL=0` is a value a caller
    /// may ask for, so "all zeroes" cannot be told from "never filled" by
    /// looking at the struct.
    static RAN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    extern "C" fn init() {
        // SAFETY: before `main`, so nothing else is running.
        unsafe { super::iul_env_fill(&raw mut IUL_ENV) };
        RAN.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Fail loudly if the settings were never read.
    ///
    /// **This is the check the C could not have.** An `.init_array` entry only
    /// runs if the linker pulls its object out of the archive, and when it
    /// does not, every diagnostic is off and `wait_poll_ms` is 0 — which means
    /// "never rescan" and turns a missing wakeup into a hang, a long way from
    /// the cause. `crates/kernel/boot` calls this before the first guest
    /// thread exists, so a link that dropped the constructor says so at
    /// startup.
    pub fn assert_initialised() {
        assert!(
            RAN.load(std::sync::atomic::Ordering::Relaxed),
            "the IUL_* settings were never read: the constructor in \
             crates/util/iulenv did not run, which means the linker dropped \
             the object defining `IUL_ENV`. Every diagnostic is off and \
             wait_poll_ms is 0, which would hang a poll rather than fail here."
        );
    }

    /// The settings struct, as `util/ish_env.h` declares it and this crate
    /// generates it. The one definition a Rust reader should name: thirteen
    /// crates generated their own copy of it until 2026-09-04, each reading
    /// the C global through an `unsafe` block per field.
    pub type Env = ffi::iul_env;

    /// Every setting, read from the C global.
    ///
    /// Safe to call from anywhere: the global is written once, by
    /// [`IUL_ENV_CTOR`], before `main` and so before any guest thread, and
    /// never again. A reader that copies the struct
    /// (`*env()`) gets the same answer as one that reads a field, and the
    /// dispatch loop's per-block `pc_hist` test is still one load and a
    /// branch, because this inlines.
    /// `&*(&raw const …)` and not `&…`, and the `allow` is what keeps it that
    /// way. `iul_env` is a `static mut`, so a shared reference to it is what
    /// `static_mut_refs` **denies**; two clippy lints suggest exactly that —
    /// `borrow_deref_ref` and `deref_addrof` — and `cargo clippy --fix` applied
    /// each of them once on 2026-09-09, with the build refusing it in the same
    /// minute both times. A comment did not stop the second, so this does.
    #[inline]
    #[allow(clippy::deref_addrof, clippy::borrow_deref_ref)]
    pub fn env() -> &'static Env {
        // SAFETY: filled before `main` by `IUL_ENV_CTOR` and never written
        // again.
        unsafe { &*(&raw const IUL_ENV) }
    }

    /// `IUL_V8_NO_MUTE`: do not swallow V8's fatal preamble on stderr.
    /// `crates/kernel/v8mute`.
    pub fn v8_no_mute() -> bool {
        env().v8_no_mute
    }

    /// What the gadget store watchpoint is armed with. `crates/asbestos/diag`.
    ///
    /// The pages are already masked; see the note beside them in
    /// [`super::iul_env_fill`].
    pub struct Watch {
        pub pages: [u64; 2],
        pub lo: u64,
        pub hi: u64,
        pub lo2: u64,
        pub hi2: u64,
        pub field: u64,
    }

    pub fn watch() -> Watch {
        let e = env();
        Watch {
            pages: [e.watch_page, e.watch_page2],
            lo: e.watch_lo,
            hi: e.watch_hi,
            lo2: e.watch_lo2,
            hi2: e.watch_hi2,
            field: e.watch_field,
        }
    }

    /// `IUL_POLL_ADDR`: a guest word to sample from the host every
    /// millisecond. 0 is off.
    pub fn poll_addr() -> u64 {
        env().poll_addr
    }

    /// `IUL_DUMP_ON_SIGTERM`.
    pub fn dump_on_sigterm() -> bool {
        env().dump_on_sigterm
    }
}

pub use settings::{
    Env, Watch, assert_initialised, dump_on_sigterm, env, poll_addr, v8_no_mute, watch,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The flag rule, which is the one anybody typing a variable gets wrong.
    #[test]
    fn a_flag_is_on_unless_it_is_exactly_zero() {
        assert!(!flag(None), "unset");
        assert!(
            flag(Some("")),
            "present and empty is on -- IUL_NO_CHAIN= always was"
        );
        assert!(flag(Some("1")));
        assert!(flag(Some("yes")));
        assert!(
            !flag(Some("0")),
            "the whole point: IUL_NO_CHAIN=0 means off"
        );
        // Not a prefix test: `00` and `0x0` are not the string "0".
        assert!(flag(Some("00")));
        assert!(flag(Some("0x0")));
    }

    /// A watched page is masked to a page, and the mask is where the value is
    /// *parsed* rather than where it is used.
    ///
    /// The assembly compares a store's page against `g_watch_page_val`, so a
    /// low bit left in it makes every comparison fail and the watchpoint record
    /// nothing — silently, which is the worst way for a diagnostic to be
    /// broken. `main()` did the mask inline and nothing could test it.
    #[test]
    fn a_watched_page_is_masked_to_a_page() {
        let page = |v: &str| address(Some(v)) & !0xfff;
        assert_eq!(page("100abc"), 0x100000);
        assert_eq!(page("0x100abc"), 0x100000, "an 0x prefix is accepted");
        assert_eq!(page("fff"), 0, "an offset with no page is page zero");
        assert_eq!(
            page("deadb000"),
            0xdeadb000,
            "an aligned value is unchanged"
        );
        // Unset is 0, which is what "no watchpoint" is.
        assert_eq!(address(None) & !0xfff, 0);
        // Not hex is 0 rather than a panic or a partial number: this runs in a
        // constructor before `main`, where there is nobody to report to.
        assert_eq!(page("nonsense"), 0);
    }

    /// Zero is a value a caller may ask for, so it has to differ from unset.
    #[test]
    fn a_default_that_is_not_zero_survives_an_explicit_zero() {
        assert_eq!(number_or(None, 1000), 1000, "unset takes the default");
        assert_eq!(
            number_or(Some("0"), 1000),
            0,
            "and 0 means 0, not the default"
        );
        assert_eq!(number_or(Some("5"), 1000), 5);
        // IUL_WAIT_POLL=0 is documented as "do not rescan, wait to be told",
        // and it is the setting that turns a missing wakeup from a latency
        // problem into a hang a test suite notices.
        assert_ne!(number_or(Some("0"), 1000), number_or(None, 1000));
    }

    /// `atoi`, not `parse`: a trailing character is ignored rather than
    /// refused, which is what a value like `1000ms` does.
    #[test]
    fn a_number_stops_at_the_first_thing_that_is_not_a_digit() {
        assert_eq!(number(Some("42")), 42);
        assert_eq!(number(Some("42ms")), 42);
        assert_eq!(number(Some("-7")), -7);
        assert_eq!(number(Some("+7")), 7);
        assert_eq!(number(Some("  9")), 9);
        assert_eq!(number(Some("abc")), 0);
        assert_eq!(number(Some("")), 0);
        assert_eq!(number(None), 0);
        // A value too large for an int saturates rather than wrapping into a
        // small or negative one, which is what `IUL_IDLE_EXIT=99999999999`
        // would otherwise become.
        assert_eq!(number(Some("99999999999")), c_int::MAX);
        assert_eq!(number(Some("-99999999999")), c_int::MIN);
    }

    #[test]
    fn an_address_is_hex_with_or_without_the_prefix() {
        assert_eq!(address(Some("1000")), 0x1000);
        assert_eq!(address(Some("0x1000")), 0x1000);
        assert_eq!(address(Some("DEADBEEF")), 0xdeadbeef);
        assert_eq!(address(Some("zzz")), 0);
        assert_eq!(address(None), 0);
    }

    /// A half-parsed range is a window nothing falls in, so it is refused
    /// whole — the reader has a default for the pair.
    #[test]
    fn a_range_needs_both_halves() {
        assert_eq!(range(Some("1000-2000")), Some((0x1000, 0x2000)));
        assert_eq!(range(Some("1000-")), None);
        assert_eq!(
            range(Some("-2000")),
            None,
            "an empty low half, not a negative"
        );
        assert_eq!(range(Some("1000")), None);
        assert_eq!(range(Some("zzz-2000")), None);
        assert_eq!(range(None), None);
    }
}
