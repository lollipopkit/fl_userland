//! `printk`, `vprintk` and `die`: the C-ABI entry points an embedder calls.
//!
//! `kernel/log.c` until 2026-09-06, kept there by two blockers that were
//! written down as one and are answered differently.
//!
//! # `iul_vprintk` takes a `va_list`
//!
//! True, and `core::ffi::VaList` is unstable. But nothing here *interprets* the
//! list — it hands it straight to `vsnprintf`, and on Apple aarch64 a `va_list`
//! is a single pointer:
//!
//! ```text
//! sizeof(va_list) = 8
//! va_start compiles to `add x8, x29, #16`   -- the frame pointer plus 16,
//!                                              which is the entry `sp`
//! ```
//!
//! So the parameter is `*mut c_void` and the call is ABI-identical to the C's.
//! Stable Rust cannot *destructure* a `va_list`; it does not need to.
//!
//! # `iul_printk` and `die` are variadic definitions
//!
//! Also true, and also not what was blocking. The reason the file gave:
//!
//! > unlike the interposed `open`/`openat` — which took a fixed number of
//! > variadic arguments, so a four-instruction trampoline could fetch them — a
//! > printf format decides how many arguments there are and what they are.
//! > There is nothing to fetch without reimplementing vsnprintf.
//!
//! **A trampoline does not have to fetch anything.** What it has to produce is
//! a `va_list`, and the measurement above says a `va_list` is the entry `sp`.
//! `mov x1, sp` and a tail call is the whole of it — two instructions, and
//! fewer than `open` needed, because `open` did have to load a value.
//!
//! The tail call is what keeps it correct: `sp` is unchanged, so the callee's
//! own frame goes *below* the pointer and the arguments it names live in the
//! caller's frame, which outlives the call.
//!
//! # `%s` stays private here, and that is not an oversight
//!
//! `crates/util/signpost` uses `%{public}s` on the grounds that its strings are
//! this kernel's own literals. A log line is not: it carries guest data —
//! `crates/kernel/offloadexec` prints a guest's whole `argv` — so os_log
//! redacting it in a release build is the right answer and the C's bare `%s` is
//! kept deliberately.

use std::ffi::{c_char, c_int, c_void};
use std::mem::MaybeUninit;

use crate::sink;

unsafe extern "C" {
    /// The C library's, which is what the format string is for. Its last
    /// parameter is a `va_list`; see the module comment for why that is a
    /// plain pointer here.
    fn vsnprintf(buf: *mut c_char, size: usize, fmt: *const c_char, ap: *mut c_void) -> c_int;
}

/// One message, bounded.
///
/// [`crate::LineBuffer`] bounds the *accumulation* across calls; this bounds one
/// call, which is what a format string and its arguments can produce. A longer
/// message is truncated here and the sink never sees the rest.
const MESSAGE_MAX: usize = 16384;

/// The last message, which is smaller because it is one line by construction.
const DIE_MAX: usize = 4096;

/// Format one message and hand it to the sink.
///
/// # Safety
/// `msg` is a NUL-terminated format string and `args` is a `va_list` matching
/// it — the contract every `printf` has.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iul_vprintk(msg: *const c_char, args: *mut c_void) {
    // `MaybeUninit`, not `[0u8; 16384]`: the C's `char msgbuf[16384]` was not
    // initialised either, and zeroing sixteen kilobytes on every log call is
    // the kind of cost a translation adds without meaning to.
    let mut buf = MaybeUninit::<[u8; MESSAGE_MAX]>::uninit();
    // SAFETY: the caller's contract; `vsnprintf` writes at most `MESSAGE_MAX`
    // bytes including the NUL.
    let n = unsafe { vsnprintf(buf.as_mut_ptr().cast(), MESSAGE_MAX, msg, args) };
    if n < 0 {
        return;
    }
    let len = (n as usize).min(MESSAGE_MAX - 1);
    // SAFETY: `vsnprintf` answered `n` and wrote `min(n, MESSAGE_MAX - 1)`
    // bytes before its NUL, so `len` bytes are initialised.
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), len) };
    sink::emit(bytes);
}

/// The target of the `die` trampoline: format, hand to the die handler, abort.
///
/// The `abort` is here rather than in the caller because `die` is `_Noreturn`
/// in `debug.h`, which an embedder compiles against.
///
/// **`extern "C"` because the `global_asm!` below tail-calls it**, with
/// `b {die_va}` and `die_va = sym die_va`. A `sym` operand is a *symbol*: the
/// assembler gets an address and nothing on either side states, or checks, a
/// calling convention. Taking the attribute off compiles and links, and is
/// wrong the first time anything dies. Same for `iul_vprintk` above and for
/// `record` in the tests.
///
/// # Safety
/// As [`iul_vprintk`].
unsafe extern "C" fn die_va(msg: *const c_char, args: *mut c_void) -> ! {
    let mut buf = MaybeUninit::<[u8; DIE_MAX]>::uninit();
    // SAFETY: the caller's contract. `vsnprintf` NUL-terminates whenever the
    // size is non-zero, which is what makes the buffer a C string below.
    let n = unsafe { vsnprintf(buf.as_mut_ptr().cast(), DIE_MAX, msg, args) };
    if n < 0 {
        // The contents are unspecified on failure, so do not read them.
        sink::die("die: the message could not be formatted");
    }
    // SAFETY: `vsnprintf` wrote a NUL within `DIE_MAX`, and the buffer
    // outlives the call.
    unsafe { sink::die_handler()(buf.as_ptr().cast()) };
    std::process::abort()
}

// --------------------------------------------------------- the two variadics

#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
compile_error!(
    "the printk and die trampolines encode the Apple aarch64 variadic ABI: a \
     variadic argument is on the stack starting at the entry `sp`, and a \
     `va_list` is a pointer to it. Neither holds on AAPCS64, where a `va_list` \
     is a 32-byte struct over two register save areas."
);

core::arch::global_asm!(
    // iul_printk(msg: x0, ...) -> iul_vprintk(msg, ap = entry sp)
    ".globl _iul_printk",
    ".p2align 2",
    "_iul_printk:",
    "    mov  x1, sp",
    "    b    {vprintk}",
    // die(msg: x0, ...) -> die_va(msg, ap = entry sp), which does not return
    ".globl _die",
    ".p2align 2",
    "_die:",
    "    mov  x1, sp",
    "    b    {die_va}",
    vprintk = sym iul_vprintk,
    die_va = sym die_va,
);

#[cfg(test)]
mod tests {
    use std::ffi::{c_char, c_void};

    // Rust may *declare* a variadic `extern "C" fn`; it is defining one that is
    // unstable. So the trampolines can be called exactly as C calls them.
    unsafe extern "C" {
        #[link_name = "iul_printk"]
        fn printk_variadic(msg: *const c_char, ...);
    }

    // A trampoline of its own, into a recording target, so the test does not
    // depend on the sink or on which log handler this build has. The two
    // instructions are the ones under test, written out again rather than
    // reused, because reusing the real one would make the test agree with
    // whatever the real one does.
    core::arch::global_asm!(
        ".globl _logline_test_printk",
        ".p2align 2",
        "_logline_test_printk:",
        "    mov  x1, sp",
        "    b    {record}",
        record = sym record,
    );

    unsafe extern "C" {
        #[link_name = "logline_test_printk"]
        fn test_printk(msg: *const c_char, ...);

        fn vsnprintf(
            buf: *mut c_char,
            size: usize,
            fmt: *const c_char,
            ap: *mut c_void,
        ) -> std::ffi::c_int;
    }

    static RECORDED: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

    /// What the trampoline tail-calls: format with the `va_list` it was handed
    /// and keep the result.
    unsafe extern "C" fn record(msg: *const c_char, args: *mut c_void) {
        let mut buf = [0u8; 256];
        // SAFETY: the trampoline's contract, which is what is under test.
        let n = unsafe { vsnprintf(buf.as_mut_ptr().cast(), buf.len(), msg, args) };
        let s = String::from_utf8_lossy(&buf[..n.max(0) as usize]).into_owned();
        *RECORDED.lock().unwrap() = s;
    }

    /// What the trampoline has to get right, checked against a recording
    /// function rather than against the log: assemble the same two
    /// instructions in front of a target that copies the `va_list` through
    /// `vsnprintf`, call it through a variadic declaration, and compare with
    /// what the C library makes of the same format and arguments.
    ///
    /// This is the `abi` test in `crates/tools/fakefsredirect` in the shape
    /// this file needs. It is the load-bearing check: if `mov x1, sp` named the
    /// wrong address, every `printk` with an argument would format garbage, and
    /// nothing else here would notice.
    #[test]
    fn the_trampoline_hands_vsnprintf_the_arguments() {
        // Mixed integer, string and float, because they go in different places:
        // a `double` argument is on the stack too on Apple aarch64, and getting
        // the base address wrong shows up first in whichever comes last.
        // SAFETY: the format names exactly these three.
        unsafe { test_printk(c"%d %s %.2f".as_ptr(), 42, c"hi".as_ptr(), 1.5f64) };
        assert_eq!(&*RECORDED.lock().unwrap(), "42 hi 1.50");

        // Nothing at all after the format, which is the case where the stack
        // slot the trampoline points at belongs to something else entirely.
        // SAFETY: the format names no arguments.
        unsafe { test_printk(c"plain".as_ptr()) };
        assert_eq!(&*RECORDED.lock().unwrap(), "plain");

        // Enough arguments to run past one 16-byte stack slot.
        // SAFETY: the format names exactly these six.
        unsafe { test_printk(c"%d%d%d%d%d%d".as_ptr(), 1, 2, 3, 4, 5, 6) };
        assert_eq!(&*RECORDED.lock().unwrap(), "123456");
    }

    /// And the real symbol resolves and runs. The line goes wherever this
    /// build's handler sends it; what is asserted is that calling it as C does
    /// links and returns.
    #[test]
    fn the_exported_printk_is_callable_as_c() {
        // SAFETY: the format names exactly these two.
        unsafe { printk_variadic(c"logline self-test %d %s\n".as_ptr(), 7, c"ok".as_ptr()) };
    }
    unsafe extern "C" {
        /// `die`, which does not return. Reached in a child process below.
        #[link_name = "die"]
        fn die_variadic(msg: *const c_char, ...);
    }

    /// The case this binary runs when it is the child of [`captured`].
    ///
    /// A **re-exec**, not a `fork`. The first version forked and hung: cargo
    /// runs a crate's tests as threads, `sink::emit` takes a `Mutex`, and a
    /// child of a multithreaded process inherits that lock in whatever state
    /// another thread left it. `die` still needs a process of its own, so one
    /// mechanism covers both.
    const CASE_VAR: &str = "IUL_LOGLINE_PRINTK_CASE";

    #[test]
    fn printk_case_child() {
        let Ok(case) = std::env::var(CASE_VAR) else {
            return;
        };
        // SAFETY: each format below names exactly the arguments after it.
        unsafe {
            match case.as_str() {
                // Three argument kinds. On Apple aarch64 every one is on the
                // stack rather than in a register, which is why a non-variadic
                // replacement of the same arity reads the wrong places -- and
                // why `mov x1, sp` has to name the first slot exactly.
                "mixed" => printk_variadic(
                    c"printk %d %s %.2f\n".as_ptr(),
                    42,
                    c"mixed".as_ptr(),
                    1.5f64,
                ),
                // No variadic arguments at all, where the slot the trampoline
                // points at holds whatever the caller last left there. Reading
                // it is fine; a format naming nothing must not use it.
                "plain" => printk_variadic(c"plain\n".as_ptr()),
                // Past the first 16-byte stack slot.
                "eight" => printk_variadic(c"%d%d%d%d%d%d%d%d\n".as_ptr(), 1, 2, 3, 4, 5, 6, 7, 8),
                // No trailing newline: unlike printk, a die message goes
                // straight to the handler, which hands one whole line to the
                // output. Adding one here produced two, which is a property of
                // the die path rather than a defect.
                "die" => die_variadic(c"dying with %s and %d".as_ptr(), c"a string".as_ptr(), 5),
                other => panic!("unknown case {other}"),
            }
        }
        std::process::exit(0);
    }

    /// Run one case in a child of this binary and answer what it wrote.
    fn captured(case: &str) -> (String, std::process::Output) {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "printk::tests::printk_case_child", "--nocapture"])
            .env(CASE_VAR, case)
            .output()
            .expect("re-exec");
        // libtest prints its own lines to stdout; the log line is on stderr.
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        (err, out)
    }

    /// The real `iul_printk`, and what comes out the other end.
    ///
    /// `tests/unit/printk_test.c` was this until 2026-09-08, and its own
    /// comment said why it existed beside `the_two_instructions_read_the_stack`
    /// above: that test assembles the same two instructions in front of a
    /// recording function, so it says the ABI reasoning is right without saying
    /// that the real symbol resolves, that `vsnprintf` gets the pointer, or
    /// that a line reaches the sink. This says all three.
    #[test]
    fn the_real_printk_formats_and_reaches_the_sink() {
        let (out, _) = captured("mixed");
        assert!(out.contains("printk 42 mixed 1.50\n"), "got {out:?}");
        let (out, _) = captured("plain");
        assert!(out.contains("plain\n"), "got {out:?}");
        let (out, _) = captured("eight");
        assert!(out.contains("12345678\n"), "got {out:?}");
    }

    /// `die` is the same trampoline into a target that does not return.
    #[test]
    fn die_formats_and_then_aborts() {
        let (out, output) = captured("die");
        assert!(out.contains("dying with a string and 5\n"), "got {out:?}");
        // SIGABRT, not an exit status: `die` ends with `abort()`, and a child
        // that returned normally would mean the die handler swallowed it.
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            output.status.signal(),
            Some(libc::SIGABRT),
            "{:?}",
            output.status
        );
    }
}
