//! What happens when a handler's frame cannot be written, and in what order
//! two pending signals are taken.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! A handler runs on a frame the kernel writes onto the stack, and a stack that
//! cannot take one — an overflowed one, or an `sp` the program has pointed at
//! nothing — is the case Linux's `force_sigsegv` is for: the process is not
//! resumed where it was, and not in the handler either. It gets a `SIGSEGV` it
//! cannot decline, unless it has a handler for *that* on an alternate stack,
//! which is how a program that installed one to report stack overflow gets to
//! report it. This kernel used to point the CPU at the handler first and write
//! the frame after, so a failed frame resumed the guest inside the handler, on
//! the stack it had just failed to write, with the `SIGSEGV` it had queued
//! blocked by the handler's own mask.
//!
//! # Every fatal case is a forked child
//!
//! The interesting answer is "it died of SIGSEGV", which the process it
//! happened to cannot print. Each case forks; the child arranges the stack and
//! raises; the parent reports how it ended. A child still running after five
//! seconds is killed and reported as such, because a kernel that resumes the
//! handler on the bad stack can loop for ever between the fault and the
//! handler.
//!
//! # The bad `sp` is a raw `svc`
//!
//! A libc call needs a stack, so the signal is raised by `kill(2)` written as
//! the instruction, with `sp` moved onto a `PROT_NONE` page for its duration.
//! The frame for the handler then has nowhere to go.

use std::ffi::c_void;
use std::sync::atomic::{AtomicI32, Ordering};

const PAGE: usize = 4096;
/// `__NR_kill` on aarch64.
const NR_KILL: u64 = 129;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<62} -> {value}");
}

fn signame(sig: i32) -> String {
    match sig {
        libc::SIGSEGV => "SIGSEGV".into(),
        libc::SIGUSR1 => "SIGUSR1".into(),
        libc::SIGUSR2 => "SIGUSR2".into(),
        libc::SIGKILL => "SIGKILL".into(),
        0 => "none".into(),
        s => format!("signal {s}"),
    }
}

/// How a child ended, in words both kernels use.
fn ended(st: i32) -> String {
    if libc::WIFEXITED(st) {
        format!("exit {}", libc::WEXITSTATUS(st))
    } else if libc::WIFSIGNALED(st) {
        format!("died of {}", signame(libc::WTERMSIG(st)))
    } else {
        "neither exited nor died".into()
    }
}

/// Run `body` in a forked child and report how it ended.
fn in_child(what: &str, body: fn()) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        body();
        // A body that returns is one whose signal did nothing at all.
        unsafe { libc::_exit(99) };
    }
    let mut st = 0;
    for _ in 0..5000 {
        let r = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
        if r == pid {
            line(what, ended(st));
            return;
        }
        unsafe { libc::usleep(1000) };
    }
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, &mut st, 0);
    }
    line(what, "still running after five seconds");
}

type Handler = extern "C" fn(i32, *mut libc::siginfo_t, *mut c_void);

/// Install `handler` for `sig` with `SA_SIGINFO` and `flags`, blocking `mask`
/// while it runs.
fn install(sig: i32, flags: i32, mask: &[i32], handler: Handler) {
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = handler as usize;
    act.sa_flags = flags | libc::SA_SIGINFO;
    unsafe {
        libc::sigemptyset(&mut act.sa_mask);
        for m in mask {
            libc::sigaddset(&mut act.sa_mask, *m);
        }
        libc::sigaction(sig, &act, std::ptr::null_mut());
    }
}

/// `SIG_DFL` or `SIG_IGN` for `sig`. Rust's runtime installs a `SIGSEGV`
/// handler of its own, to report a stack overflow; a case about the default
/// action has to put the default back.
fn dispose(sig: i32, handler: libc::sighandler_t) {
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = handler;
    unsafe {
        libc::sigemptyset(&mut act.sa_mask);
        libc::sigaction(sig, &act, std::ptr::null_mut());
    }
}

fn block(sig: i32, how: i32) {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, sig);
        libc::sigprocmask(how, &set, std::ptr::null_mut());
    }
}

/// An alternate stack of 64 KB, or none. Rust's runtime gives the main thread
/// one for its own `SIGSEGV` handler; a case says which it has rather than
/// inheriting that.
fn altstack(on: bool) {
    let mut ss: libc::stack_t = unsafe { std::mem::zeroed() };
    if on {
        let size = 64 * 1024;
        ss.ss_sp = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        ss.ss_size = size;
    } else {
        ss.ss_flags = libc::SS_DISABLE;
    }
    unsafe { libc::sigaltstack(&ss, std::ptr::null_mut()) };
}

/// A `SIGSEGV` handler that reports having run: exit `40 + si_code`, so that a
/// forced `SIGSEGV` (`SI_KERNEL`, 0x80, so 168) and a real fault (`SEGV_MAPERR`
/// 1, `SEGV_ACCERR` 2) read differently.
extern "C" fn segv_reports(_sig: i32, info: *mut libc::siginfo_t, _ctx: *mut c_void) {
    let raw = unsafe { std::slice::from_raw_parts(info.cast::<u8>(), 12) };
    let code = i32::from_ne_bytes(raw[8..12].try_into().unwrap());
    unsafe { libc::_exit(40 + (code & 0xff)) };
}

/// A `SIGUSR1` handler that reports having run.
extern "C" fn usr1_reports(_sig: i32, _info: *mut libc::siginfo_t, _ctx: *mut c_void) {
    unsafe { libc::_exit(60) };
}

/// Overflow the main thread's stack. 512 bytes a frame, so about sixteen
/// thousand calls to the 8 MB default.
#[inline(never)]
#[allow(unconditional_recursion)]
fn recurse(depth: u64) -> u64 {
    let pad = [depth; 64];
    std::hint::black_box(&pad);
    recurse(depth + 1) + pad[(depth % 64) as usize]
}

/// `kill(getpid(), sig)` as a raw `svc`, with `sp` on a `PROT_NONE` page: the
/// frame for the handler cannot be written there. Restores `sp` after, for the
/// one case where the signal does nothing.
#[inline(never)]
fn raise_with_unwritable_sp(sig: i32) {
    let region = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            2 * PAGE,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let bad = region as u64 + (2 * PAGE) as u64 - 64;
    let pid = unsafe { libc::getpid() } as u64;
    unsafe {
        core::arch::asm!(
            "mov x9, sp",
            "mov sp, {bad}",
            "svc #0",
            "mov sp, x9",
            bad = in(reg) bad,
            inout("x0") pid => _,
            in("x1") sig as u64,
            in("x8") NR_KILL,
            out("x9") _,
        );
    }
}

// ------------------------------------------------------------- the children

fn overflow_handler_off_altstack() {
    altstack(false);
    install(libc::SIGSEGV, 0, &[], segv_reports);
    recurse(0);
}

fn overflow_handler_on_altstack() {
    altstack(true);
    install(libc::SIGSEGV, libc::SA_ONSTACK, &[], segv_reports);
    recurse(0);
}

fn usr1_frame_fails_segv_handler_on_altstack() {
    altstack(true);
    install(libc::SIGSEGV, libc::SA_ONSTACK, &[], segv_reports);
    install(libc::SIGUSR1, 0, &[], usr1_reports);
    raise_with_unwritable_sp(libc::SIGUSR1);
}

fn usr1_frame_fails_segv_handler_off_altstack() {
    altstack(false);
    install(libc::SIGSEGV, 0, &[], segv_reports);
    install(libc::SIGUSR1, 0, &[], usr1_reports);
    raise_with_unwritable_sp(libc::SIGUSR1);
}

fn usr1_frame_fails_segv_default_and_blocked() {
    altstack(false);
    dispose(libc::SIGSEGV, libc::SIG_DFL);
    block(libc::SIGSEGV, libc::SIG_BLOCK);
    install(libc::SIGUSR1, 0, &[], usr1_reports);
    raise_with_unwritable_sp(libc::SIGUSR1);
}

fn usr1_frame_fails_segv_ignored() {
    altstack(false);
    dispose(libc::SIGSEGV, libc::SIG_IGN);
    install(libc::SIGUSR1, 0, &[], usr1_reports);
    raise_with_unwritable_sp(libc::SIGUSR1);
}

/// The control: the same bad `sp`, and a handler whose frame goes elsewhere.
fn usr1_frame_on_altstack() {
    altstack(true);
    install(libc::SIGUSR1, libc::SA_ONSTACK, &[], usr1_reports);
    raise_with_unwritable_sp(libc::SIGUSR1);
}

/// The signal whose frame fails is `SIGSEGV` itself, with a handler for it
/// that has nowhere to run. A kernel that forced a *handled* `SIGSEGV` would
/// try the same handler on the same stack for ever.
fn segv_frame_fails_segv_handler_off_altstack() {
    altstack(false);
    install(libc::SIGSEGV, 0, &[], segv_reports);
    raise_with_unwritable_sp(libc::SIGSEGV);
}

// ---------------------------------------------------- two pending at once

/// Which handler ran first, and for each, whether the mask the frame saved --
/// the one restored when it returns, which is the mask the signal interrupted
/// -- had the *other* signal blocked. -1 for a handler that did not run.
static FIRST: AtomicI32 = AtomicI32::new(0);
static SAVED_HAS_OTHER: [AtomicI32; 2] = [AtomicI32::new(-1), AtomicI32::new(-1)];

fn note(slot: usize, sig: i32, ctx: *mut c_void, other: i32) {
    let _ = FIRST.compare_exchange(0, sig, Ordering::SeqCst, Ordering::SeqCst);
    // aarch64 `ucontext_t`: `uc_flags` (8), `uc_link` (8), `uc_stack` (24),
    // then `uc_sigmask`, whose first word holds signals 1..=64.
    let raw = unsafe { std::slice::from_raw_parts(ctx.cast::<u8>(), 48) };
    let mask = u64::from_ne_bytes(raw[40..48].try_into().unwrap());
    SAVED_HAS_OTHER[slot].store(((mask >> (other - 1)) & 1) as i32, Ordering::SeqCst);
}

extern "C" fn usr1_notes(sig: i32, _info: *mut libc::siginfo_t, ctx: *mut c_void) {
    note(0, sig, ctx, libc::SIGUSR2);
}

extern "C" fn usr2_notes(sig: i32, _info: *mut libc::siginfo_t, ctx: *mut c_void) {
    note(1, sig, ctx, libc::SIGUSR1);
}

fn main() {
    println!("## a frame that cannot be written");
    in_child(
        "stack overflow, SIGSEGV handler off the altstack",
        overflow_handler_off_altstack,
    );
    in_child(
        "stack overflow, SIGSEGV handler on an altstack",
        overflow_handler_on_altstack,
    );
    in_child(
        "SIGUSR1 frame unwritable, SIGSEGV handler on an altstack",
        usr1_frame_fails_segv_handler_on_altstack,
    );
    in_child(
        "SIGUSR1 frame unwritable, SIGSEGV handler off the altstack",
        usr1_frame_fails_segv_handler_off_altstack,
    );
    in_child(
        "SIGUSR1 frame unwritable, SIGSEGV default and blocked",
        usr1_frame_fails_segv_default_and_blocked,
    );
    in_child(
        "SIGUSR1 frame unwritable, SIGSEGV ignored",
        usr1_frame_fails_segv_ignored,
    );
    in_child(
        "SIGUSR1 handler on an altstack, sp unwritable (control)",
        usr1_frame_on_altstack,
    );
    in_child(
        "SIGSEGV frame unwritable, SIGSEGV handler off the altstack",
        segv_frame_fails_segv_handler_off_altstack,
    );

    println!("## two signals pending at once");
    {
        // Each handler's mask names the other, so whichever runs first, the
        // second waits for it to return. Raised in the order that would be
        // wrong if arrival order decided: a real kernel takes the lower number
        // first.
        install(libc::SIGUSR1, 0, &[libc::SIGUSR2], usr1_notes);
        install(libc::SIGUSR2, 0, &[libc::SIGUSR1], usr2_notes);
        block(libc::SIGUSR1, libc::SIG_BLOCK);
        block(libc::SIGUSR2, libc::SIG_BLOCK);
        unsafe {
            libc::raise(libc::SIGUSR2);
            libc::raise(libc::SIGUSR1);
        }
        let mut both: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut both);
            libc::sigaddset(&mut both, libc::SIGUSR1);
            libc::sigaddset(&mut both, libc::SIGUSR2);
            libc::sigprocmask(libc::SIG_UNBLOCK, &both, std::ptr::null_mut());
        }
        line("the first handler to run", signame(FIRST.load(Ordering::SeqCst)));
        line(
            "SIGUSR1's handler: the mask it interrupted had SIGUSR2 blocked",
            SAVED_HAS_OTHER[0].load(Ordering::SeqCst),
        );
        line(
            "SIGUSR2's handler: the mask it interrupted had SIGUSR1 blocked",
            SAVED_HAS_OTHER[1].load(Ordering::SeqCst),
        );
    }
}
