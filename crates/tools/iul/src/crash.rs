//! The host-side crash handler, and the terminal it puts back.
//!
//! # Two jobs, and only one of them is a diagnostic
//!
//! A `SIGSEGV` or `SIGBUS` **inside JIT code** is how a guest's bad memory
//! access reaches this kernel: the gadgets fault on the host, and the handler
//! turns that into a guest fault by pointing the machine at
//! `jit_crash_trampoline`, which returns `INT_JIT_CRASH` through `fiber_exit`.
//! That is a hot path in the sense that it must be correct, not that it is
//! frequent — every guest `SIGSEGV` goes through it.
//!
//! Anything else is a crash in the emulator itself, and all the handler can do
//! is print enough to identify it and leave.
//!
//! # The offsets
//!
//! The handler writes into `struct cpu_state` through `_cpu`, which is `x1`.
//! **These were four hand-written `#define`s until 2026-09-03 and three of them
//! were wrong**: `struct cpu_state` gained `excl_val2` on 2026-07-10, when
//! `STXP` became a real pair compare-exchange, which moved everything after it
//! by eight bytes and nothing told `main.c`. Since then the handler had been
//! writing the guest fault address into the exclusive-monitor value, the
//! read/write flag into `segfault_addr` — so every recovered fault was reported
//! at address 0 or 1 — and restoring the host stack pointer from sixteen bytes
//! before `jit_exit_sp`.
//!
//! They are `offset_of!` on the generated struct here, which is the same answer
//! `asbestos/offsets.c` computes for the assembly and cannot drift from the
//! header. `tools/hardcoded-offsets.py` is what found the C's.

use std::mem::offset_of;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use crate::ffi;

/// The host terminal's settings, saved before the guest is given a raw one.
///
/// A `OnceLock`, not a `Mutex`: it is set once before any thread exists and
/// read from an `atexit` handler, where taking a lock another thread might
/// hold is how an exit hangs; reading a set `OnceLock` takes none. It was a
/// `static mut` and a validity flag beside it until 2026-10-17.
static SAVED_TERMIOS: std::sync::OnceLock<rustix::termios::Termios> = std::sync::OnceLock::new();

/// Put the host terminal back the way it was.
///
/// Installed as `crates/kernel/exitcalls`' hook by [`save_terminal`], so an
/// embedder that does not link this binary installs nothing and the exit path
/// calls through a null check. It was a strong definition overriding a weak one
/// in `kernel/task.c` until 2026-09-06; see the hook's comment for why that
/// shape does not survive a release link.
pub extern "C" fn restore_termios() {
    if let Some(saved) = SAVED_TERMIOS.get() {
        let _ = rustix::termios::tcsetattr(
            rustix::stdio::stdin(),
            rustix::termios::OptionalActions::Now,
            saved,
        );
    }
}

/// Remember the terminal, if there is one.
pub(crate) fn save_terminal() {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return;
    }
    if let Ok(t) = rustix::termios::tcgetattr(rustix::stdio::stdin())
        && SAVED_TERMIOS.set(t).is_ok()
    {
        // SAFETY: registering a plain `extern "C" fn()`.
        unsafe { libc::atexit(restore_termios) };
        // And on the guest's own way out, which does not go through `atexit`:
        // `do_exit_group` reaches `crates/kernel/exitcalls`.
        exitcalls::set_restore_termios_hook(restore_termios);
    }
}

unsafe extern "C" {
    /// The assembly trampoline that returns `INT_JIT_CRASH` through
    /// `fiber_exit`. `asbestos/guest-arm64/gadgets-aarch64/entry.S`.
    fn jit_crash_trampoline();
}

/// Install the handler on an alternate stack.
///
/// The alternate stack is what lets a stack-overflow fault be reported at all:
/// without it the handler runs on the stack that just overflowed.
///
/// # Safety
/// Called from `main` before any thread exists.
pub(crate) unsafe fn install_handlers() {
    // Leaked deliberately: the handler runs for the life of the process and the
    // kernel keeps the pointer.
    let size = libc::SIGSTKSZ.max(64 * 1024);
    let stack = Box::leak(vec![0u8; size].into_boxed_slice());
    let ss = libc::stack_t {
        ss_sp: stack.as_mut_ptr().cast(),
        ss_flags: 0,
        ss_size: size,
    };
    unsafe { libc::sigaltstack(&ss, std::ptr::null_mut()) };

    // SAFETY: the handler reports and ends the process.
    unsafe {
        util_hostsig::install(
            &[libc::SIGSEGV, libc::SIGBUS, libc::SIGABRT, libc::SIGILL, libc::SIGTRAP],
            util_hostsig::Handler::Info(crash_handler),
            &[],
            true,
        )
    };
}

/// What the handler saw, for a debugger or a core dump to find.
///
/// Nothing in this tree reads them; they were in `kernel/calls.c`, which is
/// gone, and the one place that did was a trace line in the fault arm. An
/// embedder that installs a handler like this one defines its own.
///
/// # Atomics, because the writer is every guest thread at once
///
/// They were `static mut` until 2026-09-12, written as four plain stores and a
/// `jit_crash_count += 1` from inside [`crash_handler`]. That handler runs on
/// **whichever thread faulted**, and a guest's `SIGSEGV` is how its bad memory
/// accesses reach this kernel — so two guest threads faulting at once run two
/// copies of it concurrently, and `+= 1` is a load, an add and a store with
/// nothing between them. A data race in Rust is undefined behaviour whatever
/// the machine does with it, and the count was also simply wrong: two
/// concurrent faults recorded one.
///
/// `Relaxed` is the whole ordering: these are a report, not a protocol, and
/// nothing decides anything on them. Reading them does not need the handler to
/// have finished.
///
/// **The symbols do not change.** `AtomicU64` is `#[repr(transparent)]` over
/// `UnsafeCell<u64>`, so a debugger or a core dump reads the same eight bytes
/// at the same name — which is the only interface these have.
#[unsafe(no_mangle)]
pub static jit_last_host_fault: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
pub static jit_last_x7: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
pub static jit_last_x10: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
pub static jit_crash_count: AtomicI32 = AtomicI32::new(0);

/// Write `n` bytes of `s` to stderr, from a signal handler.
///
/// `write(2)` and nothing else: `println!` locks and allocates, and both are
/// forbidden here — the thread this interrupted may hold the lock or be inside
/// the allocator, which is exactly the state a crash tends to arrive in.
fn emit(s: &[u8]) {
    // SAFETY: a bounded write to a descriptor, which is async-signal-safe.
    unsafe { libc::write(libc::STDERR_FILENO, s.as_ptr().cast(), s.len()) };
}

/// A `u64` as sixteen hex digits, without allocating.
fn hex(v: u64, out: &mut [u8; 18]) -> &[u8] {
    out[0] = b'0';
    out[1] = b'x';
    for i in 0..16 {
        let nibble = (v >> (60 - 4 * i)) & 0xf;
        out[2 + i] = b"0123456789abcdef"[nibble as usize];
    }
    &out[..18]
}

fn emit_reg(name: &[u8], v: u64) {
    let mut buf = [0u8; 18];
    emit(name);
    emit(b": ");
    emit(hex(v, &mut buf));
    emit(b"\n");
}

/// # Safety
/// Called by the kernel as an `SA_SIGINFO` handler: `info` and `ctx` are what it passes.
unsafe extern "C" fn crash_handler(sig: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // SAFETY: the kernel's contract for an `SA_SIGINFO` handler.
    let uc = ctx.cast::<libc::ucontext_t>();
    if uc.is_null() || info.is_null() {
        emit(b"\n=== HOST CRASH: no context ===\n");
        unsafe { libc::_exit(139) };
    }
    let mc = unsafe { (*uc).uc_mcontext };
    if mc.is_null() {
        emit(b"\n=== HOST CRASH: no machine context ===\n");
        unsafe { libc::_exit(139) };
    }
    let ss = unsafe { &mut (*mc).__ss };

    // Inside JIT code, a fault is the *guest's*. Redirect to the trampoline
    // rather than `_setjmp`ing on every block entry, which is what this shape
    // buys: the recovery costs nothing until it happens.
    // A thread with no slot is an embedder's own, not a guest thread, so a
    // fault in it is a real crash. `pthread_getspecific` is on POSIX's
    // async-signal-safe list, which is what a handler needs and what
    // `_tlv_get_addr` is not -- it allocates on first touch.
    let jit = jitstate::current();
    let in_jit =
        !jit.is_null() && unsafe { (*jit).in_jit.load(std::sync::atomic::Ordering::Relaxed) } != 0;
    if (sig == libc::SIGSEGV || sig == libc::SIGBUS) && in_jit {
        // `_cpu` is x1: a pointer to the `struct cpu_state` that begins a
        // `struct fiber_frame`, so an offset into the frame is an offset from
        // it too.
        let cpu = ss.__x[1];
        // x7 is `_addr`, the host pointer, which is `data_minus_addr + guest`;
        // x10 holds `data_minus_addr` on the TLB-hit path.
        let (x7, x10) = (ss.__x[7], ss.__x[10]);
        let guest_addr = (x7.wrapping_sub(x10)) & 0xffff_ffff_ffff;

        // SAFETY: `info` was checked non-null above; the kernel's contract for
        // an `SA_SIGINFO` handler makes `si_addr` readable.
        jit_last_host_fault.store(unsafe { (*info).si_addr } as u64, Ordering::Relaxed);
        jit_last_x7.store(x7, Ordering::Relaxed);
        jit_last_x10.store(x10, Ordering::Relaxed);
        jit_crash_count.fetch_add(1, Ordering::Relaxed);

        // The host's ESR says which it was. Bit 6 (WnR): 0 read, 1 write.
        let esr = unsafe { (*mc).__es.__esr };
        let was_write = i32::from(esr & 0x40 != 0);

        // SAFETY: `cpu` is the `struct cpu_state` the faulting gadget was
        // running with, and every offset is `offset_of!` on the generated
        // struct — the same layout `asbestos/offsets.c` gives the assembly.
        unsafe {
            let at = |off: usize| (cpu as usize + off) as *mut u8;
            at(offset_of!(ffi::cpu_state, segfault_addr))
                .cast::<u64>()
                .write(guest_addr);
            at(offset_of!(ffi::cpu_state, segfault_was_write))
                .cast::<i32>()
                .write(was_write);
            // Back to the start of the block, to be re-executed.
            at(offset_of!(ffi::cpu_state, pc))
                .cast::<u64>()
                .write((*jit).saved_pc.load(std::sync::atomic::Ordering::Relaxed));
            // And the stack pointer `fiber_enter` saved, so `fiber_exit` pops
            // the callee-saved frame from where it actually is.
            ss.__sp = at(offset_of!(ffi::fiber_frame, jit_exit_sp))
                .cast::<u64>()
                .read();
        }
        ss.__pc = jit_crash_trampoline as *const () as u64;

        // Unblock the signal so the next fault is delivered too: returning
        // from a handler normally does this, and this return goes somewhere
        // else.
        util_hostsig::unblock(&[sig]);
        return;
    }

    // Not the guest's: the emulator itself. Say enough to identify it.
    emit(b"\n=== HOST CRASH: signal ");
    let mut buf = [0u8; 18];
    emit(hex(sig as u64, &mut buf));
    emit(b" ===\nfault addr");
    emit_reg(b"", unsafe { (*info).si_addr } as u64);
    emit_reg(b"pc ", ss.__pc);
    emit_reg(b"lr ", ss.__lr);
    emit_reg(b"sp ", ss.__sp);
    // The ones a JIT crash is read from: the guest registers the gadgets keep
    // things in. `x1` is `_cpu`, `x7` the host address a memory gadget was
    // using and `x28` the guest sp.
    for (name, r) in [
        (&b"x0 "[..], 0usize),
        (&b"x1 "[..], 1),
        (&b"x2 "[..], 2),
        (&b"x7 "[..], 7),
        (&b"x28"[..], 28),
    ] {
        emit_reg(name, ss.__x[r]);
    }
    let mut bt = [std::ptr::null_mut::<libc::c_void>(); 20];
    // SAFETY: `backtrace` walks the frame pointers and writes at most 20
    // entries; `backtrace_symbols_fd` writes to a descriptor and allocates
    // nothing, which is why it is the `_fd` form.
    unsafe {
        let n = libc::backtrace(bt.as_mut_ptr(), bt.len() as i32);
        libc::backtrace_symbols_fd(bt.as_ptr(), n, libc::STDERR_FILENO);
        libc::_exit(139);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four offsets the handler writes through, against what the compiler
    /// says. Not a check that `offset_of!` works — a check that the *fields*
    /// are the ones this thinks they are, so a rename in `emu/cpu.h` fails
    /// here rather than silently writing into a neighbour, which is exactly
    /// what happened to the C for four months.
    #[test]
    fn the_fields_the_handler_writes_are_distinct() {
        let offs = [
            offset_of!(ffi::cpu_state, pc),
            offset_of!(ffi::cpu_state, segfault_addr),
            offset_of!(ffi::cpu_state, segfault_was_write),
        ];
        let mut sorted = offs.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), offs.len(), "three fields, three offsets");
        // `struct cpu_state` begins a `struct fiber_frame`, which is what makes
        // an offset from `_cpu` reach the frame's own fields.
        assert_eq!(offset_of!(ffi::fiber_frame, cpu), 0);
        assert!(offset_of!(ffi::fiber_frame, jit_exit_sp) > 0);
    }

    /// The hex formatter, which runs where nothing may allocate.
    #[test]
    fn hex_is_sixteen_digits_and_a_prefix() {
        let mut b = [0u8; 18];
        assert_eq!(hex(0, &mut b), b"0x0000000000000000");
        assert_eq!(hex(0xdead_beef, &mut b), b"0x00000000deadbeef");
        assert_eq!(hex(u64::MAX, &mut b), b"0xffffffffffffffff");
    }
}
