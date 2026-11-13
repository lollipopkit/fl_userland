//! Where a finished log line goes: the lock, the ring, and the handler this
//! build was configured with.
//!
//! # What is still C, and why it is only that
//!
//! The former `kernel/log.c` kept three functions and nothing else:
//!
//! - `iul_vprintk`, which takes a `va_list`. Stable Rust has no way to accept
//!   one — `core::ffi::VaList` is unstable.
//! - `iul_printk` and `die`, which are **variadic**, and this is not the
//!   `open`/`openat` case: those took a fixed number of variadic arguments and
//!   a four-instruction trampoline could fetch them. A `printf` format decides
//!   how many arguments there are and what they are, so there is nothing to
//!   fetch without reimplementing `vsnprintf`.
//!
//! Everything after the `vsnprintf` is here, reached through [`log_emit`].
//!
//! # The two handlers that stay behind
//!
//! `LOG_HANDLER_NSLOG` and `LOG_HANDLER_OS_LOG` expand to **clang builtins** —
//! `__builtin_os_log_format` and `__builtin_os_log_format_buffer_size`, plus a
//! format string placed in `__TEXT,__oslogstring` — and `CFSTR`, which builds a
//! static `CFString`. Neither has a Rust equivalent, and hand-encoding Apple's
//! private argument buffer to call `_os_log_fault_impl` directly would be a
//! wire format with no specification and no way to test it against one.
//!
//! That puts them in the same class `docs/remaining-c.md` already has for
//! `util/signpost.c`: a contract with the toolchain rather than a remaining C
//! implementation. The other three handlers are here.

use std::sync::Mutex;

/// The output lock — `kernel/log.c`'s `log_lock` until 2026-09-06.
///
/// It covers the **output**, which is what stops two finished lines
/// interleaving inside one write. The partial line each thread is building is
/// per-thread and needs no lock at all; see the module comment on
/// [`crate::LineBuffer`].
///
/// A Rust `Mutex` rather than the tree's `lock_t`, which is the one thing here
/// a `-DLOCK_DEBUG=1` build no longer sees. That is a deliberate trade and a
/// small one: this is a leaf lock — nothing is taken while it is held except
/// the ring's own, which is inside it and was already invisible to the C's
/// bookkeeping in the same way — so it cannot take part in an inversion, which
/// is what the instrument exists to find.
static OUTPUT: Mutex<()> = Mutex::new(());

/// One already-formatted message, from [`crate::printk::iul_vprintk`]'s
/// `vsnprintf`.
///
/// Accumulates into whole lines and hands each one to the handler and the
/// kernel log ring. Bounded by [`crate::LineBuffer`]; a message longer than
/// one `vsnprintf` buffer was truncated before it got here.
///
/// Not an export since 2026-09-06: its one caller was `kernel/log.c` and is
/// this crate's own module now.
pub(crate) fn emit(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    // Poisoning is not a failure mode worth propagating out of a log call: a
    // panic in a handler would leave every later line silent. Take the guard
    // either way.
    let _held = OUTPUT.lock().unwrap_or_else(|e| e.into_inner());
    crate::with_pending(|buf| buf.append(bytes, output_line));
}

/// One whole line from Rust, with the newline supplied here.
///
/// **Seven crates had a private copy of the same eight lines** until
/// 2026-09-06 — `CString::new(msg)` and then `iul_printk("%s\n", s)` — and
/// all seven inherited two problems from it. The lesser is the cost: an
/// allocation and a `vsnprintf` re-parse of a string that was already
/// formatted. The other is a defect. `CString::new` **fails** on an interior
/// NUL, every copy wrote `if let Ok(..)`, and so a log line containing one
/// vanished — in the crate whose [`crate::LineBuffer::append`] says in as many
/// words that a NUL is kept, because "a log line that contains one is a log
/// line that contains one".
///
/// Nothing here needs the C varargs path: the caller has a `&str` and the sink
/// takes bytes.
pub fn printk(msg: &str) {
    let _held = OUTPUT.lock().unwrap_or_else(|e| e.into_inner());
    crate::with_pending(|buf| {
        buf.append(msg.as_bytes(), output_line);
        buf.append(b"\n", output_line);
    });
}

/// One complete line, without its newline.
fn output_line(line: &[u8]) {
    backend::write_line(line);
    // The kernel log ring, which `sys_syslog` reads. Its own lock is taken
    // inside this one, which is the order the C had.
    crate::klog::append(line);
    crate::klog::append(b"\n");
}

/// The handler this build was configured with.
///
/// Exactly one `LOG_HANDLER_*` `cfg` is set — a build names one in
/// `TMPFS_RS_CLANG_ARGS` and `build.rs` sets `dprintf` when it names none — and
/// the `cfg`s below mirror the C's `#if`/`#elif` chain, including its order.
///
/// **Both failure modes are compile errors.** None defined reaches the
/// `compile_error!` at the bottom rather than a silent no-op, which is what the
/// C's dangling `#endif` gave: `log_line` was simply undefined and the link
/// failed. Two defined gives two definitions of `write_line`, which is why
/// these are `-D`s and not cargo features — features are additive, so two
/// dependents asking for different handlers would union them rather than
/// conflict. See `build.rs`.
mod backend {
    #[cfg(iul_log_handler_dprintf)]
    pub fn write_line(line: &[u8]) {
        // Descriptor 666 is the embedder contract. A standalone test binary
        // cannot assume that descriptor exists because its `OPEN_MAX` may be
        // lower, so the test build uses stderr, which the child harness owns.
        #[cfg(test)]
        let fd = libc::STDERR_FILENO;
        #[cfg(not(test))]
        let fd = 666;
        // `writev` keeps the line and its newline in one call.
        let iov = [
            libc::iovec {
                iov_base: line.as_ptr() as *mut libc::c_void,
                iov_len: line.len(),
            },
            libc::iovec {
                iov_base: c"\n".as_ptr() as *mut libc::c_void,
                iov_len: 1,
            },
        ];
        // SAFETY: two valid buffers; a closed descriptor answers -1, which is
        // what the C did with it too.
        unsafe { libc::writev(fd, iov.as_ptr(), 2) };
    }

    #[cfg(iul_log_handler_syslog)]
    pub fn write_line(line: &[u8]) {
        if let Ok(c) = std::ffi::CString::new(line) {
            // SAFETY: a literal format and one NUL-terminated argument.
            unsafe { libc::syslog(libc::LOG_DEBUG, c"%s".as_ptr(), c.as_ptr()) };
        }
    }

    #[cfg(iul_log_handler_stderr)]
    pub fn write_line(line: &[u8]) {
        use std::io::Write;
        let mut err = std::io::stderr().lock();
        let _ = err.write_all(line);
        let _ = err.write_all(b"\n");
    }

    /// `os_log_fault(OS_LOG_DEFAULT, "%s", line)`, which was `kernel/log.c`'s
    /// four lines until 2026-09-06.
    ///
    /// `os_log_fault` is a macro over **`__builtin_os_log_format`**, which
    /// encodes a format's arguments into a byte buffer at compile time and has
    /// no Rust equivalent. What it produces for one `%s` and a pointer is
    /// twelve bytes, measured off clang the same way
    /// `crates/util/signpost` measured its two:
    ///
    /// ```text
    /// bare %s   size=12   02 01 20 08 88 77 66 55 44 33 22 11
    /// ```
    ///
    /// `0x20` rather than signpost's `0x22` is the whole difference, and it is
    /// what settled which nibble is which: the descriptor is
    /// `(string << 4) | annotation`, and a bare `%s` carries no annotation.
    ///
    /// **Private, deliberately.** os_log redacts an unannotated `%s` in a
    /// release build. `crates/util/signpost` marks its strings `{public}`
    /// because they are this kernel's own literals; a log line is not — it
    /// carries guest data, including a whole `argv` — so redaction is the right
    /// answer here and the C's bare `%s` is preserved rather than improved.
    #[cfg(iul_log_handler_os_log)]
    pub fn write_line(line: &[u8]) {
        let Ok(c) = std::ffi::CString::new(line) else {
            return;
        };
        let mut buf = [0u8; 12];
        buf[0] = 0x02; // has a non-scalar argument
        buf[1] = 0x01; // one argument
        buf[2] = 0x20; // (string << 4) | none
        buf[3] = 0x08; // eight bytes
        buf[4..].copy_from_slice(&(c.as_ptr() as usize as u64).to_le_bytes());
        // SAFETY: `FMT` and `__dso_handle` are 'static and in this image;
        // `buf` describes exactly the one argument `FMT` names; `c` outlives
        // the call.
        unsafe {
            _os_log_impl(
                (&raw const __dso_handle).cast_mut(),
                (&raw const _os_log_default).cast_mut(),
                OS_LOG_TYPE_FAULT,
                FMT.as_ptr().cast(),
                buf.as_mut_ptr(),
                buf.len() as u32,
            );
        }
    }

    /// `OS_LOG_TYPE_FAULT` from `<os/log.h>`.
    #[cfg(iul_log_handler_os_log)]
    const OS_LOG_TYPE_FAULT: std::ffi::c_int = 0x11;

    /// The format literal, where the tracing library resolves it from. clang
    /// puts an os_log format string here; a pointer into `.rodata` is not
    /// something a trace can name.
    #[cfg(iul_log_handler_os_log)]
    #[used]
    #[unsafe(link_section = "__TEXT,__oslogstring,cstring_literals")]
    static FMT: [u8; 3] = *b"%s\0";

    #[cfg(iul_log_handler_os_log)]
    unsafe extern "C" {
        /// This image's mach header, which the trace resolves `FMT` against.
        static __dso_handle: std::ffi::c_void;
        /// `OS_LOG_DEFAULT`, which is the address of this global.
        static _os_log_default: std::ffi::c_void;
        fn _os_log_impl(
            dso: *mut std::ffi::c_void,
            log: *mut std::ffi::c_void,
            ty: std::ffi::c_int,
            format: *const std::ffi::c_char,
            buf: *mut u8,
            size: u32,
        );
    }

    /// `NSLog(CFSTR("%s"), line)`, which was the other half of
    /// `kernel/log.c`'s Apple backend.
    ///
    /// `CFSTR` is `__builtin___CFStringMakeConstantString`, which builds a
    /// constant `CFString` in `__DATA,__cfstring`. There is no Rust equivalent
    /// of the builtin and there is a runtime one of the *result*:
    /// `CFStringCreateWithCString`, made once. `NSLog` itself is an ordinary
    /// variadic C function — Rust may *declare* one, which is all a caller
    /// needs.
    #[cfg(iul_log_handler_nslog)]
    pub fn write_line(line: &[u8]) {
        use std::sync::OnceLock;

        /// A `CFStringRef`, which is immutable and documented thread-safe.
        struct Fmt(usize);

        static FMT: OnceLock<Fmt> = OnceLock::new();
        let fmt = FMT.get_or_init(|| {
            // SAFETY: a 'static literal and a documented encoding constant.
            Fmt(unsafe {
                CFStringCreateWithCString(
                    std::ptr::null(),
                    c"%s".as_ptr(),
                    K_CF_STRING_ENCODING_UTF8,
                ) as usize
            })
        });
        if fmt.0 == 0 {
            return;
        }
        if let Ok(c) = std::ffi::CString::new(line) {
            // SAFETY: the format names exactly this one argument.
            unsafe { NSLog(fmt.0 as *const std::ffi::c_void, c.as_ptr()) };
        }
    }

    /// `kCFStringEncodingUTF8`, from `<CoreFoundation/CFString.h>`.
    #[cfg(iul_log_handler_nslog)]
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    #[cfg(iul_log_handler_nslog)]
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(
            alloc: *const std::ffi::c_void,
            c_str: *const std::ffi::c_char,
            encoding: u32,
        ) -> *const std::ffi::c_void;
    }

    // **Foundation, not CoreFoundation.** The two are named together often
    // enough that it was got wrong here first, and the C could not have said
    // so: `kernel/log.c` included `<CoreFoundation/CoreFoundation.h>` and
    // declared `NSLog` by hand, leaving the framework to the build system. A
    // `#[link]` attribute puts it where the declaration is, and the check is
    // that the crate's tests *link* under this handler rather than only
    // compile.
    #[cfg(iul_log_handler_nslog)]
    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {
        fn NSLog(fmt: *const std::ffi::c_void, ...);
    }

    #[cfg(not(any(
        iul_log_handler_dprintf,
        iul_log_handler_syslog,
        iul_log_handler_stderr,
        iul_log_handler_nslog,
        iul_log_handler_os_log,
    )))]
    compile_error!(
        "no LOG_HANDLER_* cfg is set. build.rs sets dprintf when the build \
         names none, so reaching this means build.rs did not run or its \
         default was removed."
    );
}

// ---------------------------------------------------------------------------
// die
// ---------------------------------------------------------------------------

/// What `die` calls before aborting, if an embedder installed one -- the
/// way to route a fatal message somewhere an iOS app can show it.
///
/// A writable `static mut` function pointer named `die_handler` until
/// 2026-10-17, which an embedder assigned and both readers read in an
/// `unsafe` block. Set once now, by [`iul_set_die_handler`], so a reader on
/// the way to `abort` takes no lock.
pub type DieHandler = unsafe extern "C" fn(*const std::ffi::c_char);
static DIE_HANDLER: std::sync::OnceLock<DieHandler> = std::sync::OnceLock::new();

/// Install the embedder's die handler. Once: a second call answers false and
/// changes nothing, so a fatal message never races a replacement.
#[unsafe(no_mangle)]
pub extern "C" fn iul_set_die_handler(handler: DieHandler) -> bool {
    DIE_HANDLER.set(handler).is_ok()
}

/// The handler to call: the embedder's, or [`default_die_handler`].
pub(crate) fn die_handler() -> DieHandler {
    DIE_HANDLER.get().copied().unwrap_or(default_die_handler)
}

/// Print it. The C's `default_die_handler`, which was `printk("%s\n", msg)`.
///
/// # Safety
/// `msg` is NUL-terminated.
unsafe extern "C" fn default_die_handler(msg: *const std::ffi::c_char) {
    if msg.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    let bytes = unsafe { std::ffi::CStr::from_ptr(msg) }.to_bytes();
    let _held = OUTPUT.lock().unwrap_or_else(|e| e.into_inner());
    output_line(bytes);
}

/// Last words, then `abort`.
///
/// The Rust counterpart of `die`, so a caller with a `String` does not go
/// through a varargs formatter to deliver it. `crates/kernel/taskcalls` had its
/// own copy, whose comment records why the C form is awkward: `die`'s first
/// parameter is a *format* string, so a message with a `%` in it reads
/// arguments that are not there, and every caller had to remember to pass its
/// message as an argument to `"%s"` instead.
///
/// An interior NUL is replaced rather than dropped — the handler takes a C
/// string, so it cannot be passed through, and a last message with a `?` in it
/// is still the last message. `crates/kernel/taskcalls` dropped it and
/// aborted silently.
pub fn die(msg: &str) -> ! {
    let owned;
    let text = if msg.contains('\0') {
        owned = msg.replace('\0', "?");
        owned.as_str()
    } else {
        msg
    };
    if let Ok(c) = std::ffi::CString::new(text) {
        // SAFETY: a NUL-terminated string that outlives the call, which is
        // the handler's contract.
        unsafe { die_handler()(c.as_ptr()) };
    }
    std::process::abort()
}
