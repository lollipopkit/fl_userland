//! `libfakefs_redirect.dylib`: making a guest absolute path reach the guest's
//! file inside a **host** process.
//!
//! Native offload runs a registered program — `ffmpeg`, `ffprobe` — as a host
//! binary rather than emulating it, and that process asks the *host* for
//! `/tmp/in.mp4`. This library is injected with `DYLD_INSERT_LIBRARIES` and
//! interposes the filesystem calls, rewriting an absolute guest path to the
//! fakefs data directory named in `FAKEFS_ROOT`.
//!
//! **Nothing built it until 2026-09-01.** `crates/kernel/offloadexec` looks for
//! it beside the `iul` binary; not finding one it warned and carried on with
//! redirection off, which is every run this tree had ever done — so an
//! offloaded `ffmpeg` asked to read `/tmp/in.mp4` read the host's `/tmp`.
//!
//! macOS only, and by construction: `__DATA,__interpose` is a Mach-O section and
//! `DYLD_INSERT_LIBRARIES` is dyld's.
//!
//! # The two variadic calls, which were C until 2026-09-06
//!
//! `open` and `openat` take `mode` only with `O_CREAT`, and stable Rust still
//! cannot *define* a variadic `extern "C" fn`. That was the whole of
//! `kernel/libfakefs_redirect.c`, and the reason it gave was real: on Apple
//! aarch64 a variadic argument is on the stack where a named one is in a
//! register, so a non-variadic replacement of the same arity reads `mode` from
//! `x2` and every `O_CREAT` open gets whatever was there.
//!
//! What that reason does not cover is that **the variadic part is four
//! instructions**. A `global_asm!` trampoline loads the first stack slot into
//! the next free register and tail-calls a non-variadic Rust function, and the
//! ABI knowledge involved stops there. See the `abi` test module, which
//! assembles the same four instructions against a recording function and calls
//! them through a variadic declaration — Rust may *declare* one.
//!
//! # It is a staticlib, and it is the second one
//!
//! `CLAUDE.md` says not to add one. The reason that rule exists is that two
//! Rust staticlibs in **one link** are two copies of the standard library,
//! whose symbols are strong globals under the release profile's LTO. This is
//! linked into `libfakefs_redirect.dylib` and nothing else, and `libiul.a` is
//! still the only staticlib in the product.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::OnceLock;

/// Where the guest's files are on the host, from `FAKEFS_ROOT`.
///
/// Read on first use rather than from a constructor. A `__mod_init_func` entry
/// emitted from a static library is a linker behaviour — `util/ish_env.c` keeps
/// its constructor in C for exactly that reason — and there is nothing here
/// that needs to happen before the first interposed call.
fn root() -> Option<&'static [u8]> {
    static ROOT: OnceLock<Option<Vec<u8>>> = OnceLock::new();
    ROOT.get_or_init(|| {
        let v = std::env::var_os("FAKEFS_ROOT")?;
        let mut b = std::os::unix::ffi::OsStrExt::as_bytes(v.as_os_str()).to_vec();
        // A trailing slash would give a doubled one in every rewritten path.
        while b.len() > 1 && b.last() == Some(&b'/') {
            b.pop();
        }
        (!b.is_empty()).then_some(b)
    })
    .as_deref()
}

/// Host-only paths a native binary needs, which must not be redirected.
///
/// Each ends in `/`, so `/dev/` does not match `/device`. That is the rule the
/// C had and it is worth keeping written down: a prefix without the separator
/// is the shape that made a mount cache answer for `/devfoo`.
const PASSTHROUGH: &[&[u8]] = &[
    b"/dev/",
    b"/opt/",
    b"/usr/local/",
    b"/usr/lib/",
    b"/usr/share/",
    b"/System/",
    b"/Library/",
    b"/Applications/",
    b"/private/",
    b"/Users/",
    b"/cores/",
    b"/AppleInternal/",
    // `/usr/bin` and `/usr/sbin` but **not** `/usr`: a guest has its own
    // `/usr/share`, and a host binary needs the host's tools.
    b"/usr/bin/",
    b"/usr/sbin/",
];

/// What to do with a path.
#[derive(Debug, PartialEq, Eq)]
pub enum Redirect {
    /// Use it as it is: relative, host-only, or already under the root.
    Keep,
    /// Use this instead.
    To(Vec<u8>),
    /// It cannot be expressed. **Not** "use the original": that would hand the
    /// host's file at that path to a program that asked for the guest's, which
    /// is the whole thing this library exists to prevent. The C returned the
    /// original here.
    TooLong,
}

/// The longest host path this can build. macOS's `PATH_MAX`.
pub const PATH_MAX: usize = 1024;

/// Where a guest path goes.
pub(crate) fn redirect_path(path: &[u8], root: Option<&[u8]>) -> Redirect {
    let Some(root) = root else {
        return Redirect::Keep;
    };
    if !path.starts_with(b"/") {
        return Redirect::Keep;
    }
    // Already under the root. **On a component boundary**: the C compared
    // `root.len()` bytes and stopped, so a root of `/tmp/iul-dev-a` claimed
    // `/tmp/iul-dev-abc` too — the same defect the mount table had, where a
    // prefix that does not end on a `/` is not a parent.
    if path.starts_with(root) && matches!(path.get(root.len()), None | Some(b'/')) {
        return Redirect::Keep;
    }
    if PASSTHROUGH.iter().any(|p| path.starts_with(p)) {
        return Redirect::Keep;
    }
    // Room for the root, the path and the NUL the caller appends.
    if root.len() + path.len() + 1 > PATH_MAX {
        return Redirect::TooLong;
    }
    let mut out = Vec::with_capacity(root.len() + path.len() + 1);
    out.extend_from_slice(root);
    out.extend_from_slice(path);
    Redirect::To(out)
}

/// The path to pass on, as a C string, or `None` for `ENAMETOOLONG`.
///
/// `owned` holds a rewritten path for as long as the caller uses it.
///
/// # Safety
/// `path` is NUL-terminated or null.
unsafe fn resolve(path: *const c_char, owned: &mut Vec<u8>) -> Option<*const c_char> {
    if path.is_null() {
        return Some(path);
    }
    // SAFETY: the caller's contract.
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    match redirect_path(bytes, root()) {
        Redirect::Keep => Some(path),
        Redirect::To(mut v) => {
            v.push(0);
            *owned = v;
            Some(owned.as_ptr().cast())
        }
        Redirect::TooLong => None,
    }
}

/// `errno = ENAMETOOLONG`, for a path that cannot be rewritten.
fn too_long<T>(answer: T) -> T {
    // SAFETY: `__error()` is libc's per-thread errno slot.
    unsafe { *libc::__error() = libc::ENAMETOOLONG };
    answer
}

// ---------------------------------------------------------------------------
// The interpose table
// ---------------------------------------------------------------------------

/// One `__DATA,__interpose` entry: the replacement and what it replaces.
///
/// dyld patches the global offset table, so every call from the target binary
/// goes through the replacement — which is cleaner than `dlsym(RTLD_NEXT)`,
/// because it needs no lookup on the call path and cannot recurse.
#[repr(C)]
pub struct Interpose {
    replacement: *const c_void,
    replacee: *const c_void,
}

// SAFETY: two function addresses, written once by the linker and never
// modified. `Sync` is what a `static` of them needs.
unsafe impl Sync for Interpose {}

/// `interpose!(my_unlink => unlink)`: the entry, and nothing else.
///
/// The section name carries a third field — `interposing` is the section
/// *type*, which is what makes dyld read it.
///
/// **Every replacement must be `extern "C"`, and this macro cannot check it.**
/// `$replacement as *const c_void` erases the calling convention, so a
/// replacement written with the Rust ABI compiles, links and is loaded — and
/// is called by dyld on the target binary's behalf with the C one. The
/// `wrap!` macro below writes the attribute for the thirteen it generates;
/// `my_rename` and `my_faccessat` are hand-written and it is theirs to carry.
/// The 2026-09-11 sweep that took `extern "C"` off 200 Rust-only functions
/// stripped both, and the whole workspace still compiled and tested clean.
macro_rules! interpose {
    ($replacement:path => $replacee:path, $name:ident) => {
        #[used]
        #[unsafe(link_section = "__DATA,__interpose,interposing")]
        static $name: Interpose = Interpose {
            replacement: $replacement as *const c_void,
            replacee: $replacee as *const c_void,
        };
    };
}

/// One interposed call over a single path.
///
/// The shape is always the same: rewrite, or answer `ENAMETOOLONG` without
/// calling anything. Writing it out sixteen times is what the C did, and each
/// copy was one line away from silently passing the host's path through.
macro_rules! wrap {
    (
        $(#[$meta:meta])*
        fn $name:ident ( $path:ident $(, $arg:ident : $ty:ty)* ) -> $ret:ty
            = $real:path, $fail:expr
    ) => {
        $(#[$meta])*
        unsafe extern "C" fn $name(path: *const c_char $(, $arg: $ty)*) -> $ret {
            let mut owned = Vec::new();
            // SAFETY: dyld calls this with the target's own arguments.
            let Some($path) = (unsafe { resolve(path, &mut owned) }) else {
                return too_long($fail);
            };
            unsafe { $real($path $(, $arg)*) }
        }
    };
}

wrap!(fn my_stat(p, sb: *mut libc::stat) -> c_int = libc::stat, -1);
wrap!(fn my_lstat(p, sb: *mut libc::stat) -> c_int = libc::lstat, -1);
wrap!(fn my_access(p, mode: c_int) -> c_int = libc::access, -1);
wrap!(fn my_opendir(p) -> *mut libc::DIR = libc::opendir, std::ptr::null_mut());
wrap!(fn my_unlink(p) -> c_int = libc::unlink, -1);
wrap!(fn my_mkdir(p, mode: libc::mode_t) -> c_int = libc::mkdir, -1);
wrap!(fn my_rmdir(p) -> c_int = libc::rmdir, -1);
wrap!(fn my_chdir(p) -> c_int = libc::chdir, -1);
wrap!(fn my_truncate(p, len: libc::off_t) -> c_int = libc::truncate, -1);
wrap!(fn my_chmod(p, mode: libc::mode_t) -> c_int = libc::chmod, -1);
wrap!(fn my_fopen(p, mode: *const c_char) -> *mut libc::FILE = libc::fopen, std::ptr::null_mut());
wrap!(fn my_realpath(p, resolved: *mut c_char) -> *mut c_char
    = libc::realpath, std::ptr::null_mut());
wrap!(fn my_readlink(p, buf: *mut c_char, sz: libc::size_t) -> libc::ssize_t
    = libc::readlink, -1);

interpose!(my_stat => libc::stat, I_STAT);
interpose!(my_lstat => libc::lstat, I_LSTAT);
interpose!(my_access => libc::access, I_ACCESS);
interpose!(my_opendir => libc::opendir, I_OPENDIR);
interpose!(my_unlink => libc::unlink, I_UNLINK);
interpose!(my_mkdir => libc::mkdir, I_MKDIR);
interpose!(my_rmdir => libc::rmdir, I_RMDIR);
interpose!(my_chdir => libc::chdir, I_CHDIR);
interpose!(my_truncate => libc::truncate, I_TRUNCATE);
interpose!(my_chmod => libc::chmod, I_CHMOD);
interpose!(my_fopen => libc::fopen, I_FOPEN);
interpose!(my_realpath => libc::realpath, I_REALPATH);
interpose!(my_readlink => libc::readlink, I_READLINK);

/// `rename` takes two paths, so it is the one that does not fit [`wrap!`].
unsafe extern "C" fn my_rename(old: *const c_char, new: *const c_char) -> c_int {
    let (mut a, mut b) = (Vec::new(), Vec::new());
    // SAFETY: dyld calls this with the target's own arguments.
    let (Some(old), Some(new)) = (unsafe { resolve(old, &mut a) }, unsafe {
        resolve(new, &mut b)
    }) else {
        return too_long(-1);
    };
    unsafe { libc::rename(old, new) }
}
interpose!(my_rename => libc::rename, I_RENAME);

/// `faccessat` redirects only for `AT_FDCWD`: with a real directory descriptor
/// the path is relative to it and is not a guest absolute path at all.
unsafe extern "C" fn my_faccessat(
    fd: c_int,
    path: *const c_char,
    mode: c_int,
    flag: c_int,
) -> c_int {
    let mut owned = Vec::new();
    let path = if fd == libc::AT_FDCWD {
        // SAFETY: dyld calls this with the target's own arguments.
        match unsafe { resolve(path, &mut owned) } {
            Some(p) => p,
            None => return too_long(-1),
        }
    } else {
        path
    };
    unsafe { libc::faccessat(fd, path, mode, flag) }
}
interpose!(my_faccessat => libc::faccessat, I_FACCESSAT);

// ---------------------------------------------------------------------------
// The two variadic calls
// ---------------------------------------------------------------------------

// `open` and `openat` take `mode` only with `O_CREAT`, and stable Rust cannot
// *define* a variadic `extern "C" fn`. That is still true; what changed on
// 2026-09-06 is that it stopped mattering, because **the variadic part is four
// instructions and this tree already permits assembly**.
//
// On Apple aarch64 the named arguments are in registers and every variadic one
// is on the stack, starting at the entry `sp`. So a trampoline that loads the
// first stack slot into the next free register and tail-calls a *non*-variadic
// Rust function is the whole of the ABI knowledge involved. Measured rather
// than read: `clang -O0` on the C this replaces sets its `va_list` to
// `x29 + 0x10`, which is the entry `sp`, then reads four bytes (`ldr w8`) and
// advances by eight — so the slot is 8 bytes wide and the value in it is 4.
//
// **The load is unconditional and the `O_CREAT` test is in Rust.** Reading the
// slot when the caller passed no mode is safe — `[sp]` is inside the caller's
// own frame — but the value is whatever was there, so it must not be used. The
// alternative, testing `O_CREAT` in the trampoline, would put `0x200` in
// assembly where nothing checks it against `fcntl.h`. The test below is what
// says the register lands where the Rust side expects it.

#[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
compile_error!("the open/openat trampolines encode the Apple aarch64 variadic ABI");

core::arch::global_asm!(
    // open(path: x0, flags: w1, ...) -> my_open_impl(path, flags, mode: w2)
    ".globl _fakefs_open_tramp",
    ".p2align 2",
    "_fakefs_open_tramp:",
    "    ldr  w2, [sp]",
    "    b    {open_impl}",
    // openat(fd: w0, path: x1, flags: w2, ...) -> my_openat_impl(.., mode: w3)
    ".globl _fakefs_openat_tramp",
    ".p2align 2",
    "_fakefs_openat_tramp:",
    "    ldr  w3, [sp]",
    "    b    {openat_impl}",
    open_impl = sym my_open_impl,
    openat_impl = sym my_openat_impl,
);

unsafe extern "C" {
    /// The variadic entry dyld sees for `open`; [`my_open_impl`] does the work.
    fn fakefs_open_tramp();
    /// The variadic entry dyld sees for `openat`.
    fn fakefs_openat_tramp();
}

/// `mode` is meaningful only with `O_CREAT`; see the trampoline above.
fn mode_for(flags: c_int, raw: c_int) -> libc::mode_t {
    if flags & libc::O_CREAT != 0 {
        raw as libc::mode_t
    } else {
        0
    }
}

/// # Safety
/// Reached only through `fakefs_open_tramp`, which supplies `mode`.
unsafe extern "C" fn my_open_impl(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    let mut owned = Vec::new();
    // SAFETY: dyld calls this with the target's own arguments.
    let Some(path) = (unsafe { resolve(path, &mut owned) }) else {
        return too_long(-1);
    };
    unsafe { libc::open(path, flags, mode_for(flags, mode) as c_int) }
}

/// Only for `AT_FDCWD`: with a real directory descriptor the path is relative
/// to it and is not a guest absolute path at all.
///
/// # Safety
/// Reached only through `fakefs_openat_tramp`, which supplies `mode`.
unsafe extern "C" fn my_openat_impl(
    fd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    let mut owned = Vec::new();
    let path = if fd == libc::AT_FDCWD {
        // SAFETY: dyld calls this with the target's own arguments.
        match unsafe { resolve(path, &mut owned) } {
            Some(p) => p,
            None => return too_long(-1),
        }
    } else {
        path
    };
    unsafe { libc::openat(fd, path, flags, mode_for(flags, mode) as c_int) }
}

interpose!(fakefs_open_tramp => libc::open, I_OPEN);
interpose!(fakefs_openat_tramp => libc::openat, I_OPENAT);

#[cfg(test)]
mod tests;
