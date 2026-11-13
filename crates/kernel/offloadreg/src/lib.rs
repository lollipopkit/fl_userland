//! Which guest programs run natively instead of being emulated.
//!
//! `iul -n ffmpeg` says that an `execve` of anything whose basename is `ffmpeg`
//! should run the host's binary; `iul -n ffprobe=/usr/local/bin/ffprobe` says
//! which one. An embedder can also register an **in-process handler** — a
//! function called on the guest thread with a translated `argv` and pipe-backed
//! stdio.
//!
//! This is the registry: the spec parsing, the list, and the basename lookup an
//! `execve` does. Everything around it — `posix_spawn`, the path translation,
//! the pipe forwarding — stays in `kernel/native_offload.c`, which is macOS-only
//! and reaches `current`.
//!
//! # Each entry is leaked, and that is the point
//!
//! `struct task` holds a pointer to the entry a thread is currently running, so
//! that a signal can reach the handler's abort callback while it is in flight. A
//! `Vec<Entry>` would move its elements on the next registration and leave that
//! pointer dangling — which the C's fixed array of 32 could not do. Each entry
//! is `Box::leak`ed, so its address is stable for the life of the process, and
//! the `Vec` holds pointers.
//!
//! It also removes the fixed 32: registration answered `-1` past it, which an
//! embedder registering per-feature handlers could reach.
//!
//! # The lock
//!
//! Registration happens at startup today — `main.c`'s `-n`, and constructors in
//! `kernel/offload_tests/` — so the unsynchronised array the C had was very
//! probably never raced. It is under a `Mutex` here because an embedder
//! registering a handler after the guest has started is a supported thing to do
//! and the lookup is once per `execve`, where a mutex costs nothing. This is not
//! a bug report: nothing was observed.


use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::Mutex;

/// A handler called on the guest thread. `kernel/native_offload.h`.
pub type HandlerFn = extern "C" fn(
    argc: c_int,
    argv: *mut *mut c_char,
    stdin_fd: c_int,
    stdout_fd: c_int,
    stderr_fd: c_int,
) -> c_int;

/// Asks a wedged in-process handler to stop waiting. Answers whether it will.
pub type AbortFn = extern "C" fn(c_int) -> bool;

/// One registration.
#[repr(C)]
pub struct Entry {
    /// The basename an `execve` is matched against.
    guest_name: CString,
    /// The host binary, or `None` for a handler.
    native_path: Option<CString>,
    handler: Option<HandlerFn>,
    /// Optional, and separate from registration so that an offload without one
    /// keeps the pre-existing "cannot be interrupted" behaviour.
    ///
    /// **Behind a lock since 2026-09-30.** It is set after the entry is
    /// published and read by a signalling thread through a `&'static Entry`,
    /// and it was a plain field written through the registry's
    /// `&'static mut` -- a `&mut` and a `&` to one object at once, which is
    /// undefined whether or not the two ever landed together.
    abort_fn: Mutex<Option<AbortFn>>,
}

impl Entry {
    /// The in-process handler, if this registration is one.
    pub fn handler(&self) -> Option<HandlerFn> {
        self.handler
    }

    /// What to call when a signal should stop a handler that is in flight.
    pub fn abort(&self) -> Option<AbortFn> {
        *self.abort_fn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The basename an `execve` is matched against.
    pub fn name(&self) -> &CStr {
        &self.guest_name
    }

    /// The host binary, or `None` for a handler.
    pub fn native_path(&self) -> Option<&CStr> {
        self.native_path.as_deref()
    }
}

/// The entry for a guest path, matched on its basename.
///
/// The reference is `'static` because entries are leaked: `struct task` holds
/// one while a handler is in flight, so the address has to outlive the task.
pub fn find(guest_path: &[u8]) -> Option<&'static Entry> {
    let base = basename(guest_path);
    with(|reg| reg.iter().copied().find(|e| e.guest_name.to_bytes() == base))
}

/// Leaked entries, so that a pointer handed to `struct task` stays valid.
///
/// Shared references: nothing mutates an entry except through the lock inside
/// it. It held `&'static mut` until 2026-09-30, so `find` had to launder one
/// into a `&'static` through a raw pointer.
static REGISTRY: Mutex<Vec<&'static Entry>> = Mutex::new(Vec::new());

/// The sentinel `native_offload_lookup` answers for a handler-only entry: the
/// caller only needs to know that this name is offloaded, and then asks again
/// for the handler.
const BUILTIN: &CStr = c"[builtin]";

fn with<T>(f: impl FnOnce(&mut Vec<&'static Entry>) -> T) -> T {
    f(&mut REGISTRY.lock().unwrap_or_else(|e| e.into_inner()))
}

/// The part of a path after the last `/`.
///
/// A registration names a program, and an `execve` names a path — `/usr/bin/ffmpeg`
/// and `ffmpeg` are the same program.
pub fn basename(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// What a `-n` spec asks for: a name, and optionally the host path to use.
///
/// `name=path` gives both; `name` alone means the host `PATH` is searched.
pub(crate) fn parse_spec(spec: &[u8]) -> (&[u8], Option<&[u8]>) {
    match spec.iter().position(|&b| b == b'=') {
        Some(i) => (&spec[..i], Some(&spec[i + 1..])),
        None => (spec, None),
    }
}

/// Where a host binary is looked for when the spec does not say.
pub const SEARCH_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"];

/// The first of [`SEARCH_DIRS`] that holds an executable called `name`.
///
/// A name that does not fit a `PATH_MAX` buffer is skipped rather than
/// truncated — a truncated path is not a shorter name, it is a different one,
/// and this one is then `exec`ed. In Rust the join cannot truncate at all; what
/// is kept is the *length* rule, because the host's `access` still has one.
fn find_in_search_dirs(name: &str) -> Option<CString> {
    for dir in SEARCH_DIRS {
        let path = format!("{dir}/{name}");
        if path.len() >= libc::PATH_MAX as usize {
            continue;
        }
        let Ok(c) = CString::new(path) else { continue };
        if is_executable(&c) {
            return Some(c);
        }
    }
    None
}

fn is_executable(path: &CStr) -> bool {
    rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
}

/// Register `spec`. 0, or -1 with a reason on stderr.
pub fn offload_add(spec: &CStr) -> c_int {
    let spec = spec.to_bytes();
    let (name, path) = parse_spec(spec);
    let Ok(name) = CString::new(name) else {
        return -1;
    };

    let native_path = match path {
        Some(p) => {
            let Ok(p) = CString::new(p) else { return -1 };
            if !is_executable(&p) {
                eprintln!(
                    "native_offload: {}: not found or not executable",
                    p.to_string_lossy()
                );
                return -1;
            }
            p
        }
        None => {
            let Some(found) = name.to_str().ok().and_then(find_in_search_dirs) else {
                eprintln!(
                    "native_offload: {}: not found in host PATH",
                    name.to_string_lossy()
                );
                return -1;
            };
            found
        }
    };

    eprintln!(
        "native_offload: {} \u{2192} {}",
        name.to_string_lossy(),
        native_path.to_string_lossy()
    );
    push(Entry {
        guest_name: name,
        native_path: Some(native_path),
        handler: None,
        abort_fn: Mutex::new(None),
    });
    0
}

/// Register an in-process handler for `guest_name`.
pub fn offload_add_handler(guest_name: &CStr, handler: HandlerFn) -> c_int {
    let name = guest_name.to_owned();
    eprintln!(
        "native_offload: {} \u{2192} [builtin]",
        name.to_string_lossy()
    );
    push(Entry {
        guest_name: name,
        native_path: None,
        handler: Some(handler),
        abort_fn: Mutex::new(None),
    });
    0
}

fn push(e: Entry) {
    with(|r| r.push(Box::leak(Box::new(e))));
}

/// Attach an abort callback to a registered in-process handler.
///
/// `-1` for a name that is not registered, and for one registered as a host
/// binary — signals to those already go through `kill`.
///
pub fn offload_set_abort_handler(name: &CStr, abort_fn: AbortFn) -> c_int {
    with(|r| {
        for e in r.iter() {
            if e.guest_name.as_c_str() != name {
                continue;
            }
            if e.handler.is_none() {
                return -1;
            }
            *e.abort_fn.lock().unwrap_or_else(|p| p.into_inner()) = Some(abort_fn);
            eprintln!(
                "native_offload: {} abort handler registered",
                name.to_string_lossy()
            );
            return 0;
        }
        -1
    })
}

/// The host binary for this path, `[builtin]` for a handler, or `None` for a
/// name that is not registered.
pub fn offload_lookup(guest_path: &CStr) -> Option<&'static CStr> {
    let e = find(guest_path.to_bytes())?;
    Some(e.native_path().unwrap_or(BUILTIN))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A registration names a program and an `execve` names a path.
    #[test]
    fn a_lookup_matches_the_basename() {
        assert_eq!(basename(b"/usr/bin/ffmpeg"), b"ffmpeg");
        assert_eq!(basename(b"ffmpeg"), b"ffmpeg");
        assert_eq!(basename(b"/ffmpeg"), b"ffmpeg");
        assert_eq!(basename(b"./ffmpeg"), b"ffmpeg");
        // A trailing slash leaves nothing, which matches no registration --
        // and `execve("/usr/bin/")` is EACCES before it gets here anyway.
        assert_eq!(basename(b"/usr/bin/"), b"");
        assert_eq!(basename(b""), b"");
    }

    /// `name` and `name=path`, and the first `=` is the separator: a host path
    /// may contain one.
    #[test]
    fn a_spec_splits_at_the_first_equals() {
        assert_eq!(parse_spec(b"ffmpeg"), (&b"ffmpeg"[..], None));
        assert_eq!(
            parse_spec(b"ffprobe=/usr/local/bin/ffprobe"),
            (&b"ffprobe"[..], Some(&b"/usr/local/bin/ffprobe"[..]))
        );
        assert_eq!(
            parse_spec(b"x=/opt/a=b/x"),
            (&b"x"[..], Some(&b"/opt/a=b/x"[..]))
        );
        // A spec that is only an `=` asks for an empty name, which matches
        // nothing -- and is not the same as no `=` at all.
        assert_eq!(parse_spec(b"=path"), (&b""[..], Some(&b"path"[..])));
        assert_eq!(parse_spec(b"name="), (&b"name"[..], Some(&b""[..])));
    }

    /// The search order is fixed and Homebrew comes first, which is what makes
    /// `-n ffmpeg` find the one a developer installed rather than an older
    /// system copy.
    #[test]
    fn the_search_order_prefers_homebrew() {
        assert_eq!(SEARCH_DIRS[0], "/opt/homebrew/bin");
        assert_eq!(SEARCH_DIRS.len(), 4);
        assert!(SEARCH_DIRS.iter().all(|d| d.starts_with('/')));
    }

    /// A name nothing has is not found, and `/bin/sh` is — the one binary every
    /// machine this runs on has in one of the four directories.
    #[test]
    fn the_search_finds_what_is_there_and_not_what_is_not() {
        assert!(find_in_search_dirs("sh").is_some());
        assert!(find_in_search_dirs("no-such-program-9f3a").is_none());
        // A name long enough to overflow PATH_MAX is skipped rather than
        // truncated: a truncated path is a *different* program, and it would
        // then be exec'd.
        assert!(find_in_search_dirs(&"x".repeat(libc::PATH_MAX as usize)).is_none());
    }

    /// Registering a handler and finding it. The entry's address is what
    /// `struct task` holds while the handler runs, so it has to survive the
    /// registrations that follow it.
    #[test]
    fn an_entrys_address_survives_later_registrations() {
        extern "C" fn h(_: c_int, _: *mut *mut c_char, _: c_int, _: c_int, _: c_int) -> c_int {
            0
        }
        let name = c"test-offload-stable";
        assert_eq!(offload_add_handler(name, h), 0);
        let first: *const Entry = find(name.to_bytes()).expect("just registered");

        for i in 0..64 {
            let other = CString::new(format!("test-offload-filler-{i}")).unwrap();
            assert_eq!(offload_add_handler(&other, h), 0);
        }
        let again = find(name.to_bytes()).expect("still registered");
        assert!(std::ptr::eq(again, first));
        assert!(again.handler().is_some());
        // A handler-only entry answers the sentinel rather than a path.
        assert_eq!(offload_lookup(name), Some(BUILTIN));
    }

    /// An abort callback attaches to a handler and not to a host binary, and
    /// not at all to a name nothing registered.
    #[test]
    fn an_abort_callback_needs_a_handler() {
        extern "C" fn h(_: c_int, _: *mut *mut c_char, _: c_int, _: c_int, _: c_int) -> c_int {
            0
        }
        extern "C" fn a(_: c_int) -> bool {
            true
        }
        let name = c"test-offload-abort";
        assert_eq!(offload_add_handler(name, h), 0);
        assert_eq!(offload_set_abort_handler(name, a), 0);
        assert!(find(name.to_bytes()).and_then(Entry::abort).is_some());

        assert_eq!(
            offload_set_abort_handler(c"test-offload-absent", a),
            -1,
            "a name nothing registered"
        );
    }

    /// A lookup of something nobody registered answers nothing rather than
    /// the first entry.
    #[test]
    fn an_unregistered_name_is_not_found() {
        assert!(find(b"test-offload-nothing").is_none());
        assert!(offload_lookup(c"test-offload-nothing").is_none());
    }

    /// A spec naming a path that is not executable is refused, which is what
    /// stops `-n x=/etc/passwd` becoming an exec of it.
    #[test]
    fn a_spec_naming_something_unexecutable_is_refused() {
        assert_eq!(offload_add(c"test-offload-bad=/etc/hosts"), -1);
        assert!(find(b"test-offload-bad").is_none());

        assert_eq!(offload_add(c"test-offload-missing=/no/such/binary/at/all"), -1);
    }
}
