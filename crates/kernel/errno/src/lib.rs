//! Host errno to guest errno.
//!
//! A syscall reports failure by returning a small negative number, and a guest
//! libc decides whether one is an error by its range: musl's `__syscall_ret`
//! reads an unsigned return above `-4096` as `-errno` and anything else as a
//! successful result. So the one property this table must have is not that any
//! particular errno maps to any particular other one — it is that **every**
//! input produces something inside `[-4095, -1]`.
//!
//! The C this replaces did not have that property. Its fallback for an errno
//! not in the table was `-(err | 0x1000)`, which is `-4096` or below for every
//! input that could reach it, so an unrecognised host errno arrived in the
//! guest as a large negative *success*, and the caller used it as a length, a
//! descriptor or a pointer. 64 of the first 140 host errnos took that path.
//!
//! The numbers on the guest side are asm-generic's, which is what aarch64
//! Linux uses. They are stored negative, and they are `crates/util/errno`'s --
//! this crate re-exports them as [`guest`] and does not own them.

use std::ffi::c_int;

mod mapping;
#[cfg(test)]
pub(crate) use mapping::darwin;
pub use mapping::{Mapped, guest, map};

// ---------------------------------------------------------------------------
// The two callers reach it through
// ---------------------------------------------------------------------------

/// Raise `SIGPIPE` at the calling thread, installed by
/// `crates/kernel/boot`'s `become_first_process` before any guest can run.
///
/// # Why a hook
///
/// This crate is a leaf: every syscall family calls [`errno_map`], so it must
/// depend on nothing. Delivering a signal is `crates/kernel/signaldeliver`'s,
/// which depends on the dispatcher, which depends on the page table, which
/// depends on this — a cycle, and one that stayed invisible for as long as the
/// call went through a hand-written `unsafe extern "C"` block.
///
/// **If it is never installed, a write to a closed pipe answers `EPIPE` and
/// raises nothing**, and `yes | head` in the guest does not terminate. The
/// smoke gate is what would notice.
static RAISE_SIGPIPE: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Install it. The first call wins.
pub fn set_sigpipe_hook(f: fn()) {
    let _ = RAISE_SIGPIPE.set(f);
}

/// The guest errno for a failed host call, translated, and — for `EPIPE` — the
/// `SIGPIPE` that goes with it.
///
/// **The signal is the reason this is not just [`map`].** A write to a closed
/// pipe or socket must raise `SIGPIPE` at the writer as well as answering
/// `EPIPE`, and every caller in the tree gets that by calling this rather than
/// remembering to do it.
pub fn errno_map() -> c_int {
    raised(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// [`errno_map`] for an errno already in hand -- what a `rustix` or
/// `std::io` error carries -- with the same `SIGPIPE`.
pub fn raised(host: c_int) -> c_int {
    if host == libc::EPIPE {
        raise_sigpipe();
    }
    err_map(host)
}

/// The `SIGPIPE` a write that answered `EPIPE` owes the calling thread, unless
/// the call asked for none (a [`NoSigpipe`] is alive on this thread).
///
/// Every place that raises it comes through here -- a host `EPIPE` through
/// [`raised`], and `crates/fs/pipecalls` for the pipes this kernel implements
/// itself -- so one flag on the call covers a pipe, a socket and a FIFO alike.
pub fn raise_sigpipe() {
    if !QUIET.get()
        && let Some(raise) = RAISE_SIGPIPE.get()
    {
        raise();
    }
}

thread_local! {
    static QUIET: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `RWF_NOSIGNAL`'s `IOCB_NOSIGNAL`: while this is alive, a write on this
/// thread that answers `EPIPE` raises no `SIGPIPE`.
///
/// A flag on the thread rather than an argument because the signal is raised
/// below `FdOps::write`, which a flags word does not reach -- and a syscall
/// runs to completion on its task's own thread, so the scope is exactly the
/// call. Nested scopes restore what they found.
pub struct NoSigpipe {
    was: bool,
}

impl NoSigpipe {
    pub fn new() -> NoSigpipe {
        NoSigpipe { was: QUIET.replace(true) }
    }
}

impl Default for NoSigpipe {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NoSigpipe {
    fn drop(&mut self) {
        QUIET.set(self.was);
    }
}

/// The same translation without the signal, for a caller that has an errno in
/// hand rather than in `errno`.
///
/// The unknown case is reported, because it is the one that used to be
/// silently wrong: the table was a `switch` whose default was
/// `-(err | 0x1000)`, which is -4096 or below for every input that reached it,
/// and a guest libc reads a syscall return below -4095 as a **success**. Sixty
/// four of the first 140 host errnos took that path.
pub fn err_map(host: c_int) -> c_int {
    let m = map(host);
    if m.known == 0 {
        eprintln!("unknown host errno {host}, reporting EIO");
    }
    m.guest
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RWF_NOSIGNAL`'s scope silences the hook on this thread, for as long as
    /// it lives and no longer. The only test in this binary that installs it.
    #[test]
    fn no_sigpipe_silences_the_hook_for_its_scope() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static RAISED: AtomicU32 = AtomicU32::new(0);
        set_sigpipe_hook(|| {
            RAISED.fetch_add(1, Ordering::SeqCst);
        });
        raised(libc::EPIPE);
        assert_eq!(RAISED.load(Ordering::SeqCst), 1);
        {
            let _quiet = NoSigpipe::new();
            raised(libc::EPIPE);
            {
                let _inner = NoSigpipe::new();
                raise_sigpipe();
            }
            raise_sigpipe();
            assert_eq!(RAISED.load(Ordering::SeqCst), 1, "raised inside the scope");
        }
        raise_sigpipe();
        assert_eq!(RAISED.load(Ordering::SeqCst), 2, "still quiet after the scope");
    }

    /// What a guest libc will accept as an error.
    fn is_a_guest_errno(r: c_int) -> bool {
        (-4095..=-1).contains(&r)
    }

    /// The property the whole table exists for.
    ///
    /// Not a sample: every input, including ones no host defines. The old
    /// fallback failed this for 64 of the first 140, and the reason it was
    /// never noticed is that nothing had ever asked.
    #[test]
    fn every_input_maps_to_a_guest_errno() {
        for host in -10_000..=10_000 {
            let m = map(host);
            assert!(
                is_a_guest_errno(m.guest),
                "map({host}) = {}, which a guest libc reads as success",
                m.guest
            );
        }
    }

    #[test]
    fn the_fallback_is_reported_as_unknown() {
        // So the caller can log it. A silent fallback would turn a missing
        // entry into a wrong error nobody ever hears about.
        let m = map(9999);
        assert_eq!(m.known, 0);
        assert_eq!(m.guest, guest::EIO);
        assert_eq!(map(libc::EPERM).known, 1);
    }

    /// The C ABI wrapper answers the `guest` field and not the `known` one.
    ///
    /// `tests/unit/errno_test.c` was this file's test until 2026-09-08 and
    /// went through `err_map` for all three of its checks. Everything else it
    /// asked is covered above and more widely -- it swept host errnos 1 to 140
    /// where `every_input_maps_to_a_guest_errno` sweeps -10000 to 10000 -- so
    /// what is left of it is the one line the wrapper can get wrong.
    #[test]
    fn the_c_abi_wrapper_answers_the_guest_errno() {
        for host in [
            libc::EPERM,
            libc::ENOENT,
            libc::EAGAIN,
            libc::ENOSYS,
            libc::ELOOP,
        ] {
            assert_eq!(err_map(host), map(host).guest);
        }
        // And an input no host defines still lands in range, which is what a
        // guest libc reads as an error rather than a success.
        assert!(is_a_guest_errno(err_map(9999)));
    }

    #[test]
    fn the_numbering_is_linux_and_not_the_host() {
        // These differ between Darwin and Linux, so a table that passed the
        // host value through would fail here.
        assert_eq!(map(libc::ENOTEMPTY).guest, -39);
        assert_eq!(map(libc::ELOOP).guest, -40);
        assert_eq!(map(libc::EOVERFLOW).guest, -75);
        assert_eq!(map(libc::ECANCELED).guest, -125);
        assert_eq!(map(libc::EPERM).guest, -1);
    }

    /// Every errno the host defines must be recognised, not merely in range.
    ///
    /// The range property alone is satisfied by a table of nothing but the
    /// fallback. This is what makes it mean something.
    #[test]
    fn every_errno_the_host_defines_is_known() {
        let mut unknown = Vec::new();
        for host in 1..=libc::ELAST {
            if map(host).known == 0 {
                unknown.push(host);
            }
        }
        assert!(
            unknown.is_empty(),
            "host errnos with no entry: {unknown:?} (ELAST is {})",
            libc::ELAST
        );
    }

    #[test]
    fn host_only_errnos_are_in_range() {
        // The darwin module writes these numbers out instead of reading a
        // header. A wrong one would fall through to the fallback, quietly
        // undoing the entry it was added for -- which the check above would
        // catch only if the number were also above ELAST.
        for e in [
            darwin::EPROCLIM,
            darwin::EBADRPC,
            darwin::ERPCMISMATCH,
            darwin::EPROGUNAVAIL,
            darwin::EPROGMISMATCH,
            darwin::EPROCUNAVAIL,
            darwin::EFTYPE,
            darwin::EAUTH,
            darwin::ENEEDAUTH,
            darwin::EPWROFF,
            darwin::EDEVERR,
            darwin::EBADEXEC,
            darwin::EBADARCH,
            darwin::ESHLIBVERS,
            darwin::EBADMACHO,
            darwin::ENOATTR,
            darwin::ENOPOLICY,
            darwin::EQFULL,
            darwin::ENOTCAPABLE,
        ] {
            assert!((1..=libc::ELAST).contains(&e), "{e} is not a Darwin errno");
            assert_eq!(map(e).known, 1, "errno {e} falls through");
        }
        // And each is a distinct number, so a copy-paste slip is caught.
        let all = [
            darwin::EPROCLIM,
            darwin::EBADRPC,
            darwin::ERPCMISMATCH,
            darwin::EPROGUNAVAIL,
            darwin::EPROGMISMATCH,
            darwin::EPROCUNAVAIL,
            darwin::EFTYPE,
            darwin::EAUTH,
            darwin::ENEEDAUTH,
            darwin::EPWROFF,
            darwin::EDEVERR,
            darwin::EBADEXEC,
            darwin::EBADARCH,
            darwin::ESHLIBVERS,
            darwin::EBADMACHO,
            darwin::ENOATTR,
            darwin::ENOPOLICY,
            darwin::EQFULL,
            darwin::ENOTCAPABLE,
        ];
        let mut sorted = all.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            all.len(),
            "two of the Darwin errnos are the same number"
        );
    }

    /// The guest errnos `iul.h` declares are a second copy of these, so read
    /// it rather than trusting the two to stay in step.
    ///
    /// It read `kernel/errno.h` and checked seventeen until 2026-09-08. That
    /// header had one reader — this test — and its numbers are the ones below,
    /// so the check was a copy comparing itself with a copy. `iul.h` is the
    /// interface an embedder compiles against and declares the two an
    /// embedder's own bridge returns, which is what is left to disagree.
    #[test]
    fn the_guest_errnos_iul_h_declares_are_these() {
        let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        while !dir.join("iul.h").is_file() {
            assert!(dir.pop(), "no repository root above CARGO_MANIFEST_DIR");
        }
        let header = std::fs::read_to_string(dir.join("iul.h")).expect("iul.h");

        let ours: &[(&str, c_int)] = &[("_E2BIG", guest::E2BIG), ("_ENOTTY", guest::ENOTTY)];
        let mut checked = 0;
        for (name, value) in ours {
            let pat = format!("#define {name} ");
            let at = header
                .find(&pat)
                .unwrap_or_else(|| panic!("iul.h no longer defines {name}"));
            let rest = &header[at + pat.len()..];
            let n: c_int = rest
                .split_whitespace()
                .next()
                .and_then(|w| w.parse().ok())
                .unwrap_or_else(|| panic!("iul.h's {name} is not a number"));
            assert_eq!(n, *value, "{name}");
            checked += 1;
        }
        assert_eq!(checked, ours.len(), "every name was found and compared");
    }
}
