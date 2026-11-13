use super::*;

#[cfg(test)]
mod abi {
    //! Does the trampoline put the variadic slot where the Rust side reads it?
    //!
    //! This is the one thing about the two interposes above that a reader
    //! cannot check by reading, and getting it wrong is silent: every
    //! `O_CREAT` open would be created with whatever happened to be on the
    //! stack. So the *same four instructions* are assembled again here against
    //! a function that records its arguments, and called through a **variadic**
    //! declaration — which is what libc's `open` is and what dyld hands the
    //! real one.
    use std::cell::RefCell;
    use std::ffi::{c_char, c_int};

    // Thread-local rather than a `static`: cargo runs tests in parallel, and
    // the trampoline tail-calls on the calling thread, so each test sees only
    // its own calls. A shared `Mutex<Vec<_>>` was written first and the two
    // tests below interleaved into it.
    thread_local! {
        static SEEN: RefCell<Vec<(i64, i64, i64, i64)>> = const { RefCell::new(Vec::new()) };
    }

    fn seen() -> Vec<(i64, i64, i64, i64)> {
        SEEN.with(|s| s.borrow().clone())
    }

    core::arch::global_asm!(
        ".globl _test_open_tramp",
        ".p2align 2",
        "_test_open_tramp:",
        "    ldr  w2, [sp]",
        "    b    {open_impl}",
        ".globl _test_openat_tramp",
        ".p2align 2",
        "_test_openat_tramp:",
        "    ldr  w3, [sp]",
        "    b    {openat_impl}",
        open_impl = sym record_open,
        openat_impl = sym record_openat,
    );

    unsafe extern "C" fn record_open(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
        SEEN.with(|s| {
            s.borrow_mut()
                .push((path as i64, flags as i64, mode as i64, 0))
        });
        0
    }

    unsafe extern "C" fn record_openat(
        fd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: c_int,
    ) -> c_int {
        SEEN.with(|s| {
            s.borrow_mut()
                .push((fd as i64, path as i64, flags as i64, mode as i64))
        });
        0
    }

    unsafe extern "C" {
        // Declared variadic, exactly as libc declares the calls these replace.
        // Rust may *declare* one; it is defining one that is unstable, which is
        // what the assembly above is for.
        fn test_open_tramp(path: *const c_char, flags: c_int, ...) -> c_int;
        fn test_openat_tramp(fd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    }

    #[test]
    fn the_mode_arrives_in_the_register_the_rust_side_reads() {
        let p = c"/a".as_ptr();
        unsafe {
            test_open_tramp(p, libc::O_CREAT, 0o644);
            test_open_tramp(p, libc::O_CREAT | libc::O_WRONLY, 0o600);
            test_open_tramp(p, libc::O_CREAT, 0o777);
        }
        let seen = seen();
        assert_eq!(seen[0].2, 0o644);
        assert_eq!(seen[1].2, 0o600);
        assert_eq!(
            seen[1].1,
            (libc::O_CREAT | libc::O_WRONLY) as i64,
            "flags must survive too"
        );
        assert_eq!(seen[2].2, 0o777);
    }

    #[test]
    fn openat_shifts_every_argument_by_one() {
        let p = c"/b".as_ptr();
        unsafe {
            test_openat_tramp(libc::AT_FDCWD, p, libc::O_CREAT, 0o640);
            test_openat_tramp(7, p, libc::O_CREAT, 0o755);
        }
        let seen = seen();
        assert_eq!(
            (seen[0].0, seen[0].2, seen[0].3),
            (libc::AT_FDCWD as i64, libc::O_CREAT as i64, 0o640)
        );
        assert_eq!((seen[1].0, seen[1].3), (7, 0o755));
        assert_eq!(
            seen[0].1, p as i64,
            "the path is the second argument, in x1"
        );
    }

    /// A caller that passes no mode at all leaves the slot holding whatever was
    /// there, which is why [`super::mode_for`] and not the trampoline decides.
    /// Reading it is safe — `[sp]` is inside the caller's frame — and the value
    /// is the thing that must not be trusted.
    #[test]
    fn without_o_creat_the_slot_is_not_a_mode_and_is_discarded() {
        assert_eq!(super::mode_for(libc::O_CREAT, 0o644), 0o644);
        assert_eq!(
            super::mode_for(libc::O_RDONLY, 0o755),
            0,
            "no O_CREAT, no mode"
        );
        assert_eq!(super::mode_for(libc::O_WRONLY | libc::O_TRUNC, -1), 0);
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    const ROOT: &[u8] = b"/host/fakefs/data";

    fn go(p: &str) -> Redirect {
        redirect_path(p.as_bytes(), Some(ROOT))
    }

    fn to(p: &str) -> Redirect {
        Redirect::To(p.as_bytes().to_vec())
    }

    #[test]
    fn a_guest_path_gets_the_root_in_front_of_it() {
        assert_eq!(go("/tmp/in.mp4"), to("/host/fakefs/data/tmp/in.mp4"));
        assert_eq!(go("/"), to("/host/fakefs/data/"));
    }

    /// The whole point of the library, as one case: without it the program
    /// reads the host's file of that name.
    #[test]
    fn a_relative_path_is_the_processs_own_business() {
        assert_eq!(go("out.mp4"), Redirect::Keep);
        assert_eq!(go(""), Redirect::Keep);
    }

    #[test]
    fn a_host_only_prefix_is_kept() {
        for p in [
            "/dev/null",
            "/usr/lib/dyld",
            "/System/Library/x",
            "/Users/me/x",
            "/usr/bin/ffmpeg",
            "/usr/sbin/x",
        ] {
            assert_eq!(go(p), Redirect::Keep, "{p}");
        }
        // `/usr` itself is *not* in the list: a guest has its own /usr/share.
        assert_eq!(go("/usr/share/x"), Redirect::Keep, "explicitly listed");
        assert_eq!(go("/usr/games/x"), to("/host/fakefs/data/usr/games/x"));
    }

    /// Each prefix ends in `/`, so a longer name that starts with the same
    /// letters is not one of them.
    #[test]
    fn a_prefix_matches_on_a_separator() {
        assert_eq!(go("/development/x"), to("/host/fakefs/data/development/x"));
        assert_eq!(go("/optional"), to("/host/fakefs/data/optional"));
    }

    /// A path already under the root is left alone — **on a component
    /// boundary**. The C compared `root_len` bytes and stopped, so a sibling
    /// directory whose name merely starts with the root's was left pointing at
    /// the host.
    #[test]
    fn a_path_already_under_the_root_is_kept() {
        assert_eq!(go("/host/fakefs/data/tmp/x"), Redirect::Keep);
        assert_eq!(go("/host/fakefs/data"), Redirect::Keep);
        // The sibling. Rewritten, because it is not under the root.
        assert_eq!(
            go("/host/fakefs/database"),
            to("/host/fakefs/data/host/fakefs/database")
        );
    }

    /// A rewrite that does not fit is **not** the original path.
    ///
    /// The C returned it, which hands the *host's* file at that path to a
    /// program that asked for the guest's — the exact failure the library
    /// exists to prevent, reached by making a path long enough.
    #[test]
    fn a_path_too_long_to_rewrite_is_refused_not_passed_through() {
        let long = format!("/{}", "a".repeat(PATH_MAX));
        assert_eq!(go(&long), Redirect::TooLong);
        // And the boundary: exactly enough room, and one byte less.
        let fits = format!("/{}", "a".repeat(PATH_MAX - ROOT.len() - 2));
        assert!(matches!(go(&fits), Redirect::To(_)), "{}", fits.len());
        let over = format!("/{}", "a".repeat(PATH_MAX - ROOT.len() - 1));
        assert_eq!(go(&over), Redirect::TooLong);
    }

    /// With no `FAKEFS_ROOT` there is nothing to redirect to, and every path is
    /// the host's. That is how this library behaves in a process nobody set it
    /// up for, which is every process that loads it by accident.
    #[test]
    fn no_root_means_no_redirection() {
        assert_eq!(redirect_path(b"/tmp/x", None), Redirect::Keep);
    }
}
