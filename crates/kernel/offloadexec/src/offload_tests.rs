//! Tests for native offload path and signal forwarding setup.

use super::*;
#[test]
fn a_url_is_not_a_path() {
    // ffmpeg is routinely handed an http:// source, and translating it as a
    // guest path would hand the host a filename that does not exist.
    assert!(contains(b"https://example.com/a.mp4", b"://"));
    assert!(!contains(b"/tmp/a.mp4", b"://"));
    assert!(!contains(b"/", b"://"), "shorter than the needle");
    assert!(!contains(b"", b"://"));
}

#[test]
fn every_skipped_environment_prefix_ends_at_the_equals() {
    // A prefix compare is only a *name* compare if it includes the `=`:
    // without it, PYTHONMALLOC= would also drop PYTHONMALLOCSTATS.
    #[cfg(target_os = "macos")]
    for p in [
        &b"OPENSSL_armcap="[..],
        b"PYTHONMALLOC=",
        b"PYTHONDONTWRITEBYTECODE=",
        b"DYLD_INSERT_LIBRARIES=",
        b"FAKEFS_ROOT=",
    ] {
        assert_eq!(p.last(), Some(&b'='), "{}", String::from_utf8_lossy(p));
        assert!(!p[..p.len() - 1].contains(&b'='));
    }
}
/// Registering an offload binary arms signal forwarding, and nothing else
/// can catch it if it stops.
///
/// With no hook installed `crates/kernel/signaldeliver` delivers the signal
/// to the emulated task — which is exactly what an *unregistered* binary
/// gets and what a forward that answered `false` gets. So no assertion
/// about a delivered signal distinguishes a missing install, and the
/// consequence in a running guest is quiet: a `kill` on an offloaded
/// ffmpeg queues a signal the host process never sees.
///
/// `native_offload_add_handler` rather than `native_offload_add`, because
/// the latter is macOS-only and prints to stderr elsewhere; both call
/// `arm_signal_forwarding` and this asserts the arming, not the platform.
#[test]
fn registering_a_handler_arms_signal_forwarding() {
    extern "C" fn nothing(
        _argc: i32,
        _argv: *mut *mut std::ffi::c_char,
        _in: i32,
        _out: i32,
        _err: i32,
    ) -> i32 {
        0
    }
    let name = c"a-name-no-guest-will-execve";
    assert_eq!(
        unsafe { crate::native_offload_add_handler(name.as_ptr(), nothing) },
        0
    );
    assert!(signaldeliver::offload_forward_hook_installed());
}

/// A counted list stops at the count; an uncounted one at the empty string.
/// Bounded by the buffer either way, which is what the slice is for: it was
/// `ARGV_MAX` bytes viewed over a buffer sized to its contents.
#[test]
fn a_packed_list_is_read_within_its_buffer() {
    assert_eq!(super::unpack(b"ls\0-l\0\0", Some(2)), vec![b"ls".to_vec(), b"-l".to_vec()]);
    assert_eq!(super::unpack(b"A=1\0B=2\0\0", None), vec![b"A=1".to_vec(), b"B=2".to_vec()]);
    assert_eq!(super::unpack(b"\0", None), Vec::<Vec<u8>>::new(), "an empty environment");
    // No terminator inside the buffer: what is complete is kept, nothing past
    // the end is read.
    assert_eq!(super::unpack(b"A=1\0B=", None), vec![b"A=1".to_vec()]);
    assert_eq!(super::unpack(b"", Some(3)), Vec::<Vec<u8>>::new());
}
