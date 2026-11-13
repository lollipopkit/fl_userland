//! Whether a write to stderr is V8 on its way to a fatal abort.
//!
//! V8 prints its fatal preamble — `# Fatal error…`, a stack dump — **before**
//! executing `BRK #0`, so by the time the `SIGTRAP` handler fires the text is
//! already on the host terminal. Catching the signature at `write` lets the
//! bytes be dropped while the call reports that they went through.
//!
//! # A false positive costs a program its stderr
//!
//! Once any one of these matches, the whole thread group is in abort mode and
//! **every subsequent stderr write is dropped**. So the list has to be signatures
//! that essentially only V8's internal abort path emits, and the cost of missing
//! some V8 noise is much lower than the cost of silencing a program.
//!
//! That is the reason this is its own crate with tests: the near-misses are the
//! interesting cases, and there was no way to write one while the list was a
//! `static const char *const[]` inside a `static` function.
//!
//! # The scan is a search, not a prefix match
//!
//! V8 sometimes coalesces the banner with a leading `#\n` or surrounding
//! preamble into a single write, so the signature is looked for anywhere in the
//! first 256 bytes rather than at offset zero. The name `v8_abort_prefix`
//! described what it was before that changed.


/// How far into a write to look. A banner that starts later than this is a
/// write big enough that dropping it on a guess is the worse mistake.
const SCAN: usize = 256;

/// The signatures. Each is something V8 or Node prints on the way to dying, and
/// nothing else does.
///
/// The `FATAL ERROR:` and `abort:` entries are deliberately specific: V8's
/// `FATAL()` prints `FATAL ERROR: <reason>` and `Runtime_Abort` prints
/// `abort: <reason>`, and matching on either alone would silence a program that
/// prints its own.
pub const SIGNATURES: &[&[u8]] = &[
    b"# Fatal error in ",              // V8_Fatal preamble
    b"# Check failed:",                // the CHECK macro
    b"#FailureMessage Object",         // FailureMessage dump
    b"----- Native stack trace -----", // the stack-trace banner
    b"----- JavaScript stack trace -----",
    b"Attempt to print stack while printing stack",
    b"<--- Last few GCs --->",       // the OOM dump
    b"FATAL ERROR: v8::",            // e.g. v8::HandleScope::CreateHandle
    b"FATAL ERROR: CALL_AND_RETRY_", // heap OOM
    b"FATAL ERROR: MarkCompactCollector",
    b"FATAL ERROR: Reached heap limit",
    b"FATAL ERROR: Scavenger",
    b"FATAL ERROR: NewSpace",
    // Known reasons from V8's `GetAbortReason` in runtime-internal.cc.
    b"abort: Invalid bytecode",
    b"abort: Unreachable",
    b"abort: kOperandIsNotAFunction",
    b"abort: kOperandIsNotACallable",
    b"abort: kExpectedFeedbackVector",
    b"abort: kInvalidJumpTableIndex",
    b"abort: kStackFrameTypesMustMatch",
    b"abort: kUnexpectedFunctionKind",
];

/// Whether `buf` carries one of [`SIGNATURES`] in its first [`SCAN`] bytes.
pub(crate) fn is_abort_banner(buf: &[u8]) -> bool {
    let scan = &buf[..buf.len().min(SCAN)];
    SIGNATURES
        .iter()
        .any(|sig| scan.len() >= sig.len() && contains(scan, sig))
}

/// `memmem`. Written out because `slice::windows` allocates nothing but reads
/// worse here, and because the empty needle — which cannot occur, since every
/// signature is non-empty — would otherwise match.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Whether this write is V8 chatter on its way to a fatal abort, and should be
/// swallowed while the call reports that it went through.
///
/// **Sticky.** One match puts the whole thread group in abort mode and drops
/// its stderr for ever, which is why the near misses are what the tests above
/// are about.
///
/// Three conditions before the scan, and each is a reason not to mute: the
/// diagnostic is turned off with `IUL_V8_NO_MUTE`, the descriptor is not
/// stderr, or there is no thread group to be in abort mode — a host thread that
/// is not running a guest has none.
///
/// This was `rw_v8_muted` in `kernel/fs.c` until 2026-09-03, and it was there
/// because it reads `current->group->v8_aborting`. It reads the same field, and
/// it reads it through `crates/kernel/taskview`.
pub fn muted(fd_no: i32, buf: &[u8]) -> bool {
    if fd_no != 2 || util_iulenv::v8_no_mute() {
        return false;
    }
    taskview::with_current_group(|g| {
        if g.v8_aborting() {
            return true;
        }
        let banner = is_abort_banner(buf);
        if banner {
            g.set_v8_aborting(true);
        }
        banner
    })
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every signature matches when it is the whole write.
    #[test]
    fn each_signature_is_recognised() {
        for sig in SIGNATURES {
            assert!(is_abort_banner(sig), "{:?}", String::from_utf8_lossy(sig));
        }
    }

    /// And when it is preceded by the empty comment line V8 sometimes
    /// coalesces in front of it. That is why the scan is a search rather than a
    /// prefix match.
    #[test]
    fn a_signature_is_found_after_a_preamble() {
        let mut buf = b"#\n\n".to_vec();
        buf.extend_from_slice(b"# Fatal error in ../deps/v8/src/heap/heap.cc");
        assert!(is_abort_banner(&buf));
    }

    /// The near misses, which are the whole reason this has tests. Once one
    /// match happens the thread group's stderr is dropped for ever, so a
    /// program printing any of these must not be silenced.
    #[test]
    fn a_program_that_prints_something_similar_is_not_silenced() {
        for line in [
            &b"abort: config not found\n"[..],
            b"abort: no such file\n",
            b"FATAL ERROR: could not open the database\n",
            b"FATAL ERROR\n",
            b"# Fatal\n",
            b"# Fatal error\n", // no trailing " in ", which V8 always has
            b"Check failed: something\n", // no leading '#'
            b"----- stack trace -----\n",
            b"<--- GCs --->\n",
            b"",
            b"\0\0\0\0",
        ] {
            assert!(
                !is_abort_banner(line),
                "{:?} was silenced",
                String::from_utf8_lossy(line)
            );
        }
    }

    /// A signature past the scan window is not looked for. The window exists so
    /// that a large write is not searched end to end on every `write(2)`.
    #[test]
    fn a_signature_past_the_window_is_not_found() {
        let sig = b"# Fatal error in ";
        let mut buf = vec![b'x'; SCAN];
        buf.extend_from_slice(sig);
        assert!(!is_abort_banner(&buf));

        // And one that *ends* inside the window is found, which is the boundary
        // the `scan.len() >= sig.len()` test is about.
        let mut buf = vec![b'x'; SCAN - sig.len()];
        buf.extend_from_slice(sig);
        assert!(is_abort_banner(&buf));
    }

    /// An empty write is not a banner. It used to be the C entry point's
    /// degenerate case — a null pointer and a zero length — and the entry
    /// point went on 2026-09-03 with the last C that called it, so what is
    /// left to assert is the slice.
    #[test]
    fn nothing_is_not_a_banner() {
        assert!(!is_abort_banner(b""));
        let sig = SIGNATURES[0];
        assert!(is_abort_banner(sig));
        assert!(!is_abort_banner(&sig[..sig.len() - 1]));
    }

    /// No signature is a prefix of another. One that was would be dead: the
    /// shorter always matches first and the longer could never be the reason.
    #[test]
    fn no_signature_shadows_another() {
        for (i, a) in SIGNATURES.iter().enumerate() {
            for (j, b) in SIGNATURES.iter().enumerate() {
                if i != j {
                    assert!(
                        !contains(b, a),
                        "{:?} contains {:?}",
                        String::from_utf8_lossy(b),
                        String::from_utf8_lossy(a)
                    );
                }
            }
        }
    }
}
